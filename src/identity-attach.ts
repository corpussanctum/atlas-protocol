/**
 * Atlas Protocol — Operator-signed identity attach (#39)
 *
 * The session's agent binding (sessionAgentId) lives only in server memory,
 * so a restart leaves an unexpired credential that no session can use: every
 * permission request is denied UNREGISTERED_AGENT and registration is locked.
 * An attach token lets the operator re-bind a restarted session to one
 * existing credential.
 *
 * Authorization model (mirrors break-glass, SPEC §9):
 *   - Tokens are issued only by `atlas-operator attach`, with the operator
 *     passphrase entered at a TTY, and carry an ML-DSA-65 operator signature.
 *     The gatekeeper verifies against the operator key pinned at startup.
 *   - A token names one credential by agentId AND credentialHash, so a
 *     registry edit (e.g. widened capabilities) invalidates it.
 *   - Single-use: the server claims the file by atomic rename (one server
 *     wins) and records the nonce, so a copy cannot be replayed.
 *   - Short TTL (default 10 min, max 60) checked from the signed fields.
 *   - The agent's key is not part of the token. Delegation from an attached
 *     credential works only if the key is in a durable keystore (#4).
 */

import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync, chmodSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { attestAgent } from "./attestation.js";
import type { IdentityRegistry } from "./identity-registry.js";
import { loadMlDsa, operatorSign, operatorVerify, type OperatorPublicKey } from "./operator-key.js";

// ---------------------------------------------------------------------------
// Types and constants
// ---------------------------------------------------------------------------

export interface AttachClaims {
  version: 1;
  agent_id: string;
  credential_hash: string;
  created_at: string;
  expires_at: string;
  nonce: string;
  operator_key_id: string;
}

export interface AttachToken extends AttachClaims {
  signature: string;
}

export type AttachRejection =
  | "NO_TOKEN"
  | "NO_OPERATOR_KEY"
  | "MALFORMED_TOKEN"
  | "WRONG_OPERATOR_KEY"
  | "BAD_SIGNATURE"
  | "TTL_EXCEEDS_MAX"
  | "EXPIRED"
  | "REPLAYED"
  | "UNKNOWN_CREDENTIAL"
  | "CREDENTIAL_CHANGED"
  | "CREDENTIAL_INVALID";

const TOKEN_FILENAME = "attach.token";
const USED_FILENAME = "attach.used.json";
export const DEFAULT_ATTACH_TTL_MINUTES = 10;
export const MAX_ATTACH_TTL_MINUTES = 60;

const claimsOf = (t: AttachClaims): Record<string, string | number> => ({
  version: t.version,
  agent_id: t.agent_id,
  credential_hash: t.credential_hash,
  created_at: t.created_at,
  expires_at: t.expires_at,
  nonce: t.nonce,
  operator_key_id: t.operator_key_id,
});

// ---------------------------------------------------------------------------
// Issuance (operator side: atlas-operator CLI only)
// ---------------------------------------------------------------------------

export async function issueAttachToken(
  dataDir: string,
  operator: { keyId: string; secretKey: Uint8Array },
  credential: { agentId: string; credentialHash: string },
  ttlMinutes: number = DEFAULT_ATTACH_TTL_MINUTES,
): Promise<AttachToken> {
  const ttl = Math.min(Math.max(1, Math.floor(ttlMinutes)), MAX_ATTACH_TTL_MINUTES);
  const now = new Date();
  const claims: AttachClaims = {
    version: 1,
    agent_id: credential.agentId,
    credential_hash: credential.credentialHash,
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl * 60_000).toISOString(),
    nonce: randomBytes(16).toString("hex"),
    operator_key_id: operator.keyId,
  };
  const token: AttachToken = { ...claims, signature: await operatorSign(operator.secretKey, claimsOf(claims)) };
  const path = join(dataDir, TOKEN_FILENAME);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(token, null, 2), { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // Non-fatal on restricted systems
  }
  return token;
}

// ---------------------------------------------------------------------------
// Verification (gatekeeper side)
// ---------------------------------------------------------------------------

export class AttachManager {
  private readonly tokenPath: string;
  private readonly usedPath: string;

  private constructor(
    dataDir: string,
    private readonly operatorKey: OperatorPublicKey | null,
    private readonly dsa: Awaited<ReturnType<typeof loadMlDsa>> | null,
  ) {
    this.tokenPath = join(dataDir, TOKEN_FILENAME);
    this.usedPath = join(dataDir, USED_FILENAME);
  }

  /** @param operatorKey Pinned for this process's lifetime; null ⇒ attach unavailable. */
  static async open(dataDir: string, operatorKey: OperatorPublicKey | null): Promise<AttachManager> {
    return new AttachManager(dataDir, operatorKey, operatorKey ? await loadMlDsa() : null);
  }

  /**
   * Claim and verify the pending attach token. The token is consumed whether
   * or not it verifies, so a bad token cannot be retried indefinitely.
   */
  consume(registry: IdentityRegistry, now = new Date()):
    | { token: AttachToken }
    | { rejected: AttachRejection; agent_id?: string } {
    const claimed = `${this.tokenPath}.claimed-${process.pid}-${randomBytes(4).toString("hex")}`;
    try {
      renameSync(this.tokenPath, claimed);
    } catch {
      return { rejected: "NO_TOKEN" };
    }
    let raw: any;
    try {
      raw = JSON.parse(readFileSync(claimed, "utf-8"));
    } catch {
      return { rejected: "MALFORMED_TOKEN" };
    } finally {
      try {
        unlinkSync(claimed);
      } catch {
        // ignore
      }
    }

    const result = this.evaluate(raw, registry, now);
    if ("token" in result) this.recordNonce(result.token, now);
    return result;
  }

  private evaluate(raw: any, registry: IdentityRegistry, now: Date):
    | { token: AttachToken }
    | { rejected: AttachRejection; agent_id?: string } {
    if (!this.operatorKey || !this.dsa) return { rejected: "NO_OPERATOR_KEY" };
    const wellFormed =
      raw?.version === 1 &&
      typeof raw.signature === "string" &&
      typeof raw.agent_id === "string" &&
      typeof raw.credential_hash === "string" &&
      typeof raw.created_at === "string" &&
      typeof raw.expires_at === "string" &&
      typeof raw.nonce === "string" &&
      typeof raw.operator_key_id === "string";
    if (!wellFormed) return { rejected: "MALFORMED_TOKEN" };
    const agent_id: string = raw.agent_id;
    if (raw.operator_key_id !== this.operatorKey.key_id) return { rejected: "WRONG_OPERATOR_KEY", agent_id };
    if (!operatorVerify(this.dsa, this.operatorKey, claimsOf(raw), raw.signature)) {
      return { rejected: "BAD_SIGNATURE", agent_id };
    }

    const created = Date.parse(raw.created_at);
    const expires = Date.parse(raw.expires_at);
    if (!Number.isFinite(created) || !Number.isFinite(expires)) return { rejected: "MALFORMED_TOKEN", agent_id };
    if (expires - created > MAX_ATTACH_TTL_MINUTES * 60_000) return { rejected: "TTL_EXCEEDS_MAX", agent_id };
    if (expires <= now.getTime()) return { rejected: "EXPIRED", agent_id };
    if (this.usedNonces(now).has(raw.nonce)) return { rejected: "REPLAYED", agent_id };

    const credential = registry.get(agent_id);
    if (!credential) return { rejected: "UNKNOWN_CREDENTIAL", agent_id };
    if (credential.credentialHash !== raw.credential_hash) return { rejected: "CREDENTIAL_CHANGED", agent_id };
    // Signature, revocation, expiry, and delegation-chain checks
    if (!registry.verify(agent_id).valid || attestAgent(registry, agent_id).denyReason) {
      return { rejected: "CREDENTIAL_INVALID", agent_id };
    }

    return { token: raw as AttachToken };
  }

  /** Nonces of consumed tokens that have not yet expired. */
  private usedNonces(now: Date): Map<string, string> {
    try {
      const entries = JSON.parse(readFileSync(this.usedPath, "utf-8")) as Record<string, string>;
      return new Map(Object.entries(entries).filter(([, exp]) => Date.parse(exp) > now.getTime()));
    } catch {
      return new Map();
    }
  }

  private recordNonce(token: AttachToken, now: Date): void {
    const used = this.usedNonces(now);
    used.set(token.nonce, token.expires_at);
    try {
      writeFileSync(this.usedPath, JSON.stringify(Object.fromEntries(used)), { mode: 0o600 });
    } catch {
      // The token file is already gone; replay needs a copy taken beforehand
    }
  }

  /** Whether an attach token is waiting to be consumed. */
  pending(): boolean {
    return existsSync(this.tokenPath);
  }
}
