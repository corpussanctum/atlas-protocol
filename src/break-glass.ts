/**
 * Atlas Protocol — Break-Glass Mechanism (SPEC §9)
 *
 * Emergency override for when the operator relay (Telegram) is unreachable:
 * while a valid token is active, "ask" verdicts are auto-approved with an
 * audit trail. Hard-deny rules are NEVER bypassed.
 *
 * Authorization model (since 1.0.5):
 *   - Tokens are issued only by the operator, via the `atlas-operator` CLI,
 *     and carry an ML-DSA-65 signature from the operator key (operator-key.ts).
 *     The gatekeeper never holds that secret key.
 *   - The gatekeeper verifies tokens against the operator public key pinned
 *     in memory at startup. Replacing the key file mid-session has no effect.
 *   - The MCP tool `atlas_break_glass_activate` cannot activate break-glass:
 *     the governed agent can call MCP tools, so it must not be able to
 *     authorize its own bypass.
 *   - Unsigned (pre-1.0.5) or tampered tokens are rejected.
 *   - TTL is capped at 4 hours and checked from the signed fields.
 *   - Usage counts live outside the signed token (in memory, persisted
 *     best-effort); the server takes the higher of the two, so deleting the
 *     usage file mid-session does not reset the count.
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, chmodSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { randomBytes } from "node:crypto";
import {
  loadMlDsa,
  operatorSign,
  operatorVerify,
  type OperatorPublicKey,
} from "./operator-key.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Signed fields of a break-glass token. */
export interface BreakGlassClaims {
  version: 2;
  reason: string;
  created_at: string;
  expires_at: string;
  /** Max requests this token can approve (0 = unlimited) */
  max_requests: number;
  nonce: string;
  operator_key_id: string;
}

export interface BreakGlassToken extends BreakGlassClaims {
  signature: string;
  /** How many requests this token has approved so far (not signed; tracked by the gatekeeper) */
  requests_used: number;
}

export type BreakGlassRejection =
  | "NO_OPERATOR_KEY"
  | "UNSIGNED_TOKEN"
  | "MALFORMED_TOKEN"
  | "WRONG_OPERATOR_KEY"
  | "BAD_SIGNATURE"
  | "TTL_EXCEEDS_MAX"
  | "EXPIRED"
  | "REQUEST_LIMIT_REACHED";

export interface BreakGlassStatus {
  active: boolean;
  operator_key_id: string | null;
  /** Why a present token is not active */
  rejected?: BreakGlassRejection;
  token?: {
    created_at: string;
    expires_at: string;
    reason: string;
    remaining_seconds: number;
    requests_used: number;
    max_requests: number;
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TOKEN_FILENAME = "break-glass.token";
const USAGE_FILENAME = "break-glass.usage.json";
export const DEFAULT_TTL_MINUTES = 60;
export const MAX_TTL_MINUTES = 240; // 4 hours max (SPEC §9.2)

const claimsOf = (t: BreakGlassClaims): Record<string, string | number> => ({
  version: t.version,
  reason: t.reason,
  created_at: t.created_at,
  expires_at: t.expires_at,
  max_requests: t.max_requests,
  nonce: t.nonce,
  operator_key_id: t.operator_key_id,
});

// ---------------------------------------------------------------------------
// Issuance (operator side: atlas-operator CLI only)
// ---------------------------------------------------------------------------

/**
 * Write an operator-signed break-glass token. Called by the operator CLI with
 * the unlocked operator secret key; the gatekeeper never calls this.
 */
export async function issueBreakGlassToken(
  dataDir: string,
  operator: { keyId: string; secretKey: Uint8Array },
  reason: string,
  ttlMinutes: number = DEFAULT_TTL_MINUTES,
  maxRequests: number = 0,
): Promise<BreakGlassToken> {
  if (!reason.trim()) throw new Error("reason is required");
  const effectiveTtl = Math.min(Math.max(1, Math.floor(ttlMinutes)), MAX_TTL_MINUTES);
  const now = new Date();
  const claims: BreakGlassClaims = {
    version: 2,
    reason,
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + effectiveTtl * 60_000).toISOString(),
    max_requests: Math.max(0, Math.floor(maxRequests)),
    nonce: randomBytes(16).toString("hex"),
    operator_key_id: operator.keyId,
  };
  const token: BreakGlassToken = {
    ...claims,
    signature: await operatorSign(operator.secretKey, claimsOf(claims)),
    requests_used: 0,
  };
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

export class BreakGlassManager {
  private readonly tokenPath: string;
  private readonly usagePath: string;
  private readonly usage = new Map<string, number>();

  private constructor(
    dataDir: string,
    private readonly operatorKey: OperatorPublicKey | null,
    private readonly dsa: Awaited<ReturnType<typeof loadMlDsa>> | null,
  ) {
    this.tokenPath = join(dataDir, TOKEN_FILENAME);
    this.usagePath = join(dataDir, USAGE_FILENAME);
  }

  /**
   * @param operatorKey The operator public key, pinned for this process's
   *   lifetime. null ⇒ break-glass is unavailable.
   */
  static async open(dataDir: string, operatorKey: OperatorPublicKey | null): Promise<BreakGlassManager> {
    return new BreakGlassManager(dataDir, operatorKey, operatorKey ? await loadMlDsa() : null);
  }

  get operatorKeyId(): string | null {
    return this.operatorKey?.key_id ?? null;
  }

  /** Check if a valid, operator-signed, unexpired break-glass token exists. */
  isActive(): boolean {
    return this.read() !== null;
  }

  /** Read and verify the current token. Returns null if missing or invalid. */
  read(): BreakGlassToken | null {
    const result = this.evaluate();
    return "token" in result ? result.token : null;
  }

  private evaluate(): { token: BreakGlassToken } | { rejected: BreakGlassRejection } | { none: true } {
    if (!existsSync(this.tokenPath)) return { none: true };
    let raw: any;
    try {
      raw = JSON.parse(readFileSync(this.tokenPath, "utf-8"));
    } catch {
      return { rejected: "MALFORMED_TOKEN" };
    }
    if (!this.operatorKey || !this.dsa) return { rejected: "NO_OPERATOR_KEY" };
    if (raw?.version !== 2 || typeof raw.signature !== "string") return { rejected: "UNSIGNED_TOKEN" };
    const wellFormed =
      typeof raw.reason === "string" &&
      typeof raw.created_at === "string" &&
      typeof raw.expires_at === "string" &&
      Number.isSafeInteger(raw.max_requests) && raw.max_requests >= 0 &&
      typeof raw.nonce === "string" &&
      typeof raw.operator_key_id === "string";
    if (!wellFormed) return { rejected: "MALFORMED_TOKEN" };
    if (raw.operator_key_id !== this.operatorKey.key_id) return { rejected: "WRONG_OPERATOR_KEY" };
    if (!operatorVerify(this.dsa, this.operatorKey, claimsOf(raw), raw.signature)) {
      return { rejected: "BAD_SIGNATURE" };
    }

    const created = Date.parse(raw.created_at);
    const expires = Date.parse(raw.expires_at);
    if (!Number.isFinite(created) || !Number.isFinite(expires)) return { rejected: "MALFORMED_TOKEN" };
    if (expires - created > MAX_TTL_MINUTES * 60_000) return { rejected: "TTL_EXCEEDS_MAX" };
    if (expires <= Date.now()) return { rejected: "EXPIRED" };

    const used = this.usedCount(raw.nonce);
    if (raw.max_requests > 0 && used >= raw.max_requests) return { rejected: "REQUEST_LIMIT_REACHED" };

    return { token: { ...(raw as BreakGlassClaims), signature: raw.signature, requests_used: used } };
  }

  private usedCount(nonce: string): number {
    let persisted = 0;
    try {
      const u = JSON.parse(readFileSync(this.usagePath, "utf-8"));
      if (u?.nonce === nonce && Number.isSafeInteger(u.used)) persisted = u.used;
    } catch {
      // Missing or corrupt usage file: fall back to memory
    }
    return Math.max(this.usage.get(nonce) ?? 0, persisted);
  }

  /** Record a break-glass approval against the active token. */
  recordUsage(): void {
    const token = this.read();
    if (!token) return;
    const used = token.requests_used + 1;
    this.usage.set(token.nonce, used);
    try {
      writeFileSync(this.usagePath, JSON.stringify({ nonce: token.nonce, used }), { mode: 0o600 });
    } catch {
      // In-memory count still applies for this process
    }
  }

  /** Revoke (delete) the break-glass token. Always allowed: it only removes privilege. */
  revoke(): boolean {
    if (!existsSync(this.tokenPath)) return false;
    try {
      unlinkSync(this.tokenPath);
      return true;
    } catch {
      return false;
    }
  }

  getStatus(): BreakGlassStatus {
    const result = this.evaluate();
    const base = { operator_key_id: this.operatorKeyId };
    if ("none" in result) return { active: false, ...base };
    if ("rejected" in result) return { active: false, ...base, rejected: result.rejected };
    const t = result.token;
    return {
      active: true,
      ...base,
      token: {
        created_at: t.created_at,
        expires_at: t.expires_at,
        reason: t.reason,
        remaining_seconds: Math.max(0, Math.round((Date.parse(t.expires_at) - Date.now()) / 1000)),
        requests_used: t.requests_used,
        max_requests: t.max_requests,
      },
    };
  }
}
