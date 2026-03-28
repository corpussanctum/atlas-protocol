/**
 * Fidelis Channel — Agent Identity (v0.5.0)
 *
 * Core credential system for agent identity attestation. Every agent that
 * passes through the gatekeeper must present a signed identity credential.
 *
 * Credential lifecycle:
 *   1. Agent requests registration → gatekeeper issues a signed credential
 *   2. Credential includes agent's ML-DSA-65 public key, role, capabilities
 *   3. Gatekeeper signs with its own ML-DSA-65 key (issuer signature)
 *   4. Credential is verified on each permission request
 *   5. Credentials can be revoked by the operator
 *
 * DID format: did:fidelis:<uuid>
 */

import { createHash, randomUUID, randomBytes } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AgentRole =
  | "claude-code"
  | "orchestrator"
  | "tool-caller"
  | "observer"
  | "admin";

export type AgentCapability =
  | "file:read"
  | "file:write"
  | "file:delete"
  | "shell:exec"
  | "shell:read"
  | "network:outbound"
  | "network:inbound"
  | "process:spawn"
  | "process:kill"
  | "credential:read"
  | "audit:read"
  | "identity:register"
  | "identity:revoke";

export interface AgentCredential {
  agentId: string;
  name: string;
  role: AgentRole;
  issuedAt: string;
  expiresAt: string;
  publicKey: string;
  capabilities: AgentCapability[];
  issuerSignature: string;
  credentialHash: string;
  version: string;
  revoked: boolean;
  revokedAt?: string;
  revokedReason?: string;
}

export interface AgentKeyPair {
  publicKey: string;   // hex-encoded ML-DSA-65 public key
  secretKey: string;   // hex-encoded ML-DSA-65 secret key
}

export interface CredentialIssueRequest {
  name: string;
  role: AgentRole;
  capabilities: AgentCapability[];
  ttlHours?: number;
}

export interface CredentialVerifyResult {
  valid: boolean;
  agentId?: string;
  reason?: string;
  expired?: boolean;
  revoked?: boolean;
}

// ---------------------------------------------------------------------------
// ML-DSA-65 type shim (matches quantum-signer.ts)
// ---------------------------------------------------------------------------

interface MlDsa65 {
  keygen: (seed?: Uint8Array) => { publicKey: Uint8Array; secretKey: Uint8Array };
  sign: (secretKey: Uint8Array, message: Uint8Array) => Uint8Array;
  verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean;
}

let _ml_dsa65: MlDsa65 | null = null;

/**
 * Initialize the ML-DSA-65 module. Must be called once before using
 * generateAgentKeyPair(). The identity registry handles this automatically.
 */
export async function initAgentIdentity(): Promise<boolean> {
  if (_ml_dsa65) return true;
  try {
    const mod = await import("@noble/post-quantum/ml-dsa");
    _ml_dsa65 = mod.ml_dsa65 as MlDsa65;
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FIDELIS_DID_PREFIX = "did:fidelis:";
const CREDENTIAL_VERSION = "0.5.0";
const DEFAULT_TTL_HOURS = 24;

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/**
 * Generate a new ML-DSA-65 keypair for an agent.
 * Requires initAgentIdentity() to have been called first.
 */
export function generateAgentKeyPair(): AgentKeyPair {
  if (!_ml_dsa65) {
    throw new Error("Agent identity not initialized — call initAgentIdentity() first");
  }
  const seed = randomBytes(32);
  const { publicKey, secretKey } = _ml_dsa65.keygen(seed);
  return {
    publicKey: Buffer.from(publicKey).toString("hex"),
    secretKey: Buffer.from(secretKey).toString("hex"),
  };
}

/**
 * Build the canonical payload for signing. Deterministic: sorted keys,
 * sorted capabilities. Excludes issuerSignature and credentialHash.
 */
export function buildCanonicalPayload(
  credential: Omit<AgentCredential, "issuerSignature" | "credentialHash">
): string {
  const sorted: Record<string, unknown> = {};
  const keys = Object.keys(credential).sort();
  for (const key of keys) {
    if (key === "issuerSignature" || key === "credentialHash") continue;
    let value = (credential as Record<string, unknown>)[key];
    if (key === "capabilities" && Array.isArray(value)) {
      value = [...value].sort();
    }
    sorted[key] = value;
  }
  return JSON.stringify(sorted);
}

/**
 * Issue a signed credential. The issuerSecretKey is the gatekeeper's
 * ML-DSA-65 secret key (same key that signs audit entries).
 */
export function issueCredential(
  request: CredentialIssueRequest,
  issuerSecretKey: Uint8Array
): AgentCredential {
  if (!_ml_dsa65) {
    throw new Error("Agent identity not initialized — call initAgentIdentity() first");
  }

  const agentKeyPair = generateAgentKeyPair();
  const now = new Date();
  const ttlHours = request.ttlHours ?? DEFAULT_TTL_HOURS;
  const expiresAt = new Date(now.getTime() + ttlHours * 60 * 60 * 1000);

  const partial: Omit<AgentCredential, "issuerSignature" | "credentialHash"> = {
    agentId: FIDELIS_DID_PREFIX + randomUUID(),
    name: request.name,
    role: request.role,
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    publicKey: agentKeyPair.publicKey,
    capabilities: [...request.capabilities],
    version: CREDENTIAL_VERSION,
    revoked: false,
  };

  const canonicalPayload = buildCanonicalPayload(partial);
  const credentialHash = createHash("sha3-256")
    .update(canonicalPayload)
    .digest("hex");

  // Sign the canonical payload with the gatekeeper's issuer key
  const payloadBytes = new Uint8Array(Buffer.from(canonicalPayload));
  const signatureBytes = _ml_dsa65.sign(issuerSecretKey, payloadBytes);
  const issuerSignature = Buffer.from(signatureBytes).toString("base64");

  return {
    ...partial,
    issuerSignature,
    credentialHash,
  };
}

/**
 * Verify a credential's issuer signature, expiry, and revocation status.
 */
export function verifyCredential(
  credential: AgentCredential,
  issuerPublicKey: Uint8Array
): CredentialVerifyResult {
  if (!_ml_dsa65) {
    return { valid: false, reason: "Agent identity not initialized" };
  }

  // Check revocation first
  if (credential.revoked) {
    return {
      valid: false,
      agentId: credential.agentId,
      reason: `Credential revoked: ${credential.revokedReason || "no reason given"}`,
      revoked: true,
      expired: false,
    };
  }

  // Check expiry
  const now = new Date();
  const expiresAt = new Date(credential.expiresAt);
  if (now > expiresAt) {
    return {
      valid: false,
      agentId: credential.agentId,
      reason: `Credential expired at ${credential.expiresAt}`,
      expired: true,
      revoked: false,
    };
  }

  // Rebuild canonical payload and verify signature
  const { issuerSignature, credentialHash, ...rest } = credential;
  const canonicalPayload = buildCanonicalPayload(rest);

  // Verify credential hash
  const expectedHash = createHash("sha3-256")
    .update(canonicalPayload)
    .digest("hex");
  if (credentialHash !== expectedHash) {
    return {
      valid: false,
      agentId: credential.agentId,
      reason: "Credential hash mismatch — credential may be tampered",
    };
  }

  // Verify issuer signature
  try {
    const payloadBytes = new Uint8Array(Buffer.from(canonicalPayload));
    const sigBytes = new Uint8Array(Buffer.from(issuerSignature, "base64"));
    const signatureValid = _ml_dsa65.verify(issuerPublicKey, payloadBytes, sigBytes);

    if (!signatureValid) {
      return {
        valid: false,
        agentId: credential.agentId,
        reason: "Issuer signature invalid — credential may be forged",
      };
    }
  } catch {
    return {
      valid: false,
      agentId: credential.agentId,
      reason: "Signature verification failed — malformed signature",
    };
  }

  return {
    valid: true,
    agentId: credential.agentId,
    expired: false,
    revoked: false,
  };
}

/**
 * Revoke a credential. Returns the updated credential with revocation metadata.
 */
export function revokeCredential(
  credential: AgentCredential,
  reason: string
): AgentCredential {
  return {
    ...credential,
    revoked: true,
    revokedAt: new Date().toISOString(),
    revokedReason: reason,
  };
}
