/**
 * Atlas Protocol — Agent Identity (v0.5.0)
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
 * DID format: did:atlas:<uuid>
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

const ATLAS_DID_PREFIX = "did:atlas:";
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
    agentId: ATLAS_DID_PREFIX + randomUUID(),
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

/**
 * Issue a signed credential AND return the agent's secret key.
 * Used when the caller needs to enable further delegation from this agent.
 * The secret key must be stored in-memory only — never persisted.
 */
export function issueCredentialWithKey(
  request: CredentialIssueRequest,
  issuerSecretKey: Uint8Array
): { credential: AgentCredential; agentSecretKey: Uint8Array } {
  if (!_ml_dsa65) {
    throw new Error("Agent identity not initialized — call initAgentIdentity() first");
  }

  const agentKeyPair = generateAgentKeyPair();
  const now = new Date();
  const ttlHours = request.ttlHours ?? DEFAULT_TTL_HOURS;
  const expiresAt = new Date(now.getTime() + ttlHours * 60 * 60 * 1000);

  const partial: Omit<AgentCredential, "issuerSignature" | "credentialHash"> = {
    agentId: ATLAS_DID_PREFIX + randomUUID(),
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

  const payloadBytes = new Uint8Array(Buffer.from(canonicalPayload));
  const signatureBytes = _ml_dsa65.sign(issuerSecretKey, payloadBytes);
  const issuerSignature = Buffer.from(signatureBytes).toString("base64");

  return {
    credential: {
      ...partial,
      issuerSignature,
      credentialHash,
    },
    agentSecretKey: Buffer.from(agentKeyPair.secretKey, "hex"),
  };
}

// ---------------------------------------------------------------------------
// Delegation Types (v0.6.0)
// ---------------------------------------------------------------------------

export interface DelegationChain {
  rootId: string;              // did:atlas:<uuid> — the original issuer
  parentId: string;            // did:atlas:<uuid> — direct parent
  depth: number;               // 0 = root, 1 = first delegation, max 3
  chainSignature: string;      // ML-DSA-65 signature over canonical delegation authority object
}

export interface DelegatedCredential extends AgentCredential {
  delegated: true;
  delegation: DelegationChain;
}

export interface DelegationRequest {
  parentAgentId: string;
  childName: string;
  childRole: AgentRole;
  capabilities: AgentCapability[];
  ttlHours?: number;
}

export type DelegationFailure =
  | "PARENT_NOT_FOUND"
  | "PARENT_EXPIRED"
  | "PARENT_REVOKED"
  | "CAPABILITY_ESCALATION"
  | "DEPTH_EXCEEDED"
  | "TTL_EXCEEDS_PARENT";

export interface DelegationValidation {
  valid: boolean;
  reason?: DelegationFailure;
}

// ---------------------------------------------------------------------------
// Delegation Constants
// ---------------------------------------------------------------------------

const MAX_DELEGATION_DEPTH = 3;

/**
 * Build a canonical delegation authority object for chain signing.
 * Binds the actual delegated authority (capabilities, expiry, depth),
 * not just identities. Prevents substitution/replay attacks.
 */
function buildDelegationAuthority(params: {
  rootId: string;
  parentId: string;
  childId: string;
  capabilities: AgentCapability[];
  expiresAt: string;
  depth: number;
  childCredentialHash: string;
}): string {
  // Build the object then sort keys per Appendix D.2 canonical serialization
  const obj: Record<string, unknown> = {
    capabilities: [...params.capabilities].sort(),
    childCredentialHash: params.childCredentialHash,
    childId: params.childId,
    depth: params.depth,
    expiresAt: params.expiresAt,
    parentId: params.parentId,
    protocol: "atlas-protocol",
    rootId: params.rootId,
    type: "delegation-authority",
    version: CREDENTIAL_VERSION,
  };
  return JSON.stringify(obj);
}

// ---------------------------------------------------------------------------
// Delegation Functions
// ---------------------------------------------------------------------------

/**
 * Type guard: returns true if the credential is a DelegatedCredential.
 */
export function isDelegatedCredential(
  credential: AgentCredential
): credential is DelegatedCredential {
  return (
    "delegated" in credential &&
    (credential as DelegatedCredential).delegated === true &&
    "delegation" in credential
  );
}

/**
 * Validate a delegation request before issuing. Checks parent existence,
 * revocation, expiry, capability subset, depth limit, and TTL bounds.
 */
export function validateDelegation(
  request: DelegationRequest,
  registry: { get(id: string): AgentCredential | undefined }
): DelegationValidation {
  const parent = registry.get(request.parentAgentId);

  if (!parent) {
    return { valid: false, reason: "PARENT_NOT_FOUND" };
  }

  if (parent.revoked) {
    return { valid: false, reason: "PARENT_REVOKED" };
  }

  const now = new Date();
  const parentExpiry = new Date(parent.expiresAt);
  if (now > parentExpiry) {
    return { valid: false, reason: "PARENT_EXPIRED" };
  }

  // Child capabilities must be a strict subset of parent capabilities
  const parentCaps = new Set(parent.capabilities);
  for (const cap of request.capabilities) {
    if (!parentCaps.has(cap)) {
      return { valid: false, reason: "CAPABILITY_ESCALATION" };
    }
  }

  // Depth check: delegated parents must not be at max depth
  if (isDelegatedCredential(parent)) {
    if (parent.delegation.depth >= MAX_DELEGATION_DEPTH) {
      return { valid: false, reason: "DEPTH_EXCEEDED" };
    }
  }

  // TTL check: if specified, child must not outlive parent
  if (request.ttlHours !== undefined) {
    const childExpiry = new Date(now.getTime() + request.ttlHours * 60 * 60 * 1000);
    if (childExpiry > parentExpiry) {
      return { valid: false, reason: "TTL_EXCEEDS_PARENT" };
    }
  }

  return { valid: true };
}

/**
 * Issue a delegated child credential. The child's TTL is capped at the
 * parent's remaining lifetime. The chain signature binds root → parent → child.
 */
export function delegateCredential(
  request: DelegationRequest,
  parentSecretKey: Uint8Array,
  issuerSecretKey: Uint8Array,
  registry: { get(id: string): AgentCredential | undefined }
): DelegatedCredential {
  if (!_ml_dsa65) {
    throw new Error("Agent identity not initialized — call initAgentIdentity() first");
  }

  // Validate without TTL check — this function caps TTL automatically
  const validation = validateDelegation(
    { ...request, ttlHours: undefined },
    registry
  );
  if (!validation.valid) {
    throw new Error(`Delegation validation failed: ${validation.reason}`);
  }

  const parent = registry.get(request.parentAgentId)!;
  const now = new Date();
  const parentExpiry = new Date(parent.expiresAt);

  // Calculate depth and rootId
  const depth = isDelegatedCredential(parent)
    ? parent.delegation.depth + 1
    : 1;
  const rootId = isDelegatedCredential(parent)
    ? parent.delegation.rootId
    : parent.agentId;

  // Cap child TTL at parent's remaining time
  const parentRemainingMs = parentExpiry.getTime() - now.getTime();
  const requestedMs = (request.ttlHours ?? DEFAULT_TTL_HOURS) * 60 * 60 * 1000;
  const childTtlMs = Math.min(requestedMs, parentRemainingMs);
  const childExpiry = new Date(now.getTime() + childTtlMs);

  // Generate child keypair
  const childKeyPair = generateAgentKeyPair();
  const childAgentId = ATLAS_DID_PREFIX + randomUUID();

  // Build the partial credential with a placeholder chain signature.
  // We need the credential hash first to bind it in the chain signature.
  const childKeyPairObj = childKeyPair; // rename for clarity
  const partialNoDelegation: Omit<AgentCredential, "issuerSignature" | "credentialHash"> = {
    agentId: childAgentId,
    name: request.childName,
    role: request.childRole,
    issuedAt: now.toISOString(),
    expiresAt: childExpiry.toISOString(),
    publicKey: childKeyPairObj.publicKey,
    capabilities: [...request.capabilities],
    version: CREDENTIAL_VERSION,
    revoked: false,
  };

  // Compute credential hash from the base credential fields
  const baseCanonical = buildCanonicalPayload(partialNoDelegation);
  const credentialHash = createHash("sha3-256").update(baseCanonical).digest("hex");

  // Build chain signature over canonical delegation authority (binds actual authority)
  const authorityPayload = buildDelegationAuthority({
    rootId,
    parentId: parent.agentId,
    childId: childAgentId,
    capabilities: request.capabilities,
    expiresAt: childExpiry.toISOString(),
    depth,
    childCredentialHash: credentialHash,
  });
  const chainMessageBytes = new Uint8Array(Buffer.from(authorityPayload));
  const chainSigBytes = _ml_dsa65.sign(parentSecretKey, chainMessageBytes);
  const chainSignature = Buffer.from(chainSigBytes).toString("base64");

  // Assemble the full delegated credential
  const partial: Omit<AgentCredential, "issuerSignature" | "credentialHash"> & {
    delegated: true;
    delegation: DelegationChain;
  } = {
    ...partialNoDelegation,
    delegated: true,
    delegation: { rootId, parentId: parent.agentId, depth, chainSignature },
  };

  // Issuer co-signs the full canonical payload (including delegation fields)
  const canonicalPayload = buildCanonicalPayload(partial);
  const fullCredentialHash = createHash("sha3-256").update(canonicalPayload).digest("hex");
  const payloadBytes = new Uint8Array(Buffer.from(canonicalPayload));
  const signatureBytes = _ml_dsa65.sign(issuerSecretKey, payloadBytes);
  const issuerSignature = Buffer.from(signatureBytes).toString("base64");

  return {
    ...partial,
    issuerSignature,
    credentialHash: fullCredentialHash,
  };
}

/**
 * Issue a delegated child credential AND return the child's secret key.
 * The secret key must be stored in-memory only — never persisted.
 */
export function delegateCredentialWithKey(
  request: DelegationRequest,
  parentSecretKey: Uint8Array,
  issuerSecretKey: Uint8Array,
  registry: { get(id: string): AgentCredential | undefined }
): { credential: DelegatedCredential; childSecretKey: Uint8Array } {
  if (!_ml_dsa65) {
    throw new Error("Agent identity not initialized — call initAgentIdentity() first");
  }

  // Validate without TTL check — this function caps TTL automatically
  const validation = validateDelegation(
    { ...request, ttlHours: undefined },
    registry
  );
  if (!validation.valid) {
    throw new Error(`Delegation validation failed: ${validation.reason}`);
  }

  const parent = registry.get(request.parentAgentId)!;
  const now = new Date();
  const parentExpiry = new Date(parent.expiresAt);

  const depth = isDelegatedCredential(parent) ? parent.delegation.depth + 1 : 1;
  const rootId = isDelegatedCredential(parent) ? parent.delegation.rootId : parent.agentId;

  const parentRemainingMs = parentExpiry.getTime() - now.getTime();
  const requestedMs = (request.ttlHours ?? DEFAULT_TTL_HOURS) * 60 * 60 * 1000;
  const childTtlMs = Math.min(requestedMs, parentRemainingMs);
  const childExpiry = new Date(now.getTime() + childTtlMs);

  const childKeyPair = generateAgentKeyPair();
  const childAgentId = ATLAS_DID_PREFIX + randomUUID();

  // Build base credential fields for hashing
  const partialNoDelegation: Omit<AgentCredential, "issuerSignature" | "credentialHash"> = {
    agentId: childAgentId,
    name: request.childName,
    role: request.childRole,
    issuedAt: now.toISOString(),
    expiresAt: childExpiry.toISOString(),
    publicKey: childKeyPair.publicKey,
    capabilities: [...request.capabilities],
    version: CREDENTIAL_VERSION,
    revoked: false,
  };

  const baseCanonical = buildCanonicalPayload(partialNoDelegation);
  const baseCredentialHash = createHash("sha3-256").update(baseCanonical).digest("hex");

  // Chain signature binds actual delegated authority (capabilities, expiry, depth, credential hash)
  const authorityPayload = buildDelegationAuthority({
    rootId,
    parentId: parent.agentId,
    childId: childAgentId,
    capabilities: request.capabilities,
    expiresAt: childExpiry.toISOString(),
    depth,
    childCredentialHash: baseCredentialHash,
  });
  const chainMessageBytes = new Uint8Array(Buffer.from(authorityPayload));
  const chainSigBytes = _ml_dsa65.sign(parentSecretKey, chainMessageBytes);
  const chainSignature = Buffer.from(chainSigBytes).toString("base64");

  const partial: Omit<AgentCredential, "issuerSignature" | "credentialHash"> & {
    delegated: true;
    delegation: DelegationChain;
  } = {
    ...partialNoDelegation,
    delegated: true,
    delegation: { rootId, parentId: parent.agentId, depth, chainSignature },
  };

  const canonicalPayload = buildCanonicalPayload(partial);
  const credentialHash = createHash("sha3-256").update(canonicalPayload).digest("hex");
  const payloadBytes = new Uint8Array(Buffer.from(canonicalPayload));
  const signatureBytes = _ml_dsa65.sign(issuerSecretKey, payloadBytes);
  const issuerSignature = Buffer.from(signatureBytes).toString("base64");

  return {
    credential: { ...partial, issuerSignature, credentialHash },
    childSecretKey: Buffer.from(childKeyPair.secretKey, "hex"),
  };
}

/**
 * Verify the full delegation chain: credential signature, chain signature,
 * parent validity, and recursive parent chain verification.
 */
export function verifyDelegationChain(
  credential: DelegatedCredential,
  registry: { get(id: string): AgentCredential | undefined },
  issuerPublicKey: Uint8Array
): CredentialVerifyResult {
  if (!_ml_dsa65) {
    return { valid: false, reason: "Agent identity not initialized" };
  }

  // Step 1: verify the credential itself (signature, expiry, revocation)
  const baseResult = verifyCredential(credential, issuerPublicKey);
  if (!baseResult.valid) {
    return baseResult;
  }

  // Step 2: verify chain signature against parent's public key
  const parent = registry.get(credential.delegation.parentId);
  if (!parent) {
    return {
      valid: false,
      agentId: credential.agentId,
      reason: "Delegation parent not found in registry",
    };
  }

  if (parent.revoked) {
    return {
      valid: false,
      agentId: credential.agentId,
      reason: "Delegation parent has been revoked",
      revoked: true,
    };
  }

  // Reconstruct the canonical delegation authority and verify chain signature
  // Build base credential hash (without delegation fields) for authority binding
  const { issuerSignature: _is, credentialHash: _ch, delegated: _d, delegation: _del, ...baseFields } = credential;
  const baseCanonical = buildCanonicalPayload(baseFields);
  const baseHash = createHash("sha3-256").update(baseCanonical).digest("hex");

  const authorityPayload = buildDelegationAuthority({
    rootId: credential.delegation.rootId,
    parentId: credential.delegation.parentId,
    childId: credential.agentId,
    capabilities: credential.capabilities,
    expiresAt: credential.expiresAt,
    depth: credential.delegation.depth,
    childCredentialHash: baseHash,
  });
  const chainMessageBytes = new Uint8Array(Buffer.from(authorityPayload));
  const chainSigBytes = new Uint8Array(
    Buffer.from(credential.delegation.chainSignature, "base64")
  );

  try {
    const parentPubKey = new Uint8Array(Buffer.from(parent.publicKey, "hex"));
    const chainValid = _ml_dsa65.verify(
      parentPubKey,
      chainMessageBytes,
      chainSigBytes
    );
    if (!chainValid) {
      return {
        valid: false,
        agentId: credential.agentId,
        reason: "Delegation chain signature invalid",
      };
    }
  } catch {
    return {
      valid: false,
      agentId: credential.agentId,
      reason: "Delegation chain signature verification failed — malformed signature",
    };
  }

  // Step 3: if parent is also delegated, recursively verify its chain
  if (isDelegatedCredential(parent)) {
    const parentResult = verifyDelegationChain(parent, registry, issuerPublicKey);
    if (!parentResult.valid) {
      return {
        valid: false,
        agentId: credential.agentId,
        reason: `Parent chain invalid: ${parentResult.reason}`,
      };
    }
  }

  return {
    valid: true,
    agentId: credential.agentId,
    expired: false,
    revoked: false,
  };
}

/**
 * Cascade-revoke all credentials delegated from a parent. Walks the
 * delegation tree depth-first, revoking every descendant.
 * Returns an array of all revoked agentIds.
 */
export function cascadeRevoke(
  parentAgentId: string,
  reason: string,
  registry: {
    get(id: string): AgentCredential | undefined;
    list(filter?: string): AgentCredential[];
  }
): string[] {
  const revoked: string[] = [];

  // Find all credentials whose delegation.parentId matches
  const children = registry.list().filter(
    (cred): cred is DelegatedCredential =>
      isDelegatedCredential(cred) && cred.delegation.parentId === parentAgentId
  );

  for (const child of children) {
    // Recursively cascade before revoking this child
    const descendantIds = cascadeRevoke(child.agentId, reason, registry);
    revoked.push(...descendantIds);

    // Revoke this child in-place (mutate the registry's object)
    child.revoked = true;
    child.revokedAt = new Date().toISOString();
    child.revokedReason = reason;
    revoked.push(child.agentId);
  }

  return revoked;
}
