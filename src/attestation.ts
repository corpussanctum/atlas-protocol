/**
 * Atlas Protocol — Attestation Layer (v0.5.0)
 *
 * Binds agent identity to audit entries and permission decisions.
 * This is the glue between the identity registry and the gatekeeper flow.
 *
 * Flow:
 *   1. attestAgent() — check if the requesting agent has a valid credential
 *   2. If attestation fails and registry is not empty → deny before policy eval
 *   3. enrichAuditEntry() — stamp identity fields onto the audit entry
 *
 * Bootstrap guard: if the registry is empty (no credentials issued yet),
 * attestation passes with identityVerified: false so the system is not
 * self-locking on first run.
 */

import type { IdentityRegistry } from "./identity-registry.js";
import type { AgentRole, AgentCapability, AgentCredential } from "./agent-identity.js";
import type { AuditEntry } from "./audit-log.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AttestationDenyReason =
  | "UNREGISTERED_AGENT"
  | "CREDENTIAL_EXPIRED"
  | "CREDENTIAL_REVOKED"
  | "CAPABILITY_MISMATCH";

export interface AttestationResult {
  agentId: string;
  identityVerified: boolean;
  credentialExpiry: string;
  role: AgentRole;
  capabilities: AgentCapability[];
  denyReason?: AttestationDenyReason;
}

// ---------------------------------------------------------------------------
// Tool name → capability mapping
// ---------------------------------------------------------------------------

const TOOL_CAPABILITY_MAP: Record<string, AgentCapability> = {
  Read: "file:read",
  Glob: "file:read",
  Grep: "file:read",
  Write: "file:write",
  Edit: "file:write",
  Bash: "shell:exec",
  Agent: "process:spawn",
  WebFetch: "network:outbound",
  WebSearch: "network:outbound",
};

/**
 * Map a Claude Code tool name to the required Atlas capability.
 * Returns undefined if no specific capability is required.
 */
export function toolToCapability(toolName: string): AgentCapability | undefined {
  return TOOL_CAPABILITY_MAP[toolName];
}

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

const BOOTSTRAP_RESULT: AttestationResult = {
  agentId: "bootstrap",
  identityVerified: false,
  credentialExpiry: "",
  role: "claude-code",
  capabilities: [],
};

/**
 * Attest an incoming agent request before policy evaluation.
 *
 * Returns an AttestationResult. The gatekeeper checks denyReason:
 *   - undefined → proceed to policy evaluation
 *   - set → deny immediately with audit entry
 *
 * Bootstrap guard: if the registry is empty, returns a pass with
 * identityVerified: false so first-run setup is not blocked.
 */
export function attestAgent(
  registry: IdentityRegistry,
  agentId: string | undefined,
  requiredCapability?: AgentCapability
): AttestationResult {
  // Bootstrap guard: empty registry → allow through unverified
  if (registry.isEmpty()) {
    return BOOTSTRAP_RESULT;
  }

  // No agent ID provided
  if (!agentId) {
    return {
      ...BOOTSTRAP_RESULT,
      denyReason: "UNREGISTERED_AGENT",
    };
  }

  // Look up the credential
  const credential = registry.get(agentId);
  if (!credential) {
    return {
      agentId,
      identityVerified: false,
      credentialExpiry: "",
      role: "claude-code",
      capabilities: [],
      denyReason: "UNREGISTERED_AGENT",
    };
  }

  // Check revocation
  if (credential.revoked) {
    return {
      agentId: credential.agentId,
      identityVerified: false,
      credentialExpiry: credential.expiresAt,
      role: credential.role,
      capabilities: credential.capabilities,
      denyReason: "CREDENTIAL_REVOKED",
    };
  }

  // Check expiry
  const now = new Date();
  if (new Date(credential.expiresAt) <= now) {
    return {
      agentId: credential.agentId,
      identityVerified: false,
      credentialExpiry: credential.expiresAt,
      role: credential.role,
      capabilities: credential.capabilities,
      denyReason: "CREDENTIAL_EXPIRED",
    };
  }

  // Check required capability
  if (requiredCapability && !credential.capabilities.includes(requiredCapability)) {
    return {
      agentId: credential.agentId,
      identityVerified: false,
      credentialExpiry: credential.expiresAt,
      role: credential.role,
      capabilities: credential.capabilities,
      denyReason: "CAPABILITY_MISMATCH",
    };
  }

  // All checks passed
  return {
    agentId: credential.agentId,
    identityVerified: true,
    credentialExpiry: credential.expiresAt,
    role: credential.role,
    capabilities: credential.capabilities,
  };
}

/**
 * Enrich an existing audit entry with identity fields.
 * Call after policy decision, before writing to audit log.
 */
export function enrichAuditEntry(
  entry: AuditEntry,
  attestation: AttestationResult
): AuditEntry {
  return {
    ...entry,
    agentId: attestation.agentId,
    identityVerified: attestation.identityVerified,
    credentialExpiry: attestation.credentialExpiry || undefined,
    agentRole: attestation.role,
    attestationDenyReason: attestation.denyReason,
  };
}

/**
 * Sanitize a credential for external display — strip issuerSignature
 * internals and any fields that should not be exposed via MCP tools.
 */
export function sanitizeCredential(
  credential: AgentCredential
): Omit<AgentCredential, "issuerSignature"> & { issuerSignature: string } {
  return {
    ...credential,
    // Truncate signature to a verification-friendly prefix
    issuerSignature: credential.issuerSignature.slice(0, 32) + "...",
  };
}
