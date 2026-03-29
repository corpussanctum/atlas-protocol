/**
 * Tests for Atlas Protocol — Attestation Layer (v0.5.0)
 *
 * Covers: attestAgent deny paths, capability checking, bootstrap guard,
 * enrichAuditEntry, and full flow integration.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { QuantumSigner } from "../src/quantum-signer.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import { attestAgent, enrichAuditEntry, toolToCapability } from "../src/attestation.js";
import type { AuditEntry } from "../src/audit-log.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-attest-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
  tempDirs = [];
});

async function createRegistry(): Promise<IdentityRegistry> {
  const dir = makeTempDir();
  const signer = await QuantumSigner.create(dir);
  return IdentityRegistry.create(dir, signer);
}

function makeBaseEntry(): AuditEntry {
  return {
    id: "test-entry-001",
    timestamp: new Date().toISOString(),
    event: "POLICY_DENY",
    hash_algorithm: "sha3-256",
    prev_hash: "GENESIS",
    verdict: "deny",
  };
}

// ---------------------------------------------------------------------------
// attestAgent — deny paths
// ---------------------------------------------------------------------------

describe("Attestation — deny paths", () => {
  it("returns bootstrap pass when registry is empty", async () => {
    const registry = await createRegistry();
    const result = attestAgent(registry, undefined);

    assert.equal(result.identityVerified, false);
    assert.equal(result.agentId, "bootstrap");
    assert.equal(result.denyReason, undefined, "Bootstrap should not deny");
  });

  it("returns UNREGISTERED_AGENT when agentId is undefined and registry has entries", async () => {
    const registry = await createRegistry();
    registry.register({ name: "existing", role: "claude-code", capabilities: [] });

    const result = attestAgent(registry, undefined);
    assert.equal(result.denyReason, "UNREGISTERED_AGENT");
    assert.equal(result.identityVerified, false);
  });

  it("returns UNREGISTERED_AGENT for unknown agentId", async () => {
    const registry = await createRegistry();
    registry.register({ name: "existing", role: "claude-code", capabilities: [] });

    const result = attestAgent(registry, "did:atlas:unknown-agent");
    assert.equal(result.denyReason, "UNREGISTERED_AGENT");
  });

  it("returns CREDENTIAL_EXPIRED for expired credential", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "soon-expired",
      role: "observer",
      capabilities: [],
      ttlHours: 0,
    });
    // Force expiry by directly mutating (test helper — not production code)
    const stored = registry.get(cred.agentId)!;
    (stored as any).expiresAt = new Date(Date.now() - 1000).toISOString();

    const result = attestAgent(registry, cred.agentId);
    assert.equal(result.denyReason, "CREDENTIAL_EXPIRED");
    assert.equal(result.identityVerified, false);
  });

  it("returns CREDENTIAL_REVOKED for revoked credential", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "revoke-target",
      role: "tool-caller",
      capabilities: ["shell:exec"],
    });
    registry.revoke(cred.agentId, "Security incident");

    const result = attestAgent(registry, cred.agentId);
    assert.equal(result.denyReason, "CREDENTIAL_REVOKED");
    assert.equal(result.identityVerified, false);
  });

  it("returns CAPABILITY_MISMATCH when required cap not present", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "limited-agent",
      role: "observer",
      capabilities: ["file:read", "audit:read"],
    });

    const result = attestAgent(registry, cred.agentId, "shell:exec");
    assert.equal(result.denyReason, "CAPABILITY_MISMATCH");
    assert.equal(result.identityVerified, false);
  });
});

// ---------------------------------------------------------------------------
// attestAgent — pass paths
// ---------------------------------------------------------------------------

describe("Attestation — pass paths", () => {
  it("returns identityVerified: true for valid credential with capability", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "capable-agent",
      role: "claude-code",
      capabilities: ["file:read", "shell:exec", "file:write"],
    });

    const result = attestAgent(registry, cred.agentId, "shell:exec");
    assert.equal(result.identityVerified, true);
    assert.equal(result.denyReason, undefined);
    assert.equal(result.agentId, cred.agentId);
    assert.equal(result.role, "claude-code");
    assert.deepEqual(result.capabilities, ["file:read", "shell:exec", "file:write"]);
  });

  it("returns identityVerified: true when no specific capability required", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "any-cap",
      role: "admin",
      capabilities: ["identity:register"],
    });

    const result = attestAgent(registry, cred.agentId);
    assert.equal(result.identityVerified, true);
    assert.equal(result.denyReason, undefined);
  });
});

// ---------------------------------------------------------------------------
// Tool → capability mapping
// ---------------------------------------------------------------------------

describe("Attestation — tool capability mapping", () => {
  it("maps Read to file:read", () => {
    assert.equal(toolToCapability("Read"), "file:read");
  });

  it("maps Write to file:write", () => {
    assert.equal(toolToCapability("Write"), "file:write");
  });

  it("maps Bash to shell:exec", () => {
    assert.equal(toolToCapability("Bash"), "shell:exec");
  });

  it("returns undefined for unknown tools", () => {
    assert.equal(toolToCapability("UnknownTool"), undefined);
  });
});

// ---------------------------------------------------------------------------
// enrichAuditEntry
// ---------------------------------------------------------------------------

describe("Attestation — enrichAuditEntry", () => {
  it("adds agentId to entry", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "enrich-test",
      role: "claude-code",
      capabilities: ["file:read"],
    });
    const attestation = attestAgent(registry, cred.agentId);
    const entry = enrichAuditEntry(makeBaseEntry(), attestation);

    assert.equal(entry.agentId, cred.agentId);
  });

  it("adds identityVerified to entry", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "verified-test",
      role: "claude-code",
      capabilities: [],
    });
    const attestation = attestAgent(registry, cred.agentId);
    const entry = enrichAuditEntry(makeBaseEntry(), attestation);

    assert.equal(entry.identityVerified, true);
  });

  it("adds credentialExpiry to entry", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "expiry-test",
      role: "observer",
      capabilities: [],
      ttlHours: 72,
    });
    const attestation = attestAgent(registry, cred.agentId);
    const entry = enrichAuditEntry(makeBaseEntry(), attestation);

    assert.ok(entry.credentialExpiry);
    assert.equal(entry.credentialExpiry, cred.expiresAt);
  });

  it("adds agentRole to entry", async () => {
    const registry = await createRegistry();
    const cred = registry.register({
      name: "role-test",
      role: "admin",
      capabilities: ["identity:register"],
    });
    const attestation = attestAgent(registry, cred.agentId);
    const entry = enrichAuditEntry(makeBaseEntry(), attestation);

    assert.equal(entry.agentRole, "admin");
  });

  it("adds attestationDenyReason when denied", async () => {
    const registry = await createRegistry();
    registry.register({ name: "blocker", role: "claude-code", capabilities: [] });

    const attestation = attestAgent(registry, "did:atlas:unknown");
    const entry = enrichAuditEntry(makeBaseEntry(), attestation);

    assert.equal(entry.attestationDenyReason, "UNREGISTERED_AGENT");
    assert.equal(entry.identityVerified, false);
  });
});

// ---------------------------------------------------------------------------
// Full flow
// ---------------------------------------------------------------------------

describe("Attestation — full flow", () => {
  it("register → attest → enrich → verify audit entry has identity fields", async () => {
    const registry = await createRegistry();

    // Step 1: Register agent
    const cred = registry.register({
      name: "full-flow-agent",
      role: "claude-code",
      capabilities: ["file:read", "shell:exec"],
      ttlHours: 48,
    });

    // Step 2: Attest the agent for a Bash request
    const attestation = attestAgent(registry, cred.agentId, "shell:exec");
    assert.equal(attestation.identityVerified, true);
    assert.equal(attestation.denyReason, undefined);

    // Step 3: Enrich audit entry
    const entry = enrichAuditEntry(makeBaseEntry(), attestation);

    // Step 4: Verify all identity fields present
    assert.equal(entry.agentId, cred.agentId);
    assert.equal(entry.identityVerified, true);
    assert.equal(entry.credentialExpiry, cred.expiresAt);
    assert.equal(entry.agentRole, "claude-code");
    assert.equal(entry.attestationDenyReason, undefined);

    // Step 5: Verify credential is valid in registry
    const verifyResult = registry.verify(cred.agentId);
    assert.equal(verifyResult.valid, true);
  });
});
