/**
 * Tests for Fidelis Channel — Identity Registry (v0.5.0)
 *
 * Covers: registration, lookup, verification, revocation, filtering,
 * file persistence, and bootstrap detection.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { QuantumSigner } from "../src/quantum-signer.js";
import { IdentityRegistry } from "../src/identity-registry.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "fidelis-registry-test-"));
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

async function createRegistry(): Promise<{ registry: IdentityRegistry; dir: string }> {
  const dir = makeTempDir();
  const signer = await QuantumSigner.create(dir);
  const registry = await IdentityRegistry.create(dir, signer);
  return { registry, dir };
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

describe("IdentityRegistry — registration", () => {
  it("register returns a valid credential", async () => {
    const { registry } = await createRegistry();
    const cred = registry.register({
      name: "test-agent",
      role: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });

    assert.ok(cred.agentId.startsWith("did:fidelis:"));
    assert.equal(cred.name, "test-agent");
    assert.equal(cred.role, "claude-code");
    assert.equal(cred.revoked, false);
    assert.ok(cred.issuerSignature);
    assert.ok(cred.credentialHash);
  });

  it("register auto-saves to disk", async () => {
    const { registry, dir } = await createRegistry();
    registry.register({
      name: "persist-test",
      role: "observer",
      capabilities: [],
    });

    const filePath = join(dir, "identity-registry.json");
    assert.ok(existsSync(filePath), "Registry file should exist");

    const content = JSON.parse(readFileSync(filePath, "utf-8"));
    assert.equal(content.length, 1);
    assert.equal(content[0].name, "persist-test");
  });
});

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

describe("IdentityRegistry — lookup", () => {
  it("get returns credential by agentId", async () => {
    const { registry } = await createRegistry();
    const cred = registry.register({
      name: "lookup-agent",
      role: "admin",
      capabilities: ["identity:register"],
    });

    const found = registry.get(cred.agentId);
    assert.ok(found);
    assert.equal(found!.agentId, cred.agentId);
    assert.equal(found!.name, "lookup-agent");
  });

  it("get returns undefined for unknown agentId", async () => {
    const { registry } = await createRegistry();
    const found = registry.get("did:fidelis:nonexistent");
    assert.equal(found, undefined);
  });
});

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

describe("IdentityRegistry — verification", () => {
  it("verify returns valid: true for active credential", async () => {
    const { registry } = await createRegistry();
    const cred = registry.register({
      name: "verify-me",
      role: "claude-code",
      capabilities: ["file:read"],
    });

    const result = registry.verify(cred.agentId);
    assert.equal(result.valid, true, `Should be valid: ${result.reason}`);
    assert.equal(result.agentId, cred.agentId);
  });

  it("verify returns valid: false for unknown agent", async () => {
    const { registry } = await createRegistry();
    const result = registry.verify("did:fidelis:unknown");
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("not found"));
  });
});

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

describe("IdentityRegistry — revocation", () => {
  it("revoke sets revoked: true", async () => {
    const { registry } = await createRegistry();
    const cred = registry.register({
      name: "revoke-me",
      role: "tool-caller",
      capabilities: ["shell:exec"],
    });

    const success = registry.revoke(cred.agentId, "Compromised");
    assert.equal(success, true);

    const revoked = registry.get(cred.agentId);
    assert.equal(revoked!.revoked, true);
    assert.equal(revoked!.revokedReason, "Compromised");
  });

  it("revoke returns false for unknown agent", async () => {
    const { registry } = await createRegistry();
    const success = registry.revoke("did:fidelis:unknown", "test");
    assert.equal(success, false);
  });

  it("verify returns revoked: true after revocation", async () => {
    const { registry } = await createRegistry();
    const cred = registry.register({
      name: "verify-revoked",
      role: "observer",
      capabilities: [],
    });
    registry.revoke(cred.agentId, "Done");

    const result = registry.verify(cred.agentId);
    assert.equal(result.valid, false);
    assert.equal(result.revoked, true);
  });
});

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

describe("IdentityRegistry — filtering", () => {
  it("list('active') excludes revoked credentials", async () => {
    const { registry } = await createRegistry();
    const c1 = registry.register({ name: "active-1", role: "claude-code", capabilities: [] });
    const c2 = registry.register({ name: "revoked-1", role: "observer", capabilities: [] });
    registry.revoke(c2.agentId, "Test");

    const active = registry.list("active");
    assert.equal(active.length, 1);
    assert.equal(active[0].agentId, c1.agentId);
  });

  it("list('revoked') returns only revoked credentials", async () => {
    const { registry } = await createRegistry();
    registry.register({ name: "active-1", role: "claude-code", capabilities: [] });
    const c2 = registry.register({ name: "revoked-1", role: "observer", capabilities: [] });
    registry.revoke(c2.agentId, "Test");

    const revoked = registry.list("revoked");
    assert.equal(revoked.length, 1);
    assert.equal(revoked[0].agentId, c2.agentId);
  });

  it("list('all') returns everything", async () => {
    const { registry } = await createRegistry();
    registry.register({ name: "a1", role: "claude-code", capabilities: [] });
    const c2 = registry.register({ name: "a2", role: "observer", capabilities: [] });
    registry.revoke(c2.agentId, "Test");

    const all = registry.list("all");
    assert.equal(all.length, 2);
  });
});

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

describe("IdentityRegistry — persistence", () => {
  it("registry persists to disk and reloads correctly", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir);

    // Create registry and register an agent
    const registry1 = await IdentityRegistry.create(dir, signer);
    const cred = registry1.register({
      name: "persist-agent",
      role: "admin",
      capabilities: ["identity:register", "identity:revoke"],
    });

    // Create a new registry instance from the same directory
    const registry2 = await IdentityRegistry.create(dir, signer);
    const found = registry2.get(cred.agentId);

    assert.ok(found, "Should reload credential from disk");
    assert.equal(found!.name, "persist-agent");
    assert.equal(found!.role, "admin");
    assert.deepEqual(found!.capabilities, ["identity:register", "identity:revoke"]);
  });

  it("isEmpty returns true for fresh registry", async () => {
    const { registry } = await createRegistry();
    assert.equal(registry.isEmpty(), true);
  });

  it("isEmpty returns false after registration", async () => {
    const { registry } = await createRegistry();
    registry.register({ name: "first", role: "claude-code", capabilities: [] });
    assert.equal(registry.isEmpty(), false);
  });
});
