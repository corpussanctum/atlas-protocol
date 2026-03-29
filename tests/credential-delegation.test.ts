/**
 * Tests for Atlas Protocol — Credential Delegation (v0.6.0)
 *
 * Covers: validateDelegation, isDelegatedCredential, registry.delegate(),
 * registry.getChildren(), registry.getDescendants(), registry.cascadeRevoke(),
 * children index persistence, and delegated credential list filter.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { QuantumSigner } from "../src/quantum-signer.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import {
  isDelegatedCredential,
  validateDelegation,
} from "../src/agent-identity.js";
import type {
  AgentCredential,
  DelegatedCredential,
  DelegationRequest,
  DelegationChain,
  AgentCapability,
} from "../src/agent-identity.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-delegation-test-"));
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

/**
 * Build a mock AgentCredential for validateDelegation tests.
 * Not cryptographically valid — only used with the mock registry.
 */
function mockCredential(overrides: Partial<AgentCredential> = {}): AgentCredential {
  const now = new Date();
  return {
    agentId: overrides.agentId ?? "did:atlas:mock-parent",
    name: overrides.name ?? "mock-agent",
    role: overrides.role ?? "claude-code",
    issuedAt: overrides.issuedAt ?? now.toISOString(),
    expiresAt: overrides.expiresAt ?? new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString(),
    publicKey: overrides.publicKey ?? "aabbcc",
    capabilities: overrides.capabilities ?? ["file:read", "shell:exec"] as AgentCapability[],
    issuerSignature: overrides.issuerSignature ?? "sig",
    credentialHash: overrides.credentialHash ?? "hash",
    version: overrides.version ?? "0.5.0",
    revoked: overrides.revoked ?? false,
    revokedAt: overrides.revokedAt,
    revokedReason: overrides.revokedReason,
    ...("delegated" in overrides ? { delegated: (overrides as DelegatedCredential).delegated } : {}),
    ...("delegation" in overrides ? { delegation: (overrides as DelegatedCredential).delegation } : {}),
  } as AgentCredential;
}

function mockDelegatedCredential(
  depth: number,
  overrides: Partial<AgentCredential> = {}
): DelegatedCredential {
  const base = mockCredential(overrides);
  return {
    ...base,
    delegated: true,
    delegation: {
      rootId: "did:atlas:root",
      parentId: "did:atlas:mock-parent",
      depth,
      chainSignature: "chainsig",
    },
  } as DelegatedCredential;
}

function mockRegistry(credentials: Map<string, AgentCredential>) {
  return {
    get(id: string): AgentCredential | undefined {
      return credentials.get(id);
    },
  };
}

// ---------------------------------------------------------------------------
// validateDelegation
// ---------------------------------------------------------------------------

describe("validateDelegation", () => {
  it("returns valid for legitimate subset request", () => {
    const parent = mockCredential({
      agentId: "did:atlas:parent-1",
      capabilities: ["file:read", "shell:exec"],
    });
    const reg = mockRegistry(new Map([["did:atlas:parent-1", parent]]));

    const result = validateDelegation(
      {
        parentAgentId: "did:atlas:parent-1",
        childName: "child",
        childRole: "observer",
        capabilities: ["file:read"],
      },
      reg
    );

    assert.equal(result.valid, true);
    assert.equal(result.reason, undefined);
  });

  it("rejects CAPABILITY_ESCALATION when child has capability parent lacks", () => {
    const parent = mockCredential({
      agentId: "did:atlas:parent-2",
      capabilities: ["file:read"],
    });
    const reg = mockRegistry(new Map([["did:atlas:parent-2", parent]]));

    const result = validateDelegation(
      {
        parentAgentId: "did:atlas:parent-2",
        childName: "child",
        childRole: "tool-caller",
        capabilities: ["file:read", "shell:exec"],
      },
      reg
    );

    assert.equal(result.valid, false);
    assert.equal(result.reason, "CAPABILITY_ESCALATION");
  });

  it("rejects DEPTH_EXCEEDED when depth > 3", () => {
    const parent = mockDelegatedCredential(3, {
      agentId: "did:atlas:deep-parent",
      capabilities: ["file:read"],
    });
    const reg = mockRegistry(new Map([["did:atlas:deep-parent", parent]]));

    const result = validateDelegation(
      {
        parentAgentId: "did:atlas:deep-parent",
        childName: "child",
        childRole: "observer",
        capabilities: ["file:read"],
      },
      reg
    );

    assert.equal(result.valid, false);
    assert.equal(result.reason, "DEPTH_EXCEEDED");
  });

  it("rejects TTL_EXCEEDS_PARENT when child outlives parent", () => {
    const parentExpiry = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours
    const parent = mockCredential({
      agentId: "did:atlas:short-parent",
      expiresAt: parentExpiry.toISOString(),
      capabilities: ["file:read"],
    });
    const reg = mockRegistry(new Map([["did:atlas:short-parent", parent]]));

    const result = validateDelegation(
      {
        parentAgentId: "did:atlas:short-parent",
        childName: "child",
        childRole: "observer",
        capabilities: ["file:read"],
        ttlHours: 10, // 10 hours > 2 hours remaining
      },
      reg
    );

    assert.equal(result.valid, false);
    assert.equal(result.reason, "TTL_EXCEEDS_PARENT");
  });

  it("rejects PARENT_EXPIRED when parent has expired", () => {
    const parent = mockCredential({
      agentId: "did:atlas:expired-parent",
      expiresAt: new Date(Date.now() - 1000).toISOString(), // 1 second ago
      capabilities: ["file:read"],
    });
    const reg = mockRegistry(new Map([["did:atlas:expired-parent", parent]]));

    const result = validateDelegation(
      {
        parentAgentId: "did:atlas:expired-parent",
        childName: "child",
        childRole: "observer",
        capabilities: ["file:read"],
      },
      reg
    );

    assert.equal(result.valid, false);
    assert.equal(result.reason, "PARENT_EXPIRED");
  });

  it("rejects PARENT_REVOKED when parent is revoked", () => {
    const parent = mockCredential({
      agentId: "did:atlas:revoked-parent",
      revoked: true,
      revokedReason: "Compromised",
      capabilities: ["file:read"],
    });
    const reg = mockRegistry(new Map([["did:atlas:revoked-parent", parent]]));

    const result = validateDelegation(
      {
        parentAgentId: "did:atlas:revoked-parent",
        childName: "child",
        childRole: "observer",
        capabilities: ["file:read"],
      },
      reg
    );

    assert.equal(result.valid, false);
    assert.equal(result.reason, "PARENT_REVOKED");
  });

  it("rejects PARENT_NOT_FOUND when parent does not exist", () => {
    const reg = mockRegistry(new Map());

    const result = validateDelegation(
      {
        parentAgentId: "did:atlas:nonexistent",
        childName: "child",
        childRole: "observer",
        capabilities: ["file:read"],
      },
      reg
    );

    assert.equal(result.valid, false);
    assert.equal(result.reason, "PARENT_NOT_FOUND");
  });
});

// ---------------------------------------------------------------------------
// isDelegatedCredential
// ---------------------------------------------------------------------------

describe("isDelegatedCredential", () => {
  it("returns true for delegated credential", () => {
    const cred = mockDelegatedCredential(1);
    assert.equal(isDelegatedCredential(cred), true);
  });

  it("returns false for root credential", () => {
    const cred = mockCredential();
    assert.equal(isDelegatedCredential(cred), false);
  });
});

// ---------------------------------------------------------------------------
// registry.delegate()
// ---------------------------------------------------------------------------

describe("IdentityRegistry — delegate()", () => {
  it("returns DelegatedCredential with delegated:true", async () => {
    const { registry } = await createRegistry();
    const parent = registry.register({
      name: "parent-agent",
      role: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });

    const child = registry.delegate({
      parentAgentId: parent.agentId,
      childName: "child-agent",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    assert.equal(child.delegated, true);
    assert.ok(isDelegatedCredential(child));
    assert.equal(child.name, "child-agent");
    assert.equal(child.role, "observer");
    assert.deepEqual(child.capabilities, ["file:read"]);
  });

  it("sets correct depth (parent.depth + 1)", async () => {
    const { registry } = await createRegistry();
    const root = registry.register({
      name: "root-agent",
      role: "admin",
      capabilities: ["file:read", "shell:exec"],
    });

    const child1 = registry.delegate({
      parentAgentId: root.agentId,
      childName: "child-1",
      childRole: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });

    assert.equal(child1.delegation.depth, 1);

    const child2 = registry.delegate({
      parentAgentId: child1.agentId,
      childName: "child-2",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    assert.equal(child2.delegation.depth, 2);
  });

  it("caps TTL at parent remaining time", async () => {
    const { registry } = await createRegistry();
    // Register parent with a 2-hour TTL
    const parent = registry.register({
      name: "short-lived-parent",
      role: "claude-code",
      capabilities: ["file:read"],
      ttlHours: 2,
    });

    // Request child with 24-hour TTL (should be capped at ~2 hours)
    const child = registry.delegate({
      parentAgentId: parent.agentId,
      childName: "child-agent",
      childRole: "observer",
      capabilities: ["file:read"],
      ttlHours: 24,
    });

    const parentExpiry = new Date(parent.expiresAt).getTime();
    const childExpiry = new Date(child.expiresAt).getTime();

    // Child expiry should not exceed parent expiry
    assert.ok(
      childExpiry <= parentExpiry,
      `Child expiry (${child.expiresAt}) should not exceed parent (${parent.expiresAt})`
    );
  });

  it("rejects capability escalation", async () => {
    const { registry } = await createRegistry();
    const parent = registry.register({
      name: "limited-parent",
      role: "observer",
      capabilities: ["file:read"],
    });

    assert.throws(
      () =>
        registry.delegate({
          parentAgentId: parent.agentId,
          childName: "escalating-child",
          childRole: "tool-caller",
          capabilities: ["file:read", "shell:exec"],
        }),
      /CAPABILITY_ESCALATION/
    );
  });
});

// ---------------------------------------------------------------------------
// registry.getChildren() and registry.getDescendants()
// ---------------------------------------------------------------------------

describe("IdentityRegistry — getChildren()", () => {
  it("returns direct children only", async () => {
    const { registry } = await createRegistry();
    const root = registry.register({
      name: "root",
      role: "admin",
      capabilities: ["file:read", "shell:exec"],
    });

    const child1 = registry.delegate({
      parentAgentId: root.agentId,
      childName: "child-1",
      childRole: "claude-code",
      capabilities: ["file:read"],
    });

    const child2 = registry.delegate({
      parentAgentId: root.agentId,
      childName: "child-2",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    // grandchild of root, child of child1
    registry.delegate({
      parentAgentId: child1.agentId,
      childName: "grandchild-1",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    const children = registry.getChildren(root.agentId);
    assert.equal(children.length, 2);
    const childIds = children.map((c) => c.agentId);
    assert.ok(childIds.includes(child1.agentId));
    assert.ok(childIds.includes(child2.agentId));
  });
});

describe("IdentityRegistry — getDescendants()", () => {
  it("returns full subtree", async () => {
    const { registry } = await createRegistry();
    const root = registry.register({
      name: "root",
      role: "admin",
      capabilities: ["file:read", "shell:exec"],
    });

    const child1 = registry.delegate({
      parentAgentId: root.agentId,
      childName: "child-1",
      childRole: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });

    const child2 = registry.delegate({
      parentAgentId: root.agentId,
      childName: "child-2",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    const grandchild = registry.delegate({
      parentAgentId: child1.agentId,
      childName: "grandchild-1",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    const descendants = registry.getDescendants(root.agentId);
    assert.equal(descendants.length, 3);
    const ids = descendants.map((c) => c.agentId);
    assert.ok(ids.includes(child1.agentId));
    assert.ok(ids.includes(child2.agentId));
    assert.ok(ids.includes(grandchild.agentId));
  });
});

// ---------------------------------------------------------------------------
// registry.cascadeRevoke()
// ---------------------------------------------------------------------------

describe("IdentityRegistry — cascadeRevoke()", () => {
  it("revokes direct children", async () => {
    const { registry } = await createRegistry();
    const root = registry.register({
      name: "root",
      role: "admin",
      capabilities: ["file:read"],
    });

    const child1 = registry.delegate({
      parentAgentId: root.agentId,
      childName: "child-1",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    const child2 = registry.delegate({
      parentAgentId: root.agentId,
      childName: "child-2",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    registry.cascadeRevoke(root.agentId, "Compromised root");

    const c1 = registry.get(child1.agentId)!;
    const c2 = registry.get(child2.agentId)!;
    assert.equal(c1.revoked, true);
    assert.equal(c1.revokedReason, "Compromised root");
    assert.equal(c2.revoked, true);
  });

  it("revokes all descendants (3 levels deep)", async () => {
    const { registry } = await createRegistry();
    const root = registry.register({
      name: "root",
      role: "admin",
      capabilities: ["file:read", "shell:exec"],
    });

    const child = registry.delegate({
      parentAgentId: root.agentId,
      childName: "level-1",
      childRole: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });

    const grandchild = registry.delegate({
      parentAgentId: child.agentId,
      childName: "level-2",
      childRole: "claude-code",
      capabilities: ["file:read"],
    });

    const greatGrandchild = registry.delegate({
      parentAgentId: grandchild.agentId,
      childName: "level-3",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    registry.cascadeRevoke(root.agentId, "Full cascade");

    assert.equal(registry.get(child.agentId)!.revoked, true);
    assert.equal(registry.get(grandchild.agentId)!.revoked, true);
    assert.equal(registry.get(greatGrandchild.agentId)!.revoked, true);
  });

  it("returns all revoked IDs", async () => {
    const { registry } = await createRegistry();
    const root = registry.register({
      name: "root",
      role: "admin",
      capabilities: ["file:read", "shell:exec"],
    });

    const child = registry.delegate({
      parentAgentId: root.agentId,
      childName: "child",
      childRole: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });

    const grandchild = registry.delegate({
      parentAgentId: child.agentId,
      childName: "grandchild",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    const revokedIds = registry.cascadeRevoke(root.agentId, "Revoke all");

    assert.equal(revokedIds.length, 2);
    assert.ok(revokedIds.includes(child.agentId));
    assert.ok(revokedIds.includes(grandchild.agentId));
  });
});

// ---------------------------------------------------------------------------
// Depth chain: root -> child1 -> child2 -> child3 -> child4 (should fail)
// ---------------------------------------------------------------------------

describe("IdentityRegistry — depth limit enforcement", () => {
  it("rejects delegation beyond max depth (3 levels)", async () => {
    const { registry } = await createRegistry();

    const root = registry.register({
      name: "root",
      role: "admin",
      capabilities: ["file:read", "shell:exec"],
    });

    const child1 = registry.delegate({
      parentAgentId: root.agentId,
      childName: "depth-1",
      childRole: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });
    assert.equal(child1.delegation.depth, 1);

    const child2 = registry.delegate({
      parentAgentId: child1.agentId,
      childName: "depth-2",
      childRole: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });
    assert.equal(child2.delegation.depth, 2);

    const child3 = registry.delegate({
      parentAgentId: child2.agentId,
      childName: "depth-3",
      childRole: "observer",
      capabilities: ["file:read"],
    });
    assert.equal(child3.delegation.depth, 3);

    // Depth 4 should fail
    assert.throws(
      () =>
        registry.delegate({
          parentAgentId: child3.agentId,
          childName: "depth-4",
          childRole: "observer",
          capabilities: ["file:read"],
        }),
      /DEPTH_EXCEEDED/
    );
  });
});

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

describe("IdentityRegistry — delegation persistence", () => {
  it("delegate() persists children index to disk", async () => {
    const { registry, dir } = await createRegistry();
    const parent = registry.register({
      name: "persist-parent",
      role: "admin",
      capabilities: ["file:read"],
    });

    const child = registry.delegate({
      parentAgentId: parent.agentId,
      childName: "persist-child",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    const filePath = join(dir, "identity-registry.json");
    assert.ok(existsSync(filePath), "Registry file should exist");

    const content = JSON.parse(readFileSync(filePath, "utf-8"));
    assert.ok(content.children, "Children index should be persisted");
    assert.ok(
      content.children[parent.agentId],
      "Parent should have children entry"
    );
    assert.ok(
      content.children[parent.agentId].includes(child.agentId),
      "Child ID should be in parent's children list"
    );
  });
});

// ---------------------------------------------------------------------------
// Delegated credential list filter
// ---------------------------------------------------------------------------

describe("IdentityRegistry — delegated list filter", () => {
  it("list('delegated') returns only delegated credentials", async () => {
    const { registry } = await createRegistry();
    const root = registry.register({
      name: "root",
      role: "admin",
      capabilities: ["file:read"],
    });

    const child = registry.delegate({
      parentAgentId: root.agentId,
      childName: "delegated-child",
      childRole: "observer",
      capabilities: ["file:read"],
    });

    const delegated = registry.list("delegated");
    assert.equal(delegated.length, 1);
    assert.equal(delegated[0].agentId, child.agentId);
    assert.ok(isDelegatedCredential(delegated[0]));

    // Root should not appear in delegated filter
    const all = registry.list("all");
    assert.equal(all.length, 2);
  });
});
