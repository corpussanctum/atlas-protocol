/**
 * Tests for signer providers and restart-durable agent keys (#4).
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { verifyDelegationChain, type DelegatedCredential } from "../src/agent-identity.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import { loadMlDsa } from "../src/operator-key.js";
import { QuantumSigner } from "../src/quantum-signer.js";
import { AGENT_KEYS_DIR, AgentKeyStore, EphemeralSigner } from "../src/signer-provider.js";

const PASS = "keystore passphrase for tests";
const MSG = new TextEncoder().encode("atlas");

describe("signer providers", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "atlas-keystore-")); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const keyFiles = () => readdirSync(join(dir, AGENT_KEYS_DIR)).filter((f) => f !== "keystore.json");
  async function keypair() {
    const dsa = await loadMlDsa();
    return { dsa, ...dsa.keygen(randomBytes(32)) };
  }

  it("EphemeralSigner signs verifiably and is not durable", async () => {
    const { dsa, publicKey, secretKey } = await keypair();
    const signer = new EphemeralSigner(dsa, secretKey, publicKey);
    assert.equal(signer.capabilities.durable, false);
    assert.ok(dsa.verify(signer.publicKey(), MSG, signer.sign(MSG)));
  });

  it("without a passphrase, keys are in memory only", async () => {
    const store = await AgentKeyStore.open(dir, undefined);
    assert.deepEqual(store.mode, { durable: false, reason: "NO_PASSPHRASE" });
    const { publicKey, secretKey } = await keypair();
    store.adopt("did:atlas:a", secretKey, publicKey);
    assert.ok(store.get("did:atlas:a"));
    assert.equal(existsSync(join(dir, AGENT_KEYS_DIR)), false);
    assert.equal((await AgentKeyStore.open(dir, undefined)).get("did:atlas:a"), undefined);
  });

  it("with a passphrase, keys are wrapped at rest and reload after a restart", async () => {
    const { dsa, publicKey, secretKey } = await keypair();
    const secretHex = Buffer.from(secretKey).toString("hex");
    const secretB64 = Buffer.from(secretKey).toString("base64");
    const store = await AgentKeyStore.open(dir, PASS);
    assert.deepEqual(store.mode, { durable: true });
    store.adopt("did:atlas:a", secretKey, publicKey);
    assert.ok(secretKey.every((b) => b === 0), "caller's copy is zeroed");

    const [file] = keyFiles();
    const raw = readFileSync(join(dir, AGENT_KEYS_DIR, file), "utf-8");
    assert.ok(!raw.includes(secretHex) && !raw.includes(secretB64), "secret key stored in the clear");
    assert.equal(statSync(join(dir, AGENT_KEYS_DIR, file)).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, AGENT_KEYS_DIR)).mode & 0o777, 0o700);

    const reopened = await AgentKeyStore.open(dir, PASS);
    const signer = reopened.get("did:atlas:a");
    assert.ok(signer?.capabilities.durable);
    assert.ok(dsa.verify(publicKey, MSG, signer!.sign(MSG)));
  });

  it("a wrong passphrase degrades to in-memory and leaves stored keys untouched", async () => {
    const { publicKey, secretKey } = await keypair();
    (await AgentKeyStore.open(dir, PASS)).adopt("did:atlas:a", secretKey, publicKey);
    const before = keyFiles();
    const wrong = await AgentKeyStore.open(dir, "not the right passphrase");
    assert.deepEqual(wrong.mode, { durable: false, reason: "WRONG_PASSPHRASE" });
    assert.equal(wrong.get("did:atlas:a"), undefined);
    wrong.delete("did:atlas:a");
    assert.deepEqual(keyFiles(), before);
  });

  it("refuses a key file moved to another agent or tampered with", async () => {
    const { publicKey, secretKey } = await keypair();
    const store = await AgentKeyStore.open(dir, PASS);
    store.adopt("did:atlas:a", secretKey, publicKey);
    const other = await keypair();
    store.adopt("did:atlas:b", other.secretKey, other.publicKey);
    const [fa, fb] = ["did:atlas:a", "did:atlas:b"].map(
      (id) => keyFiles().find((f) => readFileSync(join(dir, AGENT_KEYS_DIR, f), "utf-8").includes(id))!,
    );

    // b's file now holds a's wrapped key
    writeFileSync(join(dir, AGENT_KEYS_DIR, fb), readFileSync(join(dir, AGENT_KEYS_DIR, fa)));
    assert.equal((await AgentKeyStore.open(dir, PASS)).get("did:atlas:b"), undefined);

    const wrapped = JSON.parse(readFileSync(join(dir, AGENT_KEYS_DIR, fa), "utf-8"));
    wrapped.public_key = Buffer.from(other.publicKey).toString("hex");
    writeFileSync(join(dir, AGENT_KEYS_DIR, fa), JSON.stringify(wrapped));
    assert.equal((await AgentKeyStore.open(dir, PASS)).get("did:atlas:a"), undefined);
  });
});

describe("identity registry with a durable keystore", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "atlas-durable-reg-")); });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  async function open(passphrase: string | undefined) {
    const signer = await QuantumSigner.create(dir);
    return {
      signer,
      registry: await IdentityRegistry.create(dir, signer, await AgentKeyStore.open(dir, passphrase)),
    };
  }
  const delegateFrom = (registry: IdentityRegistry, parentAgentId: string, childName: string) =>
    registry.delegate({ parentAgentId, childName, childRole: "tool-caller", capabilities: ["file:read"], ttlHours: 1 });

  it("a delegated agent can still delegate after a restart", async () => {
    let { registry } = await open(PASS);
    const root = registry.register({ name: "root", role: "claude-code", capabilities: ["file:read", "identity:register"] });
    const child = delegateFrom(registry, root.agentId, "child");

    const restarted = await open(PASS);
    registry = restarted.registry;
    assert.ok(registry.getAgentSigner(root.agentId));
    const grandchild = delegateFrom(registry, child.agentId, "grandchild") as DelegatedCredential;
    assert.equal(grandchild.delegation.depth, 2);
    const chain = verifyDelegationChain(grandchild, registry, restarted.signer.getPublicKeyRaw()!);
    assert.equal(chain.valid, true, chain.reason);
  });

  it("without a passphrase, delegation after a restart fails with a clear reason", async () => {
    let { registry } = await open(undefined);
    const root = registry.register({ name: "root", role: "claude-code", capabilities: ["file:read", "identity:register"] });
    registry = (await open(undefined)).registry;
    assert.throws(() => delegateFrom(registry, root.agentId, "child"), /keystore is not durable/);
  });

  it("revocation destroys the stored keys, including cascaded descendants", async () => {
    const { registry } = await open(PASS);
    const root = registry.register({ name: "root", role: "claude-code", capabilities: ["file:read", "identity:register"] });
    const child = delegateFrom(registry, root.agentId, "child");
    const other = registry.register({ name: "other", role: "observer", capabilities: ["audit:read"] });
    const stored = () => readdirSync(join(dir, AGENT_KEYS_DIR)).filter((f) => f !== "keystore.json").length;
    assert.equal(stored(), 3);

    registry.revoke(other.agentId, "test");
    assert.equal(stored(), 2);
    // Cascade revokes the descendants; the parent itself is revoked separately
    registry.cascadeRevoke(root.agentId, "test");
    assert.equal(stored(), 1);
    registry.revoke(root.agentId, "test");
    assert.equal(stored(), 0);

    const reopened = (await open(PASS)).registry;
    assert.equal(reopened.getAgentSigner(child.agentId), undefined);
  });
});
