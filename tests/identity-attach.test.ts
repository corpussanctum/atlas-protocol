/**
 * Tests for operator-signed identity attach (#39).
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentCredential } from "../src/agent-identity.js";
import { AttachManager, issueAttachToken, MAX_ATTACH_TTL_MINUTES } from "../src/identity-attach.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import { generateOperatorKey, operatorSecretPath, unlockOperatorKey } from "../src/operator-key.js";
import type { OperatorPublicKey } from "../src/operator-key.js";
import { QuantumSigner } from "../src/quantum-signer.js";

const PASS = "correct horse battery";

describe("identity attach", () => {
  let dir: string;
  let pub: OperatorPublicKey;
  let operator: { keyId: string; secretKey: Uint8Array };
  let registry: IdentityRegistry;
  let manager: AttachManager;
  let cred: AgentCredential;

  const tokenPath = () => join(dir, "attach.token");
  const rejection = (r: ReturnType<AttachManager["consume"]>) => ("rejected" in r ? r.rejected : "OK");

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "atlas-attach-test-"));
    pub = await generateOperatorKey(dir, PASS);
    operator = unlockOperatorKey(operatorSecretPath(dir), PASS);
    registry = await IdentityRegistry.create(dir, await QuantumSigner.create(dir));
    cred = registry.register({ name: "session", role: "claude-code", capabilities: ["file:read"], ttlHours: 24 });
    manager = await AttachManager.open(dir, pub);
  });

  after(() => rmSync(dir, { recursive: true, force: true }));

  it("attaches with a valid token and consumes it", async () => {
    await issueAttachToken(dir, operator, cred);
    const result = manager.consume(registry);
    assert.ok("token" in result);
    assert.equal(result.token.agent_id, cred.agentId);
    assert.equal(existsSync(tokenPath()), false);
    assert.equal(rejection(manager.consume(registry)), "NO_TOKEN");
  });

  it("rejects a replayed copy of a consumed token", async () => {
    await issueAttachToken(dir, operator, cred);
    copyFileSync(tokenPath(), `${tokenPath()}.copy`);
    assert.equal(rejection(manager.consume(registry)), "OK");
    copyFileSync(`${tokenPath()}.copy`, tokenPath());
    assert.equal(rejection(manager.consume(registry)), "REPLAYED");
  });

  it("rejects a token signed by a different operator key", async () => {
    const other = mkdtempSync(join(tmpdir(), "atlas-attach-other-"));
    try {
      await generateOperatorKey(other, PASS);
      await issueAttachToken(dir, unlockOperatorKey(operatorSecretPath(other), PASS), cred);
      assert.equal(rejection(manager.consume(registry)), "WRONG_OPERATOR_KEY");
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });

  it("rejects a token whose signed fields were edited", async () => {
    const victim = registry.register({ name: "other", role: "observer", capabilities: ["audit:read"], ttlHours: 24 });
    await issueAttachToken(dir, operator, cred);
    const token = JSON.parse(readFileSync(tokenPath(), "utf-8"));
    writeFileSync(tokenPath(), JSON.stringify({ ...token, agent_id: victim.agentId, credential_hash: victim.credentialHash }));
    assert.equal(rejection(manager.consume(registry)), "BAD_SIGNATURE");
  });

  it("rejects an expired token, and caps the TTL", async () => {
    const token = await issueAttachToken(dir, operator, cred, 24 * 60);
    assert.equal(Date.parse(token.expires_at) - Date.parse(token.created_at), MAX_ATTACH_TTL_MINUTES * 60_000);
    const later = new Date(Date.parse(token.expires_at) + 1000);
    assert.equal(rejection(manager.consume(registry, later)), "EXPIRED");
  });

  it("rejects a token for a credential that changed after issuance", async () => {
    await issueAttachToken(dir, operator, { agentId: cred.agentId, credentialHash: "0".repeat(64) });
    assert.equal(rejection(manager.consume(registry)), "CREDENTIAL_CHANGED");
  });

  it("rejects unknown and revoked credentials", async () => {
    await issueAttachToken(dir, operator, { agentId: "did:atlas:nobody", credentialHash: cred.credentialHash });
    assert.equal(rejection(manager.consume(registry)), "UNKNOWN_CREDENTIAL");

    const doomed = registry.register({ name: "doomed", role: "observer", capabilities: ["audit:read"], ttlHours: 24 });
    await issueAttachToken(dir, operator, doomed);
    registry.revoke(doomed.agentId, "test");
    assert.equal(rejection(manager.consume(registry)), "CREDENTIAL_INVALID");
  });

  it("is unavailable without a pinned operator key", async () => {
    await issueAttachToken(dir, operator, cred);
    const keyless = await AttachManager.open(dir, null);
    assert.equal(rejection(keyless.consume(registry)), "NO_OPERATOR_KEY");
    assert.equal(existsSync(tokenPath()), false);
  });
});
