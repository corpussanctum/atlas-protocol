/**
 * Break-glass (SPEC §9): operator-signed tokens only.
 *
 * The governed agent can write files and call MCP tools, so any token it can
 * produce without the operator passphrase must be rejected.
 */

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, unlinkSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BreakGlassManager,
  issueBreakGlassToken,
  MAX_TTL_MINUTES,
} from "../src/break-glass.js";
import {
  generateOperatorKey,
  unlockOperatorKey,
  readOperatorPublicKey,
  operatorSecretPath,
  operatorSign,
  type OperatorPublicKey,
} from "../src/operator-key.js";

const PASS = "correct horse battery staple";

describe("break-glass with operator-signed tokens", () => {
  let dir: string;
  let pub: OperatorPublicKey;
  let operator: { keyId: string; secretKey: Uint8Array };

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "atlas-bg-"));
    pub = await generateOperatorKey(dir, PASS);
    operator = unlockOperatorKey(operatorSecretPath(dir), PASS);
  });
  after(() => rmSync(dir, { recursive: true, force: true }));
  beforeEach(() => {
    for (const f of ["break-glass.token", "break-glass.usage.json"]) {
      if (existsSync(join(dir, f))) unlinkSync(join(dir, f));
    }
  });

  const tokenPath = () => join(dir, "break-glass.token");
  const open = (key: OperatorPublicKey | null = pub) => BreakGlassManager.open(dir, key);

  it("accepts a token signed by the pinned operator key", async () => {
    await issueBreakGlassToken(dir, operator, "relay outage", 30, 0);
    const bg = await open();
    assert.equal(bg.isActive(), true);
    assert.equal(bg.read()?.reason, "relay outage");
  });

  it("rejects the pre-1.0.5 unsigned token format (agent-writable forgery)", async () => {
    const now = Date.now();
    writeFileSync(tokenPath(), JSON.stringify({
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + 3_600_000).toISOString(),
      reason: "forged",
      token_hash: "00",
      max_requests: 0,
      requests_used: 0,
    }));
    const bg = await open();
    assert.equal(bg.isActive(), false);
    assert.equal(bg.getStatus().rejected, "UNSIGNED_TOKEN");
  });

  it("rejects a token whose signed fields were edited", async () => {
    await issueBreakGlassToken(dir, operator, "short", 5, 1);
    const t = JSON.parse(readFileSync(tokenPath(), "utf-8"));
    t.expires_at = new Date(Date.now() + 3_600_000).toISOString();
    writeFileSync(tokenPath(), JSON.stringify(t));
    assert.equal((await open()).getStatus().rejected, "BAD_SIGNATURE");
  });

  it("rejects a token signed by a different key, even if the agent rewrites key_id", async () => {
    const other = mkdtempSync(join(tmpdir(), "atlas-bg-other-"));
    try {
      await generateOperatorKey(other, PASS);
      const attacker = unlockOperatorKey(operatorSecretPath(other), PASS);
      await issueBreakGlassToken(dir, attacker, "self-signed", 30, 0);
      assert.equal((await open()).getStatus().rejected, "WRONG_OPERATOR_KEY");

      const t = JSON.parse(readFileSync(tokenPath(), "utf-8"));
      t.operator_key_id = pub.key_id;
      writeFileSync(tokenPath(), JSON.stringify(t));
      assert.equal((await open()).getStatus().rejected, "BAD_SIGNATURE");
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });

  it("keeps the startup key pinned when the public key file is replaced mid-session", async () => {
    const bg = await open(); // pins `pub`
    const other = mkdtempSync(join(tmpdir(), "atlas-bg-swap-"));
    try {
      const attackerPub = await generateOperatorKey(other, PASS);
      const attacker = unlockOperatorKey(operatorSecretPath(other), PASS);
      writeFileSync(join(dir, "operator", "operator.pub.json"), JSON.stringify(attackerPub));
      await issueBreakGlassToken(dir, attacker, "swapped key", 30, 0);
      assert.equal(bg.isActive(), false);
    } finally {
      writeFileSync(join(dir, "operator", "operator.pub.json"), JSON.stringify(pub));
      rmSync(other, { recursive: true, force: true });
    }
  });

  it("is unavailable when no operator key is configured", async () => {
    await issueBreakGlassToken(dir, operator, "x", 30, 0);
    const bg = await open(null);
    assert.equal(bg.isActive(), false);
    assert.equal(bg.getStatus().rejected, "NO_OPERATOR_KEY");
  });

  it("caps TTL at issuance and rejects signed tokens claiming more than the max", async () => {
    const t = await issueBreakGlassToken(dir, operator, "long", 10_000, 0);
    assert.equal(Date.parse(t.expires_at) - Date.parse(t.created_at), MAX_TTL_MINUTES * 60_000);

    const now = Date.now();
    const claims = {
      version: 2, reason: "too long", created_at: new Date(now).toISOString(),
      expires_at: new Date(now + (MAX_TTL_MINUTES + 1) * 60_000).toISOString(),
      max_requests: 0, nonce: "n1", operator_key_id: pub.key_id,
    };
    writeFileSync(tokenPath(), JSON.stringify({ ...claims, signature: await operatorSign(operator.secretKey, claims), requests_used: 0 }));
    assert.equal((await open()).getStatus().rejected, "TTL_EXCEEDS_MAX");
  });

  it("rejects expired tokens", async () => {
    const now = Date.now();
    const claims = {
      version: 2, reason: "old", created_at: new Date(now - 7_200_000).toISOString(),
      expires_at: new Date(now - 3_600_000).toISOString(),
      max_requests: 0, nonce: "n2", operator_key_id: pub.key_id,
    };
    writeFileSync(tokenPath(), JSON.stringify({ ...claims, signature: await operatorSign(operator.secretKey, claims), requests_used: 0 }));
    assert.equal((await open()).getStatus().rejected, "EXPIRED");
  });

  it("enforces max_requests, and deleting the usage file does not reset the count", async () => {
    await issueBreakGlassToken(dir, operator, "limited", 30, 2);
    const bg = await open();
    bg.recordUsage();
    assert.equal(bg.read()?.requests_used, 1);
    unlinkSync(join(dir, "break-glass.usage.json"));
    assert.equal(bg.read()?.requests_used, 1);
    bg.recordUsage();
    assert.equal(bg.isActive(), false);
    assert.equal(bg.getStatus().rejected, "REQUEST_LIMIT_REACHED");
  });

  it("ignores requests_used written into the token file", async () => {
    await issueBreakGlassToken(dir, operator, "limited", 30, 1);
    const bg = await open();
    bg.recordUsage();
    const t = JSON.parse(readFileSync(tokenPath(), "utf-8"));
    t.requests_used = 0;
    writeFileSync(tokenPath(), JSON.stringify(t));
    assert.equal(bg.isActive(), false);
  });

  it("revoke removes the token", async () => {
    await issueBreakGlassToken(dir, operator, "x", 30, 0);
    const bg = await open();
    assert.equal(bg.revoke(), true);
    assert.equal(bg.isActive(), false);
    assert.equal(bg.revoke(), false);
  });

  it("treats corrupt JSON as malformed, not active", async () => {
    writeFileSync(tokenPath(), "{not json");
    assert.equal((await open()).getStatus().rejected, "MALFORMED_TOKEN");
  });
});

describe("operator key", () => {
  let dir: string;
  before(() => { dir = mkdtempSync(join(tmpdir(), "atlas-opkey-")); });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("rejects short passphrases", async () => {
    await assert.rejects(generateOperatorKey(dir, "short"), /at least 12/);
  });

  it("round-trips with the right passphrase and fails with a wrong one", async () => {
    const pub = await generateOperatorKey(dir, PASS);
    assert.equal(readOperatorPublicKey(dir)?.key_id, pub.key_id);
    assert.equal(unlockOperatorKey(operatorSecretPath(dir), PASS).keyId, pub.key_id);
    assert.throws(() => unlockOperatorKey(operatorSecretPath(dir), "wrong passphrase!"), /Wrong passphrase/);
  });

  it("does not store the secret key in plaintext", () => {
    const enc = readFileSync(operatorSecretPath(dir), "utf-8");
    assert.ok(!/secret_key|secretKey/.test(enc));
    assert.match(enc, /aes-256-gcm/);
  });

  it("refuses to overwrite an existing key without force", async () => {
    await assert.rejects(generateOperatorKey(dir, PASS), /already exists/);
  });

  it("detects a public key file whose key_id was edited", () => {
    const p = join(dir, "operator", "operator.pub.json");
    const pub = JSON.parse(readFileSync(p, "utf-8"));
    writeFileSync(p, JSON.stringify({ ...pub, key_id: "0000000000000000" }));
    assert.throws(() => readOperatorPublicKey(dir), /does not match its key_id/);
    writeFileSync(p, JSON.stringify(pub));
  });
});
