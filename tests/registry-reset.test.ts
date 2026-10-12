/**
 * Tests for the operator registry reset (SPEC §4.6 recovery, #32).
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLogger } from "../src/audit-log.js";
import type { AtlasConfig } from "../src/config.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import {
  generateOperatorKey,
  loadMlDsa,
  operatorSecretPath,
  operatorVerify,
  unlockOperatorKey,
} from "../src/operator-key.js";
import type { OperatorPublicKey } from "../src/operator-key.js";
import { QuantumSigner } from "../src/quantum-signer.js";
import { registryPath, resetIdentityRegistry, summarizeRegistry } from "../src/registry-reset.js";

const PASS = "correct horse battery";
const NOW = new Date("2026-10-12T12:00:00.000Z");

function makeConfig(dir: string): AtlasConfig {
  return {
    data_dir: dir,
    config_path: join(dir, "config.json"),
    telegram_bot_token: "",
    telegram_allowed_chat_ids: [],
    telegram_poll_interval_ms: 1000,
    permission_timeout_seconds: 120,
    policy_rules: [],
    audit_log_path: join(dir, "audit.jsonl"),
    audit_hmac_secret: "reset-test",
    velocity_limit_per_minute: 30,
    briefcase_path: "",
  };
}

function writeRegistry(dir: string): void {
  const cred = (agentId: string, expiresAt: string, revoked = false) => ({
    agentId, name: agentId, role: "claude-code", capabilities: ["identity:register"],
    issuedAt: "2026-04-09T00:00:00.000Z", expiresAt, revoked,
  });
  writeFileSync(registryPath(dir), JSON.stringify({
    credentials: [
      cred("did:atlas:expired", "2026-04-10T00:00:00.000Z"),
      cred("did:atlas:revoked", "2027-01-01T00:00:00.000Z", true),
      cred("did:atlas:active", "2027-01-01T00:00:00.000Z"),
    ],
    children: {},
  }));
}

describe("registry reset", () => {
  let dir: string;
  let pub: OperatorPublicKey;
  let operator: { keyId: string; secretKey: Uint8Array };
  let signer: QuantumSigner;

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "atlas-reset-test-"));
    pub = await generateOperatorKey(dir, PASS);
    operator = unlockOperatorKey(operatorSecretPath(dir), PASS);
    signer = await QuantumSigner.create(dir);
  });

  after(() => rmSync(dir, { recursive: true, force: true }));

  it("summarizes credentials by state", () => {
    writeRegistry(dir);
    const s = summarizeRegistry(dir, NOW);
    assert.ok(s);
    assert.deepEqual([s.total, s.active, s.expired, s.revoked], [3, 1, 1, 1]);
    assert.match(s.sha3, /^[0-9a-f]{64}$/);
  });

  it("logs a signed REGISTRY_RESET, then archives the registry", async () => {
    writeRegistry(dir);
    const before = summarizeRegistry(dir, NOW)!;
    const config = makeConfig(dir);
    new AuditLogger(config, undefined, signer).log("SESSION_START");

    const result = await resetIdentityRegistry(config, operator, "root credential expired", signer, NOW);
    assert.ok(result);

    assert.equal(existsSync(registryPath(dir)), false);
    assert.equal(readFileSync(result.archivedPath, "utf-8").length > 0, true);
    assert.equal(statSync(result.archivedPath).mode & 0o777, 0o600);

    const meta = result.entry.meta as Record<string, string | number>;
    assert.equal(result.entry.event, "REGISTRY_RESET");
    assert.equal(result.entry.seq, 1);
    assert.equal(meta.registry_sha3, before.sha3);
    assert.equal(meta.credentials_active, 1);

    const { credentials_expired, credentials_revoked, operator_signature, ...signed } = meta;
    const dsa = await loadMlDsa();
    assert.equal(operatorVerify(dsa, pub, signed, String(operator_signature)), true);
    assert.equal(operatorVerify(dsa, pub, { ...signed, reason: "forged" }, String(operator_signature)), false);

    const verify = new AuditLogger(config, undefined, signer).verify();
    assert.equal(verify.valid, true, verify.errors.join(", "));
  });

  it("re-opens the bootstrap window for a fresh registry load", async () => {
    const registry = await IdentityRegistry.create(dir, signer);
    assert.equal(registry.isEmpty(), true);
  });

  it("returns null when there is no registry", async () => {
    assert.equal(await resetIdentityRegistry(makeConfig(dir), operator, "noop", signer, NOW), null);
  });
});
