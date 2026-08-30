/**
 * Tests for Atlas Protocol — issuer key rotation (SPEC §4.5)
 *
 * Covers the full rotate → re-issue → KEY_ROTATION audit → historical
 * verification path across QuantumSigner, IdentityRegistry, and AuditLogger.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { QuantumSigner } from "../src/quantum-signer.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import { AuditLogger } from "../src/audit-log.js";
import type { AtlasConfig } from "../src/config.js";
import type { AuditEntry } from "../src/audit-log.js";

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-keyrot-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
  tempDirs = [];
});

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
    audit_hmac_secret: "",
    velocity_limit_per_minute: 30,
    briefcase_path: "",
  };
}

describe("Key rotation — end to end", () => {
  it("KEY_ROTATION is signed by the old key and later entries by the new key", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir);
    const registry = await IdentityRegistry.create(dir, signer);
    const audit = new AuditLogger(makeConfig(dir), { redact_fields: [], force_privacy: false }, signer);

    registry.register({
      name: "operator",
      role: "admin",
      capabilities: ["identity:register", "file:read"],
    });

    audit.log("SESSION_START", { meta: { phase: "before-rotation" } });

    const prepared = signer.beginRotation();
    const reissue = registry.reissueAllActive(prepared.newSecretKey);
    assert.equal(reissue.reissued, 1);
    assert.equal(reissue.failed, 0);

    audit.log("KEY_ROTATION", {
      meta: {
        old_key_hash: prepared.oldKeyHashSha3,
        new_key_hash: prepared.newKeyHashSha3,
        new_public_key_b64: prepared.newPublicKeyB64,
        effective_at: prepared.effectiveAt,
        reason: "scheduled rotation",
        credentials_reissued: reissue.reissued,
        reissue_success: true,
      },
    });

    signer.commitRotation(prepared);
    registry.syncIssuerKeys();

    audit.log("SESSION_START", { meta: { phase: "after-rotation" } });

    const verification = audit.verify();
    assert.equal(verification.valid, true, verification.errors.join("; "));
    assert.ok(verification.stats.pq_signed >= 3);

    const lines = readFileSync(join(dir, "audit.jsonl"), "utf-8").trim().split("\n");
    const entries: AuditEntry[] = lines.map((l) => JSON.parse(l));
    const rotation = entries.find((e) => e.event === "KEY_ROTATION");
    assert.ok(rotation, "KEY_ROTATION entry should exist");
    assert.equal(rotation!.meta?.old_key_hash, prepared.oldKeyHashSha3);
    assert.equal(rotation!.meta?.new_key_hash, prepared.newKeyHashSha3);
    assert.equal(rotation!.meta?.credentials_reissued, 1);
    assert.equal(rotation!.meta?.reissue_success, true);

    const after = registry.verify(registry.list("active")[0].agentId);
    assert.equal(after.valid, true);
  });
});
