/**
 * Tests for Fidelis Channel — Audit Log (v0.2.1)
 *
 * Covers: basic logging, hash chain, HMAC signing, verification,
 * and consent-tier-driven field redaction.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, createHmac } from "node:crypto";
import { AuditLogger } from "../src/audit-log.js";
import type { FidelisConfig } from "../src/config.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "fidelis-audit-test-"));
  tempDirs.push(dir);
  return dir;
}

function makeConfig(overrides: Partial<FidelisConfig> = {}): FidelisConfig {
  const dir = makeTempDir();
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
    ...overrides,
  };
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

// ---------------------------------------------------------------------------
// Basic logging
// ---------------------------------------------------------------------------

describe("AuditLogger — basic logging", () => {
  it("creates log file and directory on first write", () => {
    const dir = makeTempDir();
    const logPath = join(dir, "subdir", "audit.jsonl");
    const config = makeConfig({ audit_log_path: logPath });
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");

    const content = readFileSync(logPath, "utf-8").trim();
    assert.ok(content.length > 0, "Log file should contain data");
  });

  it("entries have correct structure", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config);
    const entry = logger.log("SESSION_START", {
      meta: { version: "0.2.1" },
    });

    assert.ok(entry.id, "Entry should have an id");
    assert.ok(entry.timestamp, "Entry should have a timestamp");
    assert.equal(entry.event, "SESSION_START");
    assert.equal(typeof entry.prev_hash, "string");
    assert.deepEqual(entry.meta, { version: "0.2.1" });
  });

  it("entries include permission and policy_result when provided", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config);
    const entry = logger.log("POLICY_DENY", {
      permission: {
        request_id: "req-1",
        tool_name: "Bash",
        description: "run command",
        input_preview: "rm -rf /",
      },
      policy_result: {
        verdict: "deny",
        matched_rule: { tool_pattern: "Bash(rm -rf *)", action: "deny" },
        anomaly_flags: [],
        sensitivity_matches: [],
        identity_evaluated: false,
      },
      verdict: "deny",
    });

    assert.equal(entry.permission?.tool_name, "Bash");
    assert.equal(entry.policy_result?.verdict, "deny");
    assert.equal(entry.verdict, "deny");
  });

  it("multiple entries are appended as separate JSONL lines", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");
    logger.log("CONFIG_LOADED");
    logger.log("PERMISSION_REQUEST");

    const lines = readFileSync(config.audit_log_path, "utf-8").trim().split("\n");
    assert.equal(lines.length, 3);
    for (const line of lines) {
      const parsed = JSON.parse(line);
      assert.ok(parsed.id);
      assert.ok(parsed.event);
    }
  });
});

// ---------------------------------------------------------------------------
// Hash chain
// ---------------------------------------------------------------------------

describe("AuditLogger — hash chain", () => {
  it("first entry has prev_hash = GENESIS", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config);
    const entry = logger.log("SESSION_START");
    assert.equal(entry.prev_hash, "GENESIS");
  });

  it("each entry's prev_hash is SHA-256 of the previous line", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");
    logger.log("CONFIG_LOADED");
    logger.log("PERMISSION_REQUEST");

    const lines = readFileSync(config.audit_log_path, "utf-8").trim().split("\n");
    assert.equal(lines.length, 3);

    const entry0 = JSON.parse(lines[0]);
    assert.equal(entry0.prev_hash, "GENESIS");

    const entry1 = JSON.parse(lines[1]);
    const expectedHash1 = createHash("sha256").update(lines[0]).digest("hex");
    assert.equal(entry1.prev_hash, expectedHash1);

    const entry2 = JSON.parse(lines[2]);
    const expectedHash2 = createHash("sha256").update(lines[1]).digest("hex");
    assert.equal(entry2.prev_hash, expectedHash2);
  });

  it("chain resumes from existing log on new AuditLogger instance", () => {
    const config = makeConfig();
    const logger1 = new AuditLogger(config);
    logger1.log("SESSION_START");

    const logger2 = new AuditLogger(config);
    logger2.log("CONFIG_LOADED");

    const lines = readFileSync(config.audit_log_path, "utf-8").trim().split("\n");
    const entry1 = JSON.parse(lines[1]);
    const expectedHash = createHash("sha256").update(lines[0]).digest("hex");
    assert.equal(entry1.prev_hash, expectedHash, "New logger should continue the chain");
  });
});

// ---------------------------------------------------------------------------
// HMAC signing
// ---------------------------------------------------------------------------

describe("AuditLogger — HMAC signing", () => {
  it("entries have no hmac field when secret is empty", () => {
    const config = makeConfig({ audit_hmac_secret: "" });
    const logger = new AuditLogger(config);
    const entry = logger.log("SESSION_START");
    assert.equal(entry.hmac, undefined);
  });

  it("entries have hmac field when secret is set", () => {
    const config = makeConfig({ audit_hmac_secret: "test-secret-key" });
    const logger = new AuditLogger(config);
    const entry = logger.log("SESSION_START");
    assert.ok(entry.hmac, "Entry should have an HMAC signature");
    assert.equal(typeof entry.hmac, "string");
    assert.equal(entry.hmac.length, 64, "SHA-256 HMAC hex should be 64 chars");
  });

  it("HMAC can be verified from the serialized entry", () => {
    const secret = "my-hmac-secret";
    const config = makeConfig({ audit_hmac_secret: secret });
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");

    const line = readFileSync(config.audit_log_path, "utf-8").trim();
    const entry = JSON.parse(line);
    const { hmac, ...rest } = entry;

    const expectedHmac = createHmac("sha256", secret)
      .update(JSON.stringify(rest))
      .digest("hex");
    assert.equal(hmac, expectedHmac, "HMAC should match recomputation");
  });

  it("HMAC verification fails for tampered entry", () => {
    const secret = "tamper-detect-secret";
    const config = makeConfig({ audit_hmac_secret: secret });
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");

    const line = readFileSync(config.audit_log_path, "utf-8").trim();
    const entry = JSON.parse(line);
    entry.event = "HUMAN_APPROVE";
    const tampered = JSON.stringify(entry);
    writeFileSync(config.audit_log_path, tampered + "\n", "utf-8");

    const verifyResult = logger.verify();
    assert.equal(verifyResult.valid, false);
    assert.ok(
      verifyResult.errors.some((e) => e.includes("HMAC mismatch")),
      `Expected HMAC mismatch error, got: ${verifyResult.errors.join(", ")}`
    );
  });
});

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

describe("AuditLogger — verify()", () => {
  it("returns valid for an empty/missing log", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config);
    const result = logger.verify();
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it("returns valid for a clean multi-entry log", () => {
    const config = makeConfig({ audit_hmac_secret: "verify-test" });
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");
    logger.log("CONFIG_LOADED");
    logger.log("PERMISSION_REQUEST");
    logger.log("POLICY_ALLOW", { verdict: "allow" });

    const result = logger.verify();
    assert.equal(result.valid, true, `Errors: ${result.errors.join(", ")}`);
    assert.equal(result.errors.length, 0);
  });

  it("detects broken chain when a line is removed", () => {
    const config = makeConfig({ audit_hmac_secret: "chain-test" });
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");
    logger.log("CONFIG_LOADED");
    logger.log("PERMISSION_REQUEST");

    const lines = readFileSync(config.audit_log_path, "utf-8").trim().split("\n");
    writeFileSync(config.audit_log_path, lines[0] + "\n" + lines[2] + "\n", "utf-8");

    const result = logger.verify();
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("chain broken")));
  });

  it("detects tampered HMAC in verification", () => {
    const secret = "integrity-secret";
    const config = makeConfig({ audit_hmac_secret: secret });
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");

    const line = readFileSync(config.audit_log_path, "utf-8").trim();
    const entry = JSON.parse(line);
    entry.hmac = "0".repeat(64);
    writeFileSync(config.audit_log_path, JSON.stringify(entry) + "\n", "utf-8");

    const result = logger.verify();
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("HMAC mismatch")));
  });

  it("detects invalid JSON in log", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config);
    logger.log("SESSION_START");

    const existing = readFileSync(config.audit_log_path, "utf-8");
    writeFileSync(config.audit_log_path, existing + "not-valid-json\n", "utf-8");

    const result = logger.verify();
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("invalid JSON")));
  });
});

// ---------------------------------------------------------------------------
// Field redaction
// ---------------------------------------------------------------------------

describe("AuditLogger — field redaction", () => {
  it("does not redact when redact_fields is empty", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config, {
      redact_fields: [],
      force_privacy: false,
    });

    const entry = logger.log("PERMISSION_REQUEST", {
      permission: {
        request_id: "req-1",
        tool_name: "Bash",
        description: "run a command",
        input_preview: "echo secret data SSN 123-45-6789",
      },
    });

    assert.equal(entry.permission?.input_preview, "echo secret data SSN 123-45-6789");
  });

  it("hashes input_preview when redact_fields includes it", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config, {
      redact_fields: ["input_preview"],
      force_privacy: false,
    });

    const rawInput = "echo secret data SSN 123-45-6789";
    const entry = logger.log("PERMISSION_REQUEST", {
      permission: {
        request_id: "req-1",
        tool_name: "Bash",
        description: "run a command",
        input_preview: rawInput,
      },
    });

    // Should be hashed, not plaintext
    assert.ok(entry.permission?.input_preview.startsWith("HASHED:"));
    assert.ok(!entry.permission?.input_preview.includes("secret"));
    assert.ok(!entry.permission?.input_preview.includes("123-45-6789"));

    // Should be verifiable
    const expectedHash = createHash("sha256").update(rawInput).digest("hex");
    assert.equal(entry.permission?.input_preview, `HASHED:${expectedHash}`);

    // Meta should note the redaction
    assert.deepEqual(entry.meta?.redacted_fields, ["input_preview"]);
  });

  it("preserves non-redacted fields", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config, {
      redact_fields: ["input_preview"],
      force_privacy: false,
    });

    const entry = logger.log("PERMISSION_REQUEST", {
      permission: {
        request_id: "req-1",
        tool_name: "Bash",
        description: "run a command",
        input_preview: "sensitive stuff",
      },
    });

    // tool_name, description, request_id should remain plaintext
    assert.equal(entry.permission?.tool_name, "Bash");
    assert.equal(entry.permission?.description, "run a command");
    assert.equal(entry.permission?.request_id, "req-1");
  });

  it("can redact multiple fields", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config, {
      redact_fields: ["input_preview", "description"],
      force_privacy: false,
    });

    const entry = logger.log("PERMISSION_REQUEST", {
      permission: {
        request_id: "req-1",
        tool_name: "Bash",
        description: "patient diagnosis F32.1",
        input_preview: "SSN 123-45-6789",
      },
    });

    assert.ok(entry.permission?.input_preview.startsWith("HASHED:"));
    assert.ok(entry.permission?.description.startsWith("HASHED:"));
    assert.equal(entry.permission?.tool_name, "Bash"); // not redacted
  });

  it("redaction can be updated after construction", () => {
    const config = makeConfig();
    const logger = new AuditLogger(config);

    // Initially no redaction
    const entry1 = logger.log("PERMISSION_REQUEST", {
      permission: {
        request_id: "req-1",
        tool_name: "Bash",
        description: "test",
        input_preview: "plaintext data",
      },
    });
    assert.equal(entry1.permission?.input_preview, "plaintext data");

    // Enable redaction
    logger.setRedaction({ redact_fields: ["input_preview"], force_privacy: true });

    const entry2 = logger.log("PERMISSION_REQUEST", {
      permission: {
        request_id: "req-2",
        tool_name: "Bash",
        description: "test",
        input_preview: "should be hashed",
      },
    });
    assert.ok(entry2.permission?.input_preview.startsWith("HASHED:"));
  });

  it("redacted entries still maintain valid hash chain", () => {
    const config = makeConfig({ audit_hmac_secret: "redaction-chain-test" });
    const logger = new AuditLogger(config, {
      redact_fields: ["input_preview"],
      force_privacy: true,
    });

    logger.log("SESSION_START");
    logger.log("PERMISSION_REQUEST", {
      permission: {
        request_id: "req-1",
        tool_name: "Bash",
        description: "test",
        input_preview: "sensitive data here",
      },
    });
    logger.log("POLICY_ALLOW", { verdict: "allow" });

    const result = logger.verify();
    assert.equal(result.valid, true, `Errors: ${result.errors.join(", ")}`);
  });
});
