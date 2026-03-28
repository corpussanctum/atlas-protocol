/**
 * Tests for Fidelis Channel — Config Loader
 */

import { describe, it, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  writeFileSync,
  rmSync,
  existsSync,
  readFileSync,
  renameSync,
} from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

import { loadConfig } from "../src/config.js";

// ---------------------------------------------------------------------------
// Helpers — manage environment and config file
// ---------------------------------------------------------------------------

const CONFIG_DIR = join(homedir(), ".fidelis-channel");
const CONFIG_PATH = join(CONFIG_DIR, "config.json");
const CONFIG_BACKUP = CONFIG_PATH + ".test-backup";

const savedEnv: Record<string, string | undefined> = {};

function setEnv(key: string, value: string) {
  if (!(key in savedEnv)) {
    savedEnv[key] = process.env[key];
  }
  process.env[key] = value;
}

function clearEnv(key: string) {
  if (!(key in savedEnv)) {
    savedEnv[key] = process.env[key];
  }
  delete process.env[key];
}

function restoreEnv() {
  for (const [key, val] of Object.entries(savedEnv)) {
    if (val === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = val;
    }
  }
  for (const key of Object.keys(savedEnv)) {
    delete savedEnv[key];
  }
}

/** Move real config.json out of the way so loadConfig sees only defaults + env. */
function stashConfigFile() {
  if (existsSync(CONFIG_PATH)) {
    renameSync(CONFIG_PATH, CONFIG_BACKUP);
  }
}

/** Restore the real config.json if we stashed it. */
function unstashConfigFile() {
  if (existsSync(CONFIG_BACKUP)) {
    renameSync(CONFIG_BACKUP, CONFIG_PATH);
  }
}

function clearAllFidelisEnv() {
  clearEnv("FIDELIS_TELEGRAM_BOT_TOKEN");
  clearEnv("FIDELIS_TELEGRAM_CHAT_IDS");
  clearEnv("FIDELIS_PERMISSION_TIMEOUT");
  clearEnv("FIDELIS_AUDIT_LOG_PATH");
  clearEnv("FIDELIS_HMAC_SECRET");
  clearEnv("FIDELIS_VELOCITY_LIMIT");
}

// ---------------------------------------------------------------------------
// Default values (config.json removed, env cleared)
// ---------------------------------------------------------------------------

describe("loadConfig — defaults", () => {
  before(() => {
    stashConfigFile();
  });

  after(() => {
    restoreEnv();
    unstashConfigFile();
  });

  afterEach(() => {
    restoreEnv();
  });

  it("returns a complete config object", () => {
    clearAllFidelisEnv();
    const config = loadConfig();
    assert.ok(config, "Config should be returned");
    assert.equal(typeof config.permission_timeout_seconds, "number");
    assert.equal(typeof config.velocity_limit_per_minute, "number");
    assert.ok(Array.isArray(config.policy_rules));
  });

  it("fail-closed timeout defaults to 120 seconds", () => {
    clearAllFidelisEnv();
    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 120);
  });

  it("default policy rules include deny rules for dangerous patterns", () => {
    clearAllFidelisEnv();
    const config = loadConfig();
    const denyRules = config.policy_rules.filter((r) => r.action === "deny");
    assert.ok(denyRules.length >= 2, "Should have at least 2 deny rules by default");

    const rmRule = config.policy_rules.find((r) =>
      r.tool_pattern.includes("rm -rf")
    );
    assert.ok(rmRule, "Should have a rule blocking rm -rf");
    assert.equal(rmRule?.action, "deny");
  });

  it("default velocity limit is 30/min", () => {
    clearAllFidelisEnv();
    const config = loadConfig();
    assert.equal(config.velocity_limit_per_minute, 30);
  });

  it("default audit log path is under ~/.fidelis-channel/", () => {
    clearAllFidelisEnv();
    const config = loadConfig();
    assert.ok(
      config.audit_log_path.includes(".fidelis-channel"),
      `Expected path containing .fidelis-channel, got: ${config.audit_log_path}`
    );
  });

  it("default telegram token is empty (fail-safe: no bot without explicit config)", () => {
    clearAllFidelisEnv();
    const config = loadConfig();
    assert.equal(config.telegram_bot_token, "");
  });

  it("default telegram chat IDs is empty array", () => {
    clearAllFidelisEnv();
    const config = loadConfig();
    assert.deepEqual(config.telegram_allowed_chat_ids, []);
  });

  it("default HMAC secret is empty (unsigned entries by default)", () => {
    clearAllFidelisEnv();
    const config = loadConfig();
    assert.equal(config.audit_hmac_secret, "");
  });
});

// ---------------------------------------------------------------------------
// Environment variable overrides (config.json removed)
// ---------------------------------------------------------------------------

describe("loadConfig — environment variable overrides", () => {
  before(() => {
    stashConfigFile();
  });

  after(() => {
    restoreEnv();
    unstashConfigFile();
  });

  afterEach(() => {
    restoreEnv();
  });

  it("FIDELIS_TELEGRAM_BOT_TOKEN overrides default", () => {
    setEnv("FIDELIS_TELEGRAM_BOT_TOKEN", "123456:ABC-DEF");
    const config = loadConfig();
    assert.equal(config.telegram_bot_token, "123456:ABC-DEF");
  });

  it("FIDELIS_TELEGRAM_CHAT_IDS parses comma-separated numbers", () => {
    setEnv("FIDELIS_TELEGRAM_CHAT_IDS", "111, 222, 333");
    const config = loadConfig();
    assert.deepEqual(config.telegram_allowed_chat_ids, [111, 222, 333]);
  });

  it("FIDELIS_TELEGRAM_CHAT_IDS ignores non-numeric values", () => {
    setEnv("FIDELIS_TELEGRAM_CHAT_IDS", "111, abc, 333");
    const config = loadConfig();
    assert.deepEqual(config.telegram_allowed_chat_ids, [111, 333]);
  });

  it("FIDELIS_PERMISSION_TIMEOUT overrides default", () => {
    setEnv("FIDELIS_PERMISSION_TIMEOUT", "60");
    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 60);
  });

  it("FIDELIS_PERMISSION_TIMEOUT falls back to 120 on invalid input", () => {
    setEnv("FIDELIS_PERMISSION_TIMEOUT", "not-a-number");
    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 120);
  });

  it("FIDELIS_AUDIT_LOG_PATH overrides default", () => {
    setEnv("FIDELIS_AUDIT_LOG_PATH", "/tmp/custom-audit.jsonl");
    const config = loadConfig();
    assert.equal(config.audit_log_path, "/tmp/custom-audit.jsonl");
  });

  it("FIDELIS_HMAC_SECRET overrides default", () => {
    setEnv("FIDELIS_HMAC_SECRET", "super-secret-key");
    const config = loadConfig();
    assert.equal(config.audit_hmac_secret, "super-secret-key");
  });

  it("FIDELIS_VELOCITY_LIMIT overrides default", () => {
    setEnv("FIDELIS_VELOCITY_LIMIT", "10");
    const config = loadConfig();
    assert.equal(config.velocity_limit_per_minute, 10);
  });
});

// ---------------------------------------------------------------------------
// JSON config file loading
// ---------------------------------------------------------------------------

describe("loadConfig — JSON config file", () => {
  before(() => {
    stashConfigFile();
  });

  after(() => {
    restoreEnv();
    // Remove any test config we wrote, then restore original
    try {
      rmSync(CONFIG_PATH);
    } catch {
      // ignore
    }
    unstashConfigFile();
  });

  afterEach(() => {
    restoreEnv();
  });

  it("loads settings from ~/.fidelis-channel/config.json", () => {
    mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(
      CONFIG_PATH,
      JSON.stringify({
        permission_timeout_seconds: 300,
        velocity_limit_per_minute: 5,
      }),
      "utf-8"
    );

    clearAllFidelisEnv();
    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 300);
    assert.equal(config.velocity_limit_per_minute, 5);
  });

  it("environment variables take priority over JSON config", () => {
    mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(
      CONFIG_PATH,
      JSON.stringify({ permission_timeout_seconds: 300 }),
      "utf-8"
    );

    setEnv("FIDELIS_PERMISSION_TIMEOUT", "45");
    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 45);
  });

  it("survives malformed JSON config gracefully", () => {
    mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, "{ this is not valid json }", "utf-8");

    clearAllFidelisEnv();
    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 120);
  });
});
