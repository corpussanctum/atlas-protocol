/**
 * Tests for Fidelis Channel — Config Loader
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { loadConfig } from "../src/config.js";

const savedEnv: Record<string, string | undefined> = {};
const tempDirs: string[] = [];

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

function makeTempDataDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "fidelis-config-test-"));
  tempDirs.push(dir);
  return dir;
}

function clearAllFidelisEnv() {
  clearEnv("FIDELIS_DATA_DIR");
  clearEnv("FIDELIS_CONFIG_PATH");
  clearEnv("FIDELIS_TELEGRAM_BOT_TOKEN");
  clearEnv("FIDELIS_TELEGRAM_CHAT_IDS");
  clearEnv("FIDELIS_PERMISSION_TIMEOUT");
  clearEnv("FIDELIS_AUDIT_LOG_PATH");
  clearEnv("FIDELIS_HMAC_SECRET");
  clearEnv("FIDELIS_VELOCITY_LIMIT");
  clearEnv("FIDELIS_POLL_INTERVAL_MS");
  clearEnv("FIDELIS_BRIEFCASE_PATH");
  clearEnv("CLAUDE_PLUGIN_DATA");
}

afterEach(() => {
  restoreEnv();
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("loadConfig — defaults", () => {
  it("returns a complete config object", () => {
    const dataDir = makeTempDataDir();
    clearAllFidelisEnv();
    setEnv("FIDELIS_DATA_DIR", dataDir);

    const config = loadConfig();
    assert.ok(config);
    assert.equal(config.data_dir, dataDir);
    assert.equal(config.config_path, join(dataDir, "config.json"));
    assert.equal(typeof config.permission_timeout_seconds, "number");
    assert.equal(typeof config.velocity_limit_per_minute, "number");
    assert.ok(Array.isArray(config.policy_rules));
  });

  it("fail-closed timeout defaults to 120 seconds", () => {
    setEnv("FIDELIS_DATA_DIR", makeTempDataDir());
    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 120);
  });

  it("default audit log path is under the resolved data dir", () => {
    const dataDir = makeTempDataDir();
    setEnv("FIDELIS_DATA_DIR", dataDir);
    const config = loadConfig();
    assert.equal(config.audit_log_path, join(dataDir, "audit.jsonl"));
  });

  it("defaults to no token and no authorized chats", () => {
    setEnv("FIDELIS_DATA_DIR", makeTempDataDir());
    const config = loadConfig();
    assert.equal(config.telegram_bot_token, "");
    assert.deepEqual(config.telegram_allowed_chat_ids, []);
  });

  it("defaults to empty briefcase_path", () => {
    setEnv("FIDELIS_DATA_DIR", makeTempDataDir());
    const config = loadConfig();
    assert.equal(config.briefcase_path, "");
  });
});

describe("loadConfig — environment variable overrides", () => {
  it("FIDELIS_TELEGRAM_BOT_TOKEN overrides default", () => {
    setEnv("FIDELIS_DATA_DIR", makeTempDataDir());
    setEnv("FIDELIS_TELEGRAM_BOT_TOKEN", "123456:ABC-DEF");
    const config = loadConfig();
    assert.equal(config.telegram_bot_token, "123456:ABC-DEF");
  });

  it("FIDELIS_TELEGRAM_CHAT_IDS parses comma-separated numbers", () => {
    setEnv("FIDELIS_DATA_DIR", makeTempDataDir());
    setEnv("FIDELIS_TELEGRAM_CHAT_IDS", "111, 222, 333");
    const config = loadConfig();
    assert.deepEqual(config.telegram_allowed_chat_ids, [111, 222, 333]);
  });

  it("FIDELIS_AUDIT_LOG_PATH overrides default", () => {
    setEnv("FIDELIS_DATA_DIR", makeTempDataDir());
    setEnv("FIDELIS_AUDIT_LOG_PATH", "/tmp/custom-audit.jsonl");
    const config = loadConfig();
    assert.equal(config.audit_log_path, "/tmp/custom-audit.jsonl");
  });

  it("FIDELIS_DATA_DIR takes precedence for default paths", () => {
    const dataDir = makeTempDataDir();
    setEnv("FIDELIS_DATA_DIR", dataDir);
    const config = loadConfig();
    assert.equal(config.config_path, join(dataDir, "config.json"));
    assert.equal(config.audit_log_path, join(dataDir, "audit.jsonl"));
  });

  it("FIDELIS_BRIEFCASE_PATH sets briefcase path", () => {
    setEnv("FIDELIS_DATA_DIR", makeTempDataDir());
    setEnv("FIDELIS_BRIEFCASE_PATH", "/home/user/my-briefcase");
    const config = loadConfig();
    assert.equal(config.briefcase_path, "/home/user/my-briefcase");
  });
});

describe("loadConfig — JSON config file", () => {
  it("loads settings from the resolved config path", () => {
    const dataDir = makeTempDataDir();
    setEnv("FIDELIS_DATA_DIR", dataDir);

    mkdirSync(dataDir, { recursive: true });
    writeFileSync(
      join(dataDir, "config.json"),
      JSON.stringify({
        permission_timeout_seconds: 300,
        velocity_limit_per_minute: 5,
      }),
      "utf-8"
    );

    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 300);
    assert.equal(config.velocity_limit_per_minute, 5);
  });

  it("environment variables take priority over JSON config", () => {
    const dataDir = makeTempDataDir();
    setEnv("FIDELIS_DATA_DIR", dataDir);

    mkdirSync(dataDir, { recursive: true });
    writeFileSync(
      join(dataDir, "config.json"),
      JSON.stringify({ permission_timeout_seconds: 300 }),
      "utf-8"
    );
    setEnv("FIDELIS_PERMISSION_TIMEOUT", "60");

    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 60);
  });
});
