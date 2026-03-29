/**
 * Tests for Atlas Protocol — Config Loader
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
  const dir = mkdtempSync(join(tmpdir(), "atlas-config-test-"));
  tempDirs.push(dir);
  return dir;
}

function clearAllAtlasEnv() {
  clearEnv("ATLAS_DATA_DIR");
  clearEnv("ATLAS_CONFIG_PATH");
  clearEnv("ATLAS_TELEGRAM_BOT_TOKEN");
  clearEnv("ATLAS_TELEGRAM_CHAT_IDS");
  clearEnv("ATLAS_PERMISSION_TIMEOUT");
  clearEnv("ATLAS_AUDIT_LOG_PATH");
  clearEnv("ATLAS_HMAC_SECRET");
  clearEnv("ATLAS_VELOCITY_LIMIT");
  clearEnv("ATLAS_POLL_INTERVAL_MS");
  clearEnv("ATLAS_BRIEFCASE_PATH");
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
    clearAllAtlasEnv();
    setEnv("ATLAS_DATA_DIR", dataDir);

    const config = loadConfig();
    assert.ok(config);
    assert.equal(config.data_dir, dataDir);
    assert.equal(config.config_path, join(dataDir, "config.json"));
    assert.equal(typeof config.permission_timeout_seconds, "number");
    assert.equal(typeof config.velocity_limit_per_minute, "number");
    assert.ok(Array.isArray(config.policy_rules));
  });

  it("fail-closed timeout defaults to 120 seconds", () => {
    setEnv("ATLAS_DATA_DIR", makeTempDataDir());
    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 120);
  });

  it("default audit log path is under the resolved data dir", () => {
    const dataDir = makeTempDataDir();
    setEnv("ATLAS_DATA_DIR", dataDir);
    const config = loadConfig();
    assert.equal(config.audit_log_path, join(dataDir, "audit.jsonl"));
  });

  it("defaults to no token and no authorized chats", () => {
    setEnv("ATLAS_DATA_DIR", makeTempDataDir());
    const config = loadConfig();
    assert.equal(config.telegram_bot_token, "");
    assert.deepEqual(config.telegram_allowed_chat_ids, []);
  });

  it("defaults to empty briefcase_path", () => {
    setEnv("ATLAS_DATA_DIR", makeTempDataDir());
    const config = loadConfig();
    assert.equal(config.briefcase_path, "");
  });
});

describe("loadConfig — environment variable overrides", () => {
  it("ATLAS_TELEGRAM_BOT_TOKEN overrides default", () => {
    setEnv("ATLAS_DATA_DIR", makeTempDataDir());
    setEnv("ATLAS_TELEGRAM_BOT_TOKEN", "123456:ABC-DEF");
    const config = loadConfig();
    assert.equal(config.telegram_bot_token, "123456:ABC-DEF");
  });

  it("ATLAS_TELEGRAM_CHAT_IDS parses comma-separated numbers", () => {
    setEnv("ATLAS_DATA_DIR", makeTempDataDir());
    setEnv("ATLAS_TELEGRAM_CHAT_IDS", "111, 222, 333");
    const config = loadConfig();
    assert.deepEqual(config.telegram_allowed_chat_ids, [111, 222, 333]);
  });

  it("ATLAS_AUDIT_LOG_PATH overrides default", () => {
    setEnv("ATLAS_DATA_DIR", makeTempDataDir());
    setEnv("ATLAS_AUDIT_LOG_PATH", "/tmp/custom-audit.jsonl");
    const config = loadConfig();
    assert.equal(config.audit_log_path, "/tmp/custom-audit.jsonl");
  });

  it("ATLAS_DATA_DIR takes precedence for default paths", () => {
    const dataDir = makeTempDataDir();
    setEnv("ATLAS_DATA_DIR", dataDir);
    const config = loadConfig();
    assert.equal(config.config_path, join(dataDir, "config.json"));
    assert.equal(config.audit_log_path, join(dataDir, "audit.jsonl"));
  });

  it("ATLAS_BRIEFCASE_PATH sets briefcase path", () => {
    setEnv("ATLAS_DATA_DIR", makeTempDataDir());
    setEnv("ATLAS_BRIEFCASE_PATH", "/home/user/my-briefcase");
    const config = loadConfig();
    assert.equal(config.briefcase_path, "/home/user/my-briefcase");
  });
});

describe("loadConfig — JSON config file", () => {
  it("loads settings from the resolved config path", () => {
    const dataDir = makeTempDataDir();
    setEnv("ATLAS_DATA_DIR", dataDir);

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
    setEnv("ATLAS_DATA_DIR", dataDir);

    mkdirSync(dataDir, { recursive: true });
    writeFileSync(
      join(dataDir, "config.json"),
      JSON.stringify({ permission_timeout_seconds: 300 }),
      "utf-8"
    );
    setEnv("ATLAS_PERMISSION_TIMEOUT", "60");

    const config = loadConfig();
    assert.equal(config.permission_timeout_seconds, 60);
  });
});
