/**
 * Tests for Atlas Protocol — Break-Glass Mechanism (v0.8.0)
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BreakGlassManager } from "../src/break-glass.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let testDir: string;
let manager: BreakGlassManager;

function setup() {
  testDir = mkdtempSync(join(tmpdir(), "atlas-bg-test-"));
  manager = new BreakGlassManager(testDir);
}

function cleanup() {
  if (testDir && existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("BreakGlassManager — creation", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("creates a token file", () => {
    const { token } = manager.create("test reason", 60);
    assert.ok(token.created_at);
    assert.ok(token.expires_at);
    assert.equal(token.reason, "test reason");
    assert.ok(token.token_hash.length > 0);
    assert.equal(token.max_requests, 0);
    assert.equal(token.requests_used, 0);
    assert.ok(existsSync(join(testDir, "break-glass.token")));
  });

  it("returns a secret different from token_hash", () => {
    const { token, secret } = manager.create("test", 60);
    assert.notEqual(secret, token.token_hash);
    assert.ok(secret.length >= 32); // 16 bytes hex = 32 chars
  });

  it("caps TTL at MAX_TTL_MINUTES (240)", () => {
    const { token } = manager.create("test", 500);
    const created = new Date(token.created_at).getTime();
    const expires = new Date(token.expires_at).getTime();
    const ttlMinutes = (expires - created) / 60_000;
    assert.ok(ttlMinutes <= 241, `TTL should be capped at 240, got ${ttlMinutes}`);
  });

  it("enforces minimum TTL of 1 minute", () => {
    const { token } = manager.create("test", 0);
    const created = new Date(token.created_at).getTime();
    const expires = new Date(token.expires_at).getTime();
    const ttlMinutes = (expires - created) / 60_000;
    assert.ok(ttlMinutes >= 0.9, `TTL should be at least 1 minute, got ${ttlMinutes}`);
  });
});

describe("BreakGlassManager — isActive", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("returns false when no token exists", () => {
    assert.equal(manager.isActive(), false);
  });

  it("returns true for a valid token", () => {
    manager.create("test", 60);
    assert.equal(manager.isActive(), true);
  });

  it("returns false for an expired token", () => {
    // Create token that expired 1 minute ago
    const { token } = manager.create("test", 1);
    // Manually expire it
    token.expires_at = new Date(Date.now() - 60_000).toISOString();
    writeFileSync(join(testDir, "break-glass.token"), JSON.stringify(token), "utf-8");
    assert.equal(manager.isActive(), false);
  });
});

describe("BreakGlassManager — request counting", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("increments requests_used on recordUsage", () => {
    manager.create("test", 60);
    manager.recordUsage();
    manager.recordUsage();
    const token = manager.read();
    assert.equal(token?.requests_used, 2);
  });

  it("auto-revokes when max_requests reached", () => {
    manager.create("test", 60, 3);
    manager.recordUsage();
    manager.recordUsage();
    manager.recordUsage();
    // After 3 uses, next read should return null (auto-revoked)
    assert.equal(manager.read(), null);
    assert.equal(manager.isActive(), false);
  });

  it("unlimited requests when max_requests is 0", () => {
    manager.create("test", 60, 0);
    for (let i = 0; i < 100; i++) {
      manager.recordUsage();
    }
    assert.equal(manager.isActive(), true);
    assert.equal(manager.read()?.requests_used, 100);
  });
});

describe("BreakGlassManager — revocation", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("revoke removes the token file", () => {
    manager.create("test", 60);
    assert.equal(manager.isActive(), true);
    const result = manager.revoke();
    assert.equal(result, true);
    assert.equal(manager.isActive(), false);
  });

  it("revoke returns false when no token exists", () => {
    assert.equal(manager.revoke(), false);
  });
});

describe("BreakGlassManager — getStatus", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("returns active: false when no token", () => {
    const status = manager.getStatus();
    assert.equal(status.active, false);
    assert.equal(status.token, undefined);
  });

  it("returns active: true with token details", () => {
    manager.create("network outage", 60);
    const status = manager.getStatus();
    assert.equal(status.active, true);
    assert.ok(status.token);
    assert.equal(status.token.reason, "network outage");
    assert.ok(status.token.remaining_seconds > 0);
    assert.ok(status.token.remaining_seconds <= 3600);
  });
});

describe("BreakGlassManager — corruption resilience", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("returns null for corrupt JSON", () => {
    writeFileSync(join(testDir, "break-glass.token"), "not json", "utf-8");
    assert.equal(manager.read(), null);
    assert.equal(manager.isActive(), false);
  });

  it("returns null for missing required fields", () => {
    writeFileSync(join(testDir, "break-glass.token"), '{"created_at":"2026-01-01"}', "utf-8");
    assert.equal(manager.read(), null);
  });
});
