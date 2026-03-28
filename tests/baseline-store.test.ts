/**
 * Tests for Fidelis Channel — Baseline Store (v0.7.0)
 *
 * Covers: save, get, list, delete, count, graceful error handling
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BaselineStore } from "../src/baseline-store.js";
import type { BaselineProfile } from "../src/baseline-types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "fidelis-baseline-test-"));
}

function mockProfile(agentId: string, overrides?: Partial<BaselineProfile>): BaselineProfile {
  const now = new Date().toISOString();
  return {
    agentId,
    agentName: overrides?.agentName ?? `Agent ${agentId}`,
    agentRole: overrides?.agentRole ?? "assistant",
    createdAt: overrides?.createdAt ?? now,
    updatedAt: overrides?.updatedAt ?? now,
    version: overrides?.version ?? "0.7.0",
    totalSessions: overrides?.totalSessions ?? 15,
    totalEvents: overrides?.totalEvents ?? 100,
    totalDenies: overrides?.totalDenies ?? 5,
    totalAllows: overrides?.totalAllows ?? 90,
    totalAsks: overrides?.totalAsks ?? 5,
    riskDistribution: overrides?.riskDistribution ?? {
      min: 0, max: 40, mean: 15, p50: 12, p75: 20, p95: 35, p99: 40,
      stddev: 10, sampleCount: 100,
    },
    techniqueFrequencies: overrides?.techniqueFrequencies ?? [],
    capabilityUsage: overrides?.capabilityUsage ?? [],
    temporalProfile: overrides?.temporalProfile ?? {
      hourlyActivity: Array(24).fill(0) as number[],
      dailyActivity: Array(7).fill(0) as number[],
      dominantPattern: "steady",
      avgSessionDurationMinutes: 30,
      avgEventsPerSession: 7,
      longestSessionMinutes: 60,
    },
    delegationProfile: overrides?.delegationProfile ?? {
      totalDelegationsIssued: 0,
      totalDelegationsReceived: 0,
      maxDepthUsed: 0,
      cascadeRevocations: 0,
      avgChildCapabilityReduction: 0,
    },
    whyHistory: overrides?.whyHistory ?? [],
    maturityLevel: overrides?.maturityLevel ?? "developing",
    thresholds: overrides?.thresholds ?? {
      riskScoreUpperBound: 35,
      riskScoreCritical: 45,
      maxDenyRatioPerCapability: 0.5,
      expectedTechniques: [],
      unexpectedTechniqueAlert: false,
    },
    _riskScores: overrides?._riskScores ?? [10, 15, 20, 12, 18],
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];
afterEach(() => {
  for (const dir of tempDirs) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  tempDirs.length = 0;
});

describe("BaselineStore", () => {
  it("save() persists a profile", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);
    const profile = mockProfile("did:fidelis:agent-1");

    await store.save(profile);

    const count = await store.count();
    assert.equal(count, 1);
  });

  it("get() retrieves a saved profile", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);
    const profile = mockProfile("did:fidelis:agent-2");

    await store.save(profile);
    const retrieved = await store.get("did:fidelis:agent-2");

    assert.ok(retrieved);
    assert.equal(retrieved.agentId, "did:fidelis:agent-2");
    assert.equal(retrieved.totalSessions, 15);
    assert.equal(retrieved.maturityLevel, "developing");
  });

  it("get() returns undefined for unknown agentId", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    const result = await store.get("did:fidelis:nonexistent");
    assert.equal(result, undefined);
  });

  it("save() overwrites existing profile (upsert)", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    const profile1 = mockProfile("did:fidelis:agent-3", { totalSessions: 10 });
    await store.save(profile1);

    const profile2 = mockProfile("did:fidelis:agent-3", { totalSessions: 50 });
    await store.save(profile2);

    const retrieved = await store.get("did:fidelis:agent-3");
    assert.ok(retrieved);
    assert.equal(retrieved.totalSessions, 50);

    const count = await store.count();
    assert.equal(count, 1);
  });

  it("list() returns all profiles", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    await store.save(mockProfile("did:fidelis:a1"));
    await store.save(mockProfile("did:fidelis:a2"));
    await store.save(mockProfile("did:fidelis:a3"));

    const all = await store.list();
    assert.equal(all.length, 3);
  });

  it("list() filters by maturity level", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    await store.save(mockProfile("did:fidelis:b1", { maturityLevel: "developing" }));
    await store.save(mockProfile("did:fidelis:b2", { maturityLevel: "established" }));
    await store.save(mockProfile("did:fidelis:b3", { maturityLevel: "developing" }));

    const developing = await store.list({ maturity: "developing" });
    assert.equal(developing.length, 2);

    const established = await store.list({ maturity: "established" });
    assert.equal(established.length, 1);
    assert.equal(established[0].agentId, "did:fidelis:b2");
  });

  it("list() filters by updatedAfter timestamp", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    await store.save(mockProfile("did:fidelis:c1", { updatedAt: "2025-01-01T00:00:00Z" }));
    await store.save(mockProfile("did:fidelis:c2", { updatedAt: "2026-03-01T00:00:00Z" }));
    await store.save(mockProfile("did:fidelis:c3", { updatedAt: "2026-03-28T00:00:00Z" }));

    const recent = await store.list({ updatedAfter: "2026-02-01T00:00:00Z" });
    assert.equal(recent.length, 2);
  });

  it("delete() removes a profile", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    await store.save(mockProfile("did:fidelis:d1"));
    await store.save(mockProfile("did:fidelis:d2"));

    await store.delete("did:fidelis:d1");

    const count = await store.count();
    assert.equal(count, 1);
  });

  it("get() returns undefined after delete()", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    await store.save(mockProfile("did:fidelis:e1"));
    await store.delete("did:fidelis:e1");

    const result = await store.get("did:fidelis:e1");
    assert.equal(result, undefined);
  });

  it("handles missing data directory gracefully (no throw on get)", async () => {
    const dir = join(tmpdir(), "fidelis-baseline-nonexistent-" + Date.now());
    tempDirs.push(dir);
    // BaselineStore constructor creates the dir, but get() on a non-existent file should not throw
    const store = new BaselineStore(dir);
    const result = await store.get("did:fidelis:missing");
    assert.equal(result, undefined);
  });
});
