/**
 * Tests for Atlas Protocol — Baseline Engine (v0.7.0)
 *
 * Covers: createEmptyProfile, calculateMaturity, calculateRiskDistribution,
 * recalculateProfile, ingestEntry, ingestAssessment, detectDrift, getBaselineContext
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createEmptyProfile,
  calculateMaturity,
  calculateRiskDistribution,
  recalculateProfile,
  ingestEntry,
  ingestAssessment,
  detectDrift,
  getBaselineContext,
} from "../src/baseline-engine.js";
import { BaselineStore } from "../src/baseline-store.js";
import type { BaselineProfile } from "../src/baseline-types.js";
import type { AuditEntry } from "../src/audit-log.js";
import type { ExpertAssessment } from "../src/why-engine.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "atlas-engine-test-"));
}

let seq = 0;

function mockAuditEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  seq++;
  return {
    id: `test-entry-${seq}`,
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    event: overrides.event ?? "POLICY_ALLOW",
    prev_hash: overrides.prev_hash ?? "GENESIS",
    ...overrides,
  } as AuditEntry;
}

function mockProfile(overrides: Partial<BaselineProfile> = {}): BaselineProfile {
  const now = new Date().toISOString();
  const hourlyActivity = Array(24).fill(0) as number[];
  // Put activity at hours 9-17
  for (let h = 9; h <= 17; h++) {
    hourlyActivity[h] = 10;
  }

  return {
    agentId: overrides.agentId ?? "did:atlas:test-agent",
    agentName: overrides.agentName ?? "Test Agent",
    agentRole: overrides.agentRole ?? "assistant",
    createdAt: overrides.createdAt ?? now,
    updatedAt: overrides.updatedAt ?? now,
    version: overrides.version ?? "0.7.0",
    totalSessions: overrides.totalSessions ?? 60,
    totalEvents: overrides.totalEvents ?? 500,
    totalDenies: overrides.totalDenies ?? 20,
    totalAllows: overrides.totalAllows ?? 450,
    totalAsks: overrides.totalAsks ?? 30,
    riskDistribution: overrides.riskDistribution ?? {
      min: 0, max: 50, mean: 20, p50: 18, p75: 28, p95: 40, p99: 48,
      stddev: 10, sampleCount: 500,
    },
    techniqueFrequencies: overrides.techniqueFrequencies ?? [
      {
        techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter",
        tactic: "Execution", count: 50, firstSeen: now, lastSeen: now, trend: "stable" as const,
      },
      {
        techniqueId: "T1083", techniqueName: "File and Directory Discovery",
        tactic: "Discovery", count: 30, firstSeen: now, lastSeen: now, trend: "stable" as const,
      },
    ],
    capabilityUsage: overrides.capabilityUsage ?? [],
    temporalProfile: overrides.temporalProfile ?? {
      hourlyActivity,
      dailyActivity: Array(7).fill(0) as number[],
      dominantPattern: "steady",
      avgSessionDurationMinutes: 30,
      avgEventsPerSession: 8,
      longestSessionMinutes: 90,
    },
    delegationProfile: overrides.delegationProfile ?? {
      totalDelegationsIssued: 0,
      totalDelegationsReceived: 0,
      maxDepthUsed: 0,
      cascadeRevocations: 0,
      avgChildCapabilityReduction: 0,
    },
    whyHistory: overrides.whyHistory ?? [],
    maturityLevel: overrides.maturityLevel ?? "established",
    thresholds: overrides.thresholds ?? {
      riskScoreUpperBound: 40,
      riskScoreCritical: 50,
      maxDenyRatioPerCapability: 0.5,
      expectedTechniques: ["T1059", "T1083"],
      unexpectedTechniqueAlert: true,
    },
    _riskScores: overrides._riskScores ?? Array(100).fill(20) as number[],
  };
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];
afterEach(() => {
  for (const dir of tempDirs) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  tempDirs.length = 0;
});

// ---------------------------------------------------------------------------
// createEmptyProfile
// ---------------------------------------------------------------------------

describe("createEmptyProfile", () => {
  it("sets correct defaults", () => {
    const profile = createEmptyProfile("did:atlas:new", "New Agent", "assistant");

    assert.equal(profile.agentId, "did:atlas:new");
    assert.equal(profile.agentName, "New Agent");
    assert.equal(profile.agentRole, "assistant");
    assert.equal(profile.totalSessions, 0);
    assert.equal(profile.totalEvents, 0);
    assert.equal(profile.totalDenies, 0);
    assert.equal(profile.totalAllows, 0);
    assert.equal(profile.totalAsks, 0);
    assert.equal(profile.maturityLevel, "insufficient");
    assert.equal(profile.riskDistribution.mean, 0);
    assert.equal(profile.techniqueFrequencies.length, 0);
    assert.equal(profile.temporalProfile.hourlyActivity.length, 24);
    assert.equal(profile.whyHistory.length, 0);
    assert.equal(profile._riskScores.length, 0);
    assert.ok(profile.createdAt);
    assert.ok(profile.updatedAt);
  });
});

// ---------------------------------------------------------------------------
// calculateMaturity
// ---------------------------------------------------------------------------

describe("calculateMaturity", () => {
  it("returns insufficient for < 10 sessions", () => {
    assert.equal(calculateMaturity(0), "insufficient");
    assert.equal(calculateMaturity(5), "insufficient");
    assert.equal(calculateMaturity(9), "insufficient");
  });

  it("returns developing for 10-49 sessions", () => {
    assert.equal(calculateMaturity(10), "developing");
    assert.equal(calculateMaturity(49), "developing");
  });

  it("returns established for 50-199 sessions", () => {
    assert.equal(calculateMaturity(50), "established");
    assert.equal(calculateMaturity(199), "established");
  });

  it("returns mature for 200+ sessions", () => {
    assert.equal(calculateMaturity(200), "mature");
    assert.equal(calculateMaturity(1000), "mature");
  });
});

// ---------------------------------------------------------------------------
// calculateRiskDistribution
// ---------------------------------------------------------------------------

describe("calculateRiskDistribution", () => {
  it("computes correct mean", () => {
    const dist = calculateRiskDistribution([10, 20, 30, 40, 50]);
    assert.equal(dist.mean, 30);
  });

  it("computes correct p95", () => {
    // 20 values: 1..20. p95 index = ceil(0.95*20)-1 = 19-1 = 18 => sorted[18] = 19
    const scores = Array.from({ length: 20 }, (_, i) => i + 1);
    const dist = calculateRiskDistribution(scores);
    assert.equal(dist.p95, 19);
  });

  it("returns zeros for empty array", () => {
    const dist = calculateRiskDistribution([]);
    assert.equal(dist.mean, 0);
    assert.equal(dist.p95, 0);
    assert.equal(dist.stddev, 0);
    assert.equal(dist.sampleCount, 0);
  });
});

// ---------------------------------------------------------------------------
// recalculateProfile
// ---------------------------------------------------------------------------

describe("recalculateProfile", () => {
  it("updates maturityLevel based on totalSessions", () => {
    const profile = mockProfile({ totalSessions: 5, maturityLevel: "insufficient" });
    const result = recalculateProfile(profile);
    assert.equal(result.maturityLevel, "insufficient");

    profile.totalSessions = 60;
    const result2 = recalculateProfile(profile);
    assert.equal(result2.maturityLevel, "established");
  });

  it("computes thresholds.riskScoreUpperBound = mean + 2*stddev", () => {
    // Use scores where mean=20, stddev is calculable
    const scores = [10, 20, 30, 10, 20, 30, 10, 20, 30, 20];
    const profile = mockProfile({ _riskScores: scores, totalSessions: 60 });
    const result = recalculateProfile(profile);

    // mean = 20, variance = sum((x-20)^2)/10 = (100+0+100+100+0+100+100+0+100+0)/10 = 60
    // stddev = sqrt(60) ≈ 7.75
    const expectedUpper = Math.min(100, result.riskDistribution.mean + 2 * result.riskDistribution.stddev);
    assert.equal(
      result.thresholds.riskScoreUpperBound,
      Math.round(expectedUpper * 100) / 100,
    );
  });
});

// ---------------------------------------------------------------------------
// ingestEntry
// ---------------------------------------------------------------------------

describe("ingestEntry", () => {
  it("creates new profile for unknown agentId", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    const entry = mockAuditEntry({ agentId: "did:atlas:new-agent", verdict: "allow" });
    const profile = await ingestEntry(entry, store);

    assert.equal(profile.agentId, "did:atlas:new-agent");
    assert.equal(profile.totalEvents, 1);

    // Verify it was persisted
    const stored = await store.get("did:atlas:new-agent");
    assert.ok(stored);
  });

  it("increments totalEvents", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    const entry1 = mockAuditEntry({ agentId: "did:atlas:counter", verdict: "allow" });
    await ingestEntry(entry1, store);

    const entry2 = mockAuditEntry({ agentId: "did:atlas:counter", verdict: "allow" });
    const profile = await ingestEntry(entry2, store);

    assert.equal(profile.totalEvents, 2);
  });

  it("increments totalDenies for deny verdict entries", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    const entry = mockAuditEntry({
      agentId: "did:atlas:deny-test",
      verdict: "deny",
      event: "POLICY_DENY",
    });
    const profile = await ingestEntry(entry, store);

    assert.equal(profile.totalDenies, 1);
    assert.equal(profile.totalAllows, 0);
  });

  it("updates techniqueFrequencies for MITRE entries", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    const entry = mockAuditEntry({
      agentId: "did:atlas:mitre-test",
      verdict: "allow",
      mitre: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    });
    const profile = await ingestEntry(entry, store);

    assert.equal(profile.techniqueFrequencies.length, 1);
    assert.equal(profile.techniqueFrequencies[0].techniqueId, "T1059");
    assert.equal(profile.techniqueFrequencies[0].count, 1);
  });

  it("updates hourlyActivity in temporalProfile", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    // Use a specific timestamp so we know the hour
    const ts = "2026-03-28T14:30:00.000Z"; // UTC hour 14
    const entry = mockAuditEntry({
      agentId: "did:atlas:temporal-test",
      timestamp: ts,
      verdict: "allow",
    });
    const profile = await ingestEntry(entry, store);

    assert.equal(profile.temporalProfile.hourlyActivity[14], 1);
  });
});

// ---------------------------------------------------------------------------
// detectDrift
// ---------------------------------------------------------------------------

describe("detectDrift", () => {
  it("returns no signals for normal behavior", () => {
    const baseline = mockProfile();
    const entry = mockAuditEntry({
      agentId: baseline.agentId,
      timestamp: "2026-03-28T12:00:00.000Z", // hour 12, within normal hours
      mitre: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    });
    const assessment: ExpertAssessment = {
      expert: "anomaly",
      finding: "Normal behavior",
      confidence: "low",
      signals: [],
      riskScore: 25,
    };

    const drift = detectDrift([entry], assessment, baseline);

    assert.equal(drift.driftDetected, false);
    assert.equal(drift.signals.length, 0);
    assert.equal(drift.overallDriftSeverity, "none");
    assert.equal(drift.recommendation, "allow");
  });

  it("returns RISK_SCORE_ELEVATED when current > upperBound", () => {
    const baseline = mockProfile();
    const entry = mockAuditEntry({
      agentId: baseline.agentId,
      timestamp: "2026-03-28T12:00:00.000Z",
    });
    const assessment: ExpertAssessment = {
      expert: "anomaly",
      finding: "Elevated risk",
      confidence: "medium",
      signals: ["suspicious_pattern"],
      riskScore: 45, // > upperBound (40) but < critical (50)
    };

    const drift = detectDrift([entry], assessment, baseline);

    assert.equal(drift.driftDetected, true);
    const riskSignal = drift.signals.find(s => s.dimension === "RISK_SCORE_ELEVATED");
    assert.ok(riskSignal);
    assert.equal(riskSignal.severity, "medium");
  });

  it("returns NEW_TECHNIQUE_OBSERVED for unseen technique", () => {
    const baseline = mockProfile();
    const entry = mockAuditEntry({
      agentId: baseline.agentId,
      timestamp: "2026-03-28T12:00:00.000Z",
      mitre: { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    });
    const assessment: ExpertAssessment = {
      expert: "anomaly",
      finding: "New technique",
      confidence: "medium",
      signals: [],
      riskScore: 25,
    };

    const drift = detectDrift([entry], assessment, baseline);

    assert.equal(drift.driftDetected, true);
    const techSignal = drift.signals.find(s => s.dimension === "NEW_TECHNIQUE_OBSERVED");
    assert.ok(techSignal);
    assert.ok(techSignal.currentValue.includes("T1190"));
  });

  it("returns overallDriftSeverity critical for critical-level signal", () => {
    const baseline = mockProfile();
    const entry = mockAuditEntry({
      agentId: baseline.agentId,
      timestamp: "2026-03-28T12:00:00.000Z",
    });
    const assessment: ExpertAssessment = {
      expert: "anomaly",
      finding: "Critical risk",
      confidence: "high",
      signals: ["critical_anomaly"],
      riskScore: 55, // > riskScoreCritical (50)
    };

    const drift = detectDrift([entry], assessment, baseline);

    assert.equal(drift.driftDetected, true);
    const riskSignal = drift.signals.find(s => s.dimension === "RISK_SCORE_ELEVATED");
    assert.ok(riskSignal);
    assert.equal(riskSignal.severity, "critical");
    assert.equal(drift.overallDriftSeverity, "critical");
    assert.equal(drift.recommendation, "block");
  });

  it("returns no drift for insufficient baseline maturity", () => {
    const baseline = mockProfile({ maturityLevel: "insufficient", totalSessions: 3 });
    const entry = mockAuditEntry({ agentId: baseline.agentId });
    const assessment: ExpertAssessment = {
      expert: "anomaly",
      finding: "Something wild",
      confidence: "high",
      signals: ["big_anomaly"],
      riskScore: 90,
    };

    const drift = detectDrift([entry], assessment, baseline);

    assert.equal(drift.driftDetected, false);
    assert.equal(drift.overallDriftSeverity, "none");
    assert.equal(drift.recommendation, "allow");
  });
});

// ---------------------------------------------------------------------------
// getBaselineContext
// ---------------------------------------------------------------------------

describe("getBaselineContext", () => {
  it("returns empty string for insufficient baseline", () => {
    const profile = mockProfile({ maturityLevel: "insufficient" });
    assert.equal(getBaselineContext(profile), "");
  });

  it("returns empty string for undefined profile", () => {
    assert.equal(getBaselineContext(undefined), "");
  });

  it("returns structured string for established baseline", () => {
    const profile = mockProfile({ maturityLevel: "established", totalSessions: 75 });
    const ctx = getBaselineContext(profile);

    assert.ok(ctx.includes("AGENT BASELINE"));
    assert.ok(ctx.includes("established"));
    assert.ok(ctx.includes("75 sessions"));
    assert.ok(ctx.includes("Typical risk score"));
    assert.ok(ctx.includes("Common techniques"));
    assert.ok(ctx.includes("Temporal"));
  });
});

// ---------------------------------------------------------------------------
// ingestAssessment
// ---------------------------------------------------------------------------

describe("ingestAssessment", () => {
  it("appends to whyHistory with real store", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    // Create a profile first via ingestEntry
    const entry = mockAuditEntry({ agentId: "did:atlas:assess-test", verdict: "allow" });
    await ingestEntry(entry, store);

    const assessment = {
      windowSummary: "1 event over 0 minutes",
      expertAssessments: [],
      synthesis: "Test synthesis",
      overallRisk: "low" as const,
      overallRiskScore: 15,
      recommendedAction: "allow" as const,
      anomalyDetected: false,
      inferredIntent: "Normal operation",
      threatNarrative: "No threat",
      generatedAt: new Date().toISOString(),
      modelUsed: "test",
      researchArtifact: {
        eventCount: 1,
        uniqueAgents: [],
        uniqueTechniques: [],
        tacticsObserved: [],
        riskProgression: [0],
        anomalySignals: [],
        temporalPattern: "steady" as const,
      },
    };

    await ingestAssessment("did:atlas:assess-test", assessment, "TEST_TRIGGER", store);

    const profile = await store.get("did:atlas:assess-test");
    assert.ok(profile);
    assert.equal(profile.whyHistory.length, 1);
    assert.equal(profile.whyHistory[0].overallRisk, "low");
    assert.equal(profile.whyHistory[0].triggerReason, "TEST_TRIGGER");
    assert.equal(profile.whyHistory[0].inferredIntent, "Normal operation");
  });
});
