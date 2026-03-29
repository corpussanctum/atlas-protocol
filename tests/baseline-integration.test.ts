/**
 * Tests for Atlas Protocol — Baseline Integration (v0.7.0)
 *
 * Full-flow integration tests: ingest entries, build baselines,
 * drift detection, synthesize with drift, formatTelegramAlert.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createEmptyProfile,
  ingestEntry,
  ingestAssessment,
  calculateRiskDistribution,
  getBaselineContext,
} from "../src/baseline-engine.js";
import { BaselineStore } from "../src/baseline-store.js";
import { synthesize } from "../src/why-engine.js";
import { formatTelegramAlert } from "../src/why-triggers.js";
import type { ExpertAssessment, WhyAssessment } from "../src/why-engine.js";
import type { AuditEntry } from "../src/audit-log.js";
import type { BaselineProfile, DriftAssessment } from "../src/baseline-types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "atlas-integration-test-"));
}

let seq = 0;

function mockAuditEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  seq++;
  return {
    id: `int-test-${seq}`,
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    event: overrides.event ?? "POLICY_ALLOW",
    prev_hash: overrides.prev_hash ?? "GENESIS",
    ...overrides,
  } as AuditEntry;
}

function makeExpert(
  expert: ExpertAssessment["expert"],
  overrides: Partial<ExpertAssessment> = {},
): ExpertAssessment {
  return {
    expert,
    finding: overrides.finding ?? "Test finding",
    confidence: overrides.confidence ?? "medium",
    signals: overrides.signals ?? [],
    riskScore: overrides.riskScore ?? 25,
  };
}

function makeDriftAssessment(overrides: Partial<DriftAssessment> = {}): DriftAssessment {
  return {
    agentId: overrides.agentId ?? "did:atlas:test-agent",
    assessedAt: overrides.assessedAt ?? new Date().toISOString(),
    baselineMaturity: overrides.baselineMaturity ?? "established",
    driftDetected: overrides.driftDetected ?? false,
    signals: overrides.signals ?? [],
    overallDriftSeverity: overrides.overallDriftSeverity ?? "none",
    recommendation: overrides.recommendation ?? "allow",
    baselineSnapshot: overrides.baselineSnapshot ?? {
      meanRiskScore: 20,
      p95RiskScore: 40,
      totalSessions: 60,
    },
  };
}

function makeBaseline(overrides: Partial<BaselineProfile> = {}): BaselineProfile {
  const now = new Date().toISOString();
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
    techniqueFrequencies: overrides.techniqueFrequencies ?? [],
    capabilityUsage: overrides.capabilityUsage ?? [],
    temporalProfile: overrides.temporalProfile ?? {
      hourlyActivity: Array(24).fill(0) as number[],
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
      expectedTechniques: [],
      unexpectedTechniqueAlert: false,
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
// Integration tests
// ---------------------------------------------------------------------------

describe("Baseline Integration", () => {
  it("full flow: ingest 10 entries changes maturity to developing", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    // Ingest entries that also increment totalSessions via recalculation
    // Note: ingestEntry increments totalEvents, not totalSessions.
    // To get "developing" maturity, we need totalSessions >= 10.
    // We manually create a profile with totalSessions=9 then ingest one more
    // and manually set totalSessions.
    const profile = createEmptyProfile("did:atlas:flow-test", "Flow Agent", "assistant");
    profile.totalSessions = 9;
    await store.save(profile);

    // Ingest an entry — this triggers recalculation
    const entry = mockAuditEntry({ agentId: "did:atlas:flow-test", verdict: "allow" });
    const result = await ingestEntry(entry, store);

    // Still insufficient because totalSessions is 9 (ingestEntry does not increment sessions)
    assert.equal(result.maturityLevel, "insufficient");

    // Now set totalSessions to 10 and re-save to simulate session boundary
    result.totalSessions = 10;
    await store.save(result);

    // Ingest another to trigger recalculation
    const entry2 = mockAuditEntry({ agentId: "did:atlas:flow-test", verdict: "allow" });
    const result2 = await ingestEntry(entry2, store);
    assert.equal(result2.maturityLevel, "developing");
  });

  it("baseline context string includes session count for established baseline", () => {
    const baseline = makeBaseline({ maturityLevel: "established", totalSessions: 75 });
    const ctx = getBaselineContext(baseline);

    assert.ok(ctx.includes("75 sessions"));
    assert.ok(ctx.includes("established"));
  });

  it("ResearchArtifact includes baselineMaturity field when baseline provided", () => {
    const experts = [
      makeExpert("anomaly", { riskScore: 30 }),
      makeExpert("intent", { riskScore: 20 }),
      makeExpert("threat", { riskScore: 25 }),
    ];
    const entries = [mockAuditEntry()];
    const baseline = makeBaseline({ maturityLevel: "established", totalSessions: 80 });

    const result = synthesize(experts, entries, undefined, baseline);

    assert.equal(result.researchArtifact.baselineMaturity, "established");
    assert.equal(result.researchArtifact.baselineSessions, 80);
  });

  it("ResearchArtifact includes riskScoreVsBaseline when baseline exists", () => {
    const experts = [
      makeExpert("anomaly", { riskScore: 40 }),
      makeExpert("intent", { riskScore: 30 }),
      makeExpert("threat", { riskScore: 35 }),
    ];
    const entries = [mockAuditEntry()];
    const baseline = makeBaseline({
      maturityLevel: "established",
      riskDistribution: {
        min: 0, max: 50, mean: 20, p50: 18, p75: 28, p95: 40, p99: 48,
        stddev: 10, sampleCount: 500,
      },
    });

    const result = synthesize(experts, entries, undefined, baseline);

    assert.ok(result.researchArtifact.riskScoreVsBaseline);
    assert.equal(result.researchArtifact.riskScoreVsBaseline.baselineMean, 20);
    assert.equal(typeof result.researchArtifact.riskScoreVsBaseline.deviationFactor, "number");
  });

  it("drift signal elevates overallRisk in synthesize() output", () => {
    const experts = [
      makeExpert("anomaly", { riskScore: 30 }),
      makeExpert("intent", { riskScore: 20 }),
      makeExpert("threat", { riskScore: 25 }),
    ];
    const entries = [mockAuditEntry()];

    // Without drift: weighted = 30*0.4+20*0.3+25*0.3 = 12+6+7.5 = 25.5 -> 26 -> "low"
    const resultNoDrift = synthesize(experts, entries);
    assert.equal(resultNoDrift.overallRisk, "low");

    // With high drift: should elevate
    const drift = makeDriftAssessment({
      driftDetected: true,
      overallDriftSeverity: "high",
      signals: [{
        dimension: "RISK_SCORE_ELEVATED",
        severity: "high",
        currentValue: "45",
        baselineValue: "mean=20, upper=40",
        deviationFactor: 2.5,
        description: "Risk score 45 exceeds upper bound 40",
      }],
    });

    const resultWithDrift = synthesize(experts, entries, drift);
    assert.equal(resultWithDrift.overallRisk, "high");
    assert.equal(resultWithDrift.anomalyDetected, true);
  });

  it("synthesize without drift does not modify risk", () => {
    const experts = [
      makeExpert("anomaly", { riskScore: 30 }),
      makeExpert("intent", { riskScore: 20 }),
      makeExpert("threat", { riskScore: 25 }),
    ];
    const entries = [mockAuditEntry()];

    const result = synthesize(experts, entries);
    // Weighted: 30*0.4+20*0.3+25*0.3 = 25.5 -> 26 -> "low"
    assert.equal(result.overallRisk, "low");
    assert.equal(result.researchArtifact.driftDetected, undefined);
    assert.equal(result.researchArtifact.driftSignals, undefined);
  });

  it("formatTelegramAlert includes drift section when driftSignals present", () => {
    const assessment: WhyAssessment = {
      windowSummary: "5 events over 10 minutes",
      expertAssessments: [],
      synthesis: "Elevated risk detected.",
      overallRisk: "high",
      overallRiskScore: 65,
      recommendedAction: "escalate",
      anomalyDetected: true,
      inferredIntent: "Possible reconnaissance",
      threatNarrative: "Agent scanning files",
      generatedAt: new Date().toISOString(),
      modelUsed: "test",
      researchArtifact: {
        eventCount: 5,
        uniqueAgents: ["did:atlas:test"],
        uniqueTechniques: ["T1083"],
        tacticsObserved: ["Discovery"],
        riskProgression: [10, 20, 30, 40, 50],
        anomalySignals: [],
        temporalPattern: "escalating",
        driftDetected: true,
        driftSignals: [
          "RISK_SCORE_ELEVATED: Risk score 45 exceeds upper bound 40",
          "NEW_TECHNIQUE_OBSERVED: 1 technique(s) not in baseline: T1190",
        ],
      },
    };

    const triggerEntry = mockAuditEntry({ event: "POLICY_DENY" });
    const alert = formatTelegramAlert(assessment, triggerEntry);

    assert.ok(alert.includes("BASELINE DRIFT"));
    assert.ok(alert.includes("RISK_SCORE_ELEVATED"));
    assert.ok(alert.includes("NEW_TECHNIQUE_OBSERVED"));
  });

  it("getBaselineContext returns empty for maturity=insufficient", () => {
    const profile = makeBaseline({ maturityLevel: "insufficient" });
    const ctx = getBaselineContext(profile);
    assert.equal(ctx, "");
  });

  it("ingestAssessment caps whyHistory at 100 entries", async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const store = new BaselineStore(dir);

    // Create a profile with 99 whyHistory entries
    const profile = createEmptyProfile("did:atlas:cap-test", "Cap Agent", "assistant");
    profile.totalSessions = 50;
    for (let i = 0; i < 99; i++) {
      profile.whyHistory.push({
        assessedAt: new Date().toISOString(),
        overallRisk: "low",
        overallRiskScore: 10,
        inferredIntent: `Intent ${i}`,
        anomalyDetected: false,
        triggerReason: "TEST",
      });
    }
    await store.save(profile);

    // Ingest 5 more assessments to exceed cap
    for (let i = 0; i < 5; i++) {
      const assessment: WhyAssessment = {
        windowSummary: "test",
        expertAssessments: [],
        synthesis: "test",
        overallRisk: "low",
        overallRiskScore: 15,
        recommendedAction: "allow",
        anomalyDetected: false,
        inferredIntent: `New intent ${i}`,
        threatNarrative: "none",
        generatedAt: new Date().toISOString(),
        modelUsed: "test",
        researchArtifact: {
          eventCount: 1,
          uniqueAgents: [],
          uniqueTechniques: [],
          tacticsObserved: [],
          riskProgression: [0],
          anomalySignals: [],
          temporalPattern: "steady",
        },
      };
      await ingestAssessment("did:atlas:cap-test", assessment, "CAP_TEST", store);
    }

    const result = await store.get("did:atlas:cap-test");
    assert.ok(result);
    assert.ok(result.whyHistory.length <= 100);
  });

  it("calculateRiskDistribution handles single-element array", () => {
    const dist = calculateRiskDistribution([42]);

    assert.equal(dist.mean, 42);
    assert.equal(dist.min, 42);
    assert.equal(dist.max, 42);
    assert.equal(dist.p50, 42);
    assert.equal(dist.p95, 42);
    assert.equal(dist.stddev, 0);
    assert.equal(dist.sampleCount, 1);
  });
});
