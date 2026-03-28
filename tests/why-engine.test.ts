/**
 * Tests for Fidelis Channel — Why Engine (v0.6.0)
 *
 * Covers: buildResearchArtifact, synthesize, assessWindow, stubAssessment
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildResearchArtifact,
  synthesize,
  assessWindow,
  stubAssessment,
} from "../src/why-engine.js";
import type { ExpertAssessment, AuditEventWindow } from "../src/why-engine.js";
import type { AuditEntry } from "../src/audit-log.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let seq = 0;

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  seq++;
  return {
    id: `test-${seq}`,
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    event: overrides.event ?? "POLICY_DENY",
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

// ---------------------------------------------------------------------------
// buildResearchArtifact
// ---------------------------------------------------------------------------

describe("buildResearchArtifact", () => {
  it("extracts unique techniques from entries", () => {
    const entries = [
      makeEntry({ mitre: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" } }),
      makeEntry({ mitre: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" } }),
      makeEntry({ mitre: { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access" } }),
    ];

    const artifact = buildResearchArtifact(entries);
    assert.deepEqual(artifact.uniqueTechniques, ["T1059", "T1003"]);
  });

  it("calculates riskProgression array", () => {
    const entries = [
      makeEntry({
        policy_result: { verdict: "deny", matched_rule: null, anomaly_flags: ["FLAG_A"], sensitivity_matches: [], identity_evaluated: false },
      }),
      makeEntry({
        policy_result: { verdict: "deny", matched_rule: null, anomaly_flags: ["FLAG_A", "FLAG_B"], sensitivity_matches: [], identity_evaluated: false },
      }),
      makeEntry({}),
    ];

    const artifact = buildResearchArtifact(entries);
    assert.equal(artifact.riskProgression.length, 3);
    assert.equal(artifact.riskProgression[0], 10); // 1 flag * 10
    assert.equal(artifact.riskProgression[1], 20); // 2 flags * 10
    assert.equal(artifact.riskProgression[2], 0);  // no flags
  });

  it("identifies temporalPattern: burst (entries span < 2 minutes)", () => {
    const now = Date.now();
    const entries = [
      makeEntry({ timestamp: new Date(now).toISOString() }),
      makeEntry({ timestamp: new Date(now + 30_000).toISOString() }), // +30s
      makeEntry({ timestamp: new Date(now + 60_000).toISOString() }), // +60s
    ];

    const artifact = buildResearchArtifact(entries);
    assert.equal(artifact.temporalPattern, "burst");
  });

  it("identifies temporalPattern: escalating (increasing risk scores)", () => {
    const now = Date.now();
    const entries = [
      makeEntry({
        timestamp: new Date(now).toISOString(),
        policy_result: { verdict: "deny", matched_rule: null, anomaly_flags: ["A"], sensitivity_matches: [], identity_evaluated: false },
      }),
      makeEntry({
        timestamp: new Date(now + 5 * 60_000).toISOString(),
        policy_result: { verdict: "deny", matched_rule: null, anomaly_flags: ["A", "B"], sensitivity_matches: [], identity_evaluated: false },
      }),
      makeEntry({
        timestamp: new Date(now + 10 * 60_000).toISOString(),
        policy_result: { verdict: "deny", matched_rule: null, anomaly_flags: ["A", "B", "C"], sensitivity_matches: [], identity_evaluated: false },
      }),
    ];

    const artifact = buildResearchArtifact(entries);
    assert.equal(artifact.temporalPattern, "escalating");
  });

  it("identifies temporalPattern: idle (entries span > 30 minutes with < 5 entries)", () => {
    const now = Date.now();
    const entries = [
      makeEntry({ timestamp: new Date(now).toISOString() }),
      makeEntry({ timestamp: new Date(now + 35 * 60_000).toISOString() }),
    ];

    const artifact = buildResearchArtifact(entries);
    assert.equal(artifact.temporalPattern, "idle");
  });

  it("identifies temporalPattern: steady (default)", () => {
    const now = Date.now();
    // Span > 2 min, >= 5 entries, non-escalating risk
    const entries = [
      makeEntry({ timestamp: new Date(now).toISOString() }),
      makeEntry({ timestamp: new Date(now + 3 * 60_000).toISOString() }),
      makeEntry({ timestamp: new Date(now + 6 * 60_000).toISOString() }),
      makeEntry({ timestamp: new Date(now + 9 * 60_000).toISOString() }),
      makeEntry({ timestamp: new Date(now + 12 * 60_000).toISOString() }),
    ];

    const artifact = buildResearchArtifact(entries);
    assert.equal(artifact.temporalPattern, "steady");
  });
});

// ---------------------------------------------------------------------------
// synthesize
// ---------------------------------------------------------------------------

describe("synthesize", () => {
  it("returns overallRisk critical when avg score > 80", () => {
    const experts = [
      makeExpert("anomaly", { riskScore: 90 }),
      makeExpert("intent", { riskScore: 85 }),
      makeExpert("threat", { riskScore: 80 }),
    ];
    const entries = [makeEntry()];

    const result = synthesize(experts, entries);
    // Weighted: 90*0.4 + 85*0.3 + 80*0.3 = 36 + 25.5 + 24 = 85.5 -> 86
    assert.equal(result.overallRisk, "critical");
  });

  it("returns overallRisk nominal for low-score experts", () => {
    const experts = [
      makeExpert("anomaly", { riskScore: 5 }),
      makeExpert("intent", { riskScore: 10 }),
      makeExpert("threat", { riskScore: 5 }),
    ];
    const entries = [makeEntry()];

    const result = synthesize(experts, entries);
    // Weighted: 5*0.4 + 10*0.3 + 5*0.3 = 2 + 3 + 1.5 = 6.5 -> 7
    assert.equal(result.overallRisk, "nominal");
  });

  it("recommendedAction is block for critical risk", () => {
    const experts = [
      makeExpert("anomaly", { riskScore: 95 }),
      makeExpert("intent", { riskScore: 90 }),
      makeExpert("threat", { riskScore: 85 }),
    ];
    const entries = [makeEntry()];

    const result = synthesize(experts, entries);
    assert.equal(result.recommendedAction, "block");
  });

  it("recommendedAction is allow for nominal risk", () => {
    const experts = [
      makeExpert("anomaly", { riskScore: 5 }),
      makeExpert("intent", { riskScore: 5 }),
      makeExpert("threat", { riskScore: 5 }),
    ];
    const entries = [makeEntry()];

    const result = synthesize(experts, entries);
    assert.equal(result.recommendedAction, "allow");
  });

  it("anomalyDetected is true when anomaly expert confidence is high", () => {
    const experts = [
      makeExpert("anomaly", { confidence: "high", riskScore: 30 }),
      makeExpert("intent", { riskScore: 10 }),
      makeExpert("threat", { riskScore: 10 }),
    ];
    const entries = [makeEntry()];

    const result = synthesize(experts, entries);
    assert.equal(result.anomalyDetected, true);
  });

  it("anomalyDetected is true when anomaly expert riskScore > 60", () => {
    const experts = [
      makeExpert("anomaly", { confidence: "low", riskScore: 65 }),
      makeExpert("intent", { riskScore: 10 }),
      makeExpert("threat", { riskScore: 10 }),
    ];
    const entries = [makeEntry()];

    const result = synthesize(experts, entries);
    assert.equal(result.anomalyDetected, true);
  });
});

// ---------------------------------------------------------------------------
// assessWindow
// ---------------------------------------------------------------------------

describe("assessWindow", () => {
  it("returns stub when Ollama is unavailable (no throw)", async () => {
    const window: AuditEventWindow = {
      entries: [makeEntry()],
    };

    const result = await assessWindow(window, {
      model: "qwen2.5:3b",
      baseUrl: "http://localhost:99999",
      windowSize: 20,
      windowMinutes: 60,
      enabled: true,
      parallelExperts: true,
    });

    // Should not throw; returns a valid WhyAssessment
    assert.ok(result);
    assert.ok(typeof result.overallRisk === "string");
    assert.ok(typeof result.synthesis === "string");
  });

  it("assessWindow stub has overallRisk nominal when disabled", async () => {
    const window: AuditEventWindow = {
      entries: [makeEntry()],
    };

    const result = await assessWindow(window, {
      model: "qwen2.5:3b",
      baseUrl: "http://localhost:99999",
      windowSize: 20,
      windowMinutes: 60,
      enabled: false,
      parallelExperts: true,
    });

    assert.equal(result.overallRisk, "nominal");
    assert.equal(result.recommendedAction, "allow");
  });
});

// ---------------------------------------------------------------------------
// stubAssessment
// ---------------------------------------------------------------------------

describe("stubAssessment", () => {
  it("returns correct structure", () => {
    const entries = [makeEntry(), makeEntry()];
    const stub = stubAssessment("Engine unavailable", entries);

    assert.equal(stub.overallRisk, "nominal");
    assert.equal(stub.overallRiskScore, 0);
    assert.equal(stub.recommendedAction, "allow");
    assert.equal(stub.anomalyDetected, false);
    assert.equal(stub.modelUsed, "none");
    assert.deepEqual(stub.expertAssessments, []);
    assert.equal(stub.synthesis, "Engine unavailable");
    assert.equal(stub.windowSummary, "2 events (stub)");
    assert.ok(stub.generatedAt);
    assert.ok(stub.researchArtifact);
    assert.equal(stub.researchArtifact.eventCount, 2);
  });
});
