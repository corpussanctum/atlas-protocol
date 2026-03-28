/**
 * Tests for Fidelis Channel — Why Triggers (v0.6.0)
 *
 * Covers: shouldTrigger, formatTelegramAlert
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { shouldTrigger, formatTelegramAlert } from "../src/why-triggers.js";
import type { TriggerConfig } from "../src/why-triggers.js";
import type { AuditEntry } from "../src/audit-log.js";
import type { WhyAssessment } from "../src/why-engine.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let seq = 0;

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  seq++;
  return {
    id: `trigger-test-${seq}`,
    timestamp: new Date().toISOString(),
    event: overrides.event ?? "POLICY_DENY",
    prev_hash: "GENESIS",
    ...overrides,
  } as AuditEntry;
}

function makeConfig(overrides: Partial<TriggerConfig> = {}): TriggerConfig {
  return {
    denyThreshold: overrides.denyThreshold ?? 3,
    highRiskTactics: overrides.highRiskTactics ?? [
      "Credential Access",
      "Exfiltration",
      "Command and Control",
      "Defense Evasion",
    ],
    cooldownSeconds: overrides.cooldownSeconds ?? 30,
    driftDetectionEnabled: overrides.driftDetectionEnabled ?? true,
    driftSeverityThreshold: overrides.driftSeverityThreshold ?? "medium",
  };
}

// ---------------------------------------------------------------------------
// shouldTrigger
// ---------------------------------------------------------------------------

describe("shouldTrigger", () => {
  it("returns DENY_THRESHOLD after threshold met", () => {
    const config = makeConfig({ denyThreshold: 3 });
    const recentEntries = [
      makeEntry({ event: "POLICY_DENY" }),
      makeEntry({ event: "POLICY_DENY" }),
      makeEntry({ event: "POLICY_DENY" }),
    ];
    const current = makeEntry({ event: "POLICY_DENY" });

    const result = shouldTrigger(current, recentEntries, config);
    assert.equal(result, "DENY_THRESHOLD");
  });

  it("returns HITL_ESCALATION on HUMAN_APPROVE event", () => {
    const config = makeConfig();
    const current = makeEntry({ event: "HUMAN_APPROVE" });

    const result = shouldTrigger(current, [], config);
    assert.equal(result, "HITL_ESCALATION");
  });

  it("returns HIGH_RISK_TECHNIQUE for matching tactic", () => {
    const config = makeConfig();
    const current = makeEntry({
      event: "POLICY_ALLOW",
      mitre: { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access" },
    });

    const result = shouldTrigger(current, [], config);
    assert.equal(result, "HIGH_RISK_TECHNIQUE");
  });

  it("returns IDENTITY_ANOMALY for UNREGISTERED_AGENT", () => {
    const config = makeConfig();
    const current = makeEntry({
      event: "POLICY_DENY",
      attestationDenyReason: "UNREGISTERED_AGENT",
    });
    // Need recentEntries with fewer denies than threshold so DENY_THRESHOLD doesn't fire first
    const recentEntries = [makeEntry({ event: "POLICY_ALLOW" })];

    const result = shouldTrigger(current, recentEntries, config);
    assert.equal(result, "IDENTITY_ANOMALY");
  });

  it("returns CASCADE_REVOCATION for cascade event", () => {
    const config = makeConfig();
    const current = makeEntry({
      event: "POLICY_ALLOW",
      meta: { event_detail: "CASCADE_REVOCATION" },
    });

    const result = shouldTrigger(current, [], config);
    assert.equal(result, "CASCADE_REVOCATION");
  });

  it("returns null below threshold", () => {
    const config = makeConfig({ denyThreshold: 5 });
    const recentEntries = [
      makeEntry({ event: "POLICY_DENY" }),
      makeEntry({ event: "POLICY_DENY" }),
    ];
    const current = makeEntry({ event: "POLICY_DENY" });

    const result = shouldTrigger(current, recentEntries, config);
    assert.equal(result, null);
  });

  it("respects cooldown (returns null within cooldown window)", () => {
    const config = makeConfig({ cooldownSeconds: 60 });
    const recentEntries = [
      makeEntry({ event: "POLICY_DENY" }),
      makeEntry({ event: "POLICY_DENY" }),
      makeEntry({ event: "POLICY_DENY" }),
    ];
    const current = makeEntry({ event: "POLICY_DENY" });
    const lastAssessmentTime = new Date(); // just now = within cooldown

    const result = shouldTrigger(current, recentEntries, config, lastAssessmentTime);
    assert.equal(result, null);
  });
});

// ---------------------------------------------------------------------------
// formatTelegramAlert
// ---------------------------------------------------------------------------

describe("formatTelegramAlert", () => {
  it("includes synthesis and riskScore", () => {
    const assessment: WhyAssessment = {
      windowSummary: "5 events over 10 minutes",
      expertAssessments: [],
      synthesis: "Agent attempted credential exfiltration across multiple tools",
      overallRisk: "high",
      overallRiskScore: 72,
      recommendedAction: "escalate",
      anomalyDetected: true,
      inferredIntent: "Data exfiltration",
      threatNarrative: "Agent escalated privileges",
      generatedAt: new Date().toISOString(),
      modelUsed: "qwen2.5:3b",
      researchArtifact: {
        eventCount: 5,
        uniqueAgents: ["agent-1"],
        uniqueTechniques: ["T1003"],
        tacticsObserved: ["Credential Access"],
        riskProgression: [10, 20, 30],
        anomalySignals: ["SENSITIVE_ACCESS"],
        temporalPattern: "escalating",
      },
    };
    const triggerEntry = makeEntry({
      event: "POLICY_DENY",
      permission: {
        request_id: "req-1",
        tool_name: "Bash",
        description: "run command",
        input_preview: "cat /etc/shadow",
      },
    });

    const output = formatTelegramAlert(assessment, triggerEntry);

    assert.ok(output.includes("Agent attempted credential exfiltration"));
    assert.ok(output.includes("72"));
    assert.ok(output.includes("HIGH"));
    assert.ok(output.includes("ESCALATE"));
    assert.ok(output.includes("Bash"));
    assert.ok(output.includes("T1003"));
    assert.ok(output.includes("5 events over 10 minutes"));
  });
});
