/**
 * Tests for Atlas Protocol — Quiet Mode (v0.8.0)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkQuietEligibility } from "../src/quiet-mode.js";
import type { QuietModeConfig } from "../src/quiet-mode.js";
import type { PermissionRequest, PolicyResult } from "../src/policy-engine.js";
import type { AttestationResult } from "../src/attestation.js";
import type { BaselineProfile } from "../src/baseline-types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides: Partial<QuietModeConfig> = {}): QuietModeConfig {
  return {
    enabled: true,
    min_maturity: "mature",
    max_anomaly_flags: 0,
    quiet_tools: new Set(["Read", "Glob", "Grep"]),
    ...overrides,
  };
}

function makeReq(tool: string, input: string): PermissionRequest {
  return {
    request_id: "test-quiet",
    tool_name: tool,
    description: "test",
    input_preview: input,
  };
}

function makePolicyResult(overrides: Partial<PolicyResult> = {}): PolicyResult {
  return {
    verdict: "ask",
    matched_rule: null,
    anomaly_flags: [],
    sensitivity_matches: [],
    identity_evaluated: false,
    ...overrides,
  };
}

function makeAttestation(verified = true): AttestationResult {
  return {
    agentId: "did:atlas:test-agent",
    identityVerified: verified,
    credentialExpiry: new Date(Date.now() + 86400_000).toISOString(),
    role: "claude-code",
    capabilities: ["file:read"],
  };
}

function makeBaseline(maturity: string = "mature", sessions: number = 250): BaselineProfile {
  return {
    agentId: "did:atlas:test-agent",
    agentName: "test",
    agentRole: "claude-code",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    version: "0.8.0",
    totalSessions: sessions,
    totalEvents: sessions * 20,
    totalDenies: 10,
    totalAllows: sessions * 15,
    totalAsks: sessions * 5,
    maturityLevel: maturity as any,
    riskDistribution: {
      min: 0, max: 30, mean: 10, p50: 8, p75: 15, p95: 25, p99: 30, stddev: 5, sampleCount: sessions,
    },
    techniqueFrequencies: [],
    capabilityUsage: [],
    temporalProfile: {
      hourlyActivity: new Array(24).fill(10),
      dailyActivity: new Array(7).fill(50),
      dominantPattern: "steady",
      avgSessionDurationMinutes: 30,
      avgEventsPerSession: 20,
      longestSessionMinutes: 120,
    },
    delegationProfile: {
      totalDelegationsIssued: 0,
      totalDelegationsReceived: 0,
      maxDepthUsed: 0,
      cascadeRevocations: 0,
      avgChildCapabilityReduction: 0,
    },
    whyHistory: [],
    thresholds: {
      riskScoreUpperBound: 20,
      riskScoreCritical: 25,
      maxDenyRatioPerCapability: 0.1,
      expectedTechniques: [],
      unexpectedTechniqueAlert: false,
    },
    _riskScores: [],
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Quiet Mode — eligibility checks", () => {
  it("approves Read of non-sensitive file for mature agent", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Read", "/home/user/project/src/index.ts"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline()
    );
    assert.equal(result.eligible, true);
  });

  it("approves Glob search for mature agent", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Glob", "**/*.ts"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline()
    );
    assert.equal(result.eligible, true);
  });

  it("approves Grep search for mature agent", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Grep", "function handleRequest"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline()
    );
    assert.equal(result.eligible, true);
  });

  it("rejects when quiet mode is disabled", () => {
    const result = checkQuietEligibility(
      makeConfig({ enabled: false }),
      makeReq("Read", "/home/user/src/index.ts"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline()
    );
    assert.equal(result.eligible, false);
    assert.ok(result.reason?.includes("disabled"));
  });

  it("rejects Bash tool (not in quiet set)", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Bash", "ls -la"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline()
    );
    assert.equal(result.eligible, false);
    assert.ok(result.reason?.includes("not in quiet"));
  });

  it("rejects Write tool (not in quiet set)", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Write", "/home/user/src/new.ts"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline()
    );
    assert.equal(result.eligible, false);
  });

  it("rejects when agent has anomaly flags", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Read", "/tmp/test.txt"),
      makePolicyResult({ anomaly_flags: ["SENSITIVE_ACCESS: token detected"] }),
      makeAttestation(),
      makeBaseline()
    );
    assert.equal(result.eligible, false);
    assert.ok(result.reason?.includes("anomaly"));
  });

  it("rejects for insufficient maturity", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Read", "/tmp/test.txt"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline("developing", 30)
    );
    assert.equal(result.eligible, false);
    assert.ok(result.reason?.includes("maturity"));
  });

  it("rejects for established maturity when min is mature", () => {
    const result = checkQuietEligibility(
      makeConfig({ min_maturity: "mature" }),
      makeReq("Read", "/tmp/test.txt"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline("established", 100)
    );
    assert.equal(result.eligible, false);
  });

  it("accepts established maturity when min is established", () => {
    const result = checkQuietEligibility(
      makeConfig({ min_maturity: "established" }),
      makeReq("Read", "/tmp/test.txt"),
      makePolicyResult(),
      makeAttestation(),
      makeBaseline("established", 100)
    );
    assert.equal(result.eligible, true);
  });

  it("rejects when identity not verified", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Read", "/tmp/test.txt"),
      makePolicyResult(),
      makeAttestation(false),
      makeBaseline()
    );
    assert.equal(result.eligible, false);
    assert.ok(result.reason?.includes("identity"));
  });

  it("rejects when no baseline exists", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Read", "/tmp/test.txt"),
      makePolicyResult(),
      makeAttestation(),
      null
    );
    assert.equal(result.eligible, false);
    assert.ok(result.reason?.includes("baseline"));
  });

  it("rejects when verdict is deny (not ask)", () => {
    const result = checkQuietEligibility(
      makeConfig(),
      makeReq("Read", "/tmp/test.txt"),
      makePolicyResult({ verdict: "deny" }),
      makeAttestation(),
      makeBaseline()
    );
    assert.equal(result.eligible, false);
  });
});

describe("Quiet Mode — sensitive path detection", () => {
  const config = makeConfig();
  const policy = makePolicyResult();
  const attest = makeAttestation();
  const baseline = makeBaseline();

  it("rejects Read of .env file", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/home/user/.env"), policy, attest, baseline);
    assert.equal(r.eligible, false);
    assert.ok(r.reason?.includes("sensitive"));
  });

  it("rejects Read of .ssh directory", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/home/user/.ssh/config"), policy, attest, baseline);
    assert.equal(r.eligible, false);
  });

  it("rejects Read of credentials file", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/data/credentials.json"), policy, attest, baseline);
    assert.equal(r.eligible, false);
  });

  it("rejects Read of token file", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/app/auth-token.json"), policy, attest, baseline);
    assert.equal(r.eligible, false);
  });

  it("rejects Read of api_key file", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/config/api_key.txt"), policy, attest, baseline);
    assert.equal(r.eligible, false);
  });

  it("rejects Read of .pem key", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/certs/server.pem"), policy, attest, baseline);
    assert.equal(r.eligible, false);
  });

  it("rejects Read of /etc paths", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/etc/hosts"), policy, attest, baseline);
    assert.equal(r.eligible, false);
  });

  it("allows Read of normal source file", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/home/user/project/src/main.ts"), policy, attest, baseline);
    assert.equal(r.eligible, true);
  });

  it("allows Read of package.json", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/home/user/project/package.json"), policy, attest, baseline);
    assert.equal(r.eligible, true);
  });

  it("allows Read of README", () => {
    const r = checkQuietEligibility(config, makeReq("Read", "/home/user/project/README.md"), policy, attest, baseline);
    assert.equal(r.eligible, true);
  });
});
