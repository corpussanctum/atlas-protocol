/**
 * Fidelis Channel — Baseline Engine (v0.7.0)
 *
 * Computation engine for per-agent behavioral baselines. Ingests audit
 * entries and Why assessments, computes derived statistics, and detects
 * behavioral drift from established patterns.
 *
 * Key principles:
 *   - Store derived statistics only, never raw entries (privacy + size)
 *   - Debounce recalculation (every 10th ingest after first 10 sessions)
 *   - Never throw — return gracefully on missing/insufficient baselines
 *   - Fire-and-forget from the gatekeeper hot path
 */

import type { AuditEntry } from "./audit-log.js";
import type { WhyAssessment, ExpertAssessment } from "./why-engine.js";
import type {
  BaselineProfile, RiskDistribution, DriftAssessment, DriftSignal,
  DriftDimension, BaselineThresholds, MaturityLevel,
  TechniqueFrequency, CapabilityUsageProfile,
} from "./baseline-types.js";
import { BaselineStore } from "./baseline-store.js";

// ---------------------------------------------------------------------------
// Tool → capability mapping
// ---------------------------------------------------------------------------

const TOOL_CAPABILITY_MAP: Record<string, string> = {
  Read: "file:read",
  Glob: "file:read",
  Grep: "file:read",
  Write: "file:write",
  Edit: "file:write",
  Bash: "shell:exec",
};

// ---------------------------------------------------------------------------
// 1. createEmptyProfile
// ---------------------------------------------------------------------------

export function createEmptyProfile(
  agentId: string,
  agentName: string,
  agentRole: string,
): BaselineProfile {
  const now = new Date().toISOString();
  return {
    agentId,
    agentName,
    agentRole,
    createdAt: now,
    updatedAt: now,
    version: "0.7.0",
    totalSessions: 0,
    totalEvents: 0,
    totalDenies: 0,
    totalAllows: 0,
    totalAsks: 0,
    riskDistribution: {
      min: 0, max: 0, mean: 0,
      p50: 0, p75: 0, p95: 0, p99: 0,
      stddev: 0, sampleCount: 0,
    },
    techniqueFrequencies: [],
    capabilityUsage: [],
    temporalProfile: {
      hourlyActivity: Array(24).fill(0) as number[],
      dailyActivity: Array(7).fill(0) as number[],
      dominantPattern: "irregular",
      avgSessionDurationMinutes: 0,
      avgEventsPerSession: 0,
      longestSessionMinutes: 0,
    },
    delegationProfile: {
      totalDelegationsIssued: 0,
      totalDelegationsReceived: 0,
      maxDepthUsed: 0,
      cascadeRevocations: 0,
      avgChildCapabilityReduction: 0,
    },
    whyHistory: [],
    maturityLevel: "insufficient",
    thresholds: {
      riskScoreUpperBound: 100,
      riskScoreCritical: 100,
      maxDenyRatioPerCapability: 0.5,
      expectedTechniques: [],
      unexpectedTechniqueAlert: false,
    },
    _riskScores: [],
  };
}

// ---------------------------------------------------------------------------
// 2. calculateMaturity
// ---------------------------------------------------------------------------

export function calculateMaturity(totalSessions: number): MaturityLevel {
  if (totalSessions < 10) return "insufficient";
  if (totalSessions < 50) return "developing";
  if (totalSessions < 200) return "established";
  return "mature";
}

// ---------------------------------------------------------------------------
// 3. calculateRiskDistribution
// ---------------------------------------------------------------------------

export function calculateRiskDistribution(scores: number[]): RiskDistribution {
  if (scores.length === 0) {
    return {
      min: 0, max: 0, mean: 0,
      p50: 0, p75: 0, p95: 0, p99: 0,
      stddev: 0, sampleCount: 0,
    };
  }

  const sorted = [...scores].sort((a, b) => a - b);
  const n = sorted.length;

  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const mean = sum / n;

  const varianceSum = sorted.reduce((acc, v) => acc + (v - mean) ** 2, 0);
  const stddev = Math.sqrt(varianceSum / n);

  const percentile = (p: number): number => {
    const idx = Math.min(Math.max(Math.ceil(p * n) - 1, 0), n - 1);
    return sorted[idx];
  };

  return {
    min: sorted[0],
    max: sorted[n - 1],
    mean: Math.round(mean * 100) / 100,
    p50: percentile(0.5),
    p75: percentile(0.75),
    p95: percentile(0.95),
    p99: percentile(0.99),
    stddev: Math.round(stddev * 100) / 100,
    sampleCount: n,
  };
}

// ---------------------------------------------------------------------------
// 4. calculateThresholds
// ---------------------------------------------------------------------------

export function calculateThresholds(
  riskDist: RiskDistribution,
  techniqueFreqs: TechniqueFrequency[],
): BaselineThresholds {
  const upperBound = Math.min(100, riskDist.mean + 2 * riskDist.stddev);
  const critical = Math.min(100, riskDist.mean + 3 * riskDist.stddev);

  const expectedTechniques = techniqueFreqs
    .filter((t) => t.count >= 3)
    .map((t) => t.techniqueId);

  return {
    riskScoreUpperBound: Math.round(upperBound * 100) / 100,
    riskScoreCritical: Math.round(critical * 100) / 100,
    maxDenyRatioPerCapability: 0.5,
    expectedTechniques,
    unexpectedTechniqueAlert: expectedTechniques.length > 0,
  };
}

// ---------------------------------------------------------------------------
// 5. recalculateProfile
// ---------------------------------------------------------------------------

export function recalculateProfile(profile: BaselineProfile): BaselineProfile {
  profile.riskDistribution = calculateRiskDistribution(profile._riskScores);
  profile.maturityLevel = calculateMaturity(profile.totalSessions);
  profile.thresholds = calculateThresholds(
    profile.riskDistribution,
    profile.techniqueFrequencies,
  );

  // Determine temporal dominant pattern from hourly distribution
  const hourly = profile.temporalProfile.hourlyActivity;
  const totalHourlyEvents = hourly.reduce((a, b) => a + b, 0);

  if (totalHourlyEvents > 0) {
    const nonZeroHours = hourly.filter((h) => h > 0).length;
    const sortedHours = [...hourly].sort((a, b) => b - a);

    // Check burst: >50% of events concentrated in <20% of hours (< 5 hours)
    const top5Sum = sortedHours.slice(0, 5).reduce((a, b) => a + b, 0);
    if (top5Sum > totalHourlyEvents * 0.5 && nonZeroHours <= 5) {
      profile.temporalProfile.dominantPattern = "burst";
    } else if (nonZeroHours > 14) {
      // Activity in >60% of hours
      profile.temporalProfile.dominantPattern = "steady";
    } else {
      profile.temporalProfile.dominantPattern = "irregular";
    }
  }

  profile.updatedAt = new Date().toISOString();
  return profile;
}

// ---------------------------------------------------------------------------
// 6. ingestEntry
// ---------------------------------------------------------------------------

export async function ingestEntry(
  entry: AuditEntry,
  store: BaselineStore,
): Promise<BaselineProfile> {
  const agentId = entry.agentId;
  if (!agentId) {
    return createEmptyProfile("unknown", "unknown", "unknown");
  }

  let profile = await store.get(agentId);
  if (!profile) {
    profile = createEmptyProfile(
      agentId,
      agentId,
      entry.agentRole ?? "unknown",
    );
  }

  // Increment totals
  profile.totalEvents++;

  if (entry.verdict === "deny") {
    profile.totalDenies++;
  } else if (entry.verdict === "allow") {
    profile.totalAllows++;
  } else if (
    entry.event.includes("ASK") ||
    entry.event === "PERMISSION_REQUEST" ||
    (entry.verdict === undefined &&
      entry.event !== "POLICY_DENY" &&
      entry.event !== "POLICY_ALLOW")
  ) {
    profile.totalAsks++;
  }

  // Temporal profile
  const ts = new Date(entry.timestamp);
  profile.temporalProfile.hourlyActivity[ts.getUTCHours()]++;
  profile.temporalProfile.dailyActivity[ts.getUTCDay()]++;

  // MITRE technique frequencies
  if (entry.mitre) {
    const existing = profile.techniqueFrequencies.find(
      (t) => t.techniqueId === entry.mitre!.id,
    );
    if (existing) {
      existing.count++;
      existing.lastSeen = entry.timestamp;
    } else {
      profile.techniqueFrequencies.push({
        techniqueId: entry.mitre.id,
        techniqueName: entry.mitre.name,
        tactic: entry.mitre.tactic,
        count: 1,
        firstSeen: entry.timestamp,
        lastSeen: entry.timestamp,
        trend: "new",
      });
    }
  }

  // Capability usage
  const toolName = entry.permission?.tool_name;
  if (toolName) {
    const capability = TOOL_CAPABILITY_MAP[toolName] ?? `tool:${toolName}`;
    let cap = profile.capabilityUsage.find((c) => c.capability === capability);
    if (!cap) {
      cap = {
        capability,
        allowCount: 0,
        denyCount: 0,
        askCount: 0,
        denyRatio: 0,
        trend: "stable",
      };
      profile.capabilityUsage.push(cap);
    }
    if (entry.verdict === "allow") {
      cap.allowCount++;
    } else if (entry.verdict === "deny") {
      cap.denyCount++;
    } else {
      cap.askCount++;
    }
    const total = cap.allowCount + cap.denyCount + cap.askCount;
    cap.denyRatio = total > 0 ? Math.round((cap.denyCount / total) * 1000) / 1000 : 0;
  }

  // Risk score from anomaly flags
  const anomalyFlags = extractAnomalyFlags(entry);
  const riskScore = Math.min(100, 10 * anomalyFlags.length);
  profile._riskScores.push(riskScore);

  // Cap _riskScores at 10000
  if (profile._riskScores.length > 10000) {
    profile._riskScores = profile._riskScores.slice(
      profile._riskScores.length - 10000,
    );
  }

  // Debounced recalculation
  if (profile.totalEvents <= 100 || profile.totalEvents % 10 === 0) {
    profile = recalculateProfile(profile);
  }

  await store.save(profile);
  return profile;
}

/**
 * Extract anomaly flags from an audit entry (mirrors why-engine's approach).
 */
function extractAnomalyFlags(entry: AuditEntry): string[] {
  const fromPolicy = entry.policy_result?.anomaly_flags ?? [];
  const fromMeta = Array.isArray((entry.meta as Record<string, unknown>)?.flags)
    ? ((entry.meta as Record<string, unknown>).flags as string[])
    : [];
  return [...new Set([...fromPolicy, ...fromMeta])];
}

// ---------------------------------------------------------------------------
// 7. ingestAssessment
// ---------------------------------------------------------------------------

export async function ingestAssessment(
  agentId: string,
  assessment: WhyAssessment,
  triggerReason: string,
  store: BaselineStore,
): Promise<void> {
  const profile = await store.get(agentId);
  if (!profile) return;

  profile.whyHistory.push({
    assessedAt: assessment.generatedAt,
    overallRisk: assessment.overallRisk,
    overallRiskScore: assessment.overallRiskScore,
    inferredIntent: assessment.inferredIntent,
    anomalyDetected: assessment.anomalyDetected,
    triggerReason,
  });

  // Cap at 100 entries
  if (profile.whyHistory.length > 100) {
    profile.whyHistory = profile.whyHistory.slice(
      profile.whyHistory.length - 100,
    );
  }

  // Always recalculate after assessment
  recalculateProfile(profile);

  await store.save(profile);
}

// ---------------------------------------------------------------------------
// 8. detectDrift
// ---------------------------------------------------------------------------

export function detectDrift(
  currentWindow: AuditEntry[],
  currentAssessment: ExpertAssessment,
  baseline: BaselineProfile,
): DriftAssessment {
  const now = new Date().toISOString();
  const base = {
    agentId: baseline.agentId,
    assessedAt: now,
    baselineMaturity: baseline.maturityLevel,
    baselineSnapshot: {
      meanRiskScore: baseline.riskDistribution.mean,
      p95RiskScore: baseline.riskDistribution.p95,
      totalSessions: baseline.totalSessions,
    },
  };

  if (baseline.maturityLevel === "insufficient") {
    return {
      ...base,
      driftDetected: false,
      signals: [],
      overallDriftSeverity: "none",
      recommendation: "allow",
    };
  }

  const signals: DriftSignal[] = [];

  // RISK_SCORE_ELEVATED
  if (currentAssessment.riskScore > baseline.thresholds.riskScoreCritical) {
    signals.push({
      dimension: "RISK_SCORE_ELEVATED" as DriftDimension,
      severity: "critical",
      currentValue: String(currentAssessment.riskScore),
      baselineValue: `mean=${baseline.riskDistribution.mean}, critical=${baseline.thresholds.riskScoreCritical}`,
      deviationFactor: baseline.riskDistribution.stddev > 0
        ? Math.round(((currentAssessment.riskScore - baseline.riskDistribution.mean) / baseline.riskDistribution.stddev) * 100) / 100
        : 0,
      description: `Risk score ${currentAssessment.riskScore} exceeds critical threshold ${baseline.thresholds.riskScoreCritical}`,
    });
  } else if (currentAssessment.riskScore > baseline.thresholds.riskScoreUpperBound) {
    signals.push({
      dimension: "RISK_SCORE_ELEVATED" as DriftDimension,
      severity: "medium",
      currentValue: String(currentAssessment.riskScore),
      baselineValue: `mean=${baseline.riskDistribution.mean}, upper=${baseline.thresholds.riskScoreUpperBound}`,
      deviationFactor: baseline.riskDistribution.stddev > 0
        ? Math.round(((currentAssessment.riskScore - baseline.riskDistribution.mean) / baseline.riskDistribution.stddev) * 100) / 100
        : 0,
      description: `Risk score ${currentAssessment.riskScore} exceeds upper bound ${baseline.thresholds.riskScoreUpperBound}`,
    });
  }

  // NEW_TECHNIQUE_OBSERVED
  if (baseline.thresholds.unexpectedTechniqueAlert) {
    const windowTechniques = new Set(
      currentWindow
        .map((e) => e.mitre?.id)
        .filter((id): id is string => id != null),
    );
    const expected = new Set(baseline.thresholds.expectedTechniques);
    const novel = [...windowTechniques].filter((t) => !expected.has(t));
    if (novel.length > 0) {
      signals.push({
        dimension: "NEW_TECHNIQUE_OBSERVED" as DriftDimension,
        severity: novel.length >= 3 ? "high" : "medium",
        currentValue: novel.join(", "),
        baselineValue: `${expected.size} expected techniques`,
        deviationFactor: novel.length,
        description: `${novel.length} technique(s) not in established baseline: ${novel.join(", ")}`,
      });
    }
  }

  // CAPABILITY_DENY_SPIKE
  const windowDenyCounts = new Map<string, { deny: number; total: number }>();
  for (const entry of currentWindow) {
    const toolName = entry.permission?.tool_name;
    if (!toolName) continue;
    const capability = TOOL_CAPABILITY_MAP[toolName] ?? `tool:${toolName}`;
    const counts = windowDenyCounts.get(capability) ?? { deny: 0, total: 0 };
    counts.total++;
    if (entry.verdict === "deny") counts.deny++;
    windowDenyCounts.set(capability, counts);
  }
  for (const [capability, counts] of windowDenyCounts) {
    if (counts.total < 2) continue;
    const windowDenyRatio = counts.deny / counts.total;
    const baselineCap = baseline.capabilityUsage.find(
      (c) => c.capability === capability,
    );
    const baselineDenyRatio = baselineCap?.denyRatio ?? 0;
    if (
      windowDenyRatio > baseline.thresholds.maxDenyRatioPerCapability &&
      windowDenyRatio > baselineDenyRatio * 2
    ) {
      signals.push({
        dimension: "CAPABILITY_DENY_SPIKE" as DriftDimension,
        severity: windowDenyRatio > 0.8 ? "high" : "medium",
        currentValue: `${capability}: ${Math.round(windowDenyRatio * 100)}% deny`,
        baselineValue: `${capability}: ${Math.round(baselineDenyRatio * 100)}% deny`,
        deviationFactor: baselineDenyRatio > 0
          ? Math.round((windowDenyRatio / baselineDenyRatio) * 100) / 100
          : windowDenyRatio * 10,
        description: `Deny ratio for ${capability} spiked to ${Math.round(windowDenyRatio * 100)}% (baseline: ${Math.round(baselineDenyRatio * 100)}%)`,
      });
    }
  }

  // TEMPORAL_ANOMALY
  const totalHourlyEvents = baseline.temporalProfile.hourlyActivity.reduce(
    (a, b) => a + b,
    0,
  );
  if (totalHourlyEvents > 0 && currentWindow.length > 0) {
    const currentHour = new Date(currentWindow[0].timestamp).getUTCHours();
    const hourShare =
      baseline.temporalProfile.hourlyActivity[currentHour] / totalHourlyEvents;
    if (hourShare < 0.05) {
      signals.push({
        dimension: "TEMPORAL_ANOMALY" as DriftDimension,
        severity: hourShare < 0.01 ? "high" : "medium",
        currentValue: `Hour ${currentHour} UTC`,
        baselineValue: `${Math.round(hourShare * 100)}% of historical activity`,
        deviationFactor: hourShare > 0 ? Math.round((1 / hourShare) * 100) / 100 : 100,
        description: `Activity at hour ${currentHour} UTC is unusual — only ${Math.round(hourShare * 100)}% of historical events occur at this time`,
      });
    }
  }

  // VOLUME_SPIKE
  if (
    baseline.temporalProfile.avgEventsPerSession > 0 &&
    currentWindow.length > baseline.temporalProfile.avgEventsPerSession * 2
  ) {
    const factor =
      Math.round(
        (currentWindow.length / baseline.temporalProfile.avgEventsPerSession) *
          100,
      ) / 100;
    signals.push({
      dimension: "VOLUME_SPIKE" as DriftDimension,
      severity: factor > 5 ? "high" : "medium",
      currentValue: `${currentWindow.length} events in window`,
      baselineValue: `avg ${baseline.temporalProfile.avgEventsPerSession} events/session`,
      deviationFactor: factor,
      description: `Window contains ${factor}x the average events per session`,
    });
  }

  // Determine overall severity
  const severityRank: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };
  let maxSeverity = 0;
  for (const sig of signals) {
    const rank = severityRank[sig.severity] ?? 0;
    if (rank > maxSeverity) maxSeverity = rank;
  }
  const overallDriftSeverity: DriftAssessment["overallDriftSeverity"] =
    maxSeverity >= 4
      ? "critical"
      : maxSeverity >= 3
        ? "high"
        : maxSeverity >= 2
          ? "medium"
          : maxSeverity >= 1
            ? "low"
            : "none";

  const recommendation: DriftAssessment["recommendation"] =
    overallDriftSeverity === "critical"
      ? "block"
      : overallDriftSeverity === "high"
        ? "escalate"
        : overallDriftSeverity === "medium"
          ? "monitor"
          : "allow";

  return {
    ...base,
    driftDetected: signals.length > 0,
    signals,
    overallDriftSeverity,
    recommendation,
  };
}

// ---------------------------------------------------------------------------
// 9. getBaselineContext
// ---------------------------------------------------------------------------

export function getBaselineContext(
  profile: BaselineProfile | undefined,
): string {
  if (!profile || profile.maturityLevel === "insufficient") return "";

  const rd = profile.riskDistribution;

  // Top 5 techniques by count
  const topTechniques = [...profile.techniqueFrequencies]
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
    .map((t) => `${t.techniqueId} (${t.count}x)`)
    .join(", ");

  // Top 3 capabilities by total usage
  const topCapabilities = [...profile.capabilityUsage]
    .sort(
      (a, b) =>
        b.allowCount + b.denyCount + b.askCount -
        (a.allowCount + a.denyCount + a.askCount),
    )
    .slice(0, 3)
    .map((c) => c.capability)
    .join(", ");

  // Last 5 why assessment risk scores
  const last5Scores = profile.whyHistory
    .slice(-5)
    .map((h) => String(h.overallRiskScore))
    .join(", ");

  return [
    `AGENT BASELINE (${profile.maturityLevel} — ${profile.totalSessions} sessions, ${profile.totalEvents} events):`,
    `- Typical risk score: mean ${rd.mean}, p95 ${rd.p95}`,
    `- Common techniques: ${topTechniques || "none observed"}`,
    `- Normal capability pattern: ${topCapabilities || "none recorded"}`,
    `- Temporal: ${profile.temporalProfile.dominantPattern} pattern`,
    `- Last 5 assessments: risk scores [${last5Scores || "none"}]`,
  ].join("\n");
}
