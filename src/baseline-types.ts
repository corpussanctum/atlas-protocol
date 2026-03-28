/**
 * Fidelis Channel — Baseline Types (v0.7.0)
 *
 * Per-agent behavioral profiles that accumulate across sessions.
 * The Why Layer compares current behavior against these baselines
 * to detect drift from established patterns.
 */

export interface RiskDistribution {
  min: number;
  max: number;
  mean: number;
  p50: number;
  p75: number;
  p95: number;
  p99: number;
  stddev: number;
  sampleCount: number;
}

export interface TechniqueFrequency {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  trend: "increasing" | "decreasing" | "stable" | "new";
}

export interface CapabilityUsageProfile {
  capability: string;
  allowCount: number;
  denyCount: number;
  askCount: number;
  denyRatio: number;
  trend: "increasing" | "decreasing" | "stable";
}

export interface TemporalProfile {
  hourlyActivity: number[];    // length 24
  dailyActivity: number[];     // length 7
  dominantPattern: "burst" | "steady" | "escalating" | "declining" | "irregular";
  avgSessionDurationMinutes: number;
  avgEventsPerSession: number;
  longestSessionMinutes: number;
}

export interface DelegationProfile {
  totalDelegationsIssued: number;
  totalDelegationsReceived: number;
  maxDepthUsed: number;
  cascadeRevocations: number;
  avgChildCapabilityReduction: number;
}

export interface WhyHistoryEntry {
  assessedAt: string;
  overallRisk: string;
  overallRiskScore: number;
  inferredIntent: string;
  anomalyDetected: boolean;
  triggerReason: string;
}

export interface BaselineThresholds {
  riskScoreUpperBound: number;
  riskScoreCritical: number;
  maxDenyRatioPerCapability: number;
  expectedTechniques: string[];
  unexpectedTechniqueAlert: boolean;
}

export type MaturityLevel = "insufficient" | "developing" | "established" | "mature";

export interface BaselineProfile {
  agentId: string;
  agentName: string;
  agentRole: string;
  createdAt: string;
  updatedAt: string;
  version: string;
  totalSessions: number;
  totalEvents: number;
  totalDenies: number;
  totalAllows: number;
  totalAsks: number;
  riskDistribution: RiskDistribution;
  techniqueFrequencies: TechniqueFrequency[];
  capabilityUsage: CapabilityUsageProfile[];
  temporalProfile: TemporalProfile;
  delegationProfile: DelegationProfile;
  whyHistory: WhyHistoryEntry[];
  maturityLevel: MaturityLevel;
  thresholds: BaselineThresholds;
  /** Running list of all observed riskScores for recalculation (capped at 10000) */
  _riskScores: number[];
}

export type DriftDimension =
  | "RISK_SCORE_ELEVATED"
  | "NEW_TECHNIQUE_OBSERVED"
  | "CAPABILITY_DENY_SPIKE"
  | "TEMPORAL_ANOMALY"
  | "VOLUME_SPIKE"
  | "DELEGATION_ANOMALY"
  | "INTENT_SHIFT";

export interface DriftSignal {
  dimension: DriftDimension;
  severity: "critical" | "high" | "medium" | "low";
  currentValue: string;
  baselineValue: string;
  deviationFactor: number;
  description: string;
}

export interface DriftAssessment {
  agentId: string;
  assessedAt: string;
  baselineMaturity: string;
  driftDetected: boolean;
  signals: DriftSignal[];
  overallDriftSeverity: "critical" | "high" | "medium" | "low" | "none";
  recommendation: "block" | "escalate" | "monitor" | "allow";
  baselineSnapshot: {
    meanRiskScore: number;
    p95RiskScore: number;
    totalSessions: number;
  };
}
