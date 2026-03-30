/**
 * Atlas Protocol — Why Engine (v0.6.0)
 *
 * Council of Experts (CoE) reasoning engine: three lightweight LLM agents
 * (anomaly detector, intent analyst, threat narrator) reason over audit event
 * windows to produce a WhyAssessment explaining *why* a pattern of agent
 * behavior is or isn't concerning.
 *
 * Design principles:
 *   - NEVER throw — the gatekeeper must not fail because the Why Layer is down
 *   - Graceful degradation: if Ollama is unreachable, return a nominal stub
 *   - Experts run in parallel by default for latency
 *   - Small-model friendly: prompts ask for terse structured JSON
 */

import type { AuditEntry } from "./audit-log.js";
import type { BaselineProfile, DriftAssessment } from "./baseline-types.js";
import { detectDrift, getBaselineContext } from "./baseline-engine.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WhyEngineConfig {
  model: string;
  baseUrl: string;
  windowSize: number;
  windowMinutes: number;
  enabled: boolean;
  parallelExperts: boolean;
}

export interface AuditEventWindow {
  entries: AuditEntry[];
  agentId?: string;
  windowMinutes?: number;
  sessionId?: string;
}

export interface ExpertAssessment {
  expert: "anomaly" | "intent" | "threat";
  finding: string;
  confidence: "high" | "medium" | "low";
  /** Each signal SHOULD reference a specific audit entry ID (e.g., "T1059 match on entry <uuid>") */
  signals: string[];
  riskScore: number;
  /** True if any signal lacks a grounded reference to a specific audit entry */
  ungroundedSignals?: boolean;
}

export interface ResearchArtifact {
  eventCount: number;
  uniqueAgents: string[];
  uniqueTechniques: string[];
  tacticsObserved: string[];
  riskProgression: number[];
  anomalySignals: string[];
  temporalPattern: "burst" | "steady" | "escalating" | "idle";
  // Longitudinal fields (v0.7.0 — populated when baseline available)
  baselineMaturity?: string;
  baselineSessions?: number;
  driftDetected?: boolean;
  driftSignals?: string[];
  riskScoreVsBaseline?: {
    currentMean: number;
    baselineMean: number;
    deviationFactor: number;
  };
  // Integrity labeling (v0.8.2+)
  /** SHA3-256 hash of the serialized AuditEventWindow input */
  derivedFrom?: string;
  /** Model identifier that generated this artifact */
  generatedBy?: string;
  /** ISO 8601 timestamp of artifact generation */
  assessedAt?: string;
  /** Fixed caution label for downstream consumers */
  caution?: string;
}

export interface ModelProvenance {
  /** Model name/tag used for inference */
  model: string;
  /** Model digest/hash from Ollama (if available) */
  modelDigest?: string;
  /** SHA-256 hash of the system prompts used */
  systemPromptHash: string;
  /** Ollama server version (if available) */
  ollamaVersion?: string;
  /** Protocol version used for assessment */
  protocolVersion: string;
}

export interface WhyAssessment {
  windowSummary: string;
  expertAssessments: ExpertAssessment[];
  synthesis: string;
  overallRisk: "critical" | "high" | "medium" | "low" | "nominal";
  overallRiskScore: number;
  recommendedAction: "block" | "escalate" | "monitor" | "allow";
  anomalyDetected: boolean;
  inferredIntent: string;
  threatNarrative: string;
  generatedAt: string;
  modelUsed: string;
  /** Model provenance and reproducibility metadata (v0.8.1+) */
  provenance?: ModelProvenance;
  researchArtifact: ResearchArtifact;
}

// ---------------------------------------------------------------------------
// Expert system prompts
// ---------------------------------------------------------------------------

const ANOMALY_PROMPT =
  "You are a security anomaly detector analyzing AI agent behavior logs. Review the provided audit events and identify any unusual patterns. Consider: frequency spikes, policy violations clustering, unexpected capability usage, deviation from baseline behavior. Respond ONLY with valid JSON: { \"finding\": \"...\", \"confidence\": \"high|medium|low\", \"signals\": [...], \"riskScore\": 0-100 }. IMPORTANT: Each signal string MUST cite a specific audit entry ID from the provided events (e.g., \"Velocity spike: 5 requests in 10s starting at entry abc12345\"). Signals without entry ID references are considered ungrounded.";

const INTENT_PROMPT =
  "You are an AI behavioral analyst. Review these audit events and infer what this agent is trying to accomplish across the session. Consider the sequence of actions, what was allowed vs denied, and what the overall trajectory suggests about agent intent. Respond ONLY with valid JSON: { \"finding\": \"...\", \"confidence\": \"high|medium|low\", \"signals\": [...], \"riskScore\": 0-100 }. IMPORTANT: Each signal string MUST reference specific audit entry IDs that support the inference (e.g., \"Sequential file reads entry abc123, def456 suggest codebase exploration\"). Describe intent in one clear sentence in the finding field.";

const THREAT_PROMPT =
  "You are a SOC analyst writing an incident brief. Review these audit events and describe what is happening in plain language a security team would understand. Map observed behaviors to MITRE ATT&CK tactics where relevant. Respond ONLY with valid JSON: { \"finding\": \"...\", \"confidence\": \"high|medium|low\", \"signals\": [...], \"riskScore\": 0-100 }. IMPORTANT: Each signal MUST cite the specific audit entry ID(s) that evidence the behavior (e.g., \"T1059.004 shell execution in entry abc12345\"). Write as if briefing a senior analyst who will decide whether to escalate.";

const EXPERT_PROMPTS: Record<"anomaly" | "intent" | "threat", string> = {
  anomaly: ANOMALY_PROMPT,
  intent: INTENT_PROMPT,
  threat: THREAT_PROMPT,
};

// Precomputed SHA-256 hash of the system prompts for provenance tracking
import { createHash } from "node:crypto";
const SYSTEM_PROMPT_HASH = createHash("sha256")
  .update(ANOMALY_PROMPT + INTENT_PROMPT + THREAT_PROMPT)
  .digest("hex");

import { PROTOCOL_VERSION } from "./protocol-version.js";

/**
 * Fetch model provenance from Ollama API (best-effort, never throws).
 */
async function fetchModelProvenance(cfg: WhyEngineConfig): Promise<ModelProvenance> {
  const provenance: ModelProvenance = {
    model: cfg.model,
    systemPromptHash: SYSTEM_PROMPT_HASH,
    protocolVersion: PROTOCOL_VERSION,
  };

  try {
    // Fetch model digest
    const showRes = await fetch(`${cfg.baseUrl}/api/show`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: cfg.model }),
      signal: AbortSignal.timeout(5_000),
    });
    if (showRes.ok) {
      const showData = await showRes.json() as { digest?: string; model_info?: Record<string, unknown> };
      if (showData.digest) {
        provenance.modelDigest = showData.digest;
      }
    }
  } catch {
    // Best-effort — provenance without digest is still useful
  }

  try {
    // Fetch Ollama version
    const versionRes = await fetch(`${cfg.baseUrl}/api/version`, {
      signal: AbortSignal.timeout(3_000),
    });
    if (versionRes.ok) {
      const versionData = await versionRes.json() as { version?: string };
      if (versionData.version) {
        provenance.ollamaVersion = versionData.version;
      }
    }
  } catch {
    // Best-effort
  }

  return provenance;
}

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------

export function loadWhyConfig(): WhyEngineConfig {
  return {
    model: process.env.WHY_ENGINE_MODEL ?? "qwen2.5:3b",
    baseUrl: process.env.WHY_ENGINE_BASE_URL ?? "http://localhost:11434",
    windowSize: parseInt(process.env.WHY_ENGINE_WINDOW_SIZE ?? "20", 10) || 20,
    windowMinutes:
      parseInt(process.env.WHY_ENGINE_WINDOW_MINUTES ?? "60", 10) || 60,
    enabled: process.env.WHY_ENGINE_ENABLED !== "false",
    parallelExperts: process.env.WHY_ENGINE_PARALLEL !== "false",
  };
}

// ---------------------------------------------------------------------------
// Ollama caller
// ---------------------------------------------------------------------------

export async function callOllama(
  prompt: string,
  systemPrompt: string,
  config: WhyEngineConfig,
): Promise<string> {
  const url = `${config.baseUrl}/api/generate`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: config.model,
      prompt,
      system: systemPrompt,
      stream: false,
    }),
  });

  if (!res.ok) {
    throw new Error(
      `Ollama returned ${res.status}: ${await res.text().catch(() => "unknown")}`,
    );
  }

  const body = (await res.json()) as { response?: string };
  if (!body.response) {
    throw new Error("Ollama response missing 'response' field");
  }
  return body.response;
}

// ---------------------------------------------------------------------------
// Window serializer
// ---------------------------------------------------------------------------

export function serializeWindow(entries: AuditEntry[]): string {
  const compact = entries.map((e) => ({
    ts: e.timestamp,
    ev: e.event,
    tool: e.permission?.tool_name ?? null,
    verdict: e.verdict ?? null,
    anomaly: extractAnomalyFlags(e),
    mitre: e.mitre?.id ?? null,
    agent: e.agentId ?? null,
  }));
  return JSON.stringify(compact);
}

// ---------------------------------------------------------------------------
// Expert runner
// ---------------------------------------------------------------------------

export async function runExpert(
  expert: "anomaly" | "intent" | "threat",
  entries: AuditEntry[],
  config: WhyEngineConfig,
  baselineContext?: string,
): Promise<ExpertAssessment> {
  // Prepend baseline context to anomaly expert prompt when available
  let systemPrompt = EXPERT_PROMPTS[expert];
  if (baselineContext && expert === "anomaly") {
    systemPrompt = baselineContext + "\n\n" + systemPrompt +
      " If baseline context is provided above, explicitly compare current behavior against baseline. Call out any dimensions where current behavior deviates from the established pattern. If no baseline is available, reason only from the current window.";
  }
  const prompt = serializeWindow(entries);

  let raw: string;
  try {
    raw = await callOllama(prompt, systemPrompt, config);
  } catch {
    return fallbackAssessment(expert);
  }

  try {
    // Extract JSON from response — the model may wrap it in markdown fences
    const jsonStr = raw.replace(/```json?\s*/g, "").replace(/```/g, "").trim();
    const parsed = JSON.parse(jsonStr) as {
      finding?: string;
      confidence?: string;
      signals?: string[];
      riskScore?: number;
    };

    const confidence = validateConfidence(parsed.confidence);
    const riskScore = Math.max(
      0,
      Math.min(100, Math.round(parsed.riskScore ?? 25)),
    );

    const signals = Array.isArray(parsed.signals)
      ? parsed.signals.filter((s): s is string => typeof s === "string")
      : [];

    // Check if any signal lacks a grounded audit entry ID reference
    // Entry IDs are UUIDs — look for hex patterns of length >= 8
    const entryIds = new Set(entries.map((e) => e.id));
    const hasUngrounded = signals.length > 0 && signals.some((s) => {
      // Check if the signal references any known entry ID (full or partial 8+ char prefix)
      return !Array.from(entryIds).some((id) => s.includes(id) || s.includes(id.slice(0, 8)));
    });

    return {
      expert,
      finding: typeof parsed.finding === "string" ? parsed.finding : "No finding",
      confidence,
      signals,
      riskScore,
      ungroundedSignals: hasUngrounded || undefined,
    };
  } catch {
    return fallbackAssessment(expert);
  }
}

function fallbackAssessment(
  expert: "anomaly" | "intent" | "threat",
): ExpertAssessment {
  return {
    expert,
    finding: "Expert failed to produce structured output",
    confidence: "low",
    signals: [],
    riskScore: 25,
    ungroundedSignals: true,
  };
}

function validateConfidence(
  value: unknown,
): "high" | "medium" | "low" {
  if (value === "high" || value === "medium" || value === "low") return value;
  return "low";
}

// ---------------------------------------------------------------------------
// Research artifact builder
// ---------------------------------------------------------------------------

export function buildResearchArtifact(
  entries: AuditEntry[],
  modelUsed?: string,
): ResearchArtifact {
  const uniqueAgents = [
    ...new Set(
      entries.map((e) => e.agentId).filter((id): id is string => id != null),
    ),
  ];

  const uniqueTechniques = [
    ...new Set(
      entries
        .map((e) => e.mitre?.id)
        .filter((id): id is string => id != null),
    ),
  ];

  const tacticsObserved = [
    ...new Set(
      entries
        .map((e) => e.mitre?.tactic)
        .filter((t): t is string => t != null),
    ),
  ];

  const riskProgression = entries.map((e) => {
    const flags = extractAnomalyFlags(e);
    if (flags.length === 0) return 0;
    return Math.min(100, 10 * flags.length);
  });

  const anomalySignals = [
    ...new Set(entries.flatMap((e) => extractAnomalyFlags(e))),
  ];

  const temporalPattern = classifyTemporalPattern(entries, riskProgression);

  // Integrity labeling — compute window hash for provenance
  const windowPayload = JSON.stringify(entries.map((e) => e.id));
  const derivedFrom = createHash("sha3-256").update(windowPayload).digest("hex");

  return {
    eventCount: entries.length,
    uniqueAgents,
    uniqueTechniques,
    tacticsObserved,
    riskProgression,
    anomalySignals,
    temporalPattern,
    derivedFrom,
    generatedBy: modelUsed,
    assessedAt: new Date().toISOString(),
    caution: "AI-generated analysis. Verify against primary audit trail.",
  };
}

function extractAnomalyFlags(entry: AuditEntry): string[] {
  // anomaly_flags live in policy_result.anomaly_flags or meta.flags
  const fromPolicy = entry.policy_result?.anomaly_flags ?? [];
  const fromMeta = Array.isArray((entry.meta as Record<string, unknown>)?.flags)
    ? ((entry.meta as Record<string, unknown>).flags as string[])
    : [];

  // Deduplicate across both sources
  return [...new Set([...fromPolicy, ...fromMeta])];
}

function classifyTemporalPattern(
  entries: AuditEntry[],
  riskProgression: number[],
): "burst" | "steady" | "escalating" | "idle" {
  if (entries.length < 2) return "steady";

  const first = new Date(entries[0].timestamp).getTime();
  const last = new Date(entries[entries.length - 1].timestamp).getTime();
  const spanMinutes = (last - first) / 60_000;

  if (spanMinutes < 2) return "burst";

  if (spanMinutes > 30 && entries.length < 5) return "idle";

  // Check monotonically increasing risk (ignoring zeros)
  const nonZero = riskProgression.filter((r) => r > 0);
  if (nonZero.length >= 3) {
    let increasing = true;
    for (let i = 1; i < nonZero.length; i++) {
      if (nonZero[i] < nonZero[i - 1]) {
        increasing = false;
        break;
      }
    }
    if (increasing) return "escalating";
  }

  return "steady";
}

// ---------------------------------------------------------------------------
// Synthesizer
// ---------------------------------------------------------------------------

export function synthesize(
  experts: ExpertAssessment[],
  entries: AuditEntry[],
  driftAssessment?: DriftAssessment,
  baseline?: BaselineProfile,
  modelUsed?: string,
): Omit<WhyAssessment, "expertAssessments"> {
  const anomalyExpert = experts.find((e) => e.expert === "anomaly");
  const intentExpert = experts.find((e) => e.expert === "intent");
  const threatExpert = experts.find((e) => e.expert === "threat");

  // Weighted average: anomaly 0.4, intent 0.3, threat 0.3
  const overallRiskScore = Math.round(
    (anomalyExpert?.riskScore ?? 0) * 0.4 +
      (intentExpert?.riskScore ?? 0) * 0.3 +
      (threatExpert?.riskScore ?? 0) * 0.3,
  );

  const overallRisk: WhyAssessment["overallRisk"] =
    overallRiskScore > 80
      ? "critical"
      : overallRiskScore > 60
        ? "high"
        : overallRiskScore > 40
          ? "medium"
          : overallRiskScore > 20
            ? "low"
            : "nominal";

  const recommendedAction: WhyAssessment["recommendedAction"] =
    overallRisk === "critical"
      ? "block"
      : overallRisk === "high"
        ? "escalate"
        : overallRisk === "medium"
          ? "monitor"
          : "allow";

  const anomalyDetected =
    anomalyExpert?.confidence === "high" ||
    (anomalyExpert?.riskScore ?? 0) > 60;

  const inferredIntent = intentExpert?.finding ?? "Unable to infer intent";
  const threatNarrative = threatExpert?.finding ?? "No threat narrative available";

  // Build synthesis from all three findings
  const parts = experts
    .map((e) => e.finding)
    .filter((f) => f !== "Expert failed to produce structured output");
  const synthesis =
    parts.length > 0
      ? parts.join(". ").replace(/\.\./g, ".") +
        (parts.length > 1 ? "" : ".")
      : "No expert produced actionable findings.";

  // Time span
  let timeSpanMinutes = 0;
  if (entries.length >= 2) {
    const first = new Date(entries[0].timestamp).getTime();
    const last = new Date(entries[entries.length - 1].timestamp).getTime();
    timeSpanMinutes = Math.round((last - first) / 60_000);
  }
  const windowSummary = `${entries.length} events over ${timeSpanMinutes} minutes`;

  const researchArtifact = buildResearchArtifact(entries, modelUsed);

  // Enrich with baseline longitudinal data (v0.7.0)
  if (baseline && baseline.maturityLevel !== "insufficient") {
    researchArtifact.baselineMaturity = baseline.maturityLevel;
    researchArtifact.baselineSessions = baseline.totalSessions;
    const currentMean = overallRiskScore;
    const baselineMean = baseline.riskDistribution.mean;
    const stddev = baseline.riskDistribution.stddev || 1;
    researchArtifact.riskScoreVsBaseline = {
      currentMean,
      baselineMean,
      deviationFactor: Math.round(((currentMean - baselineMean) / stddev) * 100) / 100,
    };
  }

  // Drift integration
  let finalOverallRisk = overallRisk;
  let finalAnomalyDetected = anomalyDetected;
  let finalSynthesis = synthesis;

  if (driftAssessment?.driftDetected) {
    researchArtifact.driftDetected = true;
    researchArtifact.driftSignals = driftAssessment.signals.map(
      (s) => `${s.dimension}: ${s.description}`
    );
    finalAnomalyDetected = true;

    // Elevate risk if drift severity is high or critical
    if (
      driftAssessment.overallDriftSeverity === "critical" &&
      finalOverallRisk !== "critical"
    ) {
      finalOverallRisk = "critical";
    } else if (
      driftAssessment.overallDriftSeverity === "high" &&
      finalOverallRisk !== "critical" &&
      finalOverallRisk !== "high"
    ) {
      finalOverallRisk = "high";
    }

    const driftSummary = driftAssessment.signals
      .map((s) => s.description)
      .join("; ");
    finalSynthesis += ` Baseline drift detected: ${driftSummary}.`;
  }

  // Recalculate recommended action based on potentially elevated risk
  const finalAction: WhyAssessment["recommendedAction"] =
    finalOverallRisk === "critical"
      ? "block"
      : finalOverallRisk === "high"
        ? "escalate"
        : finalOverallRisk === "medium"
          ? "monitor"
          : "allow";

  return {
    windowSummary,
    synthesis: finalSynthesis,
    overallRisk: finalOverallRisk,
    overallRiskScore,
    recommendedAction: finalAction,
    anomalyDetected: finalAnomalyDetected,
    inferredIntent,
    threatNarrative,
    generatedAt: new Date().toISOString(),
    modelUsed: "",
    researchArtifact,
  };
}

// ---------------------------------------------------------------------------
// Stub assessment (safe fallback)
// ---------------------------------------------------------------------------

export function stubAssessment(
  reason: string,
  entries: AuditEntry[],
): WhyAssessment {
  return {
    windowSummary: `${entries.length} events (stub)`,
    expertAssessments: [],
    synthesis: reason,
    overallRisk: "nominal",
    overallRiskScore: 0,
    recommendedAction: "allow",
    anomalyDetected: false,
    inferredIntent: "Unknown — Why engine unavailable",
    threatNarrative: "No threat narrative — Why engine unavailable",
    generatedAt: new Date().toISOString(),
    modelUsed: "none",
    researchArtifact: buildResearchArtifact(entries),
  };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function assessWindow(
  window: AuditEventWindow,
  config?: WhyEngineConfig,
  baseline?: BaselineProfile,
): Promise<WhyAssessment> {
  const cfg = config ?? loadWhyConfig();

  if (!cfg.enabled) {
    return stubAssessment("Why engine disabled", window.entries);
  }

  try {
    // Get baseline context for expert prompt injection
    const baseCtx = getBaselineContext(baseline);

    const expertTypes: Array<"anomaly" | "intent" | "threat"> = [
      "anomaly",
      "intent",
      "threat",
    ];

    let assessments: ExpertAssessment[];

    if (cfg.parallelExperts) {
      assessments = await Promise.all(
        expertTypes.map((expert) =>
          runExpert(expert, window.entries, cfg, baseCtx || undefined),
        ),
      );
    } else {
      assessments = [];
      for (const expert of expertTypes) {
        assessments.push(
          await runExpert(expert, window.entries, cfg, baseCtx || undefined),
        );
      }
    }

    // Run drift detection if baseline is sufficient
    let drift: DriftAssessment | undefined;
    const anomalyExpert = assessments.find((e) => e.expert === "anomaly");
    if (baseline && baseline.maturityLevel !== "insufficient" && anomalyExpert) {
      drift = detectDrift(window.entries, anomalyExpert, baseline);
    }

    // Fetch model provenance (best-effort, non-blocking)
    const provenance = await fetchModelProvenance(cfg);

    const base = synthesize(assessments, window.entries, drift, baseline, cfg.model);
    return {
      ...base,
      expertAssessments: assessments,
      modelUsed: cfg.model,
      provenance,
    };
  } catch {
    return stubAssessment(
      "Why engine unavailable — Ollama not reachable",
      window.entries,
    );
  }
}
