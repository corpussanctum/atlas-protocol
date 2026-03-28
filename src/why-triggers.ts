/**
 * Fidelis Channel — Why Triggers (v0.6.0)
 *
 * Determines when the Why Engine should be invoked based on audit event
 * patterns. Includes cooldown logic to prevent over-triggering and a
 * Telegram alert formatter for human-readable WhyAssessment summaries.
 */

import type { AuditEntry } from "./audit-log.js";
import type { WhyAssessment } from "./why-engine.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type WhyTrigger =
  | "DENY_THRESHOLD"
  | "HITL_ESCALATION"
  | "HIGH_RISK_TECHNIQUE"
  | "IDENTITY_ANOMALY"
  | "CASCADE_REVOCATION"
  | "MANUAL";

export interface TriggerConfig {
  denyThreshold: number;
  highRiskTactics: string[];
  cooldownSeconds: number;
}

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------

export function loadTriggerConfig(): TriggerConfig {
  const defaultTactics = [
    "Credential Access",
    "Exfiltration",
    "Command and Control",
    "Defense Evasion",
  ];

  return {
    denyThreshold:
      parseInt(process.env.WHY_TRIGGER_DENY_THRESHOLD ?? "3", 10) || 3,
    highRiskTactics: process.env.WHY_TRIGGER_HIGH_RISK_TACTICS
      ? process.env.WHY_TRIGGER_HIGH_RISK_TACTICS.split(",").map((s) =>
          s.trim(),
        )
      : defaultTactics,
    cooldownSeconds:
      parseInt(process.env.WHY_TRIGGER_COOLDOWN_SECONDS ?? "30", 10) || 30,
  };
}

// ---------------------------------------------------------------------------
// Trigger evaluation
// ---------------------------------------------------------------------------

export function shouldTrigger(
  entry: AuditEntry,
  recentEntries: AuditEntry[],
  config: TriggerConfig,
  lastAssessmentTime?: Date,
): WhyTrigger | null {
  // Cooldown check
  if (lastAssessmentTime) {
    const elapsed = (Date.now() - lastAssessmentTime.getTime()) / 1000;
    if (elapsed < config.cooldownSeconds) return null;
  }

  // DENY_THRESHOLD: current entry is a deny and recent denies meet threshold
  if (entry.event.includes("DENY")) {
    const denyCount = recentEntries.filter((e) =>
      e.event.includes("DENY"),
    ).length;
    if (denyCount >= config.denyThreshold) return "DENY_THRESHOLD";
  }

  // HITL_ESCALATION: human-in-the-loop event
  if (entry.event === "HUMAN_APPROVE" || entry.event === "HUMAN_DENY") {
    return "HITL_ESCALATION";
  }

  // HIGH_RISK_TECHNIQUE: MITRE tactic in the high-risk list
  if (
    entry.mitre?.tactic &&
    config.highRiskTactics.includes(entry.mitre.tactic)
  ) {
    return "HIGH_RISK_TECHNIQUE";
  }

  // IDENTITY_ANOMALY: unregistered agent or expired credential
  if (
    entry.attestationDenyReason === "UNREGISTERED_AGENT" ||
    entry.attestationDenyReason === "CREDENTIAL_EXPIRED"
  ) {
    return "IDENTITY_ANOMALY";
  }

  // CASCADE_REVOCATION: cascade event in meta
  if (
    (entry.meta as Record<string, unknown>)?.event_detail ===
    "CASCADE_REVOCATION"
  ) {
    return "CASCADE_REVOCATION";
  }

  return null;
}

// ---------------------------------------------------------------------------
// Telegram alert formatter
// ---------------------------------------------------------------------------

const RISK_EMOJI: Record<WhyAssessment["overallRisk"], string> = {
  critical: "\u{1F6A8}",  // 🚨
  high: "\u{1F534}",      // 🔴
  medium: "\u{1F7E0}",    // 🟠
  low: "\u{1F7E1}",       // 🟡
  nominal: "\u{1F7E2}",   // 🟢
};

const ACTION_LABEL: Record<WhyAssessment["recommendedAction"], string> = {
  block: "BLOCK",
  escalate: "ESCALATE",
  monitor: "MONITOR",
  allow: "ALLOW",
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function formatTelegramAlert(
  assessment: WhyAssessment,
  triggerEntry: AuditEntry,
): string {
  const emoji = RISK_EMOJI[assessment.overallRisk];
  const risk = assessment.overallRisk.toUpperCase();
  const score = assessment.overallRiskScore;
  const action = ACTION_LABEL[assessment.recommendedAction];

  const techniques =
    assessment.researchArtifact.uniqueTechniques.length > 0
      ? assessment.researchArtifact.uniqueTechniques.join(", ")
      : "none";

  const trigger = triggerEntry.event;
  const tool = triggerEntry.permission?.tool_name ?? "n/a";

  const lines = [
    `${emoji} <b>Why Layer: ${risk}</b> (${score}/100)`,
    "",
    `<b>Synthesis:</b> ${escapeHtml(assessment.synthesis)}`,
    "",
    `<b>Trigger:</b> ${escapeHtml(trigger)} on <code>${escapeHtml(tool)}</code>`,
    `<b>MITRE:</b> ${escapeHtml(techniques)}`,
    `<b>Action:</b> ${action}`,
    `<b>Window:</b> ${escapeHtml(assessment.windowSummary)}`,
  ];

  return lines.join("\n");
}
