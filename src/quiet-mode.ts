/**
 * Atlas Protocol — Quiet Mode (v0.8.0)
 *
 * For mature agents (200+ sessions), low-risk actions can be auto-approved
 * without Telegram operator involvement. This reduces noise while maintaining
 * full audit trail coverage.
 *
 * Quiet Mode eligibility:
 *   - Agent has baseline with maturityLevel "mature" (200+ sessions)
 *   - Request has ZERO anomaly flags
 *   - Tool requires only "file:read" or "shell:read" capability
 *   - Input does NOT match any sensitive path patterns
 *   - Policy verdict is "ask" (deny rules are NEVER bypassed)
 *
 * Non-eligible actions always go through normal flow (Telegram or break-glass).
 */

import type { PolicyResult, PermissionRequest } from "./policy-engine.js";
import type { BaselineProfile } from "./baseline-types.js";
import type { AttestationResult } from "./attestation.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface QuietModeConfig {
  /** Whether quiet mode is enabled globally (default: true if env var set) */
  enabled: boolean;
  /** Minimum maturity level required (default: "mature") */
  min_maturity: "established" | "mature";
  /** Maximum anomaly flags allowed for quiet approval (default: 0) */
  max_anomaly_flags: number;
  /** Tool names eligible for quiet mode */
  quiet_tools: Set<string>;
}

export interface QuietModeResult {
  eligible: boolean;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Sensitive path patterns (never auto-approved)
// ---------------------------------------------------------------------------

const SENSITIVE_PATTERNS = [
  /\.env/i,
  /\.ssh/i,
  /\.gnupg/i,
  /\/etc\//,
  /credentials/i,
  /secret/i,
  /token/i,
  /api.?key/i,
  /password/i,
  /shadow$/,
  /\.pem$/,
  /\.key$/,
  /\.p12$/,
  /\.pfx$/,
];

// ---------------------------------------------------------------------------
// Maturity hierarchy
// ---------------------------------------------------------------------------

const MATURITY_RANK: Record<string, number> = {
  insufficient: 0,
  developing: 1,
  established: 2,
  mature: 3,
};

// ---------------------------------------------------------------------------
// Config loader
// ---------------------------------------------------------------------------

export function loadQuietConfig(): QuietModeConfig {
  return {
    enabled: process.env.ATLAS_QUIET_MODE === "true",
    min_maturity: (process.env.ATLAS_QUIET_MIN_MATURITY as "established" | "mature") || "mature",
    max_anomaly_flags: parseInt(process.env.ATLAS_QUIET_MAX_FLAGS ?? "0", 10),
    quiet_tools: new Set(
      (process.env.ATLAS_QUIET_TOOLS ?? "Read,Glob,Grep").split(",").map((t) => t.trim())
    ),
  };
}

// ---------------------------------------------------------------------------
// Eligibility check
// ---------------------------------------------------------------------------

/**
 * Determine if a request is eligible for quiet-mode auto-approval.
 *
 * Returns { eligible: true } if the request can be silently approved,
 * or { eligible: false, reason: "..." } explaining why not.
 */
export function checkQuietEligibility(
  config: QuietModeConfig,
  req: PermissionRequest,
  policyResult: PolicyResult,
  attestation: AttestationResult,
  baseline: BaselineProfile | null | undefined,
): QuietModeResult {
  if (!config.enabled) {
    return { eligible: false, reason: "quiet mode disabled" };
  }

  // Only "ask" verdicts are eligible — deny/allow already handled
  if (policyResult.verdict !== "ask") {
    return { eligible: false, reason: `verdict is ${policyResult.verdict}, not ask` };
  }

  // Agent must be identity-verified
  if (!attestation.identityVerified) {
    return { eligible: false, reason: "agent identity not verified" };
  }

  // Must have a baseline
  if (!baseline) {
    return { eligible: false, reason: "no baseline profile" };
  }

  // Maturity check
  const agentMaturity = MATURITY_RANK[baseline.maturityLevel] ?? 0;
  const requiredMaturity = MATURITY_RANK[config.min_maturity] ?? 3;
  if (agentMaturity < requiredMaturity) {
    return { eligible: false, reason: `maturity ${baseline.maturityLevel} < required ${config.min_maturity}` };
  }

  // Tool must be in the quiet-eligible set
  if (!config.quiet_tools.has(req.tool_name)) {
    return { eligible: false, reason: `tool ${req.tool_name} not in quiet-eligible set` };
  }

  // Zero anomaly flags (or within configured max)
  if (policyResult.anomaly_flags.length > config.max_anomaly_flags) {
    return { eligible: false, reason: `${policyResult.anomaly_flags.length} anomaly flags > max ${config.max_anomaly_flags}` };
  }

  // No sensitivity matches
  if (policyResult.sensitivity_matches.length > 0) {
    return { eligible: false, reason: "sensitivity matches detected" };
  }

  // Input must not match sensitive path patterns
  const input = req.input_preview;
  for (const pattern of SENSITIVE_PATTERNS) {
    if (pattern.test(input)) {
      return { eligible: false, reason: `input matches sensitive pattern: ${pattern.source}` };
    }
  }

  return { eligible: true };
}
