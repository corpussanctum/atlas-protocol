/**
 * Atlas Protocol — Policy Engine
 *
 * Evaluates every permission request against:
 *   1. Identity context (consent tiers, sensitivity classifications, agent auth)
 *   2. Ordered rule set (glob-matched deny/ask/allow rules)
 *   3. Anomaly detection (velocity, privilege escalation, exfiltration, smuggling, PII)
 *
 * Fail-closed: if no rule matches, the default is "ask" (forward to human).
 * If the human doesn't respond within timeout, the answer is DENY.
 *
 * When an IdentityContext is loaded (via Briefcase or DIB Vault), the engine also:
 *   - Checks sensitivity classifications against tool input/description
 *   - Annotates the PolicyResult with detected consent tier violations
 *   - Auto-denies if a tool is forbidden at the active consent tier
 */

import type { PolicyRule, AtlasConfig } from "./config.js";
import type { IdentityContext, SensitivityClassification, ConsentTier } from "./identity-provider.js";
import { emptyIdentityContext } from "./identity-provider.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PolicyVerdict = "deny" | "ask" | "allow";

export interface SensitivityMatch {
  data_type: string;
  min_tier: ConsentTier;
  pattern: string;
}

export interface PolicyResult {
  verdict: PolicyVerdict;
  matched_rule: PolicyRule | null;
  anomaly_flags: string[];
  /** Sensitivity matches found in the request (from identity context) */
  sensitivity_matches: SensitivityMatch[];
  /** Whether identity context contributed to the decision */
  identity_evaluated: boolean;
}

export interface PermissionRequest {
  request_id: string;
  tool_name: string;
  description: string;
  input_preview: string;
}

// ---------------------------------------------------------------------------
// Glob-like pattern matching
// ---------------------------------------------------------------------------

function matchesPattern(pattern: string, value: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  const regex = new RegExp(`^${escaped}$`, "i");
  return regex.test(value);
}

function matchesPermission(
  pattern: string,
  toolName: string,
  inputPreview: string
): boolean {
  const parenIdx = pattern.indexOf("(");
  if (parenIdx === -1) {
    return matchesPattern(pattern, toolName);
  }

  const toolPattern = pattern.slice(0, parenIdx);
  const inputPattern = pattern.slice(parenIdx + 1, -1);

  if (!matchesPattern(toolPattern, toolName)) {
    return false;
  }

  const alternatives = inputPattern.split("|");
  return alternatives.some((alt) => matchesPattern(alt.trim(), inputPreview));
}

// ---------------------------------------------------------------------------
// Velocity tracker (sliding window)
// ---------------------------------------------------------------------------

class VelocityTracker {
  private timestamps: number[] = [];
  private readonly windowMs: number;
  private readonly limit: number;

  constructor(windowMs: number, limit: number) {
    this.windowMs = windowMs;
    this.limit = limit;
  }

  record(): boolean {
    const now = Date.now();
    this.timestamps.push(now);
    const cutoff = now - this.windowMs;
    this.timestamps = this.timestamps.filter((t) => t >= cutoff);
    return this.timestamps.length > this.limit;
  }

  get count(): number {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    return this.timestamps.filter((t) => t >= cutoff).length;
  }
}

// ---------------------------------------------------------------------------
// Policy Engine
// ---------------------------------------------------------------------------

export class PolicyEngine {
  private readonly rules: PolicyRule[];
  private readonly velocity: VelocityTracker;
  private identityContext: IdentityContext;

  constructor(config: AtlasConfig, identityContext?: IdentityContext) {
    this.rules = config.policy_rules;
    this.velocity = new VelocityTracker(60_000, config.velocity_limit_per_minute);
    this.identityContext = identityContext ?? emptyIdentityContext();
  }

  /**
   * Update the identity context (e.g. after loading a Briefcase).
   */
  setIdentityContext(ctx: IdentityContext): void {
    this.identityContext = ctx;
  }

  /**
   * Evaluate a permission request against policy rules and identity context.
   */
  evaluate(req: PermissionRequest): PolicyResult {
    const anomaly_flags: string[] = [];
    const sensitivity_matches: SensitivityMatch[] = [];
    const identity_evaluated = this.identityContext.loaded;

    // -- Velocity check ----------------------------------------------------
    if (this.velocity.record()) {
      anomaly_flags.push(
        `VELOCITY_EXCEEDED: ${this.velocity.count} requests/min exceeds limit`
      );
    }

    const lowerInput = req.input_preview.toLowerCase();
    const lowerDesc = req.description.toLowerCase();
    const combined = `${lowerInput} ${lowerDesc}`;
    const rawCombined = `${req.input_preview} ${req.description}`;

    // -- Core anomaly heuristics -------------------------------------------

    if (/sudo|chmod\s+777|chown|passwd/.test(combined)) {
      anomaly_flags.push("PRIVILEGE_ESCALATION: sudo/chmod/chown/passwd detected");
    }
    if (/\.env|\.ssh|\.gnupg|credentials|secret|token|api.?key/i.test(combined)) {
      anomaly_flags.push("SENSITIVE_ACCESS: potential credential/secret access");
    }
    if (/curl\s.*(-d|--data)|wget\s.*--post|nc\s|netcat/.test(combined)) {
      anomaly_flags.push("DATA_EXFILTRATION: outbound data transfer detected");
    }
    if (/git\s+push\s+.*--force|git\s+reset\s+--hard/.test(combined)) {
      anomaly_flags.push("DESTRUCTIVE_GIT: force push or hard reset detected");
    }

    // -- Data smuggling / obfuscation detection ----------------------------

    if (/base64|\\x[0-9a-f]{2}|eval\(|atob\(|btoa\(/.test(combined)) {
      anomaly_flags.push("OBFUSCATION_DETECTED: base64/hex encoding or dynamic execution");
    }
    // Detect long base64-like strings (>40 chars of [A-Za-z0-9+/=])
    if (/[A-Za-z0-9+/=]{40,}/.test(req.input_preview)) {
      anomaly_flags.push("ENCODED_PAYLOAD: long base64-like string detected in input");
    }
    // Pipe chains that obscure intent
    if ((req.input_preview.match(/\|/g) || []).length >= 3) {
      anomaly_flags.push("PIPE_CHAIN: complex pipe chain may obscure intent");
    }

    // -- PII / PHI heuristic detection (always-on) -------------------------

    if (/\b\d{3}-\d{2}-\d{4}\b/.test(rawCombined)) {
      anomaly_flags.push("PII_DETECTION: SSN-like pattern found in payload");
    }
    if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(rawCombined)) {
      anomaly_flags.push("PII_DETECTION: email address found in payload");
    }
    if (/\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(rawCombined)) {
      anomaly_flags.push("PII_DETECTION: phone number pattern found in payload");
    }

    // -- Identity-aware sensitivity checks ---------------------------------

    if (this.identityContext.loaded) {
      for (const sc of this.identityContext.sensitivity_classifications) {
        try {
          const regex = new RegExp(sc.pattern, "i");
          if (regex.test(rawCombined)) {
            sensitivity_matches.push({
              data_type: sc.data_type,
              min_tier: sc.min_tier,
              pattern: sc.pattern,
            });
            anomaly_flags.push(
              `CONSENT_TIER_ALERT: ${sc.data_type} detected (requires Tier ${sc.min_tier}+)`
            );
          }
        } catch {
          // Invalid regex in classification — skip
        }
      }

      // Check if the tool is forbidden at any active consent boundary
      for (const boundary of this.identityContext.consent_boundaries) {
        for (const forbiddenPattern of boundary.forbidden_tools) {
          if (matchesPermission(forbiddenPattern, req.tool_name, req.input_preview)) {
            anomaly_flags.push(
              `CONSENT_TOOL_FORBIDDEN: ${req.tool_name} forbidden at ${boundary.label} tier`
            );
            return {
              verdict: "deny",
              matched_rule: {
                tool_pattern: forbiddenPattern,
                action: "deny",
                reason: `Tool forbidden by ${boundary.label} consent boundary`,
              },
              anomaly_flags,
              sensitivity_matches,
              identity_evaluated,
            };
          }
        }
      }
    }

    // -- Static rule evaluation (first match wins) -------------------------

    for (const rule of this.rules) {
      if (matchesPermission(rule.tool_pattern, req.tool_name, req.input_preview)) {
        return {
          verdict: rule.action,
          matched_rule: rule,
          anomaly_flags,
          sensitivity_matches,
          identity_evaluated,
        };
      }
    }

    // -- Default: ask the human --------------------------------------------

    return {
      verdict: "ask",
      matched_rule: null,
      anomaly_flags,
      sensitivity_matches,
      identity_evaluated,
    };
  }
}
