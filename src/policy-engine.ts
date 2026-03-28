/**
 * Fidelis Channel — Policy Engine
 *
 * Evaluates every permission request against an ordered rule set.
 * Fail-closed: if no rule matches, the default is "ask" (forward to human).
 * If the human doesn't respond within timeout, the answer is DENY.
 *
 * Also provides velocity-based anomaly detection.
 */

import type { PolicyRule, FidelisConfig } from "./config.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PolicyVerdict = "deny" | "ask" | "allow";

export interface PolicyResult {
  verdict: PolicyVerdict;
  matched_rule: PolicyRule | null;
  anomaly_flags: string[];
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
  // Simple glob: * matches any sequence of characters
  // Convert glob to regex
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&") // escape regex specials except *
    .replace(/\*/g, ".*"); // * → .*
  const regex = new RegExp(`^${escaped}$`, "i");
  return regex.test(value);
}

/**
 * Match a pattern against the full permission context.
 * Pattern format: "ToolName" or "ToolName(input_glob)"
 */
function matchesPermission(
  pattern: string,
  toolName: string,
  inputPreview: string
): boolean {
  const parenIdx = pattern.indexOf("(");
  if (parenIdx === -1) {
    // Pattern is just a tool name glob
    return matchesPattern(pattern, toolName);
  }

  // Pattern has form: ToolGlob(inputGlob)
  const toolPattern = pattern.slice(0, parenIdx);
  const inputPattern = pattern.slice(parenIdx + 1, -1); // strip trailing )

  if (!matchesPattern(toolPattern, toolName)) {
    return false;
  }

  // Match input_preview against the input glob
  // Also check the pipe-separated alternatives: "curl*|wget*|nc *"
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

  /** Record an event and return true if velocity limit exceeded */
  record(): boolean {
    const now = Date.now();
    this.timestamps.push(now);
    // Prune old entries
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

  constructor(config: FidelisConfig) {
    this.rules = config.policy_rules;
    this.velocity = new VelocityTracker(60_000, config.velocity_limit_per_minute);
  }

  /**
   * Evaluate a permission request against the policy rules.
   * Returns a verdict and any anomaly flags.
   */
  evaluate(req: PermissionRequest): PolicyResult {
    const anomaly_flags: string[] = [];

    // Velocity check
    if (this.velocity.record()) {
      anomaly_flags.push(
        `VELOCITY_EXCEEDED: ${this.velocity.count} requests/min exceeds limit`
      );
    }

    // Privilege escalation heuristics
    const lowerInput = req.input_preview.toLowerCase();
    const lowerDesc = req.description.toLowerCase();
    const combined = `${lowerInput} ${lowerDesc}`;

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

    // Evaluate rules in order — first match wins
    for (const rule of this.rules) {
      if (matchesPermission(rule.tool_pattern, req.tool_name, req.input_preview)) {
        return {
          verdict: rule.action,
          matched_rule: rule,
          anomaly_flags,
        };
      }
    }

    // Default: ask the human
    return {
      verdict: "ask",
      matched_rule: null,
      anomaly_flags,
    };
  }
}
