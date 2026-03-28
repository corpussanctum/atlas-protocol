/**
 * Fidelis Channel — Configuration
 *
 * Loads config from environment variables and/or a JSON config file.
 * All settings have safe defaults (fail-closed).
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PolicyRule {
  /** Glob pattern matched against tool_name (e.g. "Bash", "Write*") */
  tool_pattern: string;
  /** What to do when the pattern matches */
  action: "deny" | "ask" | "allow";
  /** Human-readable reason surfaced in audit log */
  reason?: string;
}

export interface FidelisConfig {
  // -- Telegram ---------------------------------------------------------------
  /** Telegram bot token from @BotFather */
  telegram_bot_token: string;
  /** Telegram chat ID(s) allowed to issue verdicts */
  telegram_allowed_chat_ids: number[];
  /** Polling interval in ms for Telegram getUpdates */
  telegram_poll_interval_ms: number;

  // -- Timeouts ---------------------------------------------------------------
  /** Seconds to wait for a human verdict before auto-denying (fail-closed) */
  permission_timeout_seconds: number;

  // -- Policy engine ----------------------------------------------------------
  /** Ordered list of policy rules. First match wins. Default = ask. */
  policy_rules: PolicyRule[];

  // -- Audit log --------------------------------------------------------------
  /** Path to the append-only JSONL audit log */
  audit_log_path: string;
  /** HMAC-SHA256 secret for signing audit entries. If empty, entries are unsigned. */
  audit_hmac_secret: string;

  // -- Anomaly detection ------------------------------------------------------
  /** Max permission requests per minute before triggering a velocity alert */
  velocity_limit_per_minute: number;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const CONFIG_DIR = join(homedir(), ".fidelis-channel");
const DEFAULT_AUDIT_PATH = join(CONFIG_DIR, "audit.jsonl");

const DEFAULTS: FidelisConfig = {
  telegram_bot_token: "",
  telegram_allowed_chat_ids: [],
  telegram_poll_interval_ms: 1000,
  permission_timeout_seconds: 120,
  policy_rules: [
    // Default policy: block known-dangerous patterns, ask for everything else
    {
      tool_pattern: "Bash(rm -rf *)",
      action: "deny",
      reason: "Recursive force-delete blocked by Fidelis policy",
    },
    {
      tool_pattern: "Bash(*--skip-verification*)",
      action: "deny",
      reason: "Safety bypass flags blocked by Fidelis policy",
    },
    {
      tool_pattern: "Bash(*curl*|*wget*|*nc *|*netcat*)",
      action: "deny",
      reason: "Network exfiltration tool blocked by Fidelis policy",
    },
  ],
  audit_log_path: DEFAULT_AUDIT_PATH,
  audit_hmac_secret: "",
  velocity_limit_per_minute: 30,
};

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

export function loadConfig(): FidelisConfig {
  // Start from defaults
  const config: FidelisConfig = { ...DEFAULTS, policy_rules: [...DEFAULTS.policy_rules] };

  // Try loading JSON config file
  const configPath = join(CONFIG_DIR, "config.json");
  if (existsSync(configPath)) {
    try {
      const raw = JSON.parse(readFileSync(configPath, "utf-8"));
      Object.assign(config, raw);
    } catch {
      // Silently fall back to defaults — logged in audit
      console.error(`[fidelis] Warning: could not parse ${configPath}, using defaults`);
    }
  }

  // Environment overrides (highest priority)
  if (process.env.FIDELIS_TELEGRAM_BOT_TOKEN) {
    config.telegram_bot_token = process.env.FIDELIS_TELEGRAM_BOT_TOKEN;
  }
  if (process.env.FIDELIS_TELEGRAM_CHAT_IDS) {
    config.telegram_allowed_chat_ids = process.env.FIDELIS_TELEGRAM_CHAT_IDS
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !isNaN(n));
  }
  if (process.env.FIDELIS_PERMISSION_TIMEOUT) {
    config.permission_timeout_seconds = parseInt(process.env.FIDELIS_PERMISSION_TIMEOUT, 10) || 120;
  }
  if (process.env.FIDELIS_AUDIT_LOG_PATH) {
    config.audit_log_path = process.env.FIDELIS_AUDIT_LOG_PATH;
  }
  if (process.env.FIDELIS_HMAC_SECRET) {
    config.audit_hmac_secret = process.env.FIDELIS_HMAC_SECRET;
  }
  if (process.env.FIDELIS_VELOCITY_LIMIT) {
    config.velocity_limit_per_minute = parseInt(process.env.FIDELIS_VELOCITY_LIMIT, 10) || 30;
  }

  return config;
}
