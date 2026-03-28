/**
 * Fidelis Channel — Audit Log
 *
 * Append-only JSONL log with HMAC-SHA256 signatures and hash chaining.
 * Each entry includes a hash of the previous entry, creating a tamper-evident chain.
 * If no HMAC secret is configured, entries are still chained but unsigned.
 */

import { createHmac, createHash, randomUUID } from "node:crypto";
import { appendFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { FidelisConfig } from "./config.js";
import type { PolicyResult, PermissionRequest } from "./policy-engine.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AuditEventType =
  | "PERMISSION_REQUEST"     // A permission was requested by Claude Code
  | "POLICY_DENY"            // Policy engine auto-denied
  | "POLICY_ALLOW"           // Policy engine auto-allowed
  | "HUMAN_APPROVE"          // Human approved via Telegram
  | "HUMAN_DENY"             // Human denied via Telegram
  | "TIMEOUT_DENY"           // No response within timeout → fail-closed deny
  | "ANOMALY_DETECTED"       // Anomaly flag raised
  | "CHANNEL_MESSAGE"        // Inbound channel message from Telegram
  | "SESSION_START"          // Plugin started
  | "CONFIG_LOADED";         // Configuration loaded

export interface AuditEntry {
  /** Unique entry ID */
  id: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Event type */
  event: AuditEventType;
  /** Permission request details (if applicable) */
  permission?: PermissionRequest;
  /** Policy evaluation result (if applicable) */
  policy_result?: PolicyResult;
  /** Final behavior sent to Claude Code */
  verdict?: "allow" | "deny";
  /** Free-form metadata */
  meta?: Record<string, unknown>;
  /** SHA-256 hash of the previous entry (chain link) */
  prev_hash: string;
  /** HMAC-SHA256 signature of this entry (excluding the hmac field itself) */
  hmac?: string;
}

// ---------------------------------------------------------------------------
// Audit Logger
// ---------------------------------------------------------------------------

export class AuditLogger {
  private readonly logPath: string;
  private readonly hmacSecret: string;
  private prevHash: string;

  constructor(config: FidelisConfig) {
    this.logPath = config.audit_log_path;
    this.hmacSecret = config.audit_hmac_secret;

    // Ensure log directory exists
    const dir = dirname(this.logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    // Initialize chain from last entry in existing log
    this.prevHash = this.getLastHash();
  }

  /**
   * Read the last line of the audit log to get the chain hash.
   * Returns "GENESIS" if the log is empty or doesn't exist.
   */
  private getLastHash(): string {
    if (!existsSync(this.logPath)) {
      return "GENESIS";
    }
    try {
      const content = readFileSync(this.logPath, "utf-8").trim();
      if (!content) return "GENESIS";
      const lines = content.split("\n");
      const lastLine = lines[lines.length - 1];
      // Hash the entire last entry to form the chain
      return createHash("sha256").update(lastLine).digest("hex");
    } catch {
      return "GENESIS";
    }
  }

  /**
   * Append an audit entry to the log.
   */
  log(
    event: AuditEventType,
    options: {
      permission?: PermissionRequest;
      policy_result?: PolicyResult;
      verdict?: "allow" | "deny";
      meta?: Record<string, unknown>;
    } = {}
  ): AuditEntry {
    const entry: AuditEntry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      event,
      prev_hash: this.prevHash,
      ...options,
    };

    // Compute HMAC if secret is configured
    if (this.hmacSecret) {
      const payload = JSON.stringify(entry);
      entry.hmac = createHmac("sha256", this.hmacSecret)
        .update(payload)
        .digest("hex");
    }

    // Serialize and append
    const line = JSON.stringify(entry);
    appendFileSync(this.logPath, line + "\n", "utf-8");

    // Update chain hash
    this.prevHash = createHash("sha256").update(line).digest("hex");

    return entry;
  }

  /**
   * Verify the integrity of the entire audit log.
   * Returns true if the chain is intact and all HMACs are valid.
   */
  verify(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!existsSync(this.logPath)) {
      return { valid: true, errors: [] }; // Empty log is valid
    }

    const content = readFileSync(this.logPath, "utf-8").trim();
    if (!content) return { valid: true, errors: [] };

    const lines = content.split("\n");
    let expectedPrevHash = "GENESIS";

    for (let i = 0; i < lines.length; i++) {
      try {
        const entry: AuditEntry = JSON.parse(lines[i]);

        // Verify chain hash
        if (entry.prev_hash !== expectedPrevHash) {
          errors.push(
            `Line ${i + 1}: chain broken — expected prev_hash ${expectedPrevHash.slice(0, 12)}..., got ${entry.prev_hash.slice(0, 12)}...`
          );
        }

        // Verify HMAC if present and secret is available
        if (entry.hmac && this.hmacSecret) {
          const { hmac, ...rest } = entry;
          const expectedHmac = createHmac("sha256", this.hmacSecret)
            .update(JSON.stringify(rest))
            .digest("hex");
          if (hmac !== expectedHmac) {
            errors.push(`Line ${i + 1}: HMAC mismatch — entry may be tampered`);
          }
        }

        // Compute hash for next link
        expectedPrevHash = createHash("sha256").update(lines[i]).digest("hex");
      } catch {
        errors.push(`Line ${i + 1}: invalid JSON`);
      }
    }

    return { valid: errors.length === 0, errors };
  }
}
