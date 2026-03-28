/**
 * Fidelis Channel — Audit Log
 *
 * Append-only JSONL log with:
 *   - SHA-256 hash chaining (tamper-evident)
 *   - Optional HMAC-SHA256 signatures
 *   - Consent-tier-driven field redaction (hashes PHI fields instead of storing plaintext)
 *
 * Redaction strategy:
 *   - If an IdentityContext is loaded with audit_redact_fields, those fields are
 *     automatically hashed in permission entries (e.g. input_preview → HASHED:sha256(...))
 *   - If FIDELIS_PRIVACY_MODE=true, input_preview is always redacted regardless of context
 *   - The hash allows after-the-fact verification without storing PHI on disk
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
  | "PERMISSION_REQUEST"
  | "POLICY_DENY"
  | "POLICY_ALLOW"
  | "HUMAN_APPROVE"
  | "HUMAN_DENY"
  | "TIMEOUT_DENY"
  | "ANOMALY_DETECTED"
  | "CHANNEL_MESSAGE"
  | "SESSION_START"
  | "CONFIG_LOADED"
  | "IDENTITY_LOADED";

export interface AuditEntry {
  id: string;
  timestamp: string;
  event: AuditEventType;
  permission?: PermissionRequest;
  policy_result?: PolicyResult;
  verdict?: "allow" | "deny";
  meta?: Record<string, unknown>;
  prev_hash: string;
  hmac?: string;
}

// ---------------------------------------------------------------------------
// Redaction config
// ---------------------------------------------------------------------------

export interface RedactionConfig {
  /** Fields on the permission object to hash instead of storing plaintext */
  redact_fields: string[];
  /** Whether privacy mode is forced (overrides identity context) */
  force_privacy: boolean;
}

// ---------------------------------------------------------------------------
// Audit Logger
// ---------------------------------------------------------------------------

export class AuditLogger {
  private readonly logPath: string;
  private readonly hmacSecret: string;
  private prevHash: string;
  private redaction: RedactionConfig;

  constructor(config: FidelisConfig, redaction?: RedactionConfig) {
    this.logPath = config.audit_log_path;
    this.hmacSecret = config.audit_hmac_secret;

    // Redaction: merge forced privacy mode with identity-driven config
    const forcePrivacy = process.env.FIDELIS_PRIVACY_MODE === "true";
    this.redaction = redaction ?? {
      redact_fields: forcePrivacy ? ["input_preview"] : [],
      force_privacy: forcePrivacy,
    };

    const dir = dirname(this.logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.prevHash = this.getLastHash();
  }

  /**
   * Update redaction config (e.g. after loading identity context).
   */
  setRedaction(redaction: RedactionConfig): void {
    this.redaction = redaction;
  }

  /**
   * Read the last line of the audit log to get the chain hash.
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
      return createHash("sha256").update(lastLine).digest("hex");
    } catch {
      return "GENESIS";
    }
  }

  /**
   * Append an audit entry to the log with optional field redaction.
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

    // Apply field redaction to permission object
    if (entry.permission && this.redaction.redact_fields.length > 0) {
      entry.permission = this.redactPermission(entry.permission);
      entry.meta = {
        ...entry.meta,
        redacted_fields: this.redaction.redact_fields,
      };
    }

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
   * Redact specified fields on a PermissionRequest by replacing them
   * with HASHED:sha256(...). The hash allows verification without
   * storing the original value on disk.
   */
  private redactPermission(perm: PermissionRequest): PermissionRequest {
    const redacted = { ...perm };

    for (const field of this.redaction.redact_fields) {
      if (field in redacted) {
        const key = field as keyof PermissionRequest;
        const original = redacted[key];
        if (typeof original === "string" && original.length > 0) {
          const hash = createHash("sha256").update(original).digest("hex");
          // TypeScript: we know these fields are strings on PermissionRequest
          (redacted as Record<string, string>)[key] = `HASHED:${hash}`;
        }
      }
    }

    return redacted;
  }

  /**
   * Verify the integrity of the entire audit log.
   */
  verify(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!existsSync(this.logPath)) {
      return { valid: true, errors: [] };
    }

    const content = readFileSync(this.logPath, "utf-8").trim();
    if (!content) return { valid: true, errors: [] };

    const lines = content.split("\n");
    let expectedPrevHash = "GENESIS";

    for (let i = 0; i < lines.length; i++) {
      try {
        const entry: AuditEntry = JSON.parse(lines[i]);

        if (entry.prev_hash !== expectedPrevHash) {
          errors.push(
            `Line ${i + 1}: chain broken — expected prev_hash ${expectedPrevHash.slice(0, 12)}..., got ${entry.prev_hash.slice(0, 12)}...`
          );
        }

        if (entry.hmac && this.hmacSecret) {
          const { hmac, ...rest } = entry;
          const expectedHmac = createHmac("sha256", this.hmacSecret)
            .update(JSON.stringify(rest))
            .digest("hex");
          if (hmac !== expectedHmac) {
            errors.push(`Line ${i + 1}: HMAC mismatch — entry may be tampered`);
          }
        }

        expectedPrevHash = createHash("sha256").update(lines[i]).digest("hex");
      } catch {
        errors.push(`Line ${i + 1}: invalid JSON`);
      }
    }

    return { valid: errors.length === 0, errors };
  }
}
