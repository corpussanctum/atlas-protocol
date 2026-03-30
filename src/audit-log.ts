/**
 * Atlas Protocol — Audit Log (v0.4.0)
 *
 * Append-only JSONL log with:
 *   - SHA3-256 hash chaining (tamper-evident, quantum-resistant hash)
 *   - ML-DSA-65 post-quantum signatures per entry (FIPS 204)
 *   - Optional HMAC-SHA256 classical signatures (backwards-compatible)
 *   - MITRE ATT&CK enrichment (technique name + tactic per entry)
 *   - Consent-tier-driven field redaction
 *
 * Threat model: harvest-now-decrypt-later adversaries who may challenge
 * audit trail integrity 10-15+ years in the future. SHA3-256 + ML-DSA-65
 * ensures non-repudiation holds against both classical and quantum attacks.
 *
 * Backwards compatibility: the verifier detects legacy SHA-256 entries
 * (no hash_algorithm field) and validates them with the original algorithm.
 */

import { createHmac, createHash, randomUUID } from "node:crypto";
import { appendFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { AtlasConfig } from "./config.js";
import type { PolicyResult, PermissionRequest } from "./policy-engine.js";
import type { QuantumSigner } from "./quantum-signer.js";
import { enrichMitre } from "./mitre-attack.js";
import type { AttackTechnique } from "./mitre-attack.js";
import type { AgentRole } from "./agent-identity.js";

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
  | "IDENTITY_LOADED"
  | "CREDENTIAL_EXPIRED"
  | "CREDENTIAL_EXPIRY_WARNING"
  | "CHECKPOINT"
  // Proximity Mesh events (SPEC § 13.4)
  | "PROXIMITY_DISCOVERY"
  | "PROXIMITY_RANGE"
  | "PROXIMITY_VERIFIED"
  | "PROXIMITY_REJECTED"
  | "PROXIMITY_SESSION_ESTABLISHED"
  | "PROXIMITY_SESSION_CLOSED"
  | "PROXIMITY_RERANGE"
  | "PROXIMITY_DELEGATION";

export interface AuditEntry {
  id: string;
  timestamp: string;
  event: AuditEventType;
  permission?: PermissionRequest;
  policy_result?: PolicyResult;
  verdict?: "allow" | "deny";

  /** Matched policy rule identifier (tool_pattern) */
  rule_id?: string;
  /** MITRE ATT&CK enrichment from the matched rule */
  mitre?: AttackTechnique;

  meta?: Record<string, unknown>;

  // -- Agent identity attestation (v0.5.0+) --------------------------------
  /** DID of the attested agent (did:atlas:<uuid>) */
  agentId?: string;
  /** Whether the agent's credential was verified for this entry */
  identityVerified?: boolean;
  /** When the agent's credential expires */
  credentialExpiry?: string;
  /** Agent's declared role */
  agentRole?: AgentRole;
  /** Reason attestation was denied (if applicable) */
  attestationDenyReason?: string;

  // -- Why Layer (v0.6.0+) ---------------------------------------------------
  /** Whether the Why Engine was triggered for this entry */
  whyTriggered?: boolean;
  /** The trigger reason (DENY_THRESHOLD, HIGH_RISK_TECHNIQUE, etc.) */
  whyTriggerReason?: string;

  // -- Anti-truncation (v0.8.1+) ---------------------------------------------
  /** Monotonic sequence number (0-indexed, contiguous within a log file) */
  seq?: number;

  /** Hash algorithm used for prev_hash (absent on legacy SHA-256 entries) */
  hash_algorithm?: "sha3-256";
  /** Hash of the previous log line — SHA3-256 for v0.4.0+, SHA-256 for legacy */
  prev_hash: string;
  /** Classical HMAC-SHA256 signature (optional) */
  hmac?: string;
  /** ML-DSA-65 post-quantum signature, base64-encoded (optional) */
  pq_signature?: string;
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
// Hash helpers
// ---------------------------------------------------------------------------

function sha3_256(data: string): string {
  return createHash("sha3-256").update(data).digest("hex");
}

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// Audit Logger
// ---------------------------------------------------------------------------

export class AuditLogger {
  private readonly logPath: string;
  private readonly hmacSecret: string;
  private readonly signer: QuantumSigner | null;
  private prevHash: string;
  private redaction: RedactionConfig;
  /** Monotonic sequence counter — anti-truncation measure */
  private seq: number;
  /** Entries since last checkpoint */
  private entriesSinceCheckpoint: number;
  /** Checkpoint interval (number of entries between checkpoints) */
  private readonly checkpointInterval: number;

  constructor(
    config: AtlasConfig,
    redaction?: RedactionConfig,
    signer?: QuantumSigner | null,
  ) {
    this.logPath = config.audit_log_path;
    this.hmacSecret = config.audit_hmac_secret;
    this.signer = signer ?? null;
    this.checkpointInterval = parseInt(process.env.ATLAS_CHECKPOINT_INTERVAL ?? "100", 10);
    this.entriesSinceCheckpoint = 0;

    // Redaction: merge forced privacy mode with identity-driven config
    const forcePrivacy = process.env.ATLAS_PRIVACY_MODE === "true";
    this.redaction = redaction ?? {
      redact_fields: forcePrivacy ? ["input_preview"] : [],
      force_privacy: forcePrivacy,
    };

    const dir = dirname(this.logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    const { hash, seq } = this.getLastHashAndSeq();
    this.prevHash = hash;
    this.seq = seq;
  }

  /**
   * Update redaction config (e.g. after loading identity context).
   */
  setRedaction(redaction: RedactionConfig): void {
    this.redaction = redaction;
  }

  /**
   * Read the last line of the audit log and return its hash and sequence number.
   * Uses SHA3-256 for the chain going forward.
   */
  private getLastHashAndSeq(): { hash: string; seq: number } {
    if (!existsSync(this.logPath)) {
      return { hash: "GENESIS", seq: 0 };
    }
    try {
      const content = readFileSync(this.logPath, "utf-8").trim();
      if (!content) return { hash: "GENESIS", seq: 0 };
      const lines = content.split("\n");
      const lastLine = lines[lines.length - 1];
      const hash = sha3_256(lastLine);
      // Try to read seq from the last entry
      try {
        const lastEntry = JSON.parse(lastLine) as AuditEntry;
        return { hash, seq: (lastEntry.seq ?? lines.length - 1) + 1 };
      } catch {
        return { hash, seq: lines.length };
      }
    } catch {
      return { hash: "GENESIS", seq: 0 };
    }
  }

  /**
   * Append an audit entry to the log with optional field redaction,
   * MITRE ATT&CK enrichment, HMAC signing, and ML-DSA-65 signature.
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
      seq: this.seq++,
      hash_algorithm: "sha3-256",
      prev_hash: this.prevHash,
      ...options,
    };

    // ATT&CK enrichment from matched policy rule
    if (entry.policy_result?.matched_rule) {
      const rule = entry.policy_result.matched_rule;
      entry.rule_id = rule.tool_pattern;
      const technique = enrichMitre(rule.mitre_id);
      if (technique) {
        entry.mitre = technique;
      }
    }

    // Apply field redaction to permission object
    if (entry.permission && this.redaction.redact_fields.length > 0) {
      entry.permission = this.redactPermission(entry.permission);
      entry.meta = {
        ...entry.meta,
        redacted_fields: this.redaction.redact_fields,
      };
    }

    // Compute HMAC if secret is configured (classical signature)
    if (this.hmacSecret) {
      const payload = JSON.stringify(entry);
      entry.hmac = createHmac("sha256", this.hmacSecret)
        .update(payload)
        .digest("hex");
    }

    // ML-DSA-65 post-quantum signature
    if (this.signer?.available) {
      // Sign the entry content (without the pq_signature field itself)
      const payload = Buffer.from(JSON.stringify(entry));
      const sig = this.signer.sign(payload);
      if (sig) {
        entry.pq_signature = sig;
      }
    }

    // Serialize and append
    const line = JSON.stringify(entry);
    appendFileSync(this.logPath, line + "\n", "utf-8");

    // Update chain hash (SHA3-256)
    this.prevHash = sha3_256(line);

    // Auto-emit checkpoint if interval reached (non-recursive: checkpoints don't trigger more checkpoints)
    if (event !== "CHECKPOINT") {
      this.entriesSinceCheckpoint++;
      if (this.checkpointInterval > 0 && this.entriesSinceCheckpoint >= this.checkpointInterval) {
        this.entriesSinceCheckpoint = 0;
        this.log("CHECKPOINT", {
          meta: {
            checkpoint_seq: entry.seq,
            checkpoint_hash: this.prevHash,
            entries_since_start: this.seq,
          },
        });
      }
    }

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
   *
   * Checks:
   *   1. Hash chain continuity (SHA3-256 for v0.4.0+, SHA-256 for legacy)
   *   2. Sequence number continuity (anti-truncation)
   *   3. HMAC signatures (if secret configured)
   *   4. ML-DSA-65 signatures (if signer available)
   */
  verify(): {
    valid: boolean;
    errors: string[];
    stats: {
      total_entries: number;
      pq_signed: number;
      hmac_signed: number;
      legacy_sha256: number;
      checkpoints: number;
      max_seq: number;
    };
  } {
    const errors: string[] = [];
    const stats = {
      total_entries: 0,
      pq_signed: 0,
      hmac_signed: 0,
      legacy_sha256: 0,
      checkpoints: 0,
      max_seq: -1,
    };

    if (!existsSync(this.logPath)) {
      return { valid: true, errors: [], stats };
    }

    const content = readFileSync(this.logPath, "utf-8").trim();
    if (!content) return { valid: true, errors: [], stats };

    const lines = content.split("\n");
    let expectedPrevHash = "GENESIS";

    for (let i = 0; i < lines.length; i++) {
      try {
        const entry: AuditEntry = JSON.parse(lines[i]);
        stats.total_entries++;

        // Determine if this is a legacy (SHA-256) or modern (SHA3-256) entry
        const isLegacy = !entry.hash_algorithm;
        if (isLegacy) stats.legacy_sha256++;

        // Track checkpoints
        if (entry.event === "CHECKPOINT") stats.checkpoints++;

        // Verify sequence continuity (anti-truncation)
        if (entry.seq !== undefined) {
          if (stats.max_seq >= 0 && entry.seq !== stats.max_seq + 1) {
            errors.push(
              `Line ${i + 1}: sequence gap — expected seq ${stats.max_seq + 1}, got ${entry.seq}`
            );
          }
          stats.max_seq = entry.seq;
        }

        // Verify hash chain
        if (entry.prev_hash !== expectedPrevHash) {
          errors.push(
            `Line ${i + 1}: chain broken — expected prev_hash ${expectedPrevHash.slice(0, 12)}..., got ${entry.prev_hash.slice(0, 12)}...`
          );
        }

        // Verify HMAC (classical)
        if (entry.hmac && this.hmacSecret) {
          stats.hmac_signed++;
          const { hmac, pq_signature, ...rest } = entry;
          const expectedHmac = createHmac("sha256", this.hmacSecret)
            .update(JSON.stringify(rest))
            .digest("hex");
          if (hmac !== expectedHmac) {
            errors.push(`Line ${i + 1}: HMAC mismatch — entry may be tampered`);
          }
        }

        // Verify ML-DSA-65 signature
        if (entry.pq_signature && this.signer?.available) {
          stats.pq_signed++;
          const { pq_signature, ...rest } = entry;
          const payload = Buffer.from(JSON.stringify(rest));
          if (!this.signer.verify(payload, pq_signature)) {
            errors.push(`Line ${i + 1}: ML-DSA-65 signature invalid — entry may be tampered`);
          }
        }

        // Compute hash for next entry's chain check.
        // Use the same algorithm that the NEXT entry would expect.
        // For the transition: if the next entry is modern, use SHA3-256.
        // If we're at the end or next is legacy, use whatever the current entry implies.
        // Simplification: always compute SHA3-256 for modern entries, SHA-256 for legacy.
        // The next entry's prev_hash was computed by the logger that wrote it.
        if (i + 1 < lines.length) {
          // Peek at next entry to determine which hash it expects
          try {
            const nextEntry: AuditEntry = JSON.parse(lines[i + 1]);
            const nextIsLegacy = !nextEntry.hash_algorithm;
            expectedPrevHash = nextIsLegacy
              ? sha256(lines[i])
              : sha3_256(lines[i]);
          } catch {
            // If next line is invalid JSON, use SHA3-256 (modern default)
            expectedPrevHash = sha3_256(lines[i]);
          }
        } else {
          // Last entry — compute for chain state
          expectedPrevHash = sha3_256(lines[i]);
        }
      } catch {
        errors.push(`Line ${i + 1}: invalid JSON`);
        stats.total_entries++;
      }
    }

    return { valid: errors.length === 0, errors, stats };
  }
}
