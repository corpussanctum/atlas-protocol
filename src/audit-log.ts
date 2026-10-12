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

import { createHmac, createHash, randomBytes, randomUUID } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  existsSync,
  fstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
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
  | "KEY_ROTATION"
  | "REGISTRY_RESET"
  | "IDENTITY_ATTACHED"
  // Proximity Mesh events (SPEC § 13.4)
  | "PROXIMITY_DISCOVERY"
  | "PROXIMITY_RANGE"
  | "PROXIMITY_VERIFIED"
  | "PROXIMITY_REJECTED"
  | "PROXIMITY_SESSION_ESTABLISHED"
  | "PROXIMITY_SESSION_CLOSED"
  | "PROXIMITY_RERANGE"
  | "PROXIMITY_DELEGATION"
  | "PROXIMITY_HARDWARE_SELECTED"
  | "PROXIMITY_HARDWARE_ERROR";

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
// Cross-process append lock
// ---------------------------------------------------------------------------
//
// Every Claude Code session runs its own Atlas server, and they all append to
// the same log. Without a lock, two instances extend the chain from their own
// stale (seq, prev_hash) and fork it (#30). The lock is an O_EXCL lockfile so
// it needs no native addon; a holder that died mid-append leaves a file that
// is broken after LOCK_STALE_MS.

const LOCK_STALE_MS = 5_000;
const LOCK_GIVE_UP_MS = 15_000;
const LOCK_POLL_MS = 5;
/** Bytes read from the end of the log to find the last line (entries are ~5 KB). */
const TAIL_READ_BYTES = 64 * 1024;

const sleepCell = new Int32Array(new SharedArrayBuffer(4));
function sleepSync(ms: number): void {
  Atomics.wait(sleepCell, 0, 0, ms);
}

function acquireLock(lockPath: string): boolean {
  const start = Date.now();
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      writeSync(fd, String(process.pid));
      closeSync(fd);
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") return false;
    }
    try {
      const held = statSync(lockPath);
      if (Date.now() - held.mtimeMs > LOCK_STALE_MS) {
        breakStaleLock(lockPath, held.ino);
        continue;
      }
    } catch {
      continue; // released between our open and stat
    }
    if (Date.now() - start > LOCK_GIVE_UP_MS) return false;
    sleepSync(LOCK_POLL_MS);
  }
}

/**
 * Remove a stale lock without clobbering a fresh one. Two waiters can both
 * judge the same lock stale; a plain unlink by the slower one would delete
 * the lock the faster one just took. Instead, move it aside and check it is
 * the inode we judged stale; if not, put it back (link fails if a newer lock
 * already exists, in which case that one wins).
 */
/** @internal exported for tests */
export function breakStaleLock(lockPath: string, staleIno: number): void {
  const aside = `${lockPath}.stale-${process.pid}-${randomBytes(4).toString("hex")}`;
  try {
    renameSync(lockPath, aside);
  } catch {
    return; // someone else moved or released it
  }
  try {
    if (statSync(aside).ino !== staleIno) linkSync(aside, lockPath);
  } catch {
    // a newer lock is in place
  }
  try {
    unlinkSync(aside);
  } catch {
    // ignore
  }
}

function releaseLock(lockPath: string): void {
  try {
    unlinkSync(lockPath);
  } catch {
    // already gone (broken as stale by another instance)
  }
}

/** Last non-empty line of a file, reading only its tail when possible. */
function readLastLine(path: string): string | null {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return null;
  }
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return null;
    const start = Math.max(0, size - TAIL_READ_BYTES);
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    const text = buf.toString("utf-8").trimEnd();
    const nl = text.lastIndexOf("\n");
    if (nl === -1 && start > 0) {
      // Last line is longer than the tail window — fall back to a full read.
      const lines = readFileSync(fd, "utf-8").trimEnd().split("\n");
      return lines[lines.length - 1] || null;
    }
    return text.slice(nl + 1) || null;
  } finally {
    closeSync(fd);
  }
}

// ---------------------------------------------------------------------------
// Audit Logger
// ---------------------------------------------------------------------------

export class AuditLogger {
  private readonly logPath: string;
  private readonly lockPath: string;
  /** Log size right after this instance last read or wrote it; -1 = missing */
  private lastKnownSize: number;
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
    this.lockPath = `${config.audit_log_path}.lock`;
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
    this.lastKnownSize = this.currentSize();
  }

  private currentSize(): number {
    try {
      return statSync(this.logPath).size;
    } catch {
      return -1;
    }
  }

  /**
   * Re-read the chain head if another instance appended since we last looked.
   * Must be called with the append lock held. A missing or empty file (just
   * rotated) keeps the in-memory head, which is the rotation's chain anchor.
   */
  private syncChainHead(): void {
    const size = this.currentSize();
    if (size === this.lastKnownSize || size <= 0) return;
    const lastLine = readLastLine(this.logPath);
    if (!lastLine) return;
    this.prevHash = sha3_256(lastLine);
    try {
      const lastEntry = JSON.parse(lastLine) as AuditEntry;
      if (typeof lastEntry.seq === "number") this.seq = lastEntry.seq + 1;
    } catch {
      // Unparseable tail: chain to it by hash, keep our own seq.
    }
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
    const locked = acquireLock(this.lockPath);
    if (!locked) {
      console.error("[atlas] audit lock unavailable — appending unlocked; chain may fork");
    }
    let entry: AuditEntry;
    try {
      this.syncChainHead();
      entry = this.appendEntry(event, options);
      this.lastKnownSize = this.currentSize();
    } finally {
      if (locked) releaseLock(this.lockPath);
    }

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

  /** Build, sign, and append one entry. Caller holds the append lock. */
  private appendEntry(
    event: AuditEventType,
    options: {
      permission?: PermissionRequest;
      policy_result?: PolicyResult;
      verdict?: "allow" | "deny";
      meta?: Record<string, unknown>;
    },
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
   *   5. Entry id uniqueness (replay)
   *
   * Concurrent-writer forks (#30) are reported in `forks`, not `errors`: an
   * entry whose prev_hash names an earlier, non-adjacent line and whose seq is
   * that line's seq + 1 was written by a second server instance from a stale
   * chain head. Logs written before the append lock existed contain these.
   * They do not fail verification, but within a forked region the tail of
   * each branch is not protected against truncation by the chain alone.
   */
  verify(): {
    valid: boolean;
    errors: string[];
    forks: string[];
    stats: {
      total_entries: number;
      pq_signed: number;
      hmac_signed: number;
      legacy_sha256: number;
      checkpoints: number;
      max_seq: number;
      forks: number;
    };
  } {
    const errors: string[] = [];
    const forks: string[] = [];
    const stats = {
      total_entries: 0,
      pq_signed: 0,
      hmac_signed: 0,
      legacy_sha256: 0,
      checkpoints: 0,
      max_seq: -1,
      forks: 0,
    };

    if (!existsSync(this.logPath)) {
      return { valid: true, errors: [], forks: [], stats };
    }

    const content = readFileSync(this.logPath, "utf-8").trim();
    if (!content) return { valid: true, errors: [], forks: [], stats };

    const lines = content.split("\n");
    /** Hash (SHA3-256 and legacy SHA-256) of every earlier line → line index */
    const lineByHash = new Map<string, number>();
    /** seq of each line, when present and the line parsed */
    const seqs: (number | undefined)[] = [];
    const seenIds = new Set<string>();

    for (let i = 0; i < lines.length; i++) {
      try {
        const entry: AuditEntry = JSON.parse(lines[i]);
        stats.total_entries++;
        seqs[i] = entry.seq;

        // Determine if this is a legacy (SHA-256) or modern (SHA3-256) entry
        const isLegacy = !entry.hash_algorithm;
        if (isLegacy) stats.legacy_sha256++;

        // Track checkpoints
        if (entry.event === "CHECKPOINT") stats.checkpoints++;
        if (entry.seq !== undefined) stats.max_seq = Math.max(stats.max_seq, entry.seq);

        // A copied signed entry would otherwise pass as a fork
        if (entry.id) {
          if (seenIds.has(entry.id)) {
            errors.push(`Line ${i + 1}: duplicate entry id ${entry.id} — entry replayed`);
          }
          seenIds.add(entry.id);
        }

        // Resolve the parent: the adjacent line, or an earlier line (fork).
        // The entry's own algorithm says how its writer hashed the parent.
        const adjacentHash =
          i === 0 ? "GENESIS" : isLegacy ? sha256(lines[i - 1]) : sha3_256(lines[i - 1]);
        let parent: number | undefined;
        if (entry.prev_hash === adjacentHash) {
          parent = i - 1;
        } else {
          parent = lineByHash.get(entry.prev_hash);
          if (parent === undefined) {
            errors.push(
              `Line ${i + 1}: chain broken — expected prev_hash ${adjacentHash.slice(0, 12)}..., got ${entry.prev_hash.slice(0, 12)}...`
            );
          }
        }

        // Verify sequence continuity against the resolved parent (anti-truncation)
        const parentSeq = parent !== undefined && parent >= 0 ? seqs[parent] : undefined;
        if (entry.seq !== undefined && parentSeq !== undefined && entry.seq !== parentSeq + 1) {
          errors.push(
            `Line ${i + 1}: sequence gap — expected seq ${parentSeq + 1}, got ${entry.seq}`
          );
        } else if (parent !== undefined && parent !== i - 1) {
          stats.forks++;
          forks.push(
            `Line ${i + 1}: concurrent-writer fork — seq ${entry.seq} chains to line ${parent + 1} (seq ${parentSeq}), not line ${i}`
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
      } catch {
        errors.push(`Line ${i + 1}: invalid JSON`);
        stats.total_entries++;
      }

      lineByHash.set(sha3_256(lines[i]), i);
      lineByHash.set(sha256(lines[i]), i);
    }

    return { valid: errors.length === 0 && forks.length === 0, errors, forks, stats };
  }
}
