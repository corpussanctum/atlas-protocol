/**
 * Atlas Protocol — Audit Log Rotation (v0.8.0)
 *
 * Rotates the audit JSONL log when it exceeds a size threshold.
 * Preserves hash chain integrity across rotated files by recording
 * the final hash of the previous file as the genesis of the new one.
 *
 * Rotation metadata is stored in audit-rotation.json alongside the
 * rotated files, enabling verification across the full archive.
 *
 * File naming: audit-YYYYMMDD-HHMMSS.jsonl
 * Archive dir: <data_dir>/audit-archive/
 */

import {
  existsSync,
  statSync,
  renameSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  readdirSync,
  chmodSync,
  unlinkSync,
} from "node:fs";
import { join, dirname, basename } from "node:path";
import { createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RotationRecord {
  /** Original filename before rotation */
  original_name: string;
  /** Filename after rotation */
  rotated_name: string;
  /** When rotation happened */
  rotated_at: string;
  /** Number of entries in the rotated file */
  entry_count: number;
  /** Size in bytes of the rotated file */
  size_bytes: number;
  /** SHA3-256 hash of the last line (chain continuity anchor) */
  final_hash: string;
  /** SHA3-256 hash of the entire file (integrity check) */
  file_hash: string;
}

export interface RotationManifest {
  /** Ordered list of rotations (oldest first) */
  rotations: RotationRecord[];
  /** Current (active) audit log path */
  current_log: string;
}

export interface RotationConfig {
  /** Maximum audit log size in bytes before rotation (default: 10MB) */
  max_size_bytes: number;
  /** Where to store rotated files (default: <data_dir>/audit-archive/) */
  archive_dir: string;
  /** Maximum number of archived files to keep (0 = unlimited) */
  max_archives: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha3_256(data: string): string {
  return createHash("sha3-256").update(data).digest("hex");
}

function formatTimestamp(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}` +
    `-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`
  );
}

// ---------------------------------------------------------------------------
// Rotation Manager
// ---------------------------------------------------------------------------

export class AuditRotationManager {
  private readonly auditLogPath: string;
  private readonly config: RotationConfig;
  private readonly manifestPath: string;

  constructor(auditLogPath: string, config?: Partial<RotationConfig>) {
    this.auditLogPath = auditLogPath;
    const dataDir = dirname(auditLogPath);

    this.config = {
      max_size_bytes: config?.max_size_bytes ?? 10 * 1024 * 1024, // 10MB
      archive_dir: config?.archive_dir ?? join(dataDir, "audit-archive"),
      max_archives: config?.max_archives ?? 0,
    };

    this.manifestPath = join(this.config.archive_dir, "audit-rotation.json");
  }

  /**
   * Check if the current audit log needs rotation.
   */
  needsRotation(): boolean {
    if (!existsSync(this.auditLogPath)) return false;
    try {
      const stat = statSync(this.auditLogPath);
      return stat.size >= this.config.max_size_bytes;
    } catch {
      return false;
    }
  }

  /**
   * Get the current size of the audit log in bytes.
   */
  currentSize(): number {
    if (!existsSync(this.auditLogPath)) return 0;
    try {
      return statSync(this.auditLogPath).size;
    } catch {
      return 0;
    }
  }

  /**
   * Rotate the audit log. Returns the rotation record or null if rotation not needed.
   *
   * Steps:
   * 1. Read the current audit log to get final hash and entry count
   * 2. Move the file to the archive directory with a timestamped name
   * 3. Update the rotation manifest
   * 4. Prune old archives if max_archives is set
   * 5. Return the chain anchor hash (new file should use this as prev_hash)
   */
  rotate(): { record: RotationRecord; chainAnchor: string } | null {
    if (!existsSync(this.auditLogPath)) return null;

    // Read file content for metadata
    const content = readFileSync(this.auditLogPath, "utf-8");
    const trimmed = content.trim();
    if (!trimmed) return null;

    const lines = trimmed.split("\n");
    const lastLine = lines[lines.length - 1];
    const finalHash = sha3_256(lastLine);
    const fileHash = sha3_256(content);
    const fileSize = Buffer.byteLength(content, "utf-8");

    // Create archive directory
    if (!existsSync(this.config.archive_dir)) {
      mkdirSync(this.config.archive_dir, { recursive: true });
    }

    // Generate rotated filename
    const rotatedName = `audit-${formatTimestamp()}.jsonl`;
    const rotatedPath = join(this.config.archive_dir, rotatedName);

    // Move the file
    renameSync(this.auditLogPath, rotatedPath);
    try {
      chmodSync(rotatedPath, 0o600);
    } catch {
      // Non-fatal
    }

    const record: RotationRecord = {
      original_name: basename(this.auditLogPath),
      rotated_name: rotatedName,
      rotated_at: new Date().toISOString(),
      entry_count: lines.length,
      size_bytes: fileSize,
      final_hash: finalHash,
      file_hash: fileHash,
    };

    // Update manifest
    const manifest = this.loadManifest();
    manifest.rotations.push(record);
    manifest.current_log = this.auditLogPath;
    this.saveManifest(manifest);

    // Prune old archives
    if (this.config.max_archives > 0) {
      this.pruneArchives(manifest);
    }

    return { record, chainAnchor: finalHash };
  }

  /**
   * List all rotated archive files with their metadata.
   */
  listArchives(): RotationRecord[] {
    const manifest = this.loadManifest();
    return manifest.rotations;
  }

  /**
   * Verify integrity of all archived files.
   * Checks file hashes against manifest records.
   */
  verifyArchives(): {
    valid: boolean;
    errors: string[];
    verified: number;
  } {
    const manifest = this.loadManifest();
    const errors: string[] = [];
    let verified = 0;

    for (const record of manifest.rotations) {
      const archivePath = join(this.config.archive_dir, record.rotated_name);
      if (!existsSync(archivePath)) {
        errors.push(`Missing archive: ${record.rotated_name}`);
        continue;
      }

      const content = readFileSync(archivePath, "utf-8");
      const fileHash = sha3_256(content);
      if (fileHash !== record.file_hash) {
        errors.push(`Tampered archive: ${record.rotated_name} (hash mismatch)`);
        continue;
      }

      // Verify final hash matches
      const lines = content.trim().split("\n");
      const lastLine = lines[lines.length - 1];
      const finalHash = sha3_256(lastLine);
      if (finalHash !== record.final_hash) {
        errors.push(`Chain anchor mismatch: ${record.rotated_name}`);
        continue;
      }

      verified++;
    }

    return {
      valid: errors.length === 0,
      errors,
      verified,
    };
  }

  /**
   * Get archive summary stats.
   */
  getStats(): {
    archive_count: number;
    total_entries: number;
    total_size_bytes: number;
    oldest_archive?: string;
    newest_archive?: string;
  } {
    const manifest = this.loadManifest();
    const totalEntries = manifest.rotations.reduce((s, r) => s + r.entry_count, 0);
    const totalSize = manifest.rotations.reduce((s, r) => s + r.size_bytes, 0);

    return {
      archive_count: manifest.rotations.length,
      total_entries: totalEntries,
      total_size_bytes: totalSize,
      oldest_archive: manifest.rotations[0]?.rotated_at,
      newest_archive: manifest.rotations[manifest.rotations.length - 1]?.rotated_at,
    };
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private loadManifest(): RotationManifest {
    if (!existsSync(this.manifestPath)) {
      return { rotations: [], current_log: this.auditLogPath };
    }
    try {
      return JSON.parse(readFileSync(this.manifestPath, "utf-8"));
    } catch {
      return { rotations: [], current_log: this.auditLogPath };
    }
  }

  private saveManifest(manifest: RotationManifest): void {
    writeFileSync(this.manifestPath, JSON.stringify(manifest, null, 2), "utf-8");
    try {
      chmodSync(this.manifestPath, 0o600);
    } catch {
      // Non-fatal
    }
  }

  private pruneArchives(manifest: RotationManifest): void {
    while (manifest.rotations.length > this.config.max_archives) {
      const oldest = manifest.rotations.shift()!;
      const oldPath = join(this.config.archive_dir, oldest.rotated_name);
      try {
        if (existsSync(oldPath)) {
          unlinkSync(oldPath);
        }
      } catch {
        // Non-fatal
      }
    }
    this.saveManifest(manifest);
  }
}
