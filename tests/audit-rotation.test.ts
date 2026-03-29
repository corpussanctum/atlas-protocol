/**
 * Tests for Atlas Protocol — Audit Log Rotation (v0.8.0)
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, writeFileSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AuditRotationManager } from "../src/audit-rotation.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let testDir: string;
let auditPath: string;

function setup() {
  testDir = mkdtempSync(join(tmpdir(), "atlas-rot-test-"));
  auditPath = join(testDir, "audit.jsonl");
}

function cleanup() {
  if (testDir && existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
}

function writeLines(path: string, count: number): void {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    lines.push(JSON.stringify({
      id: `entry-${i}`,
      timestamp: new Date().toISOString(),
      event: "TEST_EVENT",
      prev_hash: i === 0 ? "GENESIS" : `hash-${i - 1}`,
    }));
  }
  writeFileSync(path, lines.join("\n") + "\n", "utf-8");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AuditRotationManager — needsRotation", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("returns false when no audit file exists", () => {
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 100 });
    assert.equal(mgr.needsRotation(), false);
  });

  it("returns false when file is below threshold", () => {
    writeFileSync(auditPath, '{"small": true}\n', "utf-8");
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1000 });
    assert.equal(mgr.needsRotation(), false);
  });

  it("returns true when file exceeds threshold", () => {
    // Write enough data to exceed 100 bytes
    writeFileSync(auditPath, "x".repeat(200) + "\n", "utf-8");
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 100 });
    assert.equal(mgr.needsRotation(), true);
  });
});

describe("AuditRotationManager — rotate", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("moves audit file to archive directory", () => {
    writeLines(auditPath, 10);
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1 });
    const result = mgr.rotate();

    assert.ok(result, "rotate should return a result");
    assert.ok(result.record.rotated_name.startsWith("audit-"));
    assert.ok(result.record.rotated_name.endsWith(".jsonl"));
    assert.equal(result.record.entry_count, 10);
    assert.ok(result.record.size_bytes > 0);
    assert.ok(result.record.final_hash.length > 0);
    assert.ok(result.record.file_hash.length > 0);
    assert.ok(result.chainAnchor.length > 0);

    // Original file should be gone
    assert.equal(existsSync(auditPath), false);

    // Archive file should exist
    const archivePath = join(testDir, "audit-archive", result.record.rotated_name);
    assert.ok(existsSync(archivePath));
  });

  it("returns null for empty/missing file", () => {
    const mgr = new AuditRotationManager(auditPath);
    assert.equal(mgr.rotate(), null);
  });

  it("returns null for empty content", () => {
    writeFileSync(auditPath, "", "utf-8");
    const mgr = new AuditRotationManager(auditPath);
    assert.equal(mgr.rotate(), null);
  });

  it("creates and updates rotation manifest", () => {
    writeLines(auditPath, 5);
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1 });
    mgr.rotate();

    const manifestPath = join(testDir, "audit-archive", "audit-rotation.json");
    assert.ok(existsSync(manifestPath));

    const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
    assert.equal(manifest.rotations.length, 1);
    assert.equal(manifest.current_log, auditPath);
  });

  it("appends to manifest on multiple rotations", () => {
    // First rotation
    writeLines(auditPath, 5);
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1 });
    mgr.rotate();

    // Second rotation
    writeLines(auditPath, 3);
    mgr.rotate();

    const archives = mgr.listArchives();
    assert.equal(archives.length, 2);
    assert.equal(archives[0].entry_count, 5);
    assert.equal(archives[1].entry_count, 3);
  });
});

describe("AuditRotationManager — verifyArchives", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("returns valid for intact archives", () => {
    writeLines(auditPath, 10);
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1 });
    mgr.rotate();

    const result = mgr.verifyArchives();
    assert.equal(result.valid, true);
    assert.equal(result.verified, 1);
    assert.equal(result.errors.length, 0);
  });

  it("detects tampered archive", () => {
    writeLines(auditPath, 10);
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1 });
    const rotResult = mgr.rotate()!;

    // Tamper with the archive
    const archivePath = join(testDir, "audit-archive", rotResult.record.rotated_name);
    const content = readFileSync(archivePath, "utf-8");
    writeFileSync(archivePath, content + '{"injected": true}\n', "utf-8");

    const result = mgr.verifyArchives();
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("Tampered")));
  });

  it("detects missing archive file", () => {
    writeLines(auditPath, 5);
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1 });
    const rotResult = mgr.rotate()!;

    // Delete the archive
    const archivePath = join(testDir, "audit-archive", rotResult.record.rotated_name);
    unlinkSync(archivePath);

    const result = mgr.verifyArchives();
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("Missing")));
  });
});

describe("AuditRotationManager — pruning", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("prunes archives beyond max_archives", () => {
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1, max_archives: 2 });

    // Create 3 rotations
    writeLines(auditPath, 3);
    const r1 = mgr.rotate()!;
    writeLines(auditPath, 3);
    mgr.rotate();
    writeLines(auditPath, 3);
    mgr.rotate();

    const archives = mgr.listArchives();
    assert.equal(archives.length, 2, "Should only keep 2 archives");

    // First rotation should be pruned
    const prunedPath = join(testDir, "audit-archive", r1.record.rotated_name);
    assert.equal(existsSync(prunedPath), false, "Oldest archive should be deleted");
  });
});

describe("AuditRotationManager — getStats", () => {
  beforeEach(() => setup());
  afterEach(() => cleanup());

  it("returns zero stats when no archives", () => {
    const mgr = new AuditRotationManager(auditPath);
    const stats = mgr.getStats();
    assert.equal(stats.archive_count, 0);
    assert.equal(stats.total_entries, 0);
    assert.equal(stats.total_size_bytes, 0);
  });

  it("returns aggregate stats across archives", () => {
    const mgr = new AuditRotationManager(auditPath, { max_size_bytes: 1 });
    writeLines(auditPath, 5);
    mgr.rotate();
    writeLines(auditPath, 10);
    mgr.rotate();

    const stats = mgr.getStats();
    assert.equal(stats.archive_count, 2);
    assert.equal(stats.total_entries, 15);
    assert.ok(stats.total_size_bytes > 0);
    assert.ok(stats.oldest_archive);
    assert.ok(stats.newest_archive);
  });
});
