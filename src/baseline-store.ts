/**
 * Atlas Protocol — Baseline Store (v0.7.0)
 *
 * JSON-file persistence for per-agent behavioral baselines.
 * Storage: <dataDir>/baselines/<agentId-safe>.json (chmod 600)
 *
 * Design decision: JSON files over SQLite for consistency with existing
 * persistence patterns (identity-registry, quantum-keypair, config).
 * Per-agent profiles store derived statistics only, keeping file sizes
 * small even for mature baselines with 1000+ sessions.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync, chmodSync, renameSync } from "node:fs";
import { join, dirname } from "node:path";
import type { BaselineProfile } from "./baseline-types.js";

export class BaselineStore {
  private readonly baseDir: string;

  constructor(dataDir: string) {
    this.baseDir = join(dataDir, "baselines");
    if (!existsSync(this.baseDir)) {
      mkdirSync(this.baseDir, { recursive: true });
    }
  }

  private safePath(agentId: string): string {
    // did:atlas:uuid → did-atlas-uuid.json
    const safe = agentId.replace(/[^a-zA-Z0-9-]/g, "-");
    return join(this.baseDir, `${safe}.json`);
  }

  async get(agentId: string): Promise<BaselineProfile | undefined> {
    const path = this.safePath(agentId);
    if (!existsSync(path)) return undefined;
    try {
      return JSON.parse(readFileSync(path, "utf-8")) as BaselineProfile;
    } catch {
      console.error(`[atlas] WARNING: corrupt baseline file for ${agentId}, ignoring`);
      return undefined;
    }
  }

  async save(profile: BaselineProfile): Promise<void> {
    const path = this.safePath(profile.agentId);
    const dir = dirname(path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    // Atomic write: temp file then rename
    const tmp = path + ".tmp";
    writeFileSync(tmp, JSON.stringify(profile, null, 2), "utf-8");
    try { chmodSync(tmp, 0o600); } catch { /* non-fatal */ }
    renameSync(tmp, path);
  }

  async list(filter?: {
    maturity?: BaselineProfile["maturityLevel"];
    role?: string;
    updatedAfter?: string;
  }): Promise<BaselineProfile[]> {
    if (!existsSync(this.baseDir)) return [];
    const files = readdirSync(this.baseDir).filter(f => f.endsWith(".json"));
    const profiles: BaselineProfile[] = [];
    for (const file of files) {
      try {
        const p = JSON.parse(readFileSync(join(this.baseDir, file), "utf-8")) as BaselineProfile;
        if (filter?.maturity && p.maturityLevel !== filter.maturity) continue;
        if (filter?.role && p.agentRole !== filter.role) continue;
        if (filter?.updatedAfter && p.updatedAt < filter.updatedAfter) continue;
        profiles.push(p);
      } catch { /* skip corrupt files */ }
    }
    return profiles;
  }

  async delete(agentId: string): Promise<void> {
    const path = this.safePath(agentId);
    if (existsSync(path)) {
      try { unlinkSync(path); } catch { /* non-fatal */ }
    }
  }

  async count(): Promise<number> {
    if (!existsSync(this.baseDir)) return 0;
    return readdirSync(this.baseDir).filter(f => f.endsWith(".json")).length;
  }
}
