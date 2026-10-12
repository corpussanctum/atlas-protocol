/**
 * Atlas Protocol — Operator registry reset (SPEC §4.6 recovery)
 *
 * Re-opens the bootstrap window when the identity registry can no longer be
 * used: an accidental or compromised first registration, or every credential
 * holding identity:register has expired (#32). Operator-only: the caller must
 * hold the unlocked operator secret key.
 *
 * Order matters: the signed REGISTRY_RESET entry is written before the
 * registry file is touched, and the file is archived rather than deleted so
 * the reset can be checked against it later.
 */

import { createHash } from "node:crypto";
import { chmodSync, existsSync, readFileSync, renameSync } from "node:fs";
import { basename, join } from "node:path";
import { AuditLogger } from "./audit-log.js";
import type { AuditEntry } from "./audit-log.js";
import type { AtlasConfig } from "./config.js";
import type { AgentCredential } from "./agent-identity.js";
import { operatorSign } from "./operator-key.js";
import type { QuantumSigner } from "./quantum-signer.js";

export const REGISTRY_FILE = "identity-registry.json";

export interface RegistrySummary {
  path: string;
  sha3: string;
  total: number;
  active: number;
  expired: number;
  revoked: number;
}

export function registryPath(dataDir: string): string {
  return join(dataDir, REGISTRY_FILE);
}

/** Describe the registry on disk, or null if there is none. */
export function summarizeRegistry(dataDir: string, now = new Date()): RegistrySummary | null {
  const path = registryPath(dataDir);
  if (!existsSync(path)) return null;
  const content = readFileSync(path, "utf-8");
  const raw = JSON.parse(content);
  const creds: AgentCredential[] = Array.isArray(raw) ? raw : (raw.credentials ?? []);
  const summary = { path, sha3: createHash("sha3-256").update(content).digest("hex"), total: creds.length, active: 0, expired: 0, revoked: 0 };
  for (const c of creds) {
    if (c.revoked) summary.revoked++;
    else if (new Date(c.expiresAt) <= now) summary.expired++;
    else summary.active++;
  }
  return summary;
}

export interface RegistryResetResult {
  summary: RegistrySummary;
  archivedPath: string;
  entry: AuditEntry;
}

export async function resetIdentityRegistry(
  config: AtlasConfig,
  operator: { keyId: string; secretKey: Uint8Array },
  reason: string,
  signer: QuantumSigner | null,
  now = new Date(),
): Promise<RegistryResetResult | null> {
  const summary = summarizeRegistry(config.data_dir, now);
  if (!summary) return null;

  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const archivedPath = join(config.data_dir, `identity-registry.reset-${stamp}.json`);

  const payload = {
    action: "REGISTRY_RESET",
    reason,
    registry_sha3: summary.sha3,
    archived_as: basename(archivedPath),
    credentials_total: summary.total,
    credentials_active: summary.active,
    operator_key_id: operator.keyId,
    timestamp: now.toISOString(),
  };
  const operatorSignature = await operatorSign(operator.secretKey, payload);

  const audit = new AuditLogger(config, undefined, signer);
  const entry = audit.log("REGISTRY_RESET", {
    meta: {
      ...payload,
      credentials_expired: summary.expired,
      credentials_revoked: summary.revoked,
      operator_signature: operatorSignature,
    },
  });

  renameSync(summary.path, archivedPath);
  try {
    chmodSync(archivedPath, 0o600);
  } catch {
    // Non-fatal
  }

  return { summary, archivedPath, entry };
}
