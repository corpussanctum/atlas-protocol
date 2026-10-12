/**
 * Helpers shared by the MCP server and its tool modules.
 */

import { writeFileSync, unlinkSync, chmodSync } from "node:fs";
import { join } from "node:path";

/**
 * Write a confirmation code (bootstrap or break-glass) to a single-use file
 * inside `data_dir` with mode 0600. This makes the code reachable when Atlas
 * runs as a stdio MCP child process, where stdout is the JSON-RPC channel and
 * stderr may be captured by the parent (and not visible to the operator).
 *
 * Two-channel security per SPEC §4.6 is preserved: filesystem access on the
 * host is the equivalent of physical/SSH console access — it remains a
 * separate channel from the Telegram operator relay.
 *
 * Caller MUST invoke `clearConfirmCodeFile` after the confirmation flow ends
 * (success, denial, or timeout) to enforce single-use semantics.
 */
export function writeConfirmCodeFile(dataDir: string, filename: string, code: string): string {
  const filePath = join(dataDir, filename);
  writeFileSync(filePath, code + "\n", { mode: 0o600 });
  // Defensive: ensure mode 0600 even if umask interfered with the create-mode
  try { chmodSync(filePath, 0o600); } catch { /* best effort */ }
  return filePath;
}

export function clearConfirmCodeFile(dataDir: string, filename: string): void {
  try {
    unlinkSync(join(dataDir, filename));
  } catch {
    // Best effort — file may not exist if it was never written
  }
}

/**
 * Compute time-remaining fields for a credential.
 */
export function credentialTimeRemaining(expiresAt: string): { timeRemainingMs: number; timeRemainingHuman: string } {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return { timeRemainingMs: 0, timeRemainingHuman: "expired" };
  const hours = Math.floor(ms / 3_600_000);
  const minutes = Math.floor((ms % 3_600_000) / 60_000);
  if (hours > 0) return { timeRemainingMs: ms, timeRemainingHuman: `${hours}h ${minutes}m` };
  return { timeRemainingMs: ms, timeRemainingHuman: `${minutes}m` };
}
