/**
 * Atlas Protocol — Separate-user isolation self-check (#23)
 *
 * The hardened deployment runs the gatekeeper as its own OS user, launched
 * from the agent's user through a single sudo rule
 * (deploy/separate-user/). This module reports whether the running
 * process actually has that isolation:
 *
 *   - It runs as a different user from the one that launched it (SUDO_UID,
 *     or ATLAS_AGENT_UID for other launchers).
 *   - Its data directory is owned by it and closed to group/other (0700),
 *     so the agent user cannot read or write the issuer key, audit log,
 *     registry, or agent keys.
 *   - The code it runs (package root, dist/, node_modules/) and the Node
 *     binary are not owned by the launching user and not group/other
 *     writable. Otherwise the agent could change what runs as the
 *     gatekeeper user on the next start.
 *
 * Checks are top-level (directories, not every file); the installer sets
 * ownership recursively.
 */

import { statSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface IsolationReport {
  isolated: boolean;
  process_uid: number | null;
  launched_by_uid: number | null;
  data_dir: string;
  problems: string[];
}

export interface IsolationInputs {
  dataDir: string;
  /** Package root containing dist/ and node_modules/ */
  packageRoot?: string;
  execPath?: string;
  env?: NodeJS.ProcessEnv;
  uid?: number | null;
}

const defaultPackageRoot = () => join(dirname(fileURLToPath(import.meta.url)), "..");

function parseUid(value: string | undefined): number | null {
  if (!value || !/^\d+$/.test(value)) return null;
  return Number(value);
}

export function checkIsolation(inputs: IsolationInputs): IsolationReport {
  const env = inputs.env ?? process.env;
  const uid = inputs.uid !== undefined ? inputs.uid : (typeof process.getuid === "function" ? process.getuid() : null);
  const launcher = parseUid(env.ATLAS_AGENT_UID) ?? parseUid(env.SUDO_UID);
  const problems: string[] = [];
  const report = (): IsolationReport => ({
    isolated: problems.length === 0,
    process_uid: uid,
    launched_by_uid: launcher,
    data_dir: inputs.dataDir,
    problems,
  });

  if (uid === null) {
    problems.push("OS user isolation is not supported on this platform");
    return report();
  }
  if (launcher === null) {
    problems.push("launching user unknown (not started via sudo; set ATLAS_AGENT_UID for other launchers)");
  } else if (launcher === uid) {
    problems.push(`gatekeeper runs as the launching user (uid ${uid})`);
  }

  try {
    const st = statSync(inputs.dataDir);
    if (st.uid !== uid) problems.push(`data dir is owned by uid ${st.uid}, not the gatekeeper (uid ${uid})`);
    if (st.mode & 0o077) problems.push(`data dir mode is ${(st.mode & 0o777).toString(8)}, expected 700`);
  } catch {
    problems.push("data dir is missing or unreadable");
  }

  const root = inputs.packageRoot ?? defaultPackageRoot();
  const guarded: Array<[string, string]> = [
    ["package root", root],
    ["dist/", join(root, "dist")],
    ["node_modules/", join(root, "node_modules")],
    ["node binary", inputs.execPath ?? process.execPath],
  ];
  for (const [label, path] of guarded) {
    try {
      const st = statSync(realpathSync(path));
      if (launcher !== null && st.uid === launcher) problems.push(`${label} is owned by the launching user`);
      if (st.mode & 0o022) problems.push(`${label} is group/other writable`);
    } catch {
      if (label !== "dist/") problems.push(`${label} is missing or unreadable`);
    }
  }

  return report();
}
