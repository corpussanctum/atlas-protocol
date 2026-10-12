/**
 * Tests for the separate-user isolation self-check (#23).
 *
 * Ownership by a different user can't be arranged without root, so these
 * cover the checks a single user can exercise; the CI job
 * `separate-user isolation` runs the real two-user deployment.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkIsolation } from "../src/isolation.js";

const uid = process.getuid!();
const OTHER = uid + 4242;

describe("checkIsolation", () => {
  let base: string;
  let dataDir: string;
  let packageRoot: string;
  let execPath: string;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), "atlas-isolation-"));
    dataDir = join(base, "data");
    packageRoot = join(base, "pkg");
    mkdirSync(dataDir, { mode: 0o700 });
    for (const d of [packageRoot, join(packageRoot, "dist"), join(packageRoot, "node_modules")]) {
      mkdirSync(d);
      chmodSync(d, 0o755);
    }
    execPath = join(base, "node");
    writeFileSync(execPath, "");
    chmodSync(execPath, 0o755);
  });
  afterEach(() => rmSync(base, { recursive: true, force: true }));

  const check = (env: NodeJS.ProcessEnv) => checkIsolation({ dataDir, packageRoot, execPath, env, uid });

  it("is isolated when launched by another user with private state and protected code", () => {
    const r = check({ SUDO_UID: String(OTHER) });
    assert.deepEqual(r.problems, []);
    assert.equal(r.isolated, true);
    assert.equal(r.launched_by_uid, OTHER);
  });

  it("is not isolated when the gatekeeper runs as the launching user", () => {
    const r = check({ SUDO_UID: String(uid) });
    assert.equal(r.isolated, false);
    assert.ok(r.problems.some((p) => p.includes("runs as the launching user")));
  });

  it("is not isolated when the launching user is unknown", () => {
    assert.ok(check({}).problems.some((p) => p.includes("launching user unknown")));
  });

  it("prefers ATLAS_AGENT_UID over SUDO_UID", () => {
    assert.equal(check({ ATLAS_AGENT_UID: String(OTHER), SUDO_UID: String(uid) }).isolated, true);
  });

  it("flags a data dir open to group or other", () => {
    chmodSync(dataDir, 0o750);
    const r = check({ SUDO_UID: String(OTHER) });
    assert.ok(r.problems.some((p) => p.includes("data dir mode is 750")));
  });

  it("flags agent-owned or writable code and Node binary", () => {
    chmodSync(join(packageRoot, "node_modules"), 0o775);
    chmodSync(execPath, 0o777);
    const r = check({ SUDO_UID: String(OTHER) });
    assert.ok(r.problems.includes("node_modules/ is group/other writable"));
    assert.ok(r.problems.includes("node binary is group/other writable"));

    // Here the test user owns the code, so treat it as the launcher
    const owned = checkIsolation({ dataDir, packageRoot, execPath, env: { SUDO_UID: String(uid) }, uid: OTHER });
    assert.ok(owned.problems.includes("package root is owned by the launching user"));
    assert.ok(owned.problems.some((p) => p.includes("data dir is owned by uid")));
  });
});
