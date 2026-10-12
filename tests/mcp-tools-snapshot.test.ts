/**
 * Snapshot characterization of the MCP tool surface (#5).
 *
 *   - tools/list (names, descriptions, input schemas, annotations)
 *   - a scripted call to every tool on a live server, normalized for ids,
 *     timestamps, hashes and paths
 *
 * Any change in tool behavior or schema shows up as a snapshot diff. Update
 * intentionally with:  UPDATE_SNAPSHOTS=1 npm test
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "..", "src", "index.js");
const FIXTURES = join(process.cwd(), "tests", "fixtures");
const UPDATE = process.env.UPDATE_SNAPSHOTS === "1";

function matchSnapshot(name: string, actual: unknown): void {
  const path = join(FIXTURES, name);
  const text = JSON.stringify(actual, null, 2) + "\n";
  if (UPDATE || !existsSync(path)) {
    mkdirSync(FIXTURES, { recursive: true });
    writeFileSync(path, text);
    if (!UPDATE) assert.fail(`Snapshot ${name} did not exist and was written; re-run to verify`);
    return;
  }
  assert.equal(text, readFileSync(path, "utf-8"), `Snapshot ${name} changed (UPDATE_SNAPSHOTS=1 to accept)`);
}

function normalizer(dataDir: string): (s: string) => string {
  const ids = new Map<string, string>();
  const stable = (kind: string, v: string) => {
    if (!ids.has(v)) ids.set(v, `<${kind}${ids.size + 1}>`);
    return ids.get(v)!;
  };
  return (s) =>
    s
      .split(dataDir).join("<DATA_DIR>")
      .replace(/did:atlas:[A-Za-z0-9._:-]+/g, (m) => stable("DID", m))
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, (m) => stable("UUID", m))
      .replace(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g, "<TS>")
      .replace(/\d{1,2}\/\d{1,2}\/\d{4},? \d{1,2}:\d\d:\d\d( [AP]M)?/g, "<LOCALTIME>")
      .replace(/\b[0-9a-f]{16,}\b/g, "<HEX>")
      .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, "<B64>")
      .replace(/"(duration_ms|durationMs|elapsed_ms|remaining_seconds|remainingSeconds|timeRemainingMs|size_bytes|uptime_seconds)": [\d.]+/g, '"$1": <N>')
      .replace(/\b\d+(\.\d+)?\s?ms\b/g, "<N>ms")
      .replace(/\b\d{8}-\d{6}\b/g, "<STAMP>")
      .replace(/"(size_mb|total_size_mb)": "[\d.]+"/g, '"$1": "<N>"')
      .replace(/"(issuerSignature|signature|chainSignature)": "[^"]+"/g, '"$1": "<SIG>"')
      .replace(/"timeRemainingHuman": "[^"]+"/g, '"timeRemainingHuman": "<DURATION>"')
      // Depends on the host's users and file modes (#23)
      .replace(/"isolation": \{[^}]*\}/g, '"isolation": "<ISOLATION>"');
}

describe("MCP tool surface (snapshot)", () => {
  let client: Client;
  let dataDir: string;
  let norm: (s: string) => string;

  before(async () => {
    dataDir = mkdtempSync(join(tmpdir(), "atlas-snap-"));
    norm = normalizer(dataDir);
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined && !k.startsWith("ATLAS_") && !k.startsWith("WHY_ENGINE_") && k !== "CLAUDE_PLUGIN_DATA") env[k] = v;
    }
    Object.assign(env, { ATLAS_DATA_DIR: dataDir, WHY_ENGINE_ENABLED: "false", TZ: "UTC", LANG: "C" });
    client = new Client({ name: "snapshot", version: "0.0.0" });
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [SERVER], env, stderr: "ignore" }));
  });
  after(async () => {
    await client.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("tools/list is unchanged", async () => {
    const { tools } = await client.listTools();
    matchSnapshot("tools-list.json", tools);
  });

  it("scripted calls to every tool are unchanged", async () => {
    const transcript: Array<{ tool: string; isError: boolean; text: string }> = [];
    const call = async (tool: string, args: Record<string, unknown> = {}) => {
      const res: any = await client.callTool({ name: tool, arguments: args });
      const text = norm((res.content ?? []).map((c: any) => c.text ?? "").join("\n"));
      transcript.push({ tool, isError: !!res.isError, text });
      return (res.content ?? [])[0]?.text ?? "";
    };
    const agentIdFrom = (text: string) => {
      const m = text.match(/did:atlas:[A-Za-z0-9._:-]+/);
      assert.ok(m, `no agent id in: ${text.slice(0, 200)}`);
      return m[0];
    };

    await call("atlas_status");
    await call("atlas_test_policy");
    await call("atlas_identity_list", { filter: "all" });
    const parent = agentIdFrom(await call("atlas_identity_register", {
      name: "orchestrator", role: "orchestrator", capabilities: ["file:read", "file:write", "process:spawn"],
    }));
    await call("atlas_identity_verify", { agent_id: parent });
    await call("atlas_identity_attach"); // already bound
    await call("atlas_identity_list", { filter: "active" });
    const child = agentIdFrom(await call("atlas_identity_delegate", {
      parent_agent_id: parent, child_name: "reader", child_role: "tool-caller", capabilities: ["file:read"],
    }));
    await call("atlas_identity_delegate", {
      parent_agent_id: parent, child_name: "escalator", child_role: "admin", capabilities: ["credential:read"],
    });
    await call("atlas_identity_tree", { agent_id: parent });
    await call("atlas_baseline_list");
    await call("atlas_baseline_get", { agent_id: parent });
    await call("atlas_baseline_drift", { agent_id: parent });
    await call("atlas_why_assess", {});
    await call("atlas_break_glass_status");
    await call("atlas_break_glass_activate", { reason: "snapshot" });
    await call("atlas_break_glass_revoke");
    await call("atlas_proximity_status");
    await call("atlas_proximity_sessions");
    await call("atlas_proximity_scan", { duration_ms: 10 });
    await call("atlas_proximity_connect", { device_id: "dev-1", agent_id: "did:atlas:unknown" });
    await call("atlas_proximity_disconnect", { session_id: "nope" });
    await call("atlas_identity_revoke", { agent_id: child, reason: "snapshot" });
    await call("atlas_identity_cascade_revoke", { parent_agent_id: parent, reason: "snapshot" });
    await call("atlas_identity_list", { filter: "revoked" });
    await call("atlas_identity_attach"); // unbound, no token
    await call("atlas_key_rotate", { reason: "snapshot" });
    await call("atlas_audit_verify");
    await call("atlas_audit_archives", {});
    await call("atlas_audit_rotate");
    await call("atlas_reply", { message: "hello" });
    await call("atlas_identity_register", { name: "bad" });
    await call("atlas_no_such_tool");

    matchSnapshot("tool-calls.json", transcript);
  });
});
