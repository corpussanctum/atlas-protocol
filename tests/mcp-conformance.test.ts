/**
 * MCP conformance over stdio (#7).
 *
 * Speaks raw newline-delimited JSON-RPC to the server process instead of
 * using an SDK client, so client-side leniency can't hide a protocol bug.
 * The official @modelcontextprotocol/conformance suite only drives servers
 * over HTTP, and its tool scenarios need its reference server's fixture
 * tools, so this harness covers the stdio surface Atlas actually has:
 * initialize and version negotiation, ping, tools/list shape and
 * annotations, tools/call error classes, and stdout hygiene.
 *
 * Runs against the compiled test build by default. CI also runs it against
 * the published entry point: ATLAS_CONFORMANCE_SERVER=dist/index.js.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SERVER = process.env.ATLAS_CONFORMANCE_SERVER
  ? resolve(process.env.ATLAS_CONFORMANCE_SERVER)
  : join(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js");

/** Revisions the server must accept as-is (MCP SDK v2 negotiation). */
const SUPPORTED = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
const ANNOTATION_HINTS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];

type Json = any;

/** Minimal JSON-RPC peer over a child's stdio. Every stdout line must be a JSON-RPC message. */
class RawPeer {
  readonly proc: ChildProcessWithoutNullStreams;
  readonly nonJsonLines: string[] = [];
  readonly messages: Json[] = [];
  private buf = "";
  private nextId = 1;
  private waiters = new Map<number | string, (msg: Json) => void>();

  constructor(dataDir: string) {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined && !k.startsWith("ATLAS_") && !k.startsWith("WHY_ENGINE_") && k !== "CLAUDE_PLUGIN_DATA") env[k] = v;
    }
    Object.assign(env, { ATLAS_DATA_DIR: dataDir, WHY_ENGINE_ENABLED: "false" });
    this.proc = spawn(process.execPath, [SERVER], { env, stdio: ["pipe", "pipe", "pipe"] });
    this.proc.stderr.resume();
    this.proc.stdout.setEncoding("utf-8");
    this.proc.stdout.on("data", (chunk: string) => {
      this.buf += chunk;
      let i: number;
      while ((i = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, i).replace(/\r$/, "");
        this.buf = this.buf.slice(i + 1);
        if (!line) continue;
        let msg: Json;
        try {
          msg = JSON.parse(line);
        } catch {
          this.nonJsonLines.push(line);
          continue;
        }
        this.messages.push(msg);
        if (msg.id !== undefined && this.waiters.has(msg.id)) {
          this.waiters.get(msg.id)!(msg);
          this.waiters.delete(msg.id);
        }
      }
    });
  }

  write(raw: string): void {
    this.proc.stdin.write(raw + "\n");
  }

  notify(method: string, params?: Json): void {
    this.write(JSON.stringify({ jsonrpc: "2.0", method, ...(params ? { params } : {}) }));
  }

  request(method: string, params?: Json, timeoutMs = 10_000): Promise<Json> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters.delete(id);
        reject(new Error(`no response to ${method} (id ${id}) within ${timeoutMs}ms`));
      }, timeoutMs);
      this.waiters.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      this.write(JSON.stringify({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) }));
    });
  }

  async close(): Promise<void> {
    if (this.proc.exitCode !== null) return;
    const exited = new Promise((r) => this.proc.once("exit", r));
    this.proc.stdin.end();
    const timer = setTimeout(() => this.proc.kill("SIGKILL"), 3000);
    await exited;
    clearTimeout(timer);
  }
}

function assertResponse(msg: Json, id: number | string): void {
  assert.equal(msg.jsonrpc, "2.0");
  assert.equal(msg.id, id);
  assert.ok(("result" in msg) !== ("error" in msg), "exactly one of result / error");
}

async function initialized(peer: RawPeer, protocolVersion = "2025-11-25"): Promise<Json> {
  const res = await peer.request("initialize", {
    protocolVersion,
    capabilities: {},
    clientInfo: { name: "atlas-conformance", version: "0.0.0" },
  });
  peer.notify("notifications/initialized");
  return res;
}

describe("MCP conformance over stdio (#7)", () => {
  const dirs: string[] = [];
  const peers: RawPeer[] = [];
  const open = (): RawPeer => {
    const dir = mkdtempSync(join(tmpdir(), "atlas-conformance-"));
    dirs.push(dir);
    const peer = new RawPeer(dir);
    peers.push(peer);
    return peer;
  };
  let peer: RawPeer;
  let init: Json;

  before(async () => {
    peer = open();
    init = await initialized(peer);
  });

  after(async () => {
    for (const p of peers) await p.close();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  });

  describe("lifecycle", () => {
    it("initialize returns a well-formed InitializeResult", () => {
      assertResponse(init, 1);
      const r = init.result;
      assert.equal(r.protocolVersion, "2025-11-25");
      assert.equal(r.serverInfo.name, "atlas-protocol");
      assert.match(r.serverInfo.version, /^\d+\.\d+\.\d+/);
      assert.equal(typeof r.capabilities, "object");
      assert.equal(typeof r.capabilities.tools, "object", "tools capability advertised");
      assert.equal(typeof r.instructions, "string");
    });

    it("does not advertise capabilities it does not serve", async () => {
      const caps = init.result.capabilities;
      for (const [cap, method] of [["resources", "resources/list"], ["prompts", "prompts/list"]] as const) {
        if (caps[cap]) continue;
        const res = await peer.request(method);
        assert.equal(res.error?.code, -32601, `${method} without the ${cap} capability → Method not found`);
      }
    });

    for (const version of SUPPORTED) {
      it(`accepts protocol version ${version} as requested`, async () => {
        const res = await initialized(open(), version);
        assert.equal(res.result.protocolVersion, version);
      });
    }

    it("answers an unsupported protocol version with a version it supports", async () => {
      const res = await initialized(open(), "1999-01-01");
      assert.ok(res.result, "initialize still succeeds");
      assert.ok(SUPPORTED.includes(res.result.protocolVersion), res.result.protocolVersion);
    });

    it("responds to ping with an empty result", async () => {
      const res = await peer.request("ping");
      assertResponse(res, res.id);
      assert.deepEqual(res.result, {});
    });
  });

  describe("tools/list", () => {
    let tools: Json[];
    before(async () => {
      const res = await peer.request("tools/list");
      assertResponse(res, res.id);
      tools = res.result.tools;
      assert.equal(res.result.nextCursor, undefined, "single page");
    });

    it("lists every tool once with a valid name and description", () => {
      assert.equal(tools.length, 27);
      const names = tools.map((t) => t.name);
      assert.equal(new Set(names).size, names.length, "names are unique");
      for (const t of tools) {
        assert.match(t.name, TOOL_NAME);
        assert.equal(typeof t.description, "string");
        assert.ok(t.description.length > 0, `${t.name} has a description`);
      }
    });

    it("gives every tool an object inputSchema", () => {
      for (const t of tools) {
        assert.equal(t.inputSchema?.type, "object", `${t.name}.inputSchema.type`);
        if (t.inputSchema.properties !== undefined) assert.equal(typeof t.inputSchema.properties, "object");
        for (const req of t.inputSchema.required ?? []) {
          assert.ok(req in (t.inputSchema.properties ?? {}), `${t.name}: required "${req}" is a declared property`);
        }
      }
    });

    it("annotates every tool with boolean hints that are consistent", () => {
      for (const t of tools) {
        assert.equal(typeof t.annotations, "object", `${t.name} has annotations`);
        for (const [k, v] of Object.entries(t.annotations)) {
          if (ANNOTATION_HINTS.includes(k)) assert.equal(typeof v, "boolean", `${t.name}.annotations.${k}`);
        }
        if (t.annotations.readOnlyHint === true) {
          assert.notEqual(t.annotations.destructiveHint, true, `${t.name}: read-only tools are not destructive`);
        }
      }
    });
  });

  describe("tools/call", () => {
    it("returns a CallToolResult with text content for a valid call", async () => {
      const res = await peer.request("tools/call", { name: "atlas_break_glass_status", arguments: {} });
      assertResponse(res, res.id);
      assert.notEqual(res.result.isError, true);
      assert.equal(res.result.content[0].type, "text");
      assert.equal(JSON.parse(res.result.content[0].text).active, false);
    });

    it("treats omitted arguments as an empty object", async () => {
      const res = await peer.request("tools/call", { name: "atlas_break_glass_status" });
      assert.notEqual(res.result?.isError, true);
    });

    it("rejects an unknown tool with a -32602 protocol error", async () => {
      const res = await peer.request("tools/call", { name: "no_such_tool", arguments: {} });
      assertResponse(res, res.id);
      assert.equal(res.error?.code, -32602);
      assert.match(res.error.message, /no_such_tool/);
    });

    it("reports arguments of the wrong type as a tool execution error", async () => {
      const res = await peer.request("tools/call", { name: "atlas_identity_verify", arguments: { agent_id: 42 } });
      assertResponse(res, res.id);
      assert.equal(res.result.isError, true);
      assert.match(res.result.content[0].text, /agent_id/);
    });

    it("reports a missing required argument as a tool execution error", async () => {
      const res = await peer.request("tools/call", { name: "atlas_identity_verify", arguments: {} });
      assert.equal(res.result.isError, true);
      assert.match(res.result.content[0].text, /agent_id/);
    });

    it("rejects a malformed tools/call request with a protocol error", async () => {
      const res = await peer.request("tools/call", { arguments: {} });
      assertResponse(res, res.id);
      assert.equal(res.error?.code, -32602);
    });
  });

  describe("JSON-RPC and stdio framing", () => {
    it("answers an unknown method with -32601", async () => {
      const res = await peer.request("no/such/method");
      assertResponse(res, res.id);
      assert.equal(res.error.code, -32601);
    });

    it("keeps serving after a line that is not JSON", async () => {
      peer.write("{not json");
      const res = await peer.request("ping");
      assert.deepEqual(res.result, {});
    });

    it("ignores unknown notifications", async () => {
      const before = peer.messages.length;
      peer.notify("notifications/no_such_notification", { x: 1 });
      const res = await peer.request("ping");
      assert.deepEqual(res.result, {});
      assert.equal(peer.messages.length, before + 1, "only the ping response was written");
    });

    it("writes only JSON-RPC 2.0 messages to stdout", () => {
      assert.deepEqual(peer.nonJsonLines, []);
      for (const m of peer.messages) assert.equal(m.jsonrpc, "2.0");
    });
  });
});
