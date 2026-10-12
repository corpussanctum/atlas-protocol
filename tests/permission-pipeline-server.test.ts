/**
 * Characterization tests for the permission pipeline, driven over real MCP
 * stdio against the built server.
 *
 * These pin down the verdict and the audit event sequence for each branch of
 * the pipeline, so the authority-core extraction (#5) can be shown to be
 * behavior-preserving: they were written and passing before the move.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const SERVER = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js");

const VerdictSchema = z.object({
  method: z.literal("notifications/claude/channel/permission"),
  params: z.object({ request_id: z.string(), behavior: z.enum(["allow", "deny"]) }),
});

interface Harness {
  client: Client;
  dataDir: string;
  request(tool: string, input: string): Promise<{ behavior: string; events: any[] }>;
  close(): Promise<void>;
}

async function startServer(configFile?: unknown): Promise<Harness> {
  const dataDir = mkdtempSync(join(tmpdir(), "atlas-pipeline-"));
  if (configFile !== undefined) {
    writeFileSync(join(dataDir, "config.json"), JSON.stringify(configFile));
  }
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !k.startsWith("ATLAS_") && !k.startsWith("WHY_ENGINE_") && k !== "CLAUDE_PLUGIN_DATA") {
      env[k] = v;
    }
  }
  env.ATLAS_DATA_DIR = dataDir;
  env.WHY_ENGINE_ENABLED = "false";

  const transport = new StdioClientTransport({ command: process.execPath, args: [SERVER], env, stderr: "ignore" });
  const client = new Client({ name: "pipeline-test", version: "0.0.0" });
  const waiters = new Map<string, (behavior: string) => void>();
  client.setNotificationHandler(VerdictSchema, (n) => {
    waiters.get(n.params.request_id)?.(n.params.behavior);
  });
  await client.connect(transport);

  let seq = 0;
  return {
    client,
    dataDir,
    async request(tool, input) {
      const requestId = `req${++seq}`;
      const verdict = new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no verdict for ${requestId}`)), 10_000);
        waiters.set(requestId, (b) => {
          clearTimeout(timer);
          resolve(b);
        });
      });
      await client.notification({
        method: "notifications/claude/channel/permission_request",
        params: { request_id: requestId, tool_name: tool, description: `test ${tool}`, input_preview: input },
      });
      const behavior = await verdict;
      // Audit writes are synchronous before the verdict is sent
      const log = join(dataDir, "audit.jsonl");
      const entries = existsSync(log)
        ? readFileSync(log, "utf-8").trim().split("\n").map((l) => JSON.parse(l))
        : [];
      return { behavior, events: entries.filter((e) => e.permission?.request_id === requestId) };
    },
    async close() {
      await client.close();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

const eventNames = (events: any[]) => events.map((e) => e.event);

describe("permission pipeline (server-level characterization)", () => {
  describe("bootstrap mode, default policy, no Telegram", () => {
    let h: Harness;
    before(async () => { h = await startServer(); });
    after(async () => { await h.close(); });

    it("policy deny: rm -rf is denied without a human", async () => {
      const { behavior, events } = await h.request("Bash", "rm -rf /tmp/project");
      assert.equal(behavior, "deny");
      assert.deepEqual(eventNames(events), ["PERMISSION_REQUEST", "POLICY_DENY"]);
      assert.equal(events[1].meta.agentId, "bootstrap");
      assert.equal(events[1].meta.identityVerified, false);
    });

    it("ask with no authorized chats: fail-closed TIMEOUT_DENY", async () => {
      const { behavior, events } = await h.request("Read", "/home/user/project/src/index.ts");
      assert.equal(behavior, "deny");
      assert.deepEqual(eventNames(events), ["PERMISSION_REQUEST", "TIMEOUT_DENY"]);
      assert.equal(events[1].meta.reason, "No authorized Telegram chat configured");
    });
  });

  describe("custom policy with an allow rule", () => {
    let h: Harness;
    before(async () => {
      h = await startServer({
        policy_rules: [
          { tool_pattern: "Bash(rm *)", action: "deny", reason: "no rm" },
          { tool_pattern: "Read(*)", action: "allow", reason: "reads ok" },
        ],
      });
    });
    after(async () => { await h.close(); });

    it("policy allow: matching allow rule allows without a human", async () => {
      const { behavior, events } = await h.request("Read", "/home/user/project/README.md");
      assert.equal(behavior, "allow");
      assert.deepEqual(eventNames(events), ["PERMISSION_REQUEST", "POLICY_ALLOW"]);
      assert.equal(events[1].policy_result.matched_rule.reason, "reads ok");
    });

    it("custom deny rule still denies", async () => {
      const { behavior, events } = await h.request("Bash", "rm notes.txt");
      assert.equal(behavior, "deny");
      assert.deepEqual(eventNames(events), ["PERMISSION_REQUEST", "POLICY_DENY"]);
    });
  });

  describe("registered agent", () => {
    let h: Harness;
    before(async () => {
      h = await startServer();
      const res: any = await h.client.callTool({
        name: "atlas_identity_register",
        arguments: { name: "reader", role: "claude-code", capabilities: ["file:read"] },
      });
      assert.ok(!res.isError, res.content?.[0]?.text);
    });
    after(async () => { await h.close(); });

    it("attestation deny: tool outside the agent's capabilities", async () => {
      const { behavior, events } = await h.request("Bash", "ls");
      assert.equal(behavior, "deny");
      assert.deepEqual(eventNames(events), ["PERMISSION_REQUEST", "POLICY_DENY"]);
      assert.equal(events[1].meta.attestation_deny, "CAPABILITY_MISMATCH");
    });

    it("attested agent within capabilities reaches the human step", async () => {
      const { behavior, events } = await h.request("Read", "/home/user/project/src/index.ts");
      assert.equal(behavior, "deny");
      assert.deepEqual(eventNames(events), ["PERMISSION_REQUEST", "TIMEOUT_DENY"]);
      assert.equal(events[1].meta.identityVerified, true);
    });
  });
});
