/**
 * Interop with a v2 MCP client (@modelcontextprotocol/client).
 *
 * The other server-level tests use the v1 SDK client, which matches what
 * Claude Code speaks today; this one confirms the v2 line also works:
 * tool listing, a tool call, and the Claude Code channel permission relay.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const SERVER = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js");

describe("v2 MCP client interop", () => {
  let client: Client;
  let dataDir: string;
  const verdicts = new Map<string, (behavior: string) => void>();

  before(async () => {
    dataDir = mkdtempSync(join(tmpdir(), "atlas-v2client-"));
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined && !k.startsWith("ATLAS_") && !k.startsWith("WHY_ENGINE_") && k !== "CLAUDE_PLUGIN_DATA") env[k] = v;
    }
    Object.assign(env, { ATLAS_DATA_DIR: dataDir, WHY_ENGINE_ENABLED: "false" });
    client = new Client({ name: "v2-interop", version: "0.0.0" });
    client.setNotificationHandler(
      "notifications/claude/channel/permission",
      { params: z.object({ request_id: z.string(), behavior: z.enum(["allow", "deny"]) }) },
      (params) => verdicts.get(params.request_id)?.(params.behavior),
    );
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [SERVER], env, stderr: "ignore" }));
  });
  after(async () => {
    await client.close();
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("lists all tools and calls one", async () => {
    const { tools } = await client.listTools();
    assert.equal(tools.length, 27);
    const res: any = await client.callTool({ name: "atlas_break_glass_status", arguments: {} });
    assert.equal(JSON.parse(res.content[0].text).active, false);
  });

  it("relays a permission request and returns a fail-closed verdict", async () => {
    const verdict = new Promise<string>((resolve) => verdicts.set("v2req1", resolve));
    await client.notification({
      method: "notifications/claude/channel/permission_request",
      params: { request_id: "v2req1", tool_name: "Bash", description: "rm", input_preview: "rm -rf /tmp/x" },
    });
    assert.equal(await verdict, "deny");
  });
});
