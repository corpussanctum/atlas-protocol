/**
 * End-to-end: a restarted server re-binds the session via an attach token (#39).
 */

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { issueAttachToken } from "../src/identity-attach.js";
import { generateOperatorKey, operatorSecretPath, unlockOperatorKey } from "../src/operator-key.js";

const SERVER = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js");
const PASS = "correct horse battery";

async function startServer(dataDir: string): Promise<Client> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !k.startsWith("ATLAS_") && !k.startsWith("WHY_ENGINE_") && k !== "CLAUDE_PLUGIN_DATA") env[k] = v;
  }
  Object.assign(env, { ATLAS_DATA_DIR: dataDir, WHY_ENGINE_ENABLED: "false" });
  const client = new Client({ name: "attach-e2e", version: "0.0.0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [SERVER], env, stderr: "ignore" }));
  return client;
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const res: any = await client.callTool({ name, arguments: args });
  return { isError: !!res.isError, text: (res.content ?? []).map((c: any) => c.text ?? "").join("\n") };
}

describe("identity attach across a server restart", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "atlas-attach-e2e-"));
  after(() => rmSync(dataDir, { recursive: true, force: true }));

  it("restores the session binding only with an operator-signed token", async () => {
    await generateOperatorKey(dataDir, PASS);

    let client = await startServer(dataDir);
    const reg = await call(client, "atlas_identity_register", {
      name: "session", role: "claude-code", capabilities: ["file:read", "identity:register"],
    });
    assert.equal(reg.isError, false, reg.text);
    const cred = JSON.parse(reg.text);
    await client.close();

    client = await startServer(dataDir);
    try {
      let status = JSON.parse((await call(client, "atlas_status")).text);
      assert.equal(status.agent_identity.session_agent_id, null);
      const locked = await call(client, "atlas_identity_register", { name: "x", role: "observer", capabilities: ["audit:read"] });
      assert.equal(locked.isError, true);

      const noToken = await call(client, "atlas_identity_attach");
      assert.match(noToken.text, /no attach token/);

      await issueAttachToken(dataDir, unlockOperatorKey(operatorSecretPath(dataDir), PASS), cred);
      const attached = await call(client, "atlas_identity_attach");
      assert.equal(attached.isError, false, attached.text);
      status = JSON.parse((await call(client, "atlas_status")).text);
      assert.equal(status.agent_identity.session_agent_id, cred.agentId);

      const again = await call(client, "atlas_identity_attach");
      assert.match(again.text, /already bound/);

      const events = readFileSync(join(dataDir, "audit.jsonl"), "utf-8").trim().split("\n").map((l) => JSON.parse(l));
      assert.equal(events.find((e) => e.event === "IDENTITY_ATTACHED")?.meta.agent_id, cred.agentId);
      assert.match((await call(client, "atlas_audit_verify")).text, /verified/);
    } finally {
      await client.close();
    }
  });
});
