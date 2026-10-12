/**
 * End-to-end check that the MCP server honours ATLAS_HARDWARE_ADAPTER.
 *
 * Regression: src/index.ts used to construct Mock{UWB,BLE,NFC}Driver
 * directly, so the env var documented in the README had no effect.
 * These tests spawn the real server over stdio and read
 * atlas_proximity_status.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const SERVER = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js");

async function proximityStatus(hardwareAdapter: string): Promise<any> {
  const dataDir = mkdtempSync(join(tmpdir(), "atlas-wiring-"));
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !k.startsWith("ATLAS_") && k !== "CLAUDE_PLUGIN_DATA") env[k] = v;
  }
  env.ATLAS_DATA_DIR = dataDir;
  env.ATLAS_HARDWARE_ADAPTER = hardwareAdapter;

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    env,
    stderr: "ignore",
  });
  const client = new Client({ name: "wiring-test", version: "0.0.0" });
  try {
    await client.connect(transport);
    const result: any = await client.callTool({ name: "atlas_proximity_status", arguments: {} });
    return JSON.parse(result.content[0].text);
  } finally {
    await client.close();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

describe("MCP server proximity hardware wiring", () => {
  it("instantiates the adapter named by ATLAS_HARDWARE_ADAPTER", async () => {
    const status = await proximityStatus("android");
    assert.equal(status.hardware.adapter, "android");
    assert.equal(status.hardware.source, "env");
    assert.equal(status.hardware.simulated, false);
    // No React Native runtime here, so the real driver reports unavailable
    assert.equal(status.hardware.uwb, false);
  });

  it("reports mock drivers as simulated", async () => {
    const status = await proximityStatus("mock");
    assert.equal(status.hardware.adapter, "mock");
    assert.equal(status.hardware.simulated, true);
  });

  it("surfaces an invalid adapter instead of silently using mocks", async () => {
    const status = await proximityStatus("not-a-board");
    assert.equal(status.hardware.adapter, null);
    assert.match(status.hardware.error, /Unknown ATLAS_HARDWARE_ADAPTER "not-a-board"/);
  });
});
