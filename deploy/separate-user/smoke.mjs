// Atlas Protocol — start the gatekeeper through the sudo launcher, as an MCP
// client would, and check it reports isolation (#23). Run as the agent user
// from a checkout with dev dependencies installed (npm ci).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ATLAS_USER = process.env.ATLAS_USER || "atlas";
const client = new Client({ name: "atlas-isolation-smoke", version: "0.0.0" });
await client.connect(
  new StdioClientTransport({
    command: "sudo",
    args: ["-n", "-u", ATLAS_USER, "/usr/local/libexec/atlas-gatekeeper"],
    stderr: "inherit",
  }),
);

try {
  const text = async (name) =>
    ((await client.callTool({ name, arguments: {} })).content ?? []).map((c) => c.text ?? "").join("\n");

  const status = JSON.parse(await text("atlas_status"));
  const iso = status.isolation;
  console.log("isolation:", JSON.stringify(iso));
  if (!iso?.isolated) throw new Error(`gatekeeper not isolated: ${(iso?.problems ?? []).join("; ")}`);
  if (iso.process_uid === process.getuid()) throw new Error("gatekeeper runs as the agent's uid");
  if (iso.launched_by_uid !== process.getuid()) throw new Error("launching uid not recorded as the agent's");
  if (status.data_dir !== "/var/lib/atlas-protocol") throw new Error(`unexpected data dir ${status.data_dir}`);

  const verify = await text("atlas_audit_verify");
  if (!/verified/i.test(verify)) throw new Error(`audit verify: ${verify}`);
} finally {
  await client.close();
}
