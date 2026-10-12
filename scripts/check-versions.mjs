#!/usr/bin/env node
/**
 * Fail if version identifiers or documented counts disagree across the repo.
 *
 * Authorities (SPEC.md §11.2):
 *   implementation   package.json "version"
 *   spec document    SPEC.md "**Version:**" header
 *   protocol (wire)  src/protocol-version.ts PROTOCOL_VERSION
 *   credential       src/agent-identity.ts CREDENTIAL_VERSION
 *
 * Every other copy (index.ts constants, plugin manifests, lockfile, README
 * and SPEC version maps, CHANGELOG, README tool count) must match. Also checks,
 * in both directions, README tool table vs registered tools and
 * docs/AUDIT_EVENTS.md vs the AuditEventType union and emitted event_detail values.
 *
 * Usage: node scripts/check-versions.mjs   (exit 1 on any mismatch)
 */

import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf-8");
const json = (p) => JSON.parse(read(p));

function match(p, re, label) {
  const m = read(p).match(re);
  if (!m) throw new Error(`${p}: could not find ${label} (${re})`);
  return m[1];
}

const impl = json("package.json").version;
const spec = match("SPEC.md", /^\*\*Version:\*\*\s*([\d.]+)/m, "spec version header");
const protocol = match("src/protocol-version.ts", /PROTOCOL_VERSION\s*=\s*"([\d.]+)"/, "PROTOCOL_VERSION");
const credential = match("src/agent-identity.ts", /CREDENTIAL_VERSION\s*=\s*"([\d.]+)"/, "CREDENTIAL_VERSION");

const marketplace = json(".claude-plugin/marketplace.json");
const lock = json("package-lock.json");

const readme = read("README.md");
const specMd = read("SPEC.md");

// Table row helper: | **Label** | `x.y.z` | ...
const row = (text, label) => {
  const m = text.match(new RegExp(`\\|\\s*\\*\\*${label}\\*\\*\\s*\\|\\s*\`"?([\\d.]+)"?\``));
  return m ? m[1] : undefined;
};

const checks = [
  ["src/version.ts VERSION", match("src/version.ts", /export const VERSION\s*=\s*"([\d.]+)"/, "VERSION"), impl],
  ["src/version.ts SPEC_VERSION", match("src/version.ts", /export const SPEC_VERSION\s*=\s*"([\d.]+)"/, "SPEC_VERSION"), spec],
  [".claude-plugin/plugin.json", json(".claude-plugin/plugin.json").version, impl],
  ...(marketplace.plugins ?? []).map((p, i) => [`.claude-plugin/marketplace.json plugins[${i}]`, p.version, impl]),
  ["package-lock.json", lock.version, impl],
  ['package-lock.json packages[""]', lock.packages?.[""]?.version, impl],
  ["README version map: Implementation", row(readme, "Implementation"), impl],
  ["README version map: Spec document", row(readme, "Spec document"), spec],
  ["README version map: Protocol", row(readme, "Protocol \\(wire\\)"), protocol],
  ["README version map: Credential schema", row(readme, "Credential schema"), credential],
  ["SPEC §11.2: Spec document version", row(specMd, "Spec document version"), spec],
  ["SPEC §11.2: Implementation version", row(specMd, "Implementation version"), impl],
  ["SPEC §11.2: Credential schema version", row(specMd, "Credential schema version"), credential],
  ["SPEC §11.2: Protocol version", row(specMd, "Protocol version"), protocol],
  ["CHANGELOG latest release", match("CHANGELOG.md", /^## \[(\d[\d.]*)\]/m, "latest release heading"), impl],
];

// MCP tools registered in src/mcp/tools/*.ts
const toolFiles = execFileSync("git", ["ls-files", "src/mcp/tools"], { cwd: root, encoding: "utf-8" })
  .split("\n").filter((f) => f.endsWith(".ts"));
const registeredTools = new Set(
  toolFiles.flatMap((f) => [...read(f).matchAll(/^\s*name:\s*"(atlas_[a-z_]+)"/gm)].map((m) => m[1])),
);
const toolCount = String(registeredTools.size);
for (const m of readme.matchAll(/(\d+) (?:MCP )?tools\b/g)) {
  checks.push([`README "${m[0]}"`, m[1], toolCount]);
}

// Two-way set checks: documented names vs names that exist in code
const setChecks = [];
function compareSets(label, inCode, inDocs) {
  for (const name of inCode) if (!inDocs.has(name)) setChecks.push(`${label}: "${name}" exists in code but is undocumented`);
  for (const name of inDocs) if (!inCode.has(name)) setChecks.push(`${label}: "${name}" is documented but not in code`);
}

// MCP tools: registered vs README tool tables
const readmeTools = new Set([...readme.matchAll(/^\|\s*`(atlas_[a-z_]+)`\s*\|/gm)].map((m) => m[1]));
compareSets("README tool table", registeredTools, readmeTools);

// Audit events: AuditEventType union + emitted event_detail values vs docs/AUDIT_EVENTS.md
const auditLogTs = read("src/audit-log.ts");
const union = auditLogTs.match(/export type AuditEventType =([\s\S]*?);/);
if (!union) throw new Error("src/audit-log.ts: could not find AuditEventType union");
const eventTypes = new Set([...union[1].matchAll(/"([A-Z_]+)"/g)].map((m) => m[1]));
const catalog = read("docs/AUDIT_EVENTS.md");
const [typesPart, detailPart = ""] = catalog.split(/^## `meta\.event_detail`/m);
const rowNames = (text) => new Set([...text.matchAll(/^\|\s*`([A-Z_]+)`\s*\|/gm)].map((m) => m[1]));
compareSets("docs/AUDIT_EVENTS.md event types", eventTypes, rowNames(typesPart));

const srcFiles = execFileSync("git", ["ls-files", "src"], { cwd: root, encoding: "utf-8" })
  .split("\n")
  .filter((f) => f.endsWith(".ts"));
const emittedDetails = new Set(
  srcFiles.flatMap((f) => [...read(f).matchAll(/event_detail:\s*"([A-Z_]+)"/g)].map((m) => m[1])),
);
compareSets("docs/AUDIT_EVENTS.md event_detail", emittedDetails, rowNames(detailPart));

let failed = 0;
for (const problem of setChecks) {
  console.error(`MISMATCH ${problem}`);
  failed++;
}
for (const [label, actual, expected] of checks) {
  if (actual !== expected) {
    console.error(`MISMATCH ${label}: found ${actual ?? "(missing)"}, expected ${expected}`);
    failed++;
  }
}

if (failed) {
  console.error(`\n${failed} version/count mismatch(es). Authorities: package.json, SPEC.md header, protocol-version.ts, agent-identity.ts.`);
  process.exit(1);
}
console.log(
  `OK: implementation ${impl}, spec ${spec}, protocol ${protocol}, credential ${credential}, ${toolCount} tools, ` +
    `${eventTypes.size} audit events + ${emittedDetails.size} event_detail values documented — ${checks.length} version checks consistent`,
);
