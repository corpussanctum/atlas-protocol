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
 * and SPEC version maps, CHANGELOG, README tool count) must match.
 *
 * Usage: node scripts/check-versions.mjs   (exit 1 on any mismatch)
 */

import { readFileSync } from "node:fs";
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
const indexTs = read("src/index.ts");
const readme = read("README.md");
const specMd = read("SPEC.md");

// Table row helper: | **Label** | `x.y.z` | ...
const row = (text, label) => {
  const m = text.match(new RegExp(`\\|\\s*\\*\\*${label}\\*\\*\\s*\\|\\s*\`"?([\\d.]+)"?\``));
  return m ? m[1] : undefined;
};

const checks = [
  ["src/index.ts VERSION", match("src/index.ts", /const VERSION\s*=\s*"([\d.]+)"/, "VERSION"), impl],
  ["src/index.ts SPEC_VERSION", match("src/index.ts", /const SPEC_VERSION\s*=\s*"([\d.]+)"/, "SPEC_VERSION"), spec],
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

// Documented MCP tool count vs tools actually registered in index.ts
const toolCount = String(new Set(indexTs.match(/name:\s*"atlas_[a-z_]+"/g) ?? []).size);
for (const m of readme.matchAll(/(\d+) (?:MCP )?tools\b/g)) {
  checks.push([`README "${m[0]}"`, m[1], toolCount]);
}

let failed = 0;
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
  `OK: implementation ${impl}, spec ${spec}, protocol ${protocol}, credential ${credential}, ${toolCount} tools — ${checks.length} checks consistent`,
);
