#!/usr/bin/env node
/**
 * atlas-operator: operator-only commands (SPEC §9).
 *
 *   atlas-operator keygen [--force] [--key-file PATH]
 *   atlas-operator break-glass --reason TEXT [--ttl MINUTES] [--max-requests N] [--key-file PATH]
 *   atlas-operator status
 *   atlas-operator revoke
 *   atlas-operator registry-reset --reason TEXT [--key-file PATH]
 *
 * Common: --data-dir PATH (default: same resolution as the server)
 *
 * The passphrase is read from the controlling terminal with echo off. It is
 * never accepted from arguments or environment variables, which a governed
 * agent could supply.
 */

import { join } from "node:path";
import { createInterface } from "node:readline";
import { Writable } from "node:stream";
import { loadConfig } from "./config.js";
import {
  generateOperatorKey,
  unlockOperatorKey,
  readOperatorPublicKey,
  operatorSecretPath,
  MIN_PASSPHRASE_LENGTH,
} from "./operator-key.js";
import { QuantumSigner } from "./quantum-signer.js";
import { resetIdentityRegistry, summarizeRegistry } from "./registry-reset.js";
import { BreakGlassManager, issueBreakGlassToken, DEFAULT_TTL_MINUTES, MAX_TTL_MINUTES } from "./break-glass.js";

const USAGE = `Usage:
  atlas-operator keygen [--force] [--key-file PATH]
  atlas-operator break-glass --reason TEXT [--ttl MINUTES] [--max-requests N] [--key-file PATH]
  atlas-operator status
  atlas-operator revoke
  atlas-operator registry-reset --reason TEXT [--key-file PATH]

Options:
  --data-dir PATH   Atlas data directory (default: ATLAS_DATA_DIR, CLAUDE_PLUGIN_DATA, or ~/.atlas-protocol)
  --key-file PATH   Encrypted operator secret key (default: <data-dir>/operator/operator.key.enc.json).
                    Keeping it off-host (e.g. removable media) is stronger.`;

function parseArgs(argv: string[]): { command?: string; flags: Map<string, string | true> } {
  const [command, ...rest] = argv;
  const flags = new Map<string, string | true>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a.startsWith("--")) throw new Error(`Unexpected argument: ${a}`);
    const next = rest[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags.set(a.slice(2), next);
      i++;
    } else {
      flags.set(a.slice(2), true);
    }
  }
  return { command, flags };
}

function str(flags: Map<string, string | true>, name: string): string | undefined {
  const v = flags.get(name);
  if (v === true) throw new Error(`--${name} needs a value`);
  return v;
}

function num(flags: Map<string, string | true>, name: string, fallback: number): number {
  const v = str(flags, name);
  if (v === undefined) return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`--${name} must be a non-negative integer`);
  return n;
}

async function promptHidden(question: string): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error("The passphrase must be entered at an interactive terminal (stdin is not a TTY)");
  }
  let muted = false;
  const output = new Writable({
    write(chunk, _enc, cb) {
      if (!muted) process.stderr.write(chunk);
      cb();
    },
  });
  const rl = createInterface({ input: process.stdin, output, terminal: true });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      process.stderr.write("\n");
      resolve(answer);
    });
    muted = true;
  });
}

async function main(): Promise<number> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  if (!command || command === "help" || flags.has("help")) {
    console.error(USAGE);
    return command ? 0 : 1;
  }
  const dataDirFlag = str(flags, "data-dir");
  const dataDir = dataDirFlag ?? loadConfig().data_dir;
  const keyFile = str(flags, "key-file") ?? operatorSecretPath(dataDir);

  switch (command) {
    case "keygen": {
      const p1 = await promptHidden(`New operator passphrase (min ${MIN_PASSPHRASE_LENGTH} chars): `);
      const p2 = await promptHidden("Repeat passphrase: ");
      if (p1 !== p2) throw new Error("Passphrases do not match");
      const pub = await generateOperatorKey(dataDir, p1, { force: flags.has("force"), secretPath: keyFile });
      console.log(`Operator key created: ${pub.key_id}`);
      console.log(`  public key:  ${dataDir}/operator/operator.pub.json`);
      console.log(`  secret key:  ${keyFile} (encrypted)`);
      console.log(`Restart Atlas to load it. To pin it, set ATLAS_OPERATOR_KEY_ID=${pub.key_id} in the server's launch environment.`);
      return 0;
    }

    case "break-glass": {
      const reason = str(flags, "reason");
      if (!reason) throw new Error("--reason is required");
      const ttl = num(flags, "ttl", DEFAULT_TTL_MINUTES);
      if (ttl < 1 || ttl > MAX_TTL_MINUTES) throw new Error(`--ttl must be 1–${MAX_TTL_MINUTES} minutes`);
      const maxRequests = num(flags, "max-requests", 0);
      const pub = readOperatorPublicKey(dataDir);
      if (!pub) throw new Error("No operator key configured; run `atlas-operator keygen` first");
      const operator = unlockOperatorKey(keyFile, await promptHidden(`Operator passphrase for ${pub.key_id}: `));
      if (operator.keyId !== pub.key_id) {
        throw new Error(`Key file ${operator.keyId} does not match the configured operator key ${pub.key_id}`);
      }
      const token = await issueBreakGlassToken(dataDir, operator, reason, ttl, maxRequests);
      console.log(`Break-glass active until ${token.expires_at} (${maxRequests || "unlimited"} requests).`);
      console.log("'ask' verdicts will be auto-approved and audited; hard-deny rules still apply.");
      console.log("End it early with: atlas-operator revoke");
      return 0;
    }

    case "status": {
      const pub = readOperatorPublicKey(dataDir);
      const manager = await BreakGlassManager.open(dataDir, pub);
      console.log(JSON.stringify(manager.getStatus(), null, 2));
      return 0;
    }

    case "revoke": {
      const manager = await BreakGlassManager.open(dataDir, readOperatorPublicKey(dataDir));
      console.log(manager.revoke() ? "Break-glass token revoked." : "No break-glass token found.");
      return 0;
    }

    case "registry-reset": {
      const reason = str(flags, "reason");
      if (!reason) throw new Error("--reason is required");
      const pub = readOperatorPublicKey(dataDir);
      if (!pub) throw new Error("No operator key configured; run `atlas-operator keygen` first");
      const summary = summarizeRegistry(dataDir);
      if (!summary) {
        console.log("No identity registry found; the bootstrap window is already open.");
        return 0;
      }
      console.error(
        `Registry ${summary.path}: ${summary.total} credential(s) — ` +
          `${summary.active} active, ${summary.expired} expired, ${summary.revoked} revoked.`,
      );
      const operator = unlockOperatorKey(keyFile, await promptHidden(`Operator passphrase for ${pub.key_id}: `));
      if (operator.keyId !== pub.key_id) {
        throw new Error(`Key file ${operator.keyId} does not match the configured operator key ${pub.key_id}`);
      }
      const base = loadConfig();
      const config = dataDirFlag
        ? { ...base, data_dir: dataDir, audit_log_path: join(dataDir, "audit.jsonl") }
        : base;
      if (!config.audit_hmac_secret) {
        console.error("Note: ATLAS_HMAC_SECRET is not set here; the entry is ML-DSA-65 and operator signed, without HMAC.");
      }
      const result = await resetIdentityRegistry(config, operator, reason, await QuantumSigner.create(dataDir));
      if (!result) throw new Error("Registry disappeared before reset");
      console.log(`REGISTRY_RESET logged (seq ${result.entry.seq}); registry archived to ${result.archivedPath}.`);
      console.log("Restart every running Atlas server (reconnect the MCP server in each Claude Code session) before registering:");
      console.log("they hold the old registry in memory. The next registration is a bootstrap and needs two-channel confirmation.");
      return 0;
    }

    default:
      console.error(`Unknown command: ${command}\n\n${USAGE}`);
      return 1;
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(`atlas-operator: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  },
);
