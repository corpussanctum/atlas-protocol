/**
 * Tests for canonical effects (#9 groundwork): vocabulary, scope
 * classification, rule matching, the file-tool normalizer, the pluggable
 * normalizer interface, config validation, and audit redaction of targets.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  EFFECT_KINDS,
  EFFECT_SCOPES,
  combineNormalizers,
  effectMatcherProblem,
  effectMatches,
  fileToolNormalizer,
  scopeOf,
  type Effect,
  type EffectNormalizer,
} from "../src/effects.js";
import { PolicyEngine, type PermissionRequest } from "../src/policy-engine.js";
import { applyConfigFile, loadConfig, type AtlasConfig, type PolicyRule } from "../src/config.js";
import { AuditLogger } from "../src/audit-log.js";

const req = (tool_name: string, input_preview: string): PermissionRequest => ({
  request_id: "r", tool_name, description: "", input_preview,
});

const effect = (over: Partial<Effect>): Effect => ({
  effect: "fs.write", target: "src/a.ts", recursive: false, scope: "project", reversible: false, command: "Write",
  ...over,
});

function configWith(rules: PolicyRule[]): AtlasConfig {
  const config = loadConfig();
  config.policy_rules = rules;
  return config;
}

describe("effect vocabulary", () => {
  it("matches the published JSON Schema", () => {
    const schema = JSON.parse(readFileSync(join(process.cwd(), "docs", "effect-vocabulary.schema.json"), "utf-8"));
    assert.deepEqual(schema.properties.effect.enum, [...EFFECT_KINDS]);
    assert.deepEqual(schema.properties.scope.enum, [...EFFECT_SCOPES]);
    assert.deepEqual([...schema.required].sort(), ["command", "effect", "recursive", "reversible", "scope", "target"]);
  });
});

describe("scopeOf", () => {
  const cases: Array<[string | null, string]> = [
    [null, "unknown"],
    ["", "unknown"],
    ["src/index.ts", "project"],
    ["./build", "project"],
    ["/tmp/x", "temp"],
    ["/var/tmp", "temp"],
    ["/dev/null", "temp"],
    ["/dev/sda", "device"],
    ["~/notes.txt", "home"],
    ["$HOME/.config", "home"],
    ["/home/user/project", "home"],
    ["/root", "home"],
    ["/etc/hosts", "system"],
    ["/", "system"],
    ["$BUILD_DIR", "unknown"],
    ["https://example.com/a", "remote"],
    ["user@host:/srv/data", "remote"],
  ];
  for (const [target, scope] of cases) {
    it(`${JSON.stringify(target)} → ${scope}`, () => assert.equal(scopeOf(target), scope));
  }
});

describe("effectMatches", () => {
  it("requires every given field to match", () => {
    const e = effect({ effect: "fs.delete", target: "/var/lib/app", recursive: true, scope: "system", command: "rm" });
    assert.ok(effectMatches({ effect: ["fs.delete"], recursive: true, scope: ["system", "home"] }, e));
    assert.ok(!effectMatches({ effect: ["fs.delete"], recursive: false }, e));
    assert.ok(!effectMatches({ effect: ["fs.write"] }, e));
    assert.ok(!effectMatches({ scope: ["project"] }, e));
  });

  it("matches commands case-insensitively", () => {
    assert.ok(effectMatches({ command: ["RM"] }, effect({ command: "rm" })));
    assert.ok(!effectMatches({ command: ["mv"] }, effect({ command: "rm" })));
  });

  it("matches targets with * globs and | alternatives", () => {
    const m = { target: "*/.ssh/*|*.pem" };
    assert.ok(effectMatches(m, effect({ target: "/home/u/.ssh/config" })));
    assert.ok(effectMatches(m, effect({ target: "certs/server.PEM" })));
    assert.ok(!effectMatches(m, effect({ target: "src/ssh.ts" })));
    assert.ok(!effectMatches(m, effect({ target: null })), "a target glob never matches an unknown target");
  });

  it("matches reversibility", () => {
    assert.ok(effectMatches({ reversible: false }, effect({ reversible: false })));
    assert.ok(!effectMatches({ reversible: true }, effect({ reversible: false })));
  });
});

describe("fileToolNormalizer", () => {
  it("reads a bare path", () => {
    const r = fileToolNormalizer(req("Write", "/etc/hosts"));
    assert.equal(r.complete, true);
    assert.deepEqual(r.effects, [effect({ target: "/etc/hosts", scope: "system" })]);
  });

  it("reads the path from JSON tool input", () => {
    const r = fileToolNormalizer(req("Edit", JSON.stringify({ file_path: "src/a.ts", old_string: "x", new_string: "y" })));
    assert.equal(r.complete, true);
    assert.equal(r.effects[0].effect, "fs.write");
    assert.equal(r.effects[0].target, "src/a.ts");
    assert.equal(r.effects[0].command, "Edit");
  });

  it("reads the path from truncated JSON and marks it incomplete", () => {
    const full = JSON.stringify({ file_path: "/home/u/notes.md", content: "a".repeat(500) });
    const r = fileToolNormalizer(req("Write", full.slice(0, 120)));
    assert.equal(r.complete, false);
    assert.equal(r.effects[0].target, "/home/u/notes.md");
    assert.equal(r.effects[0].scope, "home");
  });

  it("maps Read to fs.read and NotebookEdit's notebook_path", () => {
    assert.equal(fileToolNormalizer(req("Read", "README.md")).effects[0].effect, "fs.read");
    const nb = fileToolNormalizer(req("NotebookEdit", JSON.stringify({ notebook_path: "a.ipynb" })));
    assert.equal(nb.effects[0].target, "a.ipynb");
  });

  it("produces no effects for other tools, including Bash", () => {
    assert.deepEqual(fileToolNormalizer(req("Bash", "ls -la")), { effects: [], complete: true });
    assert.deepEqual(fileToolNormalizer(req("Glob", "**/*.ts")), { effects: [], complete: true });
  });

  it("reports an empty path as incomplete with an unknown target", () => {
    const r = fileToolNormalizer(req("Write", ""));
    assert.equal(r.complete, false);
    assert.equal(r.effects[0].target, null);
    assert.equal(r.effects[0].scope, "unknown");
  });
});

describe("combineNormalizers", () => {
  it("concatenates effects and is complete only if all parts are", () => {
    const a: EffectNormalizer = () => ({ effects: [effect({ command: "a" })], complete: true });
    const b: EffectNormalizer = () => ({ effects: [effect({ command: "b" })], complete: false });
    const r = combineNormalizers(a, b)(req("X", ""));
    assert.deepEqual(r.effects.map((e) => e.command), ["a", "b"]);
    assert.equal(r.complete, false);
  });
});

describe("PolicyEngine with effect rules", () => {
  it("applies an effect rule only when an effect matches", () => {
    const engine = new PolicyEngine(configWith([
      { tool_pattern: "Write", action: "deny", reason: "system write", effect: { effect: ["fs.write"], scope: ["system"] } },
    ]));
    assert.equal(engine.evaluate(req("Write", "/etc/hosts")).verdict, "deny");
    assert.equal(engine.evaluate(req("Write", "src/a.ts")).verdict, "ask");
    assert.equal(engine.evaluate(req("Write", JSON.stringify({ file_path: "/usr/local/x" }))).verdict, "deny");
  });

  it("still requires the tool pattern to match", () => {
    const engine = new PolicyEngine(configWith([
      { tool_pattern: "Edit", action: "deny", effect: { effect: ["fs.write"] } },
    ]));
    assert.equal(engine.evaluate(req("Write", "/etc/hosts")).verdict, "ask");
  });

  it("keeps first-match order across string and effect rules", () => {
    const engine = new PolicyEngine(configWith([
      { tool_pattern: "Write(/etc/hosts)", action: "ask", reason: "string first" },
      { tool_pattern: "Write", action: "deny", reason: "effect second", effect: { scope: ["system"] } },
    ]));
    const r = engine.evaluate(req("Write", "/etc/hosts"));
    assert.equal(r.verdict, "ask");
    assert.equal(r.matched_rule?.reason, "string first");
  });

  it("uses a plugged-in normalizer and reports its effects", () => {
    const stub: EffectNormalizer = (r) =>
      r.tool_name === "Bash" && r.input_preview === "make clean"
        ? { effects: [effect({ effect: "fs.delete", target: "build", recursive: true, command: "make" })], complete: true }
        : { effects: [], complete: false };
    const engine = new PolicyEngine(
      configWith([{ tool_pattern: "Bash", action: "deny", reason: "recursive delete", effect: { effect: ["fs.delete"], recursive: true } }]),
      undefined,
      { normalizer: stub },
    );
    const hit = engine.evaluate(req("Bash", "make clean"));
    assert.equal(hit.verdict, "deny");
    assert.equal(hit.effects?.[0].effect, "fs.delete");
    assert.equal(hit.effects_complete, true);
    const miss = engine.evaluate(req("Bash", "make"));
    assert.equal(miss.verdict, "ask");
    assert.equal(miss.effects_complete, false);
  });

  it("falls back to string rules when the normalizer throws", () => {
    const engine = new PolicyEngine(
      configWith([
        { tool_pattern: "Bash", action: "deny", effect: { effect: ["fs.delete"] } },
        { tool_pattern: "Bash(*danger*)", action: "deny", reason: "string rule" },
      ]),
      undefined,
      { normalizer: () => { throw new Error("boom"); } },
    );
    const r = engine.evaluate(req("Bash", "danger"));
    assert.equal(r.verdict, "deny");
    assert.equal(r.matched_rule?.reason, "string rule");
    assert.ok(r.anomaly_flags.some((f) => f.startsWith("EFFECT_NORMALIZER_ERROR")));
    assert.deepEqual(r.effects, []);
  });

  it("leaves the default rule set's verdicts unchanged for Bash", () => {
    const engine = new PolicyEngine(loadConfig());
    const r = engine.evaluate(req("Bash", "ls -la"));
    assert.equal(r.verdict, "ask");
    assert.deepEqual(r.effects, []);
  });
});

describe("config validation of effect matchers", () => {
  const rule = (effectField: unknown) => ({ policy_rules: [{ tool_pattern: "Write", action: "deny", effect: effectField }] });

  it("accepts a valid matcher", () => {
    const config = loadConfig();
    assert.deepEqual(applyConfigFile(config, rule({ effect: ["fs.write"], scope: ["system"], target: "/etc/*" })), []);
    assert.deepEqual(config.policy_rules[0].effect, { effect: ["fs.write"], scope: ["system"], target: "/etc/*" });
  });

  for (const [label, bad] of [
    ["unknown effect kind", { effect: ["fs.explode"] }],
    ["unknown scope", { scope: ["galaxy"] }],
    ["unknown field", { size: 3 }],
    ["empty matcher", {}],
    ["wrong type", { recursive: "yes" }],
  ] as const) {
    it(`rejects the whole rule set for ${label}`, () => {
      const config = loadConfig();
      const before = config.policy_rules;
      const rejected = applyConfigFile(config, rule(bad));
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].field, "policy_rules");
      assert.equal(config.policy_rules, before, "defaults kept");
      assert.ok(effectMatcherProblem(bad));
    });
  }
});

describe("audit redaction of effect targets", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("hashes effect targets whenever input_preview is redacted", () => {
    dir = mkdtempSync(join(tmpdir(), "atlas-effects-audit-"));
    const logPath = join(dir, "audit.jsonl");
    const config = configWith([]);
    config.audit_log_path = logPath;
    config.audit_hmac_secret = "";
    const audit = new AuditLogger(config, { redact_fields: ["input_preview"], force_privacy: false });
    const engine = new PolicyEngine(config);
    const request = req("Write", "/home/patient-records/jane.txt");
    audit.log("POLICY_DENY", { permission: request, policy_result: engine.evaluate(request) });

    const line = readFileSync(logPath, "utf-8");
    assert.ok(!line.includes("patient-records"), "no plaintext target in the log");
    const entry = JSON.parse(line.trim().split("\n").pop()!);
    assert.match(entry.permission.input_preview, /^HASHED:/);
    assert.match(entry.policy_result.effects[0].target, /^HASHED:[0-9a-f]{64}$/);
    assert.equal(entry.policy_result.effects[0].scope, "home", "kind and scope stay readable");
  });
});
