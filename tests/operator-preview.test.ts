/**
 * Tests for operator-relay preview redaction (#17).
 */

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildOperatorPreview, operatorPreviewPolicyFromEnv } from "../src/authority/operator-preview.js";
import { createPermissionPipeline } from "../src/authority/permission-pipeline.js";
import type { OperatorChannel, PermissionPipelineDeps } from "../src/authority/permission-pipeline.js";
import { ConsentTier } from "../src/identity-provider.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import type { PermissionRequest, PolicyResult } from "../src/policy-engine.js";
import { QuantumSigner } from "../src/quantum-signer.js";

const PHI = "Patient Jane Roe, DOB 1971-03-02, dx F33.1, MRN 0048213";

const req: PermissionRequest = {
  request_id: "fghij",
  tool_name: "Write",
  description: `Write intake note for ${PHI}`,
  input_preview: `{"file_path":"/tmp/note.md","content":"${PHI}"}`,
};

const result = (tiers: ConsentTier[] = []): PolicyResult => ({
  verdict: "ask",
  matched_rule: null,
  anomaly_flags: [],
  sensitivity_matches: tiers.map((min_tier, i) => ({ data_type: `type-${i}`, min_tier, pattern: "x" })),
  identity_evaluated: tiers.length > 0,
});

const OFF = { privacyMode: false, sendInput: false };
const PRIVATE = { privacyMode: true, sendInput: false };

describe("buildOperatorPreview", () => {
  it("passes the input through (capped) when nothing calls for redaction", () => {
    const long = { ...req, input_preview: "a".repeat(900) };
    const p = buildOperatorPreview(long, result([ConsentTier.OPERATIONAL]), OFF);
    assert.equal(p.redacted, null);
    assert.equal(p.inputPreview.length, 500);
    assert.equal(p.description, req.description);
  });

  it("withholds input and description in privacy mode, with length and digest", () => {
    const p = buildOperatorPreview(req, result(), PRIVATE);
    assert.equal(p.redacted, "PRIVACY_MODE");
    const digest = createHash("sha3-256").update(req.input_preview).digest("hex").slice(0, 16);
    assert.ok(p.inputPreview.includes(`${req.input_preview.length} chars`));
    assert.ok(p.inputPreview.includes(digest));
    assert.ok(!p.inputPreview.includes("Jane") && !p.description.includes("Jane"));
  });

  it("lets the operator opt back in to the raw input in privacy mode", () => {
    assert.equal(buildOperatorPreview(req, result(), { privacyMode: true, sendInput: true }).redacted, null);
  });

  it("always withholds Tier 3+ sensitive data, even with the opt-in", () => {
    for (const tier of [ConsentTier.CLINICAL, ConsentTier.PROTECTED, ConsentTier.RESTRICTED]) {
      const p = buildOperatorPreview(req, result([tier]), { privacyMode: false, sendInput: true });
      assert.equal(p.redacted, "SENSITIVE_DATA");
    }
  });

  it("reads the policy from the environment", () => {
    assert.deepEqual(operatorPreviewPolicyFromEnv({}), OFF);
    assert.deepEqual(
      operatorPreviewPolicyFromEnv({ ATLAS_PRIVACY_MODE: "true", ATLAS_TELEGRAM_SEND_INPUT: "true" }),
      { privacyMode: true, sendInput: true },
    );
  });
});

describe("permission pipeline relay payload", () => {
  const dir = mkdtempSync(join(tmpdir(), "atlas-preview-"));
  after(() => rmSync(dir, { recursive: true, force: true }));

  async function relay(policyResult: PolicyResult, previewPolicy: PermissionPipelineDeps["previewPolicy"]) {
    const registry = await IdentityRegistry.create(dir, await QuantumSigner.create(dir));
    const sent: string[] = [];
    const events: Array<{ event: string; data: any }> = [];
    const operator: OperatorChannel = {
      async sendReply(text) { sent.push(text); },
      async requestVerdict(id, tool, description, input, flags) {
        sent.push([id, tool, description, input, ...flags].join("\n"));
        return { decision: "deny", responder_chat_id: 42 };
      },
    };
    await createPermissionPipeline({
      registry,
      getSessionAgentId: () => undefined,
      policyEngine: { evaluate: () => policyResult },
      audit: { log: (event: any, data: any) => { events.push({ event, data }); return {} as any; } },
      operator,
      baselineStore: { get: async () => undefined },
      quietConfig: { enabled: false, min_maturity: "mature", max_anomaly_flags: 0, quiet_tools: new Set() },
      breakGlass: { isActive: () => false, recordUsage: () => {}, read: () => null as any },
      config: { permission_timeout_seconds: 5, telegram_allowed_chat_ids: [42] },
      previewPolicy,
    })(req);
    return { payload: sent.join("\n"), events };
  }

  it("sends none of a PHI-bearing input to the operator in privacy mode", async () => {
    const { payload, events } = await relay(result([ConsentTier.PROTECTED]), PRIVATE);
    for (const fragment of ["Jane Roe", "1971-03-02", "F33.1", "0048213", "/tmp/note.md"]) {
      assert.ok(!payload.includes(fragment), `relay payload leaked ${fragment}`);
    }
    const verdict = events.find((e) => e.event === "HUMAN_DENY");
    assert.equal(verdict?.data.meta.operator_preview_redacted, "SENSITIVE_DATA");
  });

  it("still sends the input when nothing calls for redaction", async () => {
    const { payload, events } = await relay(result(), OFF);
    assert.ok(payload.includes("Jane Roe"));
    assert.equal(events.find((e) => e.event === "HUMAN_DENY")?.data.meta.operator_preview_redacted, undefined);
  });
});
