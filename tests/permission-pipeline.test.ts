/**
 * Unit tests for the extracted permission pipeline (src/authority).
 *
 * Covers branches the server-level characterization tests cannot reach
 * without a live operator or mature baseline: quiet mode, break-glass,
 * human approve/deny/timeout, anomaly logging, and attestation messages.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPermissionPipeline } from "../src/authority/permission-pipeline.js";
import type { PermissionPipelineDeps, OperatorChannel } from "../src/authority/permission-pipeline.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import { QuantumSigner } from "../src/quantum-signer.js";
import type { PermissionRequest, PolicyResult } from "../src/policy-engine.js";
import type { VerdictOutcome } from "../src/telegram.js";

const req = (tool = "Read", input = "/home/user/project/src/index.ts"): PermissionRequest => ({
  request_id: "abcde",
  tool_name: tool,
  description: `test ${tool}`,
  input_preview: input,
});

const policy = (verdict: PolicyResult["verdict"], extra: Partial<PolicyResult> = {}): PolicyResult => ({
  verdict,
  matched_rule: verdict === "ask" ? null : { tool_pattern: "*", action: verdict, reason: `rule ${verdict}`, mitre_id: "T1485" },
  anomaly_flags: [],
  sensitivity_matches: [],
  identity_evaluated: false,
  ...extra,
});

class FakeOperator implements OperatorChannel {
  replies: string[] = [];
  verdictCalls: Array<{ flags: string[]; timeout: number }> = [];
  constructor(private outcome: VerdictOutcome = { decision: "timeout" }) {}
  async sendReply(text: string) { this.replies.push(text); }
  async requestVerdict(_id: string, _tool: string, _desc: string, _input: string, flags: string[], timeout: number) {
    this.verdictCalls.push({ flags, timeout });
    return this.outcome;
  }
}

describe("createPermissionPipeline", () => {
  let dir: string;
  let registry: IdentityRegistry;
  let events: Array<{ event: string; data: any }>;
  let operator: FakeOperator;
  let sessionAgentId: string | undefined;
  let breakGlassActive: boolean;
  let breakGlassUses: number;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "atlas-pipeline-unit-"));
    registry = await IdentityRegistry.create(dir, await QuantumSigner.create(dir));
    events = [];
    operator = new FakeOperator();
    sessionAgentId = undefined;
    breakGlassActive = false;
    breakGlassUses = 0;
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function pipeline(result: PolicyResult, overrides: Partial<PermissionPipelineDeps> = {}) {
    return createPermissionPipeline({
      registry,
      getSessionAgentId: () => sessionAgentId,
      policyEngine: { evaluate: () => result },
      audit: { log: (event: any, data: any) => { events.push({ event, data }); return {} as any; } },
      operator,
      baselineStore: { get: async () => undefined },
      quietConfig: { enabled: false, min_maturity: "mature", max_anomaly_flags: 0, quiet_tools: new Set(["Read"]) },
      breakGlass: {
        isActive: () => breakGlassActive,
        recordUsage: () => { breakGlassUses++; },
        read: () => ({ reason: "incident-42" }) as any,
      },
      config: { permission_timeout_seconds: 7, telegram_allowed_chat_ids: [42] },
      ...overrides,
    });
  }
  const names = () => events.map((e) => e.event);

  describe("attestation", () => {
    it("revoked session credential is denied before policy runs", async () => {
      const cred = registry.register({ name: "a", role: "claude-code", capabilities: ["file:read"] });
      registry.revoke(cred.agentId, "test");
      sessionAgentId = cred.agentId;
      let evaluated = false;
      const decide = pipeline(policy("allow"), { policyEngine: { evaluate: () => { evaluated = true; return policy("allow"); } } });
      assert.equal(await decide(req()), "deny");
      assert.equal(evaluated, false);
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "POLICY_DENY"]);
      assert.equal(events[1].data.meta.attestation_deny, "CREDENTIAL_REVOKED");
      assert.match(operator.replies[0], /IDENTITY DENIED[\s\S]*revoked/);
    });

    it("unregistered session agent is denied when the registry is non-empty", async () => {
      registry.register({ name: "someone", role: "claude-code", capabilities: ["file:read"] });
      sessionAgentId = undefined;
      assert.equal(await pipeline(policy("allow"))(req()), "deny");
      assert.equal(events[1].data.meta.attestation_deny, "UNREGISTERED_AGENT");
      assert.match(operator.replies[0], /Agent not registered/);
    });

    it("escapes tool names in operator messages", async () => {
      const cred = registry.register({ name: "a", role: "claude-code", capabilities: ["file:read"] });
      sessionAgentId = cred.agentId;
      await pipeline(policy("deny"))(req("<script>"));
      assert.ok(operator.replies.every((r) => !r.includes("<script>")));
    });
  });

  describe("policy", () => {
    it("deny notifies the operator with reason and MITRE tag", async () => {
      assert.equal(await pipeline(policy("deny"))(req("Bash", "rm -rf /")), "deny");
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "POLICY_DENY"]);
      assert.match(operator.replies[0], /AUTO-DENIED[\s\S]*rule deny[\s\S]*T1485/);
      assert.equal(operator.verdictCalls.length, 0);
    });

    it("allow does not contact the operator", async () => {
      assert.equal(await pipeline(policy("allow"))(req()), "allow");
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "POLICY_ALLOW"]);
      assert.equal(operator.replies.length + operator.verdictCalls.length, 0);
    });

    it("anomaly flags are logged before the verdict", async () => {
      await pipeline(policy("deny", { anomaly_flags: ["velocity"] }))(req());
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "ANOMALY_DETECTED", "POLICY_DENY"]);
      assert.deepEqual(events[1].data.meta.flags, ["velocity"]);
    });
  });

  describe("quiet mode", () => {
    it("auto-approves an ask for a mature, verified agent on a quiet tool", async () => {
      const cred = registry.register({ name: "a", role: "claude-code", capabilities: ["file:read"] });
      sessionAgentId = cred.agentId;
      const decide = pipeline(policy("ask"), {
        quietConfig: { enabled: true, min_maturity: "mature", max_anomaly_flags: 0, quiet_tools: new Set(["Read"]) },
        baselineStore: { get: async () => ({ maturityLevel: "mature", totalSessions: 50 }) as any },
      });
      assert.equal(await decide(req()), "allow");
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "POLICY_ALLOW"]);
      assert.equal(events[1].data.meta.quiet_mode, true);
      assert.equal(operator.verdictCalls.length, 0);
    });

    it("does not apply to bootstrap (unverified) sessions", async () => {
      const decide = pipeline(policy("ask"), {
        quietConfig: { enabled: true, min_maturity: "mature", max_anomaly_flags: 0, quiet_tools: new Set(["Read"]) },
        baselineStore: { get: async () => ({ maturityLevel: "mature", totalSessions: 50 }) as any },
      });
      assert.equal(await decide(req()), "deny");
      assert.equal(operator.verdictCalls.length, 1);
    });
  });

  describe("break-glass", () => {
    it("allows an ask without the operator and records usage", async () => {
      breakGlassActive = true;
      assert.equal(await pipeline(policy("ask"))(req()), "allow");
      assert.equal(breakGlassUses, 1);
      assert.equal(events[1].data.meta.break_glass, true);
      assert.equal(events[1].data.meta.break_glass_reason, "incident-42");
      assert.equal(operator.verdictCalls.length, 0);
    });

    it("never overrides a policy deny", async () => {
      breakGlassActive = true;
      assert.equal(await pipeline(policy("deny"))(req("Bash", "rm -rf /")), "deny");
      assert.equal(breakGlassUses, 0);
    });
  });

  describe("fail-closed guard", () => {
    it("a policy engine exception is a deny, recorded in the audit log", async () => {
      const decide = pipeline(policy("allow"), { policyEngine: { evaluate: () => { throw new Error("bad rule"); } } });
      assert.equal(await decide(req()), "deny");
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "POLICY_DENY"]);
      assert.match(events[1].data.meta.pipeline_error, /bad rule/);
    });

    it("an audit failure is still a deny (never a missing verdict)", async () => {
      const decide = pipeline(policy("allow"), { audit: { log: () => { throw new Error("disk full"); } } });
      assert.equal(await decide(req()), "deny");
    });
  });

  describe("operator verdict", () => {
    it("approve", async () => {
      operator = new FakeOperator({ decision: "allow", responder_chat_id: 42 });
      assert.equal(await pipeline(policy("ask"))(req()), "allow");
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "HUMAN_APPROVE"]);
      assert.equal(events[1].data.meta.responder_chat_id, 42);
      assert.equal(operator.verdictCalls[0].timeout, 7);
    });

    it("deny", async () => {
      operator = new FakeOperator({ decision: "deny", responder_chat_id: 42 });
      assert.equal(await pipeline(policy("ask"))(req()), "deny");
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "HUMAN_DENY"]);
    });

    it("timeout with chats configured is a fail-closed deny", async () => {
      assert.equal(await pipeline(policy("ask"))(req()), "deny");
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "TIMEOUT_DENY"]);
      assert.equal(events[1].data.meta.reason, "No human verdict received before timeout");
    });

    it("an operator channel failure is a fail-closed deny", async () => {
      operator.requestVerdict = async () => { throw new Error("telegram unreachable"); };
      assert.equal(await pipeline(policy("ask"))(req()), "deny");
      assert.deepEqual(names(), ["PERMISSION_REQUEST", "TIMEOUT_DENY"]);
      assert.match(events[1].data.meta.reason, /Operator channel error: telegram unreachable/);
    });

    it("passes sensitivity matches to the operator as flags", async () => {
      await pipeline(policy("ask", { sensitivity_matches: [{ data_type: "SSN", min_tier: 4 } as any] }))(req());
      assert.deepEqual(operator.verdictCalls[0].flags, ["📋 SSN detected (requires consent Tier 4+)"]);
    });
  });
});
