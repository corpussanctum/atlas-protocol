/**
 * Atlas Protocol — Permission pipeline (authority core)
 *
 * Transport-independent decision for a single tool permission request:
 *
 *   1. Agent attestation      (identity, credential state, capability)
 *   2. Policy evaluation      (deny / allow / ask, anomaly flags)
 *   3. Quiet mode             (auto-approve low-risk asks for mature agents)
 *   4. Break-glass            (time-limited bypass of the human step)
 *   5. Human verdict          (operator relay; timeout ⇒ deny)
 *
 * Every branch writes its audit entries before returning. Callers (the MCP
 * adapter today; A2A / gateway adapters later) only deliver the verdict.
 */

import type { PermissionRequest, PolicyResult } from "../policy-engine.js";
import type { AuditLogger } from "../audit-log.js";
import type { AtlasConfig } from "../config.js";
import type { IdentityRegistry } from "../identity-registry.js";
import type { BaselineStore } from "../baseline-store.js";
import type { BreakGlassManager } from "../break-glass.js";
import type { QuietModeConfig } from "../quiet-mode.js";
import type { VerdictOutcome, SendReplyOptions } from "../telegram.js";
import { attestAgent, enrichAuditEntry, toolToCapability } from "../attestation.js";
import { checkQuietEligibility } from "../quiet-mode.js";
import { escapeHtml } from "../html.js";

export type Verdict = "allow" | "deny";

/** The human-in-the-loop channel (Telegram in the reference implementation). */
export interface OperatorChannel {
  sendReply(text: string, options?: SendReplyOptions): Promise<unknown>;
  requestVerdict(
    requestId: string,
    toolName: string,
    description: string,
    inputPreview: string,
    anomalyFlags: string[],
    timeoutSeconds: number,
  ): Promise<VerdictOutcome>;
}

export interface PermissionPipelineDeps {
  registry: IdentityRegistry;
  /** Agent registered in this session (atlas_identity_register), if any. */
  getSessionAgentId(): string | undefined;
  policyEngine: { evaluate(req: PermissionRequest): PolicyResult };
  /** Looked up at call time so wrappers installed on audit.log still apply. */
  audit: Pick<AuditLogger, "log">;
  operator: OperatorChannel;
  baselineStore: Pick<BaselineStore, "get">;
  quietConfig: QuietModeConfig;
  breakGlass: Pick<BreakGlassManager, "isActive" | "recordUsage" | "read">;
  config: Pick<AtlasConfig, "permission_timeout_seconds" | "telegram_allowed_chat_ids">;
}

export function createPermissionPipeline(deps: PermissionPipelineDeps): (req: PermissionRequest) => Promise<Verdict> {
  const { registry, policyEngine, audit, baselineStore, quietConfig, breakGlass, config } = deps;
  const telegram = deps.operator;

  return async function decide(req: PermissionRequest): Promise<Verdict> {
    const sessionAgentId = deps.getSessionAgentId();

    // --- Step 1: Agent attestation (before policy evaluation) ---------------
    const requiredCap = toolToCapability(req.tool_name);
    const attestation = attestAgent(registry, sessionAgentId, requiredCap);

    // Enrich the initial permission request log with identity
    const enrichedMeta = {
      agentId: attestation.agentId,
      identityVerified: attestation.identityVerified,
    };

    audit.log("PERMISSION_REQUEST", {
      permission: req,
      meta: enrichedMeta,
    });

    // If attestation failed and registry is not empty → deny immediately
    if (attestation.denyReason) {
      const entry = enrichAuditEntry(
        {
          id: "",
          timestamp: "",
          event: "POLICY_DENY",
          prev_hash: "",
          permission: req,
          verdict: "deny",
        },
        attestation
      );

      audit.log("POLICY_DENY", {
        permission: req,
        verdict: "deny",
        meta: {
          attestation_deny: attestation.denyReason,
          agentId: attestation.agentId,
          identityVerified: false,
          agentRole: attestation.role,
          attestationDenyReason: attestation.denyReason,
        },
      });

      // Format human-readable denial reason
      let denyDetail = escapeHtml(attestation.denyReason);
      if (attestation.denyReason === "CREDENTIAL_EXPIRED") {
        const expiredAt = attestation.credentialExpiry
          ? new Date(attestation.credentialExpiry).toLocaleString()
          : "unknown";
        denyDetail = `Credential <b>expired</b> at ${escapeHtml(expiredAt)} — re-register with <code>atlas_identity_register</code>`;
      } else if (attestation.denyReason === "CREDENTIAL_REVOKED") {
        denyDetail = "Credential has been <b>revoked</b>";
      } else if (attestation.denyReason === "UNREGISTERED_AGENT") {
        denyDetail = "Agent not registered — use <code>atlas_identity_register</code>";
      } else if (attestation.denyReason === "CAPABILITY_MISMATCH") {
        denyDetail = `Agent lacks required capability for <code>${escapeHtml(req.tool_name)}</code>`;
      }

      await telegram
        .sendReply(
          `🚫 <b>IDENTITY DENIED</b> by Atlas attestation:\n` +
            `Tool: <code>${escapeHtml(req.tool_name)}</code>\n` +
            `Agent: <code>${escapeHtml(attestation.agentId)}</code>\n` +
            `Reason: ${denyDetail}`,
          { broadcast: true }
        )
        .catch(() => {});

      return "deny";
    }

    // --- Step 2: Policy evaluation ------------------------------------------
    const policyResult: PolicyResult = policyEngine.evaluate(req);
    if (policyResult.anomaly_flags.length > 0) {
      audit.log("ANOMALY_DETECTED", {
        permission: req,
        policy_result: policyResult,
        meta: { flags: policyResult.anomaly_flags, ...enrichedMeta },
      });
    }

    // Build identity meta to attach to all audit entries
    const identityMeta = {
      agentId: attestation.agentId,
      identityVerified: attestation.identityVerified,
      agentRole: attestation.role,
      credentialExpiry: attestation.credentialExpiry,
    };

    if (policyResult.verdict === "deny") {
      audit.log("POLICY_DENY", {
        permission: req,
        policy_result: policyResult,
        verdict: "deny",
        meta: identityMeta,
      });

      const reason = policyResult.matched_rule?.reason || "Policy rule match";
      const mitreTag = policyResult.matched_rule?.mitre_id
        ? `\nMITRE: <code>${escapeHtml(policyResult.matched_rule.mitre_id)}</code>`
        : "";
      const sensitivityInfo = policyResult.sensitivity_matches.length > 0
        ? `\nData: ${policyResult.sensitivity_matches.map((s) => s.data_type).join(", ")}`
        : "";
      await telegram
        .sendReply(
          `🚫 <b>AUTO-DENIED</b> by Atlas policy:\n` +
            `Tool: <code>${escapeHtml(req.tool_name)}</code>\n` +
            `Agent: <code>${escapeHtml(attestation.agentId)}</code>\n` +
            `Reason: ${escapeHtml(reason)}${mitreTag}${sensitivityInfo}`,
          { broadcast: true }
        )
        .catch(() => {});

      return "deny";
    }

    if (policyResult.verdict === "allow") {
      audit.log("POLICY_ALLOW", {
        permission: req,
        policy_result: policyResult,
        verdict: "allow",
        meta: identityMeta,
      });

      return "allow";
    }

    // --- Step 3: Quiet mode check (auto-approve low-risk for mature agents) --
    if (policyResult.verdict === "ask") {
      const agentBaseline = sessionAgentId
        ? await baselineStore.get(sessionAgentId)
        : undefined;
      const quietResult = checkQuietEligibility(quietConfig, req, policyResult, attestation, agentBaseline);
      if (quietResult.eligible) {
        audit.log("POLICY_ALLOW", {
          permission: req,
          policy_result: policyResult,
          verdict: "allow",
          meta: {
            ...identityMeta,
            quiet_mode: true,
            baseline_maturity: agentBaseline?.maturityLevel,
            baseline_sessions: agentBaseline?.totalSessions,
          },
        });

        return "allow";
      }
    }

    // --- Step 4: Break-glass check (bypass Telegram if active) ---------------
    if (breakGlass.isActive()) {
      breakGlass.recordUsage();
      audit.log("POLICY_ALLOW", {
        permission: req,
        policy_result: policyResult,
        verdict: "allow",
        meta: {
          ...identityMeta,
          break_glass: true,
          break_glass_reason: breakGlass.read()?.reason ?? "unknown",
        },
      });

      return "allow";
    }

    // --- Step 4: Forward to Telegram for human verdict ---------------------
    const promptFlags = [...policyResult.anomaly_flags];
    if (policyResult.sensitivity_matches.length > 0) {
      for (const sm of policyResult.sensitivity_matches) {
        promptFlags.push(`📋 ${sm.data_type} detected (requires consent Tier ${sm.min_tier}+)`);
      }
    }

    const outcome = await telegram.requestVerdict(
      req.request_id,
      req.tool_name,
      req.description,
      req.input_preview,
      promptFlags,
      config.permission_timeout_seconds
    );

    if (outcome.decision === "allow") {
      audit.log("HUMAN_APPROVE", {
        permission: req,
        policy_result: policyResult,
        verdict: "allow",
        meta: { responder_chat_id: outcome.responder_chat_id, ...identityMeta },
      });
      return "allow";
    }

    if (outcome.decision === "deny") {
      audit.log("HUMAN_DENY", {
        permission: req,
        policy_result: policyResult,
        verdict: "deny",
        meta: { responder_chat_id: outcome.responder_chat_id, ...identityMeta },
      });
      return "deny";
    }

    audit.log("TIMEOUT_DENY", {
      permission: req,
      policy_result: policyResult,
      verdict: "deny",
      meta: {
        ...identityMeta,
        reason:
          config.telegram_allowed_chat_ids.length === 0
            ? "No authorized Telegram chat configured"
            : "No human verdict received before timeout",
      },
    });
    return "deny";
  };
}
