/**
 * Atlas Protocol — MCP tools: Operator relay, audit verification, runtime status
 */

import { PROTOCOL_VERSION } from "../../protocol-version.js";
import { VERSION, SPEC_VERSION } from "../../version.js";
import { credentialTimeRemaining } from "../helpers.js";
import { escapeHtml } from "../../html.js";
import type { Tool } from "@modelcontextprotocol/server";
import type { ToolContext, ToolHandler } from "../context.js";

export const definitions: Tool[] = [
  {
    name: "atlas_reply",
    description:
      "Send a reply message to the Telegram operator. Defaults to the most recent authorized chat unless chat_id or broadcast is provided.",
    inputSchema: {
      type: "object" as const,
      properties: {
        message: { type: "string", description: "The message text to send" },
        chat_id: { type: "integer", description: "Optional Telegram chat ID" },
        broadcast: { type: "boolean", description: "Send to all authorized chats" },
        raw_html: { type: "boolean", description: "Send as trusted Telegram HTML" },
      },
      required: ["message"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "atlas_audit_verify",
    description: "Verify audit log integrity: SHA3-256 chain, HMAC, and ML-DSA-65 signatures.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "atlas_status",
    description: "Get Atlas runtime status including identity registry, quantum signing, and Telegram state.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

export function handlers(ctx: ToolContext): Record<string, ToolHandler> {
  const { config, registry, signer, audit, telegram, identityContext, breakGlass, quietConfig } = ctx;
  return {
    async atlas_reply(args) {
      const message = (args?.message as string) || "";
      const chatId = typeof args?.chat_id === "number" ? args.chat_id : undefined;
      const broadcast = Boolean(args?.broadcast);
      const rawHtml = Boolean(args?.raw_html);

      if (!message) {
        return { content: [{ type: "text" as const, text: "Error: message is required" }], isError: true };
      }

      try {
        const renderedMessage = rawHtml ? message : escapeHtml(message);
        await telegram.sendReply(`💬 <b>Claude:</b>\n${renderedMessage}`, { chatId, broadcast });
        return { content: [{ type: "text" as const, text: "Message sent to Telegram." }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: `Error: ${(error as Error).message}` }], isError: true };
      }
    },
    async atlas_audit_verify(args) {
      const result = audit.verify();
      const lines = [
        result.valid ? "✅ Audit log integrity verified." : "❌ Audit log integrity FAILED:",
      ];
      if (!result.valid && result.errors.length === 0) {
        lines.push("No tamper indicators: every link resolves and every signature verifies. The failure is concurrent-writer forks only.");
      }
      if (!result.valid) lines.push(...result.errors);
      if (result.forks.length > 0) {
        lines.push(
          "",
          `⚠️ ${result.forks.length} concurrent-writer fork(s): two server instances extended the chain from the same head.`,
          "Signed and not tampering, but the tail of each forked branch is not truncation-protected by the chain alone.",
          ...result.forks,
        );
      }
      lines.push("", `Entries: ${result.stats.total_entries}`);
      lines.push(`ML-DSA-65 signed: ${result.stats.pq_signed}`);
      lines.push(`HMAC signed: ${result.stats.hmac_signed}`);
      if (result.stats.legacy_sha256 > 0) lines.push(`Legacy SHA-256 entries: ${result.stats.legacy_sha256}`);
      return { content: [{ type: "text" as const, text: lines.join("\n") }] };
    },
    async atlas_status(args) {
      const telegramStatus = telegram.getStatus();
      const signerStatus = signer.getStatus();
      const status = {
        version: VERSION,
        protocol_version: PROTOCOL_VERSION,
        spec_version: SPEC_VERSION,
        telegram_connected: !!config.telegram_bot_token,
        channel_ready: !!config.telegram_bot_token && config.telegram_allowed_chat_ids.length > 0,
        allowed_chat_ids: config.telegram_allowed_chat_ids,
        pending_verdicts: telegramStatus.pending_verdicts,
        last_inbound_chat_id: telegramStatus.last_inbound_chat_id,
        policy_rules_count: config.policy_rules.length,
        permission_timeout_seconds: config.permission_timeout_seconds,
        velocity_limit_per_minute: config.velocity_limit_per_minute,
        audit: {
          log_path: config.audit_log_path,
          hash_algorithm: "sha3-256",
          hmac_signing: !!config.audit_hmac_secret,
          quantum_signing: signerStatus,
        },
        agent_identity: {
          session_agent_id: ctx.sessionAgentId || null,
          registry_size: registry.size,
          active_credentials: registry.list("active").length,
          bootstrap_mode: registry.isEmpty(),
          keystore: registry.keystoreMode,
          session_can_delegate: !!(ctx.sessionAgentId && registry.getAgentSigner(ctx.sessionAgentId)),
          ...(ctx.sessionAgentId && registry.get(ctx.sessionAgentId)
            ? credentialTimeRemaining(registry.get(ctx.sessionAgentId)!.expiresAt)
            : {}),
        },
        data_dir: config.data_dir,
        quiet_mode: {
          enabled: quietConfig.enabled,
          min_maturity: quietConfig.min_maturity,
          quiet_tools: Array.from(quietConfig.quiet_tools),
        },
        break_glass: breakGlass.getStatus(),
        isolation: {
          isolated: ctx.isolation.isolated,
          process_uid: ctx.isolation.process_uid,
          launched_by_uid: ctx.isolation.launched_by_uid,
          problems: ctx.isolation.problems,
        },
        identity: {
          loaded: identityContext.loaded,
          principal: identityContext.principal_label || null,
          max_consent_tier: identityContext.loaded ? identityContext.max_tier_present : null,
          consent_boundaries: identityContext.consent_boundaries.length,
          sensitivity_classifications: identityContext.sensitivity_classifications.length,
          audit_redact_fields: identityContext.audit_redact_fields,
          briefcase_path: config.briefcase_path || null,
        },
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(status, null, 2) }] };
    },
  };
}
