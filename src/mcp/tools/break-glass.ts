/**
 * Atlas Protocol — MCP tools: Break-glass status / revoke; activation is operator-only (SPEC §9)
 */

import { escapeHtml } from "../../html.js";
import type { Tool } from "@modelcontextprotocol/server";
import type { ToolContext, ToolHandler } from "../context.js";

export const definitions: Tool[] = [
  {
    name: "atlas_break_glass_activate",
    description:
      "Request a break-glass emergency override. Always refused from an agent session and reported to the operator: " +
      "only the operator can activate break-glass, via `atlas-operator break-glass` on the host (operator-key signed).",
    inputSchema: {
      type: "object" as const,
      properties: {
        reason: { type: "string", description: "Why break-glass is needed" },
        ttl_minutes: { type: "number", description: "Token lifetime in minutes (default: 60, max: 240)" },
        max_requests: { type: "number", description: "Max auto-approved requests (0 = unlimited, default: 0)" },
      },
      required: ["reason"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "atlas_break_glass_status",
    description: "Check current break-glass status.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "atlas_break_glass_revoke",
    description: "Revoke an active break-glass token immediately.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
];

export function handlers(ctx: ToolContext): Record<string, ToolHandler> {
  const { audit, telegram, breakGlass } = ctx;
  return {
    async atlas_break_glass_activate(args) {
      // Break-glass bypasses the human step, so the governed agent (which can
      // call MCP tools) must not be able to authorize it. Only the operator,
      // holding the operator key passphrase, can issue a token (SPEC §9).
      audit.log("CONFIG_LOADED", {
        meta: {
          event_detail: "BREAK_GLASS_ACTIVATION_REFUSED",
          requested_reason: typeof args?.reason === "string" ? args.reason.slice(0, 200) : null,
          session_agent_id: ctx.sessionAgentId ?? null,
        },
      });
      await telegram.sendReply(
        `⚠️ <b>BREAK-GLASS REQUESTED BY AGENT</b> (refused)\n` +
        `Reason given: ${escapeHtml(typeof args?.reason === "string" ? args.reason.slice(0, 200) : "(none)")}\n` +
        `Only the operator can activate break-glass: <code>atlas-operator break-glass --reason "…"</code>`,
        { broadcast: true }
      ).catch(() => {});
      return {
        content: [{
          type: "text" as const,
          text:
            "Break-glass cannot be activated from an agent session. The operator must run " +
            "`atlas-operator break-glass --reason \"…\"` on the host (requires the operator key passphrase). " +
            (breakGlass.operatorKeyId
              ? `Operator key: ${breakGlass.operatorKeyId}.`
              : "No operator key is configured; the operator must first run `atlas-operator keygen`."),
        }],
        isError: true,
      };
    },
    async atlas_break_glass_status(args) {
      const bgStatus = breakGlass.getStatus();
      return { content: [{ type: "text" as const, text: JSON.stringify(bgStatus, null, 2) }] };
    },
    async atlas_break_glass_revoke(args) {
      const wasActive = breakGlass.isActive();
      const revoked = breakGlass.revoke();

      if (revoked && wasActive) {
        audit.log("CONFIG_LOADED", {
          meta: { event_detail: "BREAK_GLASS_REVOKED" },
        });
        await telegram.sendReply("🔒 <b>BREAK-GLASS REVOKED</b> — normal Telegram approval flow restored.", { broadcast: true }).catch(() => {});
        return { content: [{ type: "text" as const, text: "Break-glass token revoked. Normal approval flow restored." }] };
      }

      return { content: [{ type: "text" as const, text: wasActive ? "Token file removed." : "No active break-glass token found." }] };
    },
  };
}
