#!/usr/bin/env node

/**
 * Fidelis Channel — Claude Code Channels Plugin
 *
 * Telegram approval channel for Claude Code with:
 *   - fail-closed permission relay
 *   - configurable deny/ask/allow policy rules
 *   - tamper-evident audit logging
 *   - anomaly flagging for higher-risk tool requests
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { PolicyEngine } from "./policy-engine.js";
import type { PermissionRequest, PolicyResult } from "./policy-engine.js";
import { AuditLogger } from "./audit-log.js";
import { TelegramBot } from "./telegram.js";

const VERSION = "0.2.0";

const PermissionRequestSchema = z.object({
  method: z.literal("notifications/claude/channel/permission_request"),
  params: z.object({
    request_id: z.string(),
    tool_name: z.string(),
    description: z.string(),
    input_preview: z.string(),
  }),
});

const config = loadConfig();
const policyEngine = new PolicyEngine(config);
const audit = new AuditLogger(config);
const telegram = new TelegramBot(config);

audit.log("SESSION_START", {
  meta: {
    version: VERSION,
    telegram_configured: !!config.telegram_bot_token,
    allowed_chats: config.telegram_allowed_chat_ids.length,
    policy_rules: config.policy_rules.length,
    hmac_enabled: !!config.audit_hmac_secret,
    data_dir: config.data_dir,
  },
});
audit.log("CONFIG_LOADED", {
  meta: {
    timeout_seconds: config.permission_timeout_seconds,
    velocity_limit: config.velocity_limit_per_minute,
    audit_log_path: config.audit_log_path,
    config_path: config.config_path,
  },
});

const mcp = new Server(
  {
    name: "fidelis-channel",
    version: VERSION,
  },
  {
    capabilities: {
      tools: {},
      experimental: {
        "claude/channel": {},
        "claude/channel/permission": {},
      },
    },
    instructions: [
      "Fidelis Channel forwards authorized Telegram messages into this Claude Code session.",
      "Use fidelis_reply to reply to the operator. By default replies go to the most recent authorized chat.",
      "Permission requests are evaluated by a local policy engine before being relayed to Telegram.",
      "When no verdict arrives before the timeout, Fidelis denies the request by design.",
      "Use fidelis_audit_verify to verify the audit log and fidelis_status to inspect runtime status.",
    ].join("\n"),
  }
);

mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "fidelis_reply",
      description:
        "Send a reply message to the Telegram operator. Defaults to the most recent authorized chat unless chat_id or broadcast is provided.",
      inputSchema: {
        type: "object" as const,
        properties: {
          message: {
            type: "string",
            description: "The message text to send (HTML formatting supported)",
          },
          chat_id: {
            type: "integer",
            description: "Optional Telegram chat ID to target explicitly",
          },
          broadcast: {
            type: "boolean",
            description: "Set true to send to all authorized chats",
          },
        },
        required: ["message"],
      },
    },
    {
      name: "fidelis_audit_verify",
      description:
        "Verify the integrity of the Fidelis audit log. Checks hash chain continuity and HMAC signatures.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "fidelis_status",
      description:
        "Get the current Fidelis runtime status, including Telegram readiness, allowed chats, audit settings, and pending verdict count.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
  ],
}));

mcp.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "fidelis_reply": {
      const message = (args?.message as string) || "";
      const chatId = typeof args?.chat_id === "number" ? args.chat_id : undefined;
      const broadcast = Boolean(args?.broadcast);

      if (!message) {
        return {
          content: [{ type: "text" as const, text: "Error: message is required" }],
          isError: true,
        };
      }

      try {
        await telegram.sendReply(`💬 <b>Claude:</b>\n${message}`, {
          chatId,
          broadcast,
        });
        return {
          content: [{ type: "text" as const, text: "Message sent to Telegram." }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error: ${(error as Error).message}` }],
          isError: true,
        };
      }
    }

    case "fidelis_audit_verify": {
      const result = audit.verify();
      const report = result.valid
        ? "✅ Audit log integrity verified. Hash chain intact and all HMACs present validated."
        : `❌ Audit log integrity FAILED:\n${result.errors.join("\n")}`;
      return {
        content: [{ type: "text" as const, text: report }],
      };
    }

    case "fidelis_status": {
      const telegramStatus = telegram.getStatus();
      const status = {
        version: VERSION,
        telegram_connected: !!config.telegram_bot_token,
        channel_ready:
          !!config.telegram_bot_token && config.telegram_allowed_chat_ids.length > 0,
        allowed_chat_ids: config.telegram_allowed_chat_ids,
        pending_verdicts: telegramStatus.pending_verdicts,
        last_inbound_chat_id: telegramStatus.last_inbound_chat_id,
        policy_rules_count: config.policy_rules.length,
        permission_timeout_seconds: config.permission_timeout_seconds,
        velocity_limit_per_minute: config.velocity_limit_per_minute,
        hmac_signing_enabled: !!config.audit_hmac_secret,
        audit_log_path: config.audit_log_path,
        data_dir: config.data_dir,
      };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(status, null, 2) }],
      };
    }

    default:
      return {
        content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
});

mcp.setNotificationHandler(PermissionRequestSchema, async ({ params }) => {
  const req: PermissionRequest = {
    request_id: params.request_id,
    tool_name: params.tool_name,
    description: params.description,
    input_preview: params.input_preview,
  };

  audit.log("PERMISSION_REQUEST", { permission: req });

  const policyResult: PolicyResult = policyEngine.evaluate(req);
  if (policyResult.anomaly_flags.length > 0) {
    audit.log("ANOMALY_DETECTED", {
      permission: req,
      policy_result: policyResult,
      meta: { flags: policyResult.anomaly_flags },
    });
  }

  if (policyResult.verdict === "deny") {
    audit.log("POLICY_DENY", {
      permission: req,
      policy_result: policyResult,
      verdict: "deny",
    });

    const reason = policyResult.matched_rule?.reason || "Policy rule match";
    await telegram
      .sendReply(
        `🚫 <b>AUTO-DENIED</b> by Fidelis policy:\n` +
          `Tool: <code>${escapeHtml(req.tool_name)}</code>\n` +
          `Reason: ${escapeHtml(reason)}`,
        { broadcast: true }
      )
      .catch(() => {});

    sendVerdict(req.request_id, "deny");
    return;
  }

  if (policyResult.verdict === "allow") {
    audit.log("POLICY_ALLOW", {
      permission: req,
      policy_result: policyResult,
      verdict: "allow",
    });

    sendVerdict(req.request_id, "allow");
    return;
  }

  const outcome = await telegram.requestVerdict(
    req.request_id,
    req.tool_name,
    req.description,
    req.input_preview,
    policyResult.anomaly_flags,
    config.permission_timeout_seconds
  );

  if (outcome.decision === "allow") {
    audit.log("HUMAN_APPROVE", {
      permission: req,
      policy_result: policyResult,
      verdict: "allow",
      meta: { responder_chat_id: outcome.responder_chat_id },
    });
    sendVerdict(req.request_id, "allow");
    return;
  }

  if (outcome.decision === "deny") {
    audit.log("HUMAN_DENY", {
      permission: req,
      policy_result: policyResult,
      verdict: "deny",
      meta: { responder_chat_id: outcome.responder_chat_id },
    });
    sendVerdict(req.request_id, "deny");
    return;
  }

  audit.log("TIMEOUT_DENY", {
    permission: req,
    policy_result: policyResult,
    verdict: "deny",
    meta: {
      reason:
        config.telegram_allowed_chat_ids.length === 0
          ? "No authorized Telegram chat configured"
          : "No human verdict received before timeout",
    },
  });
  sendVerdict(req.request_id, "deny");
});

telegram.onMessage((msg) => {
  audit.log("CHANNEL_MESSAGE", {
    meta: {
      from_id: msg.from_id,
      from_name: msg.from_name,
      chat_id: msg.chat_id,
      text_length: msg.text.length,
    },
  });

  mcp
    .notification({
      method: "notifications/claude/channel",
      params: {
        content: msg.text,
        meta: {
          chat_id: String(msg.chat_id),
          sender: msg.from_name,
          sender_id: String(msg.from_id),
          platform: "telegram",
          timestamp: new Date(msg.timestamp * 1000).toISOString(),
        },
      },
    })
    .catch((err) => {
      console.error("[fidelis] Failed to emit channel notification:", err);
    });
});

function sendVerdict(requestId: string, behavior: "allow" | "deny"): void {
  mcp
    .notification({
      method: "notifications/claude/channel/permission",
      params: {
        request_id: requestId,
        behavior,
      },
    })
    .catch((err) => {
      console.error("[fidelis] Failed to send verdict:", err);
    });
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function main(): Promise<void> {
  await telegram.start();

  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  console.error(`[fidelis] Fidelis Channel v${VERSION} active`);
  console.error(`[fidelis] Telegram token: ${config.telegram_bot_token ? "configured" : "NOT configured"}`);
  console.error(
    `[fidelis] Authorized chats: ${config.telegram_allowed_chat_ids.join(", ") || "none (locked until configured)"}`
  );
  console.error(`[fidelis] Policy rules: ${config.policy_rules.length}`);
  console.error(`[fidelis] Timeout: ${config.permission_timeout_seconds}s (fail-closed)`);
  console.error(`[fidelis] Audit log: ${config.audit_log_path}`);
}

main().catch((err) => {
  console.error("[fidelis] Fatal error:", err);
  process.exit(1);
});
