#!/usr/bin/env node

/**
 * Fidelis Channel — Claude Code Channels Plugin
 *
 * A fiduciary-grade agent authentication channel for Claude Code.
 * Wraps Telegram with:
 *   - Fail-closed permission relay (timeout = DENY)
 *   - Configurable policy engine (deny/ask/allow rules)
 *   - HMAC-signed, hash-chained audit log
 *   - Anomaly detection (velocity, privilege escalation, exfiltration)
 *
 * Implements the Claude Code Channels MCP contract:
 *   - Declares `claude/channel` capability
 *   - Emits `notifications/claude/channel` for inbound Telegram messages
 *   - Handles `notifications/claude/channel/permission_request` for permission relay
 *   - Sends `notifications/claude/channel/permission` verdicts back
 *   - Exposes `fidelis_reply` tool for Claude to send replies
 *   - Exposes `fidelis_audit_verify` tool to verify audit log integrity
 *
 * Transport: stdio (spawned as subprocess by Claude Code)
 *
 * Usage:
 *   claude --channels plugin:fidelis@<marketplace>
 *   # or for development:
 *   claude --dangerously-load-development-channels -- node dist/index.js
 *
 * @see https://code.claude.com/docs/en/channels-reference
 * @author TJ Lane — Corpus Sanctum Inc. / TheraNotes AI LLC
 * @license Apache-2.0
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

// ---------------------------------------------------------------------------
// Zod schemas for MCP notifications (Claude Code extensions)
// ---------------------------------------------------------------------------

const PermissionRequestSchema = z.object({
  method: z.literal("notifications/claude/channel/permission_request"),
  params: z.object({
    request_id: z.string(),
    tool_name: z.string(),
    description: z.string(),
    input_preview: z.string(),
  }),
});

// PermissionVerdictSchema is not needed as a handler — we send verdicts, not receive them.

// ---------------------------------------------------------------------------
// Initialize components
// ---------------------------------------------------------------------------

const config = loadConfig();
const policyEngine = new PolicyEngine(config);
const audit = new AuditLogger(config);
const telegram = new TelegramBot(config);

// Log startup
audit.log("SESSION_START", {
  meta: {
    version: "0.1.0",
    telegram_configured: !!config.telegram_bot_token,
    allowed_chats: config.telegram_allowed_chat_ids.length,
    policy_rules: config.policy_rules.length,
    hmac_enabled: !!config.audit_hmac_secret,
  },
});
audit.log("CONFIG_LOADED", {
  meta: {
    timeout_seconds: config.permission_timeout_seconds,
    velocity_limit: config.velocity_limit_per_minute,
    audit_log_path: config.audit_log_path,
  },
});

// ---------------------------------------------------------------------------
// MCP Server setup
// ---------------------------------------------------------------------------

const mcp = new Server(
  {
    name: "fidelis-channel",
    version: "0.1.0",
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
      "Fidelis Channel is a fiduciary-grade security layer for agent authentication.",
      "Messages from Telegram arrive as channel events. Claude can reply using the fidelis_reply tool.",
      "Permission requests are evaluated by a policy engine before reaching the human operator.",
      "If a permission request is auto-denied by policy, Claude will see a denial with the policy reason.",
      "All permission decisions are cryptographically logged in a tamper-evident audit trail.",
      "The operator can verify audit integrity using the fidelis_audit_verify tool.",
      "",
      "SECURITY MODEL: Fail-closed. If no human verdict is received within the configured timeout,",
      "the permission is automatically DENIED. This is by design — Fidelis Protocol requires explicit",
      "human authorization for all non-trivially-safe operations.",
    ].join("\n"),
  }
);

// ---------------------------------------------------------------------------
// Tool: fidelis_reply — Claude sends messages back to Telegram
// ---------------------------------------------------------------------------

mcp.setRequestHandler(
  ListToolsRequestSchema,
  async () => ({
    tools: [
      {
        name: "fidelis_reply",
        description:
          "Send a reply message to the Telegram operator. Use this to respond to channel messages, report task progress, or notify the operator of important events.",
        inputSchema: {
          type: "object" as const,
          properties: {
            message: {
              type: "string",
              description: "The message text to send (HTML formatting supported)",
            },
          },
          required: ["message"],
        },
      },
      {
        name: "fidelis_audit_verify",
        description:
          "Verify the integrity of the Fidelis audit log. Checks hash chain continuity and HMAC signatures. Returns a verification report.",
        inputSchema: {
          type: "object" as const,
          properties: {},
        },
      },
      {
        name: "fidelis_status",
        description:
          "Get the current status of the Fidelis Gatekeeper — connection state, policy rule count, audit log stats, and anomaly flags.",
        inputSchema: {
          type: "object" as const,
          properties: {},
        },
      },
    ],
  })
);

mcp.setRequestHandler(
  CallToolRequestSchema,
  async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "fidelis_reply": {
        const message = (args?.message as string) || "";
        if (!message) {
          return {
            content: [{ type: "text" as const, text: "Error: message is required" }],
            isError: true,
          };
        }
        await telegram.sendReply(`💬 <b>Claude:</b>\n${message}`);
        return {
          content: [{ type: "text" as const, text: "Message sent to Telegram operator." }],
        };
      }

      case "fidelis_audit_verify": {
        const result = audit.verify();
        const report = result.valid
          ? "✅ Audit log integrity verified. Hash chain intact, all HMACs valid."
          : `❌ Audit log integrity FAILED:\n${result.errors.join("\n")}`;
        return {
          content: [{ type: "text" as const, text: report }],
        };
      }

      case "fidelis_status": {
        const status = {
          version: "0.1.0",
          protocol: "Fidelis Protocol v0.1",
          telegram_connected: !!config.telegram_bot_token,
          allowed_chat_ids: config.telegram_allowed_chat_ids,
          policy_rules_count: config.policy_rules.length,
          permission_timeout_seconds: config.permission_timeout_seconds,
          velocity_limit_per_minute: config.velocity_limit_per_minute,
          hmac_signing_enabled: !!config.audit_hmac_secret,
          audit_log_path: config.audit_log_path,
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
  }
);

// ---------------------------------------------------------------------------
// Permission relay: intercept, evaluate, relay, respond
// ---------------------------------------------------------------------------

mcp.setNotificationHandler(
  PermissionRequestSchema,
  async ({ params }) => {
    const req: PermissionRequest = {
      request_id: params.request_id,
      tool_name: params.tool_name,
      description: params.description,
      input_preview: params.input_preview,
    };

    // Audit the incoming request
    audit.log("PERMISSION_REQUEST", { permission: req });

    // Log any anomalies
    const policyResult: PolicyResult = policyEngine.evaluate(req);
    if (policyResult.anomaly_flags.length > 0) {
      audit.log("ANOMALY_DETECTED", {
        permission: req,
        policy_result: policyResult,
        meta: { flags: policyResult.anomaly_flags },
      });
    }

    // Policy engine decision
    if (policyResult.verdict === "deny") {
      // Auto-deny: send verdict immediately
      audit.log("POLICY_DENY", {
        permission: req,
        policy_result: policyResult,
        verdict: "deny",
      });

      // Notify operator of auto-deny
      const reason = policyResult.matched_rule?.reason || "Policy rule match";
      await telegram.sendReply(
        `🚫 <b>AUTO-DENIED</b> by Fidelis policy:\n` +
        `Tool: <code>${escapeHtml(req.tool_name)}</code>\n` +
        `Reason: ${escapeHtml(reason)}`
      ).catch(() => {});

      sendVerdict(req.request_id, "deny");
      return;
    }

    if (policyResult.verdict === "allow") {
      // Auto-allow (use sparingly — only for known-safe patterns)
      audit.log("POLICY_ALLOW", {
        permission: req,
        policy_result: policyResult,
        verdict: "allow",
      });

      sendVerdict(req.request_id, "allow");
      return;
    }

    // verdict === "ask": forward to Telegram for human decision
    const approved = await telegram.requestVerdict(
      req.request_id,
      req.tool_name,
      req.description,
      req.input_preview,
      policyResult.anomaly_flags,
      config.permission_timeout_seconds
    );

    if (approved) {
      audit.log("HUMAN_APPROVE", {
        permission: req,
        policy_result: policyResult,
        verdict: "allow",
      });
      sendVerdict(req.request_id, "allow");
    } else {
      // Could be explicit denial or timeout — both result in deny (fail-closed)
      audit.log("TIMEOUT_DENY", {
        permission: req,
        policy_result: policyResult,
        verdict: "deny",
        meta: { reason: "Human denied or timeout reached (fail-closed)" },
      });
      sendVerdict(req.request_id, "deny");
    }
  }
);

// ---------------------------------------------------------------------------
// Inbound Telegram messages → Claude channel events
// ---------------------------------------------------------------------------

telegram.onMessage((msg) => {
  // Audit the inbound message
  audit.log("CHANNEL_MESSAGE", {
    meta: {
      from_id: msg.from_id,
      from_name: msg.from_name,
      chat_id: msg.chat_id,
      text_length: msg.text.length,
    },
  });

  // Forward to Claude as a channel notification
  console.error(`[fidelis] Forwarding message from ${msg.from_name}: "${msg.text.slice(0, 80)}"`);
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
    .then(() => {
      console.error("[fidelis] Channel notification sent successfully");
    })
    .catch((err) => {
      console.error("[fidelis] Failed to emit channel notification:", err);
    });
});

// ---------------------------------------------------------------------------
// Send a permission verdict back to Claude Code
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// HTML escape helper
// ---------------------------------------------------------------------------

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------------------
// Connect and run
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // Start Telegram polling
  await telegram.start();

  // Connect MCP over stdio
  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  console.error("[fidelis] Fidelis Channel v0.1.0 — fiduciary-grade agent gatekeeper active");
  console.error(`[fidelis] Telegram: ${config.telegram_bot_token ? "configured" : "NOT configured"}`);
  console.error(`[fidelis] Allowed chats: ${config.telegram_allowed_chat_ids.join(", ") || "none (pairing mode)"}`);
  console.error(`[fidelis] Policy rules: ${config.policy_rules.length}`);
  console.error(`[fidelis] Timeout: ${config.permission_timeout_seconds}s (fail-closed)`);
  console.error(`[fidelis] Audit log: ${config.audit_log_path}`);
}

main().catch((err) => {
  console.error("[fidelis] Fatal error:", err);
  process.exit(1);
});
