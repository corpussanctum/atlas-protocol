#!/usr/bin/env node

/**
 * Fidelis Channel — Claude Code Channels Plugin (v0.4.0)
 *
 * Telegram approval channel for Claude Code with:
 *   - fail-closed permission relay
 *   - configurable deny/ask/allow policy rules
 *   - tamper-evident audit logging (SHA3-256 chain + ML-DSA-65 signatures)
 *   - MITRE ATT&CK enrichment per audit entry
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
import { createIdentityProvider } from "./identity-provider.js";
import type { IdentityContext } from "./identity-provider.js";
import { QuantumSigner } from "./quantum-signer.js";

const VERSION = "0.4.0";

const PermissionRequestSchema = z.object({
  method: z.literal("notifications/claude/channel/permission_request"),
  params: z.object({
    request_id: z.string(),
    tool_name: z.string(),
    description: z.string(),
    input_preview: z.string(),
  }),
});

async function main(): Promise<void> {
  const config = loadConfig();
  const identityProvider = createIdentityProvider(config.briefcase_path || undefined);
  const identityContext = identityProvider.getContext();
  const policyEngine = new PolicyEngine(config, identityContext);

  // Initialize ML-DSA-65 quantum signer
  const signer = await QuantumSigner.create(config.data_dir);

  const audit = new AuditLogger(
    config,
    {
      redact_fields: identityContext.loaded
        ? identityContext.audit_redact_fields
        : process.env.FIDELIS_PRIVACY_MODE === "true"
          ? ["input_preview"]
          : [],
      force_privacy: process.env.FIDELIS_PRIVACY_MODE === "true",
    },
    signer,
  );
  const telegram = new TelegramBot(config);

  audit.log("SESSION_START", {
    meta: {
      version: VERSION,
      telegram_configured: !!config.telegram_bot_token,
      allowed_chats: config.telegram_allowed_chat_ids.length,
      policy_rules: config.policy_rules.length,
      hmac_enabled: !!config.audit_hmac_secret,
      pq_signing: signer.available,
      pq_algorithm: signer.available ? "ML-DSA-65" : null,
      pq_public_key_hash: signer.getPublicKeyHash(),
      data_dir: config.data_dir,
      identity_loaded: identityContext.loaded,
      identity_principal: identityContext.principal_label || null,
      identity_max_tier: identityContext.loaded ? identityContext.max_tier_present : null,
      briefcase_path: config.briefcase_path || null,
    },
  });
  audit.log("CONFIG_LOADED", {
    meta: {
      timeout_seconds: config.permission_timeout_seconds,
      velocity_limit: config.velocity_limit_per_minute,
      audit_log_path: config.audit_log_path,
      config_path: config.config_path,
      hash_algorithm: "sha3-256",
    },
  });
  if (identityContext.loaded) {
    audit.log("IDENTITY_LOADED", {
      meta: {
        principal: identityContext.principal_label,
        max_tier: identityContext.max_tier_present,
        consent_boundaries: identityContext.consent_boundaries.length,
        agent_authorizations: identityContext.agent_authorizations.length,
        sensitivity_classifications: identityContext.sensitivity_classifications.length,
        audit_redact_fields: identityContext.audit_redact_fields,
      },
    });
  }

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
            raw_html: {
              type: "boolean",
              description: "Set true to send message as trusted Telegram HTML. Default is false and content is escaped.",
            },
          },
          required: ["message"],
        },
      },
      {
        name: "fidelis_audit_verify",
        description:
          "Verify the integrity of the Fidelis audit log. Checks SHA3-256 hash chain, HMAC signatures, and ML-DSA-65 post-quantum signatures.",
        inputSchema: {
          type: "object" as const,
          properties: {},
        },
      },
      {
        name: "fidelis_status",
        description:
          "Get the current Fidelis runtime status, including Telegram readiness, quantum signing status, allowed chats, audit settings, and pending verdict count.",
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
        const rawHtml = Boolean(args?.raw_html);

        if (!message) {
          return {
            content: [{ type: "text" as const, text: "Error: message is required" }],
            isError: true,
          };
        }

        try {
          const renderedMessage = rawHtml ? message : escapeHtml(message);
          await telegram.sendReply(`💬 <b>Claude:</b>\n${renderedMessage}`, {
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
        const lines = [
          result.valid
            ? "✅ Audit log integrity verified."
            : "❌ Audit log integrity FAILED:",
        ];

        if (!result.valid) {
          lines.push(...result.errors);
        }

        lines.push("");
        lines.push(`Entries: ${result.stats.total_entries}`);
        lines.push(`ML-DSA-65 signed: ${result.stats.pq_signed}`);
        lines.push(`HMAC signed: ${result.stats.hmac_signed}`);
        if (result.stats.legacy_sha256 > 0) {
          lines.push(`Legacy SHA-256 entries: ${result.stats.legacy_sha256}`);
        }

        return {
          content: [{ type: "text" as const, text: lines.join("\n") }],
        };
      }

      case "fidelis_status": {
        const telegramStatus = telegram.getStatus();
        const signerStatus = signer.getStatus();
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
          audit: {
            log_path: config.audit_log_path,
            hash_algorithm: "sha3-256",
            hmac_signing: !!config.audit_hmac_secret,
            quantum_signing: signerStatus,
          },
          data_dir: config.data_dir,
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
      const mitreTag = policyResult.matched_rule?.mitre_id
        ? `\nMITRE: <code>${escapeHtml(policyResult.matched_rule.mitre_id)}</code>`
        : "";
      const sensitivityInfo = policyResult.sensitivity_matches.length > 0
        ? `\nData: ${policyResult.sensitivity_matches.map((s) => s.data_type).join(", ")}`
        : "";
      await telegram
        .sendReply(
          `🚫 <b>AUTO-DENIED</b> by Fidelis policy:\n` +
            `Tool: <code>${escapeHtml(req.tool_name)}</code>\n` +
            `Reason: ${escapeHtml(reason)}${mitreTag}${sensitivityInfo}`,
          { broadcast: true }
        )
        .catch(() => {});

      sendVerdict(mcp, req.request_id, "deny");
      return;
    }

    if (policyResult.verdict === "allow") {
      audit.log("POLICY_ALLOW", {
        permission: req,
        policy_result: policyResult,
        verdict: "allow",
      });

      sendVerdict(mcp, req.request_id, "allow");
      return;
    }

    // Build combined flags: anomaly flags + sensitivity annotations for Telegram prompt
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
        meta: { responder_chat_id: outcome.responder_chat_id },
      });
      sendVerdict(mcp, req.request_id, "allow");
      return;
    }

    if (outcome.decision === "deny") {
      audit.log("HUMAN_DENY", {
        permission: req,
        policy_result: policyResult,
        verdict: "deny",
        meta: { responder_chat_id: outcome.responder_chat_id },
      });
      sendVerdict(mcp, req.request_id, "deny");
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
    sendVerdict(mcp, req.request_id, "deny");
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
  console.error(`[fidelis] Audit log: ${config.audit_log_path} (SHA3-256 chain)`);
  console.error(`[fidelis] ML-DSA-65 signing: ${signer.available ? `active (key: ${signer.getPublicKeyHash()?.slice(0, 16)}...)` : "unavailable"}`);
  console.error(`[fidelis] Identity: ${identityContext.loaded ? `${identityContext.principal_label} (Tier ${identityContext.max_tier_present})` : "standalone (no briefcase)"}`);
}

function sendVerdict(mcp: Server, requestId: string, behavior: "allow" | "deny"): void {
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

main().catch((err) => {
  console.error("[fidelis] Fatal error:", err);
  process.exit(1);
});
