#!/usr/bin/env node

/**
 * Atlas Protocol — Claude Code Channels Plugin (v0.5.0)
 *
 * Telegram approval channel for Claude Code with:
 *   - agent identity attestation (ML-DSA-65 signed credentials)
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
import { randomBytes } from "node:crypto";
import { loadConfig } from "./config.js";
import { PolicyEngine } from "./policy-engine.js";
import type { PermissionRequest, PolicyResult } from "./policy-engine.js";
import { AuditLogger } from "./audit-log.js";
import type { AuditEntry } from "./audit-log.js";
import { TelegramBot } from "./telegram.js";
import { createIdentityProvider } from "./identity-provider.js";
import type { IdentityContext } from "./identity-provider.js";
import { QuantumSigner } from "./quantum-signer.js";
import { IdentityRegistry } from "./identity-registry.js";
import { attestAgent, enrichAuditEntry, toolToCapability, sanitizeCredential } from "./attestation.js";
import type { AgentRole, AgentCapability, DelegationRequest } from "./agent-identity.js";
import { isDelegatedCredential } from "./agent-identity.js";
import { assessWindow, loadWhyConfig, stubAssessment } from "./why-engine.js";
import type { WhyAssessment, AuditEventWindow } from "./why-engine.js";
import { shouldTrigger, formatTelegramAlert, loadTriggerConfig } from "./why-triggers.js";
import type { WhyTrigger } from "./why-triggers.js";
import { BaselineStore } from "./baseline-store.js";
import { ingestEntry as baselineIngestEntry, ingestAssessment as baselineIngestAssessment, detectDrift, getBaselineContext } from "./baseline-engine.js";
import type { DriftAssessment } from "./baseline-types.js";
import { runPolicyTests } from "./policy-test-runner.js";
import { BreakGlassManager } from "./break-glass.js";
import { AuditRotationManager } from "./audit-rotation.js";
import { checkQuietEligibility, loadQuietConfig } from "./quiet-mode.js";

const VERSION = "0.8.0";

const VALID_ROLES: AgentRole[] = ["claude-code", "orchestrator", "tool-caller", "observer", "admin"];
const VALID_CAPABILITIES: AgentCapability[] = [
  "file:read", "file:write", "file:delete",
  "shell:exec", "shell:read",
  "network:outbound", "network:inbound",
  "process:spawn", "process:kill",
  "credential:read", "audit:read",
  "identity:register", "identity:revoke",
];

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

  // Initialize identity registry
  const registry = await IdentityRegistry.create(config.data_dir, signer);

  // Session-level active agent ID (set by atlas_identity_register)
  let sessionAgentId: string | undefined;

  // Baseline store
  const baselineStore = new BaselineStore(config.data_dir);

  // Break-glass manager
  const breakGlass = new BreakGlassManager(config.data_dir);

  // Quiet mode
  const quietConfig = loadQuietConfig();

  // Audit log rotation
  const rotationMaxBytes = parseInt(process.env.ATLAS_AUDIT_MAX_SIZE_MB ?? "10", 10) * 1024 * 1024;
  const rotationMaxArchives = parseInt(process.env.ATLAS_AUDIT_MAX_ARCHIVES ?? "0", 10);
  const auditRotation = new AuditRotationManager(config.audit_log_path, {
    max_size_bytes: rotationMaxBytes,
    max_archives: rotationMaxArchives,
  });

  // Why Layer state
  const whyConfig = loadWhyConfig();
  const triggerConfig = loadTriggerConfig();
  let lastWhyAssessmentTime: Date | undefined;
  const recentAuditEntries: AuditEntry[] = [];

  const audit = new AuditLogger(
    config,
    {
      redact_fields: identityContext.loaded
        ? identityContext.audit_redact_fields
        : process.env.ATLAS_PRIVACY_MODE === "true"
          ? ["input_preview"]
          : [],
      force_privacy: process.env.ATLAS_PRIVACY_MODE === "true",
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
      agent_registry_size: registry.size,
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
      name: "atlas-protocol",
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
        "Atlas Protocol forwards authorized Telegram messages into this Claude Code session.",
        "Use atlas_reply to reply to the operator. By default replies go to the most recent authorized chat.",
        "Permission requests are evaluated by a local policy engine before being relayed to Telegram.",
        "When no verdict arrives before the timeout, Atlas denies the request by design.",
        "Use atlas_audit_verify to verify the audit log and atlas_status to inspect runtime status.",
        "Use atlas_identity_register to register this agent session with the gatekeeper.",
      ].join("\n"),
    }
  );

  // =========================================================================
  // MCP Tool definitions
  // =========================================================================

  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
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
      },
      {
        name: "atlas_audit_verify",
        description: "Verify audit log integrity: SHA3-256 chain, HMAC, and ML-DSA-65 signatures.",
        inputSchema: { type: "object" as const, properties: {} },
      },
      {
        name: "atlas_status",
        description: "Get Atlas runtime status including identity registry, quantum signing, and Telegram state.",
        inputSchema: { type: "object" as const, properties: {} },
      },
      // -- Identity management tools (v0.5.0) --------------------------------
      {
        name: "atlas_identity_register",
        description:
          "Register a new agent identity with the gatekeeper. Returns a signed credential. " +
          "First registration (bootstrap) is unrestricted. Subsequent registrations require identity:register capability.",
        inputSchema: {
          type: "object" as const,
          properties: {
            name: { type: "string", description: "Agent display name" },
            role: { type: "string", enum: VALID_ROLES, description: "Agent role" },
            capabilities: {
              type: "array",
              items: { type: "string", enum: VALID_CAPABILITIES },
              description: "List of granted capabilities",
            },
            ttl_hours: { type: "number", description: "Credential TTL in hours (default: 24)" },
          },
          required: ["name", "role", "capabilities"],
        },
      },
      {
        name: "atlas_identity_verify",
        description: "Verify an agent credential by agentId.",
        inputSchema: {
          type: "object" as const,
          properties: {
            agent_id: { type: "string", description: "The did:atlas:<uuid> to verify" },
          },
          required: ["agent_id"],
        },
      },
      {
        name: "atlas_identity_list",
        description: "List agent credentials. Filter: active, revoked, expired, or all.",
        inputSchema: {
          type: "object" as const,
          properties: {
            filter: { type: "string", enum: ["active", "revoked", "expired", "all"], description: "Filter (default: active)" },
          },
        },
      },
      {
        name: "atlas_identity_revoke",
        description: "Revoke an agent credential by agentId.",
        inputSchema: {
          type: "object" as const,
          properties: {
            agent_id: { type: "string", description: "The did:atlas:<uuid> to revoke" },
            reason: { type: "string", description: "Reason for revocation" },
          },
          required: ["agent_id", "reason"],
        },
      },
      // -- Delegation tools (v0.6.0) ------------------------------------------
      {
        name: "atlas_identity_delegate",
        description:
          "Delegate a scoped sub-credential from a parent agent. Child capabilities must be a subset of parent's. Max depth: 3.",
        inputSchema: {
          type: "object" as const,
          properties: {
            parent_agent_id: { type: "string", description: "Parent did:atlas:<uuid>" },
            child_name: { type: "string", description: "Child agent display name" },
            child_role: { type: "string", enum: VALID_ROLES, description: "Child agent role" },
            capabilities: {
              type: "array",
              items: { type: "string", enum: VALID_CAPABILITIES },
              description: "Capabilities (must be subset of parent)",
            },
            ttl_hours: { type: "number", description: "TTL in hours (capped at parent remaining)" },
          },
          required: ["parent_agent_id", "child_name", "child_role", "capabilities"],
        },
      },
      {
        name: "atlas_identity_cascade_revoke",
        description: "Revoke a parent credential and all descendants recursively.",
        inputSchema: {
          type: "object" as const,
          properties: {
            parent_agent_id: { type: "string", description: "Parent did:atlas:<uuid> to revoke" },
            reason: { type: "string", description: "Reason for revocation" },
          },
          required: ["parent_agent_id", "reason"],
        },
      },
      {
        name: "atlas_identity_tree",
        description: "Get the full credential tree rooted at an agentId.",
        inputSchema: {
          type: "object" as const,
          properties: {
            agent_id: { type: "string", description: "Root did:atlas:<uuid>" },
          },
          required: ["agent_id"],
        },
      },
      // -- Baseline tools (v0.7.0) ---------------------------------------------
      {
        name: "atlas_baseline_get",
        description: "Get the behavioral baseline profile for an agent.",
        inputSchema: {
          type: "object" as const,
          properties: {
            agent_id: { type: "string", description: "The did:atlas:<uuid>" },
          },
          required: ["agent_id"],
        },
      },
      {
        name: "atlas_baseline_drift",
        description: "Run drift detection against an agent's baseline using the current audit window.",
        inputSchema: {
          type: "object" as const,
          properties: {
            agent_id: { type: "string", description: "The did:atlas:<uuid>" },
            window_minutes: { type: "number", description: "Time window in minutes (default: 60)" },
          },
          required: ["agent_id"],
        },
      },
      {
        name: "atlas_baseline_list",
        description: "List all behavioral baseline profiles, optionally filtered.",
        inputSchema: {
          type: "object" as const,
          properties: {
            maturity: { type: "string", enum: ["insufficient", "developing", "established", "mature"], description: "Filter by maturity level" },
            role: { type: "string", description: "Filter by agent role" },
          },
        },
      },
      // -- Policy testing tool (v0.8.0) -----------------------------------------
      {
        name: "atlas_test_policy",
        description:
          "Run policy regression tests against known malicious/benign fixtures. " +
          "Returns pass/fail counts and details of any failures. Use after rule changes to verify no regressions.",
        inputSchema: {
          type: "object" as const,
          properties: {
            verbose: { type: "boolean", description: "Include all results, not just failures (default: false)" },
          },
        },
      },
      // -- Break-glass tools (v0.8.0) ------------------------------------------
      {
        name: "atlas_break_glass_activate",
        description:
          "Activate a break-glass emergency override. Bypasses Telegram for 'ask' verdicts (hard-deny rules are NEVER bypassed). " +
          "Requires operator confirmation via Telegram. Use only when Telegram is expected to become unreachable.",
        inputSchema: {
          type: "object" as const,
          properties: {
            reason: { type: "string", description: "Why break-glass is needed" },
            ttl_minutes: { type: "number", description: "Token lifetime in minutes (default: 60, max: 240)" },
            max_requests: { type: "number", description: "Max auto-approved requests (0 = unlimited, default: 0)" },
          },
          required: ["reason"],
        },
      },
      {
        name: "atlas_break_glass_status",
        description: "Check current break-glass status.",
        inputSchema: { type: "object" as const, properties: {} },
      },
      {
        name: "atlas_break_glass_revoke",
        description: "Revoke an active break-glass token immediately.",
        inputSchema: { type: "object" as const, properties: {} },
      },
      // -- Audit rotation tools (v0.8.0) --------------------------------------
      {
        name: "atlas_audit_rotate",
        description: "Manually trigger audit log rotation. Archives the current log and starts a new one.",
        inputSchema: { type: "object" as const, properties: {} },
      },
      {
        name: "atlas_audit_archives",
        description: "List archived audit log files with metadata, or verify archive integrity.",
        inputSchema: {
          type: "object" as const,
          properties: {
            verify: { type: "boolean", description: "Verify integrity of all archives (default: false)" },
          },
        },
      },
      // -- Why Layer tool (v0.6.0) --------------------------------------------
      {
        name: "atlas_why_assess",
        description:
          "Manually trigger a Why Layer assessment on the current audit event window. Returns a CoE analysis with anomaly detection, intent inference, and threat narrative.",
        inputSchema: {
          type: "object" as const,
          properties: {
            agent_id: { type: "string", description: "Filter to specific agent (optional)" },
            window_minutes: { type: "number", description: "Time window in minutes (default: 60)" },
            window_size: { type: "number", description: "Max entries to analyze (default: 20)" },
          },
        },
      },
    ],
  }));

  // =========================================================================
  // MCP Tool handlers
  // =========================================================================

  mcp.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      // -- Existing tools ---------------------------------------------------

      case "atlas_reply": {
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
      }

      case "atlas_audit_verify": {
        const result = audit.verify();
        const lines = [
          result.valid ? "✅ Audit log integrity verified." : "❌ Audit log integrity FAILED:",
        ];
        if (!result.valid) lines.push(...result.errors);
        lines.push("", `Entries: ${result.stats.total_entries}`);
        lines.push(`ML-DSA-65 signed: ${result.stats.pq_signed}`);
        lines.push(`HMAC signed: ${result.stats.hmac_signed}`);
        if (result.stats.legacy_sha256 > 0) lines.push(`Legacy SHA-256 entries: ${result.stats.legacy_sha256}`);
        return { content: [{ type: "text" as const, text: lines.join("\n") }] };
      }

      case "atlas_status": {
        const telegramStatus = telegram.getStatus();
        const signerStatus = signer.getStatus();
        const status = {
          version: VERSION,
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
            session_agent_id: sessionAgentId || null,
            registry_size: registry.size,
            active_credentials: registry.list("active").length,
            bootstrap_mode: registry.isEmpty(),
            ...(sessionAgentId && registry.get(sessionAgentId)
              ? credentialTimeRemaining(registry.get(sessionAgentId)!.expiresAt)
              : {}),
          },
          data_dir: config.data_dir,
          quiet_mode: {
            enabled: quietConfig.enabled,
            min_maturity: quietConfig.min_maturity,
            quiet_tools: Array.from(quietConfig.quiet_tools),
          },
          break_glass: breakGlass.getStatus(),
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
      }

      // -- Identity management tools (v0.5.0) --------------------------------

      case "atlas_identity_register": {
        const regName = args?.name as string;
        const role = args?.role as AgentRole;
        const capabilities = args?.capabilities as AgentCapability[];
        const ttlHours = typeof args?.ttl_hours === "number" ? args.ttl_hours : undefined;

        if (!regName || !role || !capabilities || !Array.isArray(capabilities)) {
          return { content: [{ type: "text" as const, text: "Error: name, role, and capabilities are required" }], isError: true };
        }
        if (!VALID_ROLES.includes(role)) {
          return { content: [{ type: "text" as const, text: `Error: invalid role '${role}'. Valid: ${VALID_ROLES.join(", ")}` }], isError: true };
        }
        for (const cap of capabilities) {
          if (!VALID_CAPABILITIES.includes(cap)) {
            return { content: [{ type: "text" as const, text: `Error: invalid capability '${cap}'. Valid: ${VALID_CAPABILITIES.join(", ")}` }], isError: true };
          }
        }

        // Auth check: bootstrap (empty registry) or caller has identity:register
        const isBootstrap = registry.isEmpty();
        if (!isBootstrap) {
          if (!sessionAgentId) {
            return { content: [{ type: "text" as const, text: "Error: no active session agent. Register fails — bootstrap already complete." }], isError: true };
          }
          const callerCred = registry.get(sessionAgentId);
          if (!callerCred || !callerCred.capabilities.includes("identity:register")) {
            return { content: [{ type: "text" as const, text: "Error: active agent lacks identity:register capability" }], isError: true };
          }
        }

        // Bootstrap confirmation: two-channel verification via console + Telegram
        // Generates a code printed to server console, operator confirms via Telegram
        // Skip if ATLAS_BOOTSTRAP_SKIP_CONFIRM=true (dev/testing only — logged as warning)
        const skipBootstrapConfirm = process.env.ATLAS_BOOTSTRAP_SKIP_CONFIRM === "true";
        if (isBootstrap && config.telegram_bot_token && !skipBootstrapConfirm) {
          const confirmCode = randomBytes(3).toString("hex").toUpperCase(); // 6 hex chars
          const confirmTimeoutMs = 120_000; // 2 minutes

          // Print code to server console (requires physical/SSH access to see)
          console.log("");
          console.log("╔══════════════════════════════════════════════════════════════╗");
          console.log("║  ATLAS BOOTSTRAP CONFIRMATION                               ║");
          console.log("║                                                              ║");
          console.log(`║  Code: ${confirmCode}                                            ║`);
          console.log("║                                                              ║");
          console.log("║  Send this code via Telegram to confirm first registration.  ║");
          console.log("║  Timeout: 120 seconds                                        ║");
          console.log("╚══════════════════════════════════════════════════════════════╝");
          console.log("");

          // Send challenge to Telegram
          const challengeMsg =
            `🔐 <b>BOOTSTRAP CONFIRMATION REQUIRED</b>\n\n` +
            `A first-time agent registration was requested:\n` +
            `<b>Name:</b> <code>${escapeHtml(regName)}</code>\n` +
            `<b>Role:</b> <code>${escapeHtml(role)}</code>\n` +
            `<b>Capabilities:</b> ${capabilities.length}\n\n` +
            `To confirm, reply with the 6-character code shown on the server console.\n` +
            `⏱ Auto-deny in 120 seconds.`;

          try {
            await telegram.sendReply(challengeMsg, { broadcast: true });
          } catch {
            // Telegram send failed — fall through to deny
            return { content: [{ type: "text" as const, text: "Error: could not send bootstrap confirmation to Telegram. Ensure Telegram is configured." }], isError: true };
          }

          // Wait for the operator to send the confirmation code
          const confirmed = await new Promise<boolean>((resolve) => {
            const timer = setTimeout(() => {
              cleanup();
              resolve(false);
            }, confirmTimeoutMs);

            const handler = (msg: import("./telegram.js").IncomingMessage) => {
              if (msg.text.trim().toUpperCase() === confirmCode) {
                cleanup();
                resolve(true);
              }
            };

            function cleanup() {
              clearTimeout(timer);
              // Remove the handler — we only need it once
              const idx = (telegram as any).messageHandlers?.indexOf(handler) ?? -1;
              if (idx >= 0) (telegram as any).messageHandlers.splice(idx, 1);
            }

            telegram.onMessage(handler);
          });

          if (!confirmed) {
            audit.log("POLICY_DENY", {
              meta: {
                event_detail: "BOOTSTRAP_CONFIRMATION_TIMEOUT",
                agent_name: regName,
                agent_role: role,
              },
            });
            await telegram.sendReply("❌ Bootstrap confirmation timed out or code not matched. Registration denied.", { broadcast: true }).catch(() => {});
            return { content: [{ type: "text" as const, text: "Error: bootstrap confirmation timed out. The 6-character code was not confirmed via Telegram within 120 seconds." }], isError: true };
          }

          // Confirmation succeeded
          await telegram.sendReply("✅ Bootstrap confirmation verified. Registering first agent credential...", { broadcast: true }).catch(() => {});
          console.log("[atlas] Bootstrap confirmation verified via Telegram.");
        }

        if (isBootstrap && skipBootstrapConfirm) {
          console.warn("[atlas] WARNING: Bootstrap confirmation skipped (ATLAS_BOOTSTRAP_SKIP_CONFIRM=true)");
          audit.log("CONFIG_LOADED", {
            meta: { event_detail: "BOOTSTRAP_CONFIRM_SKIPPED", warning: "Two-channel verification bypassed by env var" },
          });
        }

        try {
          const credential = registry.register({ name: regName, role, capabilities, ttlHours });
          sessionAgentId = credential.agentId;

          audit.log("CONFIG_LOADED", {
            meta: {
              event_detail: "AGENT_REGISTERED",
              agent_id: credential.agentId,
              agent_name: credential.name,
              agent_role: credential.role,
              capabilities: credential.capabilities,
              expires_at: credential.expiresAt,
              bootstrap_confirmed: isBootstrap,
            },
          });

          const safe = sanitizeCredential(credential);
          return { content: [{ type: "text" as const, text: JSON.stringify(safe, null, 2) }] };
        } catch (error) {
          return { content: [{ type: "text" as const, text: `Error: ${(error as Error).message}` }], isError: true };
        }
      }

      case "atlas_identity_verify": {
        const verifyId = args?.agent_id as string;
        if (!verifyId) {
          return { content: [{ type: "text" as const, text: "Error: agent_id is required" }], isError: true };
        }
        const result = registry.verify(verifyId);
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      }

      case "atlas_identity_list": {
        const filter = (args?.filter as "active" | "revoked" | "expired" | "all") || "active";
        const credentials = registry.list(filter).map((c) => ({
          ...sanitizeCredential(c),
          ...credentialTimeRemaining(c.expiresAt),
        }));
        return { content: [{ type: "text" as const, text: JSON.stringify(credentials, null, 2) }] };
      }

      case "atlas_identity_revoke": {
        const revokeId = args?.agent_id as string;
        const reason = args?.reason as string;
        if (!revokeId || !reason) {
          return { content: [{ type: "text" as const, text: "Error: agent_id and reason are required" }], isError: true };
        }

        const success = registry.revoke(revokeId, reason);
        if (!success) {
          return { content: [{ type: "text" as const, text: `Error: agent ${revokeId} not found` }], isError: true };
        }

        // Clear session agent if it was revoked
        if (sessionAgentId === revokeId) {
          sessionAgentId = undefined;
        }

        audit.log("CONFIG_LOADED", {
          meta: {
            event_detail: "AGENT_REVOKED",
            agent_id: revokeId,
            reason,
          },
        });

        return { content: [{ type: "text" as const, text: `Agent ${revokeId} revoked: ${reason}` }] };
      }

      // -- Delegation tools (v0.6.0) ------------------------------------------

      case "atlas_identity_delegate": {
        const parentId = args?.parent_agent_id as string;
        const childName = args?.child_name as string;
        const childRole = args?.child_role as AgentRole;
        const caps = args?.capabilities as AgentCapability[];
        const ttlHours = typeof args?.ttl_hours === "number" ? args.ttl_hours : undefined;

        if (!parentId || !childName || !childRole || !caps || !Array.isArray(caps)) {
          return { content: [{ type: "text" as const, text: "Error: parent_agent_id, child_name, child_role, and capabilities are required" }], isError: true };
        }

        try {
          const delegationReq: DelegationRequest = {
            parentAgentId: parentId,
            childName,
            childRole,
            capabilities: caps,
            ttlHours,
          };
          const child = registry.delegate(delegationReq);

          audit.log("CONFIG_LOADED", {
            meta: {
              event_detail: "AGENT_DELEGATED",
              parent_agent_id: parentId,
              child_agent_id: child.agentId,
              child_name: child.name,
              child_role: child.role,
              capabilities: child.capabilities,
              delegation_depth: isDelegatedCredential(child) ? child.delegation.depth : 0,
              expires_at: child.expiresAt,
            },
          });

          const safe = sanitizeCredential(child);
          return { content: [{ type: "text" as const, text: JSON.stringify(safe, null, 2) }] };
        } catch (error) {
          return { content: [{ type: "text" as const, text: `Error: ${(error as Error).message}` }], isError: true };
        }
      }

      case "atlas_identity_cascade_revoke": {
        const cascadeParentId = args?.parent_agent_id as string;
        const cascadeReason = args?.reason as string;

        if (!cascadeParentId || !cascadeReason) {
          return { content: [{ type: "text" as const, text: "Error: parent_agent_id and reason are required" }], isError: true };
        }

        // Revoke the parent itself first
        const parentRevoked = registry.revoke(cascadeParentId, cascadeReason);
        if (!parentRevoked) {
          return { content: [{ type: "text" as const, text: `Error: agent ${cascadeParentId} not found` }], isError: true };
        }

        // Cascade to descendants
        const revokedIds = registry.cascadeRevoke(cascadeParentId, cascadeReason);

        // Clear session agent if revoked
        if (sessionAgentId === cascadeParentId || revokedIds.includes(sessionAgentId || "")) {
          sessionAgentId = undefined;
        }

        audit.log("CONFIG_LOADED", {
          meta: {
            event_detail: "CASCADE_REVOCATION",
            parent_agent_id: cascadeParentId,
            reason: cascadeReason,
            revoked_count: revokedIds.length + 1,
            revoked_ids: [cascadeParentId, ...revokedIds],
          },
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              revokedCount: revokedIds.length + 1,
              revokedIds: [cascadeParentId, ...revokedIds],
            }, null, 2),
          }],
        };
      }

      case "atlas_identity_tree": {
        const treeRootId = args?.agent_id as string;
        if (!treeRootId) {
          return { content: [{ type: "text" as const, text: "Error: agent_id is required" }], isError: true };
        }

        const rootCred = registry.get(treeRootId);
        if (!rootCred) {
          return { content: [{ type: "text" as const, text: `Error: agent ${treeRootId} not found` }], isError: true };
        }

        const children = registry.getChildren(treeRootId).map(sanitizeCredential);
        const descendants = registry.getDescendants(treeRootId).map(sanitizeCredential);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              root: sanitizeCredential(rootCred),
              children,
              descendants,
            }, null, 2),
          }],
        };
      }

      // -- Why Layer tool (v0.6.0) --------------------------------------------

      // -- Baseline tools (v0.7.0) ------------------------------------------

      case "atlas_baseline_get": {
        const baselineAgentId = args?.agent_id as string;
        if (!baselineAgentId) {
          return { content: [{ type: "text" as const, text: "Error: agent_id is required" }], isError: true };
        }
        const profile = await baselineStore.get(baselineAgentId);
        if (!profile) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ error: "NO_BASELINE", message: `No baseline exists for ${baselineAgentId}` }) }] };
        }
        // Omit internal _riskScores for external display
        const { _riskScores, ...display } = profile;
        return { content: [{ type: "text" as const, text: JSON.stringify(display, null, 2) }] };
      }

      case "atlas_baseline_drift": {
        const driftAgentId = args?.agent_id as string;
        if (!driftAgentId) {
          return { content: [{ type: "text" as const, text: "Error: agent_id is required" }], isError: true };
        }
        const driftBaseline = await baselineStore.get(driftAgentId);
        if (!driftBaseline) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ driftDetected: false, recommendation: "allow", note: "No baseline exists for this agent" }, null, 2) }] };
        }
        if (driftBaseline.maturityLevel === "insufficient") {
          return { content: [{ type: "text" as const, text: JSON.stringify({ driftDetected: false, recommendation: "allow", note: "Baseline insufficient — need 10+ sessions" }, null, 2) }] };
        }

        const driftWindowMin = typeof args?.window_minutes === "number" ? args.window_minutes : 60;
        let driftEntries = [...recentAuditEntries]
          .filter((e) => e.agentId === driftAgentId)
          .filter((e) => new Date(e.timestamp) >= new Date(Date.now() - driftWindowMin * 60 * 1000));

        // Use a synthetic expert assessment from the window's risk score
        const avgRisk = driftEntries.length > 0
          ? driftEntries.reduce((sum, e) => {
              const flags = (e.policy_result?.anomaly_flags ?? []).length;
              return sum + Math.min(100, flags * 10);
            }, 0) / driftEntries.length
          : 0;

        const syntheticExpert: import("./why-engine.js").ExpertAssessment = {
          expert: "anomaly",
          finding: "Synthetic assessment for drift detection",
          confidence: "medium",
          signals: [],
          riskScore: Math.round(avgRisk),
        };

        const driftResult = detectDrift(driftEntries, syntheticExpert, driftBaseline);
        return { content: [{ type: "text" as const, text: JSON.stringify(driftResult, null, 2) }] };
      }

      case "atlas_baseline_list": {
        const matFilter = args?.maturity as string | undefined;
        const roleFilter = args?.role as string | undefined;
        const allBaselines = await baselineStore.list({
          maturity: matFilter as any,
          role: roleFilter,
        });
        // Return summary fields only — omit whyHistory and _riskScores for size
        const summaries = allBaselines.map(({ whyHistory, _riskScores, ...rest }) => rest);
        return { content: [{ type: "text" as const, text: JSON.stringify(summaries, null, 2) }] };
      }

      case "atlas_test_policy": {
        const verbose = Boolean(args?.verbose);
        const report = runPolicyTests(config);

        const lines: string[] = [];
        if (report.failed === 0) {
          lines.push(`✅ All ${report.totalFixtures} policy fixtures passed (${report.totalRules} rules)`);
        } else {
          lines.push(`❌ ${report.failed}/${report.totalFixtures} fixtures FAILED (${report.totalRules} rules)`);
          lines.push("");
          for (const f of report.failures) {
            lines.push(`  FAIL: [${f.tool}] "${f.input}" — expected ${f.expected}, got ${f.actual}` +
              (f.matchedRule ? ` (rule: ${f.matchedRule})` : " (no rule matched)"));
          }
        }
        lines.push("");
        lines.push(`Malicious: ${report.summary.malicious.passed}/${report.summary.malicious.total}`);
        lines.push(`Benign:    ${report.summary.benign.passed}/${report.summary.benign.total}`);
        lines.push(`Ask:       ${report.summary.ask.passed}/${report.summary.ask.total}`);
        lines.push(`Edge:      ${report.summary.edge.passed}/${report.summary.edge.total}`);
        lines.push(`Pass rate: ${report.passRate}`);

        if (verbose) {
          return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
        }

        return { content: [{ type: "text" as const, text: lines.join("\n") }] };
      }

      case "atlas_break_glass_activate": {
        const bgReason = args?.reason as string;
        const bgTtl = typeof args?.ttl_minutes === "number" ? args.ttl_minutes : 60;
        const bgMaxReq = typeof args?.max_requests === "number" ? args.max_requests : 0;

        if (!bgReason) {
          return { content: [{ type: "text" as const, text: "Error: reason is required" }], isError: true };
        }

        // Require Telegram confirmation before activating (if Telegram is available)
        if (config.telegram_bot_token) {
          const bgConfirmCode = randomBytes(3).toString("hex").toUpperCase();

          console.log("");
          console.log(`[atlas] BREAK-GLASS ACTIVATION CODE: ${bgConfirmCode}`);
          console.log(`[atlas] Send this code via Telegram to confirm (120s timeout).`);
          console.log("");

          try {
            await telegram.sendReply(
              `⚠️ <b>BREAK-GLASS ACTIVATION REQUEST</b>\n\n` +
              `Reason: ${escapeHtml(bgReason)}\n` +
              `TTL: ${bgTtl} minutes\n` +
              `Max requests: ${bgMaxReq || "unlimited"}\n\n` +
              `Reply with the 6-character code from the server console to confirm.`,
              { broadcast: true }
            );

            const bgConfirmed = await new Promise<boolean>((resolve) => {
              const timer = setTimeout(() => { bgCleanup(); resolve(false); }, 120_000);
              const handler = (msg: import("./telegram.js").IncomingMessage) => {
                if (msg.text.trim().toUpperCase() === bgConfirmCode) {
                  bgCleanup(); resolve(true);
                }
              };
              function bgCleanup() {
                clearTimeout(timer);
                const idx = (telegram as any).messageHandlers?.indexOf(handler) ?? -1;
                if (idx >= 0) (telegram as any).messageHandlers.splice(idx, 1);
              }
              telegram.onMessage(handler);
            });

            if (!bgConfirmed) {
              return { content: [{ type: "text" as const, text: "Error: break-glass activation not confirmed. Code not matched within 120 seconds." }], isError: true };
            }
          } catch {
            // Telegram send failed — this is the exact scenario break-glass is for.
            // Allow activation without Telegram confirmation if Telegram is down.
            console.warn("[atlas] Telegram unreachable — activating break-glass without Telegram confirmation.");
          }
        }

        const { token, secret } = breakGlass.create(bgReason, bgTtl, bgMaxReq);

        console.log("");
        console.log("╔══════════════════════════════════════════════════════╗");
        console.log("║  BREAK-GLASS TOKEN ACTIVATED                        ║");
        console.log(`║  Expires: ${token.expires_at}        ║`);
        console.log(`║  Reason: ${bgReason.slice(0, 44).padEnd(44)}║`);
        console.log("╚══════════════════════════════════════════════════════╝");
        console.log("");

        audit.log("CONFIG_LOADED", {
          meta: {
            event_detail: "BREAK_GLASS_ACTIVATED",
            reason: bgReason,
            expires_at: token.expires_at,
            ttl_minutes: bgTtl,
            max_requests: bgMaxReq,
            token_hash: token.token_hash.slice(0, 16) + "...",
          },
        });

        await telegram.sendReply(
          `🔓 <b>BREAK-GLASS ACTIVATED</b>\n` +
          `Reason: ${escapeHtml(bgReason)}\n` +
          `Expires: ${escapeHtml(token.expires_at)}\n` +
          `Ask verdicts will be auto-approved. Hard-deny rules remain enforced.`,
          { broadcast: true }
        ).catch(() => {});

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              activated: true,
              expires_at: token.expires_at,
              reason: bgReason,
              ttl_minutes: bgTtl,
              max_requests: bgMaxReq,
              note: "Hard-deny rules are NEVER bypassed. Only 'ask' verdicts are auto-approved.",
            }, null, 2),
          }],
        };
      }

      case "atlas_break_glass_status": {
        const bgStatus = breakGlass.getStatus();
        return { content: [{ type: "text" as const, text: JSON.stringify(bgStatus, null, 2) }] };
      }

      case "atlas_break_glass_revoke": {
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
      }

      case "atlas_audit_rotate": {
        const currentSize = auditRotation.currentSize();
        const rotResult = auditRotation.rotate();
        if (!rotResult) {
          return { content: [{ type: "text" as const, text: "No audit log to rotate (empty or missing)." }] };
        }

        audit.log("CONFIG_LOADED", {
          meta: {
            event_detail: "AUDIT_LOG_ROTATED",
            archived_as: rotResult.record.rotated_name,
            entry_count: rotResult.record.entry_count,
            size_bytes: rotResult.record.size_bytes,
          },
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              rotated: true,
              archived_as: rotResult.record.rotated_name,
              entries: rotResult.record.entry_count,
              size_mb: (rotResult.record.size_bytes / 1024 / 1024).toFixed(2),
              chain_anchor: rotResult.chainAnchor.slice(0, 16) + "...",
            }, null, 2),
          }],
        };
      }

      case "atlas_audit_archives": {
        const doVerify = Boolean(args?.verify);

        if (doVerify) {
          const verification = auditRotation.verifyArchives();
          const stats = auditRotation.getStats();
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                ...verification,
                ...stats,
                total_size_mb: (stats.total_size_bytes / 1024 / 1024).toFixed(2),
              }, null, 2),
            }],
          };
        }

        const archives = auditRotation.listArchives();
        const stats = auditRotation.getStats();
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              ...stats,
              total_size_mb: (stats.total_size_bytes / 1024 / 1024).toFixed(2),
              archives: archives.map((a) => ({
                name: a.rotated_name,
                entries: a.entry_count,
                size_mb: (a.size_bytes / 1024 / 1024).toFixed(2),
                rotated_at: a.rotated_at,
              })),
            }, null, 2),
          }],
        };
      }

      case "atlas_why_assess": {
        const whyAgentId = args?.agent_id as string | undefined;
        const windowMin = typeof args?.window_minutes === "number" ? args.window_minutes : whyConfig.windowMinutes;
        const windowSz = typeof args?.window_size === "number" ? args.window_size : whyConfig.windowSize;

        // Build event window from recent entries
        let windowEntries = [...recentAuditEntries];
        if (whyAgentId) {
          windowEntries = windowEntries.filter((e) => e.agentId === whyAgentId);
        }
        const cutoff = new Date(Date.now() - windowMin * 60 * 1000);
        windowEntries = windowEntries.filter((e) => new Date(e.timestamp) >= cutoff);
        windowEntries = windowEntries.slice(-windowSz);

        const window: AuditEventWindow = {
          entries: windowEntries,
          agentId: whyAgentId,
          windowMinutes: windowMin,
        };

        // Load baseline for enrichment
        const whyBaseline = whyAgentId
          ? await baselineStore.get(whyAgentId)
          : undefined;

        const assessment = await assessWindow(window, whyConfig, whyBaseline ?? undefined);
        lastWhyAssessmentTime = new Date();

        // Ingest assessment into baseline
        if (whyAgentId) {
          baselineIngestAssessment(whyAgentId, assessment, "MANUAL", baselineStore).catch(() => {});
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(assessment, null, 2),
          }],
        };
      }

      default:
        return { content: [{ type: "text" as const, text: `Unknown tool: ${name}` }], isError: true };
    }
  });

  // =========================================================================
  // Why Layer integration — track entries and auto-trigger
  // =========================================================================

  // Wrap audit.log to auto-track entries for the Why Layer
  const _originalAuditLog = audit.log.bind(audit);
  audit.log = (...args: Parameters<typeof audit.log>): AuditEntry => {
    const entry = _originalAuditLog(...args);
    trackAndTriggerWhy(entry);
    return entry;
  };

  function trackAndTriggerWhy(entry: AuditEntry): void {
    recentAuditEntries.push(entry);
    // Keep window bounded
    if (recentAuditEntries.length > whyConfig.windowSize * 2) {
      recentAuditEntries.splice(0, recentAuditEntries.length - whyConfig.windowSize);
    }

    // Fire-and-forget baseline ingest — never block the gatekeeper
    baselineIngestEntry(entry, baselineStore).catch(() => {});

    // Check if audit log needs rotation (non-blocking, fire-and-forget)
    if (auditRotation.needsRotation()) {
      try {
        const rotResult = auditRotation.rotate();
        if (rotResult) {
          console.log(`[atlas] Audit log rotated: ${rotResult.record.rotated_name} (${rotResult.record.entry_count} entries, ${(rotResult.record.size_bytes / 1024 / 1024).toFixed(1)}MB)`);
          // The AuditLogger will naturally start a new chain — its prevHash
          // will be computed from the last entry it wrote (before the file was moved).
          // The new file's first entry will reference the old chain via prev_hash.
        }
      } catch (err) {
        console.error("[atlas] Audit rotation failed:", err);
      }
    }

    // Check if Why Layer should trigger (non-blocking)
    const trigger = shouldTrigger(entry, recentAuditEntries, triggerConfig, lastWhyAssessmentTime);
    if (trigger && whyConfig.enabled) {
      const window: AuditEventWindow = {
        entries: [...recentAuditEntries].slice(-whyConfig.windowSize),
        agentId: entry.agentId,
      };

      // Load baseline for this agent, then assess with it
      const agentId = entry.agentId;
      const baselinePromise = agentId
        ? baselineStore.get(agentId)
        : Promise.resolve(undefined);

      // Fire and forget — never block the gatekeeper
      baselinePromise
        .then((baseline) => assessWindow(window, whyConfig, baseline ?? undefined))
        .then((assessment) => {
          lastWhyAssessmentTime = new Date();
          // Ingest assessment into baseline (fire-and-forget)
          if (agentId) {
            baselineIngestAssessment(agentId, assessment, trigger, baselineStore).catch(() => {});
          }
          // Send enriched Telegram alert
          const alertMsg = formatTelegramAlert(assessment, entry);
          telegram.sendReply(alertMsg, { broadcast: true }).catch(() => {});
        })
        .catch(() => {
          // Why Layer failure is non-fatal
        });
    }
  }

  // =========================================================================
  // Permission request handler (with attestation)
  // =========================================================================

  mcp.setNotificationHandler(PermissionRequestSchema, async ({ params }) => {
    const req: PermissionRequest = {
      request_id: params.request_id,
      tool_name: params.tool_name,
      description: params.description,
      input_preview: params.input_preview,
    };

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

      sendVerdict(mcp, req.request_id, "deny");
      return;
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

      sendVerdict(mcp, req.request_id, "deny");
      return;
    }

    if (policyResult.verdict === "allow") {
      audit.log("POLICY_ALLOW", {
        permission: req,
        policy_result: policyResult,
        verdict: "allow",
        meta: identityMeta,
      });

      sendVerdict(mcp, req.request_id, "allow");
      return;
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

        sendVerdict(mcp, req.request_id, "allow");
        return;
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

      sendVerdict(mcp, req.request_id, "allow");
      return;
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
      sendVerdict(mcp, req.request_id, "allow");
      return;
    }

    if (outcome.decision === "deny") {
      audit.log("HUMAN_DENY", {
        permission: req,
        policy_result: policyResult,
        verdict: "deny",
        meta: { responder_chat_id: outcome.responder_chat_id, ...identityMeta },
      });
      sendVerdict(mcp, req.request_id, "deny");
      return;
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
    sendVerdict(mcp, req.request_id, "deny");
  });

  // =========================================================================
  // Telegram message bridge
  // =========================================================================

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
        console.error("[atlas] Failed to emit channel notification:", err);
      });
  });

  // =========================================================================
  // =========================================================================
  // TTL Expiry Watchdog — proactive Telegram warnings before credentials expire
  // =========================================================================

  const TTL_CHECK_INTERVAL_MS = 5 * 60_000; // check every 5 minutes
  const TTL_WARNING_THRESHOLD = 0.80; // warn at 80% of TTL elapsed
  const warnedCredentials = new Set<string>(); // track already-warned agentIds
  const expiredNotified = new Set<string>(); // track already-notified expirations

  const ttlWatchdog = setInterval(() => {
    const now = Date.now();

    for (const cred of registry.list("all")) {
      if (cred.revoked) continue;
      const expiresAtMs = new Date(cred.expiresAt).getTime();
      const issuedAtMs = new Date(cred.issuedAt).getTime();
      const totalTtlMs = expiresAtMs - issuedAtMs;
      const elapsedMs = now - issuedAtMs;
      const remainingMs = expiresAtMs - now;

      // Already expired — send one-time expiry notification
      if (remainingMs <= 0) {
        if (!expiredNotified.has(cred.agentId)) {
          expiredNotified.add(cred.agentId);
          const { timeRemainingHuman } = credentialTimeRemaining(cred.expiresAt);
          telegram
            .sendReply(
              `⏰ <b>CREDENTIAL EXPIRED</b>\n` +
                `Agent: <code>${escapeHtml(cred.agentId)}</code>\n` +
                `Name: ${escapeHtml(cred.name)}\n` +
                `Expired at: ${escapeHtml(new Date(cred.expiresAt).toLocaleString())}\n` +
                `Action: re-register with <code>atlas_identity_register</code>`,
              { broadcast: true }
            )
            .catch(() => {});
          audit.log("CREDENTIAL_EXPIRED", {
            meta: { agentId: cred.agentId, name: cred.name, expiresAt: cred.expiresAt },
          });
        }
        continue;
      }

      // Approaching expiry — warn at 80% threshold
      if (totalTtlMs > 0 && elapsedMs / totalTtlMs >= TTL_WARNING_THRESHOLD) {
        if (!warnedCredentials.has(cred.agentId)) {
          warnedCredentials.add(cred.agentId);
          const { timeRemainingHuman } = credentialTimeRemaining(cred.expiresAt);
          telegram
            .sendReply(
              `⚠️ <b>CREDENTIAL EXPIRING SOON</b>\n` +
                `Agent: <code>${escapeHtml(cred.agentId)}</code>\n` +
                `Name: ${escapeHtml(cred.name)}\n` +
                `Time remaining: <b>${escapeHtml(timeRemainingHuman)}</b>\n` +
                `Expires at: ${escapeHtml(new Date(cred.expiresAt).toLocaleString())}\n` +
                `Action: re-register before expiry to avoid denial`,
              { broadcast: true }
            )
            .catch(() => {});
          audit.log("CREDENTIAL_EXPIRY_WARNING", {
            meta: {
              agentId: cred.agentId,
              name: cred.name,
              expiresAt: cred.expiresAt,
              timeRemainingMs: remainingMs,
              timeRemainingHuman,
            },
          });
        }
      }
    }
  }, TTL_CHECK_INTERVAL_MS);

  // Don't let the watchdog keep the process alive
  ttlWatchdog.unref();

  // Start
  // =========================================================================

  await telegram.start();

  const transport = new StdioServerTransport();
  await mcp.connect(transport);

  console.error(`[atlas] Atlas Protocol v${VERSION} active`);
  console.error(`[atlas] Telegram token: ${config.telegram_bot_token ? "configured" : "NOT configured"}`);
  console.error(
    `[atlas] Authorized chats: ${config.telegram_allowed_chat_ids.join(", ") || "none (locked until configured)"}`
  );
  console.error(`[atlas] Policy rules: ${config.policy_rules.length}`);
  console.error(`[atlas] Timeout: ${config.permission_timeout_seconds}s (fail-closed)`);
  console.error(`[atlas] Audit log: ${config.audit_log_path} (SHA3-256 chain)`);
  console.error(`[atlas] ML-DSA-65 signing: ${signer.available ? `active (key: ${signer.getPublicKeyHash()?.slice(0, 16)}...)` : "unavailable"}`);
  console.error(`[atlas] Agent registry: ${registry.size} credentials (${registry.isEmpty() ? "bootstrap mode" : "active"})`);
  console.error(`[atlas] Identity: ${identityContext.loaded ? `${identityContext.principal_label} (Tier ${identityContext.max_tier_present})` : "standalone (no briefcase)"}`);
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
      console.error("[atlas] Failed to send verdict:", err);
    });
}

/**
 * Compute time-remaining fields for a credential.
 */
function credentialTimeRemaining(expiresAt: string): { timeRemainingMs: number; timeRemainingHuman: string } {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return { timeRemainingMs: 0, timeRemainingHuman: "expired" };
  const hours = Math.floor(ms / 3_600_000);
  const minutes = Math.floor((ms % 3_600_000) / 60_000);
  if (hours > 0) return { timeRemainingMs: ms, timeRemainingHuman: `${hours}h ${minutes}m` };
  return { timeRemainingMs: ms, timeRemainingHuman: `${minutes}m` };
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

main().catch((err) => {
  console.error("[atlas] Fatal error:", err);
  process.exit(1);
});
