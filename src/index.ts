#!/usr/bin/env node

/**
 * Atlas Protocol — Claude Code Channels Plugin
 *
 * Telegram approval channel for Claude Code with:
 *   - agent identity attestation (ML-DSA-65 signed credentials)
 *   - fail-closed permission relay
 *   - configurable deny/ask/allow policy rules
 *   - tamper-evident audit logging (SHA3-256 chain + ML-DSA-65 signatures)
 *   - MITRE ATT&CK enrichment per audit entry
 *   - anomaly flagging for higher-risk tool requests
 */

import { ProtocolError, ProtocolErrorCode, Server, type JsonSchemaType } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { z } from "zod";
import { join } from "node:path";
import { loadConfig } from "./config.js";
import { PolicyEngine } from "./policy-engine.js";
import type { PermissionRequest } from "./policy-engine.js";
import { AuditLogger } from "./audit-log.js";
import type { AuditEntry } from "./audit-log.js";
import { TelegramBot } from "./telegram.js";
import { createIdentityProvider } from "./identity-provider.js";
import { IssuerKeyError, QuantumSigner } from "./quantum-signer.js";
import { IdentityRegistry } from "./identity-registry.js";
import { assessWindow, describeWhyEndpoint, loadWhyConfig } from "./why-engine.js";
import type { AuditEventWindow } from "./why-engine.js";
import { shouldTrigger, formatTelegramAlert, loadTriggerConfig } from "./why-triggers.js";
import { BaselineStore } from "./baseline-store.js";
import { ingestEntry as baselineIngestEntry, ingestAssessment as baselineIngestAssessment } from "./baseline-engine.js";
import { BreakGlassManager } from "./break-glass.js";
import { readOperatorPublicKey } from "./operator-key.js";
import { AttachManager } from "./identity-attach.js";
import type { OperatorPublicKey } from "./operator-key.js";
import { AuditRotationManager } from "./audit-rotation.js";
import { loadQuietConfig } from "./quiet-mode.js";
import { ProximityMesh, loadProximityConfig, createHardwareAdapters } from "./proximity/index.js";
import type { HardwareAdapterSet } from "./proximity/index.js";
import { PROTOCOL_VERSION } from "./protocol-version.js";
import { VERSION, SPEC_VERSION } from "./version.js";
import { credentialTimeRemaining } from "./mcp/helpers.js";
import { toolDefinitions, createToolHandlers } from "./mcp/tools/index.js";
import type { ToolContext } from "./mcp/context.js";
import { escapeHtml } from "./html.js";
import { createPermissionPipeline } from "./authority/permission-pipeline.js";
import { operatorPreviewPolicyFromEnv } from "./authority/operator-preview.js";
import { AgentKeyStore } from "./signer-provider.js";
import { checkIsolation } from "./isolation.js";


/** Claude Code channel permission relay (non-spec notification). */
const PERMISSION_REQUEST_METHOD = "notifications/claude/channel/permission_request";
const PermissionRequestParams = z.object({
  request_id: z.string(),
  tool_name: z.string(),
  description: z.string(),
  input_preview: z.string(),
});

async function main(): Promise<void> {
  const config = loadConfig();

  // Separate-user isolation self-check (#23)
  const isolation = checkIsolation({ dataDir: config.data_dir });
  if (process.env.ATLAS_REQUIRE_ISOLATION === "true" && !isolation.isolated) {
    console.error("[atlas] ATLAS_REQUIRE_ISOLATION=true but the gatekeeper is not isolated from the agent user:");
    for (const p of isolation.problems) console.error(`[atlas]   - ${p}`);
    console.error("[atlas] Refusing to start. See deploy/separate-user/README.md.");
    process.exit(1);
  }
  const identityProvider = createIdentityProvider(config.briefcase_path || undefined);
  const identityContext = identityProvider.getContext();
  const policyEngine = new PolicyEngine(config, identityContext);

  // Initialize ML-DSA-65 quantum signer. The issuer key is wrapped at rest
  // when a keystore passphrase is set (#45); if it can't be loaded, stop
  // rather than generate a new key that would invalidate every credential.
  let signer: QuantumSigner;
  try {
    signer = await QuantumSigner.create(config.data_dir, {
      passphrase: process.env.ATLAS_KEYSTORE_PASSPHRASE || undefined,
    });
  } catch (err) {
    if (!(err instanceof IssuerKeyError)) throw err;
    console.error(`[atlas] ${err.message}`);
    console.error("[atlas] Refusing to start without the issuer key.");
    process.exit(1);
  }

  // Agent key custody (#4): durable only with ATLAS_KEYSTORE_PASSPHRASE
  const agentKeys = await AgentKeyStore.open(config.data_dir, process.env.ATLAS_KEYSTORE_PASSPHRASE || undefined);
  if (!agentKeys.mode.durable && agentKeys.mode.reason !== "NO_PASSPHRASE") {
    console.error(`[atlas] Warning: agent keystore unavailable (${agentKeys.mode.reason}); agent keys will not survive a restart`);
  }

  // Initialize identity registry
  const registry = await IdentityRegistry.create(config.data_dir, signer, agentKeys);

  // Session-level active agent ID (set by atlas_identity_register)
  let sessionAgentId: string | undefined;

  // Baseline store
  const baselineStore = new BaselineStore(config.data_dir);

  // Break-glass manager
  // Operator public key: pinned for the life of this process (SPEC §9).
  // Optionally also pinned by key ID from the launch environment.
  let operatorKey: OperatorPublicKey | null = null;
  let operatorKeyError: string | undefined;
  try {
    operatorKey = readOperatorPublicKey(config.data_dir);
    const pinnedId = process.env.ATLAS_OPERATOR_KEY_ID?.trim();
    if (operatorKey && pinnedId && operatorKey.key_id !== pinnedId) {
      operatorKeyError = `operator key ${operatorKey.key_id} does not match ATLAS_OPERATOR_KEY_ID ${pinnedId}`;
      operatorKey = null;
    }
  } catch (err) {
    operatorKeyError = err instanceof Error ? err.message : String(err);
  }
  if (operatorKeyError) {
    console.error(`[atlas] Warning: break-glass disabled: ${operatorKeyError}`);
  }
  const breakGlass = await BreakGlassManager.open(config.data_dir, operatorKey);
  const identityAttach = await AttachManager.open(config.data_dir, operatorKey);

  // Quiet mode
  const quietConfig = loadQuietConfig();

  // Proximity Mesh (SPEC § 13)
  const proximityConfig = loadProximityConfig();
  // Hardware adapters are selected via ATLAS_HARDWARE_ADAPTER (or auto-detect)
  // on first proximity tool call. A failed selection is surfaced, never
  // silently replaced with mock drivers.
  let hardwarePromise: Promise<HardwareAdapterSet> | undefined;
  let hardwareError: string | undefined;
  const getHardware = (): Promise<HardwareAdapterSet> => {
    hardwarePromise ??= createHardwareAdapters().then(
      (hw) => {
        audit.log("PROXIMITY_HARDWARE_SELECTED", { meta: { adapter: hw.type, source: hw.source } });
        return hw;
      },
      (err: unknown) => {
        hardwareError = err instanceof Error ? err.message : String(err);
        audit.log("PROXIMITY_HARDWARE_ERROR", { meta: { error: hardwareError } });
        throw err;
      },
    );
    return hardwarePromise;
  };
  // ProximityMesh is initialized lazily on first proximity tool call
  let proximityMesh: ProximityMesh | undefined;
  const ensureProximityMesh = async (agentId: string): Promise<ProximityMesh> => {
    if (!proximityMesh) {
      const hw = await getHardware();
      proximityMesh = new ProximityMesh(agentId, {
        uwb: hw.uwb, ble: hw.ble, nfc: hw.nfc,
        signer, registry, audit, policy: policyEngine,
      }, proximityConfig);
    }
    return proximityMesh;
  };
  const proximityHardwareError = () => ({
    content: [{ type: "text" as const, text: `Proximity hardware unavailable: ${hardwareError}` }],
    isError: true,
  });

  // Audit log rotation
  const rotationMaxBytes = parseInt(process.env.ATLAS_AUDIT_MAX_SIZE_MB ?? "10", 10) * 1024 * 1024;
  const rotationMaxArchives = parseInt(process.env.ATLAS_AUDIT_MAX_ARCHIVES ?? "0", 10);
  const auditRotation = new AuditRotationManager(config.audit_log_path, {
    max_size_bytes: rotationMaxBytes,
    max_archives: rotationMaxArchives,
  });

  // Why Layer state
  const whyConfig = loadWhyConfig();
  const whyEndpoint = describeWhyEndpoint(whyConfig.baseUrl);
  if (whyConfig.enabled && whyEndpoint.warning) {
    console.error(`[atlas] Warning: ${whyEndpoint.warning}`);
  }
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
      protocol_version: PROTOCOL_VERSION,
      spec_version: SPEC_VERSION,
      telegram_configured: !!config.telegram_bot_token,
      allowed_chats: config.telegram_allowed_chat_ids.length,
      policy_rules: config.policy_rules.length,
      hmac_enabled: !!config.audit_hmac_secret,
      pq_signing: signer.available,
      pq_algorithm: signer.available ? "ML-DSA-65" : null,
      pq_public_key_hash: signer.getPublicKeyHash(),
      operator_key_id: operatorKey?.key_id ?? null,
      ...(operatorKeyError ? { operator_key_error: operatorKeyError } : {}),
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
      why_engine_endpoint: whyConfig.enabled
        ? { loopback: whyEndpoint.loopback, encrypted: whyEndpoint.encrypted }
        : null,
      ...(config.rejected_file_fields?.length
        ? { rejected_config_fields: config.rejected_file_fields }
        : {}),
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

  mcp.setRequestHandler("tools/list", async () => ({
    tools: toolDefinitions,
  }));

  // =========================================================================
  // MCP Tool handlers
  // =========================================================================

  const toolContext: ToolContext = {
    config,
    registry,
    signer,
    audit,
    telegram,
    identityContext,
    baselineStore,
    breakGlass,
    identityAttach,
    isolation,
    quietConfig,
    proximityConfig,
    getHardware,
    ensureProximityMesh,
    proximityHardwareError,
    auditRotation,
    whyConfig,
    recentAuditEntries,
    get sessionAgentId() { return sessionAgentId; },
    set sessionAgentId(v) { sessionAgentId = v; },
    get lastWhyAssessmentTime() { return lastWhyAssessmentTime; },
    set lastWhyAssessmentTime(v) { lastWhyAssessmentTime = v; },
    get proximityMesh() { return proximityMesh; },
    get hardwareError() { return hardwareError; },
  };
  const toolHandlers = createToolHandlers(toolContext);

  // Arguments are checked against each tool's inputSchema before dispatch (#7).
  const schemaValidator = new AjvJsonSchemaValidator();
  const argumentValidators = new Map(
    toolDefinitions.map((def) => [def.name, schemaValidator.getValidator(def.inputSchema as JsonSchemaType)]),
  );

  mcp.setRequestHandler("tools/call", async (request) => {
    const { name, arguments: args } = request.params;
    const handler = Object.hasOwn(toolHandlers, name) ? toolHandlers[name] : undefined;
    const validate = argumentValidators.get(name);
    if (!handler || !validate) {
      // MCP 2025-11-25: an unknown tool is a protocol error, not a tool result
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Unknown tool: ${name}`);
    }
    const checked = validate(args ?? {});
    if (!checked.valid) {
      // Input validation failures are tool execution errors, so the model can correct the call
      return {
        content: [{ type: "text" as const, text: `Invalid arguments for ${name}: ${checked.errorMessage}` }],
        isError: true,
      };
    }
    return handler(args);
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
          console.error(`[atlas] Audit log rotated: ${rotResult.record.rotated_name} (${rotResult.record.entry_count} entries, ${(rotResult.record.size_bytes / 1024 / 1024).toFixed(1)}MB)`);
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

  const decidePermission = createPermissionPipeline({
    registry,
    getSessionAgentId: () => sessionAgentId,
    policyEngine,
    audit,
    operator: telegram,
    baselineStore,
    quietConfig,
    breakGlass,
    config,
    previewPolicy: operatorPreviewPolicyFromEnv(),
  });

  mcp.setNotificationHandler(PERMISSION_REQUEST_METHOD, { params: PermissionRequestParams }, async (params) => {
    const req: PermissionRequest = {
      request_id: params.request_id,
      tool_name: params.tool_name,
      description: params.description,
      input_preview: params.input_preview,
    };
    sendVerdict(mcp, req.request_id, await decidePermission(req));
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

main().catch((err) => {
  console.error("[atlas] Fatal error:", err);
  process.exit(1);
});
