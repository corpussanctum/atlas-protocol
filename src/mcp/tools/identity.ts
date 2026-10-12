/**
 * Atlas Protocol — MCP tools: Agent credentials, delegation, issuer key rotation (SPEC §4)
 */

import { randomBytes } from "node:crypto";
import { attestAgent, sanitizeCredential } from "../../attestation.js";
import type { AgentRole, AgentCapability, DelegationRequest } from "../../agent-identity.js";
import { isDelegatedCredential } from "../../agent-identity.js";
import { PROTOCOL_VERSION } from "../../protocol-version.js";
import { VERSION, SPEC_VERSION } from "../../version.js";
import { escapeHtml } from "../../html.js";
import { writeConfirmCodeFile, clearConfirmCodeFile } from "../helpers.js";
import { credentialTimeRemaining } from "../helpers.js";
import type { Tool } from "@modelcontextprotocol/server";
import type { ToolContext, ToolHandler } from "../context.js";

const VALID_ROLES: AgentRole[] = ["claude-code", "orchestrator", "tool-caller", "observer", "admin"];
const VALID_CAPABILITIES: AgentCapability[] = [
  "file:read", "file:write", "file:delete",
  "shell:exec", "shell:read",
  "network:outbound", "network:inbound",
  "process:spawn", "process:kill",
  "credential:read", "audit:read",
  "identity:register", "identity:revoke",
];

export const definitions: Tool[] = [
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
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "atlas_identity_attach",
    description:
      "Re-bind this session to an existing credential after a server restart, using a one-time " +
      "attach token the operator issued with `atlas-operator attach --agent <did>`. Takes no arguments.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: false, destructiveHint: false },
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
    annotations: { readOnlyHint: true, destructiveHint: false },
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
    annotations: { readOnlyHint: true, destructiveHint: false },
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
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
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
    annotations: { readOnlyHint: false, destructiveHint: false },
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
    annotations: { readOnlyHint: false, destructiveHint: true },
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
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "atlas_key_rotate",
    description:
      "Rotate the gatekeeper ML-DSA-65 issuer key (SPEC §4.5). Logs KEY_ROTATION signed by the old key, " +
      "re-issues all active credentials with the new key, and retains the last 3 public keys for historical verification.",
    inputSchema: {
      type: "object" as const,
      properties: {
        reason: {
          type: "string",
          description: "Rotation reason (e.g. scheduled rotation, key compromise)",
        },
      },
      required: ["reason"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
];

export function handlers(ctx: ToolContext): Record<string, ToolHandler> {
  const { config, registry, signer, audit, telegram } = ctx;
  return {
    async atlas_identity_register(args) {
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
        if (!ctx.sessionAgentId) {
          return { content: [{ type: "text" as const, text: "Error: no active session agent. Register fails — bootstrap already complete." }], isError: true };
        }
        const callerCred = registry.get(ctx.sessionAgentId);
        if (!callerCred || !callerCred.capabilities.includes("identity:register")) {
          return { content: [{ type: "text" as const, text: "Error: active agent lacks identity:register capability" }], isError: true };
        }
      }

      // Bootstrap confirmation: two-channel verification per SPEC §4.6.
      // Channel 1: host (terminal stderr OR a 0600-mode file in data_dir).
      // Channel 2: Telegram operator relay (challenge + reply).
      // The code is NEVER sent over Telegram — that would collapse both
      // channels into one and defeat the threat model.
      // Skip if ATLAS_BOOTSTRAP_SKIP_CONFIRM=true (Development conformance only).
      const skipBootstrapConfirm = process.env.ATLAS_BOOTSTRAP_SKIP_CONFIRM === "true";
      if (isBootstrap && config.telegram_bot_token && !skipBootstrapConfirm) {
        const confirmCode = randomBytes(3).toString("hex").toUpperCase(); // 6 hex chars
        const confirmTimeoutMs = 120_000; // 2 minutes
        const codeFileName = "bootstrap-code.txt";
        const codeFilePath = writeConfirmCodeFile(config.data_dir, codeFileName, confirmCode);

        // Print code to STDERR (not stdout — stdout is the MCP JSON-RPC
        // channel when Atlas runs as a stdio child process). Operators with
        // a terminal will see this; operators with only filesystem access
        // can read the same code from `codeFilePath`.
        console.error("");
        console.error("╔══════════════════════════════════════════════════════════════╗");
        console.error("║  ATLAS BOOTSTRAP CONFIRMATION                                ║");
        console.error("║                                                              ║");
        console.error(`║  Code: ${confirmCode}                                                  ║`);
        console.error("║                                                              ║");
        console.error("║  Send this code via Telegram to confirm first registration.  ║");
        console.error("║  Timeout: 120 seconds                                        ║");
        console.error("╚══════════════════════════════════════════════════════════════╝");
        console.error(`[atlas] Code also written to: ${codeFilePath} (mode 0600, single-use)`);
        console.error("");

        // Send challenge to Telegram. Per SPEC §4.6, the code itself is NOT
        // included — the operator must obtain it from the host channel.
        const challengeMsg =
          `🔐 <b>BOOTSTRAP CONFIRMATION REQUIRED</b>\n\n` +
          `A first-time agent registration was requested:\n` +
          `<b>Name:</b> <code>${escapeHtml(regName)}</code>\n` +
          `<b>Role:</b> <code>${escapeHtml(role)}</code>\n` +
          `<b>Capabilities:</b> ${capabilities.length}\n\n` +
          `To confirm, reply with the 6-character code shown on the server ` +
          `console <b>or</b> read it from <code>${escapeHtml(codeFilePath)}</code> ` +
          `(host filesystem access required).\n` +
          `⏱ Auto-deny in 120 seconds.`;

        try {
          await telegram.sendReply(challengeMsg, { broadcast: true });
        } catch {
          // Telegram send failed — fall through to deny
          clearConfirmCodeFile(config.data_dir, codeFileName);
          return { content: [{ type: "text" as const, text: "Error: could not send bootstrap confirmation to Telegram. Ensure Telegram is configured." }], isError: true };
        }

        // Wait for the operator to send the confirmation code
        const confirmed = await new Promise<boolean>((resolve) => {
          const timer = setTimeout(() => {
            cleanup();
            resolve(false);
          }, confirmTimeoutMs);

          const handler = (msg: import("../../telegram.js").IncomingMessage) => {
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

        // Single-use: always clear the code file after the wait completes
        clearConfirmCodeFile(config.data_dir, codeFileName);

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
        console.error("[atlas] Bootstrap confirmation verified via Telegram.");
      }

      if (isBootstrap && skipBootstrapConfirm) {
        console.error("[atlas] WARNING: Bootstrap confirmation skipped (ATLAS_BOOTSTRAP_SKIP_CONFIRM=true)");
        audit.log("CONFIG_LOADED", {
          meta: { event_detail: "BOOTSTRAP_CONFIRM_SKIPPED", warning: "Two-channel verification bypassed by env var" },
        });
      }

      try {
        const credential = registry.register({ name: regName, role, capabilities, ttlHours });
        ctx.sessionAgentId = credential.agentId;

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
    },
    async atlas_identity_attach() {
      const current = ctx.sessionAgentId ? attestAgent(registry, ctx.sessionAgentId) : undefined;
      if (current && !current.denyReason) {
        return { content: [{ type: "text" as const, text: `Error: session is already bound to ${ctx.sessionAgentId}` }], isError: true };
      }

      const result = ctx.identityAttach.consume(registry);
      if ("rejected" in result) {
        if (result.rejected === "NO_TOKEN") {
          return {
            content: [{ type: "text" as const, text: "Error: no attach token. The operator issues one with `atlas-operator attach --agent <did>`." }],
            isError: true,
          };
        }
        audit.log("POLICY_DENY", {
          meta: { event_detail: "IDENTITY_ATTACH_REJECTED", reason: result.rejected, agent_id: result.agent_id ?? null },
        });
        return { content: [{ type: "text" as const, text: `Error: attach token rejected (${result.rejected}). It has been consumed; issue a new one.` }], isError: true };
      }

      const { token } = result;
      const previousAgentId = ctx.sessionAgentId ?? null;
      ctx.sessionAgentId = token.agent_id;
      const credential = registry.get(token.agent_id)!;
      audit.log("IDENTITY_ATTACHED", {
        meta: {
          agent_id: token.agent_id,
          credential_hash: token.credential_hash,
          operator_key_id: token.operator_key_id,
          token_nonce: token.nonce,
          token_created_at: token.created_at,
          previous_agent_id: previousAgentId,
        },
      });
      await telegram.sendReply(
        `🔗 Session attached to <code>${escapeHtml(credential.name)}</code> (operator-signed token).`,
        { broadcast: true },
      ).catch(() => {});

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            attached: true,
            ...sanitizeCredential(credential),
            ...credentialTimeRemaining(credential.expiresAt),
            note: "Delegation from this credential needs its secret key, which is not restored after a restart (#4).",
          }, null, 2),
        }],
      };
    },
    async atlas_identity_verify(args) {
      const verifyId = args?.agent_id as string;
      if (!verifyId) {
        return { content: [{ type: "text" as const, text: "Error: agent_id is required" }], isError: true };
      }
      const result = registry.verify(verifyId);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    },
    async atlas_identity_list(args) {
      const filter = (args?.filter as "active" | "revoked" | "expired" | "all") || "active";
      const credentials = registry.list(filter).map((c) => ({
        ...sanitizeCredential(c),
        ...credentialTimeRemaining(c.expiresAt),
      }));
      return { content: [{ type: "text" as const, text: JSON.stringify(credentials, null, 2) }] };
    },
    async atlas_identity_revoke(args) {
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
      if (ctx.sessionAgentId === revokeId) {
        ctx.sessionAgentId = undefined;
      }

      audit.log("CONFIG_LOADED", {
        meta: {
          event_detail: "AGENT_REVOKED",
          agent_id: revokeId,
          reason,
        },
      });

      return { content: [{ type: "text" as const, text: `Agent ${revokeId} revoked: ${reason}` }] };
    },
    async atlas_identity_delegate(args) {
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
    },
    async atlas_identity_cascade_revoke(args) {
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
      if (ctx.sessionAgentId === cascadeParentId || revokedIds.includes(ctx.sessionAgentId || "")) {
        ctx.sessionAgentId = undefined;
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
    },
    async atlas_identity_tree(args) {
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
    },
    async atlas_key_rotate(args) {
      const rotateReason = typeof args?.reason === "string" ? args.reason.trim() : "";
      if (!rotateReason) {
        return { content: [{ type: "text" as const, text: "Error: reason is required" }], isError: true };
      }
      if (!signer.available) {
        return { content: [{ type: "text" as const, text: "Error: quantum signer is not available" }], isError: true };
      }
      if (!registry.isEmpty()) {
        if (!ctx.sessionAgentId) {
          return { content: [{ type: "text" as const, text: "Error: no active agent — register an identity first" }], isError: true };
        }
        const callerCred = registry.get(ctx.sessionAgentId);
        if (!callerCred || (!callerCred.capabilities.includes("identity:register") && callerCred.role !== "admin")) {
          return { content: [{ type: "text" as const, text: "Error: active agent lacks identity:register capability or admin role" }], isError: true };
        }
      }

      try {
        const prepared = signer.beginRotation();
        const reissue = registry.reissueAllActive(prepared.newSecretKey);

        audit.log("KEY_ROTATION", {
          meta: {
            old_key_hash: prepared.oldKeyHashSha3,
            new_key_hash: prepared.newKeyHashSha3,
            new_public_key_b64: prepared.newPublicKeyB64,
            effective_at: prepared.effectiveAt,
            reason: rotateReason,
            credentials_reissued: reissue.reissued,
            reissue_success: reissue.failed === 0,
            ...(reissue.failed > 0 ? { reissue_failed_ids: reissue.failedIds } : {}),
          },
        });

        signer.commitRotation(prepared);
        registry.syncIssuerKeys();

        audit.log("SESSION_START", {
          meta: {
            version: VERSION,
            protocol_version: PROTOCOL_VERSION,
            spec_version: SPEC_VERSION,
            event_detail: "KEY_ROTATION_COMPLETE",
            pq_public_key_hash: signer.getPublicKeyHash(),
            pq_public_key_hash_sha3: signer.getPublicKeyHashSha3(),
            credentials_reissued: reissue.reissued,
            archived_key_count: signer.getArchivedPublicKeys().length,
          },
        });

        const summary = {
          rotated: true,
          old_key_hash_sha3: prepared.oldKeyHashSha3,
          new_key_hash_sha3: prepared.newKeyHashSha3,
          effective_at: prepared.effectiveAt,
          reason: rotateReason,
          credentials_reissued: reissue.reissued,
          reissue_success: reissue.failed === 0,
          archived_key_count: signer.getArchivedPublicKeys().length,
        };

        await telegram.sendReply(
          `🔑 <b>ISSUER KEY ROTATED</b>\n\n` +
          `<b>Reason:</b> ${escapeHtml(rotateReason)}\n` +
          `<b>New key hash (SHA3):</b> <code>${escapeHtml(prepared.newKeyHashSha3.slice(0, 16))}...</code>\n` +
          `<b>Credentials re-issued:</b> ${reissue.reissued}` +
          (reissue.failed > 0 ? `\n⚠️ Re-issue failures: ${reissue.failed}` : ""),
          { broadcast: true },
        ).catch(() => {});

        return { content: [{ type: "text" as const, text: JSON.stringify(summary, null, 2) }] };
      } catch (error) {
        return { content: [{ type: "text" as const, text: `Error: ${(error as Error).message}` }], isError: true };
      }
    },
  };
}
