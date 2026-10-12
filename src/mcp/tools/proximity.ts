/**
 * Atlas Protocol — MCP tools: ProximityMesh (SPEC §13; research/demo)
 */

import { ProximityMesh, loadProximityConfig, createHardwareAdapters, generateEphemeralKeypair } from "../../proximity/index.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ToolContext, ToolHandler } from "../context.js";

export const definitions: Tool[] = [
  {
    name: "atlas_proximity_status",
    description:
      "Get proximity mesh status: hardware availability, active sessions, advertising state, and configuration.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "atlas_proximity_scan",
    description: "Scan for nearby Atlas agents via BLE. Returns discovered peers with estimated distances.",
    inputSchema: {
      type: "object" as const,
      properties: {
        duration_ms: { type: "number", description: "Scan duration in milliseconds (default: 5000)" },
      },
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "atlas_proximity_connect",
    description:
      "Establish a secure mesh session with a discovered peer. Executes the full 7-step protocol: " +
      "BLE discovery → UWB ranging → Noise handshake → credential exchange → policy evaluation → session establishment → audit logging.",
    inputSchema: {
      type: "object" as const,
      properties: {
        device_id: { type: "string", description: "Device ID of the discovered peer" },
        agent_id: { type: "string", description: "Local agent's did:atlas:<uuid> to present" },
      },
      required: ["device_id", "agent_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "atlas_proximity_sessions",
    description: "List active proximity mesh sessions.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "atlas_proximity_disconnect",
    description: "Close a proximity mesh session.",
    inputSchema: {
      type: "object" as const,
      properties: {
        session_id: { type: "string", description: "Session ID to close" },
      },
      required: ["session_id"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true },
  },
];

export function handlers(ctx: ToolContext): Record<string, ToolHandler> {
  const { config, registry, proximityConfig, getHardware, ensureProximityMesh, proximityHardwareError } = ctx;
  return {
    async atlas_proximity_status(args) {
      const hw = await getHardware().catch(() => undefined);
      const hardware = hw
        ? {
            adapter: hw.type,
            source: hw.source,
            simulated: hw.type === "mock",
            uwb: await hw.uwb.isAvailable().catch(() => false),
            ble: await hw.ble.isAvailable().catch(() => false),
            nfc: await hw.nfc.isAvailable().catch(() => false),
          }
        : { adapter: null, error: ctx.hardwareError };
      const sessions = ctx.proximityMesh?.listSessions() ?? [];
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            profile: "ProximityMesh",
            hardware,
            config: proximityConfig,
            advertising: ctx.proximityMesh?.isAdvertising() ?? false,
            activeSessions: sessions.length,
            sessions: sessions.map((s) => ({
              sessionId: s.sessionId,
              remoteAgentId: s.remoteAgentId,
              distanceMeters: s.proximityProof.distanceMeters,
              method: s.proximityProof.method,
              establishedAt: s.establishedAt,
            })),
          }, null, 2),
        }],
      };
    },
    async atlas_proximity_scan(args) {
      const scanDuration = typeof args?.duration_ms === "number" ? args.duration_ms : 5000;
      if (!ctx.proximityMesh && !ctx.sessionAgentId) {
        return { content: [{ type: "text" as const, text: "No active agent — register an identity first (atlas_identity_register)" }], isError: true };
      }
      let mesh: ProximityMesh;
      try {
        mesh = await ensureProximityMesh(ctx.sessionAgentId!);
      } catch {
        return proximityHardwareError();
      }
      const peers = await mesh.scanForPeers(scanDuration);
      return {
        content: [{
          type: "text" as const,
          text: peers.length === 0
            ? "No Atlas agents discovered nearby."
            : JSON.stringify(peers.map((p) => ({
                deviceId: p.deviceId,
                agentIdHash: p.agentIdHash,
                supportedMethods: p.supportedMethods,
                maxRangeMeters: p.maxRangeMeters,
                estimatedDistanceMeters: p.estimatedDistanceMeters,
                discoveredAt: p.discoveredAt,
              })), null, 2),
        }],
      };
    },
    async atlas_proximity_connect(args) {
      const deviceId = args?.device_id as string;
      const agentId = args?.agent_id as string;
      if (!deviceId || !agentId) {
        return { content: [{ type: "text" as const, text: "device_id and agent_id are required" }], isError: true };
      }
      const cred = registry.get(agentId);
      if (!cred) {
        return { content: [{ type: "text" as const, text: `Agent ${agentId} not found in registry` }], isError: true };
      }
      let mesh: ProximityMesh;
      try {
        mesh = await ensureProximityMesh(agentId);
      } catch {
        return proximityHardwareError();
      }
      try {
        // Build a synthetic DiscoveredPeer from the device_id
        const peer = {
          deviceId,
          agentIdHash: "unknown",
          ephemeralPublicKey: generateEphemeralKeypair().publicKey,
          supportedMethods: ["uwb-sts" as const],
          maxRangeMeters: proximityConfig.maxProximityMeters,
          discoveredAt: new Date().toISOString(),
        };
        const session = await mesh.establishSession(peer, cred);
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              status: "connected",
              sessionId: session.sessionId,
              remoteAgentId: session.remoteAgentId,
              distanceMeters: session.proximityProof.distanceMeters,
              method: session.proximityProof.method,
              stsEnabled: session.proximityProof.stsEnabled,
              establishedAt: session.establishedAt,
            }, null, 2),
          }],
        };
      } catch (err: any) {
        return { content: [{ type: "text" as const, text: `Proximity connection failed: ${err.message}` }], isError: true };
      }
    },
    async atlas_proximity_sessions(args) {
      const meshSessions = ctx.proximityMesh?.listSessions() ?? [];
      return {
        content: [{
          type: "text" as const,
          text: meshSessions.length === 0
            ? "No active proximity mesh sessions."
            : JSON.stringify(meshSessions.map((s) => ({
                sessionId: s.sessionId,
                localAgentId: s.localAgentId,
                remoteAgentId: s.remoteAgentId,
                distanceMeters: s.proximityProof.distanceMeters,
                method: s.proximityProof.method,
                stsEnabled: s.proximityProof.stsEnabled,
                establishedAt: s.establishedAt,
              })), null, 2),
        }],
      };
    },
    async atlas_proximity_disconnect(args) {
      const sessId = args?.session_id as string;
      if (!sessId) {
        return { content: [{ type: "text" as const, text: "session_id is required" }], isError: true };
      }
      if (!ctx.proximityMesh) {
        return { content: [{ type: "text" as const, text: "No proximity mesh active" }], isError: true };
      }
      await ctx.proximityMesh.closeSession(sessId);
      return {
        content: [{ type: "text" as const, text: `Session ${sessId} closed.` }],
      };
    },
  };
}
