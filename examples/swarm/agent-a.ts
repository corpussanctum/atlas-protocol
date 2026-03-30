/**
 * Agent A — Music Production Agent
 *
 * Discovers nearby agents, establishes proximity mesh sessions,
 * and delegates tasks (e.g. "apply reverb based on distance").
 *
 * This agent acts as the orchestrator in the swarm.
 */

import { QuantumSigner } from "../../src/quantum-signer.js";
import { IdentityRegistry } from "../../src/identity-registry.js";
import { AuditLogger } from "../../src/audit-log.js";
import { PolicyEngine } from "../../src/policy-engine.js";
import { loadConfig } from "../../src/config.js";
import {
  ProximityMesh,
  loadProximityConfig,
  getHardwareAdapter,
} from "../../src/proximity/index.js";
import type { MeshSession, DiscoveredPeer } from "../../src/proximity/types.js";

export interface AgentAContext {
  mesh: ProximityMesh;
  credential: ReturnType<IdentityRegistry["register"]>;
  registry: IdentityRegistry;
  sessions: Map<string, MeshSession>;
}

export async function bootAgentA(dataDir: string): Promise<AgentAContext> {
  const config = loadConfig();
  config.data_dir = dataDir;
  config.audit_log_path = `${dataDir}/audit-agent-a.jsonl`;
  config.audit_hmac_secret = "";

  const signer = await QuantumSigner.create(dataDir);
  const registry = await IdentityRegistry.create(dataDir, signer);
  const audit = new AuditLogger(config, { redact_fields: [], force_privacy: false }, signer);
  const policy = new PolicyEngine(config);

  const credential = registry.register({
    name: "agent-a-producer",
    role: "orchestrator",
    capabilities: ["file:read", "file:write", "shell:exec", "process:spawn"],
  });

  const hw = await getHardwareAdapter();
  const proxConfig = loadProximityConfig();

  const mesh = new ProximityMesh(credential.agentId, {
    uwb: hw.uwb,
    ble: hw.ble,
    nfc: hw.nfc,
    signer,
    registry,
    audit,
    policy,
  }, proxConfig);

  console.log(`[Agent A] Booted as ${credential.agentId} (${credential.name})`);
  console.log(`[Agent A] Hardware adapter: ${hw.type}`);

  return { mesh, credential, registry, sessions: new Map() };
}

export async function discoverAndConnect(ctx: AgentAContext): Promise<MeshSession[]> {
  console.log("[Agent A] Starting BLE discovery...");
  await ctx.mesh.startDiscovery();

  const peers = await ctx.mesh.scanForPeers(5000);
  console.log(`[Agent A] Found ${peers.length} nearby Atlas agents`);

  const sessions: MeshSession[] = [];

  for (const peer of peers) {
    try {
      console.log(`[Agent A] Connecting to ${peer.agentIdHash} (${peer.estimatedDistanceMeters ?? "?"}m)...`);
      const session = await ctx.mesh.establishSession(peer, ctx.credential);
      sessions.push(session);
      ctx.sessions.set(session.sessionId, session);
      console.log(
        `[Agent A] Connected to ${session.remoteAgentId} ` +
        `at ${session.proximityProof.distanceMeters}m ` +
        `via ${session.proximityProof.method}`
      );
    } catch (err: any) {
      console.error(`[Agent A] Failed to connect to ${peer.agentIdHash}: ${err.message}`);
    }
  }

  return sessions;
}

export async function delegateTask(
  ctx: AgentAContext,
  session: MeshSession,
  task: { type: string; params: Record<string, unknown> },
): Promise<void> {
  const payload = Buffer.from(JSON.stringify({
    type: "task:delegate",
    from: ctx.credential.agentId,
    to: session.remoteAgentId,
    task,
    distance: session.proximityProof.distanceMeters,
  }));

  await session.send(payload);
  console.log(`[Agent A] Delegated "${task.type}" to ${session.remoteAgentId}`);
}
