/**
 * Agent B — Audio Renderer
 *
 * Listens for delegated tasks from the orchestrator (Agent A).
 * Processes audio rendering tasks with proximity-aware parameters.
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

export async function bootAgentB(dataDir: string) {
  const config = loadConfig();
  config.data_dir = dataDir;
  config.audit_log_path = `${dataDir}/audit-agent-b.jsonl`;
  config.audit_hmac_secret = "";

  const signer = await QuantumSigner.create(dataDir);
  const registry = await IdentityRegistry.create(dataDir, signer);
  const audit = new AuditLogger(config, { redact_fields: [], force_privacy: false }, signer);
  const policy = new PolicyEngine(config);

  const credential = registry.register({
    name: "agent-b-renderer",
    role: "tool-caller",
    capabilities: ["file:read", "file:write"],
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

  console.log(`[Agent B] Booted as ${credential.agentId} (renderer)`);
  console.log(`[Agent B] Advertising presence...`);
  await mesh.startDiscovery();

  return { mesh, credential, registry };
}
