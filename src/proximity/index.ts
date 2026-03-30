/**
 * Atlas Protocol — Proximity Mesh Module
 *
 * Close-proximity agent-to-agent secure transmission protocol.
 * Adds cryptographically-enforced physical proximity as a first-class
 * authentication factor to Atlas Protocol.
 *
 * Public API:
 *   - ProximityMesh: Main orchestrator for mesh session management
 *   - Attestation: Proximity proof generation and verification
 *   - Noise sessions: Encrypted agent-to-agent channels
 *   - Hardware drivers: UWB, BLE, NFC abstraction (mock + real)
 *
 * Spec reference: SPEC.md § 13 (Proximity Mesh Profile)
 */

// Types
export type {
  ProximityMethod,
  UWBRangingResult,
  BLERangingResult,
  BLEAdvertisement,
  NFCTapPayload,
  ProximityProof,
  ProximityVerifyResult,
  ProximityDenyReason,
  ProximityCapabilities,
  NoisePattern,
  NoiseSessionState,
  NoiseSession,
  NoiseHandshakeConfig,
  MeshSession,
  DiscoveredPeer,
  ProximityMeshConfig,
  ProximityAuditEventType,
  ProximityAuditMeta,
  UWBDriver,
  BLEDriver,
  NFCDriver,
} from "./types.js";

// Attestation
export {
  generateProximityProofFromUWB,
  generateProximityProofFromBLE,
  verifyProximityProof,
  generateRangingChallenge,
  hashAgentId,
  buildProximityProofPayload,
} from "./attestation.js";

// Noise sessions
export {
  initiateNoiseHandshake,
  respondNoiseHandshake,
  generateEphemeralKeypair,
} from "./noise-session.js";
export type { HandshakeResult } from "./noise-session.js";

// Hardware drivers
export {
  MockUWBDriver,
  MockBLEDriver,
  MockNFCDriver,
  detectHardware,
  ATLAS_PROXIMITY_SERVICE_UUID,
} from "./hardware.js";
export type { MockUWBConfig, MockBLEConfig, HardwareAvailability } from "./hardware.js";

// Mesh orchestrator
export {
  ProximityMesh,
  ProximityError,
  DEFAULT_MESH_CONFIG,
} from "./mesh.js";
export type { ProximityMeshDeps } from "./mesh.js";

// Hardware adapters (production drivers)
export { createHardwareAdapters } from "./adapters/index.js";
export type { AdapterType, HardwareAdapterSet } from "./adapters/index.js";

// ---------------------------------------------------------------------------
// Convenience: load proximity config from environment
// ---------------------------------------------------------------------------

import type { ProximityMeshConfig } from "./types.js";
import { DEFAULT_MESH_CONFIG } from "./mesh.js";
import { createHardwareAdapters } from "./adapters/index.js";
import type { HardwareAdapterSet } from "./adapters/index.js";

/**
 * Get hardware adapters for the current platform.
 * Auto-detects or uses ATLAS_HARDWARE_ADAPTER env var.
 * Returns mock drivers by default (zero-cost development).
 */
export async function getHardwareAdapter(): Promise<HardwareAdapterSet> {
  return createHardwareAdapters();
}

/**
 * Load proximity mesh configuration from environment variables.
 * Falls back to defaults for any unset variable.
 */
export function loadProximityConfig(): ProximityMeshConfig {
  return {
    maxProximityMeters: parseFloat(
      process.env.ATLAS_MAX_PROXIMITY_METERS ?? String(DEFAULT_MESH_CONFIG.maxProximityMeters),
    ),
    proofTtlSeconds: parseInt(
      process.env.ATLAS_PROXIMITY_PROOF_TTL_SECONDS ?? String(DEFAULT_MESH_CONFIG.proofTtlSeconds),
      10,
    ),
    requireSts:
      (process.env.ATLAS_PROXIMITY_REQUIRE_STS ?? "true") === "true",
    preferredNoisePattern:
      (process.env.ATLAS_PROXIMITY_NOISE_PATTERN as "IK" | "KK") ??
      DEFAULT_MESH_CONFIG.preferredNoisePattern,
    bleServiceUuid:
      process.env.ATLAS_PROXIMITY_BLE_UUID ?? DEFAULT_MESH_CONFIG.bleServiceUuid,
    requireUwb:
      (process.env.ATLAS_PROXIMITY_REQUIRE_UWB ?? "true") === "true",
    sessionTimeoutSeconds: parseInt(
      process.env.ATLAS_PROXIMITY_SESSION_TIMEOUT ?? String(DEFAULT_MESH_CONFIG.sessionTimeoutSeconds),
      10,
    ),
    reRangeIntervalSeconds: parseInt(
      process.env.ATLAS_PROXIMITY_RERANGE_INTERVAL ?? String(DEFAULT_MESH_CONFIG.reRangeIntervalSeconds),
      10,
    ),
  };
}
