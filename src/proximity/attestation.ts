/**
 * Atlas Protocol — Proximity Attestation
 *
 * Generates and verifies cryptographic proximity proofs. A proximity proof
 * binds a UWB/BLE ranging result to a did:atlas identity via an ML-DSA-65
 * signature. This is the core cryptographic primitive of the ProximityMesh
 * profile — every credential exchange requires a valid proximity proof.
 *
 * Spec reference: SPEC.md § 13.3 (Proximity attestation)
 */

import { createHash, randomBytes } from "node:crypto";
import type { QuantumSigner } from "../quantum-signer.js";
import type {
  ProximityProof,
  ProximityVerifyResult,
  ProximityDenyReason,
  ProximityMethod,
  UWBRangingResult,
  BLERangingResult,
  ProximityMeshConfig,
} from "./types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_PROOF_TTL_SECONDS = 30;

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

/**
 * Build the canonical payload for signing a proximity proof.
 * Deterministic: sorted keys, no signature field.
 * Follows SPEC.md Appendix D (canonical serialization rules).
 */
export function buildProximityProofPayload(
  proverId: string,
  verifierId: string,
  distanceMeters: number,
  method: ProximityMethod,
  rangingTimestamp: string,
  challenge: string,
  stsEnabled: boolean,
  expiresAt: string,
): string {
  const payload = {
    challenge,
    distanceMeters,
    expiresAt,
    method,
    proverId,
    rangingTimestamp,
    stsEnabled,
    verifierId,
  };
  return JSON.stringify(payload);
}

// ---------------------------------------------------------------------------
// Proof generation
// ---------------------------------------------------------------------------

/**
 * Generate a proximity proof from a UWB ranging result.
 * The proof is signed with the prover's ML-DSA-65 key.
 */
export function generateProximityProofFromUWB(
  proverId: string,
  verifierId: string,
  ranging: UWBRangingResult,
  signer: QuantumSigner,
  config: Pick<ProximityMeshConfig, "proofTtlSeconds">,
): ProximityProof {
  const ttl = config.proofTtlSeconds ?? DEFAULT_PROOF_TTL_SECONDS;
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  const challenge = Buffer.from(ranging.challenge).toString("hex");

  const canonical = buildProximityProofPayload(
    proverId,
    verifierId,
    ranging.distanceMeters,
    "uwb-sts",
    ranging.timestamp,
    challenge,
    ranging.stsEnabled,
    expiresAt,
  );

  const signature = signer.sign(Buffer.from(canonical));
  if (!signature) {
    throw new Error("Proximity proof signing failed — QuantumSigner unavailable");
  }

  return {
    proverId,
    verifierId,
    distanceMeters: ranging.distanceMeters,
    method: "uwb-sts",
    rangingTimestamp: ranging.timestamp,
    challenge,
    signature,
    stsEnabled: ranging.stsEnabled,
    expiresAt,
  };
}

/**
 * Generate a proximity proof from a BLE RSSI ranging result.
 * Used as fallback when UWB is unavailable.
 */
export function generateProximityProofFromBLE(
  proverId: string,
  verifierId: string,
  ranging: BLERangingResult,
  signer: QuantumSigner,
  config: Pick<ProximityMeshConfig, "proofTtlSeconds">,
): ProximityProof {
  const ttl = config.proofTtlSeconds ?? DEFAULT_PROOF_TTL_SECONDS;
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
  // BLE doesn't have a challenge — generate one for the proof
  const challenge = randomBytes(32).toString("hex");

  const canonical = buildProximityProofPayload(
    proverId,
    verifierId,
    ranging.distanceMeters,
    "ble-rssi",
    ranging.timestamp,
    challenge,
    false,
    expiresAt,
  );

  const signature = signer.sign(Buffer.from(canonical));
  if (!signature) {
    throw new Error("Proximity proof signing failed — QuantumSigner unavailable");
  }

  return {
    proverId,
    verifierId,
    distanceMeters: ranging.distanceMeters,
    method: "ble-rssi",
    rangingTimestamp: ranging.timestamp,
    challenge,
    signature,
    stsEnabled: false,
    expiresAt,
  };
}

// ---------------------------------------------------------------------------
// Proof verification
// ---------------------------------------------------------------------------

/**
 * Verify a proximity proof. Checks:
 *   1. Signature validity (ML-DSA-65)
 *   2. Proof not expired
 *   3. Distance within configured maximum
 *   4. STS requirement (if configured)
 *   5. Method is supported
 */
export function verifyProximityProof(
  proof: ProximityProof,
  proverPublicKey: Uint8Array,
  config: Pick<ProximityMeshConfig, "maxProximityMeters" | "requireSts" | "requireUwb">,
  signer: QuantumSigner,
): ProximityVerifyResult {
  // 1. Check expiry
  if (new Date(proof.expiresAt) < new Date()) {
    return { valid: false, denyReason: "PROOF_EXPIRED" };
  }

  // 2. Check distance
  if (proof.distanceMeters > config.maxProximityMeters) {
    return {
      valid: false,
      distanceMeters: proof.distanceMeters,
      method: proof.method,
      denyReason: "DISTANCE_EXCEEDED",
    };
  }

  // 3. Check STS requirement
  if (config.requireSts && !proof.stsEnabled && proof.method === "uwb-sts") {
    return { valid: false, method: proof.method, denyReason: "STS_REQUIRED" };
  }

  // 4. Check UWB requirement
  if (config.requireUwb && proof.method !== "uwb-sts") {
    return { valid: false, method: proof.method, denyReason: "METHOD_NOT_SUPPORTED" };
  }

  // 5. Verify signature
  const canonical = buildProximityProofPayload(
    proof.proverId,
    proof.verifierId,
    proof.distanceMeters,
    proof.method,
    proof.rangingTimestamp,
    proof.challenge,
    proof.stsEnabled,
    proof.expiresAt,
  );

  // Load the prover's public key for verification
  const originalKey = signer.getPublicKeyRaw();
  signer.loadPublicKey(Buffer.from(proverPublicKey).toString("base64"));

  const signatureValid = signer.verify(
    Buffer.from(canonical),
    proof.signature,
  );

  // Restore the original key
  if (originalKey) {
    signer.loadPublicKey(Buffer.from(originalKey).toString("base64"));
  }

  if (!signatureValid) {
    return { valid: false, denyReason: "SIGNATURE_INVALID" };
  }

  return {
    valid: true,
    distanceMeters: proof.distanceMeters,
    method: proof.method,
  };
}

// ---------------------------------------------------------------------------
// Challenge generation
// ---------------------------------------------------------------------------

/** Generate a cryptographic challenge for UWB ranging */
export function generateRangingChallenge(): Uint8Array {
  return randomBytes(32);
}

/** Hash a did:atlas ID down to a short form for BLE advertisements */
export function hashAgentId(agentId: string): string {
  return createHash("sha3-256").update(agentId).digest("hex").slice(0, 16);
}
