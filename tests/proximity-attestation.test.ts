/**
 * Tests for the proximity attestation layer:
 *   - Proof generation from UWB and BLE ranging
 *   - Proof verification (signature, expiry, distance, STS)
 *   - Challenge generation
 *   - Agent ID hashing
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";

import { QuantumSigner } from "../src/quantum-signer.js";
import {
  generateProximityProofFromUWB,
  generateProximityProofFromBLE,
  verifyProximityProof,
  generateRangingChallenge,
  hashAgentId,
  buildProximityProofPayload,
} from "../src/proximity/attestation.js";
import type { UWBRangingResult, BLERangingResult, ProximityMeshConfig } from "../src/proximity/types.js";

describe("Proximity Attestation — proof generation", () => {
  let signer: QuantumSigner;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "atlas-prox-test-"));
    signer = await QuantumSigner.create(tmpDir);
  });

  it("generates a valid UWB proximity proof", async () => {
    if (!signer.available) return; // skip if no PQ crypto

    const challenge = generateRangingChallenge();
    const ranging: UWBRangingResult = {
      distanceMeters: 3.5,
      stsEnabled: true,
      timestamp: new Date().toISOString(),
      challenge,
      remoteDeviceId: "uwb-device-001",
      signalQuality: 90,
      roundsCompleted: 3,
    };

    const proof = generateProximityProofFromUWB(
      "did:atlas:prover-001",
      "did:atlas:verifier-001",
      ranging,
      signer,
      { proofTtlSeconds: 30 },
    );

    assert.equal(proof.proverId, "did:atlas:prover-001");
    assert.equal(proof.verifierId, "did:atlas:verifier-001");
    assert.equal(proof.distanceMeters, 3.5);
    assert.equal(proof.method, "uwb-sts");
    assert.equal(proof.stsEnabled, true);
    assert.ok(proof.signature.length > 0);
    assert.ok(new Date(proof.expiresAt) > new Date());
  });

  it("generates a valid BLE proximity proof", async () => {
    if (!signer.available) return;

    const ranging: BLERangingResult = {
      distanceMeters: 7.2,
      rssi: -68,
      txPower: -59,
      timestamp: new Date().toISOString(),
      remoteAddress: "AA:BB:CC:DD:EE:FF",
    };

    const proof = generateProximityProofFromBLE(
      "did:atlas:prover-002",
      "did:atlas:verifier-002",
      ranging,
      signer,
      { proofTtlSeconds: 30 },
    );

    assert.equal(proof.method, "ble-rssi");
    assert.equal(proof.stsEnabled, false);
    assert.equal(proof.distanceMeters, 7.2);
    assert.ok(proof.challenge.length > 0); // BLE generates its own challenge
  });

  it("throws when signer is unavailable", async () => {
    const badSigner = new QuantumSigner();
    // Don't initialize — simulate unavailable PQ crypto

    const ranging: UWBRangingResult = {
      distanceMeters: 2.0,
      stsEnabled: true,
      timestamp: new Date().toISOString(),
      challenge: randomBytes(32),
      remoteDeviceId: "uwb-device-002",
      signalQuality: 95,
      roundsCompleted: 3,
    };

    assert.throws(
      () => generateProximityProofFromUWB("a", "b", ranging, badSigner, { proofTtlSeconds: 30 }),
      /QuantumSigner unavailable/,
    );
  });
});

describe("Proximity Attestation — proof verification", () => {
  let signer: QuantumSigner;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "atlas-prox-verify-"));
    signer = await QuantumSigner.create(tmpDir);
  });

  it("accepts a valid proof within range", async () => {
    if (!signer.available) return;

    const challenge = generateRangingChallenge();
    const ranging: UWBRangingResult = {
      distanceMeters: 4.0,
      stsEnabled: true,
      timestamp: new Date().toISOString(),
      challenge,
      remoteDeviceId: "uwb-001",
      signalQuality: 88,
      roundsCompleted: 3,
    };

    const proof = generateProximityProofFromUWB(
      "did:atlas:prover", "did:atlas:verifier",
      ranging, signer, { proofTtlSeconds: 30 },
    );

    const pubKey = signer.getPublicKeyRaw()!;
    const result = verifyProximityProof(proof, pubKey, {
      maxProximityMeters: 10,
      requireSts: false,
      requireUwb: false,
    }, signer);

    assert.equal(result.valid, true);
    assert.equal(result.distanceMeters, 4.0);
    assert.equal(result.method, "uwb-sts");
  });

  it("rejects proof exceeding max distance", async () => {
    if (!signer.available) return;

    const challenge = generateRangingChallenge();
    const ranging: UWBRangingResult = {
      distanceMeters: 15.0,
      stsEnabled: true,
      timestamp: new Date().toISOString(),
      challenge,
      remoteDeviceId: "uwb-002",
      signalQuality: 60,
      roundsCompleted: 3,
    };

    const proof = generateProximityProofFromUWB(
      "did:atlas:far", "did:atlas:verifier",
      ranging, signer, { proofTtlSeconds: 30 },
    );

    const pubKey = signer.getPublicKeyRaw()!;
    const result = verifyProximityProof(proof, pubKey, {
      maxProximityMeters: 10,
      requireSts: false,
      requireUwb: false,
    }, signer);

    assert.equal(result.valid, false);
    assert.equal(result.denyReason, "DISTANCE_EXCEEDED");
  });

  it("rejects expired proof", async () => {
    if (!signer.available) return;

    const challenge = generateRangingChallenge();
    const ranging: UWBRangingResult = {
      distanceMeters: 2.0,
      stsEnabled: true,
      timestamp: new Date().toISOString(),
      challenge,
      remoteDeviceId: "uwb-003",
      signalQuality: 95,
      roundsCompleted: 3,
    };

    const proof = generateProximityProofFromUWB(
      "did:atlas:expired", "did:atlas:verifier",
      ranging, signer, { proofTtlSeconds: 0 }, // Expires immediately
    );

    // Force expiry by backdating
    proof.expiresAt = new Date(Date.now() - 1000).toISOString();

    const pubKey = signer.getPublicKeyRaw()!;
    const result = verifyProximityProof(proof, pubKey, {
      maxProximityMeters: 10,
      requireSts: false,
      requireUwb: false,
    }, signer);

    assert.equal(result.valid, false);
    assert.equal(result.denyReason, "PROOF_EXPIRED");
  });

  it("rejects BLE when UWB is required", async () => {
    if (!signer.available) return;

    const ranging: BLERangingResult = {
      distanceMeters: 5.0,
      rssi: -65,
      txPower: -59,
      timestamp: new Date().toISOString(),
      remoteAddress: "AA:BB:CC:DD:EE:FF",
    };

    const proof = generateProximityProofFromBLE(
      "did:atlas:ble", "did:atlas:verifier",
      ranging, signer, { proofTtlSeconds: 30 },
    );

    const pubKey = signer.getPublicKeyRaw()!;
    const result = verifyProximityProof(proof, pubKey, {
      maxProximityMeters: 10,
      requireSts: false,
      requireUwb: true, // Require UWB
    }, signer);

    assert.equal(result.valid, false);
    assert.equal(result.denyReason, "METHOD_NOT_SUPPORTED");
  });
});

describe("Proximity Attestation — utilities", () => {
  it("generates 32-byte challenges", () => {
    const c1 = generateRangingChallenge();
    const c2 = generateRangingChallenge();
    assert.equal(c1.length, 32);
    assert.equal(c2.length, 32);
    assert.notDeepEqual(c1, c2); // Unique per call
  });

  it("hashes agent IDs to 16-char hex", () => {
    const hash = hashAgentId("did:atlas:12345678-abcd-1234-efgh-123456789012");
    assert.equal(hash.length, 16);
    assert.match(hash, /^[0-9a-f]{16}$/);
  });

  it("produces deterministic hashes", () => {
    const id = "did:atlas:test-agent";
    assert.equal(hashAgentId(id), hashAgentId(id));
  });

  it("produces different hashes for different IDs", () => {
    assert.notEqual(hashAgentId("did:atlas:a"), hashAgentId("did:atlas:b"));
  });

  it("builds canonical proof payloads with sorted keys", () => {
    const payload = buildProximityProofPayload(
      "prover", "verifier", 5.0, "uwb-sts",
      "2026-03-29T20:00:00Z", "abc123", true, "2026-03-29T20:01:00Z",
    );
    const parsed = JSON.parse(payload);
    const keys = Object.keys(parsed);
    const sorted = [...keys].sort();
    assert.deepEqual(keys, sorted);
  });
});
