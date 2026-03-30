/**
 * Tests for the proximity mesh orchestrator:
 *   - Hardware detection
 *   - BLE discovery (mock)
 *   - Full mesh session establishment (7-step flow)
 *   - Session management
 *   - Noise session encrypt/decrypt
 *   - Error cases (distance exceeded, no hardware, policy deny)
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes, randomUUID } from "node:crypto";

import { QuantumSigner } from "../src/quantum-signer.js";
import { IdentityRegistry } from "../src/identity-registry.js";
import { AuditLogger } from "../src/audit-log.js";
import { PolicyEngine } from "../src/policy-engine.js";
import { loadConfig } from "../src/config.js";
import {
  ProximityMesh,
  ProximityError,
  MockUWBDriver,
  MockBLEDriver,
  MockNFCDriver,
  detectHardware,
  generateEphemeralKeypair,
  initiateNoiseHandshake,
  respondNoiseHandshake,
  ATLAS_PROXIMITY_SERVICE_UUID,
  DEFAULT_MESH_CONFIG,
} from "../src/proximity/index.js";
import type { DiscoveredPeer, ProximityMeshConfig } from "../src/proximity/types.js";

describe("Proximity Mesh — hardware detection", () => {
  it("detects all hardware available", async () => {
    const hw = await detectHardware(
      new MockUWBDriver(),
      new MockBLEDriver(),
      new MockNFCDriver(true),
    );
    assert.equal(hw.uwb, true);
    assert.equal(hw.ble, true);
    assert.equal(hw.nfc, true);
  });

  it("detects UWB failure", async () => {
    const hw = await detectHardware(
      new MockUWBDriver({ simulateFailure: true }),
      new MockBLEDriver(),
      new MockNFCDriver(true),
    );
    assert.equal(hw.uwb, false);
    assert.equal(hw.ble, true);
  });

  it("handles all hardware unavailable", async () => {
    const hw = await detectHardware(
      new MockUWBDriver({ simulateFailure: true }),
      new MockBLEDriver({ simulateFailure: true }),
      new MockNFCDriver(false),
    );
    assert.equal(hw.uwb, false);
    assert.equal(hw.ble, false);
    assert.equal(hw.nfc, false);
  });
});

describe("Proximity Mesh — mock BLE discovery", () => {
  it("returns configured peers on scan", async () => {
    const mockPeer: DiscoveredPeer = {
      deviceId: "uwb-peer-001",
      agentIdHash: "abc123def456",
      ephemeralPublicKey: randomBytes(32),
      supportedMethods: ["uwb-sts"],
      maxRangeMeters: 10,
      estimatedDistanceMeters: 3.0,
      discoveredAt: new Date().toISOString(),
    };

    const ble = new MockBLEDriver({ simulatedPeers: [mockPeer] });
    const peers = await ble.scan(5000);

    assert.equal(peers.length, 1);
    assert.equal(peers[0].deviceId, "uwb-peer-001");
    assert.equal(peers[0].estimatedDistanceMeters, 3.0);
  });

  it("supports adding peers dynamically", async () => {
    const ble = new MockBLEDriver();
    assert.equal((await ble.scan(1000)).length, 0);

    ble.addPeer({
      deviceId: "dynamic-001",
      agentIdHash: "dyn123",
      ephemeralPublicKey: randomBytes(32),
      supportedMethods: ["uwb-sts", "ble-rssi"],
      maxRangeMeters: 10,
      discoveredAt: new Date().toISOString(),
    });

    assert.equal((await ble.scan(1000)).length, 1);
  });

  it("tracks advertising state", async () => {
    const ble = new MockBLEDriver();
    assert.equal(ble.isAdvertising(), false);

    await ble.startAdvertising({
      serviceUuid: ATLAS_PROXIMITY_SERVICE_UUID,
      ephemeralPublicKey: randomBytes(32),
      agentIdHash: "test",
      supportedMethods: ["uwb-sts"],
      maxRangeMeters: 10,
    });
    assert.equal(ble.isAdvertising(), true);

    await ble.stopAdvertising();
    assert.equal(ble.isAdvertising(), false);
  });
});

describe("Proximity Mesh — Noise session", () => {
  it("establishes a session and encrypts/decrypts", async () => {
    const initiatorKeys = generateEphemeralKeypair();
    const responderKeys = generateEphemeralKeypair();
    const ad = Buffer.from("proximity-proof-data");

    const { session: initiatorSession } = initiateNoiseHandshake(
      "did:atlas:responder",
      {
        localStaticPublicKey: randomBytes(32),
        localStaticSecretKey: randomBytes(32),
        localEphemeralPublicKey: initiatorKeys.publicKey,
        localEphemeralSecretKey: initiatorKeys.secretKey,
        remoteEphemeralPublicKey: responderKeys.publicKey,
        additionalData: ad,
        pattern: "IK",
      },
    );

    const { session: responderSession } = respondNoiseHandshake(
      "did:atlas:initiator",
      {
        localStaticPublicKey: randomBytes(32),
        localStaticSecretKey: randomBytes(32),
        localEphemeralPublicKey: responderKeys.publicKey,
        localEphemeralSecretKey: responderKeys.secretKey,
        remoteEphemeralPublicKey: initiatorKeys.publicKey,
        additionalData: ad,
        pattern: "IK",
      },
    );

    assert.equal(initiatorSession.state, "transport");
    assert.equal(responderSession.state, "transport");

    // Encrypt with initiator, decrypt with responder
    const message = Buffer.from("Hello from Atlas mesh!");
    const encrypted = await initiatorSession.encrypt(message);
    const decrypted = await responderSession.decrypt(encrypted);

    assert.deepEqual(Buffer.from(decrypted), message);
  });

  it("fails to decrypt with wrong keys", async () => {
    const keys1 = generateEphemeralKeypair();
    const keys2 = generateEphemeralKeypair();
    const keys3 = generateEphemeralKeypair();

    const { session: session1 } = initiateNoiseHandshake("did:atlas:a", {
      localStaticPublicKey: randomBytes(32),
      localStaticSecretKey: randomBytes(32),
      localEphemeralPublicKey: keys1.publicKey,
      localEphemeralSecretKey: keys1.secretKey,
      remoteEphemeralPublicKey: keys2.publicKey,
      pattern: "IK",
    });

    // Different session with different keys
    const { session: session3 } = respondNoiseHandshake("did:atlas:b", {
      localStaticPublicKey: randomBytes(32),
      localStaticSecretKey: randomBytes(32),
      localEphemeralPublicKey: keys3.publicKey,
      localEphemeralSecretKey: keys3.secretKey,
      remoteEphemeralPublicKey: keys1.publicKey,
      pattern: "IK",
    });

    const encrypted = await session1.encrypt(Buffer.from("secret"));
    await assert.rejects(
      () => session3.decrypt(encrypted),
      // AES-GCM will throw on auth tag mismatch
    );
  });

  it("closes session and prevents further use", async () => {
    const keys1 = generateEphemeralKeypair();
    const keys2 = generateEphemeralKeypair();

    const { session } = initiateNoiseHandshake("did:atlas:peer", {
      localStaticPublicKey: randomBytes(32),
      localStaticSecretKey: randomBytes(32),
      localEphemeralPublicKey: keys1.publicKey,
      localEphemeralSecretKey: keys1.secretKey,
      remoteEphemeralPublicKey: keys2.publicKey,
      pattern: "IK",
    });

    await session.close();
    assert.equal(session.state, "closed");

    await assert.rejects(
      () => session.encrypt(Buffer.from("should fail")),
      /Cannot encrypt in state: closed/,
    );
  });
});

describe("Proximity Mesh — full session establishment", () => {
  let signer: QuantumSigner;
  let registry: IdentityRegistry;
  let audit: AuditLogger;
  let policy: PolicyEngine;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "atlas-mesh-test-"));
    signer = await QuantumSigner.create(tmpDir);
    registry = await IdentityRegistry.create(tmpDir, signer);
    const config = loadConfig();
    config.data_dir = tmpDir;
    config.audit_log_path = join(tmpDir, "audit.jsonl");
    config.audit_hmac_secret = "";
    audit = new AuditLogger(config, { redact_fields: [], force_privacy: false }, signer);
    policy = new PolicyEngine(config);
  });

  it("establishes a session with UWB (happy path)", async () => {
    if (!signer.available) return;

    const cred = registry.register({
      name: "test-agent",
      role: "claude-code",
      capabilities: ["file:read", "shell:exec"],
    });

    const mockPeer: DiscoveredPeer = {
      deviceId: "uwb-peer-happy",
      agentIdHash: "happyhash",
      ephemeralPublicKey: randomBytes(32),
      supportedMethods: ["uwb-sts"],
      maxRangeMeters: 10,
      discoveredAt: new Date().toISOString(),
    };

    const mesh = new ProximityMesh(cred.agentId, {
      uwb: new MockUWBDriver({ simulatedDistance: 3.2, stsSupported: true }),
      ble: new MockBLEDriver({ simulatedPeers: [mockPeer] }),
      signer,
      registry,
      audit,
      policy,
    }, { ...DEFAULT_MESH_CONFIG, requireUwb: true });

    const session = await mesh.establishSession(mockPeer, cred);

    assert.ok(session.sessionId);
    assert.equal(session.localAgentId, cred.agentId);
    assert.equal(session.remoteAgentId, "happyhash");
    assert.equal(session.proximityProof.method, "uwb-sts");
    assert.equal(session.proximityProof.distanceMeters, 3.2);
    assert.equal(session.proximityProof.stsEnabled, true);
    assert.ok(session.noiseSession);
    assert.equal(session.noiseSession.state, "transport");

    // Session should be tracked
    assert.equal(mesh.listSessions().length, 1);

    await mesh.shutdown();
    assert.equal(mesh.listSessions().length, 0);
  });

  it("rejects session when distance exceeds limit", async () => {
    if (!signer.available) return;

    const cred = registry.register({
      name: "far-agent",
      role: "claude-code",
      capabilities: ["file:read"],
    });

    const peer: DiscoveredPeer = {
      deviceId: "uwb-far",
      agentIdHash: "farhash",
      ephemeralPublicKey: randomBytes(32),
      supportedMethods: ["uwb-sts"],
      maxRangeMeters: 10,
      discoveredAt: new Date().toISOString(),
    };

    const mesh = new ProximityMesh(cred.agentId, {
      uwb: new MockUWBDriver({ simulatedDistance: 25.0 }), // Way too far
      ble: new MockBLEDriver(),
      signer, registry, audit, policy,
    });

    await assert.rejects(
      () => mesh.establishSession(peer, cred),
      (err: any) => {
        assert.ok(err instanceof ProximityError);
        assert.equal(err.code, "DISTANCE_EXCEEDED");
        assert.equal(err.step, 2);
        return true;
      },
    );
  });

  it("rejects when no hardware available", async () => {
    if (!signer.available) return;

    const cred = registry.register({
      name: "no-hw-agent",
      role: "claude-code",
      capabilities: ["file:read"],
    });

    const peer: DiscoveredPeer = {
      deviceId: "phantom",
      agentIdHash: "phantom",
      ephemeralPublicKey: randomBytes(32),
      supportedMethods: ["uwb-sts"],
      maxRangeMeters: 10,
      discoveredAt: new Date().toISOString(),
    };

    const mesh = new ProximityMesh(cred.agentId, {
      uwb: new MockUWBDriver({ simulateFailure: true }),
      ble: new MockBLEDriver({ simulateFailure: true }),
      signer, registry, audit, policy,
    }, { ...DEFAULT_MESH_CONFIG, requireUwb: true });

    await assert.rejects(
      () => mesh.establishSession(peer, cred),
      (err: any) => {
        assert.ok(err instanceof ProximityError);
        assert.equal(err.code, "HARDWARE_UNAVAILABLE");
        return true;
      },
    );
  });

  it("falls back to BLE when UWB unavailable and not required", async () => {
    if (!signer.available) return;

    const cred = registry.register({
      name: "ble-agent",
      role: "claude-code",
      capabilities: ["file:read"],
    });

    const peer: DiscoveredPeer = {
      deviceId: "ble-only-device",
      agentIdHash: "blehash",
      ephemeralPublicKey: randomBytes(32),
      supportedMethods: ["ble-rssi"],
      maxRangeMeters: 10,
      estimatedDistanceMeters: 4.0,
      discoveredAt: new Date().toISOString(),
    };

    const mesh = new ProximityMesh(cred.agentId, {
      uwb: new MockUWBDriver({ simulateFailure: true }), // UWB unavailable
      ble: new MockBLEDriver({ simulatedPeers: [peer] }),
      signer, registry, audit, policy,
    }, { ...DEFAULT_MESH_CONFIG, requireUwb: false }); // BLE fallback OK

    const session = await mesh.establishSession(peer, cred);
    assert.equal(session.proximityProof.method, "ble-rssi");
    assert.equal(session.proximityProof.stsEnabled, false);

    await mesh.shutdown();
  });

  it("manages multiple concurrent sessions", async () => {
    if (!signer.available) return;

    const cred = registry.register({
      name: "multi-agent",
      role: "orchestrator",
      capabilities: ["file:read", "process:spawn"],
    });

    const peers: DiscoveredPeer[] = [
      {
        deviceId: "peer-a",
        agentIdHash: "hashA",
        ephemeralPublicKey: randomBytes(32),
        supportedMethods: ["uwb-sts"],
        maxRangeMeters: 10,
        discoveredAt: new Date().toISOString(),
      },
      {
        deviceId: "peer-b",
        agentIdHash: "hashB",
        ephemeralPublicKey: randomBytes(32),
        supportedMethods: ["uwb-sts"],
        maxRangeMeters: 10,
        discoveredAt: new Date().toISOString(),
      },
    ];

    const mesh = new ProximityMesh(cred.agentId, {
      uwb: new MockUWBDriver({ simulatedDistance: 2.5 }),
      ble: new MockBLEDriver({ simulatedPeers: peers }),
      signer, registry, audit, policy,
    });

    const session1 = await mesh.establishSession(peers[0], cred);
    const session2 = await mesh.establishSession(peers[1], cred);

    assert.equal(mesh.listSessions().length, 2);
    assert.notEqual(session1.sessionId, session2.sessionId);

    // Close one
    await mesh.closeSession(session1.sessionId);
    assert.equal(mesh.listSessions().length, 1);

    // Shutdown closes all
    await mesh.shutdown();
    assert.equal(mesh.listSessions().length, 0);
  });
});

describe("Proximity Mesh — configuration", () => {
  it("uses default config when no overrides", () => {
    assert.equal(DEFAULT_MESH_CONFIG.maxProximityMeters, 10);
    assert.equal(DEFAULT_MESH_CONFIG.proofTtlSeconds, 30);
    assert.equal(DEFAULT_MESH_CONFIG.requireSts, true);
    assert.equal(DEFAULT_MESH_CONFIG.preferredNoisePattern, "IK");
    assert.equal(DEFAULT_MESH_CONFIG.requireUwb, true);
    assert.equal(DEFAULT_MESH_CONFIG.sessionTimeoutSeconds, 3600);
  });

  it("merges partial config with defaults", async () => {
    const signer = await QuantumSigner.create(mkdtempSync(join(tmpdir(), "atlas-cfg-")));
    const registry = await IdentityRegistry.create(mkdtempSync(join(tmpdir(), "atlas-cfg2-")), signer);
    const config = loadConfig();
    config.audit_log_path = join(tmpdir(), `atlas-cfg-audit-${randomUUID()}.jsonl`);
    config.audit_hmac_secret = "";
    const audit = new AuditLogger(config, { redact_fields: [], force_privacy: false }, signer);
    const policy = new PolicyEngine(config);

    const mesh = new ProximityMesh("did:atlas:test", {
      uwb: new MockUWBDriver(),
      ble: new MockBLEDriver(),
      signer, registry, audit, policy,
    }, { maxProximityMeters: 5 }); // Override just one field

    const cfg = mesh.getConfig();
    assert.equal(cfg.maxProximityMeters, 5);
    assert.equal(cfg.requireSts, true); // Default preserved
    assert.equal(cfg.preferredNoisePattern, "IK"); // Default preserved
  });
});

describe("Proximity Mesh — mock NFC driver", () => {
  it("simulates NFC tap exchange", async () => {
    const nfc = new MockNFCDriver();
    assert.equal(await nfc.isAvailable(), true);

    const payload = {
      agentId: "did:atlas:nfc-agent",
      ephemeralPublicKey: randomBytes(32),
      pairingToken: randomBytes(16),
      expiresAt: new Date(Date.now() + 30000).toISOString(),
    };

    nfc.simulateTap(payload);
    const received = await nfc.readTap(5000);

    assert.ok(received);
    assert.equal(received!.agentId, "did:atlas:nfc-agent");

    // Second read returns null (tap consumed)
    const empty = await nfc.readTap(1000);
    assert.equal(empty, null);
  });

  it("handles unavailable NFC", async () => {
    const nfc = new MockNFCDriver(false);
    assert.equal(await nfc.isAvailable(), false);
    await assert.rejects(() => nfc.readTap(1000), /NFC hardware unavailable/);
  });
});
