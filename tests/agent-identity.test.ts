/**
 * Tests for Atlas Protocol — Agent Identity (v0.5.0)
 *
 * Covers: keypair generation, credential issuance, canonical payload,
 * signature verification, expiry, revocation, tamper detection.
 */

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import {
  initAgentIdentity,
  generateAgentKeyPair,
  issueCredential,
  verifyCredential,
  revokeCredential,
  buildCanonicalPayload,
} from "../src/agent-identity.js";
import type { AgentCapability } from "../src/agent-identity.js";

// ---------------------------------------------------------------------------
// ML-DSA-65 type shim for direct keygen (same as quantum-signer.ts)
// ---------------------------------------------------------------------------

interface MlDsa65 {
  keygen: (seed?: Uint8Array) => { publicKey: Uint8Array; secretKey: Uint8Array };
  sign: (secretKey: Uint8Array, message: Uint8Array) => Uint8Array;
  verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean;
}

let ml_dsa65: MlDsa65;
let issuerPublicKey: Uint8Array;
let issuerSecretKey: Uint8Array;

before(async () => {
  await initAgentIdentity();
  const mod = await import("@noble/post-quantum/ml-dsa");
  ml_dsa65 = mod.ml_dsa65 as MlDsa65;

  // Generate a gatekeeper issuer keypair for tests
  const seed = randomBytes(32);
  const keys = ml_dsa65.keygen(seed);
  issuerPublicKey = keys.publicKey;
  issuerSecretKey = keys.secretKey;
});

// ---------------------------------------------------------------------------
// Keypair generation
// ---------------------------------------------------------------------------

describe("Agent Identity — keypair generation", () => {
  it("generateAgentKeyPair returns valid ML-DSA-65 keypair", () => {
    const kp = generateAgentKeyPair();
    assert.ok(kp.publicKey, "Should have public key");
    assert.ok(kp.secretKey, "Should have secret key");
    assert.equal(typeof kp.publicKey, "string");
    assert.equal(typeof kp.secretKey, "string");
    // ML-DSA-65 public key is 1952 bytes = 3904 hex chars
    assert.ok(kp.publicKey.length > 1000, `Public key should be substantial (got ${kp.publicKey.length})`);
    assert.ok(kp.secretKey.length > 1000, `Secret key should be substantial (got ${kp.secretKey.length})`);
  });
});

// ---------------------------------------------------------------------------
// Credential issuance
// ---------------------------------------------------------------------------

describe("Agent Identity — credential issuance", () => {
  it("issueCredential returns credential with did:atlas: prefix", () => {
    const cred = issueCredential(
      { name: "test-agent", role: "claude-code", capabilities: ["file:read"] },
      issuerSecretKey
    );
    assert.ok(cred.agentId.startsWith("did:atlas:"), `agentId should start with did:atlas:, got ${cred.agentId}`);
    assert.equal(cred.name, "test-agent");
    assert.equal(cred.role, "claude-code");
    assert.equal(cred.version, "0.5.0");
    assert.equal(cred.revoked, false);
  });

  it("issueCredential sets correct expiry from ttlHours", () => {
    const before = Date.now();
    const cred = issueCredential(
      { name: "ttl-test", role: "observer", capabilities: [], ttlHours: 48 },
      issuerSecretKey
    );
    const after = Date.now();

    const issued = new Date(cred.issuedAt).getTime();
    const expires = new Date(cred.expiresAt).getTime();
    const ttlMs = expires - issued;

    // Should be ~48 hours (within 1 second tolerance)
    assert.ok(Math.abs(ttlMs - 48 * 60 * 60 * 1000) < 1000, `TTL should be ~48h, got ${ttlMs}ms`);
    assert.ok(issued >= before && issued <= after, "issuedAt should be within test window");
  });

  it("issueCredential defaults to 24h TTL", () => {
    const cred = issueCredential(
      { name: "default-ttl", role: "tool-caller", capabilities: ["shell:exec"] },
      issuerSecretKey
    );
    const issued = new Date(cred.issuedAt).getTime();
    const expires = new Date(cred.expiresAt).getTime();
    const ttlMs = expires - issued;

    assert.ok(Math.abs(ttlMs - 24 * 60 * 60 * 1000) < 1000, `Default TTL should be ~24h, got ${ttlMs}ms`);
  });

  it("issueCredential signs with issuerSecretKey verifiable by issuerPublicKey", () => {
    const cred = issueCredential(
      { name: "sig-test", role: "admin", capabilities: ["identity:register"] },
      issuerSecretKey
    );

    const result = verifyCredential(cred, issuerPublicKey);
    assert.equal(result.valid, true, `Should verify: ${result.reason}`);
  });
});

// ---------------------------------------------------------------------------
// Credential hash
// ---------------------------------------------------------------------------

describe("Agent Identity — credential hash", () => {
  it("credentialHash matches SHA3-256 of canonical payload", () => {
    const cred = issueCredential(
      { name: "hash-test", role: "claude-code", capabilities: ["file:read", "shell:exec"] },
      issuerSecretKey
    );

    const { issuerSignature, credentialHash, ...rest } = cred;
    const canonical = buildCanonicalPayload(rest);
    const expectedHash = createHash("sha3-256").update(canonical).digest("hex");

    assert.equal(credentialHash, expectedHash, "credentialHash should match SHA3-256(canonicalPayload)");
  });
});

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

describe("Agent Identity — verification", () => {
  it("verifyCredential returns valid: true for fresh credential", () => {
    const cred = issueCredential(
      { name: "fresh", role: "claude-code", capabilities: [] },
      issuerSecretKey
    );
    const result = verifyCredential(cred, issuerPublicKey);
    assert.equal(result.valid, true);
    assert.equal(result.agentId, cred.agentId);
    assert.equal(result.expired, false);
    assert.equal(result.revoked, false);
  });

  it("verifyCredential returns expired: true for past-expiry credential", () => {
    const cred = issueCredential(
      { name: "expired", role: "observer", capabilities: [], ttlHours: 0 },
      issuerSecretKey
    );
    // Force expiry to the past
    cred.expiresAt = new Date(Date.now() - 1000).toISOString();
    // Note: this breaks the signature, so we re-sign
    const { issuerSignature, credentialHash, ...rest } = cred;
    const canonical = buildCanonicalPayload(rest);
    cred.credentialHash = createHash("sha3-256").update(canonical).digest("hex");
    const payloadBytes = new Uint8Array(Buffer.from(canonical));
    cred.issuerSignature = Buffer.from(ml_dsa65.sign(issuerSecretKey, payloadBytes)).toString("base64");

    const result = verifyCredential(cred, issuerPublicKey);
    assert.equal(result.valid, false);
    assert.equal(result.expired, true);
  });

  it("verifyCredential returns valid: false for tampered credential", () => {
    const cred = issueCredential(
      { name: "tamper-test", role: "claude-code", capabilities: ["file:read"] },
      issuerSecretKey
    );

    // Tamper: change the name
    cred.name = "tampered-agent";

    const result = verifyCredential(cred, issuerPublicKey);
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("hash mismatch") || result.reason?.includes("tampered"), `Should detect tampering: ${result.reason}`);
  });

  it("verifyCredential returns valid: false with wrong issuer key", () => {
    const cred = issueCredential(
      { name: "wrong-key", role: "claude-code", capabilities: [] },
      issuerSecretKey
    );

    // Verify with a different key
    const otherKeys = ml_dsa65.keygen(randomBytes(32));
    const result = verifyCredential(cred, otherKeys.publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes("signature"), `Should detect wrong key: ${result.reason}`);
  });
});

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

describe("Agent Identity — revocation", () => {
  it("revokeCredential sets revoked: true and revokedAt timestamp", () => {
    const cred = issueCredential(
      { name: "revoke-me", role: "tool-caller", capabilities: ["shell:exec"] },
      issuerSecretKey
    );
    assert.equal(cred.revoked, false);

    const revoked = revokeCredential(cred, "Security concern");
    assert.equal(revoked.revoked, true);
    assert.ok(revoked.revokedAt, "Should have revokedAt timestamp");
    assert.equal(revoked.revokedReason, "Security concern");
    assert.equal(revoked.agentId, cred.agentId); // Same agent
  });

  it("verifyCredential returns revoked: true for revoked credential", () => {
    const cred = issueCredential(
      { name: "verify-revoked", role: "observer", capabilities: [] },
      issuerSecretKey
    );
    const revoked = revokeCredential(cred, "No longer needed");

    const result = verifyCredential(revoked, issuerPublicKey);
    assert.equal(result.valid, false);
    assert.equal(result.revoked, true);
  });
});

// ---------------------------------------------------------------------------
// Canonical payload
// ---------------------------------------------------------------------------

describe("Agent Identity — canonical payload", () => {
  it("buildCanonicalPayload is deterministic (same input → same output)", () => {
    const partial = {
      agentId: "did:atlas:test-123",
      name: "determinism",
      role: "claude-code" as const,
      issuedAt: "2026-03-28T00:00:00.000Z",
      expiresAt: "2026-03-29T00:00:00.000Z",
      publicKey: "abcdef",
      capabilities: ["shell:exec", "file:read"] as AgentCapability[],
      version: "0.5.0",
      revoked: false,
    };

    const payload1 = buildCanonicalPayload(partial);
    const payload2 = buildCanonicalPayload(partial);
    assert.equal(payload1, payload2, "Same input should produce identical output");
  });

  it("buildCanonicalPayload excludes issuerSignature and credentialHash", () => {
    const partial = {
      agentId: "did:atlas:test-456",
      name: "exclusion",
      role: "observer" as const,
      issuedAt: "2026-03-28T00:00:00.000Z",
      expiresAt: "2026-03-29T00:00:00.000Z",
      publicKey: "abcdef",
      capabilities: [] as AgentCapability[],
      version: "0.5.0",
      revoked: false,
    };

    const payload = buildCanonicalPayload(partial);
    assert.ok(!payload.includes("issuerSignature"), "Should not contain issuerSignature");
    assert.ok(!payload.includes("credentialHash"), "Should not contain credentialHash");
  });

  it("buildCanonicalPayload sorts capabilities for determinism", () => {
    const partial1 = {
      agentId: "did:atlas:sort-test",
      name: "sort",
      role: "claude-code" as const,
      issuedAt: "2026-03-28T00:00:00.000Z",
      expiresAt: "2026-03-29T00:00:00.000Z",
      publicKey: "abcdef",
      capabilities: ["shell:exec", "file:read"] as AgentCapability[],
      version: "0.5.0",
      revoked: false,
    };
    const partial2 = {
      ...partial1,
      capabilities: ["file:read", "shell:exec"] as AgentCapability[],
    };

    const payload1 = buildCanonicalPayload(partial1);
    const payload2 = buildCanonicalPayload(partial2);
    assert.equal(payload1, payload2, "Different capability order should produce same payload");
  });
});
