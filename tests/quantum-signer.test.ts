/**
 * Tests for Atlas Protocol — Quantum Signer (ML-DSA-65)
 *
 * Covers: keypair generation/persistence, signing, verification,
 * tamper detection, and graceful degradation.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { QuantumSigner } from "../src/quantum-signer.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-quantum-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
  tempDirs = [];
});

// ---------------------------------------------------------------------------
// Keypair generation and persistence
// ---------------------------------------------------------------------------

describe("QuantumSigner — keypair management", () => {
  it("generates a keypair on first initialization", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir);

    assert.ok(signer.available, "Signer should be available after initialization");
    assert.ok(signer.getPublicKeyHash(), "Public key hash should be set");
    assert.equal(signer.getPublicKeyHash()!.length, 64, "SHA-256 hash should be 64 hex chars");

    // Keypair file should exist
    const keyPath = join(dir, "quantum-keypair.json");
    assert.ok(existsSync(keyPath), "Keypair file should be created");

    // Keypair file should contain valid JSON
    const raw = JSON.parse(readFileSync(keyPath, "utf-8"));
    assert.equal(raw.algorithm, "ML-DSA-65");
    assert.equal(raw.nist_standard, "FIPS 204");
    assert.ok(raw.public_key_b64, "Should have base64 public key");
    assert.ok(raw.secret_key_b64, "Should have base64 secret key");
    assert.ok(raw.public_key_hash, "Should have public key hash");
    assert.ok(raw.created_at, "Should have creation timestamp");
  });

  it("reloads existing keypair on subsequent initialization", async () => {
    const dir = makeTempDir();

    const signer1 = await QuantumSigner.create(dir);
    const hash1 = signer1.getPublicKeyHash();

    const signer2 = await QuantumSigner.create(dir);
    const hash2 = signer2.getPublicKeyHash();

    assert.equal(hash1, hash2, "Same keypair should produce same public key hash");
  });

  it("reports status correctly", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir);
    const status = signer.getStatus();

    assert.equal(status.available, true);
    assert.equal(status.algorithm, "ML-DSA-65");
    assert.ok(status.public_key_hash);
    assert.ok(status.key_path);
  });
});

// ---------------------------------------------------------------------------
// Signing and verification
// ---------------------------------------------------------------------------

describe("QuantumSigner — sign and verify", () => {
  it("signs a payload and produces a base64 signature", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir);

    const payload = Buffer.from("test audit entry content");
    const sig = signer.sign(payload);

    assert.ok(sig, "Should produce a signature");
    assert.equal(typeof sig, "string");

    // ML-DSA-65 signatures are ~3309 bytes, base64 encoded ~4412 chars
    assert.ok(sig!.length > 1000, `Signature should be substantial (got ${sig!.length} chars)`);
  });

  it("verifies a valid signature", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir);

    const payload = Buffer.from('{"event":"POLICY_DENY","tool":"Bash","input":"rm -rf /"}');
    const sig = signer.sign(payload)!;

    const valid = signer.verify(payload, sig);
    assert.equal(valid, true, "Signature should verify");
  });

  it("rejects a signature for a different payload", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir);

    const payload1 = Buffer.from("original content");
    const payload2 = Buffer.from("tampered content");
    const sig = signer.sign(payload1)!;

    const valid = signer.verify(payload2, sig);
    assert.equal(valid, false, "Signature should not verify for different payload");
  });

  it("rejects a corrupted signature", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir);

    const payload = Buffer.from("test content");
    const sig = signer.sign(payload)!;

    // Corrupt the signature (flip some base64 chars)
    const corrupted = sig.slice(0, -10) + "AAAAAAAAAA";

    const valid = signer.verify(payload, corrupted);
    assert.equal(valid, false, "Corrupted signature should not verify");
  });

  it("cross-instance verification works with same keypair", async () => {
    const dir = makeTempDir();

    const signer1 = await QuantumSigner.create(dir);
    const payload = Buffer.from("signed by instance 1");
    const sig = signer1.sign(payload)!;

    // Create a second instance that loads the same keypair
    const signer2 = await QuantumSigner.create(dir);
    const valid = signer2.verify(payload, sig);
    assert.equal(valid, true, "Second instance should verify signature from first");
  });

  it("cross-instance verification fails with different keypair", async () => {
    const dir1 = makeTempDir();
    const dir2 = makeTempDir();

    const signer1 = await QuantumSigner.create(dir1);
    const signer2 = await QuantumSigner.create(dir2);

    const payload = Buffer.from("signed by instance 1");
    const sig = signer1.sign(payload)!;

    const valid = signer2.verify(payload, sig);
    assert.equal(valid, false, "Different keypair should not verify");
  });
});

// ---------------------------------------------------------------------------
// Public key loading
// ---------------------------------------------------------------------------

describe("QuantumSigner — public key loading", () => {
  it("can load a public key for verification-only mode", async () => {
    const dir1 = makeTempDir();
    const dir2 = makeTempDir();

    // Generate keypair and sign
    const signer1 = await QuantumSigner.create(dir1);
    const payload = Buffer.from("verification-only test");
    const sig = signer1.sign(payload)!;

    // Load public key from keypair file
    const keypairFile = join(dir1, "quantum-keypair.json");
    const keypair = JSON.parse(readFileSync(keypairFile, "utf-8"));

    // Create verifier with different data dir, load public key
    const verifier = await QuantumSigner.create(dir2);
    verifier.loadPublicKey(keypair.public_key_b64);

    const valid = verifier.verify(payload, sig);
    assert.equal(valid, true, "Should verify with loaded public key");
  });
});
