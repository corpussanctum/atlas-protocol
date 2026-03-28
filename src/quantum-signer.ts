/**
 * Fidelis Channel — Quantum Signer (ML-DSA-65)
 *
 * Post-quantum digital signatures for audit log entries using ML-DSA-65
 * (FIPS 204, formerly CRYSTALS-Dilithium). Designed for harvest-now-decrypt-later
 * threat models where audit non-repudiation must hold 10-15+ years forward.
 *
 * Key management:
 *   - Keypair auto-generated on first run and stored in the data directory
 *   - Public key hash logged at session start for key pinning
 *   - Private key never leaves the data directory
 *
 * Dependency: @noble/post-quantum (pure JS, no native bindings)
 * Graceful degradation: if the library is unavailable, signing is skipped
 * and a warning is logged.
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface QuantumKeypair {
  algorithm: string;
  nist_standard: string;
  public_key_b64: string;
  secret_key_b64: string;
  public_key_hash: string;
  created_at: string;
}

export interface QuantumSignerStatus {
  available: boolean;
  algorithm: string | null;
  public_key_hash: string | null;
  key_path: string | null;
}

// ---------------------------------------------------------------------------
// ML-DSA-65 type shim (resolved at runtime via dynamic import)
// ---------------------------------------------------------------------------

interface MlDsa65 {
  keygen: (seed?: Uint8Array) => { publicKey: Uint8Array; secretKey: Uint8Array };
  sign: (secretKey: Uint8Array, message: Uint8Array) => Uint8Array;
  verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => boolean;
}

// ---------------------------------------------------------------------------
// Quantum Signer
// ---------------------------------------------------------------------------

export class QuantumSigner {
  private ml_dsa65: MlDsa65 | null = null;
  private publicKey: Uint8Array | null = null;
  private secretKey: Uint8Array | null = null;
  private publicKeyHash: string | null = null;
  private keyPath: string | null = null;
  private _available = false;

  get available(): boolean {
    return this._available;
  }

  /**
   * Factory: initialize the signer by loading the crypto library and
   * generating or loading a keypair from the data directory.
   */
  static async create(dataDir: string): Promise<QuantumSigner> {
    const signer = new QuantumSigner();
    await signer.initialize(dataDir);
    return signer;
  }

  private async initialize(dataDir: string): Promise<void> {
    // Try to load @noble/post-quantum
    try {
      const mod = await import("@noble/post-quantum/ml-dsa");
      this.ml_dsa65 = mod.ml_dsa65 as MlDsa65;
    } catch {
      console.error(
        "[fidelis] WARNING: @noble/post-quantum not available — " +
        "audit entries will not have ML-DSA-65 signatures. " +
        "Install with: npm install @noble/post-quantum"
      );
      return;
    }

    // Load or generate keypair
    this.keyPath = join(dataDir, "quantum-keypair.json");
    this.loadOrGenerateKeypair();
    this._available = true;
  }

  private loadOrGenerateKeypair(): void {
    if (!this.ml_dsa65 || !this.keyPath) return;

    if (existsSync(this.keyPath)) {
      try {
        const raw: QuantumKeypair = JSON.parse(readFileSync(this.keyPath, "utf-8"));
        this.publicKey = Buffer.from(raw.public_key_b64, "base64");
        this.secretKey = Buffer.from(raw.secret_key_b64, "base64");
        this.publicKeyHash = raw.public_key_hash;
        return;
      } catch {
        console.error("[fidelis] WARNING: corrupt quantum keypair file, regenerating");
      }
    }

    // Generate new keypair
    const seed = randomBytes(32);
    const { publicKey, secretKey } = this.ml_dsa65.keygen(seed);

    this.publicKey = publicKey;
    this.secretKey = secretKey;
    this.publicKeyHash = createHash("sha256").update(publicKey).digest("hex");

    const keypair: QuantumKeypair = {
      algorithm: "ML-DSA-65",
      nist_standard: "FIPS 204",
      public_key_b64: Buffer.from(publicKey).toString("base64"),
      secret_key_b64: Buffer.from(secretKey).toString("base64"),
      public_key_hash: this.publicKeyHash,
      created_at: new Date().toISOString(),
    };

    // Ensure directory exists
    const dir = dirname(this.keyPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    writeFileSync(this.keyPath, JSON.stringify(keypair, null, 2), "utf-8");

    // Restrict permissions: owner read/write only
    try {
      chmodSync(this.keyPath, 0o600);
    } catch {
      // Non-fatal — may not have permission to chmod on some systems
    }

    console.error(
      `[fidelis] Generated ML-DSA-65 keypair — public key hash: ${this.publicKeyHash.slice(0, 16)}...`
    );
  }

  /**
   * Sign a payload with ML-DSA-65. Returns base64-encoded signature,
   * or undefined if signing is not available.
   */
  sign(payload: Buffer): string | undefined {
    if (!this._available || !this.ml_dsa65 || !this.secretKey) return undefined;
    const sig = this.ml_dsa65.sign(this.secretKey, new Uint8Array(payload));
    return Buffer.from(sig).toString("base64");
  }

  /**
   * Verify an ML-DSA-65 signature. Returns true if valid, false if invalid
   * or if verification is not available.
   */
  verify(payload: Buffer, signatureB64: string): boolean {
    if (!this._available || !this.ml_dsa65 || !this.publicKey) return false;
    try {
      const sig = Buffer.from(signatureB64, "base64");
      return this.ml_dsa65.verify(this.publicKey, new Uint8Array(payload), new Uint8Array(sig));
    } catch {
      return false;
    }
  }

  /**
   * Get the SHA-256 hash of the public key (for key pinning in audit logs).
   */
  getPublicKeyHash(): string | null {
    return this.publicKeyHash;
  }

  /**
   * Get runtime status for the fidelis_status tool.
   */
  getStatus(): QuantumSignerStatus {
    return {
      available: this._available,
      algorithm: this._available ? "ML-DSA-65" : null,
      public_key_hash: this.publicKeyHash,
      key_path: this.keyPath,
    };
  }

  /**
   * Get the raw public key bytes (for credential verification).
   */
  getPublicKeyRaw(): Uint8Array | null {
    return this.publicKey;
  }

  /**
   * Get the raw secret key bytes (for credential signing).
   * Handle with care — this is the gatekeeper's issuer key.
   */
  getSecretKeyRaw(): Uint8Array | null {
    return this.secretKey;
  }

  /**
   * Load a public key from base64 for verification-only mode
   * (e.g., verifying logs signed by another instance).
   */
  loadPublicKey(publicKeyB64: string): void {
    if (!this.ml_dsa65) return;
    this.publicKey = Buffer.from(publicKeyB64, "base64");
    this.publicKeyHash = createHash("sha256").update(this.publicKey).digest("hex");
  }
}
