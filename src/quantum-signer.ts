/**
 * Atlas Protocol — Quantum Signer (ML-DSA-65)
 *
 * Post-quantum digital signatures for audit log entries using ML-DSA-65
 * (FIPS 204, formerly CRYSTALS-Dilithium). Designed for harvest-now-decrypt-later
 * threat models where audit non-repudiation must hold 10-15+ years forward.
 *
 * Key management:
 *   - Keypair auto-generated on first run and stored in the data directory
 *   - With a keystore passphrase (ATLAS_KEYSTORE_PASSPHRASE) the secret key
 *     is stored wrapped in quantum-keypair.enc.json (scrypt → AES-256-GCM, as
 *     for agent keys), and a plaintext quantum-keypair.json is migrated on
 *     start (#45). A missing or wrong passphrase for a wrapped key, or an
 *     unreadable key file, throws IssuerKeyError: the key is never silently
 *     regenerated, since a new key invalidates every credential.
 *   - Public key hash logged at session start for key pinning
 *   - The secret key is held in a private field and never exported
 *   - Rotation (SPEC §4.5): generate new key, log KEY_ROTATION signed by the
 *     old key, archive old public keys (last 3) for historical verification
 *
 * Hashing:
 *   - `public_key_hash` is SHA-256 (stable SESSION_START pinning field)
 *   - KEY_ROTATION `old_key_hash` / `new_key_hash` are SHA3-256 per SPEC §4.5
 *
 * Dependency: @noble/post-quantum (pure JS, no native bindings)
 * Graceful degradation: if the library is unavailable, signing is skipped
 * and a warning is logged.
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync, renameSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { deriveKey, keyIdFor, SCRYPT_PARAMS } from "./operator-key.js";
import { unwrapSecret, wrapSecret, type SignerProvider, type WrappedSecret } from "./signer-provider.js";

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

/** quantum-keypair.enc.json: the issuer key wrapped under the keystore passphrase (#45). */
export interface WrappedIssuerKeypair {
  version: 1;
  algorithm: "ML-DSA-65";
  nist_standard: string;
  public_key_b64: string;
  public_key_hash: string;
  created_at: string;
  kdf: { name: "scrypt"; N: number; r: number; p: number; salt: string };
  cipher: { name: "aes-256-gcm" } & WrappedSecret;
}

export type IssuerKeyStorage = "wrapped" | "plaintext";

export interface QuantumSignerStatus {
  available: boolean;
  algorithm: string | null;
  public_key_hash: string | null;
  public_key_hash_sha3: string | null;
  key_path: string | null;
  /** How the issuer secret key is stored at rest (#45) */
  key_storage: IssuerKeyStorage | null;
  archived_key_count: number;
}

export interface QuantumSignerOptions {
  /** Keystore passphrase (ATLAS_KEYSTORE_PASSPHRASE). Set: store the key wrapped. */
  passphrase?: string;
}

/** The issuer key can't be loaded. Startup must stop rather than generate a new key. */
export class IssuerKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IssuerKeyError";
  }
}

export const ISSUER_KEY_FILE = "quantum-keypair.json";
export const ISSUER_KEY_WRAPPED_FILE = "quantum-keypair.enc.json";
const ISSUER_LABEL = "atlas-issuer";

/** True when the data dir holds a wrapped issuer key, which needs the passphrase to load. */
export function issuerKeyIsWrapped(dataDir: string): boolean {
  return existsSync(join(dataDir, ISSUER_KEY_WRAPPED_FILE));
}

/** Archived issuer public key retained for historical audit verification. */
export interface ArchivedPublicKey {
  public_key_b64: string;
  /** SHA-256 of the public key (matches SESSION_START pq_public_key_hash). */
  public_key_hash: string;
  /** SHA3-256 of the public key (SPEC §4.5 KEY_ROTATION hashes). */
  public_key_hash_sha3: string;
  created_at: string;
  archived_at: string;
}

/**
 * A newly generated keypair that has not yet been activated.
 * Sign KEY_ROTATION with the current (old) key, re-issue credentials with
 * `newSecretKey`, then call `commitRotation`.
 */
export interface PreparedRotation {
  oldKeyHash: string;
  oldKeyHashSha3: string;
  newKeyHash: string;
  newKeyHashSha3: string;
  newPublicKeyB64: string;
  newPublicKey: Uint8Array;
  newSecretKey: Uint8Array;
  effectiveAt: string;
}

const MAX_ARCHIVED_KEYS = 3;

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function sha3Hex(data: Uint8Array): string {
  return createHash("sha3-256").update(data).digest("hex");
}

/** Write via a temp file and rename, so a crash never leaves a half-written key. */
function writeAtomic(path: string, contents: string): void {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, contents, { mode: 0o600 });
  try {
    chmodSync(tmp, 0o600);
  } catch {
    // Non-fatal on restricted filesystems
  }
  renameSync(tmp, path);
}

function writeRestricted(path: string, contents: string): void {
  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(path, contents, "utf-8");
  try {
    chmodSync(path, 0o600);
  } catch {
    // Non-fatal — may not have permission to chmod on some systems
  }
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
  #secretKey: Uint8Array | null = null;
  /** Key-encryption key and its scrypt salt, when the key is stored wrapped */
  #kek: { key: Buffer; salt: Buffer } | null = null;
  private publicKeyHash: string | null = null;
  private publicKeyHashSha3: string | null = null;
  private keyCreatedAt: string | null = null;
  private keyPath: string | null = null;
  private wrappedPath: string | null = null;
  private archivePath: string | null = null;
  private archivedPublicKeys: ArchivedPublicKey[] = [];
  private _available = false;

  get available(): boolean {
    return this._available;
  }

  /**
   * Factory: initialize the signer by loading the crypto library and
   * generating or loading a keypair from the data directory.
   * Throws IssuerKeyError when an existing key can't be loaded.
   */
  static async create(dataDir: string, options: QuantumSignerOptions = {}): Promise<QuantumSigner> {
    const signer = new QuantumSigner();
    await signer.initialize(dataDir, options.passphrase || undefined);
    return signer;
  }

  private async initialize(dataDir: string, passphrase: string | undefined): Promise<void> {
    // Try to load @noble/post-quantum
    try {
      const mod = await import("@noble/post-quantum/ml-dsa");
      this.ml_dsa65 = mod.ml_dsa65 as MlDsa65;
    } catch {
      console.error(
        "[atlas] WARNING: @noble/post-quantum not available — " +
        "audit entries will not have ML-DSA-65 signatures. " +
        "Install with: npm install @noble/post-quantum"
      );
      return;
    }

    // Load or generate keypair
    this.keyPath = join(dataDir, ISSUER_KEY_FILE);
    this.wrappedPath = join(dataDir, ISSUER_KEY_WRAPPED_FILE);
    this.archivePath = join(dataDir, "quantum-key-archive.json");
    this.loadOrGenerateKeypair(passphrase);
    this.loadArchive();
    this._available = true;
  }

  private loadOrGenerateKeypair(passphrase: string | undefined): void {
    if (!this.ml_dsa65 || !this.keyPath || !this.wrappedPath) return;
    const hasWrapped = existsSync(this.wrappedPath);
    const hasPlain = existsSync(this.keyPath);

    if (hasWrapped) {
      if (!passphrase) {
        throw new IssuerKeyError(
          `The issuer key ${this.wrappedPath} is encrypted; set ATLAS_KEYSTORE_PASSPHRASE to the keystore passphrase`,
        );
      }
      this.loadWrapped(passphrase);
      if (hasPlain) {
        // An interrupted migration left both copies; drop the plaintext only if they agree.
        const plain = this.readPlaintext();
        if (Buffer.compare(Buffer.from(plain.public_key_b64, "base64"), Buffer.from(this.publicKey!)) !== 0) {
          throw new IssuerKeyError(
            `${this.keyPath} and ${this.wrappedPath} hold different issuer keys; remove the one that is not current`,
          );
        }
        unlinkSync(this.keyPath);
      }
      return;
    }

    if (hasPlain) {
      const raw = this.readPlaintext();
      this.publicKey = Buffer.from(raw.public_key_b64, "base64");
      this.#secretKey = Buffer.from(raw.secret_key_b64, "base64");
      this.publicKeyHash = raw.public_key_hash || sha256Hex(this.publicKey);
      this.publicKeyHashSha3 = sha3Hex(this.publicKey);
      this.keyCreatedAt = raw.created_at ?? null;
      if (passphrase) {
        this.wrapWith(passphrase);
        console.error(`[atlas] Issuer key migrated to ${this.wrappedPath} (encrypted); plaintext copy removed`);
      }
      return;
    }

    // First run: generate a new keypair
    const seed = randomBytes(32);
    const { publicKey, secretKey } = this.ml_dsa65.keygen(seed);

    this.publicKey = publicKey;
    this.#secretKey = secretKey;
    this.publicKeyHash = sha256Hex(publicKey);
    this.publicKeyHashSha3 = sha3Hex(publicKey);
    this.keyCreatedAt = new Date().toISOString();

    if (passphrase) {
      this.wrapWith(passphrase);
    } else {
      this.persistCurrentKeypair();
    }

    console.error(
      `[atlas] Generated ML-DSA-65 keypair — public key hash: ${this.publicKeyHash.slice(0, 16)}...`
    );
  }

  private readPlaintext(): QuantumKeypair {
    try {
      const raw = JSON.parse(readFileSync(this.keyPath!, "utf-8")) as QuantumKeypair;
      if (typeof raw.public_key_b64 !== "string" || typeof raw.secret_key_b64 !== "string") {
        throw new Error("missing key fields");
      }
      return raw;
    } catch (err) {
      throw new IssuerKeyError(
        `The issuer key ${this.keyPath} is unreadable (${err instanceof Error ? err.message : String(err)}). ` +
          "Restore it from backup; a new key would invalidate every credential.",
      );
    }
  }

  private loadWrapped(passphrase: string): void {
    let file: WrappedIssuerKeypair;
    try {
      file = JSON.parse(readFileSync(this.wrappedPath!, "utf-8")) as WrappedIssuerKeypair;
      if (file.version !== 1 || file.kdf?.name !== "scrypt" || file.cipher?.name !== "aes-256-gcm") {
        throw new Error("unsupported format");
      }
    } catch (err) {
      throw new IssuerKeyError(
        `The issuer key ${this.wrappedPath} is unreadable (${err instanceof Error ? err.message : String(err)})`,
      );
    }
    const salt = Buffer.from(file.kdf.salt, "base64");
    const kek = deriveKey(passphrase, salt, file.kdf);
    const publicKey = Buffer.from(file.public_key_b64, "base64");
    let secretKey: Buffer;
    try {
      secretKey = unwrapSecret(kek, ISSUER_LABEL, file.cipher, publicKey);
    } catch {
      throw new IssuerKeyError(
        `Wrong ATLAS_KEYSTORE_PASSPHRASE for the issuer key ${this.wrappedPath} (or the file was modified)`,
      );
    }
    this.publicKey = publicKey;
    this.#secretKey = secretKey;
    this.#kek = { key: kek, salt };
    this.publicKeyHash = file.public_key_hash || sha256Hex(publicKey);
    this.publicKeyHashSha3 = sha3Hex(publicKey);
    this.keyCreatedAt = file.created_at ?? null;
  }

  /**
   * Store the current key wrapped under a key derived from `passphrase`
   * (fresh salt), check that it reads back, then remove any plaintext copy.
   */
  private wrapWith(passphrase: string): void {
    const salt = randomBytes(16);
    this.#kek = { key: deriveKey(passphrase, salt, SCRYPT_PARAMS), salt };
    this.persistWrapped();
    const check = new QuantumSigner();
    check.ml_dsa65 = this.ml_dsa65;
    check.wrappedPath = this.wrappedPath;
    check.loadWrapped(passphrase);
    const same = Buffer.compare(Buffer.from(check.#secretKey!), Buffer.from(this.#secretKey!)) === 0;
    check.#secretKey!.fill(0);
    if (!same) throw new IssuerKeyError(`The wrapped issuer key ${this.wrappedPath} did not read back correctly`);
    if (this.keyPath && existsSync(this.keyPath)) unlinkSync(this.keyPath);
  }

  private persistWrapped(): void {
    if (!this.wrappedPath || !this.#kek || !this.publicKey || !this.#secretKey || !this.publicKeyHash) return;
    const file: WrappedIssuerKeypair = {
      version: 1,
      algorithm: "ML-DSA-65",
      nist_standard: "FIPS 204",
      public_key_b64: Buffer.from(this.publicKey).toString("base64"),
      public_key_hash: this.publicKeyHash,
      created_at: this.keyCreatedAt ?? new Date().toISOString(),
      kdf: { name: "scrypt", ...SCRYPT_PARAMS, salt: this.#kek.salt.toString("base64") },
      cipher: { name: "aes-256-gcm", ...wrapSecret(this.#kek.key, ISSUER_LABEL, this.#secretKey, this.publicKey) },
    };
    writeAtomic(this.wrappedPath, JSON.stringify(file, null, 2));
  }

  private persistCurrentKeypair(): void {
    if (this.#kek) {
      this.persistWrapped();
      return;
    }
    if (!this.keyPath || !this.publicKey || !this.#secretKey || !this.publicKeyHash) return;

    const keypair: QuantumKeypair = {
      algorithm: "ML-DSA-65",
      nist_standard: "FIPS 204",
      public_key_b64: Buffer.from(this.publicKey).toString("base64"),
      secret_key_b64: Buffer.from(this.#secretKey).toString("base64"),
      public_key_hash: this.publicKeyHash,
      created_at: this.keyCreatedAt ?? new Date().toISOString(),
    };

    writeRestricted(this.keyPath, JSON.stringify(keypair, null, 2));
  }

  /**
   * Re-wrap the issuer key under a new passphrase (operator command). Also
   * encrypts a key still stored in plaintext. A server already running keeps
   * the old key-encryption key, so stop it first: a rotation there would
   * re-wrap under the old passphrase.
   */
  rewrap(newPassphrase: string): void {
    if (!this._available || !this.#secretKey) throw new IssuerKeyError("No issuer key loaded");
    this.wrapWith(newPassphrase);
  }

  private loadArchive(): void {
    if (!this.archivePath || !existsSync(this.archivePath)) {
      this.archivedPublicKeys = [];
      return;
    }
    try {
      const raw = JSON.parse(readFileSync(this.archivePath, "utf-8"));
      const keys: ArchivedPublicKey[] = Array.isArray(raw?.keys) ? raw.keys : [];
      this.archivedPublicKeys = keys.slice(0, MAX_ARCHIVED_KEYS);
    } catch {
      console.error("[atlas] WARNING: corrupt quantum key archive, starting empty");
      this.archivedPublicKeys = [];
    }
  }

  private persistArchive(): void {
    if (!this.archivePath) return;
    writeRestricted(
      this.archivePath,
      JSON.stringify({ keys: this.archivedPublicKeys }, null, 2)
    );
  }

  /**
   * Sign a payload with ML-DSA-65. Returns base64-encoded signature,
   * or undefined if signing is not available.
   */
  sign(payload: Buffer): string | undefined {
    if (!this._available || !this.ml_dsa65 || !this.#secretKey) return undefined;
    const sig = this.ml_dsa65.sign(this.#secretKey, new Uint8Array(payload));
    return Buffer.from(sig).toString("base64");
  }

  /**
   * Verify an ML-DSA-65 signature. Returns true if valid, false if invalid
   * or if verification is not available.
   */
  verify(payload: Buffer, signatureB64: string): boolean {
    if (!this._available || !this.ml_dsa65) return false;
    try {
      const sig = new Uint8Array(Buffer.from(signatureB64, "base64"));
      const msg = new Uint8Array(payload);
      if (this.publicKey && this.ml_dsa65.verify(this.publicKey, msg, sig)) {
        return true;
      }
      // SPEC §4.5: historical entries verify against retained old public keys
      for (const archived of this.archivedPublicKeys) {
        const pk = new Uint8Array(Buffer.from(archived.public_key_b64, "base64"));
        if (this.ml_dsa65.verify(pk, msg, sig)) return true;
      }
      return false;
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
   * SHA3-256 hash of the current public key (SPEC §4.5 KEY_ROTATION hashes).
   */
  getPublicKeyHashSha3(): string | null {
    return this.publicKeyHashSha3;
  }

  /**
   * Retained old issuer public keys (most recent first, max 3).
   */
  getArchivedPublicKeys(): ArchivedPublicKey[] {
    return [...this.archivedPublicKeys];
  }

  /**
   * Generate a new ML-DSA-65 keypair without activating it.
   * Sign the KEY_ROTATION audit entry with the current key, re-issue
   * credentials with `prepared.newSecretKey`, then `commitRotation`.
   */
  beginRotation(): PreparedRotation {
    if (!this._available || !this.ml_dsa65 || !this.publicKey || !this.#secretKey) {
      throw new Error("Cannot rotate — quantum signer is not available");
    }
    if (!this.publicKeyHash || !this.publicKeyHashSha3) {
      throw new Error("Cannot rotate — current public key hash unavailable");
    }

    const seed = randomBytes(32);
    const { publicKey, secretKey } = this.ml_dsa65.keygen(seed);

    return {
      oldKeyHash: this.publicKeyHash,
      oldKeyHashSha3: this.publicKeyHashSha3,
      newKeyHash: sha256Hex(publicKey),
      newKeyHashSha3: sha3Hex(publicKey),
      newPublicKeyB64: Buffer.from(publicKey).toString("base64"),
      newPublicKey: publicKey,
      newSecretKey: secretKey,
      effectiveAt: new Date().toISOString(),
    };
  }

  /**
   * Activate a prepared rotation: archive the old public key (keep last 3),
   * switch signing to the new keypair, persist both files.
   */
  commitRotation(prepared: PreparedRotation): void {
    if (!this.publicKey || !this.publicKeyHash) {
      throw new Error("Cannot commit rotation — no current keypair");
    }

    const archived: ArchivedPublicKey = {
      public_key_b64: Buffer.from(this.publicKey).toString("base64"),
      public_key_hash: this.publicKeyHash,
      public_key_hash_sha3: this.publicKeyHashSha3 ?? sha3Hex(this.publicKey),
      created_at: this.keyCreatedAt ?? new Date().toISOString(),
      archived_at: prepared.effectiveAt,
    };
    this.archivedPublicKeys = [archived, ...this.archivedPublicKeys].slice(0, MAX_ARCHIVED_KEYS);
    this.persistArchive();

    this.publicKey = prepared.newPublicKey;
    this.#secretKey = prepared.newSecretKey;
    this.publicKeyHash = prepared.newKeyHash;
    this.publicKeyHashSha3 = prepared.newKeyHashSha3;
    this.keyCreatedAt = prepared.effectiveAt;
    this.persistCurrentKeypair();

    console.error(
      `[atlas] ML-DSA-65 key rotated — new public key hash: ${this.publicKeyHash.slice(0, 16)}...`
    );
  }

  /**
   * Get runtime status for the atlas_status tool.
   */
  getStatus(): QuantumSignerStatus {
    return {
      available: this._available,
      algorithm: this._available ? "ML-DSA-65" : null,
      public_key_hash: this.publicKeyHash,
      public_key_hash_sha3: this.publicKeyHashSha3,
      key_path: this.#kek ? this.wrappedPath : this.keyPath,
      key_storage: this._available ? (this.#kek ? "wrapped" : "plaintext") : null,
      archived_key_count: this.archivedPublicKeys.length,
    };
  }

  /**
   * Get the raw public key bytes (for credential verification).
   */
  getPublicKeyRaw(): Uint8Array | null {
    return this.publicKey;
  }

  /**
   * The issuer key as a SignerProvider (#4), for credential issuance. It signs
   * with whichever key is current, so it stays valid across rotation.
   * Null when signing is unavailable.
   */
  asSignerProvider(): SignerProvider | null {
    if (!this._available || !this.ml_dsa65 || !this.#secretKey || !this.publicKey) return null;
    const self = this;
    return {
      get id() { return self.publicKey ? keyIdFor(self.publicKey) : ""; },
      algorithm: "ML-DSA-65",
      capabilities: { durable: true },
      publicKey: () => Uint8Array.from(self.publicKey ?? []),
      sign(message: Uint8Array): Uint8Array {
        if (!self.ml_dsa65 || !self.#secretKey) throw new Error("Issuer key unavailable");
        return self.ml_dsa65.sign(self.#secretKey, message);
      },
    };
  }

  /**
   * Load a public key from base64 for verification-only mode
   * (e.g., verifying logs signed by another instance).
   */
  loadPublicKey(publicKeyB64: string): void {
    if (!this.ml_dsa65) return;
    this.publicKey = Buffer.from(publicKeyB64, "base64");
    this.publicKeyHash = sha256Hex(this.publicKey);
    this.publicKeyHashSha3 = sha3Hex(this.publicKey);
  }
}
