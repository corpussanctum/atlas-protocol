/**
 * Atlas Protocol — Signer providers and the agent keystore (#4)
 *
 * A SignerProvider signs with an ML-DSA-65 key it never exports. Two
 * implementations:
 *
 *   - EphemeralSigner: key in process memory only. A gatekeeper restart
 *     loses it, so delegation from that agent stops working.
 *   - FileBackedEncryptedSigner: key wrapped at rest (scrypt → AES-256-GCM,
 *     file mode 0600, directory 0700) under a key-encryption key derived
 *     from ATLAS_KEYSTORE_PASSPHRASE, and unwrapped into memory on load.
 *
 * AgentKeyStore holds one provider per agent. With a passphrase it is
 * durable: new agent keys are written encrypted and reloaded after a
 * restart. Without one (or with the wrong one) it behaves as before:
 * keys live in memory only, and any key files on disk are left untouched.
 *
 * Custody limit: the passphrase is in the gatekeeper's environment, which
 * the governed agent may be able to read when both run as the same OS user.
 * Wrapping protects keys in backups and copies of the data directory; the
 * separate-user deployment (#23) is what keeps the agent from the key.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { deriveKey, keyIdFor, loadMlDsa, SCRYPT_PARAMS } from "./operator-key.js";

type MlDsa65 = Awaited<ReturnType<typeof loadMlDsa>>;

export interface SignerCapabilities {
  /** The key survives a gatekeeper restart. */
  durable: boolean;
}

export interface SignerProvider {
  /** First 16 hex chars of SHA3-256(public key) */
  readonly id: string;
  readonly algorithm: "ML-DSA-65";
  readonly capabilities: SignerCapabilities;
  publicKey(): Uint8Array;
  sign(message: Uint8Array): Uint8Array;
}

class InMemorySigner implements SignerProvider {
  readonly id: string;
  readonly algorithm = "ML-DSA-65" as const;
  readonly #secretKey: Uint8Array;
  readonly #publicKey: Uint8Array;

  constructor(
    private readonly dsa: MlDsa65,
    secretKey: Uint8Array,
    publicKey: Uint8Array,
    readonly capabilities: SignerCapabilities,
  ) {
    this.#secretKey = Uint8Array.from(secretKey);
    this.#publicKey = Uint8Array.from(publicKey);
    this.id = keyIdFor(publicKey);
  }

  publicKey(): Uint8Array {
    return Uint8Array.from(this.#publicKey);
  }

  sign(message: Uint8Array): Uint8Array {
    return this.dsa.sign(this.#secretKey, message);
  }
}

export class EphemeralSigner extends InMemorySigner {
  constructor(dsa: MlDsa65, secretKey: Uint8Array, publicKey: Uint8Array) {
    super(dsa, secretKey, publicKey, { durable: false });
  }
}

// ---------------------------------------------------------------------------
// Encrypted file format
// ---------------------------------------------------------------------------

interface WrappedKey {
  version: 1;
  algorithm: "ML-DSA-65";
  /** Owner label bound into the AEAD (e.g. the agent's DID) */
  label: string;
  public_key: string; // hex
  cipher: { name: "aes-256-gcm"; iv: string; tag: string; ciphertext: string };
}

const aad = (label: string, publicKeyHex: string) => Buffer.from(`${label}\n${publicKeyHex}`);

function writePrivate(path: string, contents: string): void {
  writeFileSync(path, contents, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // Non-fatal on restricted filesystems
  }
}

export interface WrappedSecret {
  iv: string;
  tag: string;
  ciphertext: string;
}

/**
 * AES-256-GCM wrap of a secret key, bound to `label` and the public key.
 * Shared by agent keys and the issuer key (#45).
 */
export function wrapSecret(kek: Buffer, label: string, secretKey: Uint8Array, publicKey: Uint8Array): WrappedSecret {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", kek, iv);
  cipher.setAAD(aad(label, Buffer.from(publicKey).toString("hex")));
  const ciphertext = Buffer.concat([cipher.update(secretKey), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

/** Inverse of `wrapSecret`. Throws on a wrong key, tampering, or a label/public-key mismatch. */
export function unwrapSecret(kek: Buffer, label: string, wrapped: WrappedSecret, publicKey: Uint8Array): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", kek, Buffer.from(wrapped.iv, "base64"));
  decipher.setAAD(aad(label, Buffer.from(publicKey).toString("hex")));
  decipher.setAuthTag(Buffer.from(wrapped.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(wrapped.ciphertext, "base64")), decipher.final()]);
}

export class FileBackedEncryptedSigner extends InMemorySigner {
  private constructor(dsa: MlDsa65, secretKey: Uint8Array, publicKey: Uint8Array) {
    super(dsa, secretKey, publicKey, { durable: true });
  }

  /** Wrap `secretKey` under `kek` and write it to `path`. */
  static create(
    path: string,
    label: string,
    dsa: MlDsa65,
    kek: Buffer,
    secretKey: Uint8Array,
    publicKey: Uint8Array,
  ): FileBackedEncryptedSigner {
    const wrapped: WrappedKey = {
      version: 1,
      algorithm: "ML-DSA-65",
      label,
      public_key: Buffer.from(publicKey).toString("hex"),
      cipher: { name: "aes-256-gcm", ...wrapSecret(kek, label, secretKey, publicKey) },
    };
    writePrivate(path, JSON.stringify(wrapped, null, 2));
    return new FileBackedEncryptedSigner(dsa, secretKey, publicKey);
  }

  /** Unwrap the key at `path`. Throws if it is missing, tampered, or bound to another label. */
  static load(path: string, label: string, dsa: MlDsa65, kek: Buffer): FileBackedEncryptedSigner {
    const wrapped = JSON.parse(readFileSync(path, "utf-8")) as WrappedKey;
    if (wrapped.version !== 1 || wrapped.algorithm !== "ML-DSA-65" || wrapped.cipher?.name !== "aes-256-gcm") {
      throw new Error("Unsupported wrapped key format");
    }
    if (wrapped.label !== label) throw new Error("Wrapped key belongs to a different owner");
    const publicKey = Buffer.from(wrapped.public_key, "hex");
    const secretKey = unwrapSecret(kek, label, wrapped.cipher, publicKey);
    try {
      return new FileBackedEncryptedSigner(dsa, secretKey, publicKey);
    } finally {
      secretKey.fill(0);
    }
  }
}

// ---------------------------------------------------------------------------
// Agent keystore
// ---------------------------------------------------------------------------

export const AGENT_KEYS_DIR = "agent-keys";
const KEYSTORE_META = "keystore.json";
const CHECK_PLAINTEXT = "atlas-agent-keystore-v1";

interface KeystoreMeta {
  version: 1;
  kdf: { name: "scrypt"; N: number; r: number; p: number; salt: string };
  check: { iv: string; tag: string; ciphertext: string };
}

export type KeystoreMode =
  | { durable: true }
  | { durable: false; reason: "NO_PASSPHRASE" | "WRONG_PASSPHRASE" | "UNREADABLE" };

export class AgentKeyStore {
  private readonly signers = new Map<string, SignerProvider>();

  private constructor(
    private readonly dir: string,
    private readonly dsa: MlDsa65,
    private readonly kek: Buffer | null,
    readonly mode: KeystoreMode,
  ) {}

  /**
   * Open the keystore under `dataDir`. A missing passphrase, a wrong one, or
   * an unreadable keystore yields an in-memory store (never an exception), so
   * the gatekeeper still starts; `mode` says why.
   */
  static async open(dataDir: string, passphrase: string | undefined): Promise<AgentKeyStore> {
    const dsa = await loadMlDsa();
    const dir = join(dataDir, AGENT_KEYS_DIR);
    if (!passphrase) return new AgentKeyStore(dir, dsa, null, { durable: false, reason: "NO_PASSPHRASE" });

    const metaPath = join(dir, KEYSTORE_META);
    try {
      if (!existsSync(metaPath)) {
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const salt = randomBytes(16);
        const kek = deriveKey(passphrase, salt, SCRYPT_PARAMS);
        const iv = randomBytes(12);
        const cipher = createCipheriv("aes-256-gcm", kek, iv);
        const ciphertext = Buffer.concat([cipher.update(CHECK_PLAINTEXT), cipher.final()]);
        const meta: KeystoreMeta = {
          version: 1,
          kdf: { name: "scrypt", ...SCRYPT_PARAMS, salt: salt.toString("base64") },
          check: {
            iv: iv.toString("base64"),
            tag: cipher.getAuthTag().toString("base64"),
            ciphertext: ciphertext.toString("base64"),
          },
        };
        writePrivate(metaPath, JSON.stringify(meta, null, 2));
        return new AgentKeyStore(dir, dsa, kek, { durable: true });
      }

      const meta = JSON.parse(readFileSync(metaPath, "utf-8")) as KeystoreMeta;
      if (meta.version !== 1 || meta.kdf?.name !== "scrypt") {
        return new AgentKeyStore(dir, dsa, null, { durable: false, reason: "UNREADABLE" });
      }
      const kek = deriveKey(passphrase, Buffer.from(meta.kdf.salt, "base64"), meta.kdf);
      try {
        const decipher = createDecipheriv("aes-256-gcm", kek, Buffer.from(meta.check.iv, "base64"));
        decipher.setAuthTag(Buffer.from(meta.check.tag, "base64"));
        const check = Buffer.concat([
          decipher.update(Buffer.from(meta.check.ciphertext, "base64")),
          decipher.final(),
        ]).toString();
        if (check !== CHECK_PLAINTEXT) throw new Error("check mismatch");
      } catch {
        return new AgentKeyStore(dir, dsa, null, { durable: false, reason: "WRONG_PASSPHRASE" });
      }
      return new AgentKeyStore(dir, dsa, kek, { durable: true });
    } catch {
      return new AgentKeyStore(dir, dsa, null, { durable: false, reason: "UNREADABLE" });
    }
  }

  private pathFor(agentId: string): string {
    return join(this.dir, `${createHash("sha3-256").update(agentId).digest("hex").slice(0, 32)}.json`);
  }

  /**
   * Take custody of a freshly generated agent key. The caller's copy of
   * `secretKey` is zeroed; from here on the key is reachable only through
   * the returned provider.
   */
  adopt(agentId: string, secretKey: Uint8Array, publicKey: Uint8Array): SignerProvider {
    try {
      const signer = this.kek
        ? FileBackedEncryptedSigner.create(this.pathFor(agentId), agentId, this.dsa, this.kek, secretKey, publicKey)
        : new EphemeralSigner(this.dsa, secretKey, publicKey);
      this.signers.set(agentId, signer);
      return signer;
    } finally {
      secretKey.fill(0);
    }
  }

  /** The agent's signer: in memory, else unwrapped from disk if durable. */
  get(agentId: string): SignerProvider | undefined {
    const cached = this.signers.get(agentId);
    if (cached || !this.kek) return cached;
    const path = this.pathFor(agentId);
    if (!existsSync(path)) return undefined;
    try {
      const signer = FileBackedEncryptedSigner.load(path, agentId, this.dsa, this.kek);
      this.signers.set(agentId, signer);
      return signer;
    } catch {
      return undefined;
    }
  }

  /** Destroy the agent's key in memory and on disk (revocation). */
  delete(agentId: string): void {
    this.signers.delete(agentId);
    if (!this.kek) return;
    try {
      unlinkSync(this.pathFor(agentId));
    } catch {
      // Not stored, or already gone
    }
  }
}
