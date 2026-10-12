/**
 * Atlas Protocol — Operator key (SPEC §9)
 *
 * An ML-DSA-65 keypair that belongs to the human operator, not the gatekeeper.
 * The secret key is stored encrypted under the operator's passphrase
 * (scrypt → AES-256-GCM), so a governed agent that can read the data
 * directory still cannot sign. The gatekeeper holds only the public key,
 * pinned in memory at startup.
 *
 * Used to authorize break-glass tokens: the gatekeeper accepts a token only
 * if it carries a valid operator signature.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";

type MlDsa65 = {
  keygen: (seed?: Uint8Array) => { publicKey: Uint8Array; secretKey: Uint8Array };
  sign: (secretKey: Uint8Array, msg: Uint8Array) => Uint8Array;
  verify: (publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array) => boolean;
};

let mlDsa: MlDsa65 | null = null;
export async function loadMlDsa(): Promise<MlDsa65> {
  if (!mlDsa) {
    const mod = await import("@noble/post-quantum/ml-dsa");
    mlDsa = mod.ml_dsa65 as MlDsa65;
  }
  return mlDsa;
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

export const OPERATOR_DIR = "operator";
export const OPERATOR_PUBLIC_FILE = "operator.pub.json";
export const OPERATOR_SECRET_FILE = "operator.key.enc.json";

export const operatorPublicPath = (dataDir: string) => join(dataDir, OPERATOR_DIR, OPERATOR_PUBLIC_FILE);
export const operatorSecretPath = (dataDir: string) => join(dataDir, OPERATOR_DIR, OPERATOR_SECRET_FILE);

export interface OperatorPublicKey {
  algorithm: "ML-DSA-65";
  /** First 16 hex chars of SHA3-256(public key) */
  key_id: string;
  public_key: string; // base64
  created_at: string;
}

interface EncryptedSecretKey {
  algorithm: "ML-DSA-65";
  key_id: string;
  kdf: { name: "scrypt"; N: number; r: number; p: number; salt: string };
  cipher: { name: "aes-256-gcm"; iv: string; tag: string; ciphertext: string };
}

const SCRYPT = { N: 1 << 16, r: 8, p: 1 } as const;
const SCRYPT_MAXMEM = 256 * 1024 * 1024;
export const MIN_PASSPHRASE_LENGTH = 12;

export function keyIdFor(publicKey: Uint8Array): string {
  return createHash("sha3-256").update(publicKey).digest("hex").slice(0, 16);
}

function deriveKey(passphrase: string, salt: Buffer, params: { N: number; r: number; p: number }): Buffer {
  return scryptSync(passphrase.normalize("NFKC"), salt, 32, { ...params, maxmem: SCRYPT_MAXMEM });
}

function writePrivate(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, contents, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // Non-fatal on restricted filesystems
  }
}

/**
 * Generate an operator keypair. Writes the public key and the passphrase-
 * encrypted secret key. Refuses to overwrite an existing key unless `force`.
 */
export async function generateOperatorKey(
  dataDir: string,
  passphrase: string,
  options: { force?: boolean; secretPath?: string } = {},
): Promise<OperatorPublicKey> {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
  const pubPath = operatorPublicPath(dataDir);
  const secPath = options.secretPath ?? operatorSecretPath(dataDir);
  if (!options.force && (existsSync(pubPath) || existsSync(secPath))) {
    throw new Error(`Operator key already exists at ${pubPath}; pass --force to replace it`);
  }

  const dsa = await loadMlDsa();
  const { publicKey, secretKey } = dsa.keygen(randomBytes(32));
  const keyId = keyIdFor(publicKey);

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(passphrase, salt, SCRYPT), iv);
  cipher.setAAD(Buffer.from(keyId));
  const ciphertext = Buffer.concat([cipher.update(secretKey), cipher.final()]);

  const encrypted: EncryptedSecretKey = {
    algorithm: "ML-DSA-65",
    key_id: keyId,
    kdf: { name: "scrypt", ...SCRYPT, salt: salt.toString("base64") },
    cipher: {
      name: "aes-256-gcm",
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    },
  };
  const pub: OperatorPublicKey = {
    algorithm: "ML-DSA-65",
    key_id: keyId,
    public_key: Buffer.from(publicKey).toString("base64"),
    created_at: new Date().toISOString(),
  };

  writePrivate(secPath, JSON.stringify(encrypted, null, 2));
  writePrivate(pubPath, JSON.stringify(pub, null, 2));
  return pub;
}

/** Decrypt the operator secret key. Throws on a wrong passphrase or tampering. */
export function unlockOperatorKey(secretPath: string, passphrase: string): { keyId: string; secretKey: Uint8Array } {
  const enc = JSON.parse(readFileSync(secretPath, "utf-8")) as EncryptedSecretKey;
  if (enc.algorithm !== "ML-DSA-65" || enc.kdf?.name !== "scrypt" || enc.cipher?.name !== "aes-256-gcm") {
    throw new Error("Unsupported operator key format");
  }
  const key = deriveKey(passphrase, Buffer.from(enc.kdf.salt, "base64"), enc.kdf);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(enc.cipher.iv, "base64"));
  decipher.setAAD(Buffer.from(enc.key_id));
  decipher.setAuthTag(Buffer.from(enc.cipher.tag, "base64"));
  try {
    const secretKey = Buffer.concat([
      decipher.update(Buffer.from(enc.cipher.ciphertext, "base64")),
      decipher.final(),
    ]);
    return { keyId: enc.key_id, secretKey: new Uint8Array(secretKey) };
  } catch {
    throw new Error("Wrong passphrase or corrupted operator key");
  }
}

/** Read the operator public key file, or null if none is configured. */
export function readOperatorPublicKey(dataDir: string): OperatorPublicKey | null {
  const path = operatorPublicPath(dataDir);
  if (!existsSync(path)) return null;
  const pub = JSON.parse(readFileSync(path, "utf-8")) as OperatorPublicKey;
  if (pub.algorithm !== "ML-DSA-65" || typeof pub.public_key !== "string") {
    throw new Error(`Invalid operator public key at ${path}`);
  }
  if (keyIdFor(Buffer.from(pub.public_key, "base64")) !== pub.key_id) {
    throw new Error(`Operator public key at ${path} does not match its key_id`);
  }
  return pub;
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/**
 * Canonical bytes for signing: keys sorted, no whitespace. Values are
 * strings/numbers only (enforced by the token schema).
 */
export function canonicalBytes(payload: Record<string, string | number>): Buffer {
  const sorted = Object.keys(payload).sort().map((k) => [k, payload[k]]);
  return Buffer.from(JSON.stringify(Object.fromEntries(sorted)), "utf-8");
}

export async function operatorSign(secretKey: Uint8Array, payload: Record<string, string | number>): Promise<string> {
  const dsa = await loadMlDsa();
  return Buffer.from(dsa.sign(secretKey, canonicalBytes(payload))).toString("base64");
}

export function operatorVerify(
  dsa: MlDsa65,
  pub: OperatorPublicKey,
  payload: Record<string, string | number>,
  signatureB64: string,
): boolean {
  try {
    return dsa.verify(
      Buffer.from(pub.public_key, "base64"),
      canonicalBytes(payload),
      Buffer.from(signatureB64, "base64"),
    );
  } catch {
    return false;
  }
}
