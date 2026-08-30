/**
 * Atlas Protocol — Proximity session crypto
 *
 * Encrypted agent-to-agent channel for the ProximityMesh profile (SPEC §13.4).
 *
 * This is an X25519 ECDH + HKDF-SHA256 + AES-256-GCM construction that follows
 * the IK/KK *key-use pattern* (ephemeral DH, static identity mixed into the
 * KDF). It is NOT a byte-compatible Noise_IK_25519_ChaChaPoly_SHA256 handshake:
 * static keys presented by the mesh are ML-DSA-65 (not X25519), so they are
 * bound as KDF context rather than used for DH.
 *
 * The proximity proof is mixed into HKDF as additional data, cryptographically
 * linking physical proximity to the session keys.
 *
 * Spec reference: SPEC.md § 13.4 (Secure channel establishment flow)
 */

import {
  createHash,
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  diffieHellman,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  createHmac,
} from "node:crypto";
import type {
  NoiseSession,
  NoiseSessionState,
  NoisePattern,
  NoiseHandshakeConfig,
} from "./types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROTOCOL_NAME = "Atlas_X25519_AESGCM_SHA256";
const SESSION_DEFAULT_TTL_HOURS = 1;
const NONCE_LENGTH = 12;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;
const X25519_KEY_LENGTH = 32;

// PKCS#8 / SPKI DER prefixes for raw 32-byte X25519 keys (RFC 8410).
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

// ---------------------------------------------------------------------------
// HKDF (for deriving session keys from handshake output)
// ---------------------------------------------------------------------------

function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  let t = Buffer.alloc(0);
  let okm = Buffer.alloc(0);
  let i = 1;

  while (okm.length < length) {
    const hmac = createHmac("sha256", prk);
    hmac.update(Buffer.concat([t, info, Buffer.from([i])]));
    t = hmac.digest();
    okm = Buffer.concat([okm, t]);
    i++;
  }

  return okm.subarray(0, length);
}

function hkdfDerive(
  inputKeyMaterial: Buffer,
  salt: Buffer,
  info: Buffer,
  length: number
): Buffer {
  const prk = createHmac("sha256", salt).update(inputKeyMaterial).digest();
  return hkdfExpand(prk, info, length);
}

// ---------------------------------------------------------------------------
// Session key derivation
// ---------------------------------------------------------------------------

interface DerivedKeys {
  /** Key for encrypting messages from initiator to responder */
  sendKey: Buffer;
  /** Key for decrypting messages from responder to initiator */
  receiveKey: Buffer;
  /** Session binding hash (includes proximity proof) */
  sessionHash: string;
}

function x25519PrivateFromRaw(raw: Uint8Array) {
  if (raw.length !== X25519_KEY_LENGTH) {
    throw new Error(`X25519 secret key must be ${X25519_KEY_LENGTH} bytes`);
  }
  return createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "pkcs8",
  });
}

function x25519PublicFromRaw(raw: Uint8Array) {
  if (raw.length !== X25519_KEY_LENGTH) {
    throw new Error(`X25519 public key must be ${X25519_KEY_LENGTH} bytes`);
  }
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
}

function x25519Dh(localSecret: Uint8Array, remotePublic: Uint8Array): Buffer {
  return diffieHellman({
    privateKey: x25519PrivateFromRaw(localSecret),
    publicKey: x25519PublicFromRaw(remotePublic),
  });
}

/**
 * Derive symmetric session keys from a real X25519 shared secret.
 * The proximity proof is mixed into HKDF so the transport keys are bound
 * to physical proximity.
 */
function deriveSessionKeys(
  localEphemeralSecret: Uint8Array,
  remoteEphemeralPublic: Uint8Array,
  additionalData: Uint8Array | undefined,
  isInitiator: boolean,
): DerivedKeys {
  const sharedSecret = x25519Dh(localEphemeralSecret, remoteEphemeralPublic);

  const salt = createHash("sha256")
    .update(PROTOCOL_NAME)
    .digest();

  const info = additionalData && additionalData.length > 0
    ? Buffer.concat([Buffer.from("atlas-proximity-session"), Buffer.from(additionalData)])
    : Buffer.from("atlas-proximity-session");

  const keyMaterial = hkdfDerive(sharedSecret, salt, info, KEY_LENGTH * 2);

  const key1 = keyMaterial.subarray(0, KEY_LENGTH);
  const key2 = keyMaterial.subarray(KEY_LENGTH, KEY_LENGTH * 2);

  const sessionHash = createHash("sha256")
    .update(keyMaterial)
    .update(info)
    .digest("hex");

  return {
    sendKey: isInitiator ? key1 : key2,
    receiveKey: isInitiator ? key2 : key1,
    sessionHash,
  };
}

// ---------------------------------------------------------------------------
// Noise Session implementation
// ---------------------------------------------------------------------------

class AtlasNoiseSession implements NoiseSession {
  sessionId: string;
  remoteAgentId: string;
  pattern: NoisePattern;
  state: NoiseSessionState;
  establishedAt: string;
  expiresAt: string;

  private sendKey: Buffer;
  private receiveKey: Buffer;
  private sendNonce: number = 0;
  private receiveNonce: number = 0;
  readonly sessionHash: string;

  constructor(
    remoteAgentId: string,
    pattern: NoisePattern,
    keys: DerivedKeys,
    ttlHours: number = SESSION_DEFAULT_TTL_HOURS,
  ) {
    this.sessionId = randomUUID();
    this.remoteAgentId = remoteAgentId;
    this.pattern = pattern;
    this.state = "transport";
    this.establishedAt = new Date().toISOString();
    this.expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000).toISOString();
    this.sendKey = keys.sendKey;
    this.receiveKey = keys.receiveKey;
    this.sessionHash = keys.sessionHash;
  }

  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    if (this.state !== "transport") {
      throw new Error(`Cannot encrypt in state: ${this.state}`);
    }
    if (new Date(this.expiresAt) < new Date()) {
      this.state = "closed";
      throw new Error("Session expired");
    }

    const nonce = Buffer.alloc(NONCE_LENGTH);
    nonce.writeBigUInt64LE(BigInt(this.sendNonce++), 4);

    const cipher = createCipheriv("aes-256-gcm", this.sendKey, nonce);
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(plaintext)),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    // Format: [nonce (12)] [tag (16)] [ciphertext (variable)]
    return Buffer.concat([nonce, tag, encrypted]);
  }

  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (this.state !== "transport") {
      throw new Error(`Cannot decrypt in state: ${this.state}`);
    }
    if (new Date(this.expiresAt) < new Date()) {
      this.state = "closed";
      throw new Error("Session expired");
    }

    const buf = Buffer.from(ciphertext);
    if (buf.length < NONCE_LENGTH + TAG_LENGTH) {
      throw new Error("Ciphertext too short");
    }

    const nonce = buf.subarray(0, NONCE_LENGTH);
    const tag = buf.subarray(NONCE_LENGTH, NONCE_LENGTH + TAG_LENGTH);
    const data = buf.subarray(NONCE_LENGTH + TAG_LENGTH);

    const decipher = createDecipheriv("aes-256-gcm", this.receiveKey, nonce);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(data),
      decipher.final(),
    ]);

    this.receiveNonce++;
    return decrypted;
  }

  async close(): Promise<void> {
    this.state = "closed";
    // Zero out keys
    this.sendKey.fill(0);
    this.receiveKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Handshake — initiator side
// ---------------------------------------------------------------------------

export interface HandshakeResult {
  session: NoiseSession;
  /** The session binding hash (for audit logging) */
  sessionHash: string;
}

/**
 * Perform a Noise IK or KK handshake as the initiator.
 * The proximity proof is bound as Additional Data, linking physical
 * proximity to the cryptographic session.
 *
 * @param remoteAgentId - The remote agent's did:atlas identifier
 * @param config - Handshake configuration including keys and AD
 * @returns The established Noise session
 */
export function initiateNoiseHandshake(
  remoteAgentId: string,
  config: NoiseHandshakeConfig,
): HandshakeResult {
  const keys = deriveSessionKeys(
    config.localEphemeralSecretKey,
    config.remoteEphemeralPublicKey,
    config.additionalData,
    true,
  );

  const session = new AtlasNoiseSession(remoteAgentId, config.pattern, keys);

  return { session, sessionHash: keys.sessionHash };
}

/**
 * Perform a Noise IK or KK handshake as the responder.
 */
export function respondNoiseHandshake(
  remoteAgentId: string,
  config: NoiseHandshakeConfig,
): HandshakeResult {
  const keys = deriveSessionKeys(
    config.localEphemeralSecretKey,
    config.remoteEphemeralPublicKey,
    config.additionalData,
    false,
  );

  const session = new AtlasNoiseSession(remoteAgentId, config.pattern, keys);

  return { session, sessionHash: keys.sessionHash };
}

/**
 * Generate an ephemeral X25519 keypair for the proximity handshake.
 * Returns raw 32-byte keys suitable for BLE advertisement payloads.
 */
export function generateEphemeralKeypair(): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const pubDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const secDer = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  return {
    publicKey: new Uint8Array(pubDer.subarray(pubDer.length - X25519_KEY_LENGTH)),
    secretKey: new Uint8Array(secDer.subarray(secDer.length - X25519_KEY_LENGTH)),
  };
}
