/**
 * Atlas Protocol — Noise Protocol Session
 *
 * Implements a simplified Noise Protocol Framework session for encrypted
 * agent-to-agent communication over UWB data channels. Uses the IK pattern
 * (initiator knows responder's static key) or KK pattern (both know each
 * other's static keys, for pre-paired agents).
 *
 * The proximity proof is bound into the handshake as Additional Data (AD),
 * cryptographically linking physical proximity to the encrypted session.
 *
 * In production, this would use a full Noise implementation (e.g. noise-protocol
 * or @stablelib/noise). This implementation provides the correct protocol flow
 * and type contracts using Node.js crypto primitives.
 *
 * Spec reference: SPEC.md § 13.4 (Secure channel establishment flow)
 */

import { createHash, createCipheriv, createDecipheriv, randomBytes, randomUUID, createHmac } from "node:crypto";
import type {
  NoiseSession,
  NoiseSessionState,
  NoisePattern,
  NoiseHandshakeConfig,
} from "./types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NOISE_PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_SHA256";
const SESSION_DEFAULT_TTL_HOURS = 1;
const NONCE_LENGTH = 12;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;

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

/**
 * Derive symmetric session keys from the handshake material.
 * The proximity proof is mixed into the derivation as additional context,
 * binding the physical proximity attestation to the encrypted channel.
 */
function deriveSessionKeys(
  localEphemeralSecret: Uint8Array,
  remoteEphemeralPublic: Uint8Array,
  additionalData: Uint8Array | undefined,
  isInitiator: boolean,
): DerivedKeys {
  // Simulate DH by hashing the shared material in canonical order.
  // In production, this would be X25519(localSecret, remotePub) which
  // yields the same shared secret on both sides. Here we sort the public
  // keys lexicographically so both sides derive identical key material.
  const localPub = createHash("sha256").update(Buffer.from(localEphemeralSecret)).digest();
  const remotePub = Buffer.from(remoteEphemeralPublic);
  const [first, second] = Buffer.compare(localPub, remotePub) <= 0
    ? [localPub, remotePub]
    : [remotePub, localPub];
  const dhInput = Buffer.concat([first, second]);

  const salt = createHash("sha256")
    .update(NOISE_PROTOCOL_NAME)
    .digest();

  // Mix in additional data (proximity proof) if present
  const info = additionalData
    ? Buffer.concat([Buffer.from("atlas-proximity-session"), Buffer.from(additionalData)])
    : Buffer.from("atlas-proximity-session");

  const keyMaterial = hkdfDerive(dhInput, salt, info, KEY_LENGTH * 2);

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
 * Generate an ephemeral X25519 keypair for the Noise handshake.
 * In production, use actual X25519. Here we use random bytes as a stand-in
 * since the real DH is handled by the Noise library.
 */
export function generateEphemeralKeypair(): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  const secretKey = randomBytes(32);
  // In production: X25519 scalar multiplication
  // For now: derive public key as hash of secret (deterministic, one-way)
  const publicKey = createHash("sha256").update(secretKey).digest();
  return {
    publicKey: new Uint8Array(publicKey),
    secretKey: new Uint8Array(secretKey),
  };
}
