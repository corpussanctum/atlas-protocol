/**
 * Atlas Protocol — Proximity Mesh Types
 *
 * Type definitions for the close-proximity agent-to-agent secure transmission
 * protocol. Covers hardware abstraction, proximity attestation, Noise Protocol
 * sessions, and mesh orchestration.
 *
 * Spec reference: SPEC.md § 13 (Proximity Mesh Profile)
 */

// ---------------------------------------------------------------------------
// Hardware abstraction
// ---------------------------------------------------------------------------

/** Supported proximity ranging methods, ordered by preference */
export type ProximityMethod = "uwb-sts" | "ble-rssi" | "nfc";

/** Raw result from a UWB Time-of-Flight ranging exchange */
export interface UWBRangingResult {
  /** Measured distance in meters (cm precision typical for FiRa 3.0) */
  distanceMeters: number;
  /** Whether Scrambled Timestamp Sequence was used (relay-attack resistant) */
  stsEnabled: boolean;
  /** ISO-8601 timestamp of the ranging measurement */
  timestamp: string;
  /** Raw challenge nonce used in the ranging exchange */
  challenge: Uint8Array;
  /** Remote device identifier (hardware-level) */
  remoteDeviceId: string;
  /** Signal quality indicator 0-100 */
  signalQuality: number;
  /** Number of ranging rounds completed (multi-round improves accuracy) */
  roundsCompleted: number;
}

/** Raw result from BLE RSSI-based distance estimation */
export interface BLERangingResult {
  /** Estimated distance in meters (less precise than UWB) */
  distanceMeters: number;
  /** Raw RSSI value in dBm */
  rssi: number;
  /** Calibrated TX power at 1m */
  txPower: number;
  /** ISO-8601 timestamp */
  timestamp: string;
  /** BLE device address */
  remoteAddress: string;
}

/** BLE advertisement payload for Atlas agent discovery */
export interface BLEAdvertisement {
  /** atlas-proximity service UUID */
  serviceUuid: string;
  /** Short-lived ephemeral X25519 public key for Noise handshake */
  ephemeralPublicKey: Uint8Array;
  /** did:atlas identifier (truncated hash for space) */
  agentIdHash: string;
  /** Supported proximity methods */
  supportedMethods: ProximityMethod[];
  /** Maximum range this agent will accept (meters) */
  maxRangeMeters: number;
}

/** NFC tap payload for ultra-close bootstrap */
export interface NFCTapPayload {
  /** did:atlas identifier */
  agentId: string;
  /** Ephemeral X25519 public key */
  ephemeralPublicKey: Uint8Array;
  /** One-time pairing token */
  pairingToken: Uint8Array;
  /** ISO-8601 timestamp (short expiry) */
  expiresAt: string;
}

// ---------------------------------------------------------------------------
// Proximity attestation
// ---------------------------------------------------------------------------

/** Cryptographically signed proof that an agent is within range */
export interface ProximityProof {
  /** did:atlas of the proving agent */
  proverId: string;
  /** did:atlas of the verifying agent */
  verifierId: string;
  /** Measured distance in meters */
  distanceMeters: number;
  /** Which method was used */
  method: ProximityMethod;
  /** ISO-8601 timestamp of the ranging measurement */
  rangingTimestamp: string;
  /** The challenge nonce used (hex-encoded) */
  challenge: string;
  /** ML-DSA-65 signature over the canonical proof payload */
  signature: string;
  /** Whether STS was enabled (UWB only) */
  stsEnabled: boolean;
  /** Proof expiry — proximity proofs are short-lived (default 30s) */
  expiresAt: string;
}

/** Result of verifying a proximity proof */
export interface ProximityVerifyResult {
  /** Whether the proof is valid */
  valid: boolean;
  /** Measured distance */
  distanceMeters?: number;
  /** Method used */
  method?: ProximityMethod;
  /** Denial reason if invalid */
  denyReason?: ProximityDenyReason;
}

export type ProximityDenyReason =
  | "SIGNATURE_INVALID"
  | "PROOF_EXPIRED"
  | "DISTANCE_EXCEEDED"
  | "STS_REQUIRED"
  | "CHALLENGE_MISMATCH"
  | "UNKNOWN_PROVER"
  | "METHOD_NOT_SUPPORTED"
  | "HARDWARE_UNAVAILABLE";

/** Credential extension for proximity-capable agents */
export interface ProximityCapabilities {
  /** Methods this agent supports */
  supportedMethods: ProximityMethod[];
  /** Maximum range this agent will accept (meters) */
  maxRangeMeters: number;
  /** Whether distance bounding is supported (UWB STS) */
  distanceBoundingSupported: boolean;
  /** Last verified range (updated after each successful attestation) */
  lastVerifiedRangeMeters?: number;
  /** ISO-8601 of last verification */
  lastVerifiedTimestamp?: string;
}

// ---------------------------------------------------------------------------
// Noise Protocol session
// ---------------------------------------------------------------------------

/** Noise Protocol pattern used for the handshake */
export type NoisePattern = "IK" | "KK";

/** State of a Noise Protocol session */
export type NoiseSessionState =
  | "init"
  | "handshake"
  | "transport"
  | "closed"
  | "error";

/** Represents an established Noise Protocol session */
export interface NoiseSession {
  /** Unique session identifier */
  sessionId: string;
  /** Remote agent's did:atlas */
  remoteAgentId: string;
  /** Which Noise pattern was used */
  pattern: NoisePattern;
  /** Current session state */
  state: NoiseSessionState;
  /** When the session was established */
  establishedAt: string;
  /** Session expiry (re-key or close) */
  expiresAt: string;
  /** Encrypt a payload for the remote agent */
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  /** Decrypt a payload from the remote agent */
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
  /** Graceful close */
  close(): Promise<void>;
}

/** Configuration for a Noise handshake */
export interface NoiseHandshakeConfig {
  /** Local agent's static ML-DSA-65 public key */
  localStaticPublicKey: Uint8Array;
  /** Local agent's static ML-DSA-65 secret key */
  localStaticSecretKey: Uint8Array;
  /** Local ephemeral X25519 keypair (generated per-handshake) */
  localEphemeralPublicKey: Uint8Array;
  localEphemeralSecretKey: Uint8Array;
  /** Remote agent's static public key (for IK pattern, known in advance) */
  remoteStaticPublicKey?: Uint8Array;
  /** Remote agent's ephemeral public key (from BLE advertisement) */
  remoteEphemeralPublicKey: Uint8Array;
  /** Additional data to bind into the handshake (proximity proof) */
  additionalData?: Uint8Array;
  /** Pattern selection */
  pattern: NoisePattern;
}

// ---------------------------------------------------------------------------
// Mesh session (full protocol flow)
// ---------------------------------------------------------------------------

/** Represents a fully established proximity mesh session */
export interface MeshSession {
  /** Unique mesh session ID */
  sessionId: string;
  /** Local agent's did:atlas */
  localAgentId: string;
  /** Remote agent's did:atlas */
  remoteAgentId: string;
  /** The proximity proof that established this session */
  proximityProof: ProximityProof;
  /** The underlying Noise session for encrypted communication */
  noiseSession: NoiseSession;
  /** Remote agent's verified credential */
  remoteCredential: unknown; // AgentCredential, kept as unknown to avoid circular imports
  /** When this mesh session was established */
  establishedAt: string;
  /** Send an encrypted, authenticated message */
  send(payload: Uint8Array): Promise<void>;
  /** Receive and decrypt a message */
  receive(): Promise<Uint8Array>;
  /** Close the session and log to audit trail */
  close(): Promise<void>;
}

/** Discovery result — a nearby Atlas agent advertising its presence */
export interface DiscoveredPeer {
  /** Hardware device identifier */
  deviceId: string;
  /** Short hash of the peer's did:atlas (from BLE advertisement) */
  agentIdHash: string;
  /** Ephemeral public key for Noise handshake */
  ephemeralPublicKey: Uint8Array;
  /** Supported proximity methods */
  supportedMethods: ProximityMethod[];
  /** Maximum range the peer accepts */
  maxRangeMeters: number;
  /** Estimated distance (from BLE RSSI during discovery) */
  estimatedDistanceMeters?: number;
  /** ISO-8601 of discovery */
  discoveredAt: string;
}

/** Configuration for the proximity mesh */
export interface ProximityMeshConfig {
  /** Maximum acceptable range in meters (default: 10) */
  maxProximityMeters: number;
  /** Proof TTL in seconds (default: 30) */
  proofTtlSeconds: number;
  /** Whether UWB STS is required (default: true for ProximityMesh profile) */
  requireSts: boolean;
  /** Noise pattern preference (default: IK) */
  preferredNoisePattern: NoisePattern;
  /** BLE service UUID for discovery */
  bleServiceUuid: string;
  /** Whether to require UWB or allow BLE RSSI fallback */
  requireUwb: boolean;
  /** Session timeout in seconds (default: 3600) */
  sessionTimeoutSeconds: number;
  /** Re-range interval in seconds (default: 60, 0 = no re-ranging) */
  reRangeIntervalSeconds: number;
}

// ---------------------------------------------------------------------------
// Audit event types for proximity
// ---------------------------------------------------------------------------

export type ProximityAuditEventType =
  | "PROXIMITY_DISCOVERY"
  | "PROXIMITY_RANGE"
  | "PROXIMITY_VERIFIED"
  | "PROXIMITY_REJECTED"
  | "PROXIMITY_SESSION_ESTABLISHED"
  | "PROXIMITY_SESSION_CLOSED"
  | "PROXIMITY_RERANGE"
  | "PROXIMITY_DELEGATION";

/** Proximity-specific metadata for audit entries */
export interface ProximityAuditMeta {
  /** Event sub-type */
  proximityEvent: ProximityAuditEventType;
  /** Remote agent's did:atlas */
  remoteAgentId?: string;
  /** Distance in meters */
  distanceMeters?: number;
  /** Method used */
  method?: ProximityMethod;
  /** Whether STS was enabled */
  stsEnabled?: boolean;
  /** Deny reason (for rejected events) */
  proximityDenyReason?: ProximityDenyReason;
  /** Session ID (for session events) */
  meshSessionId?: string;
  /** Proof signature (truncated for audit) */
  proofSignaturePrefix?: string;
}

// ---------------------------------------------------------------------------
// Hardware driver interface (platform adapters implement this)
// ---------------------------------------------------------------------------

/** Abstract interface for UWB hardware */
export interface UWBDriver {
  /** Check if UWB hardware is available */
  isAvailable(): Promise<boolean>;
  /** Initiate ranging with a discovered device */
  range(deviceId: string, options: { stsEnabled: boolean; challenge: Uint8Array }): Promise<UWBRangingResult>;
  /** Send data over UWB data channel */
  send(deviceId: string, data: Uint8Array): Promise<void>;
  /** Receive data from UWB data channel */
  receive(deviceId: string, timeoutMs: number): Promise<Uint8Array>;
}

/** Abstract interface for BLE hardware */
export interface BLEDriver {
  /** Check if BLE hardware is available */
  isAvailable(): Promise<boolean>;
  /** Start advertising as an Atlas agent */
  startAdvertising(advertisement: BLEAdvertisement): Promise<void>;
  /** Stop advertising */
  stopAdvertising(): Promise<void>;
  /** Scan for nearby Atlas agents */
  scan(durationMs: number): Promise<DiscoveredPeer[]>;
  /** Get RSSI-based distance estimate for a device */
  estimateDistance(deviceId: string): Promise<BLERangingResult>;
}

/** Abstract interface for NFC hardware */
export interface NFCDriver {
  /** Check if NFC hardware is available */
  isAvailable(): Promise<boolean>;
  /** Write a tap payload */
  writeTap(payload: NFCTapPayload): Promise<void>;
  /** Read a tap payload */
  readTap(timeoutMs: number): Promise<NFCTapPayload | null>;
}
