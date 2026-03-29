/**
 * Atlas DIDComm Adapter — Core Types
 *
 * This file is the spine of the adapter package. All other modules import from here.
 * Types define the contract between the adapter and both the DIDComm transport layer
 * and the Atlas gatekeeper — the adapter owns neither.
 */

// ---------------------------------------------------------------------------
// Direction
// ---------------------------------------------------------------------------

export type DidcommDirection = "send" | "receive";

// ---------------------------------------------------------------------------
// Messaging capabilities (extends Atlas capability model)
// ---------------------------------------------------------------------------

export type MessagingCapability =
  | "peer:bind"
  | "peer:revoke"
  | "message:send"
  | "message:receive"
  | "message:send:financial"
  | "message:receive:financial"
  | "message:send:health"
  | "message:receive:health";

// ---------------------------------------------------------------------------
// Peer binding
// ---------------------------------------------------------------------------

/**
 * Represents a remote DIDComm peer in the local trust model.
 * peerDid is a remote did:peer identifier — NOT a did:atlas identifier.
 * mappedAgentId, if set, is the local did:atlas credential that represents
 * this peer inside this gatekeeper's environment.
 */
export interface PeerBinding {
  peerDid: string;
  alias?: string;
  trustState: "untrusted" | "paired" | "approved" | "revoked";
  mappedAgentId?: string;
  allowedMessageTypes: string[];
  allowedDirections: Array<"send" | "receive">;
  createdAt: string;
  updatedAt: string;
  lastSeenAt?: string;
  metadata?: Record<string, string>;
  /** Delegation scope — if set, this peer is serviced by a delegated sub-agent */
  delegationScope?: DelegationScope;
}

// ---------------------------------------------------------------------------
// Delegation scope (Milestone 3)
// ---------------------------------------------------------------------------

/**
 * When an orchestrator delegates messaging authority for a specific peer,
 * the DelegationScope binds a delegated credential to that peer with
 * restricted capabilities. The adapter enforces these restrictions before
 * calling Atlas authorize().
 */
export interface DelegationScope {
  /** The delegated agent's did:atlas ID */
  delegatedAgentId: string;
  /** The parent (orchestrator) agent's did:atlas ID */
  parentAgentId: string;
  /** Capabilities the delegated agent holds (subset of parent's) */
  grantedCapabilities: MessagingCapability[];
  /** Message types this delegation is restricted to (empty = all) */
  allowedMessageTypes: string[];
  /** Directions this delegation allows */
  allowedDirections: Array<"send" | "receive">;
  /** When this delegation expires */
  expiresAt: string;
  /** When this delegation was created */
  createdAt: string;
}

// ---------------------------------------------------------------------------
// DIDComm message (minimal — we don't own the transport)
// ---------------------------------------------------------------------------

export interface DidcommMessage {
  id: string;
  type: string;
  from?: string;
  to?: string[];
  thid?: string;
  body?: unknown;
  transport?: {
    encrypted?: boolean;
    authenticated?: boolean;
    signed?: boolean;
  };
}

// ---------------------------------------------------------------------------
// Classified message
// ---------------------------------------------------------------------------

/**
 * Output of MessageClassifier. Normalizes DIDComm message intent into
 * Atlas-friendly terms. The adapter never makes policy decisions —
 * it only classifies.
 */
export interface ClassifiedMessage {
  messageType: string;
  protocolFamily: string;
  direction: DidcommDirection;
  preview?: string;
  sensitivityLabels: string[];
  requiredCapability: MessagingCapability;
}

// ---------------------------------------------------------------------------
// DIDComm permission request
// ---------------------------------------------------------------------------

/**
 * The normalized Atlas permission request for any DIDComm action.
 * tool_name is always "DIDComm" so Atlas policy rules can match on it.
 * input_preview is a stable slug-safe string for glob pattern matching.
 */
export interface DidcommPermissionRequest {
  request_id: string;
  tool_name: "DIDComm";
  action: DidcommDirection | "pair" | "revoke-peer";
  peer_did: string;
  peer_alias?: string;
  local_agent_id?: string;
  message_type: string;
  protocol_family: string;
  thread_id?: string;
  content_preview?: string;
  input_preview: string;
  sensitivity_labels: string[];
  transport_meta: {
    encrypted: boolean;
    authenticated: boolean;
    signed: boolean;
  };
  metadata?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Atlas authorization result
// ---------------------------------------------------------------------------

export interface AuthorizationResult {
  verdict: "allow" | "ask" | "deny";
  reason?: string;
}

// ---------------------------------------------------------------------------
// DIDComm-specific Atlas audit event types
// ---------------------------------------------------------------------------

export type AtlasDidcommEventType =
  | "DIDCOMM_PAIR_INIT"
  | "DIDCOMM_PAIR_ACCEPT"
  | "DIDCOMM_PEER_BOUND"
  | "DIDCOMM_SEND_ALLOW"
  | "DIDCOMM_SEND_DENY"
  | "DIDCOMM_RECEIVE_ALLOW"
  | "DIDCOMM_RECEIVE_DENY"
  | "DIDCOMM_PEER_REVOKED"
  | "DIDCOMM_DELEGATED_SEND"
  | "DIDCOMM_DELEGATED_RECEIVE";

// ---------------------------------------------------------------------------
// DIDComm audit event
// ---------------------------------------------------------------------------

/**
 * Extends Atlas audit semantics. seq, prev_hash, pq_signature fields are
 * populated by the Atlas bridge, not the adapter.
 */
export interface AtlasDidcommAuditEvent {
  id?: string;
  timestamp: string;
  event: AtlasDidcommEventType;
  peerDid: string;
  agentId?: string;
  messageType?: string;
  direction?: DidcommDirection;
  identityVerified?: boolean;
  verdict: "allow" | "ask" | "deny";
  reason?: string;
  sensitivityLabels?: string[];
  metadata?: Record<string, string>;
  seq?: number;
  prev_hash?: string;
  pq_signature?: string;
}

// ---------------------------------------------------------------------------
// Transport interface
// ---------------------------------------------------------------------------

/**
 * The adapter talks to this interface only — never to a DIDComm library directly.
 * Implementations plug in their own DIDComm stack here.
 */
export interface DidcommTransport {
  createInvitation(): Promise<string>;
  acceptInvitation(invitation: string): Promise<{ peerDid: string }>;
  sendMessage(peerDid: string, msg: DidcommMessage): Promise<void>;
  unpackMessage(raw: Uint8Array | string): Promise<DidcommMessage>;
}

// ---------------------------------------------------------------------------
// Peer store interface
// ---------------------------------------------------------------------------

export interface PeerStore {
  get(peerDid: string): Promise<PeerBinding | undefined>;
  put(peer: PeerBinding): Promise<void>;
  list(filter?: "all" | "approved" | "revoked" | "untrusted"): Promise<PeerBinding[]>;
  delete(peerDid: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Atlas bridge interface
// ---------------------------------------------------------------------------

/**
 * The minimal surface the adapter needs from the Atlas gatekeeper.
 * Implementations wire this to the Atlas MCP tools or internal APIs.
 * The bridge is responsible for seq, prev_hash, and pq_signature.
 */
export interface AtlasBridge {
  authorize(req: DidcommPermissionRequest): Promise<AuthorizationResult>;
  logEvent(event: AtlasDidcommAuditEvent): Promise<void>;
  registerPeerBinding(binding: PeerBinding): Promise<void>;
  revokePeerBinding(peerDid: string, reason: string): Promise<void>;
  /**
   * Check if a delegated credential is still valid (not expired/revoked).
   * MUST be implemented for delegation-aware messaging. When a delegation
   * scope is present on a peer, this is called on every message — not optional.
   * If not implemented, delegation-scoped messages are denied (fail-closed).
   */
  isDelegationValid?(agentId: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Classifier interface
// ---------------------------------------------------------------------------

export interface MessageClassifier {
  classifyInbound(msg: DidcommMessage): ClassifiedMessage;
  classifyOutbound(msg: DidcommMessage): ClassifiedMessage;
}

// ---------------------------------------------------------------------------
// Inbound/outbound results
// ---------------------------------------------------------------------------

export interface InboundResult {
  delivered: boolean;
  reason?: string;
  event?: AtlasDidcommEventType;
}

export interface OutboundResult {
  sent: boolean;
  reason?: string;
  event?: AtlasDidcommEventType;
}
