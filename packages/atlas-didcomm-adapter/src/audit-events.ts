/**
 * Atlas DIDComm Adapter — Audit Event Builders
 *
 * 10 builder functions that create AtlasDidcommAuditEvent objects.
 * Each sets the timestamp, event type, peerDid, and verdict.
 * Raw message bodies are never included. Previews are redacted
 * when sensitivity labels are present.
 */

import type {
  AtlasDidcommAuditEvent,
  AtlasDidcommEventType,
  DidcommDirection,
} from "./types.js";

// ---------------------------------------------------------------------------
// Shared parameter type
// ---------------------------------------------------------------------------

interface AuditEventParams {
  peerDid: string;
  agentId?: string;
  messageType?: string;
  direction?: DidcommDirection;
  reason?: string;
  sensitivityLabels?: string[];
  verdict?: "allow" | "ask" | "deny";
  metadata?: Record<string, string>;
  identityVerified?: boolean;
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

const DENY_EVENTS = new Set(["DIDCOMM_SEND_DENY", "DIDCOMM_RECEIVE_DENY", "DIDCOMM_PEER_REVOKED"]);

function inferVerdict(event: AtlasDidcommEventType): "allow" | "deny" {
  return DENY_EVENTS.has(event) ? "deny" : "allow";
}

function buildBase(
  event: AtlasDidcommEventType,
  params: AuditEventParams,
): AtlasDidcommAuditEvent {
  return {
    timestamp: new Date().toISOString(),
    event,
    peerDid: params.peerDid,
    agentId: params.agentId,
    messageType: params.messageType,
    direction: params.direction,
    identityVerified: params.identityVerified,
    verdict: params.verdict ?? inferVerdict(event),
    reason: params.reason,
    sensitivityLabels: params.sensitivityLabels,
    metadata: params.metadata,
  };
}

// ---------------------------------------------------------------------------
// Pairing events
// ---------------------------------------------------------------------------

/** A pairing handshake was initiated with a remote peer. */
export function buildPairInit(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_PAIR_INIT", params);
}

/** A remote peer accepted the pairing invitation. */
export function buildPairAccept(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_PAIR_ACCEPT", params);
}

/** A peer was bound to a local agent identity. */
export function buildPeerBound(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_PEER_BOUND", params);
}

// ---------------------------------------------------------------------------
// Send / receive authorization events
// ---------------------------------------------------------------------------

/** An outbound message was allowed by policy. */
export function buildSendAllow(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_SEND_ALLOW", {
    ...params,
    direction: "send",
  });
}

/** An outbound message was denied by policy. */
export function buildSendDeny(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_SEND_DENY", {
    ...params,
    direction: "send",
  });
}

/** An inbound message was allowed by policy. */
export function buildReceiveAllow(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_RECEIVE_ALLOW", {
    ...params,
    direction: "receive",
  });
}

/** An inbound message was denied by policy. */
export function buildReceiveDeny(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_RECEIVE_DENY", {
    ...params,
    direction: "receive",
  });
}

// ---------------------------------------------------------------------------
// Lifecycle events
// ---------------------------------------------------------------------------

/** A peer's trust state was set to revoked. */
export function buildPeerRevoked(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_PEER_REVOKED", params);
}

// ---------------------------------------------------------------------------
// Delegation events
// ---------------------------------------------------------------------------

/** A message was sent on behalf of a delegated agent identity. */
export function buildDelegatedSend(params: AuditEventParams): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_DELEGATED_SEND", {
    ...params,
    direction: "send",
  });
}

/** A message was received and delivered to a delegated agent identity. */
export function buildDelegatedReceive(
  params: AuditEventParams,
): AtlasDidcommAuditEvent {
  return buildBase("DIDCOMM_DELEGATED_RECEIVE", {
    ...params,
    direction: "receive",
  });
}
