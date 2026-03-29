/**
 * Atlas DIDComm Adapter — Inbound Message Handler
 *
 * Enforces the Atlas gatekeeper on all received DIDComm messages.
 *
 * ENFORCEMENT ORDER (rigid, no reordering):
 *   1. Unpack message
 *   2. Sender identification
 *   3. Peer binding exists and is approved
 *   4. Delegation valid (not expired, not revoked)
 *   5. Direction allowed by delegation scope
 *   6. Message type allowed by delegation scope
 *   7. Capability allowed by delegation scope
 *   8. Replay check (message ID dedup)
 *   9. Classify message
 *  10. Atlas authorize()
 *  11. Deliver to local router
 *  12. Log success
 *
 * Fail closed at every step. Hard expiry (no grace window).
 */

import type {
  DidcommTransport,
  PeerStore,
  AtlasBridge,
  MessageClassifier,
  DidcommMessage,
  ClassifiedMessage,
  InboundResult,
} from "./types.js";
import type { PolicyMapper } from "./policy-mapper.js";
import { buildReceiveAllow, buildReceiveDeny } from "./audit-events.js";

// ---------------------------------------------------------------------------
// Inbound Handler
// ---------------------------------------------------------------------------

export class InboundHandler {
  /** Seen message IDs for replay detection (bounded LRU) */
  private readonly seenMessageIds: Set<string> = new Set();
  private readonly maxSeenIds: number;

  constructor(
    private readonly transport: DidcommTransport,
    private readonly peerStore: PeerStore,
    private readonly atlas: AtlasBridge,
    private readonly classifier: MessageClassifier,
    private readonly mapper: PolicyMapper,
    private readonly localRouter?: (msg: DidcommMessage, classified: ClassifiedMessage) => Promise<void>,
    options?: { maxSeenMessageIds?: number },
  ) {
    this.maxSeenIds = options?.maxSeenMessageIds ?? 10_000;
  }

  async handle(raw: Uint8Array | string): Promise<InboundResult> {
    // Step 1: Unpack
    const msg = await this.transport.unpackMessage(raw);

    // Step 2: Sender identification
    const senderDid = msg.from;
    if (!senderDid) {
      await this.logDeny("unknown", msg.type, undefined, "NO_SENDER");
      return { delivered: false, reason: "NO_SENDER", event: "DIDCOMM_RECEIVE_DENY" };
    }

    // Step 3: Peer binding exists and is approved
    const peer = await this.peerStore.get(senderDid);
    if (!peer) {
      await this.logDeny(senderDid, msg.type, undefined, "PEER_NOT_FOUND");
      return { delivered: false, reason: "PEER_NOT_FOUND", event: "DIDCOMM_RECEIVE_DENY" };
    }
    if (peer.trustState === "revoked") {
      await this.logDeny(senderDid, msg.type, peer.mappedAgentId, "PEER_REVOKED");
      return { delivered: false, reason: "PEER_REVOKED", event: "DIDCOMM_RECEIVE_DENY" };
    }
    if (peer.trustState !== "approved") {
      await this.logDeny(senderDid, msg.type, peer.mappedAgentId, "PEER_NOT_APPROVED");
      return { delivered: false, reason: "PEER_NOT_APPROVED", event: "DIDCOMM_RECEIVE_DENY" };
    }

    // Steps 4-7: Delegation scope enforcement (when scope is present)
    if (peer.delegationScope) {
      const scopeResult = await this.enforceDelegationScope(peer.delegationScope, senderDid, msg, "receive");
      if (scopeResult) return scopeResult;
    }

    // Step 8: Replay check
    if (this.seenMessageIds.has(msg.id)) {
      await this.logDeny(senderDid, msg.type, peer.mappedAgentId, "REPLAY_DETECTED");
      return { delivered: false, reason: "REPLAY_DETECTED", event: "DIDCOMM_RECEIVE_DENY" };
    }
    this.recordMessageId(msg.id);

    // Step 9: Classify
    const classified = this.classifier.classifyInbound(msg);

    // Step 10: Atlas authorize()
    const request = this.mapper.toPermissionRequest(msg, {
      direction: "receive",
      peer,
      classified,
    });
    const decision = await this.atlas.authorize(request);

    if (decision.verdict !== "allow") {
      await this.atlas.logEvent(buildReceiveDeny({
        peerDid: senderDid,
        agentId: peer.mappedAgentId,
        messageType: msg.type,
        direction: "receive",
        sensitivityLabels: classified.sensitivityLabels,
        reason: decision.reason ?? decision.verdict,
      }));
      return { delivered: false, reason: decision.reason ?? decision.verdict, event: "DIDCOMM_RECEIVE_DENY" };
    }

    // Step 11: Deliver to local router
    if (this.localRouter) {
      await this.localRouter(msg, classified);
    }

    // Step 12: Log success
    await this.atlas.logEvent(buildReceiveAllow({
      peerDid: senderDid,
      agentId: peer.mappedAgentId,
      messageType: msg.type,
      direction: "receive",
      sensitivityLabels: classified.sensitivityLabels,
    }));

    peer.lastSeenAt = new Date().toISOString();
    await this.peerStore.put(peer);

    return { delivered: true, event: "DIDCOMM_RECEIVE_ALLOW" };
  }

  // -------------------------------------------------------------------------
  // Delegation scope enforcement (steps 4-7)
  // -------------------------------------------------------------------------

  private async enforceDelegationScope(
    scope: import("./types.js").DelegationScope,
    peerDid: string,
    msg: DidcommMessage,
    direction: "send" | "receive",
  ): Promise<InboundResult | null> {
    const agentId = scope.delegatedAgentId;

    // Step 4: Delegation valid — hard expiry, no grace window
    if (new Date(scope.expiresAt).getTime() <= Date.now()) {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_EXPIRED");
      return { delivered: false, reason: "DELEGATION_EXPIRED", event: "DIDCOMM_RECEIVE_DENY" };
    }

    // Step 4b: Delegation not revoked — MUST check, fail-closed if bridge doesn't implement
    if (this.atlas.isDelegationValid) {
      const valid = await this.atlas.isDelegationValid(agentId);
      if (!valid) {
        await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_REVOKED");
        return { delivered: false, reason: "DELEGATION_REVOKED", event: "DIDCOMM_RECEIVE_DENY" };
      }
    } else {
      // Bridge does not implement isDelegationValid — fail closed
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_VALIDATION_UNAVAILABLE");
      return { delivered: false, reason: "DELEGATION_VALIDATION_UNAVAILABLE", event: "DIDCOMM_RECEIVE_DENY" };
    }

    // Step 5: Direction allowed
    if (!scope.allowedDirections.includes(direction)) {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_DIRECTION_DENIED");
      return { delivered: false, reason: "DELEGATION_DIRECTION_DENIED", event: "DIDCOMM_RECEIVE_DENY" };
    }

    // Step 6: Message type allowed (empty = all)
    if (scope.allowedMessageTypes.length > 0 && !scope.allowedMessageTypes.includes(msg.type)) {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_MESSAGE_TYPE_DENIED");
      return { delivered: false, reason: "DELEGATION_MESSAGE_TYPE_DENIED", event: "DIDCOMM_RECEIVE_DENY" };
    }

    // Step 7: Capability check — classify to get required capability, check against scope
    const classified = this.classifier.classifyInbound(msg);
    if (!scope.grantedCapabilities.includes(classified.requiredCapability)) {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_CAPABILITY_DENIED");
      return { delivered: false, reason: "DELEGATION_CAPABILITY_DENIED", event: "DIDCOMM_RECEIVE_DENY" };
    }

    return null; // All delegation checks passed
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private async logDeny(peerDid: string, messageType: string | undefined, agentId: string | undefined, reason: string): Promise<void> {
    await this.atlas.logEvent(buildReceiveDeny({ peerDid, messageType, agentId, reason }));
  }

  private recordMessageId(id: string): void {
    this.seenMessageIds.add(id);
    // Bounded: evict oldest when full (simple approach — not a true LRU, but sufficient)
    if (this.seenMessageIds.size > this.maxSeenIds) {
      const first = this.seenMessageIds.values().next().value;
      if (first !== undefined) this.seenMessageIds.delete(first);
    }
  }
}
