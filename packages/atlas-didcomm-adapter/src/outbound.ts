/**
 * Atlas DIDComm Adapter — Outbound Message Handler
 *
 * Enforces the Atlas gatekeeper on all sent DIDComm messages.
 * CRITICAL: A denied message MUST NEVER hit the wire.
 *
 * ENFORCEMENT ORDER (rigid, no reordering):
 *   1. Peer binding exists and is approved
 *   2. Delegation valid (not expired, not revoked)
 *   3. Direction allowed by delegation scope
 *   4. Message type allowed by delegation scope
 *   5. Capability allowed by delegation scope
 *   6. Replay check (message ID dedup)
 *   7. Classify message
 *   8. Atlas authorize()
 *   9. Send to wire
 *  10. Log success
 *
 * Fail closed at every step. Hard expiry (no grace window).
 */

import type {
  DidcommTransport,
  PeerStore,
  AtlasBridge,
  MessageClassifier,
  MessageIdLog,
  DidcommMessage,
  OutboundResult,
} from "./types.js";
import type { PolicyMapper } from "./policy-mapper.js";
import { buildSendAllow, buildSendDeny } from "./audit-events.js";

// ---------------------------------------------------------------------------
// Outbound Handler
// ---------------------------------------------------------------------------

export class OutboundHandler {
  private readonly messageIdLog: MessageIdLog;

  constructor(
    private readonly transport: DidcommTransport,
    private readonly peerStore: PeerStore,
    private readonly atlas: AtlasBridge,
    private readonly classifier: MessageClassifier,
    private readonly mapper: PolicyMapper,
    messageIdLog?: MessageIdLog,
  ) {
    this.messageIdLog = messageIdLog ?? new InMemoryIdLog();
  }

  async send(peerDid: string, msg: DidcommMessage): Promise<OutboundResult> {
    // Step 1: Peer binding exists and is approved
    const peer = await this.peerStore.get(peerDid);
    if (!peer) {
      await this.logDeny(peerDid, msg.type, undefined, "PEER_NOT_FOUND");
      return { sent: false, reason: "PEER_NOT_FOUND", event: "DIDCOMM_SEND_DENY" };
    }
    if (peer.trustState === "revoked") {
      await this.logDeny(peerDid, msg.type, peer.mappedAgentId, "PEER_REVOKED");
      return { sent: false, reason: "PEER_REVOKED", event: "DIDCOMM_SEND_DENY" };
    }
    if (peer.trustState !== "approved") {
      await this.logDeny(peerDid, msg.type, peer.mappedAgentId, "PEER_NOT_APPROVED");
      return { sent: false, reason: "PEER_NOT_APPROVED", event: "DIDCOMM_SEND_DENY" };
    }

    // Steps 2-5: Delegation scope enforcement (when scope is present)
    if (peer.delegationScope) {
      const scopeResult = await this.enforceDelegationScope(peer.delegationScope, peerDid, msg);
      if (scopeResult) return scopeResult;
    }

    // Step 6: Replay/idempotency check (persisted across restarts)
    if (await this.messageIdLog.hasSeen(msg.id)) {
      await this.logDeny(peerDid, msg.type, peer.mappedAgentId, "REPLAY_DETECTED");
      return { sent: false, reason: "REPLAY_DETECTED", event: "DIDCOMM_SEND_DENY" };
    }
    await this.messageIdLog.record(msg.id);

    // Step 7: Classify
    const classified = this.classifier.classifyOutbound(msg);

    // Step 8: Atlas authorize()
    const request = this.mapper.toPermissionRequest(msg, {
      direction: "send",
      peer,
      classified,
    });
    const decision = await this.atlas.authorize(request);

    if (decision.verdict !== "allow") {
      await this.atlas.logEvent(buildSendDeny({
        peerDid,
        agentId: peer.mappedAgentId,
        messageType: msg.type,
        direction: "send",
        sensitivityLabels: classified.sensitivityLabels,
        reason: decision.reason ?? decision.verdict,
      }));
      return { sent: false, reason: decision.reason ?? decision.verdict, event: "DIDCOMM_SEND_DENY" };
    }

    // Step 9: Send to wire (ONLY after all checks pass)
    await this.transport.sendMessage(peerDid, msg);

    // Step 10: Log success
    await this.atlas.logEvent(buildSendAllow({
      peerDid,
      agentId: peer.mappedAgentId,
      messageType: msg.type,
      direction: "send",
      sensitivityLabels: classified.sensitivityLabels,
    }));

    return { sent: true, event: "DIDCOMM_SEND_ALLOW" };
  }

  // -------------------------------------------------------------------------
  // Delegation scope enforcement (steps 2-5)
  // -------------------------------------------------------------------------

  private async enforceDelegationScope(
    scope: import("./types.js").DelegationScope,
    peerDid: string,
    msg: DidcommMessage,
  ): Promise<OutboundResult | null> {
    const agentId = scope.delegatedAgentId;

    // Step 2: Delegation valid — hard expiry, no grace window
    if (new Date(scope.expiresAt).getTime() <= Date.now()) {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_EXPIRED");
      return { sent: false, reason: "DELEGATION_EXPIRED", event: "DIDCOMM_SEND_DENY" };
    }

    // Step 2b: Delegation not revoked — fail-closed if bridge doesn't implement
    if (this.atlas.isDelegationValid) {
      const valid = await this.atlas.isDelegationValid(agentId);
      if (!valid) {
        await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_REVOKED");
        return { sent: false, reason: "DELEGATION_REVOKED", event: "DIDCOMM_SEND_DENY" };
      }
    } else {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_VALIDATION_UNAVAILABLE");
      return { sent: false, reason: "DELEGATION_VALIDATION_UNAVAILABLE", event: "DIDCOMM_SEND_DENY" };
    }

    // Step 3: Direction allowed
    if (!scope.allowedDirections.includes("send")) {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_DIRECTION_DENIED");
      return { sent: false, reason: "DELEGATION_DIRECTION_DENIED", event: "DIDCOMM_SEND_DENY" };
    }

    // Step 4: Message type allowed (empty = all)
    if (scope.allowedMessageTypes.length > 0 && !scope.allowedMessageTypes.includes(msg.type)) {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_MESSAGE_TYPE_DENIED");
      return { sent: false, reason: "DELEGATION_MESSAGE_TYPE_DENIED", event: "DIDCOMM_SEND_DENY" };
    }

    // Step 5: Capability check
    const classified = this.classifier.classifyOutbound(msg);
    if (!scope.grantedCapabilities.includes(classified.requiredCapability)) {
      await this.logDeny(peerDid, msg.type, agentId, "DELEGATION_CAPABILITY_DENIED");
      return { sent: false, reason: "DELEGATION_CAPABILITY_DENIED", event: "DIDCOMM_SEND_DENY" };
    }

    return null; // All delegation checks passed
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private async logDeny(peerDid: string, messageType: string | undefined, agentId: string | undefined, reason: string): Promise<void> {
    await this.atlas.logEvent(buildSendDeny({ peerDid, messageType, agentId, reason }));
  }
}

/** Volatile fallback for dev/testing when no persistent log is provided */
class InMemoryIdLog implements MessageIdLog {
  private readonly ids = new Set<string>();
  async hasSeen(id: string) { return this.ids.has(id); }
  async record(id: string) { this.ids.add(id); }
  async size() { return this.ids.size; }
}
