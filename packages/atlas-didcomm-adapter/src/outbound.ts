/**
 * Atlas DIDComm Adapter — Outbound Message Handler
 *
 * Enforces the Atlas gatekeeper on all sent DIDComm messages.
 * Pipeline: peer check → classify → authorize → send to wire → log.
 * CRITICAL: A denied message MUST NEVER hit the wire.
 */

import type {
  DidcommTransport,
  PeerStore,
  AtlasBridge,
  MessageClassifier,
  DidcommMessage,
  OutboundResult,
} from "./types.js";
import type { PolicyMapper } from "./policy-mapper.js";
import { buildSendAllow, buildSendDeny } from "./audit-events.js";

// ---------------------------------------------------------------------------
// Outbound Handler
// ---------------------------------------------------------------------------

export class OutboundHandler {
  constructor(
    private readonly transport: DidcommTransport,
    private readonly peerStore: PeerStore,
    private readonly atlas: AtlasBridge,
    private readonly classifier: MessageClassifier,
    private readonly mapper: PolicyMapper,
  ) {}

  /**
   * Send a DIDComm message to a peer.
   * Returns whether the message was transmitted to the wire.
   */
  async send(peerDid: string, msg: DidcommMessage): Promise<OutboundResult> {
    // Step 1: Peer lookup
    const peer = await this.peerStore.get(peerDid);

    // Step 2: Trust check — must be "approved"
    if (!peer || peer.trustState !== "approved") {
      const reason = !peer
        ? "PEER_NOT_FOUND"
        : peer.trustState === "revoked"
          ? "PEER_REVOKED"
          : "PEER_NOT_APPROVED";

      await this.atlas.logEvent(buildSendDeny({
        peerDid,
        messageType: msg.type,
        direction: "send",
        reason,
      }));
      return { sent: false, reason, event: "DIDCOMM_SEND_DENY" };
    }

    // Step 3: Classify
    const classified = this.classifier.classifyOutbound(msg);

    // Step 4: Build Atlas permission request
    const request = this.mapper.toPermissionRequest(msg, {
      direction: "send",
      peer,
      classified,
    });

    // Step 5: Authorize
    const decision = await this.atlas.authorize(request);

    // Step 6: Deny if not allowed — NEVER send to wire
    if (decision.verdict !== "allow") {
      await this.atlas.logEvent(buildSendDeny({
        peerDid,
        agentId: peer.mappedAgentId,
        messageType: msg.type,
        direction: "send",
        sensitivityLabels: classified.sensitivityLabels,
        reason: decision.reason ?? decision.verdict,
      }));
      return {
        sent: false,
        reason: decision.reason ?? decision.verdict,
        event: "DIDCOMM_SEND_DENY",
      };
    }

    // Step 7: Send to wire (only after authorization)
    await this.transport.sendMessage(peerDid, msg);

    // Step 8: Log success
    await this.atlas.logEvent(buildSendAllow({
      peerDid,
      agentId: peer.mappedAgentId,
      messageType: msg.type,
      direction: "send",
      sensitivityLabels: classified.sensitivityLabels,
    }));

    return { sent: true, event: "DIDCOMM_SEND_ALLOW" };
  }
}
