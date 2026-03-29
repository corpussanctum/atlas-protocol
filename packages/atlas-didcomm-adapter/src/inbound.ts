/**
 * Atlas DIDComm Adapter — Inbound Message Handler
 *
 * Enforces the Atlas gatekeeper on all received DIDComm messages.
 * Pipeline: unpack → peer check → classify → authorize → deliver → log.
 * Fail closed at every step.
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
  constructor(
    private readonly transport: DidcommTransport,
    private readonly peerStore: PeerStore,
    private readonly atlas: AtlasBridge,
    private readonly classifier: MessageClassifier,
    private readonly mapper: PolicyMapper,
    private readonly localRouter?: (msg: DidcommMessage, classified: ClassifiedMessage) => Promise<void>,
  ) {}

  /**
   * Handle an inbound raw DIDComm message.
   * Returns whether the message was delivered to the local router.
   */
  async handle(raw: Uint8Array | string): Promise<InboundResult> {
    // Step 1: Unpack
    const msg = await this.transport.unpackMessage(raw);

    // Step 2: Peer lookup
    const senderDid = msg.from;
    if (!senderDid) {
      await this.atlas.logEvent(buildReceiveDeny({
        peerDid: "unknown",
        reason: "Message has no sender DID",
      }));
      return { delivered: false, reason: "NO_SENDER", event: "DIDCOMM_RECEIVE_DENY" };
    }

    const peer = await this.peerStore.get(senderDid);

    // Step 3: Trust check — no binding or revoked → deny
    if (!peer || peer.trustState === "revoked") {
      await this.atlas.logEvent(buildReceiveDeny({
        peerDid: senderDid,
        messageType: msg.type,
        reason: !peer ? "PEER_NOT_TRUSTED" : "PEER_REVOKED",
      }));
      return {
        delivered: false,
        reason: !peer ? "PEER_NOT_TRUSTED" : "PEER_REVOKED",
        event: "DIDCOMM_RECEIVE_DENY",
      };
    }

    // Step 4: Classify
    const classified = this.classifier.classifyInbound(msg);

    // Step 5: Build Atlas permission request
    const request = this.mapper.toPermissionRequest(msg, {
      direction: "receive",
      peer,
      classified,
    });

    // Step 6: Authorize
    const decision = await this.atlas.authorize(request);

    // Step 7: Deny if not allowed
    if (decision.verdict !== "allow") {
      await this.atlas.logEvent(buildReceiveDeny({
        peerDid: senderDid,
        agentId: peer.mappedAgentId,
        messageType: msg.type,
        direction: "receive",
        sensitivityLabels: classified.sensitivityLabels,
        reason: decision.reason ?? decision.verdict,
      }));
      return {
        delivered: false,
        reason: decision.reason ?? decision.verdict,
        event: "DIDCOMM_RECEIVE_DENY",
      };
    }

    // Step 8: Deliver to local router
    if (this.localRouter) {
      await this.localRouter(msg, classified);
    }

    // Step 9: Log success
    await this.atlas.logEvent(buildReceiveAllow({
      peerDid: senderDid,
      agentId: peer.mappedAgentId,
      messageType: msg.type,
      direction: "receive",
      sensitivityLabels: classified.sensitivityLabels,
    }));

    // Step 10: Update last seen
    peer.lastSeenAt = new Date().toISOString();
    await this.peerStore.put(peer);

    return { delivered: true, event: "DIDCOMM_RECEIVE_ALLOW" };
  }
}
