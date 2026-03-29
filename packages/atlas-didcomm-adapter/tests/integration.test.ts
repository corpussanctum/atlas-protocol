import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { AtlasDidcommAdapter } from "../src/index.js";
import { MockPeerStore } from "../src/peer-store.js";
import { MockAtlasBridge } from "./helpers/mock-atlas.js";
import { MockTransport } from "./helpers/mock-transport.js";
import type { DidcommMessage, ClassifiedMessage } from "../src/types.js";

function makeMsg(type: string, from?: string, body?: unknown): DidcommMessage {
  return { id: randomUUID(), type, from, body };
}

describe("AtlasDidcommAdapter (integration)", () => {
  let transport: MockTransport;
  let peerStore: MockPeerStore;
  let atlas: MockAtlasBridge;
  let deliveredMessages: Array<{ msg: DidcommMessage; classified: ClassifiedMessage }>;
  let adapter: AtlasDidcommAdapter;

  beforeEach(() => {
    transport = new MockTransport();
    peerStore = new MockPeerStore();
    atlas = new MockAtlasBridge();
    deliveredMessages = [];

    adapter = new AtlasDidcommAdapter({
      transport,
      atlas,
      peerStore,
      localRouter: async (msg, classified) => {
        deliveredMessages.push({ msg, classified });
      },
    });
  });

  it("full pairing flow: invite -> accept -> approve -> approved", async () => {
    atlas.setVerdict("allow");

    // Create invitation
    const invite = await adapter.createInvitation("agent-1");
    assert.ok(invite.invitationId);
    assert.ok(invite.invitation);

    // Accept invitation
    const result = await adapter.acceptInvitation({
      invitation: invite.invitation,
      localAgentId: "agent-1",
      alias: "test-peer",
    });

    assert.equal(result.approved, true);
    assert.equal(result.trustState, "approved");
    assert.equal(result.peerDid, "did:peer:mock-peer-123");

    // Verify peer is stored as approved
    const peer = await adapter.getPeer("did:peer:mock-peer-123");
    assert.ok(peer);
    assert.equal(peer.trustState, "approved");
  });

  it("receive health message: atlas allow -> delivered", async () => {
    // Set up an approved peer
    atlas.setVerdict("allow");
    await adapter.acceptInvitation({ invitation: "inv", alias: "clinic" });

    // Clear events from pairing
    atlas.events = [];
    deliveredMessages = [];

    // Receive a health message from the approved peer
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:mock-peer-123", { summary: "annual checkup" });
    const result = await adapter.handleInbound(JSON.stringify(msg));

    assert.equal(result.delivered, true);
    assert.equal(result.event, "DIDCOMM_RECEIVE_ALLOW");
    assert.equal(deliveredMessages.length, 1);
    assert.equal(deliveredMessages[0].classified.protocolFamily, "health");
  });

  it("receive health message: atlas deny -> not delivered", async () => {
    // Set up an approved peer first
    atlas.setVerdict("allow");
    await adapter.acceptInvitation({ invitation: "inv" });

    // Now deny subsequent messages
    atlas.setVerdict("deny");
    deliveredMessages = [];

    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:mock-peer-123");
    const result = await adapter.handleInbound(JSON.stringify(msg));

    assert.equal(result.delivered, false);
    assert.equal(result.event, "DIDCOMM_RECEIVE_DENY");
    assert.equal(deliveredMessages.length, 0);
  });

  it("send health message: atlas allow -> sent", async () => {
    // Set up an approved peer
    atlas.setVerdict("allow");
    await adapter.acceptInvitation({ invitation: "inv" });
    transport.messagesSent = [];

    const msg = makeMsg("clinic/appointment.summary.response", undefined, { plan: "follow-up in 6mo" });
    const result = await adapter.send("did:peer:mock-peer-123", msg);

    assert.equal(result.sent, true);
    assert.equal(result.event, "DIDCOMM_SEND_ALLOW");
    assert.equal(transport.messagesSent.length, 1);
  });

  it("send to unapproved peer -> denied", async () => {
    // Peer exists but was denied during pairing (untrusted)
    atlas.setVerdict("deny");
    await adapter.acceptInvitation({ invitation: "inv" });
    transport.messagesSent = [];

    const msg = makeMsg("test/msg");
    const result = await adapter.send("did:peer:mock-peer-123", msg);

    assert.equal(result.sent, false);
    assert.equal(result.reason, "PEER_NOT_APPROVED");
    assert.equal(transport.messagesSent.length, 0);
  });

  it("receive from revoked peer -> denied", async () => {
    // Set up peer then revoke
    atlas.setVerdict("allow");
    await adapter.acceptInvitation({ invitation: "inv" });
    await adapter.revokePeer("did:peer:mock-peer-123", "trust violation");
    atlas.events = [];

    const msg = makeMsg("test/msg", "did:peer:mock-peer-123");
    const result = await adapter.handleInbound(JSON.stringify(msg));

    assert.equal(result.delivered, false);
    assert.equal(result.reason, "PEER_REVOKED");
    assert.equal(deliveredMessages.length, 0);
  });

  it("full bidirectional exchange", async () => {
    atlas.setVerdict("allow");
    await adapter.acceptInvitation({ invitation: "inv", alias: "partner" });
    deliveredMessages = [];
    transport.messagesSent = [];

    // Receive an inbound message
    const inMsg = makeMsg("clinic/appointment.summary.request", "did:peer:mock-peer-123", { q: "status?" });
    const inResult = await adapter.handleInbound(JSON.stringify(inMsg));
    assert.equal(inResult.delivered, true);

    // Send a response
    const outMsg = makeMsg("clinic/appointment.summary.response", undefined, { a: "all good" });
    const outResult = await adapter.send("did:peer:mock-peer-123", outMsg);
    assert.equal(outResult.sent, true);

    // Verify both directions worked
    assert.equal(deliveredMessages.length, 1);
    assert.equal(transport.messagesSent.length, 1);
  });

  it("revoke mid-session: subsequent operations fail", async () => {
    atlas.setVerdict("allow");
    await adapter.acceptInvitation({ invitation: "inv" });

    // Verify send works before revocation
    const msg1 = makeMsg("test/msg");
    const beforeRevoke = await adapter.send("did:peer:mock-peer-123", msg1);
    assert.equal(beforeRevoke.sent, true);

    // Revoke the peer
    await adapter.revokePeer("did:peer:mock-peer-123", "compromised");

    // Verify send fails after revocation
    const msg2 = makeMsg("test/msg");
    const afterRevoke = await adapter.send("did:peer:mock-peer-123", msg2);
    assert.equal(afterRevoke.sent, false);
    assert.equal(afterRevoke.reason, "PEER_REVOKED");

    // Verify receive fails after revocation
    const inMsg = makeMsg("test/msg", "did:peer:mock-peer-123");
    const inResult = await adapter.handleInbound(JSON.stringify(inMsg));
    assert.equal(inResult.delivered, false);
    assert.equal(inResult.reason, "PEER_REVOKED");
  });
});
