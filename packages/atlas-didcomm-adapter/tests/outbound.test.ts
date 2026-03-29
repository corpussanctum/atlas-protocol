import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { OutboundHandler } from "../src/outbound.js";
import { DefaultClassifier } from "../src/classifier.js";
import { PolicyMapper } from "../src/policy-mapper.js";
import { MockPeerStore } from "../src/peer-store.js";
import { MockAtlasBridge } from "./helpers/mock-atlas.js";
import { MockTransport } from "./helpers/mock-transport.js";
import type { DidcommMessage, PeerBinding } from "../src/types.js";

function makeMsg(type: string, from?: string, body?: unknown): DidcommMessage {
  return { id: randomUUID(), type, from, body };
}

function makePeer(overrides?: Partial<PeerBinding>): PeerBinding {
  return {
    peerDid: "did:peer:test-peer",
    trustState: "approved",
    allowedMessageTypes: [],
    allowedDirections: ["send", "receive"],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

describe("OutboundHandler", () => {
  let transport: MockTransport;
  let peerStore: MockPeerStore;
  let atlas: MockAtlasBridge;
  let classifier: DefaultClassifier;
  let mapper: PolicyMapper;
  let handler: OutboundHandler;

  beforeEach(() => {
    transport = new MockTransport();
    peerStore = new MockPeerStore();
    atlas = new MockAtlasBridge();
    classifier = new DefaultClassifier();
    mapper = new PolicyMapper();
    handler = new OutboundHandler(transport, peerStore, atlas, classifier, mapper);
  });

  it("denies when peer is not found", async () => {
    const msg = makeMsg("test/msg");
    const result = await handler.send("did:peer:nonexistent", msg);
    assert.equal(result.sent, false);
    assert.equal(result.reason, "PEER_NOT_FOUND");
    assert.equal(result.event, "DIDCOMM_SEND_DENY");
  });

  it("denies when peer is 'paired' (not approved)", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:paired", trustState: "paired" }));
    const msg = makeMsg("test/msg");
    const result = await handler.send("did:peer:paired", msg);
    assert.equal(result.sent, false);
    assert.equal(result.reason, "PEER_NOT_APPROVED");
  });

  it("denies when peer is 'revoked'", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:revoked", trustState: "revoked" }));
    const msg = makeMsg("test/msg");
    const result = await handler.send("did:peer:revoked", msg);
    assert.equal(result.sent, false);
    assert.equal(result.reason, "PEER_REVOKED");
  });

  it("denies when peer is 'untrusted'", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:untrusted", trustState: "untrusted" }));
    const msg = makeMsg("test/msg");
    const result = await handler.send("did:peer:untrusted", msg);
    assert.equal(result.sent, false);
    assert.equal(result.reason, "PEER_NOT_APPROVED");
  });

  it("logs DIDCOMM_SEND_DENY for all denial cases", async () => {
    const msg = makeMsg("test/msg");

    // Not found
    await handler.send("did:peer:nope", msg);
    // Paired
    await peerStore.put(makePeer({ peerDid: "did:peer:paired", trustState: "paired" }));
    await handler.send("did:peer:paired", msg);
    // Revoked
    await peerStore.put(makePeer({ peerDid: "did:peer:revoked", trustState: "revoked" }));
    await handler.send("did:peer:revoked", msg);

    const denyEvents = atlas.getEventsByType("DIDCOMM_SEND_DENY");
    assert.equal(denyEvents.length, 3, "All three denial cases should log DIDCOMM_SEND_DENY");
  });

  it("does NOT call transport.sendMessage on deny", async () => {
    const msg = makeMsg("test/msg");
    await handler.send("did:peer:nonexistent", msg);
    assert.equal(transport.messagesSent.length, 0, "No message should hit the wire on deny");
  });

  it("calls atlas.authorize for approved peer", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:approved" }));
    atlas.setVerdict("allow");
    const msg = makeMsg("test/msg");
    await handler.send("did:peer:approved", msg);
    // We know authorize was called because SEND_ALLOW was logged
    const allowEvents = atlas.getEventsByType("DIDCOMM_SEND_ALLOW");
    assert.equal(allowEvents.length, 1);
  });

  it("denies when atlas returns 'deny' and does not send to wire", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:policy-deny" }));
    atlas.setVerdict("deny");
    const msg = makeMsg("test/msg");
    const result = await handler.send("did:peer:policy-deny", msg);
    assert.equal(result.sent, false);
    assert.equal(result.event, "DIDCOMM_SEND_DENY");
    assert.equal(transport.messagesSent.length, 0);
  });

  it("denies when atlas returns 'ask' and does not send to wire", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:policy-ask" }));
    atlas.setVerdict("ask");
    const msg = makeMsg("test/msg");
    const result = await handler.send("did:peer:policy-ask", msg);
    assert.equal(result.sent, false);
    assert.equal(result.event, "DIDCOMM_SEND_DENY");
    assert.equal(transport.messagesSent.length, 0);
  });

  it("calls transport.sendMessage on allow", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:send-ok" }));
    atlas.setVerdict("allow");
    const msg = makeMsg("test/msg", undefined, { payload: "data" });
    await handler.send("did:peer:send-ok", msg);
    assert.equal(transport.messagesSent.length, 1);
    assert.equal(transport.messagesSent[0].peerDid, "did:peer:send-ok");
    assert.deepEqual(transport.messagesSent[0].msg.id, msg.id);
  });

  it("logs DIDCOMM_SEND_ALLOW after successful send", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:logged" }));
    atlas.setVerdict("allow");
    const msg = makeMsg("test/msg");
    const result = await handler.send("did:peer:logged", msg);
    assert.equal(result.sent, true);
    assert.equal(result.event, "DIDCOMM_SEND_ALLOW");
    const allowEvents = atlas.getEventsByType("DIDCOMM_SEND_ALLOW");
    assert.equal(allowEvents.length, 1);
  });
});
