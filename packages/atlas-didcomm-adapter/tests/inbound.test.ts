import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { InboundHandler } from "../src/inbound.js";
import { DefaultClassifier } from "../src/classifier.js";
import { PolicyMapper } from "../src/policy-mapper.js";
import { MockPeerStore } from "../src/peer-store.js";
import { MockAtlasBridge } from "./helpers/mock-atlas.js";
import { MockTransport } from "./helpers/mock-transport.js";
import type { DidcommMessage, PeerBinding, ClassifiedMessage } from "../src/types.js";

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

function packMsg(msg: DidcommMessage): string {
  return JSON.stringify(msg);
}

describe("InboundHandler", () => {
  let transport: MockTransport;
  let peerStore: MockPeerStore;
  let atlas: MockAtlasBridge;
  let classifier: DefaultClassifier;
  let mapper: PolicyMapper;
  let deliveredMessages: Array<{ msg: DidcommMessage; classified: ClassifiedMessage }>;
  let handler: InboundHandler;

  beforeEach(() => {
    transport = new MockTransport();
    peerStore = new MockPeerStore();
    atlas = new MockAtlasBridge();
    classifier = new DefaultClassifier();
    mapper = new PolicyMapper();
    deliveredMessages = [];

    const localRouter = async (msg: DidcommMessage, classified: ClassifiedMessage) => {
      deliveredMessages.push({ msg, classified });
    };

    handler = new InboundHandler(transport, peerStore, atlas, classifier, mapper, localRouter);
  });

  it("denies message from unknown peer (no binding)", async () => {
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:unknown-sender");
    const result = await handler.handle(packMsg(msg));
    assert.equal(result.delivered, false);
    assert.equal(result.reason, "PEER_NOT_FOUND");
  });

  it("denies message from revoked peer", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:revoked-sender", trustState: "revoked" }));
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:revoked-sender");
    const result = await handler.handle(packMsg(msg));
    assert.equal(result.delivered, false);
    assert.equal(result.reason, "PEER_REVOKED");
  });

  it("logs DIDCOMM_RECEIVE_DENY for unknown peer", async () => {
    const msg = makeMsg("test/msg", "did:peer:unknown");
    await handler.handle(packMsg(msg));
    const denyEvents = atlas.getEventsByType("DIDCOMM_RECEIVE_DENY");
    assert.equal(denyEvents.length, 1);
  });

  it("logs DIDCOMM_RECEIVE_DENY for revoked peer", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:revoked", trustState: "revoked" }));
    const msg = makeMsg("test/msg", "did:peer:revoked");
    await handler.handle(packMsg(msg));
    const denyEvents = atlas.getEventsByType("DIDCOMM_RECEIVE_DENY");
    assert.equal(denyEvents.length, 1);
  });

  it("calls classifier on trusted peer message", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:trusted" }));
    atlas.setVerdict("allow");
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:trusted", { summary: "checkup" });
    const result = await handler.handle(packMsg(msg));
    assert.equal(result.delivered, true);
    // Classification happened because the message was delivered with classified data
    assert.equal(deliveredMessages.length, 1);
    assert.equal(deliveredMessages[0].classified.protocolFamily, "health");
  });

  it("calls atlas.authorize with classified request", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:auth-test" }));
    atlas.setVerdict("allow");
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:auth-test");
    await handler.handle(packMsg(msg));
    // Authorize was called — we know because RECEIVE_ALLOW was logged
    const allowEvents = atlas.getEventsByType("DIDCOMM_RECEIVE_ALLOW");
    assert.equal(allowEvents.length, 1);
  });

  it("denies when atlas returns 'deny'", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:denied" }));
    atlas.setVerdict("deny");
    const msg = makeMsg("test/msg", "did:peer:denied");
    const result = await handler.handle(packMsg(msg));
    assert.equal(result.delivered, false);
    assert.equal(result.event, "DIDCOMM_RECEIVE_DENY");
  });

  it("denies when atlas returns 'ask'", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:ask" }));
    atlas.setVerdict("ask");
    const msg = makeMsg("test/msg", "did:peer:ask");
    const result = await handler.handle(packMsg(msg));
    assert.equal(result.delivered, false);
    assert.equal(result.event, "DIDCOMM_RECEIVE_DENY");
  });

  it("calls localRouter when atlas allows", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:allowed" }));
    atlas.setVerdict("allow");
    const msg = makeMsg("test/msg", "did:peer:allowed", { hello: "world" });
    await handler.handle(packMsg(msg));
    assert.equal(deliveredMessages.length, 1);
    assert.deepEqual((deliveredMessages[0].msg.body as Record<string, string>).hello, "world");
  });

  it("logs DIDCOMM_RECEIVE_ALLOW on success", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:success" }));
    atlas.setVerdict("allow");
    const msg = makeMsg("test/msg", "did:peer:success");
    const result = await handler.handle(packMsg(msg));
    assert.equal(result.event, "DIDCOMM_RECEIVE_ALLOW");
    const allowEvents = atlas.getEventsByType("DIDCOMM_RECEIVE_ALLOW");
    assert.equal(allowEvents.length, 1);
  });

  it("never delivers when auth fails even with localRouter present", async () => {
    await peerStore.put(makePeer({ peerDid: "did:peer:no-deliver" }));
    atlas.setVerdict("deny");
    const msg = makeMsg("test/msg", "did:peer:no-deliver");
    await handler.handle(packMsg(msg));
    assert.equal(deliveredMessages.length, 0, "localRouter should NOT be called when auth fails");
  });

  it("handles message with no from field as denied", async () => {
    const msg = makeMsg("test/msg"); // no from
    const result = await handler.handle(packMsg(msg));
    assert.equal(result.delivered, false);
    assert.equal(result.reason, "NO_SENDER");
    assert.equal(result.event, "DIDCOMM_RECEIVE_DENY");
  });
});
