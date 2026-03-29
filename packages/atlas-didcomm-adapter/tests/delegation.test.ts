/**
 * Tests for Milestone 3 — Delegation-aware messaging
 *
 * Covers: peer-scoped delegation, scope enforcement in inbound/outbound,
 * expired/revoked delegation handling, cascade revocation effects.
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { PairingManager } from "../src/pairing.js";
import { InboundHandler } from "../src/inbound.js";
import { OutboundHandler } from "../src/outbound.js";
import { DefaultClassifier } from "../src/classifier.js";
import { PolicyMapper } from "../src/policy-mapper.js";
import { MockPeerStore } from "../src/peer-store.js";
import { MockAtlasBridge } from "./helpers/mock-atlas.js";
import { MockTransport } from "./helpers/mock-transport.js";
import type { PeerBinding, DelegationScope, DidcommMessage } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMsg(type: string, from?: string, body?: unknown): DidcommMessage {
  return { id: randomUUID(), type, from, body };
}

function makePeer(overrides?: Partial<PeerBinding>): PeerBinding {
  return {
    peerDid: "did:peer:clinic-123",
    trustState: "approved",
    allowedMessageTypes: [],
    allowedDirections: ["send", "receive"],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

function makeScope(overrides?: Partial<DelegationScope>): DelegationScope {
  return {
    delegatedAgentId: "did:atlas:delegated-health-agent",
    parentAgentId: "did:atlas:orchestrator-001",
    grantedCapabilities: ["message:send:health", "message:receive:health"],
    allowedMessageTypes: ["clinic/appointment.summary.request", "clinic/appointment.summary.response"],
    allowedDirections: ["send", "receive"],
    expiresAt: new Date(Date.now() + 3600_000).toISOString(), // 1 hour
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Pairing — delegation binding
// ---------------------------------------------------------------------------

describe("Delegation — PairingManager", () => {
  let atlas: MockAtlasBridge;
  let store: MockPeerStore;
  let transport: MockTransport;
  let pairing: PairingManager;

  beforeEach(() => {
    atlas = new MockAtlasBridge();
    store = new MockPeerStore();
    transport = new MockTransport();
    pairing = new PairingManager(transport, store, atlas);
  });

  it("bindPeerToAgent sets mappedAgentId on approved peer", async () => {
    await store.put(makePeer());
    const result = await pairing.bindPeerToAgent("did:peer:clinic-123", "did:atlas:sub-agent");
    assert.equal(result.mappedAgentId, "did:atlas:sub-agent");
  });

  it("bindPeerToAgent throws for unknown peer", async () => {
    await assert.rejects(
      () => pairing.bindPeerToAgent("did:peer:unknown", "did:atlas:x"),
      /Peer not found/,
    );
  });

  it("bindPeerToAgent throws for non-approved peer", async () => {
    await store.put(makePeer({ trustState: "paired" }));
    await assert.rejects(
      () => pairing.bindPeerToAgent("did:peer:clinic-123", "did:atlas:x"),
      /Cannot bind agent/,
    );
  });

  it("setDelegationScope sets scope and mappedAgentId", async () => {
    await store.put(makePeer());
    const scope = makeScope();
    const result = await pairing.setDelegationScope("did:peer:clinic-123", scope);
    assert.deepEqual(result.delegationScope, scope);
    assert.equal(result.mappedAgentId, "did:atlas:delegated-health-agent");
  });

  it("setDelegationScope logs DIDCOMM_DELEGATED_SEND event", async () => {
    await store.put(makePeer());
    await pairing.setDelegationScope("did:peer:clinic-123", makeScope());
    const events = atlas.getEventsByType("DIDCOMM_DELEGATED_SEND");
    assert.equal(events.length, 1);
    assert.equal(events[0].agentId, "did:atlas:delegated-health-agent");
  });

  it("setDelegationScope throws for non-approved peer", async () => {
    await store.put(makePeer({ trustState: "revoked" }));
    await assert.rejects(
      () => pairing.setDelegationScope("did:peer:clinic-123", makeScope()),
      /Cannot set delegation/,
    );
  });

  it("clearDelegationScope removes scope and mappedAgentId", async () => {
    const peer = makePeer();
    const scope = makeScope();
    peer.delegationScope = scope;
    peer.mappedAgentId = scope.delegatedAgentId;
    await store.put(peer);

    const result = await pairing.clearDelegationScope("did:peer:clinic-123");
    assert.equal(result.delegationScope, undefined);
    assert.equal(result.mappedAgentId, undefined);
  });

  it("acceptInvitation sets mappedAgentId from localAgentId", async () => {
    const result = await pairing.acceptInvitation({
      invitation: "test-invite",
      localAgentId: "did:atlas:my-agent",
    });
    assert.equal(result.binding.mappedAgentId, "did:atlas:my-agent");
  });
});

// ---------------------------------------------------------------------------
// Outbound — delegation scope enforcement
// ---------------------------------------------------------------------------

describe("Delegation — OutboundHandler scope enforcement", () => {
  let atlas: MockAtlasBridge;
  let store: MockPeerStore;
  let transport: MockTransport;
  let outbound: OutboundHandler;

  beforeEach(() => {
    atlas = new MockAtlasBridge();
    store = new MockPeerStore();
    transport = new MockTransport();
    outbound = new OutboundHandler(transport, store, atlas, new DefaultClassifier(), new PolicyMapper());
  });

  it("allows send when message type is in delegation scope", async () => {
    await store.put(makePeer({ delegationScope: makeScope() }));
    const result = await outbound.send(
      "did:peer:clinic-123",
      makeMsg("clinic/appointment.summary.request"),
    );
    assert.equal(result.sent, true);
    assert.equal(transport.messagesSent.length, 1);
  });

  it("denies send when message type is NOT in delegation scope", async () => {
    await store.put(makePeer({ delegationScope: makeScope() }));
    const result = await outbound.send(
      "did:peer:clinic-123",
      makeMsg("bank/statement.request"),
    );
    assert.equal(result.sent, false);
    assert.equal(result.reason, "DELEGATION_MESSAGE_TYPE_DENIED");
    assert.equal(transport.messagesSent.length, 0, "Denied message must never hit wire");
  });

  it("denies send when delegation has expired", async () => {
    const expiredScope = makeScope({
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    await store.put(makePeer({ delegationScope: expiredScope }));
    const result = await outbound.send(
      "did:peer:clinic-123",
      makeMsg("clinic/appointment.summary.request"),
    );
    assert.equal(result.sent, false);
    assert.equal(result.reason, "DELEGATION_EXPIRED");
    assert.equal(transport.messagesSent.length, 0);
  });

  it("denies send when delegation direction excludes send", async () => {
    const receiveOnly = makeScope({ allowedDirections: ["receive"] });
    await store.put(makePeer({ delegationScope: receiveOnly }));
    const result = await outbound.send(
      "did:peer:clinic-123",
      makeMsg("clinic/appointment.summary.request"),
    );
    assert.equal(result.sent, false);
    assert.equal(result.reason, "DELEGATION_DIRECTION_DENIED");
  });

  it("denies send when isDelegationValid returns false", async () => {
    atlas.isDelegationValid = async () => false;
    await store.put(makePeer({ delegationScope: makeScope() }));
    const result = await outbound.send(
      "did:peer:clinic-123",
      makeMsg("clinic/appointment.summary.request"),
    );
    assert.equal(result.sent, false);
    assert.equal(result.reason, "DELEGATION_REVOKED");
    assert.equal(transport.messagesSent.length, 0);
  });

  it("allows send when scope has empty allowedMessageTypes (all types)", async () => {
    const anyType = makeScope({ allowedMessageTypes: [] });
    await store.put(makePeer({ delegationScope: anyType }));
    const result = await outbound.send(
      "did:peer:clinic-123",
      makeMsg("any/message.type"),
    );
    assert.equal(result.sent, true);
  });

  it("logs DIDCOMM_SEND_DENY with delegated agentId on scope denial", async () => {
    await store.put(makePeer({ delegationScope: makeScope() }));
    await outbound.send("did:peer:clinic-123", makeMsg("bank/statement.request"));
    const denyEvents = atlas.getEventsByType("DIDCOMM_SEND_DENY");
    assert.equal(denyEvents.length, 1);
    assert.equal(denyEvents[0].agentId, "did:atlas:delegated-health-agent");
  });
});

// ---------------------------------------------------------------------------
// Inbound — delegation scope enforcement
// ---------------------------------------------------------------------------

describe("Delegation — InboundHandler scope enforcement", () => {
  let atlas: MockAtlasBridge;
  let store: MockPeerStore;
  let transport: MockTransport;
  let inbound: InboundHandler;
  let delivered: boolean;

  beforeEach(() => {
    atlas = new MockAtlasBridge();
    store = new MockPeerStore();
    transport = new MockTransport();
    delivered = false;
    inbound = new InboundHandler(
      transport, store, atlas, new DefaultClassifier(), new PolicyMapper(),
      async () => { delivered = true; },
    );
  });

  function rawMsg(type: string, from: string): string {
    return JSON.stringify(makeMsg(type, from));
  }

  it("allows receive when message type is in delegation scope", async () => {
    await store.put(makePeer({ peerDid: "did:peer:clinic-123", delegationScope: makeScope() }));
    const result = await inbound.handle(rawMsg("clinic/appointment.summary.response", "did:peer:clinic-123"));
    assert.equal(result.delivered, true);
    assert.equal(delivered, true);
  });

  it("denies receive when message type is NOT in delegation scope", async () => {
    await store.put(makePeer({ peerDid: "did:peer:clinic-123", delegationScope: makeScope() }));
    const result = await inbound.handle(rawMsg("bank/statement.response", "did:peer:clinic-123"));
    assert.equal(result.delivered, false);
    assert.equal(result.reason, "DELEGATION_MESSAGE_TYPE_DENIED");
    assert.equal(delivered, false);
  });

  it("denies receive when delegation has expired", async () => {
    const expired = makeScope({ expiresAt: new Date(Date.now() - 60_000).toISOString() });
    await store.put(makePeer({ peerDid: "did:peer:clinic-123", delegationScope: expired }));
    const result = await inbound.handle(rawMsg("clinic/appointment.summary.response", "did:peer:clinic-123"));
    assert.equal(result.delivered, false);
    assert.equal(result.reason, "DELEGATION_EXPIRED");
  });

  it("denies receive when delegation direction excludes receive", async () => {
    const sendOnly = makeScope({ allowedDirections: ["send"] });
    await store.put(makePeer({ peerDid: "did:peer:clinic-123", delegationScope: sendOnly }));
    const result = await inbound.handle(rawMsg("clinic/appointment.summary.response", "did:peer:clinic-123"));
    assert.equal(result.delivered, false);
    assert.equal(result.reason, "DELEGATION_DIRECTION_DENIED");
  });

  it("denies receive when isDelegationValid returns false (cascade revoked)", async () => {
    atlas.isDelegationValid = async () => false;
    await store.put(makePeer({ peerDid: "did:peer:clinic-123", delegationScope: makeScope() }));
    const result = await inbound.handle(rawMsg("clinic/appointment.summary.response", "did:peer:clinic-123"));
    assert.equal(result.delivered, false);
    assert.equal(result.reason, "DELEGATION_REVOKED");
  });
});

// ---------------------------------------------------------------------------
// Integration — orchestrator delegation flow
// ---------------------------------------------------------------------------

describe("Delegation — Full orchestrator flow", () => {
  let atlas: MockAtlasBridge;
  let store: MockPeerStore;
  let transport: MockTransport;
  let pairing: PairingManager;
  let inbound: InboundHandler;
  let outbound: OutboundHandler;
  let routedMessages: Array<{ type: string }>;

  beforeEach(() => {
    atlas = new MockAtlasBridge();
    store = new MockPeerStore();
    transport = new MockTransport();
    transport.invitationResult = { peerDid: "did:peer:clinic-456" };
    routedMessages = [];
    const classifier = new DefaultClassifier();
    const mapper = new PolicyMapper();
    pairing = new PairingManager(transport, store, atlas);
    inbound = new InboundHandler(transport, store, atlas, classifier, mapper,
      async (msg) => { routedMessages.push({ type: msg.type }); },
    );
    outbound = new OutboundHandler(transport, store, atlas, classifier, mapper);
  });

  it("pair → delegate → send health → receive health → revoke delegation", async () => {
    // 1. Pair and approve
    const pairResult = await pairing.acceptInvitation({
      invitation: "clinic-invite",
      localAgentId: "did:atlas:orchestrator-001",
      alias: "clinic",
    });
    assert.equal(pairResult.approved, true);
    assert.equal(pairResult.trustState, "approved");

    // 2. Delegate health messaging to a sub-agent for this peer
    const scope = makeScope({
      delegatedAgentId: "did:atlas:health-sub",
      parentAgentId: "did:atlas:orchestrator-001",
      grantedCapabilities: ["message:send:health", "message:receive:health"],
      allowedMessageTypes: ["clinic/appointment.summary.request", "clinic/appointment.summary.response"],
      allowedDirections: ["send", "receive"],
    });
    await pairing.setDelegationScope("did:peer:clinic-456", scope);

    // Verify binding
    const peer = await store.get("did:peer:clinic-456");
    assert.equal(peer?.mappedAgentId, "did:atlas:health-sub");
    assert.ok(peer?.delegationScope);

    // 3. Send health message (should be allowed)
    const sendResult = await outbound.send(
      "did:peer:clinic-456",
      makeMsg("clinic/appointment.summary.request"),
    );
    assert.equal(sendResult.sent, true);

    // 4. Receive health response (should be delivered)
    const receiveResult = await inbound.handle(
      JSON.stringify(makeMsg("clinic/appointment.summary.response", "did:peer:clinic-456")),
    );
    assert.equal(receiveResult.delivered, true);
    assert.equal(routedMessages.length, 1);

    // 5. Try to send financial message (should be denied by scope)
    const financialResult = await outbound.send(
      "did:peer:clinic-456",
      makeMsg("bank/statement.request"),
    );
    assert.equal(financialResult.sent, false);
    assert.equal(financialResult.reason, "DELEGATION_MESSAGE_TYPE_DENIED");

    // 6. Clear delegation scope
    await pairing.clearDelegationScope("did:peer:clinic-456");
    const afterClear = await store.get("did:peer:clinic-456");
    assert.equal(afterClear?.delegationScope, undefined);
    assert.equal(afterClear?.mappedAgentId, undefined);
  });
});
