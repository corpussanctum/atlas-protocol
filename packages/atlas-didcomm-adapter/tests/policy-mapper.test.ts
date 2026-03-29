import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { PolicyMapper } from "../src/policy-mapper.js";
import type { DidcommMessage, ClassifiedMessage, PeerBinding } from "../src/types.js";

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

function makeClassified(overrides?: Partial<ClassifiedMessage>): ClassifiedMessage {
  return {
    messageType: "clinic/appointment.summary.request",
    protocolFamily: "health",
    direction: "receive",
    sensitivityLabels: ["health", "phi"],
    requiredCapability: "message:receive:health",
    preview: '{"appointment":"summary"}',
    ...overrides,
  };
}

describe("PolicyMapper", () => {
  const mapper = new PolicyMapper();

  it("tool_name is always 'DIDComm'", () => {
    const msg = makeMsg("test/msg", "did:peer:test-peer");
    const peer = makePeer();
    const classified = makeClassified();
    const req = mapper.toPermissionRequest(msg, { direction: "receive", peer, classified });
    assert.equal(req.tool_name, "DIDComm");
  });

  it("action is 'receive' for inbound messages", () => {
    const msg = makeMsg("test/msg", "did:peer:test-peer");
    const classified = makeClassified({ direction: "receive" });
    const req = mapper.toPermissionRequest(msg, { direction: "receive", peer: makePeer(), classified });
    assert.equal(req.action, "receive");
  });

  it("action is 'send' for outbound messages", () => {
    const msg = makeMsg("test/msg");
    const classified = makeClassified({ direction: "send" });
    const req = mapper.toPermissionRequest(msg, { direction: "send", peer: makePeer(), classified });
    assert.equal(req.action, "send");
  });

  it("buildPairingRequest sets action to 'pair'", () => {
    const req = mapper.buildPairingRequest({ peerDid: "did:peer:new" });
    assert.equal(req.action, "pair");
    assert.equal(req.tool_name, "DIDComm");
    assert.equal(req.protocol_family, "pairing");
  });

  it("input_preview is single-line and includes peer_did, trust, type, family", () => {
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:test-peer");
    const peer = makePeer({ trustState: "approved" });
    const classified = makeClassified();
    const req = mapper.toPermissionRequest(msg, { direction: "receive", peer, classified });

    assert.ok(!req.input_preview.includes("\n"), "input_preview should be single-line");
    assert.ok(req.input_preview.includes("did:peer:test-peer"), "should include peer_did");
    assert.ok(req.input_preview.includes("approved"), "should include trust state");
    assert.ok(req.input_preview.includes("clinic/appointment.summary.request"), "should include message type");
    assert.ok(req.input_preview.includes("health"), "should include family");
  });

  it("content_preview is redacted when sensitivity labels present and redactSensitiveContent=true", () => {
    const redactMapper = new PolicyMapper({ redactSensitiveContent: true });
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:test-peer");
    const classified = makeClassified({ sensitivityLabels: ["health", "phi"], preview: '{"data":"secret"}' });
    const req = redactMapper.toPermissionRequest(msg, { direction: "receive", peer: makePeer(), classified });

    assert.ok(req.content_preview, "content_preview should exist");
    assert.ok(req.content_preview.startsWith("[REDACTED:"), "should be redacted");
    assert.ok(req.content_preview.includes("health"), "redaction label should include sensitivity type");
  });

  it("content_preview is NOT redacted when redactSensitiveContent=false", () => {
    const noRedactMapper = new PolicyMapper({ redactSensitiveContent: false });
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:test-peer");
    const classified = makeClassified({ sensitivityLabels: ["health", "phi"], preview: '{"data":"visible"}' });
    const req = noRedactMapper.toPermissionRequest(msg, { direction: "receive", peer: makePeer(), classified });

    assert.ok(req.content_preview, "content_preview should exist");
    assert.ok(!req.content_preview.startsWith("[REDACTED"), "should NOT be redacted");
    assert.ok(req.content_preview.includes("visible"), "original preview content should be present");
  });

  it("sensitivity_labels are deduped and sorted", () => {
    const msg = makeMsg("test/msg");
    const classified = makeClassified({ sensitivityLabels: ["phi", "health", "phi", "health"] });
    const req = mapper.toPermissionRequest(msg, { direction: "receive", peer: makePeer(), classified });
    assert.deepEqual(req.sensitivity_labels, ["health", "phi"]);
  });

  it("input_preview truncated at maxPreviewLength", () => {
    const shortMapper = new PolicyMapper({ maxPreviewLength: 30 });
    const msg = makeMsg("clinic/appointment.summary.request", "did:peer:a-very-long-did-identifier-that-exceeds-limits");
    const classified = makeClassified();
    const req = shortMapper.toPermissionRequest(msg, { direction: "receive", peer: makePeer({ peerDid: "did:peer:a-very-long-did-identifier-that-exceeds-limits" }), classified });
    assert.ok(req.input_preview.length <= 30, `input_preview should be truncated to 30 chars, got ${req.input_preview.length}`);
  });

  it("content_preview is undefined when classified has no preview", () => {
    const msg = makeMsg("test/msg");
    const classified = makeClassified({ preview: undefined });
    const req = mapper.toPermissionRequest(msg, { direction: "receive", peer: makePeer(), classified });
    assert.equal(req.content_preview, undefined);
  });
});
