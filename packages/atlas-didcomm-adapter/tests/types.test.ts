import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type {
  MessagingCapability,
  PeerBinding,
  DidcommPermissionRequest,
  AtlasDidcommEventType,
  ClassifiedMessage,
} from "../src/types.js";

describe("types", () => {
  describe("MessagingCapability", () => {
    it("includes all expected stable string values", () => {
      const capabilities: MessagingCapability[] = [
        "peer:bind",
        "peer:revoke",
        "message:send",
        "message:receive",
        "message:send:financial",
        "message:receive:financial",
        "message:send:health",
        "message:receive:health",
      ];
      assert.equal(capabilities.length, 8);
      // Each value is a non-empty string
      for (const cap of capabilities) {
        assert.equal(typeof cap, "string");
        assert.ok(cap.length > 0);
      }
    });
  });

  describe("PeerBinding trustState", () => {
    it("supports all four trust state transitions", () => {
      const states: PeerBinding["trustState"][] = [
        "untrusted",
        "paired",
        "approved",
        "revoked",
      ];
      assert.equal(states.length, 4);
      // Verify the natural lifecycle order is representable
      const binding: PeerBinding = {
        peerDid: "did:peer:test",
        trustState: "untrusted",
        allowedMessageTypes: [],
        allowedDirections: ["send", "receive"],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      binding.trustState = "paired";
      assert.equal(binding.trustState, "paired");
      binding.trustState = "approved";
      assert.equal(binding.trustState, "approved");
      binding.trustState = "revoked";
      assert.equal(binding.trustState, "revoked");
    });
  });

  describe("DidcommPermissionRequest", () => {
    it("tool_name is always 'DIDComm'", () => {
      const req: DidcommPermissionRequest = {
        request_id: "test-id",
        tool_name: "DIDComm",
        action: "receive",
        peer_did: "did:peer:test",
        message_type: "test/message",
        protocol_family: "test",
        input_preview: "DIDComm:receive peer=did:peer:test",
        sensitivity_labels: [],
        transport_meta: { encrypted: false, authenticated: false, signed: false },
      };
      assert.equal(req.tool_name, "DIDComm");
    });
  });

  describe("AtlasDidcommEventType", () => {
    it("all 10 event types exist as valid values", () => {
      const eventTypes: AtlasDidcommEventType[] = [
        "DIDCOMM_PAIR_INIT",
        "DIDCOMM_PAIR_ACCEPT",
        "DIDCOMM_PEER_BOUND",
        "DIDCOMM_SEND_ALLOW",
        "DIDCOMM_SEND_DENY",
        "DIDCOMM_RECEIVE_ALLOW",
        "DIDCOMM_RECEIVE_DENY",
        "DIDCOMM_PEER_REVOKED",
        "DIDCOMM_DELEGATED_SEND",
        "DIDCOMM_DELEGATED_RECEIVE",
      ];
      assert.equal(eventTypes.length, 10);
      const unique = new Set(eventTypes);
      assert.equal(unique.size, 10, "All event types should be unique");
    });
  });

  describe("ClassifiedMessage", () => {
    it("direction can be 'send' or 'receive'", () => {
      const inbound: ClassifiedMessage = {
        messageType: "test/msg",
        protocolFamily: "test",
        direction: "receive",
        sensitivityLabels: [],
        requiredCapability: "message:receive",
      };
      assert.equal(inbound.direction, "receive");

      const outbound: ClassifiedMessage = {
        messageType: "test/msg",
        protocolFamily: "test",
        direction: "send",
        sensitivityLabels: [],
        requiredCapability: "message:send",
      };
      assert.equal(outbound.direction, "send");
    });
  });
});
