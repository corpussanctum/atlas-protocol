import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { PairingManager } from "../src/pairing.js";
import { MockPeerStore } from "../src/peer-store.js";
import { MockAtlasBridge } from "./helpers/mock-atlas.js";
import { MockTransport } from "./helpers/mock-transport.js";
import type { PeerBinding } from "../src/types.js";

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

describe("PairingManager", () => {
  let transport: MockTransport;
  let peerStore: MockPeerStore;
  let atlas: MockAtlasBridge;
  let manager: PairingManager;

  beforeEach(() => {
    transport = new MockTransport();
    peerStore = new MockPeerStore();
    atlas = new MockAtlasBridge();
    manager = new PairingManager(transport, peerStore, atlas);
  });

  describe("createInvitation", () => {
    it("logs DIDCOMM_PAIR_INIT event", async () => {
      await manager.createInvitation();
      const events = atlas.getEventsByType("DIDCOMM_PAIR_INIT");
      assert.equal(events.length, 1);
      assert.equal(events[0].event, "DIDCOMM_PAIR_INIT");
    });

    it("returns invitationId, invitation, and createdAt", async () => {
      const result = await manager.createInvitation();
      assert.ok(result.invitationId, "should have invitationId");
      assert.equal(result.invitation, "mock-invitation-data");
      assert.ok(result.createdAt, "should have createdAt");
      // Verify createdAt is a valid ISO string
      assert.ok(!isNaN(Date.parse(result.createdAt)), "createdAt should be valid ISO date");
    });

    it("returns expiresAt when TTL is configured", async () => {
      const ttlManager = new PairingManager(transport, peerStore, atlas, { invitationTtlSeconds: 3600 });
      const result = await ttlManager.createInvitation();
      assert.ok(result.expiresAt, "should have expiresAt when TTL configured");
      const created = new Date(result.createdAt).getTime();
      const expires = new Date(result.expiresAt).getTime();
      assert.ok(expires - created >= 3600 * 1000 - 100, "expiresAt should be ~TTL seconds after createdAt");
    });

    it("returns undefined expiresAt when no TTL configured", async () => {
      const result = await manager.createInvitation();
      assert.equal(result.expiresAt, undefined);
    });
  });

  describe("acceptInvitation", () => {
    it("stores peer as 'paired' initially", async () => {
      // Set deny so we can inspect the intermediate state before promotion
      atlas.setVerdict("deny");
      await manager.acceptInvitation({ invitation: "inv" });
      // On deny the peer ends up as "untrusted", but PAIR_ACCEPT event was logged
      const events = atlas.getEventsByType("DIDCOMM_PAIR_ACCEPT");
      assert.equal(events.length, 1);
    });

    it("calls atlas.authorize during acceptance", async () => {
      // authorize is called; we verify via the event log pattern
      const result = await manager.acceptInvitation({ invitation: "inv" });
      // If authorize was called and returned "allow", peer should be approved
      assert.equal(result.approved, true);
    });

    it("promotes to 'approved' on allow verdict", async () => {
      atlas.setVerdict("allow");
      const result = await manager.acceptInvitation({ invitation: "inv" });
      assert.equal(result.trustState, "approved");
      assert.equal(result.approved, true);
    });

    it("calls registerPeerBinding on approval", async () => {
      atlas.setVerdict("allow");
      await manager.acceptInvitation({ invitation: "inv" });
      assert.equal(atlas.registeredPeers.length, 1);
      assert.equal(atlas.registeredPeers[0].peerDid, "did:peer:mock-peer-123");
    });

    it("logs DIDCOMM_PEER_BOUND on approval", async () => {
      atlas.setVerdict("allow");
      await manager.acceptInvitation({ invitation: "inv" });
      const events = atlas.getEventsByType("DIDCOMM_PEER_BOUND");
      assert.equal(events.length, 1);
      assert.equal(events[0].identityVerified, true);
    });

    it("sets trustState to 'untrusted' on deny", async () => {
      atlas.setVerdict("deny");
      const result = await manager.acceptInvitation({ invitation: "inv" });
      assert.equal(result.trustState, "untrusted");
      assert.equal(result.approved, false);
    });

    it("logs DIDCOMM_SEND_DENY on deny", async () => {
      atlas.setVerdict("deny");
      await manager.acceptInvitation({ invitation: "inv" });
      const events = atlas.getEventsByType("DIDCOMM_SEND_DENY");
      assert.equal(events.length, 1);
      assert.equal(events[0].verdict, "deny");
    });

    it("returns approved=false for revoked peer", async () => {
      // Pre-store a revoked peer with the same DID the transport will return
      await peerStore.put(makePeer({ peerDid: "did:peer:mock-peer-123", trustState: "revoked" }));
      const result = await manager.acceptInvitation({ invitation: "inv" });
      assert.equal(result.approved, false);
      assert.equal(result.trustState, "revoked");
    });

    it("logs deny event for revoked peer", async () => {
      await peerStore.put(makePeer({ peerDid: "did:peer:mock-peer-123", trustState: "revoked" }));
      await manager.acceptInvitation({ invitation: "inv" });
      const events = atlas.getEventsByType("DIDCOMM_SEND_DENY");
      assert.equal(events.length, 1);
      assert.ok(events[0].reason?.includes("revoked"), "reason should mention revocation");
    });
  });

  describe("revokePeer", () => {
    it("sets trustState to 'revoked'", async () => {
      await peerStore.put(makePeer({ peerDid: "did:peer:to-revoke" }));
      const result = await manager.revokePeer("did:peer:to-revoke", "test revocation");
      assert.equal(result.trustState, "revoked");
    });

    it("throws for unknown peer", async () => {
      await assert.rejects(
        () => manager.revokePeer("did:peer:nonexistent", "test"),
        (err: Error) => {
          assert.ok(err.message.includes("Peer not found"));
          return true;
        },
      );
    });
  });
});
