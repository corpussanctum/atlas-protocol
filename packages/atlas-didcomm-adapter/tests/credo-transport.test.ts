/**
 * Tests for Credo-TS Transport (Milestone 4)
 *
 * Uses a mock Credo agent to verify the transport correctly bridges
 * between the DidcommTransport interface and Credo's API surface.
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { CredoTransport } from "../src/transports/credo.js";
import type { CredoAgentLike } from "../src/transports/credo.js";

// ---------------------------------------------------------------------------
// Mock Credo Agent
// ---------------------------------------------------------------------------

class MockCredoAgent implements CredoAgentLike {
  public invitationsCreated = 0;
  public messagesSent: Array<{ connectionId: string; message: string }> = [];
  public connectionsCreated: Array<{ id: string; theirDid: string }> = [];

  oob = {
    createInvitation: async (config?: { label?: string }) => {
      this.invitationsCreated++;
      return {
        outOfBandInvitation: {
          toUrl: (params: { domain: string }) => `${params.domain}?oob=mock-invitation-${this.invitationsCreated}`,
        },
        id: `oob-${this.invitationsCreated}`,
      };
    },
    receiveInvitationFromUrl: async (_url: string) => {
      const conn = { id: "conn-accepted-1", theirDid: "did:peer:remote-clinic" };
      this.connectionsCreated.push(conn);
      return { connectionRecord: conn };
    },
  };

  connections = {
    getById: async (id: string) => {
      return { id, theirDid: "did:peer:remote-clinic", state: "completed" };
    },
    findAllByOutOfBandId: async (_oobId: string) => {
      return [{ id: "conn-1", theirDid: "did:peer:remote-clinic", state: "completed" }];
    },
    returnWhenIsConnected: async (id: string) => {
      return { id, theirDid: "did:peer:remote-clinic" };
    },
  };

  basicMessages = {
    sendMessage: async (connectionId: string, message: string) => {
      this.messagesSent.push({ connectionId, message });
    },
  };

  dids = {
    resolve: async (did: string) => {
      return { didDocument: { id: did } };
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("CredoTransport", () => {
  let agent: MockCredoAgent;
  let transport: CredoTransport;

  beforeEach(() => {
    agent = new MockCredoAgent();
    transport = new CredoTransport(agent, {
      invitationDomain: "https://atlas.example.com",
      agentLabel: "Test Atlas Agent",
    });
  });

  describe("createInvitation", () => {
    it("creates an OOB invitation URL with configured domain", async () => {
      const url = await transport.createInvitation();
      assert.ok(url.startsWith("https://atlas.example.com"));
      assert.ok(url.includes("oob="));
      assert.equal(agent.invitationsCreated, 1);
    });

    it("creates multiple unique invitations", async () => {
      const url1 = await transport.createInvitation();
      const url2 = await transport.createInvitation();
      assert.notEqual(url1, url2);
      assert.equal(agent.invitationsCreated, 2);
    });
  });

  describe("acceptInvitation", () => {
    it("returns the remote peer DID", async () => {
      const result = await transport.acceptInvitation("https://clinic.example.com?oob=xyz");
      assert.equal(result.peerDid, "did:peer:remote-clinic");
    });

    it("caches the connection for later sendMessage", async () => {
      await transport.acceptInvitation("https://clinic.example.com?oob=xyz");
      const connId = transport.getConnectionId("did:peer:remote-clinic");
      assert.ok(connId, "Connection should be cached");
    });

    it("throws when no connection record returned", async () => {
      agent.oob.receiveInvitationFromUrl = async () => ({ connectionRecord: undefined as any });
      await assert.rejects(
        () => transport.acceptInvitation("bad-invite"),
        /No connection record/,
      );
    });

    it("throws when peer DID not available after connection", async () => {
      agent.connections.returnWhenIsConnected = async (id) => ({ id, theirDid: undefined as any });
      await assert.rejects(
        () => transport.acceptInvitation("no-did-invite"),
        /peer DID not available/,
      );
    });
  });

  describe("sendMessage", () => {
    it("sends a serialized message via basicMessages", async () => {
      // First pair to cache the connection
      await transport.acceptInvitation("https://clinic.example.com?oob=xyz");

      await transport.sendMessage("did:peer:remote-clinic", {
        id: "msg-001",
        type: "clinic/appointment.summary.request",
        body: { patientRef: "P-123" },
      });

      assert.equal(agent.messagesSent.length, 1);
      const sent = JSON.parse(agent.messagesSent[0].message);
      assert.equal(sent["@type"], "clinic/appointment.summary.request");
      assert.equal(sent["@id"], "msg-001");
      assert.equal(sent.patientRef, "P-123");
    });

    it("throws when no cached connection exists", async () => {
      await assert.rejects(
        () => transport.sendMessage("did:peer:unknown", { id: "x", type: "test" }),
        /No cached connection/,
      );
    });

    it("includes thread ID when present", async () => {
      await transport.acceptInvitation("invite");
      await transport.sendMessage("did:peer:remote-clinic", {
        id: "msg-002",
        type: "test/msg",
        thid: "thread-abc",
      });
      const sent = JSON.parse(agent.messagesSent[0].message);
      assert.deepEqual(sent["~thread"], { thid: "thread-abc" });
    });
  });

  describe("unpackMessage", () => {
    it("unpacks a JSON string into DidcommMessage", async () => {
      const raw = JSON.stringify({
        "@type": "clinic/appointment.summary.response",
        "@id": "msg-100",
        "~thread": { thid: "thread-xyz" },
        from: "did:peer:clinic",
        summary: "All clear",
      });
      const msg = await transport.unpackMessage(raw);
      assert.equal(msg.type, "clinic/appointment.summary.response");
      assert.equal(msg.id, "msg-100");
      assert.equal(msg.thid, "thread-xyz");
      assert.equal(msg.from, "did:peer:clinic");
      assert.deepEqual(msg.body, { summary: "All clear" });
    });

    it("unpacks a Uint8Array", async () => {
      const raw = new TextEncoder().encode(JSON.stringify({
        "@type": "test/ping",
        "@id": "p-1",
      }));
      const msg = await transport.unpackMessage(raw);
      assert.equal(msg.type, "test/ping");
      assert.equal(msg.id, "p-1");
    });

    it("sets transport metadata defaults (encrypted/authenticated)", async () => {
      const msg = await transport.unpackMessage(JSON.stringify({ "@type": "test", "@id": "1" }));
      assert.equal(msg.transport?.encrypted, true);
      assert.equal(msg.transport?.authenticated, true);
    });

    it("throws on invalid JSON", async () => {
      await assert.rejects(
        () => transport.unpackMessage("not json {{{"),
        /Failed to parse/,
      );
    });
  });

  describe("cacheConnection", () => {
    it("manually caches a connection for a peer DID", () => {
      transport.cacheConnection("did:peer:manual", "conn-manual-1");
      assert.equal(transport.getConnectionId("did:peer:manual"), "conn-manual-1");
    });
  });
});
