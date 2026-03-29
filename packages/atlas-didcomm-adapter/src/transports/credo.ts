/**
 * Atlas DIDComm Adapter — Credo-TS Transport
 *
 * Concrete DidcommTransport implementation using Credo-TS (formerly Aries Framework JavaScript).
 * Bridges the adapter's transport interface to Credo's agent, connections, and message handling.
 *
 * Usage:
 *   import { Agent } from '@credo-ts/core';
 *   import { CredoTransport } from '@corpussanctum/atlas-didcomm-adapter/transports/credo';
 *
 *   const credoAgent = new Agent({ ... });
 *   await credoAgent.initialize();
 *   const transport = new CredoTransport(credoAgent);
 *   const adapter = new AtlasDidcommAdapter({ transport, atlas, ... });
 *
 * This file has a peer dependency on @credo-ts/core — it is NOT bundled.
 * Consumers must install Credo separately.
 */

import type { DidcommTransport, DidcommMessage } from "../types.js";

// ---------------------------------------------------------------------------
// Credo-TS type shims (minimal surface — avoids hard dependency)
// ---------------------------------------------------------------------------

/**
 * Minimal interface the Credo Agent must satisfy. This avoids importing
 * @credo-ts/core directly, making the transport compilable without Credo
 * installed. Runtime callers pass their real Credo Agent instance.
 */
export interface CredoAgentLike {
  oob: {
    createInvitation(config?: {
      label?: string;
      autoAcceptConnection?: boolean;
    }): Promise<{ outOfBandInvitation: { toUrl(params: { domain: string }): string }; id: string }>;
    receiveInvitationFromUrl(url: string, config?: {
      autoAcceptConnection?: boolean;
      autoAcceptInvitation?: boolean;
    }): Promise<{ connectionRecord?: { id: string; theirDid?: string } }>;
  };
  connections: {
    getById(id: string): Promise<{ id: string; theirDid?: string; state: string }>;
    findAllByOutOfBandId(oobId: string): Promise<Array<{ id: string; theirDid?: string; state: string }>>;
    returnWhenIsConnected(id: string, opts?: { timeoutMs?: number }): Promise<{ id: string; theirDid?: string }>;
  };
  basicMessages: {
    sendMessage(connectionId: string, message: string): Promise<void>;
  };
  dids: {
    resolve(did: string): Promise<{ didDocument?: { id: string } }>;
  };
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface CredoTransportOptions {
  /** Domain for OOB invitation URLs (default: "https://example.com") */
  invitationDomain?: string;
  /** Connection timeout in ms (default: 30000) */
  connectionTimeoutMs?: number;
  /** Auto-accept connections (default: true) */
  autoAcceptConnection?: boolean;
  /** Agent label for invitations (default: "Atlas Agent") */
  agentLabel?: string;
}

// ---------------------------------------------------------------------------
// Connection cache
// ---------------------------------------------------------------------------

interface CachedConnection {
  connectionId: string;
  peerDid: string;
}

// ---------------------------------------------------------------------------
// CredoTransport
// ---------------------------------------------------------------------------

export class CredoTransport implements DidcommTransport {
  private readonly agent: CredoAgentLike;
  private readonly options: Required<CredoTransportOptions>;
  /** Map peerDid → connectionId for outbound routing */
  private readonly connectionCache: Map<string, string> = new Map();
  /** Pending OOB invitation IDs awaiting connection */
  private readonly pendingOobIds: Set<string> = new Set();

  constructor(agent: CredoAgentLike, options?: CredoTransportOptions) {
    this.agent = agent;
    this.options = {
      invitationDomain: options?.invitationDomain ?? "https://example.com",
      connectionTimeoutMs: options?.connectionTimeoutMs ?? 30_000,
      autoAcceptConnection: options?.autoAcceptConnection ?? true,
      agentLabel: options?.agentLabel ?? "Atlas Agent",
    };
  }

  /**
   * Create a DIDComm OOB invitation URL.
   */
  async createInvitation(): Promise<string> {
    const result = await this.agent.oob.createInvitation({
      label: this.options.agentLabel,
      autoAcceptConnection: this.options.autoAcceptConnection,
    });

    this.pendingOobIds.add(result.id);

    return result.outOfBandInvitation.toUrl({
      domain: this.options.invitationDomain,
    });
  }

  /**
   * Accept an OOB invitation URL. Returns the remote peer's DID.
   */
  async acceptInvitation(invitation: string): Promise<{ peerDid: string }> {
    const result = await this.agent.oob.receiveInvitationFromUrl(invitation, {
      autoAcceptConnection: this.options.autoAcceptConnection,
      autoAcceptInvitation: true,
    });

    if (!result.connectionRecord) {
      throw new Error("No connection record returned from invitation acceptance");
    }

    // Wait for connection to complete
    const connection = await this.agent.connections.returnWhenIsConnected(
      result.connectionRecord.id,
      { timeoutMs: this.options.connectionTimeoutMs },
    );

    const peerDid = connection.theirDid;
    if (!peerDid) {
      throw new Error("Connection established but peer DID not available");
    }

    // Cache the connection for outbound routing
    this.connectionCache.set(peerDid, connection.id);

    return { peerDid };
  }

  /**
   * Send a DIDComm message to a peer via their connection.
   */
  async sendMessage(peerDid: string, msg: DidcommMessage): Promise<void> {
    const connectionId = this.connectionCache.get(peerDid);
    if (!connectionId) {
      throw new Error(`No cached connection for peer: ${peerDid}. Pair first.`);
    }

    // Serialize the message as a basic message
    // For production: this would use Credo's protocol-specific handlers
    const payload = JSON.stringify({
      "@type": msg.type,
      "@id": msg.id,
      "~thread": msg.thid ? { thid: msg.thid } : undefined,
      ...((msg.body && typeof msg.body === "object") ? msg.body : { content: msg.body }),
    });

    await this.agent.basicMessages.sendMessage(connectionId, payload);
  }

  /**
   * Unpack a raw inbound message into a DidcommMessage.
   * In a real deployment, this is called by Credo's message handler
   * which has already decrypted and authenticated the message.
   */
  async unpackMessage(raw: Uint8Array | string): Promise<DidcommMessage> {
    const str = typeof raw === "string" ? raw : new TextDecoder().decode(raw);

    try {
      const parsed = JSON.parse(str);

      // Handle Credo basic message format
      const type = parsed["@type"] ?? parsed.type ?? "unknown";
      const id = parsed["@id"] ?? parsed.id ?? crypto.randomUUID();
      const thid = parsed["~thread"]?.thid ?? parsed.thid;

      // Extract sender DID from Credo message metadata if available
      const from = parsed._meta?.senderDid ?? parsed.from;

      // Remove protocol-level fields, keep the rest as body
      const { "@type": _t, "@id": _i, "~thread": _th, _meta, type: _ty, id: _id, from: _f, thid: _tid, to: _to, ...body } = parsed;

      return {
        id,
        type,
        from,
        to: parsed.to,
        thid,
        body: Object.keys(body).length > 0 ? body : undefined,
        transport: {
          encrypted: parsed._meta?.encrypted ?? true,  // Credo messages are typically encrypted
          authenticated: parsed._meta?.authenticated ?? true,
          signed: parsed._meta?.signed ?? false,
        },
      };
    } catch {
      throw new Error("Failed to parse inbound message as JSON");
    }
  }

  /**
   * Register a connection for a peer DID (used when the connection
   * was established outside the normal invitation flow).
   */
  cacheConnection(peerDid: string, connectionId: string): void {
    this.connectionCache.set(peerDid, connectionId);
  }

  /**
   * Look up a cached connection ID for a peer DID.
   */
  getConnectionId(peerDid: string): string | undefined {
    return this.connectionCache.get(peerDid);
  }
}
