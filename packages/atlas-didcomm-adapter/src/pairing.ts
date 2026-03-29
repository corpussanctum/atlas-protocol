/**
 * Atlas DIDComm Adapter — Pairing Orchestration
 *
 * Manages the DIDComm invitation → acceptance → Atlas authorization → binding flow.
 * Pairing is not trust. A "paired" peer must still be authorized by Atlas before
 * any messages can flow.
 */

import { randomUUID } from "node:crypto";
import type {
  PeerBinding,
  PeerStore,
  AtlasBridge,
  DidcommTransport,
  DidcommPermissionRequest,
  AtlasDidcommAuditEvent,
} from "./types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PairingInvite {
  invitationId: string;
  invitation: string;
  createdAt: string;
  expiresAt?: string;
}

export interface PairingResult {
  peerDid: string;
  trustState: PeerBinding["trustState"];
  approved: boolean;
  binding: PeerBinding;
}

export interface PairingManagerOptions {
  invitationTtlSeconds?: number;
}

// ---------------------------------------------------------------------------
// Pairing Manager
// ---------------------------------------------------------------------------

export class PairingManager {
  private readonly transport: DidcommTransport;
  private readonly peerStore: PeerStore;
  private readonly atlas: AtlasBridge;
  private readonly ttlSeconds?: number;

  constructor(
    transport: DidcommTransport,
    peerStore: PeerStore,
    atlas: AtlasBridge,
    options?: PairingManagerOptions,
  ) {
    this.transport = transport;
    this.peerStore = peerStore;
    this.atlas = atlas;
    this.ttlSeconds = options?.invitationTtlSeconds;
  }

  /**
   * Create a DIDComm invitation. Logs DIDCOMM_PAIR_INIT.
   */
  async createInvitation(localAgentId?: string): Promise<PairingInvite> {
    const invitation = await this.transport.createInvitation();
    const now = new Date();
    const invitationId = randomUUID();

    const event: AtlasDidcommAuditEvent = {
      timestamp: now.toISOString(),
      event: "DIDCOMM_PAIR_INIT",
      peerDid: "pending",
      agentId: localAgentId,
      verdict: "allow",
      reason: "Invitation created",
    };
    await this.atlas.logEvent(event);

    return {
      invitationId,
      invitation,
      createdAt: now.toISOString(),
      expiresAt: this.ttlSeconds
        ? new Date(now.getTime() + this.ttlSeconds * 1000).toISOString()
        : undefined,
    };
  }

  /**
   * Accept a DIDComm invitation. Steps:
   * 1. Accept via transport → get peerDid
   * 2. Check if peer is already revoked → deny immediately
   * 3. Store peer as "paired"
   * 4. Request Atlas authorization for the pairing
   * 5. On allow → promote to "approved", register binding
   * 6. On deny → set to "untrusted"
   */
  async acceptInvitation(params: {
    invitation: string;
    localAgentId?: string;
    alias?: string;
    allowedMessageTypes?: string[];
    allowedDirections?: Array<"send" | "receive">;
    metadata?: Record<string, string>;
  }): Promise<PairingResult> {
    const { peerDid } = await this.transport.acceptInvitation(params.invitation);
    const now = new Date().toISOString();

    // Check if peer was previously revoked
    const existing = await this.peerStore.get(peerDid);
    if (existing?.trustState === "revoked") {
      const denyEvent: AtlasDidcommAuditEvent = {
        timestamp: now,
        event: "DIDCOMM_SEND_DENY",
        peerDid,
        agentId: params.localAgentId,
        verdict: "deny",
        reason: "Peer previously revoked",
      };
      await this.atlas.logEvent(denyEvent);
      return {
        peerDid,
        trustState: "revoked",
        approved: false,
        binding: existing,
      };
    }

    // Store as paired (not yet approved)
    const binding: PeerBinding = {
      peerDid,
      alias: params.alias,
      trustState: "paired",
      allowedMessageTypes: params.allowedMessageTypes ?? [],
      allowedDirections: params.allowedDirections ?? ["send", "receive"],
      createdAt: now,
      updatedAt: now,
      metadata: params.metadata,
    };
    await this.peerStore.put(binding);

    // Log acceptance
    const acceptEvent: AtlasDidcommAuditEvent = {
      timestamp: now,
      event: "DIDCOMM_PAIR_ACCEPT",
      peerDid,
      agentId: params.localAgentId,
      verdict: "allow",
      reason: "Invitation accepted, awaiting authorization",
    };
    await this.atlas.logEvent(acceptEvent);

    // Request Atlas authorization
    const pairRequest: DidcommPermissionRequest = {
      request_id: randomUUID(),
      tool_name: "DIDComm",
      action: "pair",
      peer_did: peerDid,
      peer_alias: params.alias,
      local_agent_id: params.localAgentId,
      message_type: "atlas/pair-request",
      protocol_family: "pairing",
      input_preview: `DIDComm:pair peer=${peerDid} alias=${params.alias ?? "none"}`,
      sensitivity_labels: [],
      transport_meta: { encrypted: false, authenticated: false, signed: false },
      metadata: params.metadata,
    };

    const decision = await this.atlas.authorize(pairRequest);

    if (decision.verdict === "allow") {
      binding.trustState = "approved";
      binding.updatedAt = new Date().toISOString();
      await this.peerStore.put(binding);
      await this.atlas.registerPeerBinding(binding);

      const boundEvent: AtlasDidcommAuditEvent = {
        timestamp: binding.updatedAt,
        event: "DIDCOMM_PEER_BOUND",
        peerDid,
        agentId: params.localAgentId,
        identityVerified: true,
        verdict: "allow",
        reason: "Peer approved by Atlas",
      };
      await this.atlas.logEvent(boundEvent);

      return { peerDid, trustState: "approved", approved: true, binding };
    }

    // Denied
    binding.trustState = "untrusted";
    binding.updatedAt = new Date().toISOString();
    await this.peerStore.put(binding);

    const denyEvent: AtlasDidcommAuditEvent = {
      timestamp: binding.updatedAt,
      event: "DIDCOMM_SEND_DENY",
      peerDid,
      agentId: params.localAgentId,
      verdict: "deny",
      reason: decision.reason ?? "Atlas denied pairing",
    };
    await this.atlas.logEvent(denyEvent);

    return { peerDid, trustState: "untrusted", approved: false, binding };
  }

  /**
   * Revoke a peer binding. Sets trustState to "revoked" and notifies Atlas.
   */
  async revokePeer(peerDid: string, reason: string): Promise<PeerBinding> {
    const existing = await this.peerStore.get(peerDid);
    if (!existing) {
      throw new Error(`Peer not found: ${peerDid}`);
    }

    existing.trustState = "revoked";
    existing.updatedAt = new Date().toISOString();
    await this.peerStore.put(existing);
    await this.atlas.revokePeerBinding(peerDid, reason);

    const event: AtlasDidcommAuditEvent = {
      timestamp: existing.updatedAt,
      event: "DIDCOMM_PEER_REVOKED",
      peerDid,
      verdict: "deny",
      reason,
    };
    await this.atlas.logEvent(event);

    return existing;
  }
}
