/**
 * Atlas DIDComm Adapter — Policy Mapper
 *
 * Maps DIDComm messages into Atlas DidcommPermissionRequest objects.
 * The mapper classifies but never decides — Atlas policy engine decides.
 */

import { randomUUID } from "node:crypto";
import type {
  DidcommMessage,
  DidcommPermissionRequest,
  DidcommDirection,
  ClassifiedMessage,
  PeerBinding,
} from "./types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PolicyMapperOptions {
  /** Maximum length for input_preview (default: 200) */
  maxPreviewLength?: number;
  /** Redact content_preview when sensitivity labels present (default: true) */
  redactSensitiveContent?: boolean;
}

export interface MapContext {
  direction: DidcommDirection;
  peer?: PeerBinding;
  classified: ClassifiedMessage;
}

// ---------------------------------------------------------------------------
// Policy Mapper
// ---------------------------------------------------------------------------

export class PolicyMapper {
  private readonly maxPreview: number;
  private readonly redactSensitive: boolean;

  constructor(options?: PolicyMapperOptions) {
    this.maxPreview = options?.maxPreviewLength ?? 200;
    this.redactSensitive = options?.redactSensitiveContent ?? true;
  }

  /**
   * Map a classified DIDComm message into an Atlas permission request.
   */
  toPermissionRequest(
    msg: DidcommMessage,
    ctx: MapContext,
  ): DidcommPermissionRequest {
    const peer = ctx.peer;
    const classified = ctx.classified;

    // Build content preview — redact if sensitive
    let contentPreview: string | undefined;
    if (classified.preview) {
      if (this.redactSensitive && classified.sensitivityLabels.length > 0) {
        contentPreview = `[REDACTED: ${classified.sensitivityLabels.join(",")}]`;
      } else {
        contentPreview = classified.preview.slice(0, this.maxPreview);
      }
    }

    // Build slug-safe input_preview for Atlas glob pattern matching
    const trustLabel = peer?.trustState ?? "unknown";
    const inputPreview = this.buildInputPreview(
      ctx.direction,
      peer?.peerDid ?? msg.from ?? "unknown",
      trustLabel,
      classified.messageType,
      classified.protocolFamily,
    );

    // Dedupe and sort sensitivity labels
    const labels = [...new Set(classified.sensitivityLabels)].sort();

    return {
      request_id: randomUUID(),
      tool_name: "DIDComm",
      action: ctx.direction,
      peer_did: peer?.peerDid ?? msg.from ?? "unknown",
      peer_alias: peer?.alias,
      local_agent_id: peer?.mappedAgentId,
      message_type: classified.messageType,
      protocol_family: classified.protocolFamily,
      thread_id: msg.thid,
      content_preview: contentPreview,
      input_preview: inputPreview,
      sensitivity_labels: labels,
      transport_meta: {
        encrypted: msg.transport?.encrypted ?? false,
        authenticated: msg.transport?.authenticated ?? false,
        signed: msg.transport?.signed ?? false,
      },
      metadata: peer?.metadata,
    };
  }

  /**
   * Build a pairing permission request (not a message request).
   */
  buildPairingRequest(params: {
    peerDid: string;
    alias?: string;
    localAgentId?: string;
    metadata?: Record<string, string>;
  }): DidcommPermissionRequest {
    return {
      request_id: randomUUID(),
      tool_name: "DIDComm",
      action: "pair",
      peer_did: params.peerDid,
      peer_alias: params.alias,
      local_agent_id: params.localAgentId,
      message_type: "atlas/pair-request",
      protocol_family: "pairing",
      input_preview: `DIDComm:pair peer=${params.peerDid} alias=${params.alias ?? "none"}`,
      sensitivity_labels: [],
      transport_meta: { encrypted: false, authenticated: false, signed: false },
      metadata: params.metadata,
    };
  }

  /**
   * Build a single-line slug-safe input_preview for Atlas policy matching.
   */
  private buildInputPreview(
    direction: string,
    peerDid: string,
    trustState: string,
    messageType: string,
    family: string,
  ): string {
    const raw = `DIDComm:${direction} peer=${peerDid} trust=${trustState} type=${messageType} family=${family}`;
    return raw.slice(0, this.maxPreview).replace(/[\n\r]/g, " ");
  }
}
