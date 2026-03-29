/**
 * Atlas DIDComm Adapter — Public API
 *
 * Binds DIDComm messaging to the Atlas Protocol gatekeeper.
 * The adapter classifies and routes; Atlas decides.
 */

// Types
export type {
  PeerBinding,
  DidcommMessage,
  ClassifiedMessage,
  DidcommPermissionRequest,
  AuthorizationResult,
  AtlasDidcommAuditEvent,
  AtlasDidcommEventType,
  DidcommTransport,
  PeerStore,
  AtlasBridge,
  MessageClassifier,
  InboundResult,
  OutboundResult,
  MessagingCapability,
  DidcommDirection,
} from "./types.js";

// Core classes
export { PairingManager } from "./pairing.js";
export type { PairingInvite, PairingResult, PairingManagerOptions } from "./pairing.js";
export { PolicyMapper } from "./policy-mapper.js";
export type { PolicyMapperOptions, MapContext } from "./policy-mapper.js";
export { DefaultClassifier } from "./classifier.js";
export type { ClassifierOptions } from "./classifier.js";
export { FilePeerStore, MockPeerStore } from "./peer-store.js";
export { InboundHandler } from "./inbound.js";
export { OutboundHandler } from "./outbound.js";

// Audit event builders
export {
  buildPairInit,
  buildPairAccept,
  buildPeerBound,
  buildSendAllow,
  buildSendDeny,
  buildReceiveAllow,
  buildReceiveDeny,
  buildPeerRevoked,
  buildDelegatedSend,
  buildDelegatedReceive,
} from "./audit-events.js";

// ---------------------------------------------------------------------------
// AtlasDidcommAdapter — Convenience facade
// ---------------------------------------------------------------------------

import type {
  DidcommTransport,
  PeerStore,
  AtlasBridge,
  MessageClassifier as IMessageClassifier,
  DidcommMessage,
  InboundResult,
  OutboundResult,
  PeerBinding,
} from "./types.js";
import { PairingManager } from "./pairing.js";
import type { PairingInvite, PairingResult } from "./pairing.js";
import { PolicyMapper } from "./policy-mapper.js";
import type { PolicyMapperOptions } from "./policy-mapper.js";
import { DefaultClassifier } from "./classifier.js";
import type { ClassifierOptions } from "./classifier.js";
import { FilePeerStore } from "./peer-store.js";
import { InboundHandler } from "./inbound.js";
import { OutboundHandler } from "./outbound.js";
import type { ClassifiedMessage } from "./types.js";

export interface AtlasDidcommAdapterOptions {
  transport: DidcommTransport;
  atlas: AtlasBridge;
  dataDir?: string;
  peerStore?: PeerStore;
  classifier?: IMessageClassifier;
  localRouter?: (msg: DidcommMessage, classified: ClassifiedMessage) => Promise<void>;
  policyMapper?: PolicyMapper;
  invitationTtlSeconds?: number;
  mapperOptions?: PolicyMapperOptions;
  classifierOptions?: ClassifierOptions;
}

export class AtlasDidcommAdapter {
  private readonly pairing: PairingManager;
  private readonly inbound: InboundHandler;
  private readonly outbound: OutboundHandler;
  private readonly store: PeerStore;

  constructor(options: AtlasDidcommAdapterOptions) {
    this.store = options.peerStore
      ?? (options.dataDir ? new FilePeerStore(options.dataDir) : (() => { throw new Error("Either peerStore or dataDir is required"); })());

    const classifier = options.classifier ?? new DefaultClassifier(options.classifierOptions);
    const mapper = options.policyMapper ?? new PolicyMapper(options.mapperOptions);

    this.pairing = new PairingManager(
      options.transport,
      this.store,
      options.atlas,
      { invitationTtlSeconds: options.invitationTtlSeconds },
    );

    this.inbound = new InboundHandler(
      options.transport,
      this.store,
      options.atlas,
      classifier,
      mapper,
      options.localRouter,
    );

    this.outbound = new OutboundHandler(
      options.transport,
      this.store,
      options.atlas,
      classifier,
      mapper,
    );
  }

  // -- Pairing ---------------------------------------------------------------

  createInvitation(localAgentId?: string): Promise<PairingInvite> {
    return this.pairing.createInvitation(localAgentId);
  }

  acceptInvitation(params: Parameters<PairingManager["acceptInvitation"]>[0]): Promise<PairingResult> {
    return this.pairing.acceptInvitation(params);
  }

  revokePeer(peerDid: string, reason: string): Promise<PeerBinding> {
    return this.pairing.revokePeer(peerDid, reason);
  }

  // -- Messaging -------------------------------------------------------------

  handleInbound(raw: Uint8Array | string): Promise<InboundResult> {
    return this.inbound.handle(raw);
  }

  send(peerDid: string, msg: DidcommMessage): Promise<OutboundResult> {
    return this.outbound.send(peerDid, msg);
  }

  // -- Peer management -------------------------------------------------------

  getPeer(peerDid: string): Promise<PeerBinding | undefined> {
    return this.store.get(peerDid);
  }

  listPeers(filter?: "all" | "approved" | "revoked"): Promise<PeerBinding[]> {
    return this.store.list(filter);
  }
}
