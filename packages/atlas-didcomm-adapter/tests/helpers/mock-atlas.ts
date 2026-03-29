import type { AtlasBridge, AtlasDidcommAuditEvent, AuthorizationResult, DidcommPermissionRequest, PeerBinding } from "../../src/types.js";

export class MockAtlasBridge implements AtlasBridge {
  public events: AtlasDidcommAuditEvent[] = [];
  public defaultVerdict: "allow" | "ask" | "deny" = "allow";
  public registeredPeers: PeerBinding[] = [];
  public revokedPeers: Array<{ peerDid: string; reason: string }> = [];

  setVerdict(verdict: "allow" | "ask" | "deny"): void { this.defaultVerdict = verdict; }

  async authorize(req: DidcommPermissionRequest): Promise<AuthorizationResult> {
    return { verdict: this.defaultVerdict };
  }
  async logEvent(event: AtlasDidcommAuditEvent): Promise<void> { this.events.push(event); }
  async registerPeerBinding(binding: PeerBinding): Promise<void> { this.registeredPeers.push(binding); }
  async revokePeerBinding(peerDid: string, reason: string): Promise<void> { this.revokedPeers.push({ peerDid, reason }); }

  // Optional — delegation validity check. Set to a function to enable.
  isDelegationValid?: (agentId: string) => Promise<boolean>;

  getLastEvent(): AtlasDidcommAuditEvent | undefined { return this.events[this.events.length - 1]; }
  getEventsByType(type: string): AtlasDidcommAuditEvent[] { return this.events.filter(e => e.event === type); }
  reset(): void { this.events = []; this.defaultVerdict = "allow"; this.registeredPeers = []; this.revokedPeers = []; this.isDelegationValid = undefined; }
}
