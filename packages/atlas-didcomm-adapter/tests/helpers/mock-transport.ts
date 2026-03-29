import type { DidcommTransport, DidcommMessage } from "../../src/types.js";

export class MockTransport implements DidcommTransport {
  public invitationsCreated = 0;
  public messagesSent: Array<{ peerDid: string; msg: DidcommMessage }> = [];
  public invitationResult = { peerDid: "did:peer:mock-peer-123" };

  async createInvitation(): Promise<string> { this.invitationsCreated++; return "mock-invitation-data"; }
  async acceptInvitation(_invitation: string): Promise<{ peerDid: string }> { return this.invitationResult; }
  async sendMessage(peerDid: string, msg: DidcommMessage): Promise<void> { this.messagesSent.push({ peerDid, msg }); }
  async unpackMessage(raw: Uint8Array | string): Promise<DidcommMessage> {
    const str = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
    return JSON.parse(str) as DidcommMessage;
  }
  reset(): void { this.invitationsCreated = 0; this.messagesSent = []; }
}
