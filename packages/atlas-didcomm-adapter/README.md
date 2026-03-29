# Atlas DIDComm Adapter

DIDComm integration adapter for the [Atlas Protocol](../../README.md) gatekeeper. Binds DIDComm peer-to-peer messaging to Atlas identity, policy, and audit — so every message between agents is governed by the same trust model that governs tool calls.

## What the adapter does

1. **Bootstrap trust** — pair two peers via DIDComm out-of-band invitation flow
2. **Map remote peer identity** into local Atlas trust decisions (`did:peer` stays remote, `did:atlas` stays local)
3. **Enforce** all inbound/outbound message actions through the Atlas gatekeeper
4. **Emit auditable events** into the Atlas audit log

## What the adapter does NOT do

- Parse or own the DIDComm transport stack (that's pluggable via `DidcommTransport`)
- Make policy decisions (Atlas decides; the adapter classifies only)
- Convert `did:peer` to `did:atlas` (they are separate identity domains)
- Implement DIDComm mediators, routing, or group messaging

## Design rules

1. **Fail closed.** Missing peer binding, failed Atlas auth, or no operator approval = message not processed.
2. **Pairing is not trust.** `paired` state is not `approved` state. Atlas authorization is required before any message can flow.
3. **`did:atlas` stays local.** Remote peer DIDs stay remote. Never conflated.
4. **No policy in the adapter.** Classification and mapping only. Atlas decides.
5. **No raw payload logging.** Respects Atlas redaction model.

## Installation

```bash
cd packages/atlas-didcomm-adapter
npm install
npm run build
npm test  # 129 tests
```

## Enforcement pipeline

Every message (inbound and outbound) passes through a rigid 10-step pipeline:

```
1. Peer binding exists and is approved
2. Delegation valid (hard expiry, no grace window)
3. Delegation not revoked (fail-closed if bridge doesn't implement isDelegationValid)
4. Direction allowed by delegation scope
5. Message type allowed by delegation scope
6. Capability allowed by delegation scope
7. Replay check (persistent message ID dedup — survives restarts)
8. Classify message
9. Atlas authorize()
10. Deliver/send
```

Steps are evaluated in this exact order. No reordering. Denied outbound messages never reach the wire.

## Usage

```typescript
import { AtlasDidcommAdapter } from '@corpussanctum/atlas-didcomm-adapter';
import { CredoTransport } from '@corpussanctum/atlas-didcomm-adapter/transports/credo';

const adapter = new AtlasDidcommAdapter({
  transport: new CredoTransport(credoAgent),
  atlas: myAtlasBridge,
  dataDir: '/data/atlas-didcomm',  // peer store + replay log persistence
});

// Pair with a clinic agent
const invite = await adapter.createInvitation('did:atlas:my-agent');
const result = await adapter.acceptInvitation({
  invitation: clinicInviteUrl,
  localAgentId: 'did:atlas:my-agent',
  alias: 'clinic',
});

// Delegate health messaging to a sub-agent for this peer
await adapter.setDelegationScope('did:peer:clinic-456', {
  delegatedAgentId: 'did:atlas:health-sub',
  parentAgentId: 'did:atlas:my-agent',
  grantedCapabilities: ['message:send:health', 'message:receive:health'],
  allowedMessageTypes: ['clinic/appointment.summary.request'],
  allowedDirections: ['send', 'receive'],
  expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  createdAt: new Date().toISOString(),
});

// Send a health message (enforced by scope + Atlas)
await adapter.send('did:peer:clinic-456', {
  id: crypto.randomUUID(),
  type: 'clinic/appointment.summary.request',
  body: { patientRef: 'P-123' },
});

// Handle inbound (from Credo message handler)
const result = await adapter.handleInbound(rawMessage);
```

## Delegation-aware messaging

An orchestrator Atlas credential can delegate scoped messaging authority to a sub-agent for a specific peer:

- **Peer-scoped**: the delegation is bound to one `did:peer` via `setDelegationScope()`
- **Capability-restricted**: only the granted `MessagingCapability` values are allowed
- **Message-type-restricted**: only listed DIDComm message types pass (or all if empty)
- **Direction-restricted**: send-only, receive-only, or bidirectional
- **Time-limited**: hard expiry, no grace window
- **Cascade-revocable**: when a parent credential is revoked via Atlas, `isDelegationValid()` returns false and all scoped messages are denied

## Replay protection

Message ID dedup is **persistent across process restarts** via `FileMessageIdLog`:

- Stored at `<dataDir>/didcomm-seen-ids.json` (chmod 0600, atomic writes)
- Bounded at 50k IDs (configurable), oldest-first eviction
- Both inbound and outbound messages are checked
- An adversary who restarts the adapter cannot replay previously seen messages

## Audit trail

All 10 DIDComm event types are logged through the Atlas bridge:

| Event | When |
|-------|------|
| `DIDCOMM_PAIR_INIT` | Invitation created |
| `DIDCOMM_PAIR_ACCEPT` | Invitation accepted |
| `DIDCOMM_PEER_BOUND` | Peer approved by Atlas |
| `DIDCOMM_SEND_ALLOW` | Outbound message authorized and sent |
| `DIDCOMM_SEND_DENY` | Outbound message denied (with reason) |
| `DIDCOMM_RECEIVE_ALLOW` | Inbound message authorized and delivered |
| `DIDCOMM_RECEIVE_DENY` | Inbound message denied (with reason) |
| `DIDCOMM_PEER_REVOKED` | Peer trust revoked |
| `DIDCOMM_DELEGATED_SEND` | Delegation scope set for outbound |
| `DIDCOMM_DELEGATED_RECEIVE` | Delegation scope set for inbound |

Denial reasons are exact and machine-readable: `DELEGATION_EXPIRED`, `DELEGATION_REVOKED`, `DELEGATION_DIRECTION_DENIED`, `DELEGATION_MESSAGE_TYPE_DENIED`, `DELEGATION_CAPABILITY_DENIED`, `DELEGATION_VALIDATION_UNAVAILABLE`, `REPLAY_DETECTED`, `PEER_NOT_FOUND`, `PEER_REVOKED`, `PEER_NOT_APPROVED`, `NO_SENDER`.

## Architecture

```
src/
├── types.ts              # All interfaces (PeerBinding, DidcommTransport, AtlasBridge, etc.)
├── pairing.ts            # Invitation → acceptance → Atlas authorization → binding
├── policy-mapper.ts      # DIDComm messages → Atlas PermissionRequest
├── peer-store.ts         # FilePeerStore + FileMessageIdLog (persistent, atomic, 0600)
├── classifier.ts         # DefaultClassifier (6 family mappings + prefix fallback)
├── audit-events.ts       # 10 event builders
├── inbound.ts            # 10-step receive pipeline, fail-closed
├── outbound.ts           # 10-step send pipeline, wire never called before auth
├── index.ts              # AtlasDidcommAdapter facade + all exports
└── transports/
    ├── index.ts           # Transport exports
    └── credo.ts           # Credo-TS transport (DidcommTransport implementation)
```

## Transport interface

The adapter does not depend on any DIDComm library. Consumers implement `DidcommTransport`:

```typescript
interface DidcommTransport {
  createInvitation(): Promise<string>;
  acceptInvitation(invitation: string): Promise<{ peerDid: string }>;
  sendMessage(peerDid: string, msg: DidcommMessage): Promise<void>;
  unpackMessage(raw: Uint8Array | string): Promise<DidcommMessage>;
}
```

The included `CredoTransport` implements this using [Credo-TS](https://github.com/openwallet-foundation/credo-ts) (formerly Aries Framework JavaScript). Credo is a peer dependency, not bundled.

## Testing

```bash
npm test  # 129 tests, 0 failures
```

| Suite | Tests |
|-------|-------|
| Types | 5 |
| Peer store + message ID log | 17 |
| Classifier | 12 |
| Policy mapper | 10 |
| Pairing | 15 |
| Inbound | 12 |
| Outbound | 11 |
| Delegation | 24 |
| Replay protection | 3 (inbound + outbound + persistence) |
| Credo transport | 14 |
| Integration | 8 |

## License

[Apache 2.0](../../LICENSE)
