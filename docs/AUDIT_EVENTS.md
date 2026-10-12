# Audit Event Catalog

Every entry in the audit log (`<data_dir>/audit.jsonl`) has an `event` field from the list below. This catalog covers the reference implementation. The required entry fields, hash chain, and signatures are specified in [SPEC.md §6](../SPEC.md).

CI enforces that this file matches the code in both directions (`npm run check:versions`): every `AuditEventType` member and every `meta.event_detail` value emitted in `src/` must appear here, and every name in the tables must still exist in the code.

## Event types

### Permission pipeline

| Event | Emitted when |
|---|---|
| `PERMISSION_REQUEST` | A tool permission request enters the pipeline (before any verdict) |
| `POLICY_DENY` | The automated pipeline (policy rules, identity, consent tier, quiet mode) denies the request without asking a human |
| `POLICY_ALLOW` | Policy (or break-glass / quiet mode for mature agents) allows the request without asking a human |
| `HUMAN_APPROVE` | The operator approves via the Telegram relay |
| `HUMAN_DENY` | The operator denies via the Telegram relay |
| `TIMEOUT_DENY` | No operator verdict arrived before `permission_timeout_seconds`; denied by design (fail-closed) |
| `ANOMALY_DETECTED` | The policy engine raised anomaly flags (velocity, sensitivity, unusual patterns) for a request |
| `CHANNEL_MESSAGE` | An authorized operator message was forwarded into the Claude Code session |

### Session and configuration

| Event | Emitted when |
|---|---|
| `SESSION_START` | The server starts; records implementation, protocol, and spec versions plus the signer's public-key hash |
| `CONFIG_LOADED` | Configuration was loaded at startup (`rejected_config_fields` lists `config.json` fields that failed validation). Also used for several administrative actions; see `event_detail` below |
| `IDENTITY_LOADED` | A DIB Briefcase identity context was loaded |
| `CHECKPOINT` | Periodic signed checkpoint over the hash chain (emitted automatically by the audit logger) |
| `KEY_ROTATION` | Issuer key rotation, signed by the **old** key (SPEC §4.5) |

### Credentials

| Event | Emitted when |
|---|---|
| `CREDENTIAL_EXPIRED` | A request presented an expired agent credential |
| `CREDENTIAL_EXPIRY_WARNING` | An active credential is close to expiry |

### Proximity Mesh (research/demo)

| Event | Emitted when |
|---|---|
| `PROXIMITY_RANGE` | A UWB ranging measurement was taken during session setup |
| `PROXIMITY_VERIFIED` | A proximity proof verified within the configured distance |
| `PROXIMITY_REJECTED` | A proximity session was refused (distance, proof, credential, or policy failure) |
| `PROXIMITY_SESSION_ESTABLISHED` | A proximity mesh session was established |
| `PROXIMITY_SESSION_CLOSED` | A proximity mesh session was closed |
| `PROXIMITY_HARDWARE_SELECTED` | Hardware adapters were selected (`meta.adapter`, `meta.source`) |
| `PROXIMITY_HARDWARE_ERROR` | Hardware adapter selection failed; proximity tools return errors |
| `PROXIMITY_DISCOVERY` | Reserved: declared, not yet emitted |
| `PROXIMITY_RERANGE` | Reserved: declared, not yet emitted |
| `PROXIMITY_DELEGATION` | Reserved: declared, not yet emitted |

## `meta.event_detail` sub-events

Some administrative actions are recorded under a general event type, with the specific action in `meta.event_detail`. When filtering the log, match on both fields.

| `event_detail` | Logged as | Meaning |
|---|---|---|
| `AGENT_REGISTERED` | `CONFIG_LOADED` | `atlas_identity_register` issued a credential |
| `AGENT_REVOKED` | `CONFIG_LOADED` | `atlas_identity_revoke` revoked a credential |
| `AGENT_DELEGATED` | `CONFIG_LOADED` | `atlas_identity_delegate` issued a scoped child credential |
| `CASCADE_REVOCATION` | `CONFIG_LOADED` | `atlas_identity_cascade_revoke` revoked a parent and its descendants |
| `BOOTSTRAP_CONFIRM_SKIPPED` | `CONFIG_LOADED` | Two-channel bootstrap confirmation was bypassed by environment variable |
| `BOOTSTRAP_CONFIRMATION_TIMEOUT` | `POLICY_DENY` | The bootstrap confirmation code was not returned in time |
| `BREAK_GLASS_ACTIVATED` | `CONFIG_LOADED` | Emergency Telegram bypass activated |
| `BREAK_GLASS_REVOKED` | `CONFIG_LOADED` | Emergency bypass revoked |
| `AUDIT_LOG_ROTATED` | `CONFIG_LOADED` | The audit log was rotated into an archive |
| `KEY_ROTATION_COMPLETE` | `SESSION_START` | First entry signed by the new issuer key after rotation |
