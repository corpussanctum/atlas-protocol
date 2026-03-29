# Atlas Protocol Specification

**Version:** 0.8.1-draft
**Status:** Working Draft
**Authors:** TJ Lane (Corpus Sanctum)
**Last updated:** 2026-03-29

This document defines the normative requirements for Atlas Protocol. It separates **what a conformant implementation MUST do** from **how the reference implementation happens to do it**. The reference implementation (this repository) uses Telegram, Ollama, and MCP as its transport and runtime, but those are binding choices of this implementation, not of the protocol.

Key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. Overview

Atlas Protocol is a fail-closed permission governance protocol for autonomous AI agents. It defines:

- **Agent identity** — DID-based credentials signed with post-quantum cryptography
- **Policy evaluation** — ordered rule matching with anomaly detection
- **Permission relay** — operator-in-the-loop approval for ambiguous requests
- **Audit integrity** — tamper-evident, anti-truncation, post-quantum signed audit trail
- **Behavioral baselines** — longitudinal drift detection across sessions
- **Delegation** — scoped, depth-limited credential delegation with authority binding

The protocol does NOT prescribe:

- Which messaging system delivers operator prompts (Telegram, Slack, email, local console)
- Which inference runtime powers the Why Layer (Ollama, vLLM, API)
- Which plugin framework hosts the gatekeeper (MCP, LSP, custom)
- Which storage backend persists credentials (JSON files, database, HSM)

## 2. Conformance profiles

| Profile | Intended use | Bootstrap confirmation | Break-glass | Quiet mode | Why Layer | Baseline drift |
|---|---|---|---|---|---|---|
| **Development** | Local testing, CI | MAY skip | MAY omit | MAY enable freely | MAY disable | MAY omit |
| **Production** | Deployed agent governance | MUST require | SHOULD support | SHOULD restrict to mature agents | SHOULD enable | MUST enable |
| **Research** | Protocol experimentation | MUST require | SHOULD support | MAY enable | MUST enable | MUST enable |

Implementations MUST declare which conformance profile they target. The reference implementation defaults to Production.

## 3. Core protocol

### 3.1 Fail-closed default

An implementation MUST deny any request that cannot be resolved through the permission pipeline. Specifically:

- If identity attestation fails, the request MUST be denied.
- If no policy rule matches, the request MUST be forwarded to the operator (not auto-allowed).
- If the operator does not respond within the configured timeout, the request MUST be denied.
- If the relay transport is unreachable and no break-glass token is active, the request MUST be denied.

### 3.2 Permission pipeline

Every tool request MUST pass through these stages in order:

1. **Identity attestation** — verify the requesting agent holds a valid, unexpired, unrevoked credential with the required capability.
2. **Policy evaluation** — match the request against the ordered rule set. First match wins.
3. **Quiet mode** (OPTIONAL) — if enabled, auto-approve eligible low-risk requests for mature agents.
4. **Break-glass** (OPTIONAL) — if an active token exists, auto-approve "ask" verdicts.
5. **Operator relay** — forward unresolved "ask" verdicts to the operator and await response.

Hard-deny rules (step 2) MUST NOT be bypassed by quiet mode, break-glass, or any other mechanism. Only "ask" verdicts may be auto-resolved by steps 3-4.

### 3.3 Policy engine semantics

- Rules MUST be evaluated in order. First match wins.
- Each rule has a `tool_pattern` (glob-like), an `action` (deny | ask | allow), and an OPTIONAL `reason`.
- Pattern matching MUST be case-insensitive.
- If no rule matches, the default verdict MUST be "ask".
- Implementations SHOULD tag deny rules with MITRE ATT&CK technique IDs.

### 3.4 Anomaly detection

The policy engine MUST scan every request for anomaly indicators. At minimum:

- **Velocity** — requests per minute exceeding a configurable threshold.
- **Privilege escalation** — sudo, chmod, chown, passwd patterns.
- **Data exfiltration** — outbound data transfer indicators.
- **Obfuscation** — base64, hex encoding, dynamic execution patterns.
- **PII detection** — SSN, email, phone number patterns.

Anomaly flags MUST be attached to the audit entry and included in operator prompts.

## 4. Agent identity (`did:atlas`)

### 4.1 DID method syntax

```
did:atlas:<uuid>
```

Where `<uuid>` is a RFC 4122 v4 UUID. Example: `did:atlas:550e8400-e29b-41d4-a716-446655440000`.

> **Note:** The current `did:atlas` method is locally-scoped to a single gatekeeper operator. A future version will define namespace syntax and cross-operator resolution semantics to support federated deployments.

### 4.2 DID document

A `did:atlas` identifier resolves to an `AgentCredential` object within the local identity registry. There is no external resolution endpoint — `did:atlas` is a locally-scoped method designed for single-operator environments.

**Canonical DID Document structure:**

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:atlas:550e8400-e29b-41d4-a716-446655440000",
  "verificationMethod": [{
    "id": "did:atlas:550e8400...#key-1",
    "type": "PostQuantum2024",
    "controller": "did:atlas:550e8400...",
    "publicKeyHex": "<ML-DSA-65 public key>"
  }],
  "authentication": ["did:atlas:550e8400...#key-1"],
  "assertionMethod": ["did:atlas:550e8400...#key-1"]
}
```

### 4.3 Resolution semantics

| Operation | Behavior |
|---|---|
| **Create** | `register()` generates a new keypair, assigns a DID, and stores the credential. The issuer MUST sign the canonical credential payload with its ML-DSA-65 key. |
| **Read** | `get(agentId)` returns the credential object or `null` if not found. Resolution MUST be O(1). |
| **Update** | Credentials are immutable after issuance. To change capabilities or role, revoke and re-issue. |
| **Deactivate** | `revoke(agentId, reason)` sets `revoked: true` and records `revokedAt` + `revokedReason`. A revoked credential MUST fail attestation. Revocation is permanent and irreversible. |

### 4.4 Error states

| State | Resolution result |
|---|---|
| DID not found in registry | `null` (attestation returns `UNREGISTERED_AGENT`) |
| Credential expired | Attestation returns `CREDENTIAL_EXPIRED` |
| Credential revoked | Attestation returns `CREDENTIAL_REVOKED` |
| Capability mismatch | Attestation returns `CAPABILITY_MISMATCH` |
| Registry empty (bootstrap) | Attestation returns unverified pass (bootstrap guard) |

### 4.5 Issuer key discovery and rotation

The gatekeeper's ML-DSA-65 keypair serves as the sole trusted issuer. The public key hash is logged in the `SESSION_START` audit entry for key pinning.

**Issuer key discovery:**

A verifier that does not have the issuer public key pinned locally MUST discover it through one of the following mechanisms, in priority order:

1. **Local pinning** (RECOMMENDED) — the verifier has a pre-shared copy of the issuer's public key or its SHA3-256 hash, obtained through an out-of-band trust establishment (e.g., manual exchange, secure configuration).
2. **SESSION_START extraction** — the verifier reads the most recent `SESSION_START` entry in the audit trail and extracts the `pq_public_key_hash` field from its `meta` object. The verifier SHOULD compare this hash against a separately obtained reference value before trusting it. A `SESSION_START` entry whose `pq_public_key_hash` cannot be independently corroborated MUST be treated as untrusted.
3. **Well-known URI** (future) — a future version of this specification will define a `/.well-known/atlas-issuer` endpoint for publishing the issuer public key and rotation history. Implementations MAY implement this endpoint ahead of formal specification.

For single-operator deployments (the gatekeeper is the only verifier), mechanism 1 is implicit — the gatekeeper holds the key. For multi-party verification (hospital auditor, grant reviewer, VA system), mechanism 1 or 3 is REQUIRED; mechanism 2 alone is insufficient because a compromised gatekeeper could forge `SESSION_START` entries.

**Key rotation procedure:**

1. Generate a new ML-DSA-65 keypair.
2. Log a `KEY_ROTATION` audit entry (signed by the OLD key) containing the new public key hash.
3. Re-issue all active credentials signed by the new key.
4. Archive the old keypair (retain for verification of historical audit entries).
5. The new `SESSION_START` entry pins the new key.

> **Note:** The reference implementation does not yet implement automated key rotation or well-known URI publication. These are specified for forward compatibility.

### 4.6 Bootstrap guard

When the identity registry is empty (first run), attestation MUST return an unverified pass to avoid a catch-22 (can't register without a credential, can't get a credential without registering).

For **Production** conformance, the first credential registration MUST require two-channel confirmation: a verification code displayed on the host console and confirmed via the operator relay. This prevents a compromised agent from registering a malicious admin credential during the bootstrap window.

For **Development** conformance, two-channel confirmation MAY be skipped.

## 5. Credential delegation

### 5.1 Delegation constraints

- Child capabilities MUST be a strict subset of the parent's capabilities.
- Child TTL MUST NOT exceed the parent's remaining lifetime.
- Maximum delegation depth MUST NOT exceed 3.
- Delegation from a revoked or expired parent MUST fail.

### 5.2 Chain signature (authority binding)

The delegation chain signature MUST bind the actual delegated authority, not just identities. The signed payload MUST be a canonical JSON object containing:

```json
{
  "protocol": "atlas-protocol",
  "version": "<protocol version>",
  "type": "delegation-authority",
  "rootId": "<root DID>",
  "parentId": "<parent DID>",
  "childId": "<child DID>",
  "capabilities": ["<sorted capability list>"],
  "expiresAt": "<ISO 8601>",
  "depth": <integer>,
  "childCredentialHash": "<SHA3-256 of child credential canonical payload>"
}
```

The parent agent's ML-DSA-65 secret key signs this object. The gatekeeper's issuer key co-signs the full credential.

This prevents substitution attacks where an attacker replays a chain signature with different capabilities or expiry.

### 5.3 Cascade revocation

Revoking a parent credential MUST revoke all descendants. Implementations MUST walk the delegation tree depth-first and revoke every child.

### 5.4 Verification

Verifying a delegated credential MUST:

1. Verify the credential's issuer signature (gatekeeper key).
2. Verify the credential hash (SHA3-256 of canonical payload).
3. Verify the chain signature against the parent's public key and the canonical delegation authority.
4. Verify the parent is not revoked or expired.
5. If the parent is itself delegated, recursively verify its chain.

## 6. Audit log

### 6.1 Format

The audit log MUST be append-only JSONL (one JSON object per line).

### 6.2 Integrity layers

Implementations MUST provide at minimum:

1. **Hash chaining** — each entry MUST include `prev_hash`, the SHA3-256 hash of the previous line. The first entry uses `"GENESIS"`.
2. **Sequence numbers** — each entry MUST include `seq`, a monotonic 0-indexed integer. The verifier MUST detect gaps.

Implementations SHOULD provide:

3. **Post-quantum signatures** — ML-DSA-65 (FIPS 204) signature per entry in `pq_signature`.
4. **Periodic checkpoints** — `CHECKPOINT` entries at configurable intervals containing `checkpoint_seq`, `checkpoint_hash`, and `entries_since_start`.

Implementations MAY provide:

5. **HMAC-SHA256 signatures** — classical `hmac` field for backwards compatibility.
6. **External anchoring** — publishing checkpoint hashes to a transparency log or blockchain.

### 6.3 Anti-truncation

Hash chaining detects tampering within the chain but not silent truncation (removing entries from the end). Implementations MUST defend against truncation via:

- Monotonic sequence numbers (gap detection).
- Periodic signed checkpoint entries.

Implementations SHOULD additionally consider:

- External checkpoint anchoring (e.g., publishing checkpoint hashes to an append-only third-party log).
- Signed rotation manifests that record the final sequence number and hash of each archived file.

### 6.4 Rotation

When the audit log exceeds a configurable size threshold, implementations SHOULD rotate the file to an archive directory. The rotation manifest MUST record:

- Rotated filename
- Entry count
- File size
- SHA3-256 hash of the last line (chain anchor)
- SHA3-256 hash of the entire file (integrity check)

The chain anchor from the rotated file becomes the effective `prev_hash` for the new file's first entry.

### 6.5 Entry schema

Every audit entry MUST include: `id`, `timestamp`, `event`, `seq`, `prev_hash`.

Every audit entry SHOULD include: `hash_algorithm`, `pq_signature`.

Event-specific fields (`permission`, `policy_result`, `verdict`, `agentId`, `identityVerified`, `mitre`, etc.) are included when applicable.

### 6.6 Field redaction

When privacy mode is enabled or consent tiers require it, sensitive fields on the permission object MUST be replaced with `HASHED:<sha256>` rather than stored in plaintext. The hash allows verification without exposing the original value.

## 7. Why Layer (Council of Experts)

### 7.1 Design constraints

The Why Layer MUST:

- **Never block the gatekeeper.** If the inference runtime is unavailable, return a nominal stub.
- **Never throw.** Failures are swallowed and logged, not propagated.
- Be non-gating — it informs, it does not decide.

### 7.2 Expert agents

A conformant Why Layer MUST run at least 3 expert perspectives:

- **Anomaly detection** — statistical/behavioral anomalies
- **Intent inference** — what the agent is trying to accomplish
- **Threat narration** — MITRE ATT&CK mapping, incident brief

Experts MAY run in parallel.

### 7.3 Model provenance

Every `WhyAssessment` SHOULD include a `provenance` object containing:

| Field | Description |
|---|---|
| `model` | Model name/tag used for inference |
| `modelDigest` | Model content hash from the runtime (if available) |
| `systemPromptHash` | SHA-256 hash of the system prompts used |
| `ollamaVersion` | Inference runtime version (if available) |
| `protocolVersion` | Atlas Protocol version |

This prevents the CoE from being an unattributed hallucination layer. Consumers of `WhyAssessment` artifacts MUST treat findings as model-generated opinions, not ground truth. The provenance enables reproducibility analysis and version-pinning for compliance.

### 7.4 Evidence citation

Each signal in the `ExpertAssessment.signals` array MUST reference at least one specific audit entry by its `id` field (e.g., `"T1059 match on entry abc12345"`). This grounds the CoE output in observable evidence rather than model confabulation.

Implementations MUST surface a flag when signals cannot be grounded to specific entries:

```typescript
interface ExpertAssessment {
  // ...
  signals: string[];            // Each SHOULD contain an audit entry ID reference
  ungroundedSignals?: boolean;  // true if any signal lacks an entry citation
}
```

Consumers of `WhyAssessment` artifacts MUST treat findings with `ungroundedSignals: true` as lower-confidence than grounded findings. Research artifacts that contain ungrounded signals MUST NOT be presented as primary evidence without explicit disclosure.

### 7.5 Research artifact integrity

Every `ResearchArtifact` MUST include:

| Field | Description |
|---|---|
| `derivedFrom` | SHA3-256 hash of the serialized audit event window (entry IDs) |
| `generatedBy` | Model identifier from `ModelProvenance` |
| `assessedAt` | ISO 8601 timestamp of artifact generation |
| `caution` | Fixed string: `"AI-generated analysis. Verify against primary audit trail."` |

Research artifacts MUST NOT be presented as primary evidence without corroboration against the audit trail. The `derivedFrom` hash allows a verifier to confirm which audit entries were analyzed.

### 7.6 Evidentiary discipline

Implementations SHOULD:

- Pin model versions in production deployments (not "latest").
- Log when the model used differs from the configured model.
- Include confidence levels on all expert findings.
- Prefer grounded signals over free-text assertions.

## 8. Behavioral baselines

### 8.1 Profile requirements

Each agent MUST accumulate a persistent behavioral profile across sessions. Profiles MUST contain:

- Risk distribution statistics (mean, stddev, percentiles)
- MITRE technique frequency counts
- Per-capability allow/deny/ask ratios
- Temporal activity patterns
- Maturity level classification

### 8.2 Maturity model

| Level | Sessions | Drift detection |
|---|---|---|
| Insufficient | < 10 | No — weak signal |
| Developing | 10-49 | Limited |
| Established | 50-199 | Full |
| Mature | 200+ | Full + eligible for quiet mode |

### 8.3 Drift detection

When the Why Layer fires, implementations MUST check for drift against the agent's baseline. At minimum 5 dimensions:

- Risk score elevation
- New MITRE technique
- Capability deny rate spike
- Temporal anomaly (unusual hours)
- Volume spike

## 9. Break-glass mechanism

### 9.1 Purpose

Provides emergency override when the operator relay transport is unreachable.

### 9.2 Requirements

- Break-glass MUST only bypass "ask" verdicts. Hard-deny rules MUST NOT be bypassed.
- Tokens MUST be time-limited (maximum 4 hours).
- Tokens MUST be stored with restrictive file permissions (0600).
- Activation SHOULD require operator confirmation via the relay transport, falling back to console-only confirmation when the transport is already down.
- All break-glass approvals MUST be logged in the audit trail.
- Implementations MAY support request count limits on tokens.

## 10. Quiet mode

### 10.1 Purpose

Reduces operator noise for mature agents performing low-risk actions.

### 10.2 Eligibility

A request is eligible for quiet-mode auto-approval only if ALL of the following are true:

- Quiet mode is enabled (off by default).
- The policy verdict is "ask" (never bypasses deny).
- The agent's identity is verified.
- The agent's baseline maturity meets the configured threshold (default: mature).
- The tool is in the quiet-eligible set (default: read-only tools).
- The request has zero anomaly flags.
- The request has zero sensitivity matches.
- The input does not match any sensitive path pattern.

### 10.3 Sensitive path patterns

At minimum, implementations MUST block quiet-mode approval for paths matching:

`.env`, `.ssh`, `.gnupg`, `/etc/`, `credentials`, `secret`, `token`, `api_key`, `password`, `shadow`, `.pem`, `.key`, `.p12`, `.pfx`.

## 11. Extensions

### 11.1 DIB Briefcase integration (OPTIONAL)

When a DIB Briefcase is loaded, the policy engine enforces consent boundaries from a 7-tier consent model (Public through Sealed / 42 CFR Part 2). This is an optional privacy hardening layer — Atlas works fully without it.

The Briefcase provides:

- **Consent boundaries** — forbidden tool patterns per consent tier
- **Sensitivity classifications** — regex patterns that detect data types requiring specific consent levels
- **Audit redaction** — fields to hash instead of storing in plaintext

Implementations MAY support other consent/privacy frameworks through the same extension point.

### 11.2 Inference runtime (reference: Ollama)

The reference implementation uses Ollama for the Why Layer's Council of Experts. Implementations MAY use any inference runtime that supports:

- Chat completion with JSON-structured output
- Configurable model selection
- Local-first deployment (recommended for privacy)

### 11.3 Operator relay (reference: Telegram)

The reference implementation uses the Telegram Bot API for operator relay. Implementations MAY use any transport that supports:

- Authenticated message delivery to the operator
- Bi-directional messaging (prompt + verdict)
- Message delivery confirmation

Examples: Slack, Discord, email, SMS, local console, custom webhook.

---

## Appendix A: Cryptographic algorithms

| Purpose | Algorithm | Standard | Notes |
|---|---|---|---|
| Credential signing | ML-DSA-65 | FIPS 204 | Post-quantum, harvest-now-decrypt-later resistant |
| Audit entry signing | ML-DSA-65 | FIPS 204 | Same keypair as credential issuer |
| Hash chaining | SHA3-256 | FIPS 202 | Quantum-resistant hash |
| Credential hash | SHA3-256 | FIPS 202 | Canonical payload digest |
| Audit HMAC (optional) | HMAC-SHA256 | RFC 2104 | Classical, backwards-compatible |
| Field redaction | SHA-256 | FIPS 180-4 | One-way hash for privacy |
| System prompt hash | SHA-256 | FIPS 180-4 | Provenance tracking |

## Appendix B: Reference implementation mapping

| Spec concept | Reference implementation |
|---|---|
| Operator relay | Telegram Bot API (`telegram.ts`) |
| Inference runtime | Ollama (`why-engine.ts`) |
| Plugin framework | MCP (Model Context Protocol) |
| Credential storage | JSON files, chmod 600 |
| Key storage | `quantum-keypair.json`, chmod 600 |
| Audit storage | JSONL files with rotation |
| Baseline storage | Per-agent JSON files |

## Appendix C: MITRE ATT&CK coverage

The reference policy ruleset covers techniques from these ATT&CK tactics:

- Initial Access (T1190, T1195.002)
- Execution (T1059, T1059.004, T1059.006)
- Persistence (T1053.003, T1098.004, T1543, T1546.004)
- Privilege Escalation (T1548, T1548.001)
- Defense Evasion (T1027, T1027.002, T1070, T1140, T1222.002, T1562.001, T1562.004)
- Credential Access (T1003, T1110, T1552, T1555, T1558)
- Discovery (T1018, T1046, T1057, T1082, T1087.002, T1135)
- Lateral Movement (T1021)
- Collection (T1040)
- Command and Control (T1071.001, T1095, T1572, T1573.002)
- Exfiltration (T1048, T1567)
- Impact (T1485, T1489, T1496, T1561)
