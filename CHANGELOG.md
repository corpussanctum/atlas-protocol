# Changelog

All notable changes to Atlas Protocol are documented in this file.

## [Unreleased]

### Fixed
- `atlas_proximity_disconnect` reported "Session … closed." for IDs that
  were never active; it now returns `isError` with "not found" (#26).
- Docs claimed 97 policy rules (90 deny) and "120+" fixtures. The default set
  has always been **96 rules (89 deny, 7 ask)**, and `atlas_test_policy` runs
  **79** fixtures; the March "96→97" correction was itself a miscount. No rule
  was removed (#25). `check:versions` now derives these counts from
  `src/config.ts` and the test runner, and fails on any prose mismatch.

### Changed
- MCP tool definitions and handlers moved from `src/index.ts` into
  `src/mcp/tools/<domain>.ts` with a shared `ToolContext`, and versions moved
  to `src/version.ts`. `index.ts` went from 1818 to 535 lines (#5). Behavior
  unchanged, as shown by new snapshot tests of `tools/list` and a scripted call
  to all 26 tools, written before the move.

## [1.0.5] - 2026-10-12

Security release: break-glass can only be activated by the operator
(operator-signed tokens), and the permission pipeline fails closed on
internal errors. **Action required** to keep using break-glass: run
`atlas-operator keygen` and restart Atlas.

### Security
- **Break-glass now requires an operator signature (GHSA-4qq7-gm8p-g5vx).**
  Before this change, a break-glass token was plain JSON in the data directory,
  so any process that could write there, including the governed agent through
  its own file tools, could create an active override that auto-approved every
  "ask" for up to 4 hours. Separately, `atlas_break_glass_activate` skipped
  confirmation when no Telegram token was configured, or when sending the
  Telegram challenge failed.
  - New `atlas-operator` CLI (`keygen`, `break-glass`, `status`, `revoke`).
    The operator key is ML-DSA-65, with its secret half encrypted under an
    operator passphrase (scrypt + AES-256-GCM). The passphrase is read only
    from an interactive terminal.
  - The gatekeeper verifies the token's signature, key identity, expiry, and
    TTL limit from the signed fields. It pins the operator public key at
    startup (optionally also via `ATLAS_OPERATOR_KEY_ID`), and tracks usage
    outside the token file.
  - `atlas_break_glass_activate` always refuses, audits
    `BREAK_GLASS_ACTIVATION_REFUSED`, and alerts the operator.
  - **Breaking:** existing unsigned tokens are ignored, and break-glass is
    unavailable until the operator runs `atlas-operator keygen` and restarts.
- SPEC 1.1.0: §9.2 now requires operator-signed activation, and Appendix H
  documents the same-user agent threat. The README's earlier claim that
  activation "falls back to console-only confirmation" was never implemented.

- **Permission pipeline is now fail-closed on internal errors.** If the
  operator channel threw (e.g. Telegram unreachable), or the policy engine or
  audit logger raised, the request got no verdict at all. Now an operator
  error is recorded as `TIMEOUT_DENY` (`reason: "Operator channel error: …"`),
  and any other pipeline exception is a `POLICY_DENY` with `meta.pipeline_error`.
  In every case an explicit deny is returned.

### Changed
- The permission pipeline moved from `src/index.ts` into
  `src/authority/permission-pipeline.ts` (`createPermissionPipeline`) with
  injected dependencies and a transport-neutral `OperatorChannel`: the first
  step of the authority-core extraction (#5). Behavior unchanged, as shown by
  new MCP-level characterization tests written before the move.

## [1.0.4] - 2026-10-12

Hardening from the first CodeQL pass: `config.json` is validated field by
field, the Why Layer flags non-local plaintext endpoints, and audit events
are cataloged and checked against the code in CI.

### Security
- **`config.json` is now validated per field** (CodeQL `js/file-access-to-http`
  triage, #16). Previously `Object.assign` copied any JSON value into the live
  config, so a string `permission_timeout_seconds` reached the HTML-formatted
  Telegram approval prompt and a non-numeric value distorted the fail-closed
  timer. Invalid or unknown fields now keep their defaults, warn on stderr, and
  are recorded in the `CONFIG_LOADED` audit entry as `rejected_config_fields`.
  A malformed `policy_rules` entry rejects the whole custom set, so no deny
  rule is silently dropped. `config_path` is no longer overridable from the file.
- **Why Layer endpoint check:** a non-loopback plain-HTTP `WHY_ENGINE_BASE_URL`
  logs a startup warning, and `CONFIG_LOADED` records whether the endpoint is
  loopback/encrypted. Assessments send audit entries and baseline profiles to it.

### Added
- **Audit event catalog** (`docs/AUDIT_EVENTS.md`): all 25 event types and the 10
  `meta.event_detail` sub-events (with their parent event), including 3
  reserved proximity events that are declared but not yet emitted.
- `check:versions` now checks in both directions that the README tool table
  matches registered tools, and that the audit catalog matches the
  `AuditEventType` union and every `event_detail` emitted in `src/` (#3).

### Fixed
- README listed Why Layer window defaults as 50 entries / 30 minutes; the code
  uses 20 / 60.
- DIDComm adapter test checked the invitation URL with a prefix match; it now
  compares the parsed origin.

## [1.0.3] - 2026-10-12

Stabilization: ProximityMesh hardware selection actually works and never
silently falls back to mocks, version drift is enforced in CI, and the
supply chain is audited on every push.

### Fixed
- **`ATLAS_HARDWARE_ADAPTER` had no effect.** The MCP server constructed
  `Mock{UWB,BLE,NFC}Driver` directly and never called the adapter factory, so
  every ProximityMesh ran on mock drivers regardless of configuration. The
  server now selects drivers through `createHardwareAdapters()` on the first
  proximity tool call, and an end-to-end test spawns the server to prove the
  env var changes the instantiated driver.
- **Raspberry Pi auto-detection never ran.** The factory called `require()`
  inside an ESM module; the resulting `ReferenceError` was swallowed and
  detection always fell back to mock.

### Changed
- `atlas_proximity_status` reports `hardware.adapter`, `hardware.source`
  (`env` / `auto-detect` / `default`), and `hardware.simulated`.
- An unrecognized `ATLAS_HARDWARE_ADAPTER` value, or adapter drivers that fail
  to load, now make the proximity tools return an error (and log
  `PROXIMITY_HARDWARE_ERROR`) instead of degrading to mock drivers. Successful
  selection logs `PROXIMITY_HARDWARE_SELECTED`.
- ESP32 is no longer auto-selected whenever any `/dev/ttyUSB*` / `ttyACM*`
  device exists; it requires `ATLAS_HARDWARE_ADAPTER=esp32-uart`.
- Lockfile refreshed via `npm audit fix` (in-range only; MCP SDK 1.28.0 →
  1.32.1). Clears 9 advisories (1 critical, 4 high) in the SDK's HTTP/OAuth
  transitive dependencies.

### Added
- `npm run check:versions` (`scripts/check-versions.mjs`): fails when
  implementation / spec / protocol / credential-schema versions or the README
  tool count disagree across `package.json`, `src/`, plugin manifests,
  lockfile, README and SPEC §11.2 version maps, and CHANGELOG.
- CI: version-consistency job, `npm audit --omit=dev --audit-level=high` for
  both packages, and a package-contents check. CodeQL (`security-extended`)
  workflow and Dependabot for npm + GitHub Actions.
- GitHub issue templates (bug, security-hardening task) and a PR template.

## [1.0.2] - 2026-08-29

Honest 1.0 follow-up: version map frozen, CI added, issuer key rotation
implemented per SPEC §4.5, proximity handshake uses real X25519, and
ProximityMesh is labeled research/demo until hardware is validated.

### Added
- **Issuer key rotation (SPEC §4.5).** `atlas_key_rotate` generates a new
  ML-DSA-65 issuer key, logs a `KEY_ROTATION` audit entry signed by the old
  key, re-issues all active credentials with the new key, and retains the
  last 3 public keys so historical audit signatures still verify.
- **GitHub Actions CI** — `npm test` + `npm run build` on Node 20 and 22,
  plus the DIDComm adapter suite.
- **Version map** in README and SPEC §11.2: spec document / implementation /
  protocol wire / credential schema are now named separately.

### Changed
- **Proximity handshake uses real X25519 ECDH** instead of hash-simulated DH.
  Transport remains AES-256-GCM; this is an IK/KK *key-use pattern*, not a
  byte-compatible Noise_IK handshake. Protocol name:
  `Atlas_X25519_AESGCM_SHA256`.
- **SESSION_START** now records `protocol_version` (0.8.4) and `spec_version`
  alongside the implementation `version`.
- ProximityMesh marketplace plugin and README limitations now state that
  hardware adapters are untested reference drivers.
- SPEC.md document version 1.0.0 → **1.0.1** (editorial + implemented
  rotation; protocol wire version remains 0.8.4). The 1.0.0 changelog said
  the spec was a Release Candidate; the document status was already Published.

### Fixed
- **Bootstrap & break-glass confirmation now reachable under stdio MCP transport.**
  Previously the 6-character confirmation code was written to `stdout` via
  `console.log`, which collides with the JSON-RPC channel when Atlas runs as
  a stdio MCP child process — the operator could see the Telegram challenge
  but had no way to obtain the code. The code is now written to STDERR (so
  it remains visible in terminal launches) and additionally persisted to
  `<data_dir>/bootstrap-code.txt` (or `break-glass-code.txt`) with mode 0600
  for the duration of the confirmation window. The file is single-use:
  deleted on confirmation success, denial, or timeout. Two-channel verification
  per SPEC §4.6 is preserved — filesystem access on the host remains a separate
  channel from the Telegram operator relay, and the code is **never** sent over
  Telegram.
- All `console.log` calls in `src/index.ts` migrated to `console.error` to
  prevent any future stdout pollution of the MCP JSON-RPC stream.
- Runtime `VERSION` constant (`src/index.ts`) was still `1.0.0` after the
  1.0.1 package bump; now tracks the implementation version.
- README architecture tree claimed 20 tools / 96 rules; swarm demo said
  96-rule; RELEASE_CHECKLIST said 575 tests.
- SPEC §4.1 linked a non-existent GitHub issue for federation tracking.
- Android adapter error pointed at a missing `examples/android/` directory.

## [1.0.1] - 2026-03-30

Marketplace submission prep: `manifest_version` 0.2, privacy policy URLs,
MCP tool annotations. Package version was bumped; the runtime `VERSION`
constant was not (fixed in 1.0.2).

## [1.0.0] - 2026-03-29

First stable release. All pre-tag blockers resolved, test vectors verified, spec status
upgraded from Working Draft to Release Candidate.

### Fixed
- J.2 verifier pseudocode: `JSON.stringify(authority)` → `canonicalize(authority)` with D.2 reference

### Changed
- SPEC.md version: 0.8.4-draft → 1.0.0 Release Candidate

## [0.8.4] - 2026-03-29

### Added (SPEC.md — adoption and clarity)
- **Appendix F: Canonical worked examples** — 7 complete examples: root credential, delegated
  credential, delegation authority payload, audit entry, checkpoint, rotation manifest, redacted
  permission object. Sufficient to build a verifier from examples + normative rules.
- **Appendix G: Conformance test vectors** — fixed hash values for: credential hash, audit
  prev_hash, delegation authority hash, redacted field HMAC, rotation bridge. Generated from
  `scripts/gen-test-vectors.mjs`. Enables interop testing without reading source code.
- **Appendix H: Security limitations** — explicit enumeration of what Atlas does not solve:
  host compromise, malicious operator, compromised runtime, bad rulesets, LLM semantic gaps,
  relay compromise, low-entropy redaction, replay/rollback, key compromise, multi-party trust.
- **Appendix I: Terminology** — 15 standardized term definitions (ask, deny, allow, attestation,
  verified identity, local DID, checkpoint, archive, anchor, mature baseline, sensitive path,
  grounded signal, operator, seq).
- **Appendix J: Verifier pseudocode** — 5 verification procedures: credential, delegated
  credential, audit chain, archive bridge, checkpoint continuity.
- **RELEASE_CHECKLIST.md** — per-release drift verification questions covering spec/implementation
  sync, code quality, version bump, security, and documentation.
- **scripts/gen-test-vectors.mjs** — generates conformance test vector hashes from known inputs.

### Changed
- **README**: Replaced "holds up 15 years" language with precise cryptographic claims referencing
  SPEC.md Appendix H security limitations.

## [0.8.3] - 2026-03-29

### Changed (SPEC.md — normative precision hardening)
- **§6.2.1 Sequence number semantics** — seq is global monotonic (no reset on rotation),
  exact failure modes for gaps/duplicates/missing, concurrency rule (single writer only)
- **§6.5 Rotation** — manifest now requires `final_seq`/`next_seq` fields, exact first-entry-
  after-rotation behavior, cross-archive verification procedure (5 steps), manifest failure modes
- **§3.3.1 Policy rule grammar** — formal wildcard syntax (`*` only, no regex), escaping rules,
  case-insensitivity, tool vs input matching, ordering guarantee, portability requirement
- **§4.5 Key rotation** — `KEY_ROTATION` audit event schema with exact fields (old/new key hash,
  effective timestamp, reissue count/success), historical verification expectations
- **§4.6 Bootstrap guard** — exact "registry empty" definition, first-credential constraints,
  confirmation code entropy/timeout/replay/max-attempts requirements
- **§10 Quiet mode** — 6 explicit invariants (never bypasses deny, not an alternate policy engine,
  sensitivity before eligibility, any flag/uncertainty kills eligibility), evaluation order specified
- **§7.4 Evidence citation** — grounding definition (8+ char UUID prefix match), minimum evidence
  count per expert type, mandatory confidence downgrade when `ungroundedSignals: true`
- **§11 Forward compatibility** — unknown field handling for runtime objects vs signed payloads,
  `extensions` namespace convention, version authority rules, compatibility matrix
- **Appendix E** — normative error code enums: attestation (4 codes), delegation (6), audit
  verification (9), break-glass (6), extensibility convention (`X_` prefix)

## [0.8.2] - 2026-03-29

### Added
- **Issuer key discovery** in SPEC.md §4.5 — normative mechanism for third-party verifiers
  to discover the trusted issuer public key (local pinning RECOMMENDED, SESSION_START
  extraction as fallback, well-known URI placeholder for future)
- **Evidence citation requirements** in SPEC.md §7.4 — expert signals MUST reference
  specific audit entry IDs; `ungroundedSignals` flag added to `ExpertAssessment` type
  - Expert prompts updated to explicitly require entry ID citations
  - Post-processing detects signals that lack grounded references to known entry IDs
  - Fallback assessments marked `ungroundedSignals: true` by default
- **Research artifact integrity labeling** — `ResearchArtifact` now includes:
  - `derivedFrom`: SHA3-256 hash of the audit event window (entry IDs)
  - `generatedBy`: model identifier from provenance
  - `assessedAt`: ISO 8601 generation timestamp
  - `caution`: fixed string "AI-generated analysis. Verify against primary audit trail."
- **SPEC.md §7.5** — normative requirements for research artifact integrity fields

### Fixed
- Research conformance profile bootstrap requirement upgraded from MAY to MUST (consistency
  with production profile — research deployments collecting data must have bootstrap integrity)

## [0.8.1] - 2026-03-29

### Added
- **SPEC.md** — normative protocol specification, cleanly separated from reference implementation
  - Conformance profiles: Development, Production, Research with MUST/SHOULD precision
  - Complete `did:atlas` method spec: syntax, CRUD, resolution, error states, deactivation
  - Key rotation procedure (specified for forward compatibility)
  - Anti-truncation requirements (sequence numbers + checkpoints)
  - Model provenance requirements for Why Layer assessments
  - DIB Briefcase framed as optional extension, not bolted-on afterthought
- **Audit anti-truncation** — monotonic sequence numbers (`seq` field) on every entry
  - Verifier detects sequence gaps (silent truncation defense)
  - Periodic `CHECKPOINT` entries with running entry count and hash anchor
  - Configurable interval via `ATLAS_CHECKPOINT_INTERVAL` (default: every 100 entries)
- **Model provenance** in Why Layer assessments
  - `ModelProvenance` type: model name, model digest from Ollama, system prompt hash, runtime version
  - Fetches model digest and Ollama version at assessment time (best-effort, never blocks)
  - System prompt hash precomputed at startup for reproducibility tracking

### Changed
- **Delegation chain signature** now binds actual delegated authority, not just identities
  - Signed payload is a canonical JSON object containing: childId, parentId, rootId, capabilities, expiresAt, depth, protocol version, and child credential hash
  - Prevents substitution attacks where a chain signature is replayed with different capabilities or expiry
  - Verification reconstructs the canonical authority and checks against parent's public key
- **Audit verifier** now checks sequence number continuity alongside hash chain continuity
  - Reports `max_seq` and `checkpoints` count in verification stats

### Fixed
- **Rule count arithmetic**: README and docs claimed 97 rules but actual count is 96 (89 deny + 7 ask). Fixed all references.

## [0.8.0] - 2026-03-29

### Added
- **Policy Test Framework** — comprehensive regression testing for all 97 policy rules
  - 120+ fixtures covering malicious, benign, ask, and edge-case inputs
  - `atlas_test_policy` MCP tool for runtime regression testing
  - MITRE ATT&CK ID validation per fixture
  - Discovered 2 false-positive patterns: `TRUNCATE` matching `*ncat*`, `rsync` matching `*nc *`
- **Bootstrap Confirmation** — two-channel verification for first credential registration
  - 6-character confirmation code printed to server console
  - Operator must confirm via Telegram to finalize bootstrap
  - Prevents malicious first-credential registration during bootstrap window
  - `ATLAS_BOOTSTRAP_SKIP_CONFIRM=true` env var for dev/testing
- **Break-Glass Mechanism** — emergency override when Telegram is unreachable
  - Time-limited token (default 1h, max 4h) stored at `<data_dir>/break-glass.token`
  - Auto-approves "ask" verdicts only — hard-deny rules are NEVER bypassed
  - Requires Telegram or console confirmation to activate
  - Request counting with optional `max_requests` limit
  - `atlas_break_glass_activate`, `atlas_break_glass_status`, `atlas_break_glass_revoke` MCP tools
  - All break-glass actions prominently logged in audit trail
- **Audit Log Rotation** — automatic archival when log exceeds size threshold
  - Configurable via `ATLAS_AUDIT_MAX_SIZE_MB` (default: 10MB)
  - Archives to `<data_dir>/audit-archive/` with timestamped filenames
  - SHA3-256 file hash + chain anchor preserved in rotation manifest
  - `atlas_audit_rotate` and `atlas_audit_archives` MCP tools
  - Archive integrity verification (`atlas_audit_archives --verify`)
  - Optional pruning with `ATLAS_AUDIT_MAX_ARCHIVES`
- **Quiet Mode** — reduced noise for mature agents
  - Auto-approves low-risk actions (Read, Glob, Grep) for mature agents (200+ sessions)
  - Requires zero anomaly flags + non-sensitive path + verified identity
  - Sensitive path detection: `.env`, `.ssh`, `/etc/`, credentials, keys, tokens
  - Enable via `ATLAS_QUIET_MODE=true`
  - Configurable maturity threshold: `ATLAS_QUIET_MIN_MATURITY=established|mature`

### Changed
- Permission handler now has 5 steps: attestation → policy → quiet mode → break-glass → Telegram
- `atlas_status` now includes `quiet_mode` and `break_glass` status sections
- Version bumped to 0.8.0

## [0.7.0] - 2026-03-28

### Added
- **Persistent Behavioral Baselines** — per-agent profiles that accumulate across sessions
  - `BaselineProfile` with 8 behavioral dimensions: risk distribution, technique frequencies,
    capability usage, temporal patterns, delegation behavior, Why Layer history
  - 4-tier maturity model: insufficient (<10 sessions) → developing → established → mature (200+)
  - `RiskDistribution` with min/max/mean/p50/p75/p95/p99/stddev from accumulated observations
  - `TemporalProfile` with hourly and daily activity distributions
  - Auto-calculated drift thresholds (mean ± 2σ upper bound, ± 3σ critical)
- **Drift Detection** — 5 behavioral drift dimensions:
  - `RISK_SCORE_ELEVATED` — current risk exceeds baseline threshold
  - `NEW_TECHNIQUE_OBSERVED` — MITRE technique not in baseline
  - `CAPABILITY_DENY_SPIKE` — deny ratio for a capability >> baseline
  - `TEMPORAL_ANOMALY` — activity at unusual hours
  - `VOLUME_SPIKE` — event rate >> baseline average
  - Each signal includes severity, deviation factor, and human-readable description
- **Baseline-Aware Why Layer** — anomaly expert prompt now includes baseline context:
  - Historical risk scores, common techniques, temporal patterns
  - Expert explicitly compares current behavior against longitudinal baseline
  - Drift assessment integrated into `synthesize()` — elevates risk when drift detected
- **ResearchArtifact longitudinal fields**:
  - `baselineMaturity`, `baselineSessions`, `driftDetected`, `driftSignals`
  - `riskScoreVsBaseline` with current mean, baseline mean, and deviation factor
- **Baseline Store** — JSON-file persistence (one file per agent, chmod 600, atomic writes)
- **3 new MCP tools**:
  - `atlas_baseline_get` — retrieve full baseline profile for an agent
  - `atlas_baseline_drift` — run drift detection against current window
  - `atlas_baseline_list` — list profiles with maturity/role filters
- **BASELINE_DRIFT trigger** — Why Layer auto-fires when drift detected
- **Telegram alerts** enriched with baseline drift section when signals present
- Fire-and-forget baseline ingestion in audit.log wrapper (never blocks gatekeeper)
- New source files: `baseline-types.ts`, `baseline-store.ts`, `baseline-engine.ts`
- New test suites: `baseline-store.test.ts`, `baseline-engine.test.ts`, `baseline-integration.test.ts`
- 44 new tests (359 total, all passing)

### Changed
- Version bumped to 0.7.0 (persistent behavioral baselines release)
- `assessWindow()` now accepts optional `BaselineProfile` parameter
- `runExpert()` prepends baseline context to anomaly expert system prompt
- `synthesize()` accepts optional `DriftAssessment` and `BaselineProfile`
- `WhyTrigger` type extended with `BASELINE_DRIFT`
- `TriggerConfig` extended with `driftDetectionEnabled` and `driftSeverityThreshold`
- Auto-trigger hook ingests every audit entry into baseline (fire-and-forget)
- Why Layer assessments automatically ingested into agent baselines

### Security
- Baseline profiles store derived statistics only — no raw audit data (privacy)
- Baseline files written with chmod 600 (owner read/write only)
- Atomic file writes (tmp + rename) prevent corruption
- Internal `_riskScores` array stripped from MCP tool responses
- Drift thresholds not exposed unless specifically requested

## [0.6.0] - 2026-03-28

### Added
- **Credential Delegation** — orchestrator agents issue scoped sub-credentials
  - `DelegationChain` binds root → parent → child with ML-DSA-65 chain signatures
  - `DelegatedCredential` extends AgentCredential with delegation metadata
  - Max delegation depth: 3 (configurable constant)
  - Child capabilities must be strict subset of parent's
  - Child TTL automatically capped at parent's remaining lifetime
  - `validateDelegation()` — pre-flight check with 6 failure modes
  - `delegateCredential()` / `delegateCredentialWithKey()` — chain-signed issuance
  - `verifyDelegationChain()` — recursive verification of entire chain
  - `cascadeRevoke()` — revoking a parent cascades to all descendants
  - `issueCredentialWithKey()` — returns agent secret key for delegation support
- **3 new MCP tools** for delegation:
  - `atlas_identity_delegate` — issue scoped child credential
  - `atlas_identity_cascade_revoke` — revoke parent + all descendants
  - `atlas_identity_tree` — view credential hierarchy
- **Identity Registry delegation support**:
  - `delegate()`, `getChildren()`, `getDescendants()`, `cascadeRevoke()`
  - `children` index persisted in registry JSON for efficient tree walks
  - Agent secret keys stored in-memory (never persisted) for delegation chain
  - `list("delegated")` filter for delegation-only view
- **Why Layer** — Council of Experts (CoE) reasoning engine
  - 3 expert agents: Anomaly Detector, Intent Inferencer, Threat Narrator
  - Parallel async execution via Ollama (local-first, privacy-preserving)
  - `WhyAssessment` with risk scoring, recommended actions, research artifacts
  - `ResearchArtifact` structured for grant demos and research papers
  - Configurable via env vars: WHY_ENGINE_MODEL, WHY_ENGINE_BASE_URL, etc.
  - Graceful degradation: returns nominal stub if Ollama unavailable (never throws)
- **Why Triggers** — automatic Why Layer invocation on:
  - DENY_THRESHOLD (3+ denies in window)
  - HITL_ESCALATION (human approve/deny events)
  - HIGH_RISK_TECHNIQUE (Credential Access, Exfiltration, C2, Defense Evasion)
  - IDENTITY_ANOMALY (unregistered agent, expired credential)
  - CASCADE_REVOCATION events
  - Cooldown logic prevents over-triggering (default: 30s)
- **1 new MCP tool**: `atlas_why_assess` — manual Why Layer assessment
- **Telegram alerts enriched** with Why Layer synthesis and risk scores
- **AuditEntry extensions**: `whyTriggered`, `whyTriggerReason` fields
- Auto-tracking of audit entries for Why Layer event windows
- New source files: `why-engine.ts`, `why-triggers.ts`
- New test suites: `credential-delegation.test.ts`, `why-engine.test.ts`, `why-triggers.test.ts`
- 44 new tests (315 total, all passing)

### Changed
- Version bumped to 0.6.0 (credential delegation + Why Layer release)
- Registry save format: `{ credentials, children }` (backwards-compatible load)
- `register()` now stores agent secret key in-memory for delegation support
- Audit logger wrapped to auto-track entries for Why Layer trigger evaluation

### Security
- Delegation chain signatures provide cryptographic binding (root → child)
- Capability escalation impossible — child capabilities strictly subset of parent
- Cascade revocation ensures compromised parent revokes entire subtree
- Agent secret keys never persisted to disk — in-memory session lifetime only
- Why Layer is non-blocking: gatekeeper never fails if Ollama is down

## [0.5.0] - 2026-03-28

### Added
- **Agent Identity Attestation** — every agent must present a signed credential
  - DID-format agent IDs (`did:atlas:<uuid>`)
  - ML-DSA-65 issuer-signed credentials with SHA3-256 credential hashes
  - Per-agent ML-DSA-65 keypairs generated at registration
  - Role-based access: `claude-code`, `orchestrator`, `tool-caller`, `observer`, `admin`
  - 13 granular capabilities (`file:read`, `shell:exec`, `identity:register`, etc.)
  - Configurable TTL (default 24h) with expiry enforcement
  - Credential revocation with reason tracking
- **Identity Registry** with JSON file persistence (chmod 600)
  - Auto-save on mutation, auto-load on startup
  - Filter by: active, revoked, expired, all
  - Bootstrap guard: first-run allows through unverified (no self-lock)
- **Attestation layer** integrated before policy evaluation
  - Deny paths: `UNREGISTERED_AGENT`, `CREDENTIAL_EXPIRED`, `CREDENTIAL_REVOKED`, `CAPABILITY_MISMATCH`
  - Tool-to-capability mapping (Read→file:read, Bash→shell:exec, etc.)
  - All audit entries enriched with identity fields
- **4 new MCP tools**:
  - `atlas_identity_register` — issue a signed agent credential
  - `atlas_identity_verify` — verify an agent's credential status
  - `atlas_identity_list` — list credentials with filtering
  - `atlas_identity_revoke` — revoke a credential with reason
- **5 new identity fields** on AuditEntry (additive, no breaking changes):
  `agentId`, `identityVerified`, `credentialExpiry`, `agentRole`, `attestationDenyReason`
- New source files: `agent-identity.ts`, `identity-registry.ts`, `attestation.ts`
- New test suites: `agent-identity.test.ts`, `identity-registry.test.ts`, `attestation.test.ts`
- Key accessors on QuantumSigner: `getPublicKeyRaw()`, `getSecretKeyRaw()`

### Changed
- Version bumped to 0.5.0 (agent identity attestation release)
- Permission request handler now runs attestation before policy evaluation
- `atlas_status` reports agent registry state and session agent ID
- Telegram denial messages include agent ID for traceability

### Security
- Credentials are issuer-signed with ML-DSA-65 (post-quantum non-repudiation)
- Agent secret keys never stored in registry or exposed via MCP tools
- Registry file restricted to owner read/write (0600)
- Bootstrap guard prevents self-lock on first run while enforcing identity after first registration

## [0.4.0] - 2026-03-28

### Added
- **ML-DSA-65 post-quantum signatures** on every audit log entry (FIPS 204)
  - Keypair auto-generated on first run, stored in data directory (chmod 600)
  - Public key hash logged at session start for key pinning
  - Signatures verified during `atlas_audit_verify`
  - Designed for harvest-now-decrypt-later threat model (10-15+ year non-repudiation)
- **SHA3-256 hash chaining** replaces SHA-256 for quantum-resistant tamper detection
  - Backwards-compatible verifier handles legacy SHA-256 entries
  - `hash_algorithm` field on each entry disambiguates the chain algorithm
- **MITRE ATT&CK enrichment** on every policy decision audit entry
  - `rule_id` field captures the matched policy rule
  - `mitre` object includes technique ID, name, and tactic
  - Static lookup table covers all 65+ techniques in the default ruleset
- **Structured verification stats** from `atlas_audit_verify`:
  total entries, PQ-signed count, HMAC-signed count, legacy entry count
- New dependency: `@noble/post-quantum` (pure JS ML-DSA-65, no native bindings)
- New source files: `quantum-signer.ts`, `mitre-attack.ts`
- New test suite: `quantum-signer.test.ts` (keypair management, signing, verification, tamper detection)

### Changed
- Version bumped to 0.4.0 (quantum-hardened audit release)
- Audit log entry schema extended with `hash_algorithm`, `rule_id`, `mitre`, `pq_signature` fields
- `atlas_audit_verify` now reports verification stats (PQ signatures, HMAC, legacy entries)
- `atlas_status` now includes quantum signing status and audit hash algorithm

### Security
- ML-DSA-65 provides non-repudiation against quantum adversaries
- SHA3-256 chain is resistant to length-extension attacks (unlike SHA-256)
- Keypair file restricted to owner read/write (0600)
- Graceful degradation: if `@noble/post-quantum` is unavailable, entries are unsigned but logging continues

## [0.3.1] - 2026-03-28

### Added
- **MITRE ATT&CK tagging** on all 96 policy rules — 64 unique technique IDs
- **Kali/offensive security tool coverage** — 39 new deny rules covering:
  - Reconnaissance: nmap, masscan, zmap, nikto, gobuster, ffuf, feroxbuster, recon-ng, theHarvester, amass, subfinder
  - SMB/DNS enumeration: enum4linux, smbclient, smbmap, dnsrecon, dnsenum, fierce
  - CMS scanning: wpscan, joomscan, whatweb, droopescan
  - Exploitation frameworks: Metasploit (msfconsole, msfvenom), sqlmap, searchsploit, BeEF, XSSer
  - Brute force: Hydra, Medusa, Patator, ncrack, John the Ripper, Hashcat, ophcrack
  - Wordlist generation: CeWL, Crunch, CUPP
  - Credential dumping: Mimikatz, LaZagne, Impacket (secretsdump, wmiexec, psexec.py), CrackMapExec
  - C2 frameworks: Cobalt Strike, Sliver, Empire, Covenant, Havoc, Merlin, Mythic
  - Network poisoning/MITM: Responder, Ettercap, Bettercap, arpspoof, mitmproxy
  - AD/lateral movement: BloodHound, SharpHound, Kerbrute, Rubeus, Evil-WinRM
  - Privilege escalation enumeration: LinPEAS, WinPEAS, LinEnum, linux-exploit-suggester, pspy
  - Wireless attacks: aircrack-ng, airmon-ng, airodump-ng, wifite
  - Packet crafting: hping3, scapy, tcpreplay
  - Payload generation/evasion: Veil, Shellter, UPX packer
  - Binary exploitation: ROPgadget, pwntools, ropper
- **Anti-forensics detection** — history clearing, HISTFILE unsetting, journal log tampering, shred
- **LOLBin network channels** — /dev/tcp redirects, openssl s_client, chisel, proxychains
- **System credential file protection** — /etc/shadow, /etc/passwd read blocking
- **MITRE ID in Telegram deny notifications** — operators see the ATT&CK technique on every auto-deny
- 54 new tests (145 total, all passing)

### Changed
- Policy engine expanded from 50 to 96 rules (89 hard deny + 7 ask)
- `PolicyRule` interface now includes optional `mitre_id` field

## [0.3.0] - 2026-03-28

### Added
- **Hardened default policy engine** with 50 rules (43 hard deny + 7 ask)
  - Filesystem destruction (rm -rf, mkfs, dd, wipefs)
  - Safety bypass flags (--no-verify, --skip-verification, --insecure)
  - Network exfiltration/C2 (curl, wget, nc, scp, rsync, ftp, socat, ngrok)
  - Credential/secret theft (cat .env, .ssh, id_rsa — both Bash and Read tools)
  - Git destructive operations (force push, hard reset, clean -fd)
  - Privilege escalation (chmod 777, SUID/SGID, chown root)
  - Firewall teardown (iptables -F, ufw disable, nft flush)
  - Container escape (--privileged, --pid=host, --net=host)
  - Docker destruction (rm -f, kill, system prune)
  - Crypto mining (xmrig, cpuminer, minerd)
  - Shell obfuscation (base64 decode+exec, eval+curl)
  - Reverse shell patterns (python/perl/ruby socket)
  - Sensitive path writes (Write to /etc, .ssh, .bashrc, crontab)
- **Ask rules** for operations requiring human approval:
  - systemctl stop/disable/restart/reload
  - docker compose down/up/restart
  - Destructive SQL (DROP TABLE, TRUNCATE, DELETE FROM)
  - Package installation (npm, pip, apt)
  - git push (any)
- 52 new tests covering all hardened default rules
- Repository metadata (homepage, bugs, repository URL) in package.json
- `files` field in package.json for clean npm publishing

### Changed
- Version bumped to 0.3.0 (security-hardened release)
- Plugin manifest now references `.mcp.marketplace.json` (template variables only)

### Security
- Removed `.mcp.json` from git history (contained development credentials)
- Added `.mcp.json` and `.mcp.local.json` to `.gitignore`
- Default policy posture assumes hostile agents, not cooperative ones

## [0.2.2] - 2026-03-27

### Changed
- Synced package and plugin manifest versions
- Removed chat-only citation markup from README
- Reworked test execution: compile-first flow, no `tsx` runtime dependency
- Hardened SessionStart hook with `mkdir -p` for data directory

### Fixed
- Telegram `sendMessage()` now throws on HTTP or API failure
- `requestVerdict()` only waits if at least one prompt was delivered
- Default reply path escapes HTML; `raw_html=true` for intentional rich formatting

## [0.2.0] - 2026-03-26

### Added
- Identity Provider with DIB Briefcase integration
- 7-tier consent model (Public through Sealed)
- Sensitivity classification engine (SSN, email, DOB, diagnosis codes, MRN, crisis content)
- Consent boundary enforcement with `forbidden_tools` per tier
- Audit log field redaction (tier-driven)
- Agent authorization context
- Smuggling/obfuscation detection (base64, hex encoding, eval, pipe chains)
- PII/PHI heuristic detection (SSN, email, phone — always-on)

### Changed
- Cross-LLM review pass: tightened security and plugin conventions

## [0.1.0] - 2026-03-25

### Added
- Initial release
- Fail-closed Telegram permission relay
- Policy engine with glob-pattern rule matching
- Tamper-evident audit log with SHA-256 hash chaining
- Optional HMAC-SHA256 audit signing
- Velocity limiting (requests per minute)
- Anomaly detection (privilege escalation, sensitive access, data exfiltration, destructive git)
- Three MCP tools: `atlas_reply`, `atlas_status`, `atlas_audit_verify`
