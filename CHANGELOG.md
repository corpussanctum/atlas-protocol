# Changelog

All notable changes to Atlas Protocol are documented in this file.

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
