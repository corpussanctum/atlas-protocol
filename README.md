# Atlas Protocol

A Claude Code plugin that gates autonomous agent sessions with identity attestation, behavioral baselines, and a post-quantum audit trail — all relayed through Telegram for operator oversight.

Atlas is designed around a single assumption: **the agent might be compromised**. Every default is fail-closed. Agents must prove identity before acting. Behavioral drift is detected across sessions. And every decision is signed with ML-DSA-65 so the audit trail holds up 15 years from now.

> **Spec vs Implementation:** This README documents the reference implementation. For the normative protocol specification (conformance profiles, MUST/SHOULD requirements, DID method, delegation signing semantics), see **[SPEC.md](SPEC.md)**.

## How it works

```
              ┌─────────────────────────────────────────────────────────────────┐
              │                       Atlas Gatekeeper                         │
              │                                                                 │
  Agent ─────►│  Identity ──► Policy ──► Quiet ──► Break ──► Telegram ──► Verdict
              │  Attestation   Engine    Mode?     Glass?     Relay      Allow/ │
              │                                                          Deny  │
              │     ▼            ▼         ▼         ▼          ▼          ▼    │
              │  ┌──────────────────────────────────────────────────────────┐   │
              │  │              Quantum Audit Log (+ rotation)             │   │
              │  │   SHA3-256 chain + ML-DSA-65 sigs + ATT&CK + ID        │   │
              │  └──────────────────────────────────────────────────────────┘   │
              │                          ▼                                      │
              │                  Behavioral Baseline                            │
              │              (per-agent drift detection)                        │
              └─────────────────────────────────────────────────────────────────┘
```

When an agent requests permission to use a tool:

1. **Identity attestation** — is the agent registered? Is its credential valid, unexpired, unrevoked? Does it have the required capability?
2. **Policy engine** — 96 ordered rules evaluated against the request. 89 hard-deny rules block dangerous patterns immediately. 7 ask rules forward to the operator.
3. **Quiet mode** — if the agent is mature (200+ sessions), the request is low-risk (read-only, no anomaly flags, no sensitive paths), and quiet mode is enabled, auto-approve without Telegram.
4. **Break-glass** — if a break-glass token is active (Telegram outage), auto-approve "ask" verdicts. Hard-deny rules are never bypassed.
5. **Telegram relay** — unresolved requests go to the operator. `yes <id>` or `no <id>`. No reply = denied.
6. **Audit log** — every decision is recorded with ML-DSA-65 signatures, SHA3-256 hash chaining, MITRE ATT&CK enrichment, and agent identity binding. Auto-rotated when size threshold is exceeded.
7. **Baseline update** — the decision is ingested into the agent's persistent behavioral profile for longitudinal drift detection.

## Requirements

- Claude Code **v2.1.81+** (permission relay support)
- Node.js **>= 20.0.0**
- A Telegram bot token from [@BotFather](https://t.me/BotFather)
- At least one authorized Telegram chat ID
- Optional: [Ollama](https://ollama.com) for the Why Layer's Council of Experts

> **Note:** Channels are in research preview and require a claude.ai login. Console/API-key auth does not support them. Team and Enterprise orgs must explicitly enable channels. Custom plugins require the `--dangerously-load-development-channels` flag until Anthropic allowlists them through channel review.

## Installation

### From a marketplace

```bash
claude plugin install atlas-protocol@<marketplace>
```

Claude Code prompts for the Telegram bot token, allowed chat IDs, and optional HMAC secret through the `userConfig` mechanism.

### Local development

```bash
git clone https://github.com/corpussanctum/atlas-protocol.git
cd atlas-protocol
npm install && npm run build
claude --plugin-dir ./atlas-protocol
```

## Configuration

Atlas reads configuration from environment variables, a config file (`config.json` in the data directory), and built-in defaults — in that priority order.

### Required

| Variable | Description |
|---|---|
| `ATLAS_TELEGRAM_BOT_TOKEN` | Telegram bot token from @BotFather |
| `ATLAS_TELEGRAM_CHAT_IDS` | Comma-separated authorized Telegram chat IDs |

### Optional

| Variable | Default | Description |
|---|---|---|
| `ATLAS_PERMISSION_TIMEOUT` | `120` | Seconds before fail-closed denial |
| `ATLAS_HMAC_SECRET` | — | HMAC-SHA256 secret for audit log signing |
| `ATLAS_AUDIT_LOG_PATH` | `<data_dir>/audit.jsonl` | Audit log location |
| `ATLAS_DATA_DIR` | `${CLAUDE_PLUGIN_DATA}` or `~/.atlas-protocol` | Persistent state directory |
| `ATLAS_BRIEFCASE_PATH` | — | Path to a DIB Briefcase for consent-tier enforcement |
| `ATLAS_PRIVACY_MODE` | `false` | Force audit field redaction |
| `ATLAS_VELOCITY_LIMIT` | `30` | Requests per minute before anomaly flag |
| `ATLAS_POLL_INTERVAL_MS` | `1000` | Telegram polling interval |
| `WHY_ENGINE_MODEL` | `qwen2.5:3b` | Ollama model for Why Layer experts |
| `WHY_ENGINE_BASE_URL` | `http://localhost:11434` | Ollama API endpoint |
| `WHY_ENGINE_WINDOW_SIZE` | `50` | Max audit entries in assessment window |
| `WHY_ENGINE_WINDOW_MINUTES` | `30` | Time window for assessment |
| `ATLAS_QUIET_MODE` | `false` | Enable quiet mode for mature agents |
| `ATLAS_QUIET_MIN_MATURITY` | `mature` | Minimum maturity for quiet mode (`established` or `mature`) |
| `ATLAS_QUIET_TOOLS` | `Read,Glob,Grep` | Comma-separated tools eligible for quiet mode |
| `ATLAS_QUIET_MAX_FLAGS` | `0` | Maximum anomaly flags allowed for quiet approval |
| `ATLAS_AUDIT_MAX_SIZE_MB` | `10` | Audit log size before auto-rotation (MB) |
| `ATLAS_AUDIT_MAX_ARCHIVES` | `0` | Maximum archived log files to keep (0 = unlimited) |
| `ATLAS_BOOTSTRAP_SKIP_CONFIRM` | `false` | Skip bootstrap two-channel confirmation (dev/testing only) |

## Agent identity

Every agent that passes through the gatekeeper must present a signed identity credential. Credentials use the DID format `did:atlas:<uuid>` and are signed by the gatekeeper's ML-DSA-65 issuer key.

### Roles and capabilities

| Role | Typical use |
|---|---|
| `claude-code` | Primary Claude Code session |
| `orchestrator` | Multi-agent coordinator (can delegate) |
| `tool-caller` | Single-purpose tool executor |
| `observer` | Read-only monitoring agent |
| `admin` | Operator-level (can register/revoke) |

13 granular capabilities control what each agent can do: `file:read`, `file:write`, `file:delete`, `shell:exec`, `shell:read`, `network:outbound`, `network:inbound`, `process:spawn`, `process:kill`, `credential:read`, `audit:read`, `identity:register`, `identity:revoke`.

### Credential delegation

Orchestrator agents can issue scoped sub-credentials to child agents. Delegation is constrained:

- Child capabilities must be a **strict subset** of the parent's
- Child TTL is automatically **capped** at the parent's remaining lifetime
- Maximum delegation depth: **3**
- Chain signatures (ML-DSA-65) bind root -> parent -> child cryptographically
- **Cascade revocation** — revoking a parent revokes all descendants

### Bootstrap guard

On first run (empty registry), Atlas allows requests through unverified so the system is not self-locking. The first credential registration requires **two-channel confirmation**: a 6-character code is printed to the server console and must be sent via Telegram by the operator. This proves physical host access + Telegram access simultaneously, preventing a compromised agent from registering a malicious admin credential during the bootstrap window.

Once the first credential is registered, identity enforcement activates. Set `ATLAS_BOOTSTRAP_SKIP_CONFIRM=true` to bypass confirmation in dev/testing environments.

## Policy engine

The default ruleset contains **96 ordered rules** (89 deny + 7 ask) evaluated on every request. First match wins.

### Hard deny (89 rules, no human override)

| Category | Examples |
|---|---|
| Filesystem destruction | `rm -rf`, `mkfs`, `wipefs`, `dd`, block device writes, `shred` |
| Safety bypass flags | `--no-verify`, `--skip-verification`, `--insecure` |
| Network exfiltration | `curl`, `wget`, `nc`, `scp`, `rsync`, `ngrok`, tunnels, `/dev/tcp` |
| Credential theft | `cat .env`, `.ssh/id_rsa`, `/etc/shadow` — both Bash and Read tools |
| Git destructive | `push --force`, `reset --hard`, `clean -fd`, `checkout -- .` |
| Privilege escalation | `chmod 777`, SUID/SGID, `chown root` |
| Firewall teardown | `iptables -F`, `ufw disable`, `nft flush` |
| Container escape | `--privileged`, `--pid=host`, `docker system prune` |
| Crypto mining | `xmrig`, `cpuminer`, `minerd` |
| Shell obfuscation | base64 decode + exec, `eval` + `curl`, reverse shells |
| Sensitive path writes | Write to `/etc`, `.ssh`, `.bashrc`, `crontab` |
| Anti-forensics | `history -c`, HISTFILE tampering, journal deletion |
| Offensive tools | nmap, Metasploit, sqlmap, Hydra, Mimikatz, BloodHound, Cobalt Strike, and 30+ more |

### Ask (7 rules, forwarded to operator)

| Category | Pattern |
|---|---|
| Service lifecycle | `systemctl stop/disable/restart/reload` |
| Docker compose | `compose down/rm`, `compose up/restart` |
| Destructive SQL | `DROP TABLE`, `TRUNCATE`, `DELETE FROM` |
| Package install | `npm install`, `pip install`, `apt install` |
| Git push | Any `git push` |

### Anomaly detection (always-on)

Every request is scanned for velocity spikes, PII patterns (SSN, email, phone), obfuscation (base64, hex, eval, pipe chains), and data exfiltration indicators. Anomaly flags attach to the audit entry and appear in Telegram prompts.

### Policy regression testing

Run `atlas_test_policy` via MCP to validate all 96 rules against 120+ known malicious/benign fixtures. This should be run after any policy rule changes to catch regressions.

```bash
# From tests:
npm test

# From a Claude Code session:
# Call atlas_test_policy (verbose: true for full report)
```

## Break-glass mechanism

When Telegram is unreachable or expected to become unavailable, operators can activate a break-glass token that auto-approves "ask" verdicts without Telegram. This addresses the Telegram single-point-of-failure concern.

**Security properties:**
- Hard-deny rules are **never** bypassed — only "ask" verdicts
- Token is time-limited (default: 1 hour, max: 4 hours)
- Activation requires Telegram confirmation (or falls back to console-only when Telegram is already down)
- Optional `max_requests` limit to cap auto-approved requests
- All break-glass actions are prominently logged in the audit trail
- Token stored at `<data_dir>/break-glass.token` (mode 0600)

```
# Activate via MCP tool:
atlas_break_glass_activate(reason: "Telegram API outage", ttl_minutes: 60)

# Check status:
atlas_break_glass_status()

# Revoke early:
atlas_break_glass_revoke()
```

## Quiet mode

For mature agents (200+ sessions) performing low-risk actions, quiet mode auto-approves requests without Telegram involvement — reducing noise while maintaining full audit trail coverage.

**Eligibility requirements (all must be met):**
- `ATLAS_QUIET_MODE=true` (off by default)
- Agent baseline maturity >= configured threshold (default: `mature` / 200+ sessions)
- Agent identity verified
- Tool is in the quiet-eligible set (default: `Read`, `Glob`, `Grep`)
- Zero anomaly flags on the request
- No sensitivity classification matches
- Input does not match any sensitive path pattern (`.env`, `.ssh`, `/etc/`, credentials, keys, tokens, `.pem`, `.key`, etc.)

Non-eligible requests always go through the normal Telegram or break-glass flow.

## Why Layer (Council of Experts)

When triggered, a Council of 3 expert agents analyzes the recent audit window:

| Expert | Focus |
|---|---|
| **Anomaly Detector** | Frequency spikes, policy violations, unusual capability usage, baseline deviations |
| **Intent Inferencer** | Infers agent intent from the action sequence (allowed vs. denied paths) |
| **Threat Narrator** | Maps behaviors to MITRE ATT&CK tactics, writes an incident brief |

Experts run in parallel via Ollama (local-first, privacy-preserving). Each produces an independent risk score and signal list. The synthesizer combines them into an overall assessment with a recommended action (allow / monitor / escalate / block).

### Triggers

The Why Layer fires automatically on:

| Trigger | Condition |
|---|---|
| `DENY_THRESHOLD` | 3+ denies in the recent window |
| `HITL_ESCALATION` | Human approve or deny event |
| `HIGH_RISK_TECHNIQUE` | MITRE tactic is Credential Access, Exfiltration, C2, or Defense Evasion |
| `IDENTITY_ANOMALY` | Unregistered agent or expired credential |
| `CASCADE_REVOCATION` | Cascade revoke event |
| `BASELINE_DRIFT` | Behavioral drift detected against longitudinal baseline |
| `MANUAL` | Operator invokes `atlas_why_assess` |

A 30-second cooldown (configurable) prevents over-triggering. If Ollama is unavailable, the Why Layer returns a nominal stub — it never blocks the gatekeeper.

## Behavioral baselines

Each agent accumulates a persistent behavioral profile across sessions. Profiles are stored as JSON files (one per agent, chmod 600) and contain derived statistics only — no raw audit data.

### 8 behavioral dimensions

- **Risk distribution** — min, max, mean, p50, p75, p95, p99, stddev across all sessions
- **Technique frequencies** — per MITRE technique counts with first/last seen and trend
- **Capability usage** — per-capability allow/deny/ask counts and deny ratios
- **Temporal patterns** — hourly and daily activity distributions, session duration stats
- **Delegation profile** — delegations issued/received, max depth used, cascade revocations
- **Why Layer history** — last 100 assessments with risk scores and trigger reasons
- **Thresholds** — auto-calculated from the profile (mean + 2σ upper bound, mean + 3σ critical)
- **Maturity level** — insufficient (<10 sessions), developing (10-49), established (50-199), mature (200+)

### Drift detection

5 drift dimensions are checked when the Why Layer fires:

| Signal | Fires when |
|---|---|
| `RISK_SCORE_ELEVATED` | Current risk exceeds baseline threshold (upper = high, critical = critical) |
| `NEW_TECHNIQUE_OBSERVED` | MITRE technique not seen in baseline history |
| `CAPABILITY_DENY_SPIKE` | Deny ratio for a capability is >2x baseline and >50% absolute |
| `TEMPORAL_ANOMALY` | Activity at an hour with <5% historical share |
| `VOLUME_SPIKE` | Event count >2x the baseline average per session |

Drift signals are included in the Why Layer assessment, enriched into the audit entry, and surfaced in Telegram alerts.

## MCP tools

Atlas exposes 20 MCP tools to the Claude Code session:

### Core

| Tool | Description |
|---|---|
| `atlas_reply` | Send a message to the operator via Telegram |
| `atlas_audit_verify` | Verify audit log integrity (SHA3-256 chain + HMAC + ML-DSA-65) |
| `atlas_status` | Runtime status: Telegram, identity, policy, audit, quiet mode, break-glass, baselines |

### Identity management

| Tool | Description |
|---|---|
| `atlas_identity_register` | Issue a signed agent credential (bootstrap requires two-channel confirmation) |
| `atlas_identity_verify` | Verify a credential by agentId |
| `atlas_identity_list` | List credentials (filter: active, revoked, expired, delegated, all) |
| `atlas_identity_revoke` | Revoke a credential |

### Credential delegation

| Tool | Description |
|---|---|
| `atlas_identity_delegate` | Issue a scoped child credential from a parent |
| `atlas_identity_cascade_revoke` | Revoke a parent and all its descendants |
| `atlas_identity_tree` | View the credential delegation hierarchy |

### Why Layer and baselines

| Tool | Description |
|---|---|
| `atlas_why_assess` | Manually trigger a Council of Experts assessment |
| `atlas_baseline_get` | Retrieve the full behavioral profile for an agent |
| `atlas_baseline_drift` | Run drift detection against the current audit window |
| `atlas_baseline_list` | List baseline profiles with maturity/role filters |

### Policy testing

| Tool | Description |
|---|---|
| `atlas_test_policy` | Run 120+ regression fixtures against current policy rules |

### Break-glass

| Tool | Description |
|---|---|
| `atlas_break_glass_activate` | Activate emergency Telegram bypass (time-limited, ask-only) |
| `atlas_break_glass_status` | Check break-glass token status |
| `atlas_break_glass_revoke` | Revoke break-glass token, restore normal flow |

### Audit rotation

| Tool | Description |
|---|---|
| `atlas_audit_rotate` | Manually trigger audit log rotation |
| `atlas_audit_archives` | List or verify archived audit log files |

## Skills

Three slash commands are available inside a Claude Code session:

| Skill | Description |
|---|---|
| `/atlas:status` | Show configuration, policy rule counts, and audit log stats |
| `/atlas:audit` | Inspect the audit trail — verify, view recent entries, export |
| `/atlas:configure` | Set up or modify bot token, chat IDs, and HMAC secret |

## Audit log

The audit log is append-only JSONL with three layers of integrity protection:

1. **SHA3-256 hash chaining** — tamper-evident, quantum-resistant, resistant to length-extension attacks
2. **ML-DSA-65 post-quantum signatures** (FIPS 204) — non-repudiation holds against harvest-now-decrypt-later adversaries 10-15+ years forward
3. **HMAC-SHA256 classical signatures** (optional) — backwards compatibility layer

### Rotation

When the audit log exceeds the configured size threshold (default: 10MB), it is automatically archived to `<data_dir>/audit-archive/audit-YYYYMMDD-HHMMSS.jsonl`. A rotation manifest tracks each archived file's SHA3-256 file hash and chain anchor, enabling integrity verification across the full archive.

Configure with `ATLAS_AUDIT_MAX_SIZE_MB` and `ATLAS_AUDIT_MAX_ARCHIVES` (pruning).

### Entry schema

| Field | Description |
|---|---|
| `id` | UUID |
| `timestamp` | ISO 8601 |
| `event` | Event type |
| `rule_id` | Matched policy rule pattern |
| `mitre` | ATT&CK enrichment: `{ id, name, tactic }` |
| `agentId` | DID of the attested agent |
| `identityVerified` | Whether the agent's credential was verified |
| `agentRole` | Agent's declared role |
| `attestationDenyReason` | Why attestation was denied (if applicable) |
| `whyTriggered` | Whether the Why Layer fired for this entry |
| `whyTriggerReason` | The trigger type |
| `hash_algorithm` | `"sha3-256"` |
| `prev_hash` | SHA3-256 of previous log line |
| `hmac` | HMAC-SHA256 signature (if configured) |
| `pq_signature` | ML-DSA-65 signature, base64-encoded |

### Key management

The ML-DSA-65 signing keypair is auto-generated on first run and stored at `<data_dir>/quantum-keypair.json` (mode 0600). The public key hash is logged in `SESSION_START` for key pinning. The same key serves as the credential issuer for agent identity.

## Identity and Briefcase integration

If `ATLAS_BRIEFCASE_PATH` points to a [DIB Briefcase](https://github.com/corpussanctum/dib) directory, Atlas loads a 7-tier consent model (Public through Sealed / 42 CFR Part 2). The policy engine enforces consent boundaries and redacts sensitive fields in audit entries. A sample Briefcase is included in `sample-briefcase/`.

This is an optional hardening layer. Atlas works fully without it.

## Architecture

```
src/
├── index.ts               # MCP server, 20 tools, permission handler (5-step pipeline)
├── config.ts              # Configuration loader + 96 default rules
├── policy-engine.ts       # 96 rules, anomaly detection, velocity tracking
├── policy-test-runner.ts  # Runtime regression test fixtures + runner
├── audit-log.ts           # SHA3-256 chain + ML-DSA-65 + HMAC + identity fields
├── audit-rotation.ts      # Size-based log rotation with integrity manifest
├── quantum-signer.ts      # ML-DSA-65 keypair management, signing, verification
├── agent-identity.ts      # Credential types, issuance, verification, delegation
├── identity-registry.ts   # In-memory registry with JSON persistence
├── attestation.ts         # Identity attestation + audit enrichment
├── why-engine.ts          # Council of Experts (3 parallel agents via Ollama)
├── why-triggers.ts        # Auto-trigger logic + Telegram alert formatting
├── baseline-types.ts      # Behavioral profile types, drift signals, maturity model
├── baseline-store.ts      # Per-agent JSON file persistence (atomic writes)
├── baseline-engine.ts     # Profile calculation, drift detection, ingestion
├── break-glass.ts         # Emergency Telegram bypass (time-limited tokens)
├── quiet-mode.ts          # Auto-approve low-risk actions for mature agents
├── mitre-attack.ts        # ATT&CK technique → name + tactic lookup (65+ entries)
├── identity-provider.ts   # DIB Briefcase integration (consent tiers)
└── telegram.ts            # Telegram Bot API client (native fetch, long-polling)
```

**Dependencies**: `@modelcontextprotocol/sdk`, `zod`, `@noble/post-quantum`. No HTTP library — Telegram and Ollama use Node's native `fetch`.

## Testing

```bash
npm run build && npm test
```

575 tests across 18 test suites covering policy rules, policy regression fixtures, audit integrity, audit rotation, quantum signing, identity lifecycle, credential delegation, attestation flow, Why Layer reasoning, trigger logic, baseline calculation, drift detection, break-glass mechanism, quiet mode eligibility, and configuration loading.

## Limitations

- This is a security tool, not a compliance certification. It does not replace local review of high-risk actions, legal counsel, or organizational security policy.
- The Telegram relay depends on Telegram's availability. The **break-glass mechanism** provides an emergency bypass when Telegram is unreachable (auto-deny remains the default without it).
- The policy engine uses glob patterns and string matching, not semantic analysis. Known false positives exist (e.g., `TRUNCATE` matching the `ncat` network tool pattern). Defense in depth applies.
- The Why Layer requires a running Ollama instance. Without it, the layer returns nominal stubs — it never blocks the gatekeeper.
- Behavioral baselines need ~10 sessions before drift detection produces meaningful signals (maturity model handles this).
- Agent secret keys are held in-memory only for delegation support — they do not survive process restarts.
- Quiet mode requires explicit opt-in (`ATLAS_QUIET_MODE=true`) and only affects read-only tools for mature agents.

## License

[Apache 2.0](LICENSE)

---

Built by [Corpus Sanctum](https://github.com/corpussanctum) for operator oversight of autonomous AI agents.
