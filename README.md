# Fidelis Channel

A Claude Code plugin that relays tool-approval prompts to Telegram, enforces 96 hardened security rules locally, and records every decision in a quantum-resistant, tamper-evident audit log.

Fidelis is designed around a single assumption: **the agent might be compromised**. Every default is fail-closed — no token means no approvals, no chat ID means no inbound messages, and timeouts always deny.

## How it works

```
Claude Code ──► Policy Engine ──► Telegram (operator) ──► Approve / Deny
                   │                                            │
                   ├── auto-deny (43 rules)                     │
                   ├── auto-allow (if configured)               │
                   └── ask ──────────────────────────────────────┘
                                                                │
                                                          Audit Log
                                       (SHA3-256 chain + ML-DSA-65 + HMAC)
```

When Claude Code requests permission to run a tool:

1. The **policy engine** evaluates the request against 50 ordered rules
2. **43 hard-deny rules** block dangerous patterns immediately — filesystem destruction, credential theft, network exfiltration, privilege escalation, reverse shells, and more
3. **7 ask rules** forward to Telegram for human approval — service lifecycle, git push, destructive SQL, package installs
4. The operator replies `yes <id>` or `no <id>` in Telegram
5. If no reply arrives before the timeout, the request is **denied**
6. Every decision is recorded in an append-only, hash-chained audit log

Fidelis also acts as a **two-way chat bridge**: authorized Telegram messages are forwarded into the Claude Code session, and Claude can reply using the `fidelis_reply` tool.

## Requirements

- Claude Code **v2.1.81+** (permission relay support)
- Node.js **>= 20.0.0**
- A Telegram bot token from [@BotFather](https://t.me/BotFather)
- At least one authorized Telegram chat ID

> **Note:** Channels are in research preview and require a claude.ai login. Console/API-key auth does not support them. Team and Enterprise orgs must explicitly enable channels. Custom plugins require the `--dangerously-load-development-channels` flag until Anthropic allowlists them through channel review.

## Installation

### From a marketplace

```bash
claude plugin install fidelis-channel@<marketplace>
```

When you enable the plugin, Claude Code prompts for the Telegram bot token, allowed chat IDs, and optional audit HMAC secret through the `userConfig` mechanism.

### Local development

```bash
git clone https://github.com/corpussanctum/fidelis-channel.git
cd fidelis-channel
npm install && npm run build
claude --plugin-dir ./fidelis-channel
```

For channel testing during the research preview:

```bash
claude --dangerously-load-development-channels plugin:fidelis-channel@<marketplace> \
       --channels plugin:fidelis-channel@<marketplace>
```

## Configuration

Fidelis reads configuration from three sources, in order of priority:

1. **Environment variables** (highest priority)
2. **Config file** (`config.json` in the data directory)
3. **Built-in defaults**

### Required

| Variable | Description |
|---|---|
| `FIDELIS_TELEGRAM_BOT_TOKEN` | Telegram bot token from @BotFather |
| `FIDELIS_TELEGRAM_CHAT_IDS` | Comma-separated authorized Telegram chat IDs |

### Optional

| Variable | Default | Description |
|---|---|---|
| `FIDELIS_PERMISSION_TIMEOUT` | `120` | Seconds before fail-closed denial |
| `FIDELIS_HMAC_SECRET` | — | HMAC-SHA256 secret for audit log signing |
| `FIDELIS_AUDIT_LOG_PATH` | `<data_dir>/audit.jsonl` | Audit log location |
| `FIDELIS_DATA_DIR` | `${CLAUDE_PLUGIN_DATA}` or `~/.fidelis-channel` | Persistent state directory |
| `FIDELIS_BRIEFCASE_PATH` | — | Path to a DIB Briefcase for identity-aware consent |
| `FIDELIS_PRIVACY_MODE` | `false` | Force audit field redaction |
| `FIDELIS_VELOCITY_LIMIT` | `30` | Requests per minute before anomaly flag |
| `FIDELIS_POLL_INTERVAL_MS` | `1000` | Telegram polling interval |

## Policy engine

The default ruleset contains **50 ordered rules** evaluated on every tool request. First match wins.

### Hard deny (43 rules, no human override)

| Category | Examples |
|---|---|
| Filesystem destruction | `rm -rf`, `mkfs`, `wipefs`, `dd`, block device writes |
| Safety bypass flags | `--no-verify`, `--skip-verification`, `--insecure` |
| Network exfiltration | `curl`, `wget`, `nc`, `scp`, `rsync`, `ngrok`, tunnels |
| Credential theft | `cat .env`, `.ssh/id_rsa`, `.gnupg` — both Bash and Read tools |
| Git destructive | `push --force`, `reset --hard`, `clean -fd` |
| Privilege escalation | `chmod 777`, SUID/SGID, `chown root` |
| Firewall teardown | `iptables -F`, `ufw disable`, `nft flush` |
| Container escape | `--privileged`, `--pid=host`, `--net=host` |
| Crypto mining | `xmrig`, `cpuminer`, `minerd` |
| Shell obfuscation | base64 decode + exec, `eval` + `curl`, reverse shells |
| Sensitive path writes | Write to `/etc`, `.ssh`, `.bashrc`, `crontab` |

### Ask (7 rules, forwarded to operator)

| Category | Pattern |
|---|---|
| Service lifecycle | `systemctl stop/disable/restart/reload` |
| Docker compose | `compose down/rm`, `compose up/restart` |
| Destructive SQL | `DROP TABLE`, `TRUNCATE`, `DELETE FROM` |
| Package install | `npm install`, `pip install`, `apt install` |
| Git push | Any `git push` |

### Anomaly detection (always-on)

On top of the rule engine, every request is scanned for:

- **Velocity spikes** — more than 30 requests/minute
- **PII patterns** — SSN, email, phone numbers
- **Obfuscation** — base64/hex encoding, `eval`, 3+ pipe chains
- **Exfiltration** — `curl -d`, `wget --post`, netcat

Anomaly flags are attached to the audit entry and included in Telegram prompts.

## Tools

Fidelis exposes three MCP tools to the Claude Code session:

| Tool | Description |
|---|---|
| `fidelis_reply` | Send a message to the operator. Targets the most recent authorized chat by default. Pass `broadcast=true` to send to all authorized chats, or `chat_id` to target a specific one. HTML is escaped unless `raw_html=true`. |
| `fidelis_audit_verify` | Verify the audit log's SHA3-256 hash chain, HMAC signatures, and ML-DSA-65 post-quantum signatures. Returns verification stats. |
| `fidelis_status` | Return a runtime snapshot: Telegram connection state, quantum signing status, policy rule count, audit settings, identity context, and pending verdicts. |

## Skills

Three slash commands are available inside a Claude Code session:

| Skill | Description |
|---|---|
| `/fidelis:status` | Show configuration, policy rule counts, and audit log stats |
| `/fidelis:audit` | Inspect the audit trail — verify, view recent entries, export |
| `/fidelis:configure` | Set up or modify bot token, chat IDs, and HMAC secret |

## Audit log

The audit log is append-only JSONL with three layers of integrity protection:

1. **SHA3-256 hash chaining** — each line contains the hash of the previous line, forming a tamper-evident chain. SHA3-256 is resistant to length-extension attacks and provides quantum-resistant hash integrity.

2. **ML-DSA-65 post-quantum signatures** (FIPS 204) — every entry is signed with a per-instance ML-DSA-65 keypair. This ensures non-repudiation holds against harvest-now-decrypt-later adversaries who may challenge the audit trail 10-15+ years in the future.

3. **HMAC-SHA256 classical signatures** (optional) — if `FIDELIS_HMAC_SECRET` is configured, entries are also signed with a classical HMAC for backwards compatibility.

### Structured entry schema

Each audit entry includes:

| Field | Description |
|---|---|
| `id` | UUID |
| `timestamp` | ISO 8601 |
| `event` | Event type (see below) |
| `rule_id` | Matched policy rule pattern |
| `mitre` | ATT&CK enrichment: `{ id, name, tactic }` |
| `hash_algorithm` | `"sha3-256"` (absent on legacy entries) |
| `prev_hash` | SHA3-256 of previous log line |
| `hmac` | HMAC-SHA256 signature (if configured) |
| `pq_signature` | ML-DSA-65 signature, base64-encoded |

### Event types

| Event | Meaning |
|---|---|
| `POLICY_DENY` | Blocked by a local policy rule |
| `POLICY_ALLOW` | Allowed by a local policy rule |
| `HUMAN_APPROVE` | Operator approved in Telegram |
| `HUMAN_DENY` | Operator denied in Telegram |
| `TIMEOUT_DENY` | No response before timeout — denied by default |
| `ANOMALY_DETECTED` | Anomaly flags raised on the request |
| `IDENTITY_LOADED` | Briefcase identity context loaded |

The distinction between `HUMAN_DENY` and `TIMEOUT_DENY` matters for auditing whether a denial was an active decision or a fail-closed default.

### Key management

The ML-DSA-65 signing keypair is auto-generated on first run and stored at `<data_dir>/quantum-keypair.json` (mode 0600). The public key hash is logged in the `SESSION_START` audit entry for key pinning. To verify logs from a different instance, load the public key from the originating keypair file.

## Identity and Briefcase integration

If `FIDELIS_BRIEFCASE_PATH` points to a [DIB Briefcase](https://github.com/corpussanctum/dib) directory, Fidelis loads a 7-tier consent model:

1. **Public** — name, role, public profile
2. **Operational** — work context, projects
3. **Clinical** — treatment context
4. **Protected** — PHI, PII, diagnosis codes
5. **Restricted** — trauma, crisis, substance use
6. **Confidential** — legal, forensic, court records
7. **Sealed** — special legal protection (42 CFR Part 2)

With a Briefcase loaded, the policy engine enforces consent boundaries — auto-denying tools forbidden at the active consent tier and redacting sensitive fields in audit entries. A sample Briefcase is included in `sample-briefcase/` for reference.

This is an optional hardening layer. Fidelis works fully without it.

## Architecture

```
src/
├── index.ts               # MCP server entry point + permission handler
├── policy-engine.ts       # Rule evaluation, anomaly detection, velocity tracking
├── audit-log.ts           # Append-only JSONL with SHA3-256 chain + ML-DSA-65 + HMAC
├── quantum-signer.ts      # ML-DSA-65 keypair management, signing, verification
├── mitre-attack.ts        # ATT&CK technique → name + tactic lookup table
├── identity-provider.ts   # DIB Briefcase integration (consent tiers)
├── telegram.ts            # Telegram Bot API client (native fetch, long-polling)
└── config.ts              # Configuration loader + 96 default rules
```

**Dependencies are minimal by design**: `@modelcontextprotocol/sdk`, `zod`, and `@noble/post-quantum` (pure JS ML-DSA-65, no native bindings). The Telegram client uses Node's native `fetch` — no HTTP library needed.

## Testing

```bash
npm run build && npm test
```

The test suite covers all 50 policy rules, audit log integrity verification, Briefcase parsing, consent tier enforcement, anomaly detection, and configuration loading.

## Limitations

- This is a security tool, not a compliance certification. It does not replace local review of high-risk actions, legal counsel, or organizational security policy.
- The Telegram relay depends on Telegram's availability. If Telegram is unreachable, all forwarded requests time out and are denied.
- The policy engine uses glob patterns and string matching, not semantic analysis. A sufficiently creative prompt injection could craft tool arguments that evade pattern-based rules. Defense in depth applies.
- Briefcase integration is one-directional: Fidelis reads the Briefcase but does not write to it.

## License

[Apache 2.0](LICENSE)

---

Built by [Corpus Sanctum](https://github.com/corpussanctum) for operator oversight of autonomous AI agents.
