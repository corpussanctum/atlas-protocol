# Fidelis Channel

**Fiduciary-grade agent authentication for Claude Code.**

A Claude Code Channels plugin that wraps Telegram with a security layer designed for healthcare, legal, and fiduciary AI contexts — where autonomous agent actions require verifiable, auditable human authorization.

> *Part of the [Fidelis Protocol](https://github.com/corpussanctum/fidelis-protocol) — an open standard for fiduciary AI-agent interoperability.*

---

## What it does

When Claude Code needs permission to run a tool (write a file, execute a command, access a resource), Fidelis Channel:

1. **Evaluates** the request against a configurable policy engine
2. **Auto-denies** requests matching known-dangerous patterns (fail-closed)
3. **Forwards** ambiguous requests to your Telegram with anomaly flags
4. **Waits** for your explicit `yes`/`no` verdict
5. **Auto-denies** if you don't respond within the timeout (fail-closed)
6. **Logs** every decision in a tamper-evident, HMAC-signed audit trail

You also get a full two-way Telegram channel — message Claude Code from your phone, get replies, kick off tasks while you're away.

## Why it exists

Anthropic's native Channels permission relay is a good start. But it lacks:

- **Fail-closed defaults** — native channels have no timeout-to-deny behavior
- **Policy engine** — no way to auto-block dangerous patterns before they reach you
- **Anomaly detection** — no velocity tracking, privilege escalation detection, or exfiltration alerts
- **Cryptographic audit** — no tamper-evident logging for compliance/regulatory contexts
- **Fiduciary framing** — no concept of an agent acting in a principal's best interest with verifiable authorization

Fidelis Channel adds all of these on top of the standard Channels contract.

## Quick start

### 1. Create a bot with BotFather

Open [@BotFather](https://t.me/BotFather) on Telegram and send `/newbot`. You'll get a token like `123456789:AAHfiqk...`.

### 2. Install the plugin

```
/plugin install fidelis-channel@claude-plugins-official
```

### 3. Configure

```
/fidelis:configure 123456789:AAHfiqk...
```

This saves the token to `~/.fidelis-channel/config.json`. Then add your Telegram chat ID (DM [@userinfobot](https://t.me/userinfobot) to find yours):

```
/fidelis:configure chat 123456789
```

Enable HMAC audit signing:

```
/fidelis:configure hmac generate
```

### 4. Launch with the channel flag

```bash
claude --channels plugin:fidelis-channel@claude-plugins-official
```

Or for development (before marketplace approval):

```bash
claude --dangerously-load-development-channels server:fidelis-channel
```

### 5. Message your bot

DM your bot on Telegram. Your message arrives in the Claude session. Claude can reply using the `fidelis_reply` tool.

### Manual setup (without marketplace)

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "fidelis-channel": {
      "command": "node",
      "args": ["/path/to/fidelis-channel/dist/index.js"],
      "env": {
        "FIDELIS_TELEGRAM_BOT_TOKEN": "your-token",
        "FIDELIS_TELEGRAM_CHAT_IDS": "your-chat-id"
      }
    }
  }
}
```

### Policy configuration

Create `~/.fidelis-channel/config.json` for full control:

```json
{
  "telegram_bot_token": "123456789:AAHfiqk...",
  "telegram_allowed_chat_ids": [123456789],
  "permission_timeout_seconds": 120,
  "audit_hmac_secret": "your-secret-key-here",
  "velocity_limit_per_minute": 30,
  "policy_rules": [
    {
      "tool_pattern": "Bash(rm -rf *)",
      "action": "deny",
      "reason": "Recursive force-delete blocked"
    },
    {
      "tool_pattern": "Bash(*curl*|*wget*|*nc *|*netcat*)",
      "action": "deny",
      "reason": "Network exfiltration blocked"
    },
    {
      "tool_pattern": "Read",
      "action": "allow",
      "reason": "File reads are safe"
    }
  ]
}
```

## Architecture

```
┌─────────────────┐     stdio      ┌──────────────────────────────────┐
│   Claude Code   │◄──────────────►│       Fidelis Channel (MCP)      │
│                 │                 │                                  │
│ • Tool calls    │   permission    │  ┌────────────┐                  │
│ • File edits    │───request──────►│  │  Policy     │──deny──►audit   │
│ • Bash cmds     │                 │  │  Engine     │                  │
│                 │                 │  └─────┬──────┘                  │
│                 │   verdict       │        │ask                      │
│                 │◄───────────────│  ┌─────▼──────┐   ┌──────────┐  │
│                 │                 │  │  Telegram   │◄─►│  Human   │  │
│                 │   channel msg   │  │  Bot        │   │  (you)   │  │
│                 │◄───────────────│  └─────────────┘   └──────────┘  │
│                 │                 │                                  │
│                 │                 │  ┌─────────────┐                  │
│                 │                 │  │  Audit Log  │ HMAC + chain    │
│                 │                 │  └─────────────┘                  │
└─────────────────┘                 └──────────────────────────────────┘
```

### Security model

| Layer | What it does |
|-------|-------------|
| **Policy engine** | Pattern-matched rules evaluate every request before it reaches a human. First match wins. Known-dangerous patterns are auto-denied. |
| **Anomaly detection** | Velocity tracking (requests/min), privilege escalation detection (sudo, chmod, credential access), data exfiltration patterns (curl POST, netcat). Anomaly flags are shown in the Telegram prompt. |
| **Fail-closed timeout** | If no human verdict arrives within the configured timeout (default 120s), the request is automatically DENIED. No silent approvals. |
| **Sender gating** | Only Telegram chat IDs in the allowlist can issue verdicts. All other messages are silently dropped. |
| **Audit trail** | Every decision is logged to an append-only JSONL file with SHA-256 hash chaining and optional HMAC-SHA256 signatures. |

### Policy rules

Rules are evaluated in order. First match wins. If no rule matches, the default is `ask` (forward to human).

```json
{
  "tool_pattern": "Bash(*curl*|*wget*)",
  "action": "deny",
  "reason": "Outbound network access blocked"
}
```

Pattern format: `ToolName` or `ToolName(input_glob)` where `*` matches any characters. Pipe `|` separates alternatives inside the input glob.

### Anomaly flags

The policy engine detects these patterns and surfaces them as warnings in the Telegram prompt:

- `VELOCITY_EXCEEDED` — too many permission requests per minute
- `PRIVILEGE_ESCALATION` — sudo, chmod 777, chown, passwd
- `SENSITIVE_ACCESS` — .env, .ssh, credentials, API keys
- `DATA_EXFILTRATION` — curl with POST data, netcat
- `DESTRUCTIVE_GIT` — force push, hard reset

### Audit log verification

From within a Claude Code session:

```
Use the fidelis_audit_verify tool to check the audit log integrity.
```

Or programmatically:

```typescript
import { AuditLogger } from "fidelis-channel/audit-log";
const audit = new AuditLogger(config);
const { valid, errors } = audit.verify();
```

## Tools exposed to Claude

| Tool | Description |
|------|-------------|
| `fidelis_reply` | Send a message back to the Telegram operator |
| `fidelis_audit_verify` | Verify audit log hash chain and HMAC integrity |
| `fidelis_status` | Get current gatekeeper status and configuration |

## Roadmap

- [ ] Post-quantum signatures (ML-DSA-65 via liboqs, replacing HMAC)
- [ ] DIB Vault integration (consent-tiered permission policies)
- [ ] Fiduciary score — quantified trust metric from audit history
- [ ] Multi-operator quorum (N-of-M approval for high-risk actions)
- [ ] Briefcase context injection (load operator identity into Claude session)
- [ ] Plugin marketplace submission (official Anthropic allowlist)
- [ ] WhatsApp / Signal / Slack channel support

## Fidelis Protocol

This plugin is the reference implementation of the **Fidelis Protocol** — a proposed standard for fiduciary AI-agent interoperability, analogous to SMART on FHIR for healthcare data exchange.

The core principle: **an AI agent acting on behalf of a principal must provide cryptographic proof of authorization, maintain an auditable decision trail, and default to denial when authorization is ambiguous.**

Learn more at [corpussanctum.org](https://corpussanctum.org).

## License

Apache-2.0 — Corpus Sanctum Inc.
