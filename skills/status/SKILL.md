---
name: status
description: Show Fidelis Channel status — connection state, policy summary, audit stats, recent decisions. Use when the user asks "is fidelis running", "what's the gatekeeper status", or wants a security overview.
user-invocable: true
allowed-tools:
  - Read
  - Bash(wc *)
  - Bash(tail *)
  - Bash(ls *)
---

# /fidelis:status — Fidelis Channel Status

Shows the current state of the Fidelis Channel security layer.

Arguments passed: `$ARGUMENTS`

---

## What to show

### 1. Configuration

Read `~/.fidelis-channel/config.json`:
- Telegram bot: configured/not configured
- Allowed chat IDs: list them
- HMAC signing: enabled/disabled
- Permission timeout: N seconds (fail-closed)
- Velocity limit: N requests/minute

### 2. Policy rules

Count by action type:
- **Deny rules** (auto-block): list patterns and reasons
- **Allow rules** (auto-pass): list patterns
- **Ask rules** (forward to human): list if any explicit ones exist
- Note: anything not matching a rule defaults to "ask"

### 3. Audit log

Read `~/.fidelis-channel/audit.jsonl`:
- File exists: yes/no
- Entry count: `wc -l`
- File size
- Last 5 entries: show timestamp, event type, and verdict (if applicable)
- Chain integrity: note that user can verify with `fidelis_audit_verify` tool

### 4. Active session

If the user has the `fidelis_status` MCP tool available, suggest using it for
live runtime info (pending verdicts, velocity count).

---

## Format

Use a clean summary format:

```
Fidelis Channel Status
━━━━━━━━━━━━━━━━━━━━━━
Telegram:    configured (bot ID: 865872415...)
Allowed:     1 chat (123456789)
HMAC:        enabled
Timeout:     120s (fail-closed)
Policy:      3 deny, 7 allow, 2 ask
Audit:       142 entries, 48 KB, chain intact
```
