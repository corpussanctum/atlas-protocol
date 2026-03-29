---
name: status
description: Show Atlas Protocol status — connection state, policy summary, audit stats, recent decisions. Use when the user asks "is atlas running", "what's the gatekeeper status", or wants a security overview.
user-invocable: true
allowed-tools:
  - Read
  - Bash(wc *)
  - Bash(tail *)
  - Bash(ls *)
---

# /atlas:status — Atlas Protocol Status

Shows the current state of the Atlas Protocol security layer.

Arguments passed: `$ARGUMENTS`

---

## What to show

### 1. Configuration

Read `~/.atlas-protocol/config.json`:
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

Read `~/.atlas-protocol/audit.jsonl`:
- File exists: yes/no
- Entry count: `wc -l`
- File size
- Last 5 entries: show timestamp, event type, and verdict (if applicable)
- Chain integrity: note that user can verify with `atlas_audit_verify` tool

### 4. Active session

If the user has the `atlas_status` MCP tool available, suggest using it for
live runtime info (pending verdicts, velocity count).

---

## Format

Use a clean summary format:

```
Atlas Protocol Status
━━━━━━━━━━━━━━━━━━━━━━
Telegram:    configured (bot ID: 865872415...)
Allowed:     1 chat (123456789)
HMAC:        enabled
Timeout:     120s (fail-closed)
Policy:      3 deny, 7 allow, 2 ask
Audit:       142 entries, 48 KB, chain intact
```
