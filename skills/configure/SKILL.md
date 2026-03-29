---
name: configure
description: Set up Atlas Protocol — save Telegram bot token, set HMAC secret, review policy rules. Use when the user pastes a bot token, asks to configure Atlas, or wants to check channel status.
user-invocable: true
allowed-tools:
  - Read
  - Write
  - Bash(ls *)
  - Bash(mkdir *)
  - Bash(chmod *)
---

# /atlas:configure — Atlas Protocol Setup

Writes configuration to `~/.atlas-protocol/config.json` and orients the user
on security policy. The MCP server reads config at boot.

Arguments passed: `$ARGUMENTS`

---

## Dispatch on arguments

### No args — status and guidance

Read both config files and give the user a complete picture:

1. **Token** — check `~/.atlas-protocol/config.json` for `telegram_bot_token`.
   Show set/not-set; if set, show first 10 chars masked (`865872415:...`).

2. **HMAC** — check for `audit_hmac_secret`. Show enabled/disabled.

3. **Policy rules** — count and summarize: how many deny, how many allow, how
   many ask. Show the deny rules explicitly (they're the safety net).

4. **Timeout** — show `permission_timeout_seconds` and note that timeout = deny
   (fail-closed).

5. **Allowed chats** — list chat IDs. If empty, warn that no one can issue verdicts.

6. **Audit log** — check if `~/.atlas-protocol/audit.jsonl` exists, show entry
   count and file size.

7. **What next** — end with a concrete next step:
   - No token → *"Run `/atlas:configure <token>` with the token from BotFather."*
   - Token set, no chat IDs → *"Add your chat ID: `/atlas:configure chat <id>`"*
   - Everything configured → *"Ready. Launch with `claude --dangerously-load-development-channels server:atlas-protocol`"*

### `<token>` — save bot token

1. Treat `$ARGUMENTS` as the token (trim whitespace). BotFather tokens look
   like `123456789:AAH...` — numeric prefix, colon, long string.
2. `mkdir -p ~/.atlas-protocol`
3. Read existing `config.json` if present; update `telegram_bot_token`, preserve
   other keys. Write back.
4. Confirm, then show the no-args status.

### `chat <id>` — add allowed chat ID

1. Parse numeric chat ID from `$ARGUMENTS`.
2. Add to `telegram_allowed_chat_ids` array in config.json (dedup).
3. Confirm and show updated allowlist.

### `hmac <secret>` — set HMAC signing secret

1. Write `audit_hmac_secret` to config.json.
2. Note: existing audit entries signed with old secret will fail verification.

### `hmac generate` — generate a random HMAC secret

1. Generate 32 random hex bytes.
2. Write to config.json.
3. Show the secret once (user should save it).

### `clear` — remove all configuration

Delete config.json. Confirm this is irreversible.

---

## Implementation notes

- Config dir might not exist on first run. Missing file = not configured.
- The MCP server reads config once at boot. Changes need a session restart.
- The `.mcp.json` in the project directory also has env vars — those take
  precedence over config.json. For marketplace use, config.json is preferred.
