# Fidelis Channel revision notes

## What changed in this pass

- Moved plugin metadata toward current Claude Code plugin conventions.
- Added plugin-native channel `userConfig` prompts for:
  - `bot_token`
  - `owner_chat_ids`
  - `audit_hmac_secret`
- Switched plugin runtime state to `${CLAUDE_PLUGIN_DATA}` via `FIDELIS_DATA_DIR`.
- Added a `SessionStart` hook that installs runtime Node dependencies into `${CLAUDE_PLUGIN_DATA}/node_modules`.
- Kept the runtime entrypoint at `dist/index.js` and built `dist/` into the package.
- Tightened Telegram gating so that **no authorized chat IDs = no inbound forwarding**.
- Changed `fidelis_reply` so it does **not** broadcast by default.
- Split explicit `HUMAN_DENY` from `TIMEOUT_DENY` in the audit path.
- Rewrote README to remove risky marketplace wording and reduce overclaiming.
- Rewrote skills to align with plugin-native setup instead of plaintext secret storage.

## Test/build status

- `npm test` ✅
- `npm run build` ✅

## Remaining things I would still pressure-test with Claude Code

1. **Manifest/channel validation in Claude Code itself**
   - Run `claude plugin validate`
   - Confirm `channels[].userConfig` is accepted exactly as written
   - Confirm `.mcp.json` substitutions resolve correctly in your local Claude version

2. **Real Telegram workflow smoke test**
   - install locally with `--plugin-dir`
   - verify channel messages arrive only from configured chat IDs
   - verify permission relay accepts `yes <id>` / `no <id>`
   - verify reply routing targets the right chat

3. **Marketplace polish**
   - add real public repository/homepage links only after they work
   - decide whether you truly want the term `fiduciary` in the public listing
   - add a proper icon/branding review if Anthropic surfaces it prominently

4. **Operational hardening**
   - decide whether failed Telegram API sends during `requestVerdict` should be surfaced more explicitly
   - decide whether unauthorized senders should receive a generic rejection message instead of silent drop
   - consider adding tests around Telegram verdict parsing and reply routing
