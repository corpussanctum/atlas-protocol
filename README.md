# Fidelis Channel

Telegram approval channel for Claude Code with:

- fail-closed permission relay
- configurable policy rules
- anomaly flags for higher-risk requests
- tamper-evident audit logging
- optional identity-aware redaction via a DIB-style Briefcase

This plugin is meant to tighten remote approval and operator oversight. It is **not** a compliance certification, legal guarantee, or a substitute for local review of high-risk actions.

## What it does

When Claude Code hits a tool approval prompt, Fidelis Channel can:

1. evaluate the request against local deny/ask/allow rules
2. auto-deny known-dangerous patterns
3. forward unresolved requests to Telegram
4. wait for an explicit `yes <id>` or `no <id>` reply
5. auto-deny on timeout
6. record the decision in a hash-chained audit log, with optional HMAC signing

It also works as a two-way chat bridge: authorized Telegram messages are injected into the Claude Code session, and Claude can reply with the `fidelis_reply` tool.

## Current constraints

- Channels are in research preview and require Claude Code **v2.1.80+**.
- Permission relay requires Claude Code **v2.1.81+**.
- Channels require **claude.ai login**; Console/API-key auth does not support them.
- Team and Enterprise orgs must explicitly enable channels.
- Custom channel plugins still need `--dangerously-load-development-channels` until Anthropic allowlists them through channel review.

## Security posture

This revision intentionally tightens a few things:

- **No open pairing mode.** If no authorized chat ID is configured, inbound Telegram messages are ignored and permission prompts fail closed.
- **No default reply broadcast.** `fidelis_reply` targets the most recent authorized chat by default. Broadcasting is explicit.
- **Distinct audit outcomes.** Explicit human denials and timeout denials are logged separately.
- **Plugin-state aware paths.** Runtime state lives in `${CLAUDE_PLUGIN_DATA}` when installed as a plugin.
- **Delivery-aware prompting.** Permission prompts only wait for a remote verdict if at least one authorized Telegram delivery succeeded.
- **Safer reply rendering.** Claude replies are HTML-escaped by default unless `raw_html=true` is passed intentionally.

## Installation

### Marketplace install

Replace `your-marketplace` with the marketplace that actually hosts this plugin:

```bash
claude plugin install fidelis-channel@your-marketplace
```

Do **not** claim or document `claude-plugins-official` unless the plugin is actually listed there.

When you enable the plugin, Claude Code can prompt for channel-specific configuration using `channels[].userConfig`. This package uses that mechanism for the Telegram bot token, allowed chat IDs, and optional audit HMAC secret.

### Local development

```bash
claude --plugin-dir ./fidelis-channel
```

Plugin skills are namespaced by the plugin name, so commands appear like `/fidelis-channel:status`.

### Channel testing during preview

For local testing during the channel research preview, run Claude Code with the development-channel bypass for your plugin entry:

```bash
claude --dangerously-load-development-channels plugin:fidelis-channel@your-marketplace --channels plugin:fidelis-channel@your-marketplace
```

## Runtime packaging notes

Marketplace plugins are copied into Claude Code’s local plugin cache, so they should not rely on files outside the plugin directory. This package keeps its runnable assets inside the plugin and uses `${CLAUDE_PLUGIN_DATA}` for persistent state.

The included `SessionStart` hook installs runtime dependencies into `${CLAUDE_PLUGIN_DATA}/node_modules` when the bundled manifest changes.

## Configuration model

Primary path:

- `bot_token` — Telegram bot token from BotFather
- `owner_chat_ids` — comma-separated Telegram chat IDs allowed to send messages and approve requests
- `audit_hmac_secret` — optional HMAC secret for audit signing

Advanced users can still override runtime behavior with environment variables such as:

- `FIDELIS_TELEGRAM_BOT_TOKEN`
- `FIDELIS_TELEGRAM_CHAT_IDS`
- `FIDELIS_PERMISSION_TIMEOUT`
- `FIDELIS_HMAC_SECRET`
- `FIDELIS_AUDIT_LOG_PATH`
- `FIDELIS_DATA_DIR`
- `FIDELIS_BRIEFCASE_PATH`
- `FIDELIS_PRIVACY_MODE`

## Tools exposed to Claude

- `fidelis_reply` — send a Telegram reply, optionally to a specific `chat_id` or to all authorized chats with `broadcast=true`; HTML is escaped by default unless `raw_html=true`
- `fidelis_audit_verify` — verify audit log integrity
- `fidelis_status` — inspect current runtime status

## Audit log

The audit log is append-only JSONL with SHA-256 hash chaining. If you provide an HMAC secret, entries are also signed with HMAC-SHA256.

Audit events distinguish:

- `POLICY_DENY`
- `POLICY_ALLOW`
- `HUMAN_APPROVE`
- `HUMAN_DENY`
- `TIMEOUT_DENY`
- `IDENTITY_LOADED`

That separation matters if you want a truthful record of whether a denial came from a person, a local policy, or fail-closed timeout behavior.

## Identity / Briefcase mode

If `FIDELIS_BRIEFCASE_PATH` points at a supported Briefcase directory, Fidelis loads consent boundaries, sensitivity classifications, and audit-redaction rules from that directory. This is an optional hardening layer, not a substitute for system-level privacy controls.

## Validation before submission

Run the validator before submitting:

```bash
claude plugin validate
```

Also do a real end-to-end smoke test with Telegram and the development-channel flag before you try channel review.
