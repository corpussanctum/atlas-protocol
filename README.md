# Fidelis Channel

Telegram approval channel for Claude Code with:

- fail-closed permission relay
- configurable policy rules
- anomaly flags for higher-risk requests
- tamper-evident audit logging

This plugin is meant to make remote approval and operator oversight tighter. It is **not** a compliance certification, legal guarantee, or a substitute for local review of high-risk actions.

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
- Team and Enterprise orgs must explicitly enable channels. citeturn175972view2

## Security posture

This revision intentionally tightens a few things:

- **No open pairing mode.** If no authorized chat ID is configured, inbound Telegram messages are ignored and permission prompts fail closed.
- **No default reply broadcast.** `fidelis_reply` now targets the most recent authorized chat by default. Broadcasting is explicit.
- **Distinct audit outcomes.** Explicit human denials and timeout denials are logged separately.
- **Plugin-state aware paths.** By default, runtime state lives in `${CLAUDE_PLUGIN_DATA}` when installed as a plugin, which survives updates. Claude Code docs recommend that location for installed dependencies and plugin state. citeturn987090view0

## Installation

### Marketplace install

Replace `your-marketplace` with the marketplace that actually hosts this plugin:

```bash
claude plugin install fidelis-channel@your-marketplace
```

Do **not** claim or document `claude-plugins-official` unless the plugin is actually listed there. Marketplace identifiers are public-facing and come from the marketplace definition, not from the plugin itself. citeturn175972view1

When you enable the plugin, Claude Code can prompt for channel-specific configuration using `channels[].userConfig`. This package uses that mechanism for the Telegram bot token, allowed chat IDs, and optional audit HMAC secret. Sensitive values can be stored in the system keychain. citeturn213093view0turn987090view1

### Local development

```bash
claude --plugin-dir ./fidelis-channel
```

Plugin skills are namespaced by the plugin name, so commands appear like `/fidelis-channel:status`. citeturn516797view2turn987090view1

## Runtime packaging notes

Marketplace plugins are copied into Claude Code’s local plugin cache, so they should not rely on files outside the plugin directory. Claude Code documents `${CLAUDE_PLUGIN_ROOT}` for bundled files and `${CLAUDE_PLUGIN_DATA}` for persistent state and installed dependencies. This package follows that pattern. citeturn987090view0

The included `SessionStart` hook installs runtime dependencies into `${CLAUDE_PLUGIN_DATA}/node_modules` when the bundled manifest changes. That matches the documented pattern for plugins that need Node dependencies at runtime. citeturn987090view0

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

## Tools exposed to Claude

- `fidelis_reply` — send a Telegram reply, optionally to a specific `chat_id` or to all authorized chats with `broadcast=true`
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

That separation matters if you want a truthful record of whether a denial came from a person or from fail-closed timeout behavior.

## Limits and honest positioning

This plugin can improve operator control and evidence trails. It does **not** by itself make a workflow HIPAA compliant, legally compliant, or “fiduciary” in any enforceable sense. If you use those terms publicly, back them with a precise threat model, operational controls, and limitation language.

## Validation before submission

Run the plugin validator before submitting:

```bash
claude plugin validate
```

Claude Code docs recommend `claude plugin validate` or `/plugin validate` to catch manifest and frontmatter issues before distribution. citeturn213093view6
