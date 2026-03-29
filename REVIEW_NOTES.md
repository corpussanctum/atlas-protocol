# Atlas Protocol revision notes — v0.2.2

## What changed in this pass

- Synced package and plugin manifest versions to `0.2.2`.
- Removed chat-only citation markup that had leaked into `README.md`.
- Reworked test execution so the repo no longer depends on an unlisted `tsx` runtime.
- Added `tsconfig.tests.json` and compile-first test flow.
- Hardened the `SessionStart` hook with an explicit `mkdir -p` for `${CLAUDE_PLUGIN_DATA}`.
- Made Telegram sends delivery-aware:
  - `sendMessage()` now throws on HTTP or Telegram API failure
  - `requestVerdict()` only waits for a response if at least one prompt was delivered
- Added safer Claude reply handling:
  - default reply path escapes HTML
  - optional `raw_html=true` allows intentional rich formatting

## What still deserves pressure-testing

1. `claude plugin validate`
2. real Telegram permission relay from a phone
3. channel enable flow with `channels[].userConfig`
4. development-channel startup using `--dangerously-load-development-channels`
5. whether the Briefcase layer should be fail-open or fail-closed when explicitly configured but missing/bad

## Blunt take

This is a better package than v0.2.1.
The biggest remaining non-code question is product positioning: whether the Briefcase / consent story should stay optional and lightweight, or become a stricter policy boundary with an explicit failure mode.
