---
name: audit
description: Verify and inspect the Atlas audit trail — check chain integrity, view recent decisions, export for compliance. Use when the user asks about audit logs, chain verification, or compliance evidence.
user-invocable: true
allowed-tools:
  - Read
  - Bash(wc *)
  - Bash(tail *)
  - Bash(ls *)
  - Bash(head *)
---

# /atlas:audit — Audit Trail Inspection

Inspect and verify the Atlas Protocol cryptographic audit log.

Arguments passed: `$ARGUMENTS`

---

## Dispatch on arguments

### No args — overview + verify

1. Check `~/.atlas-protocol/audit.jsonl` exists
2. Show entry count, file size, first and last timestamps
3. Parse last 10 entries, show summary table:
   - Timestamp | Event | Tool | Verdict | Anomaly flags
4. If the `atlas_audit_verify` MCP tool is available, call it to verify
   chain integrity. Otherwise, note that verification requires an active
   Atlas Protocol session.

### `verify` — explicit chain verification

If the `atlas_audit_verify` tool is available, call it and show results.

If not available (no active channel session), manually verify:
1. Read each line of audit.jsonl
2. Check prev_hash chain (SHA-256 of previous line)
3. If HMAC secret is available in config.json, verify HMAC signatures
4. Report: total entries, chain status, any broken links or tampered entries

### `recent [N]` — show last N decisions

Default N=20. Parse the last N entries and show:
- Permission requests with their verdicts
- Policy denials with matched rules
- Anomaly detections with flags
- Skip SESSION_START and CONFIG_LOADED events (noise)

### `stats` — aggregate statistics

Parse entire audit log and compute:
- Total permission requests
- Auto-denied by policy: count and top patterns
- Auto-allowed by policy: count and top patterns
- Forwarded to human: count
- Human approved vs denied
- Timeout denials (fail-closed)
- Anomaly flags: count by type
- Average response time (if timestamps allow)

### `export` — export for compliance

Copy audit.jsonl to a timestamped file:
`~/.atlas-protocol/exports/audit-YYYY-MM-DD.jsonl`

Note that the exported file retains hash chain and HMAC signatures —
it can be independently verified by anyone with the HMAC secret.

---

## Security note

**This skill only reads the audit log — it never modifies it.**
The audit log is append-only by design. If the user asks to delete
or edit entries, refuse and explain that tamper-evidence requires
immutability.
