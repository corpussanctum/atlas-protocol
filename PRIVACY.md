# Privacy Policy — Atlas Protocol

**Last updated:** 2026-03-30

## What Atlas Processes

Atlas Protocol is a **local-first security tool**. It processes:

- **Tool permission requests** — tool name, description, and input preview text from the Claude Code session
- **Agent identity data** — DIDs, public keys, roles, capabilities, and credential metadata
- **Behavioral baselines** — per-agent usage patterns derived from audit log entries
- **Proximity data** (ProximityMesh profile only) — UWB distance measurements, BLE signal strength, and device identifiers

## Where Data Goes

| Data | Destination | Purpose |
|---|---|---|
| Permission requests + verdicts | **Telegram** (operator relay) | Human-in-the-loop approval |
| Audit log entries | **Local filesystem** only | Tamper-evident audit trail |
| Agent credentials | **Local filesystem** only | Identity registry |
| Behavioral baselines | **Local filesystem** only | Drift detection |
| Why Layer prompts | **Ollama** (local or configured endpoint) | Anomaly assessment |
| Proximity proofs | **Local filesystem** + **peer device** (mesh sessions) | Proximity attestation |

Atlas does **not** send data to Anthropic, Corpus Sanctum, or any third-party analytics service. The only external communication is with:

1. **Telegram Bot API** — for operator message relay (requires user-configured bot token)
2. **Ollama API** — for Why Layer assessments (defaults to localhost, user-configurable)

## Data Retention

- **Audit logs** are retained locally until manually deleted or rotated (configurable via `ATLAS_AUDIT_MAX_ARCHIVES`)
- **Identity credentials** persist in the data directory until revoked or expired
- **Behavioral baselines** persist indefinitely in the data directory
- **Proximity session data** is held in memory only and discarded when sessions close

## User Control

- All data is stored in `ATLAS_DATA_DIR` (default: `~/.atlas-protocol`). Delete this directory to remove all Atlas data.
- Telegram communication can be disabled by not providing `ATLAS_TELEGRAM_BOT_TOKEN` (Atlas will deny all "ask" requests without operator relay).
- Audit field redaction can be forced with `ATLAS_PRIVACY_MODE=true`, which hashes tool inputs before logging.
- The Why Layer can be disabled by not running Ollama — it returns nominal stubs and never blocks.

## Clinical / PHI Data

Atlas is designed for use in clinical contexts (see [SPEC.md §12.1](SPEC.md) for DIB Briefcase integration). When processing clinical sessions:

- Tool inputs may contain PHI. Enable `ATLAS_PRIVACY_MODE=true` to redact these from audit logs.
- Telegram approval prompts include the tool name, description, and the **first 500 characters of the tool input**, so the operator can make an informed decision. This preview passes through Telegram's servers. `ATLAS_PRIVACY_MODE` currently redacts the audit log only, not the Telegram preview (tracked in the issue tracker). Don't route PHI-bearing sessions through the Telegram relay without accounting for this.
- The Why Layer sends recent audit entries (tool names, verdicts, timestamps) and behavioral baselines to Ollama. Configure a local Ollama instance to keep PHI on-premises. Atlas warns at startup if the endpoint is non-loopback plain HTTP.

## Contact

For privacy questions: tj@corpussanctum.ai
