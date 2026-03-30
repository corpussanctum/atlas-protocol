# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in Atlas Protocol, please report it responsibly:

**Email:** tj@corpussanctum.ai
**Subject line:** `[SECURITY] Atlas Protocol — <brief description>`

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions or components
- Potential impact assessment
- Suggested fix (if you have one)

## Response Timeline

- **Acknowledgment:** Within 48 hours of report
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Best effort, typically within 30 days for critical issues

## Disclosure Policy

- We follow coordinated disclosure. Please allow us reasonable time to address the issue before public disclosure.
- We will credit reporters in the fix commit and changelog unless anonymity is requested.
- We will not pursue legal action against researchers who report in good faith.

## Scope

The following are in scope:

- Policy engine bypass (a request that should be denied gets allowed)
- Audit log tampering (modifying entries without detection)
- Credential forgery or privilege escalation through delegation
- Hash chain integrity violations
- Signature verification bypass
- Identity impersonation or credential replay

The following are out of scope (see [SPEC.md Appendix H](SPEC.md#appendix-h-security-limitations)):

- Host compromise (Atlas assumes the host OS is trustworthy)
- Telegram API availability or Telegram-side vulnerabilities
- Ollama model behavior (the Why Layer is advisory, never authoritative)
- Side-channel attacks on ML-DSA-65 key material in memory

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |
