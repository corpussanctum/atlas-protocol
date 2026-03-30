# Contributing to Atlas Protocol

Thanks for your interest in Atlas Protocol. This guide covers the most common contribution paths.

## Getting Started

```bash
git clone https://github.com/corpussanctum/atlas-protocol.git
cd atlas-protocol
npm install && npm run build
npm test  # 614 tests should pass
```

## Contributing Policy Rules

The policy engine is the most accessible contribution surface. Atlas ships with 96 rules (89 deny, 7 ask) in `src/config.ts`. Adding a new rule is straightforward.

### Rule structure

```typescript
interface PolicyRule {
  tool_pattern: string;   // Glob pattern matched against tool_name (e.g. "Bash", "Write*")
  action: "deny" | "ask" | "allow";
  reason?: string;        // Human-readable — appears in audit log and Telegram relay
  mitre_id?: string;      // MITRE ATT&CK technique ID (e.g. "T1059.004")
}
```

### Adding a rule

1. Open `src/config.ts` and find the `DEFAULT_RULES` array.
2. Rules are evaluated **in order** — first match wins. Place deny rules before ask rules.
3. Add your rule with a clear `reason` and a `mitre_id` if applicable.
4. Add a test case in `tests/policy-engine.test.ts`.
5. Run `npm test` to verify nothing breaks.

### Example: blocking `terraform destroy`

```typescript
{
  tool_pattern: "Bash",
  action: "deny",
  reason: "terraform destroy — destructive infrastructure operation",
  mitre_id: "T1485",  // Data Destruction
}
```

For input-pattern rules (matching command content rather than tool name), see the anomaly detection section of `src/policy-engine.ts`. The engine checks `description` and `input_preview` fields against glob patterns.

### Rule guidelines

- **Be specific.** Overly broad patterns cause false positives. Prefer `"Bash"` + input matching over `"*"`.
- **Include a reason.** Operators see this in Telegram. A good reason helps them decide quickly.
- **Map to ATT&CK.** Use [MITRE ATT&CK](https://attack.mitre.org/) technique IDs where applicable. See `src/mitre-attack.ts` for the enrichment layer.
- **Test the negative case.** Ensure your pattern doesn't accidentally block legitimate operations.

## Contributing Hardware Adapters

The ProximityMesh profile uses a driver interface (`UWBDriver`, `BLEDriver`, `NFCDriver` in `src/proximity/types.ts`). New adapters go in `src/proximity/adapters/`.

1. Implement the interface for your hardware.
2. Register it in `src/proximity/adapters/index.ts` (the factory switch).
3. Add tests using the mock peer pattern from `tests/proximity-mesh.test.ts`.
4. Mark the adapter as `UNTESTED REFERENCE DRIVER` until validated on real hardware.

## Code Contributions

- All code is TypeScript, targeting Node.js 20+.
- Run `npm run build` to check types. Run `npm test` to run the full suite.
- Tests use Node.js built-in test runner (`node --test`), not Jest.
- The spec (`SPEC.md`) is normative. If your change affects protocol behavior, update the spec too.

## What We're Looking For

- New policy rules for common dangerous patterns
- Hardware adapter implementations (especially real-hardware-tested ones)
- Bug reports with reproduction steps
- Spec clarifications or conformance edge cases
- DIDComm adapter improvements (`packages/atlas-didcomm-adapter/`)

## What We're Not Looking For

- Framework migrations or build tool changes
- Adding optional dependencies without a strong justification
- Changes to cryptographic primitives (ML-DSA-65, SHA3-256, AES-256-GCM) — these are spec-locked

## Reporting Security Issues

Do **not** open a public issue for security vulnerabilities. Email tj@corpussanctum.ai with details. We'll coordinate disclosure.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
