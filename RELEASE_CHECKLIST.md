# Release Checklist

Every release of Atlas Protocol MUST answer these questions before merging to main. This prevents silent drift between prose documentation, normative specification, and running code.

## Spec / Implementation Sync

- [ ] **README changed?** If yes, does SPEC.md need a corresponding update?
- [ ] **SPEC.md changed?** If yes, does the reference implementation conform to the new normative text?
- [ ] **Conformance profile matrix changed?** If yes, are all MUST/SHOULD/MAY annotations consistent with the implementation's actual behavior?
- [ ] **MCP tool names changed?** If yes, update: README tool tables, SPEC.md (if tools are spec-referenced), CHANGELOG, skill docs.
- [ ] **Audit event schema changed?** If yes, update: SPEC.md §6.6, Appendix D (canonical serialization), Appendix F (examples), Appendix G (test vectors).
- [ ] **Error codes changed?** If yes, update: SPEC.md Appendix E, TypeScript type definitions, CHANGELOG.
- [ ] **Policy rules added/removed?** If yes, run `atlas_test_policy` and update rule counts in README and SPEC.md.
- [ ] **Examples or test vectors changed?** If yes, regenerate vectors with `node scripts/gen-test-vectors.mjs` and update Appendix G.

## Code Quality

- [ ] `npm run build` passes with no errors.
- [ ] `npm test` passes all tests (currently 575).
- [ ] No new `any` casts without justification.
- [ ] No `require()` in ESM modules.

## Version Bump

- [ ] `package.json` version updated.
- [ ] `src/index.ts` VERSION constant updated.
- [ ] `src/why-engine.ts` PROTOCOL_VERSION updated (if spec-level changes).
- [ ] `CHANGELOG.md` entry added with date.
- [ ] `SPEC.md` front matter version updated (if spec-level changes).

## Security

- [ ] No credentials, tokens, or secrets in committed files.
- [ ] No new `--no-verify`, `--insecure`, or safety bypass patterns.
- [ ] Policy regression tests pass (`atlas_test_policy`).
- [ ] If audit schema changed: verify hash chain test still passes.
- [ ] If delegation changed: verify chain signature test still passes.

## Documentation

- [ ] CHANGELOG describes what changed and why.
- [ ] If new env vars added: documented in README configuration table.
- [ ] If new MCP tools added: documented in README tools table.
- [ ] Architecture tree in README matches actual `src/` contents.
