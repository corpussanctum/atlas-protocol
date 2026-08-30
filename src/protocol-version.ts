/**
 * Single source of truth for the Atlas Protocol version.
 *
 * This is the overall spec version governing pipeline behavior, audit format,
 * delegation semantics, and conformance requirements. It appears in:
 *   - SESSION_START → meta.protocol_version
 *   - Delegation authority → version
 *   - ModelProvenance.protocolVersion
 *
 * Distinct from the implementation version (package.json / atlas_status)
 * and the spec document version (SPEC.md header). See SPEC.md §11.2.
 *
 * This is NOT the credential schema version (0.5.0), which tracks the
 * structure of AgentCredential objects and lives in agent-identity.ts.
 */
export const PROTOCOL_VERSION = "0.8.4";
