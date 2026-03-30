/**
 * Single source of truth for the Atlas Protocol version.
 *
 * This is the overall spec version governing pipeline behavior, audit format,
 * delegation semantics, and conformance requirements. It appears in:
 *   - SESSION_START → meta.version
 *   - Delegation authority → version
 *   - ModelProvenance.protocolVersion
 *
 * This is NOT the credential schema version (0.5.0), which tracks the
 * structure of AgentCredential objects and lives in agent-identity.ts.
 */
export const PROTOCOL_VERSION = "0.8.4";
