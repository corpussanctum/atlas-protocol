/**
 * Generate test vectors and canonical examples for SPEC.md appendices.
 * Run: node scripts/gen-test-vectors.mjs
 */
import { createHash, createHmac } from "node:crypto";

function buildCanonical(obj) {
  const sorted = {};
  for (const key of Object.keys(obj).sort()) {
    let val = obj[key];
    if (key === "capabilities" && Array.isArray(val)) val = [...val].sort();
    if (val === undefined) continue;
    sorted[key] = val;
  }
  return JSON.stringify(sorted);
}

// Test vector 1: Credential hash
const cred = {
  agentId: "did:atlas:00000000-0000-4000-8000-000000000001",
  capabilities: ["file:write", "file:read", "shell:exec"],
  expiresAt: "2026-03-30T00:00:00.000Z",
  issuedAt: "2026-03-29T00:00:00.000Z",
  name: "test-agent",
  publicKey: "0000000000000000",
  revoked: false,
  role: "claude-code",
  version: "0.5.0",
};
const canonical = buildCanonical(cred);
const credHash = createHash("sha3-256").update(canonical).digest("hex");
console.log("=== TV1: CREDENTIAL HASH ===");
console.log("Canonical:", canonical);
console.log("SHA3-256:", credHash);

// Test vector 2: Audit prev_hash
const auditLine = '{"event":"SESSION_START","hash_algorithm":"sha3-256",' +
  '"id":"00000000-0000-4000-8000-000000000099",' +
  '"prev_hash":"GENESIS","seq":0,' +
  '"timestamp":"2026-03-29T00:00:00.000Z"}';
const prevHash = createHash("sha3-256").update(auditLine).digest("hex");
console.log("\n=== TV2: AUDIT PREV_HASH ===");
console.log("Line:", auditLine);
console.log("SHA3-256:", prevHash);

// Test vector 3: Redacted field
const redKey = "atlas-redaction-v1:test-secret-key";
const ssn = "000-00-0000";
const redacted = createHmac("sha256", redKey).update(ssn).digest("hex");
console.log("\n=== TV3: REDACTED FIELD ===");
console.log("Key:", redKey);
console.log("Value:", ssn);
console.log("HMAC-SHA256:", redacted);

// Test vector 4: Delegation authority hash
const delAuth = {
  protocol: "atlas-protocol",
  version: "0.5.0",
  type: "delegation-authority",
  rootId: "did:atlas:00000000-0000-4000-8000-000000000001",
  parentId: "did:atlas:00000000-0000-4000-8000-000000000001",
  childId: "did:atlas:00000000-0000-4000-8000-000000000002",
  capabilities: ["file:read"],
  expiresAt: "2026-03-30T00:00:00.000Z",
  depth: 1,
  childCredentialHash: credHash,
};
const delCanonical = JSON.stringify(delAuth);
const delHash = createHash("sha3-256").update(delCanonical).digest("hex");
console.log("\n=== TV4: DELEGATION AUTHORITY HASH ===");
console.log("Canonical:", delCanonical);
console.log("SHA3-256:", delHash);

// Test vector 5: Chain continuity across rotation
const lastLine = '{"event":"POLICY_ALLOW","seq":499,"prev_hash":"abc123"}';
const finalHash = createHash("sha3-256").update(lastLine).digest("hex");
console.log("\n=== TV5: ROTATION BRIDGE ===");
console.log("Last line of old file:", lastLine);
console.log("final_hash (= next file's first prev_hash):", finalHash);
console.log("next_seq:", 500);
