/**
 * Atlas Protocol — Identity Provider
 *
 * Abstraction layer between the policy engine and the principal's identity context.
 *
 * Two implementations:
 *   - StandaloneIdentityProvider: no external deps, returns empty context, plugin works as-is
 *   - BriefcaseIdentityProvider: reads DIB Briefcase markdown files (SOUL.md, USER.md, AGENTS.md)
 *     and exposes consent tiers, sensitivity classifications, and agent authorization to the
 *     policy engine
 *
 * A future DibVaultIdentityProvider could call the live API on port 8004, but the
 * Briefcase approach works offline and doesn't require a running service.
 *
 * Design principle: the policy engine NEVER receives raw identity data. It receives
 * a IdentityContext summary with only the fields needed for access decisions.
 */

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Consent Tier model (aligned with DIB Briefcase 7-tier system)
// ---------------------------------------------------------------------------

export enum ConsentTier {
  /** Public profile — name, role, general preferences */
  PUBLIC = 1,
  /** Operational — work context, project info, non-sensitive metadata */
  OPERATIONAL = 2,
  /** Clinical — treatment context, shared with authorized treatment team */
  CLINICAL = 3,
  /** Protected — PHI, PII, insurance, diagnosis codes */
  PROTECTED = 4,
  /** Restricted — trauma narratives, crisis data, substance use detail */
  RESTRICTED = 5,
  /** Confidential — legal, forensic, court-ordered records */
  CONFIDENTIAL = 6,
  /** Sealed — content under special legal protection (e.g. 42 CFR Part 2) */
  SEALED = 7,
}

// ---------------------------------------------------------------------------
// Identity context: what the policy engine sees
// ---------------------------------------------------------------------------

export interface ConsentBoundary {
  /** The tier level (1-7) */
  tier: ConsentTier;
  /** Human-readable label for this tier */
  label: string;
  /** What data falls under this tier */
  description: string;
  /** Where this data is allowed to flow */
  allowed_destinations: string[];
  /** Tools that are explicitly forbidden from accessing this tier */
  forbidden_tools: string[];
}

export interface AgentAuthorization {
  /** Agent identifier (e.g. session ID, agent name) */
  agent_id: string;
  /** Maximum consent tier this agent can access */
  max_tier: ConsentTier;
  /** Purpose statement: why this agent has access */
  purpose: string;
  /** Expiry timestamp (ISO 8601) — empty string means no expiry */
  expires: string;
}

export interface SensitivityClassification {
  /** Regex pattern to detect this type of sensitive data */
  pattern: string;
  /** What type of data this pattern matches */
  data_type: string;
  /** Minimum consent tier required to handle this data */
  min_tier: ConsentTier;
}

export interface IdentityContext {
  /** Whether an identity is loaded (false = standalone mode) */
  loaded: boolean;
  /** Principal's display identifier (never PHI — use a pseudonym or role) */
  principal_label: string;
  /** Consent boundaries defined for this principal */
  consent_boundaries: ConsentBoundary[];
  /** Agent authorizations: which agents can access what */
  agent_authorizations: AgentAuthorization[];
  /** Sensitivity patterns: what data types require elevated consent */
  sensitivity_classifications: SensitivityClassification[];
  /** The maximum tier present in the Briefcase (for audit redaction decisions) */
  max_tier_present: ConsentTier;
  /** Fields that should be redacted in audit logs (driven by consent tiers) */
  audit_redact_fields: string[];
}

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

export interface IdentityProvider {
  /** Load identity context. Returns empty context on failure (fail-open to standalone mode). */
  load(): IdentityContext;
  /** Get the current identity context without reloading */
  getContext(): IdentityContext;
  /** Check if the provider has a loaded identity */
  isLoaded(): boolean;
}

// ---------------------------------------------------------------------------
// Empty context (standalone mode)
// ---------------------------------------------------------------------------

export function emptyIdentityContext(): IdentityContext {
  return {
    loaded: false,
    principal_label: "",
    consent_boundaries: [],
    agent_authorizations: [],
    sensitivity_classifications: [],
    max_tier_present: ConsentTier.PUBLIC,
    audit_redact_fields: [],
  };
}

// ---------------------------------------------------------------------------
// StandaloneIdentityProvider — no DIB, no Briefcase, just the plugin
// ---------------------------------------------------------------------------

export class StandaloneIdentityProvider implements IdentityProvider {
  private context: IdentityContext;

  constructor() {
    this.context = emptyIdentityContext();
  }

  load(): IdentityContext {
    return this.context;
  }

  getContext(): IdentityContext {
    return this.context;
  }

  isLoaded(): boolean {
    return false;
  }
}

// ---------------------------------------------------------------------------
// BriefcaseIdentityProvider — reads DIB Briefcase files
// ---------------------------------------------------------------------------

/**
 * Briefcase directory layout (from DIB Briefcase Context Kit):
 *
 *   briefcase/
 *   ├── SOUL.md         Tier 1 — public identity, role, preferences
 *   ├── USER.md         Tier 2 — operational context, projects, work
 *   ├── CLINICAL.md     Tier 3 — clinical context, treatment team data
 *   ├── PROTECTED.md    Tier 4 — PHI, PII, diagnosis codes
 *   ├── RESTRICTED.md   Tier 5 — trauma, crisis, substance use
 *   ├── AGENTS.md       Agent authorization manifest
 *   └── CONSENT.md      Consent boundaries and flow rules
 *
 * Files are markdown with YAML frontmatter. The provider parses frontmatter
 * for structured fields and uses file presence to determine max_tier.
 */

const TIER_FILES: Array<{ file: string; tier: ConsentTier; label: string }> = [
  { file: "SOUL.md", tier: ConsentTier.PUBLIC, label: "Public" },
  { file: "USER.md", tier: ConsentTier.OPERATIONAL, label: "Operational" },
  { file: "CLINICAL.md", tier: ConsentTier.CLINICAL, label: "Clinical" },
  { file: "PROTECTED.md", tier: ConsentTier.PROTECTED, label: "Protected" },
  { file: "RESTRICTED.md", tier: ConsentTier.RESTRICTED, label: "Restricted" },
  { file: "CONFIDENTIAL.md", tier: ConsentTier.CONFIDENTIAL, label: "Confidential" },
  { file: "SEALED.md", tier: ConsentTier.SEALED, label: "Sealed" },
];

export class BriefcaseIdentityProvider implements IdentityProvider {
  private readonly briefcasePath: string;
  private context: IdentityContext;

  constructor(briefcasePath: string) {
    this.briefcasePath = briefcasePath;
    this.context = emptyIdentityContext();
  }

  load(): IdentityContext {
    if (!existsSync(this.briefcasePath)) {
      console.error(
        `[atlas-identity] Briefcase path not found: ${this.briefcasePath}. Falling back to standalone mode.`
      );
      return this.context;
    }

    const ctx: IdentityContext = {
      loaded: true,
      principal_label: "",
      consent_boundaries: [],
      agent_authorizations: [],
      sensitivity_classifications: [],
      max_tier_present: ConsentTier.PUBLIC,
      audit_redact_fields: [],
    };

    // Scan for tier files to determine max tier and build consent boundaries
    for (const { file, tier, label } of TIER_FILES) {
      const filePath = join(this.briefcasePath, file);
      if (existsSync(filePath)) {
        ctx.max_tier_present = tier;
        const frontmatter = parseFrontmatter(filePath);
        ctx.consent_boundaries.push({
          tier,
          label,
          description: (frontmatter["description"] as string) || `${label} tier data`,
          allowed_destinations: parseStringArray(frontmatter["allowed_destinations"]),
          forbidden_tools: parseStringArray(frontmatter["forbidden_tools"]),
        });
      }
    }

    // Parse principal label from SOUL.md frontmatter
    const soulPath = join(this.briefcasePath, "SOUL.md");
    if (existsSync(soulPath)) {
      const fm = parseFrontmatter(soulPath);
      ctx.principal_label = (fm["principal_label"] as string) || (fm["name"] as string) || "";
    }

    // Parse agent authorizations from AGENTS.md
    const agentsPath = join(this.briefcasePath, "AGENTS.md");
    if (existsSync(agentsPath)) {
      ctx.agent_authorizations = parseAgentAuthorizations(agentsPath);
    }

    // Parse consent rules from CONSENT.md
    const consentPath = join(this.briefcasePath, "CONSENT.md");
    if (existsSync(consentPath)) {
      const fm = parseFrontmatter(consentPath);
      ctx.sensitivity_classifications = parseSensitivityClassifications(fm);
      const redactFields = parseStringArray(fm["audit_redact_fields"]);
      ctx.audit_redact_fields = redactFields.length > 0 ? redactFields : deriveRedactFields(ctx.max_tier_present);
    } else {
      // Default redaction based on max tier
      ctx.audit_redact_fields = deriveRedactFields(ctx.max_tier_present);
    }

    this.context = ctx;
    return ctx;
  }

  getContext(): IdentityContext {
    return this.context;
  }

  isLoaded(): boolean {
    return this.context.loaded;
  }
}

// ---------------------------------------------------------------------------
// Default redaction: tier-driven
// ---------------------------------------------------------------------------

function deriveRedactFields(maxTier: ConsentTier): string[] {
  if (maxTier >= ConsentTier.CLINICAL) {
    // Tier 3+: redact tool input previews (could contain PHI)
    return ["input_preview"];
  }
  // Tier 1-2: no automatic redaction
  return [];
}

// ---------------------------------------------------------------------------
// YAML frontmatter parser (minimal, no dependency)
// ---------------------------------------------------------------------------

interface Frontmatter {
  [key: string]: unknown;
}

function parseFrontmatter(filePath: string): Frontmatter {
  try {
    const content = readFileSync(filePath, "utf-8");
    const match = content.match(/^---\s*\n([\s\S]*?)\n---/);
    if (!match) return {};

    const yaml = match[1];
    const result: Frontmatter = {};

    for (const line of yaml.split("\n")) {
      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) continue;
      const key = line.slice(0, colonIdx).trim();
      let value = line.slice(colonIdx + 1).trim();

      // Handle inline arrays: [item1, item2]
      if (value.startsWith("[") && value.endsWith("]")) {
        result[key] = value
          .slice(1, -1)
          .split(",")
          .map((s) => s.trim().replace(/^["']|["']$/g, ""));
        continue;
      }

      // Strip quotes
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }

      // Try numeric
      const num = Number(value);
      if (!isNaN(num) && value !== "") {
        result[key] = num;
        continue;
      }

      result[key] = value;
    }

    return result;
  } catch {
    return {};
  }
}

function parseStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "string" && value) return value.split(",").map((s) => s.trim());
  return [];
}

// ---------------------------------------------------------------------------
// AGENTS.md parser
// ---------------------------------------------------------------------------

function parseAgentAuthorizations(filePath: string): AgentAuthorization[] {
  try {
    const content = readFileSync(filePath, "utf-8");
    const authorizations: AgentAuthorization[] = [];

    // Parse markdown table or YAML blocks
    // Format: ## agent_id\n max_tier: N\n purpose: ...\n expires: ...
    const blocks = content.split(/^## /m).filter((b) => b.trim());

    for (const block of blocks) {
      const lines = block.split("\n");
      const agentId = lines[0]?.trim() || "";
      if (!agentId) continue;

      const fields: Record<string, string> = {};
      for (const line of lines.slice(1)) {
        const colonIdx = line.indexOf(":");
        if (colonIdx === -1) continue;
        const key = line.slice(0, colonIdx).trim().toLowerCase().replace(/[^a-z_]/g, "");
        fields[key] = line.slice(colonIdx + 1).trim();
      }

      authorizations.push({
        agent_id: agentId,
        max_tier: (parseInt(fields["max_tier"] || "1", 10) || 1) as ConsentTier,
        purpose: fields["purpose"] || "",
        expires: fields["expires"] || "",
      });
    }

    return authorizations;
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Sensitivity classifications parser
// ---------------------------------------------------------------------------

function parseSensitivityClassifications(fm: Frontmatter): SensitivityClassification[] {
  // Default clinical sensitivity patterns
  const defaults: SensitivityClassification[] = [
    {
      pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b",
      data_type: "SSN",
      min_tier: ConsentTier.PROTECTED,
    },
    {
      pattern: "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
      data_type: "EMAIL",
      min_tier: ConsentTier.OPERATIONAL,
    },
    {
      pattern: "\\b(?:DOB|date.?of.?birth)\\s*[:=]\\s*\\d",
      data_type: "DOB",
      min_tier: ConsentTier.PROTECTED,
    },
    {
      pattern: "\\b(?:ICD-?10|CPT|HCPCS|DSM-?5?)\\s*[:=]?\\s*[A-Z]?\\d",
      data_type: "DIAGNOSIS_CODE",
      min_tier: ConsentTier.CLINICAL,
    },
    {
      pattern: "\\b(?:MRN|medical.?record|patient.?id)\\s*[:=]?\\s*\\d",
      data_type: "MRN",
      min_tier: ConsentTier.PROTECTED,
    },
    {
      pattern: "\\b(?:suicid|self.?harm|ideation|attempt|overdose|SI|SH)\\b",
      data_type: "CRISIS_CONTENT",
      min_tier: ConsentTier.RESTRICTED,
    },
  ];

  // Merge with any custom patterns from CONSENT.md frontmatter
  const custom = fm["sensitivity_patterns"];
  if (Array.isArray(custom)) {
    for (const item of custom) {
      if (typeof item === "object" && item && "pattern" in item) {
        defaults.push(item as SensitivityClassification);
      }
    }
  }

  return defaults;
}

// ---------------------------------------------------------------------------
// Factory: create the right provider based on config
// ---------------------------------------------------------------------------

export function createIdentityProvider(briefcasePath?: string): IdentityProvider {
  if (briefcasePath && existsSync(briefcasePath)) {
    const provider = new BriefcaseIdentityProvider(briefcasePath);
    provider.load();
    return provider;
  }
  return new StandaloneIdentityProvider();
}
