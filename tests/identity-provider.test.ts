/**
 * Tests for Atlas Protocol — Identity Provider
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  StandaloneIdentityProvider,
  BriefcaseIdentityProvider,
  createIdentityProvider,
  ConsentTier,
  emptyIdentityContext,
} from "../src/identity-provider.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-identity-test-"));
  tempDirs.push(dir);
  return dir;
}

function makeBriefcase(files: Record<string, string>): string {
  const dir = makeTempDir();
  const briefcasePath = join(dir, "briefcase");
  mkdirSync(briefcasePath, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(briefcasePath, name), content, "utf-8");
  }
  return briefcasePath;
}

afterEach(() => {
  for (const dir of tempDirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
  tempDirs = [];
});

// ---------------------------------------------------------------------------
// StandaloneIdentityProvider
// ---------------------------------------------------------------------------

describe("StandaloneIdentityProvider", () => {
  it("returns empty context", () => {
    const provider = new StandaloneIdentityProvider();
    const ctx = provider.load();
    assert.equal(ctx.loaded, false);
    assert.equal(ctx.principal_label, "");
    assert.deepEqual(ctx.consent_boundaries, []);
    assert.deepEqual(ctx.agent_authorizations, []);
    assert.deepEqual(ctx.audit_redact_fields, []);
  });

  it("isLoaded returns false", () => {
    const provider = new StandaloneIdentityProvider();
    assert.equal(provider.isLoaded(), false);
  });

  it("getContext returns same as load", () => {
    const provider = new StandaloneIdentityProvider();
    provider.load();
    const ctx = provider.getContext();
    assert.equal(ctx.loaded, false);
  });
});

// ---------------------------------------------------------------------------
// emptyIdentityContext
// ---------------------------------------------------------------------------

describe("emptyIdentityContext", () => {
  it("returns a valid empty context", () => {
    const ctx = emptyIdentityContext();
    assert.equal(ctx.loaded, false);
    assert.equal(ctx.max_tier_present, ConsentTier.PUBLIC);
    assert.deepEqual(ctx.consent_boundaries, []);
    assert.deepEqual(ctx.sensitivity_classifications, []);
  });
});

// ---------------------------------------------------------------------------
// BriefcaseIdentityProvider
// ---------------------------------------------------------------------------

describe("BriefcaseIdentityProvider — basic loading", () => {
  it("falls back to standalone if path does not exist", () => {
    const provider = new BriefcaseIdentityProvider("/nonexistent/path");
    const ctx = provider.load();
    assert.equal(ctx.loaded, false);
    assert.equal(provider.isLoaded(), false);
  });

  it("loads from a valid briefcase directory", () => {
    const path = makeBriefcase({
      "SOUL.md": [
        "---",
        "name: Test Veteran",
        "principal_label: TV-001",
        "description: Public profile",
        "---",
        "# Public Identity",
        "Role: veteran, software engineer",
      ].join("\n"),
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.equal(ctx.loaded, true);
    assert.equal(ctx.principal_label, "TV-001");
    assert.equal(provider.isLoaded(), true);
  });

  it("uses name field as fallback for principal_label", () => {
    const path = makeBriefcase({
      "SOUL.md": [
        "---",
        "name: John Doe",
        "---",
        "# Identity",
      ].join("\n"),
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.equal(ctx.principal_label, "John Doe");
  });
});

describe("BriefcaseIdentityProvider — consent tiers", () => {
  it("detects max tier from present files", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\ndescription: Public\n---\n",
      "USER.md": "---\ndescription: Operational\n---\n",
      "CLINICAL.md": "---\ndescription: Clinical context\n---\n",
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.equal(ctx.max_tier_present, ConsentTier.CLINICAL);
    assert.equal(ctx.consent_boundaries.length, 3);
  });

  it("tier 1 only when just SOUL.md exists", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\ndescription: Public only\n---\n",
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.equal(ctx.max_tier_present, ConsentTier.PUBLIC);
    assert.equal(ctx.consent_boundaries.length, 1);
  });

  it("parses forbidden_tools from frontmatter", () => {
    const path = makeBriefcase({
      "CLINICAL.md": [
        "---",
        "description: Clinical tier",
        "forbidden_tools: [Bash(*curl*), Bash(*wget*)]",
        "---",
        "# Clinical",
      ].join("\n"),
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    const clinicalBoundary = ctx.consent_boundaries.find((b) => b.tier === ConsentTier.CLINICAL);
    assert.ok(clinicalBoundary);
    assert.deepEqual(clinicalBoundary.forbidden_tools, ["Bash(*curl*)", "Bash(*wget*)"]);
  });

  it("parses allowed_destinations from frontmatter", () => {
    const path = makeBriefcase({
      "CLINICAL.md": [
        "---",
        "description: Clinical",
        "allowed_destinations: [treatment_team, ehr_system]",
        "---",
      ].join("\n"),
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    const clinicalBoundary = ctx.consent_boundaries.find((b) => b.tier === ConsentTier.CLINICAL);
    assert.deepEqual(clinicalBoundary?.allowed_destinations, ["treatment_team", "ehr_system"]);
  });
});

describe("BriefcaseIdentityProvider — agent authorizations", () => {
  it("parses AGENTS.md", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\nname: Test\n---\n",
      "AGENTS.md": [
        "## claude-code-session-1",
        "max_tier: 2",
        "purpose: Development assistance",
        "expires: 2026-12-31",
        "",
        "## theranotes-clinical",
        "max_tier: 4",
        "purpose: Clinical documentation",
        "expires: ",
      ].join("\n"),
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.equal(ctx.agent_authorizations.length, 2);

    const agent1 = ctx.agent_authorizations.find((a) => a.agent_id === "claude-code-session-1");
    assert.ok(agent1);
    assert.equal(agent1.max_tier, 2);
    assert.equal(agent1.purpose, "Development assistance");
    assert.equal(agent1.expires, "2026-12-31");

    const agent2 = ctx.agent_authorizations.find((a) => a.agent_id === "theranotes-clinical");
    assert.ok(agent2);
    assert.equal(agent2.max_tier, 4);
  });

  it("returns empty array when no AGENTS.md", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\nname: Test\n---\n",
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.deepEqual(ctx.agent_authorizations, []);
  });
});

describe("BriefcaseIdentityProvider — audit redaction", () => {
  it("derives input_preview redaction for Tier 3+", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\nname: Test\n---\n",
      "USER.md": "---\ndescription: Op\n---\n",
      "CLINICAL.md": "---\ndescription: Clinical\n---\n",
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.deepEqual(ctx.audit_redact_fields, ["input_preview"]);
  });

  it("no automatic redaction for Tier 1-2 only", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\nname: Test\n---\n",
      "USER.md": "---\ndescription: Op\n---\n",
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.deepEqual(ctx.audit_redact_fields, []);
  });

  it("uses explicit audit_redact_fields from CONSENT.md", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\nname: Test\n---\n",
      "CONSENT.md": [
        "---",
        "audit_redact_fields: [input_preview, description]",
        "---",
      ].join("\n"),
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.deepEqual(ctx.audit_redact_fields, ["input_preview", "description"]);
  });
});

describe("BriefcaseIdentityProvider — sensitivity classifications", () => {
  it("includes default clinical patterns", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\nname: Test\n---\n",
      "CONSENT.md": "---\n---\n",
    });

    const provider = new BriefcaseIdentityProvider(path);
    const ctx = provider.load();
    assert.ok(ctx.sensitivity_classifications.length >= 5);
    const types = ctx.sensitivity_classifications.map((s) => s.data_type);
    assert.ok(types.includes("SSN"));
    assert.ok(types.includes("EMAIL"));
    assert.ok(types.includes("CRISIS_CONTENT"));
    assert.ok(types.includes("DIAGNOSIS_CODE"));
    assert.ok(types.includes("MRN"));
  });
});

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

describe("createIdentityProvider", () => {
  it("returns StandaloneIdentityProvider when no path given", () => {
    const provider = createIdentityProvider();
    assert.equal(provider.isLoaded(), false);
  });

  it("returns StandaloneIdentityProvider when path does not exist", () => {
    const provider = createIdentityProvider("/nonexistent/briefcase");
    assert.equal(provider.isLoaded(), false);
  });

  it("returns loaded BriefcaseIdentityProvider when path exists", () => {
    const path = makeBriefcase({
      "SOUL.md": "---\nname: Factory Test\n---\n",
    });

    const provider = createIdentityProvider(path);
    assert.equal(provider.isLoaded(), true);
    assert.equal(provider.getContext().principal_label, "Factory Test");
  });
});
