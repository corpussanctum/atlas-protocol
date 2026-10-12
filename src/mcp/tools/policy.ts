/**
 * Atlas Protocol — MCP tools: Policy regression testing
 */

import { runPolicyTests } from "../../policy-test-runner.js";
import type { Tool } from "@modelcontextprotocol/server";
import type { ToolContext, ToolHandler } from "../context.js";

export const definitions: Tool[] = [
  {
    name: "atlas_test_policy",
    description:
      "Run policy regression tests against known malicious/benign fixtures. " +
      "Returns pass/fail counts and details of any failures. Use after rule changes to verify no regressions.",
    inputSchema: {
      type: "object" as const,
      properties: {
        verbose: { type: "boolean", description: "Include all results, not just failures (default: false)" },
      },
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

export function handlers(ctx: ToolContext): Record<string, ToolHandler> {
  const { config } = ctx;
  return {
    async atlas_test_policy(args) {
      const verbose = Boolean(args?.verbose);
      const report = runPolicyTests(config);

      const lines: string[] = [];
      if (report.failed === 0) {
        lines.push(`✅ All ${report.totalFixtures} policy fixtures passed (${report.totalRules} rules)`);
      } else {
        lines.push(`❌ ${report.failed}/${report.totalFixtures} fixtures FAILED (${report.totalRules} rules)`);
        lines.push("");
        for (const f of report.failures) {
          lines.push(`  FAIL: [${f.tool}] "${f.input}" — expected ${f.expected}, got ${f.actual}` +
            (f.matchedRule ? ` (rule: ${f.matchedRule})` : " (no rule matched)"));
        }
      }
      lines.push("");
      lines.push(`Malicious: ${report.summary.malicious.passed}/${report.summary.malicious.total}`);
      lines.push(`Benign:    ${report.summary.benign.passed}/${report.summary.benign.total}`);
      lines.push(`Ask:       ${report.summary.ask.passed}/${report.summary.ask.total}`);
      lines.push(`Edge:      ${report.summary.edge.passed}/${report.summary.edge.total}`);
      lines.push(`Pass rate: ${report.passRate}`);

      if (verbose) {
        return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
      }

      return { content: [{ type: "text" as const, text: lines.join("\n") }] };
    },
  };
}
