/**
 * Atlas Protocol — MCP tools: Why Layer assessments
 */

import { assessWindow, describeWhyEndpoint, loadWhyConfig, stubAssessment } from "../../why-engine.js";
import type { WhyAssessment, AuditEventWindow } from "../../why-engine.js";
import { ingestEntry as baselineIngestEntry, ingestAssessment as baselineIngestAssessment, detectDrift, getBaselineContext } from "../../baseline-engine.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ToolContext, ToolHandler } from "../context.js";

export const definitions: Tool[] = [
  {
    name: "atlas_why_assess",
    description:
      "Manually trigger a Why Layer assessment on the current audit event window. Returns a CoE analysis with anomaly detection, intent inference, and threat narrative.",
    inputSchema: {
      type: "object" as const,
      properties: {
        agent_id: { type: "string", description: "Filter to specific agent (optional)" },
        window_minutes: { type: "number", description: "Time window in minutes (default: 60)" },
        window_size: { type: "number", description: "Max entries to analyze (default: 20)" },
      },
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

export function handlers(ctx: ToolContext): Record<string, ToolHandler> {
  const { baselineStore, whyConfig, recentAuditEntries } = ctx;
  return {
    async atlas_why_assess(args) {
      const whyAgentId = args?.agent_id as string | undefined;
      const windowMin = typeof args?.window_minutes === "number" ? args.window_minutes : whyConfig.windowMinutes;
      const windowSz = typeof args?.window_size === "number" ? args.window_size : whyConfig.windowSize;

      // Build event window from recent entries
      let windowEntries = [...recentAuditEntries];
      if (whyAgentId) {
        windowEntries = windowEntries.filter((e) => e.agentId === whyAgentId);
      }
      const cutoff = new Date(Date.now() - windowMin * 60 * 1000);
      windowEntries = windowEntries.filter((e) => new Date(e.timestamp) >= cutoff);
      windowEntries = windowEntries.slice(-windowSz);

      const window: AuditEventWindow = {
        entries: windowEntries,
        agentId: whyAgentId,
        windowMinutes: windowMin,
      };

      // Load baseline for enrichment
      const whyBaseline = whyAgentId
        ? await baselineStore.get(whyAgentId)
        : undefined;

      const assessment = await assessWindow(window, whyConfig, whyBaseline ?? undefined);
      ctx.lastWhyAssessmentTime = new Date();

      // Ingest assessment into baseline
      if (whyAgentId) {
        baselineIngestAssessment(whyAgentId, assessment, "MANUAL", baselineStore).catch(() => {});
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(assessment, null, 2),
        }],
      };
    },
  };
}
