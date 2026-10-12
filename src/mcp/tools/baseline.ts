/**
 * Atlas Protocol — MCP tools: Behavioral baselines and drift
 */

import { ingestEntry as baselineIngestEntry, ingestAssessment as baselineIngestAssessment, detectDrift, getBaselineContext } from "../../baseline-engine.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ToolContext, ToolHandler } from "../context.js";

export const definitions: Tool[] = [
  {
    name: "atlas_baseline_get",
    description: "Get the behavioral baseline profile for an agent.",
    inputSchema: {
      type: "object" as const,
      properties: {
        agent_id: { type: "string", description: "The did:atlas:<uuid>" },
      },
      required: ["agent_id"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "atlas_baseline_drift",
    description: "Run drift detection against an agent's baseline using the current audit window.",
    inputSchema: {
      type: "object" as const,
      properties: {
        agent_id: { type: "string", description: "The did:atlas:<uuid>" },
        window_minutes: { type: "number", description: "Time window in minutes (default: 60)" },
      },
      required: ["agent_id"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "atlas_baseline_list",
    description: "List all behavioral baseline profiles, optionally filtered.",
    inputSchema: {
      type: "object" as const,
      properties: {
        maturity: { type: "string", enum: ["insufficient", "developing", "established", "mature"], description: "Filter by maturity level" },
        role: { type: "string", description: "Filter by agent role" },
      },
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

export function handlers(ctx: ToolContext): Record<string, ToolHandler> {
  const { baselineStore, recentAuditEntries } = ctx;
  return {
    async atlas_baseline_get(args) {
      const baselineAgentId = args?.agent_id as string;
      if (!baselineAgentId) {
        return { content: [{ type: "text" as const, text: "Error: agent_id is required" }], isError: true };
      }
      const profile = await baselineStore.get(baselineAgentId);
      if (!profile) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "NO_BASELINE", message: `No baseline exists for ${baselineAgentId}` }) }] };
      }
      // Omit internal _riskScores for external display
      const { _riskScores, ...display } = profile;
      return { content: [{ type: "text" as const, text: JSON.stringify(display, null, 2) }] };
    },
    async atlas_baseline_drift(args) {
      const driftAgentId = args?.agent_id as string;
      if (!driftAgentId) {
        return { content: [{ type: "text" as const, text: "Error: agent_id is required" }], isError: true };
      }
      const driftBaseline = await baselineStore.get(driftAgentId);
      if (!driftBaseline) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ driftDetected: false, recommendation: "allow", note: "No baseline exists for this agent" }, null, 2) }] };
      }
      if (driftBaseline.maturityLevel === "insufficient") {
        return { content: [{ type: "text" as const, text: JSON.stringify({ driftDetected: false, recommendation: "allow", note: "Baseline insufficient — need 10+ sessions" }, null, 2) }] };
      }

      const driftWindowMin = typeof args?.window_minutes === "number" ? args.window_minutes : 60;
      let driftEntries = [...recentAuditEntries]
        .filter((e) => e.agentId === driftAgentId)
        .filter((e) => new Date(e.timestamp) >= new Date(Date.now() - driftWindowMin * 60 * 1000));

      // Use a synthetic expert assessment from the window's risk score
      const avgRisk = driftEntries.length > 0
        ? driftEntries.reduce((sum, e) => {
            const flags = (e.policy_result?.anomaly_flags ?? []).length;
            return sum + Math.min(100, flags * 10);
          }, 0) / driftEntries.length
        : 0;

      const syntheticExpert: import("../../why-engine.js").ExpertAssessment = {
        expert: "anomaly",
        finding: "Synthetic assessment for drift detection",
        confidence: "medium",
        signals: [],
        riskScore: Math.round(avgRisk),
      };

      const driftResult = detectDrift(driftEntries, syntheticExpert, driftBaseline);
      return { content: [{ type: "text" as const, text: JSON.stringify(driftResult, null, 2) }] };
    },
    async atlas_baseline_list(args) {
      const matFilter = args?.maturity as string | undefined;
      const roleFilter = args?.role as string | undefined;
      const allBaselines = await baselineStore.list({
        maturity: matFilter as any,
        role: roleFilter,
      });
      // Return summary fields only — omit whyHistory and _riskScores for size
      const summaries = allBaselines.map(({ whyHistory, _riskScores, ...rest }) => rest);
      return { content: [{ type: "text" as const, text: JSON.stringify(summaries, null, 2) }] };
    },
  };
}
