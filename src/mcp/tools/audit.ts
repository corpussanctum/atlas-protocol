/**
 * Atlas Protocol — MCP tools: Audit log rotation and archives
 */


import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ToolContext, ToolHandler } from "../context.js";

export const definitions: Tool[] = [
  {
    name: "atlas_audit_rotate",
    description: "Manually trigger audit log rotation. Archives the current log and starts a new one.",
    inputSchema: { type: "object" as const, properties: {} },
    annotations: { readOnlyHint: false, destructiveHint: false },
  },
  {
    name: "atlas_audit_archives",
    description: "List archived audit log files with metadata, or verify archive integrity.",
    inputSchema: {
      type: "object" as const,
      properties: {
        verify: { type: "boolean", description: "Verify integrity of all archives (default: false)" },
      },
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

export function handlers(ctx: ToolContext): Record<string, ToolHandler> {
  const { audit, auditRotation } = ctx;
  return {
    async atlas_audit_rotate(args) {
      const currentSize = auditRotation.currentSize();
      const rotResult = auditRotation.rotate();
      if (!rotResult) {
        return { content: [{ type: "text" as const, text: "No audit log to rotate (empty or missing)." }] };
      }

      audit.log("CONFIG_LOADED", {
        meta: {
          event_detail: "AUDIT_LOG_ROTATED",
          archived_as: rotResult.record.rotated_name,
          entry_count: rotResult.record.entry_count,
          size_bytes: rotResult.record.size_bytes,
        },
      });

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            rotated: true,
            archived_as: rotResult.record.rotated_name,
            entries: rotResult.record.entry_count,
            size_mb: (rotResult.record.size_bytes / 1024 / 1024).toFixed(2),
            chain_anchor: rotResult.chainAnchor.slice(0, 16) + "...",
          }, null, 2),
        }],
      };
    },
    async atlas_audit_archives(args) {
      const doVerify = Boolean(args?.verify);

      if (doVerify) {
        const verification = auditRotation.verifyArchives();
        const stats = auditRotation.getStats();
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              ...verification,
              ...stats,
              total_size_mb: (stats.total_size_bytes / 1024 / 1024).toFixed(2),
            }, null, 2),
          }],
        };
      }

      const archives = auditRotation.listArchives();
      const stats = auditRotation.getStats();
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            ...stats,
            total_size_mb: (stats.total_size_bytes / 1024 / 1024).toFixed(2),
            archives: archives.map((a) => ({
              name: a.rotated_name,
              entries: a.entry_count,
              size_mb: (a.size_bytes / 1024 / 1024).toFixed(2),
              rotated_at: a.rotated_at,
            })),
          }, null, 2),
        }],
      };
    },
  };
}
