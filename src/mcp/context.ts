/**
 * Atlas Protocol — dependencies and session state shared by MCP tool handlers.
 *
 * Mutable session state is exposed through accessors backed by main()'s
 * variables, so tool handlers and the rest of the server see the same values.
 */

import type { AtlasConfig } from "../config.js";
import type { IdentityRegistry } from "../identity-registry.js";
import type { QuantumSigner } from "../quantum-signer.js";
import type { AuditLogger, AuditEntry } from "../audit-log.js";
import type { TelegramBot } from "../telegram.js";
import type { IdentityContext } from "../identity-provider.js";
import type { BaselineStore } from "../baseline-store.js";
import type { BreakGlassManager } from "../break-glass.js";
import type { QuietModeConfig } from "../quiet-mode.js";
import type { AuditRotationManager } from "../audit-rotation.js";
import type { WhyEngineConfig } from "../why-engine.js";
import type { ProximityMesh, ProximityMeshConfig, HardwareAdapterSet } from "../proximity/index.js";

export interface ToolResult {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export type ToolHandler = (args: Record<string, unknown> | undefined) => Promise<ToolResult>;

export interface ToolContext {
  config: AtlasConfig;
  registry: IdentityRegistry;
  signer: QuantumSigner;
  audit: AuditLogger;
  telegram: TelegramBot;
  identityContext: IdentityContext;
  baselineStore: BaselineStore;
  breakGlass: BreakGlassManager;
  quietConfig: QuietModeConfig;
  proximityConfig: ProximityMeshConfig;
  getHardware(): Promise<HardwareAdapterSet>;
  ensureProximityMesh(agentId: string): Promise<ProximityMesh>;
  proximityHardwareError(): ToolResult;
  auditRotation: AuditRotationManager;
  whyConfig: WhyEngineConfig;
  /** Recent audit entries tracked for the Why Layer (shared, mutated by the server) */
  recentAuditEntries: AuditEntry[];

  /** Agent registered in this session via atlas_identity_register */
  sessionAgentId: string | undefined;
  lastWhyAssessmentTime: Date | undefined;
  readonly proximityMesh: ProximityMesh | undefined;
  readonly hardwareError: string | undefined;
}
