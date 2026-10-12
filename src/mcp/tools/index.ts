/**
 * Atlas Protocol — MCP tool registry. Order here is the order clients see in
 * tools/list (pinned by tests/fixtures/tools-list.json).
 */

import type { ToolContext, ToolHandler } from "../context.js";
import * as core from "./core.js";
import * as identity from "./identity.js";
import * as baseline from "./baseline.js";
import * as policy from "./policy.js";
import * as breakGlass from "./break-glass.js";
import * as audit from "./audit.js";
import * as why from "./why.js";
import * as proximity from "./proximity.js";

const MODULES = [core, identity, baseline, policy, breakGlass, audit, why, proximity];

export const toolDefinitions = MODULES.flatMap((m) => m.definitions);

export function createToolHandlers(ctx: ToolContext): Record<string, ToolHandler> {
  const handlers: Record<string, ToolHandler> = {};
  for (const m of MODULES) {
    for (const [name, handler] of Object.entries(m.handlers(ctx))) {
      if (Object.hasOwn(handlers, name)) throw new Error(`Duplicate tool handler: ${name}`);
      handlers[name] = handler;
    }
  }
  for (const def of toolDefinitions) {
    if (!Object.hasOwn(handlers, def.name)) throw new Error(`Tool without handler: ${def.name}`);
  }
  return handlers;
}
