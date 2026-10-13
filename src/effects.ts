/**
 * Atlas Protocol — Canonical effects (#9, groundwork)
 *
 * Policy rules can match on what a request does, not only on how it is
 * spelled. A normalizer turns a permission request into a list of effects:
 *
 *   { effect, target, recursive, scope, reversible, command }
 *
 * This module defines the vocabulary (also published as
 * docs/effect-vocabulary.schema.json for other enforcement layers), the rule
 * matcher, and the normalizer interface. The built-in normalizer covers the
 * file tools (Read, Write, Edit, MultiEdit, NotebookEdit), whose input is a
 * path. Shell commands produce no effects until a shell normalizer is plugged
 * in through the EffectNormalizer interface, so Bash requests are evaluated
 * exactly as before.
 *
 * Effects only add evidence for rules to match. A normalizer that can't fully
 * parse its input reports `complete: false`; string rules still apply and the
 * default verdict is still "ask".
 */

export const EFFECT_KINDS = [
  "exec", // a program runs
  "exec.dynamic", // code or a command name decided at runtime
  "fs.read",
  "fs.write",
  "fs.delete",
  "fs.permission", // mode or ownership change
  "device.write", // raw block or character device
  "net.connect",
  "net.listen",
  "vcs.push",
  "vcs.rewrite", // history or working-tree changes the VCS can't undo
] as const;
export type EffectKind = (typeof EFFECT_KINDS)[number];

export const EFFECT_SCOPES = ["project", "temp", "home", "system", "device", "remote", "unknown"] as const;
export type EffectScope = (typeof EFFECT_SCOPES)[number];

export interface Effect {
  effect: EffectKind;
  /** Path, host or URL the effect applies to; null when not statically known */
  target: string | null;
  recursive: boolean;
  scope: EffectScope;
  /** Whether the effect can normally be undone */
  reversible: boolean;
  /** Program producing the effect (basename), or the tool name for non-shell tools */
  command: string;
}

export interface NormalizedRequest {
  effects: Effect[];
  /** False when the normalizer could not fully interpret the input */
  complete: boolean;
}

/** The part of a permission request a normalizer sees. */
export interface NormalizerInput {
  tool_name: string;
  input_preview: string;
}

/** Pluggable: must be deterministic and must not call out to a model. */
export type EffectNormalizer = (req: NormalizerInput) => NormalizedRequest;

/**
 * Rule-side matcher. Every field that is present must match; a rule with a
 * matcher applies when at least one effect of the request matches.
 */
export interface EffectMatcher {
  effect?: EffectKind[];
  /** Command basenames, case-insensitive */
  command?: string[];
  /** Glob over the target (`*` wildcard, `|` alternatives, case-insensitive) */
  target?: string;
  recursive?: boolean;
  scope?: EffectScope[];
  reversible?: boolean;
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/** Classify a target path, host or URL. */
export function scopeOf(target: string | null): EffectScope {
  if (!target) return "unknown";
  const t = target.trim();
  if (!t) return "unknown";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t) || /^[^/\s]+@[^/\s]+:/.test(t)) return "remote";
  if (t === "/dev/null") return "temp";
  if (t.startsWith("/dev/")) return "device";
  if (t === "/tmp" || t.startsWith("/tmp/") || t === "/var/tmp" || t.startsWith("/var/tmp/")) return "temp";
  if (t === "~" || t.startsWith("~/") || t.startsWith("$HOME") || t.startsWith("${HOME}")) return "home";
  if (t === "/root" || t.startsWith("/root/") || t === "/home" || t.startsWith("/home/")) return "home";
  if (t.startsWith("/")) return "system";
  if (t.startsWith("$")) return "unknown";
  return "project";
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

function globMatch(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

export function effectMatches(m: EffectMatcher, e: Effect): boolean {
  if (m.effect && !m.effect.includes(e.effect)) return false;
  if (m.command && !m.command.some((c) => c.toLowerCase() === e.command.toLowerCase())) return false;
  if (m.target !== undefined) {
    if (e.target === null) return false;
    if (!m.target.split("|").some((alt) => globMatch(alt.trim(), e.target!))) return false;
  }
  if (m.recursive !== undefined && m.recursive !== e.recursive) return false;
  if (m.scope && !m.scope.includes(e.scope)) return false;
  if (m.reversible !== undefined && m.reversible !== e.reversible) return false;
  return true;
}

const MATCHER_KEYS = new Set(["effect", "command", "target", "recursive", "scope", "reversible"]);
const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

/** Validate a matcher from config.json. Returns a problem description, or null. */
export function effectMatcherProblem(v: unknown): string | null {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return "effect must be an object";
  const m = v as Record<string, unknown>;
  for (const k of Object.keys(m)) if (!MATCHER_KEYS.has(k)) return `effect.${k} is not a matcher field`;
  if (Object.keys(m).length === 0) return "effect matcher must constrain at least one field";
  if (m.effect !== undefined && !(isStringArray(m.effect) && m.effect.every((k) => (EFFECT_KINDS as readonly string[]).includes(k)))) {
    return `effect.effect must be an array of ${EFFECT_KINDS.join(", ")}`;
  }
  if (m.scope !== undefined && !(isStringArray(m.scope) && m.scope.every((s) => (EFFECT_SCOPES as readonly string[]).includes(s)))) {
    return `effect.scope must be an array of ${EFFECT_SCOPES.join(", ")}`;
  }
  if (m.command !== undefined && !isStringArray(m.command)) return "effect.command must be an array of strings";
  if (m.target !== undefined && typeof m.target !== "string") return "effect.target must be a string";
  if (m.recursive !== undefined && typeof m.recursive !== "boolean") return "effect.recursive must be a boolean";
  if (m.reversible !== undefined && typeof m.reversible !== "boolean") return "effect.reversible must be a boolean";
  return null;
}

// ---------------------------------------------------------------------------
// Built-in normalizer: file tools
// ---------------------------------------------------------------------------

const FILE_TOOLS: Record<string, { effect: EffectKind; reversible: boolean; keys: string[] }> = {
  Read: { effect: "fs.read", reversible: true, keys: ["file_path"] },
  Write: { effect: "fs.write", reversible: false, keys: ["file_path"] },
  Edit: { effect: "fs.write", reversible: false, keys: ["file_path"] },
  MultiEdit: { effect: "fs.write", reversible: false, keys: ["file_path"] },
  NotebookEdit: { effect: "fs.write", reversible: false, keys: ["notebook_path", "file_path"] },
};

/**
 * The file path from a file tool's input preview: either the bare path, or
 * the tool input as JSON (possibly truncated), from which the path field is
 * read.
 */
function filePathFrom(preview: string, keys: string[]): { path: string | null; complete: boolean } {
  const p = preview.trim();
  if (!p) return { path: null, complete: false };
  if (!p.startsWith("{")) return { path: p, complete: true };
  try {
    const obj = JSON.parse(p) as Record<string, unknown>;
    for (const k of keys) if (typeof obj[k] === "string") return { path: obj[k] as string, complete: true };
    return { path: null, complete: false };
  } catch {
    // Truncated JSON: take the path field if it is complete
    for (const k of keys) {
      const m = p.match(new RegExp(`"${k}"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"`));
      if (m) return { path: JSON.parse(`"${m[1]}"`) as string, complete: false };
    }
    return { path: null, complete: false };
  }
}

export const fileToolNormalizer: EffectNormalizer = (req) => {
  const spec = FILE_TOOLS[req.tool_name];
  if (!spec) return { effects: [], complete: true };
  const { path, complete } = filePathFrom(req.input_preview, spec.keys);
  return {
    effects: [{
      effect: spec.effect,
      target: path,
      recursive: false,
      scope: scopeOf(path),
      reversible: spec.reversible,
      command: req.tool_name,
    }],
    complete,
  };
};

/**
 * Run several normalizers and concatenate their effects. Complete only if
 * every normalizer was.
 */
export function combineNormalizers(...normalizers: EffectNormalizer[]): EffectNormalizer {
  return (req) => {
    const effects: Effect[] = [];
    let complete = true;
    for (const n of normalizers) {
      const r = n(req);
      effects.push(...r.effects);
      complete &&= r.complete;
    }
    return { effects, complete };
  };
}
