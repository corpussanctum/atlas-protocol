/**
 * Atlas Protocol — What the operator relay is allowed to see (#17)
 *
 * The approval prompt travels through a third-party relay (Telegram's
 * servers in the reference implementation), so the raw tool input and
 * description are withheld when:
 *
 *   - a sensitivity classification at consent Tier 3 (CLINICAL) or above
 *     matched the request — always, regardless of configuration; or
 *   - privacy mode is on (ATLAS_PRIVACY_MODE=true), unless the operator has
 *     explicitly opted in with ATLAS_TELEGRAM_SEND_INPUT=true.
 *
 * A redacted prompt still shows the tool name, the detected data types (via
 * the prompt flags), the input length, and a SHA3-256 digest the operator
 * can compare on-host. The audit log is governed separately by its own
 * redaction settings.
 */

import { createHash } from "node:crypto";
import { ConsentTier } from "../identity-provider.js";
import type { PermissionRequest, PolicyResult } from "../policy-engine.js";

export interface OperatorPreviewPolicy {
  /** ATLAS_PRIVACY_MODE=true */
  privacyMode: boolean;
  /** ATLAS_TELEGRAM_SEND_INPUT=true: relay the raw input even in privacy mode */
  sendInput: boolean;
}

export type RedactionReason = "SENSITIVE_DATA" | "PRIVACY_MODE";

export interface OperatorPreview {
  description: string;
  inputPreview: string;
  redacted: RedactionReason | null;
}

/** Characters of tool input a non-redacted prompt may carry. */
export const OPERATOR_PREVIEW_MAX_CHARS = 500;

export function operatorPreviewPolicyFromEnv(env: NodeJS.ProcessEnv = process.env): OperatorPreviewPolicy {
  return {
    privacyMode: env.ATLAS_PRIVACY_MODE === "true",
    sendInput: env.ATLAS_TELEGRAM_SEND_INPUT === "true",
  };
}

export function buildOperatorPreview(
  req: PermissionRequest,
  policyResult: PolicyResult,
  policy: OperatorPreviewPolicy,
): OperatorPreview {
  const sensitive = policyResult.sensitivity_matches.some((m) => m.min_tier >= ConsentTier.CLINICAL);
  const redacted: RedactionReason | null = sensitive
    ? "SENSITIVE_DATA"
    : policy.privacyMode && !policy.sendInput
      ? "PRIVACY_MODE"
      : null;

  if (!redacted) {
    return {
      description: req.description,
      inputPreview: req.input_preview.slice(0, OPERATOR_PREVIEW_MAX_CHARS),
      redacted: null,
    };
  }

  const digest = createHash("sha3-256").update(req.input_preview).digest("hex");
  const why = redacted === "SENSITIVE_DATA" ? "sensitive data detected" : "privacy mode";
  return {
    description: `[withheld: ${why}]`,
    inputPreview: `[withheld: ${req.input_preview.length} chars, sha3-256 ${digest.slice(0, 16)}]`,
    redacted,
  };
}
