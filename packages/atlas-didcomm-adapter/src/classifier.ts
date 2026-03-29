/**
 * Atlas DIDComm Adapter — Message Classifier
 *
 * Classifies DIDComm messages into Atlas-friendly terms: protocol family,
 * sensitivity labels, required capability, and a safe preview. The classifier
 * never makes policy decisions — it only normalizes intent.
 */

import type {
  ClassifiedMessage,
  DidcommDirection,
  DidcommMessage,
  MessageClassifier,
  MessagingCapability,
} from "./types.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface ClassifierOptions {
  /** Additional or override message-type mappings. */
  customMappings?: Map<string, ProtocolMapping>;
  /** Max chars for the safe body preview. Default 200. */
  maxPreviewLength?: number;
}

interface ProtocolMapping {
  family: string;
  sensitivity: string[];
  sendCapability: MessagingCapability;
  receiveCapability: MessagingCapability;
}

// ---------------------------------------------------------------------------
// Default protocol-family mappings
// ---------------------------------------------------------------------------

const DEFAULT_MAPPINGS = new Map<string, ProtocolMapping>([
  [
    "atlas/pair-request",
    {
      family: "pairing",
      sensitivity: [],
      sendCapability: "peer:bind",
      receiveCapability: "peer:bind",
    },
  ],
  [
    "clinic/appointment.summary.request",
    {
      family: "health",
      sensitivity: ["health", "phi"],
      sendCapability: "message:send:health",
      receiveCapability: "message:receive:health",
    },
  ],
  [
    "clinic/appointment.summary.response",
    {
      family: "health",
      sensitivity: ["health", "phi"],
      sendCapability: "message:send:health",
      receiveCapability: "message:receive:health",
    },
  ],
  [
    "clinic/care-plan.request",
    {
      family: "health",
      sensitivity: ["health", "phi"],
      sendCapability: "message:send:health",
      receiveCapability: "message:receive:health",
    },
  ],
  [
    "bank/statement.request",
    {
      family: "financial",
      sensitivity: ["financial", "pii"],
      sendCapability: "message:send:financial",
      receiveCapability: "message:receive:financial",
    },
  ],
  [
    "bank/statement.response",
    {
      family: "financial",
      sensitivity: ["financial", "pii"],
      sendCapability: "message:send:financial",
      receiveCapability: "message:receive:financial",
    },
  ],
]);

// ---------------------------------------------------------------------------
// Prefix-based fallback inference
// ---------------------------------------------------------------------------

const PREFIX_FAMILIES: Array<{
  prefix: string;
  family: string;
  sensitivity: string[];
  sendCapability: MessagingCapability;
  receiveCapability: MessagingCapability;
}> = [
  {
    prefix: "health/",
    family: "health",
    sensitivity: ["health", "phi"],
    sendCapability: "message:send:health",
    receiveCapability: "message:receive:health",
  },
  {
    prefix: "clinic/",
    family: "health",
    sensitivity: ["health", "phi"],
    sendCapability: "message:send:health",
    receiveCapability: "message:receive:health",
  },
  {
    prefix: "bank/",
    family: "financial",
    sensitivity: ["financial", "pii"],
    sendCapability: "message:send:financial",
    receiveCapability: "message:receive:financial",
  },
];

// ---------------------------------------------------------------------------
// DefaultClassifier
// ---------------------------------------------------------------------------

export class DefaultClassifier implements MessageClassifier {
  private readonly mappings: Map<string, ProtocolMapping>;
  private readonly maxPreviewLength: number;

  constructor(options?: ClassifierOptions) {
    // Merge default mappings with any custom overrides
    this.mappings = new Map(DEFAULT_MAPPINGS);
    if (options?.customMappings) {
      for (const [key, value] of options.customMappings) {
        this.mappings.set(key, value);
      }
    }
    this.maxPreviewLength = options?.maxPreviewLength ?? 200;
  }

  classifyInbound(msg: DidcommMessage): ClassifiedMessage {
    return this.classify(msg, "receive");
  }

  classifyOutbound(msg: DidcommMessage): ClassifiedMessage {
    return this.classify(msg, "send");
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  private classify(
    msg: DidcommMessage,
    direction: DidcommDirection,
  ): ClassifiedMessage {
    const mapping = this.resolve(msg.type);

    const requiredCapability =
      direction === "send" ? mapping.sendCapability : mapping.receiveCapability;

    return {
      messageType: msg.type,
      protocolFamily: mapping.family,
      direction,
      preview: this.safePreview(msg.body),
      sensitivityLabels: mapping.sensitivity,
      requiredCapability,
    };
  }

  /**
   * Look up exact match first, then prefix-based inference, then fallback.
   */
  private resolve(messageType: string): ProtocolMapping {
    // Exact match
    const exact = this.mappings.get(messageType);
    if (exact) {
      return exact;
    }

    // Prefix-based inference
    for (const rule of PREFIX_FAMILIES) {
      if (messageType.startsWith(rule.prefix)) {
        return rule;
      }
    }

    // Unknown fallback
    return {
      family: "unknown",
      sensitivity: [],
      sendCapability: "message:send",
      receiveCapability: "message:receive",
    };
  }

  /**
   * Extract a safe preview string from the message body.
   * JSON-stringifies the body and truncates — never exposes raw PHI.
   */
  private safePreview(body: unknown): string | undefined {
    if (body === undefined || body === null) {
      return undefined;
    }

    try {
      const raw = JSON.stringify(body);
      if (raw.length <= this.maxPreviewLength) {
        return raw;
      }
      return raw.slice(0, this.maxPreviewLength) + "...";
    } catch {
      return "[unserializable body]";
    }
  }
}
