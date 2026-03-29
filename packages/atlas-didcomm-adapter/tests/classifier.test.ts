import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { DefaultClassifier } from "../src/classifier.js";
import type { DidcommMessage, MessagingCapability } from "../src/types.js";

function makeMsg(type: string, from?: string, body?: unknown): DidcommMessage {
  return { id: randomUUID(), type, from, body };
}

describe("DefaultClassifier", () => {
  const classifier = new DefaultClassifier();

  describe("classifyInbound", () => {
    it("classifies health messages with correct family, sensitivity, and capability", () => {
      const msg = makeMsg("clinic/appointment.summary.request", "did:peer:sender");
      const result = classifier.classifyInbound(msg);
      assert.equal(result.protocolFamily, "health");
      assert.deepEqual(result.sensitivityLabels, ["health", "phi"]);
      assert.equal(result.requiredCapability, "message:receive:health");
      assert.equal(result.direction, "receive");
    });

    it("classifies financial messages with correct family", () => {
      const msg = makeMsg("bank/statement.request", "did:peer:sender");
      const result = classifier.classifyInbound(msg);
      assert.equal(result.protocolFamily, "financial");
      assert.deepEqual(result.sensitivityLabels, ["financial", "pii"]);
      assert.equal(result.requiredCapability, "message:receive:financial");
    });

    it("classifies pairing messages with family=pairing and capability=peer:bind", () => {
      const msg = makeMsg("atlas/pair-request", "did:peer:sender");
      const result = classifier.classifyInbound(msg);
      assert.equal(result.protocolFamily, "pairing");
      assert.equal(result.requiredCapability, "peer:bind");
      assert.deepEqual(result.sensitivityLabels, []);
    });
  });

  describe("classifyOutbound", () => {
    it("sets direction to 'send'", () => {
      const msg = makeMsg("clinic/appointment.summary.response");
      const result = classifier.classifyOutbound(msg);
      assert.equal(result.direction, "send");
      assert.equal(result.requiredCapability, "message:send:health");
    });
  });

  describe("unknown type fallback", () => {
    it("returns family=unknown for unrecognized message types", () => {
      const msg = makeMsg("custom/unknown-protocol");
      const result = classifier.classifyInbound(msg);
      assert.equal(result.protocolFamily, "unknown");
      assert.deepEqual(result.sensitivityLabels, []);
    });
  });

  describe("custom mappings", () => {
    it("custom mappings override defaults", () => {
      const custom = new Map<string, { family: string; sensitivity: string[]; sendCapability: MessagingCapability; receiveCapability: MessagingCapability }>([
        ["custom/test", {
          family: "custom-family",
          sensitivity: ["custom-label"],
          sendCapability: "message:send",
          receiveCapability: "message:receive",
        }],
      ]);
      const customClassifier = new DefaultClassifier({ customMappings: custom });
      const msg = makeMsg("custom/test");
      const result = customClassifier.classifyInbound(msg);
      assert.equal(result.protocolFamily, "custom-family");
      assert.deepEqual(result.sensitivityLabels, ["custom-label"]);
    });
  });

  describe("prefix inference", () => {
    it("health/ prefix infers health family", () => {
      const msg = makeMsg("health/vitals.reading");
      const result = classifier.classifyInbound(msg);
      assert.equal(result.protocolFamily, "health");
      assert.deepEqual(result.sensitivityLabels, ["health", "phi"]);
    });

    it("clinic/ prefix infers health family", () => {
      const msg = makeMsg("clinic/some-new-type");
      const result = classifier.classifyInbound(msg);
      assert.equal(result.protocolFamily, "health");
    });

    it("bank/ prefix infers financial family", () => {
      const msg = makeMsg("bank/new-transaction");
      const result = classifier.classifyInbound(msg);
      assert.equal(result.protocolFamily, "financial");
      assert.deepEqual(result.sensitivityLabels, ["financial", "pii"]);
    });
  });

  describe("preview handling", () => {
    it("truncates preview at maxPreviewLength", () => {
      const shortClassifier = new DefaultClassifier({ maxPreviewLength: 10 });
      const longBody = { data: "a".repeat(100) };
      const msg = makeMsg("test/msg", undefined, longBody);
      const result = shortClassifier.classifyInbound(msg);
      assert.ok(result.preview, "preview should exist");
      assert.ok(result.preview.length <= 13, "preview should be truncated (10 + '...')");
      assert.ok(result.preview.endsWith("..."), "truncated preview should end with '...'");
    });

    it("uses JSON.stringify for body preview (no raw PHI exposure)", () => {
      const body = { patientName: "John Doe", diagnosis: "cold" };
      const msg = makeMsg("clinic/appointment.summary.request", undefined, body);
      const result = classifier.classifyInbound(msg);
      assert.ok(result.preview, "preview should exist");
      // Should be JSON-stringified, not toString()
      assert.ok(result.preview.includes('"patientName"'), "preview should be JSON-stringified");
    });

    it("returns undefined preview for null/undefined body", () => {
      const msg = makeMsg("test/msg");
      const result = classifier.classifyInbound(msg);
      assert.equal(result.preview, undefined);
    });

    it("sensitivity labels are present for health messages", () => {
      const msg = makeMsg("clinic/appointment.summary.request");
      const result = classifier.classifyInbound(msg);
      assert.ok(result.sensitivityLabels.length > 0, "health messages should have sensitivity labels");
      assert.ok(result.sensitivityLabels.includes("health"));
      assert.ok(result.sensitivityLabels.includes("phi"));
    });
  });
});
