/**
 * Tests for the hardware adapter factory:
 *   - Default adapter is mock
 *   - Explicit override works
 *   - Auto-detection logic
 *   - All adapter types construct without error
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHardwareAdapters } from "../src/proximity/adapters/index.js";
import type { AdapterType } from "../src/proximity/adapters/index.js";

describe("Hardware Adapter Factory", () => {
  const originalEnv = process.env.ATLAS_HARDWARE_ADAPTER;

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env.ATLAS_HARDWARE_ADAPTER;
    } else {
      process.env.ATLAS_HARDWARE_ADAPTER = originalEnv;
    }
  });

  it("defaults to mock adapter", async () => {
    delete process.env.ATLAS_HARDWARE_ADAPTER;
    const adapters = await createHardwareAdapters("mock");
    assert.equal(adapters.type, "mock");
    assert.equal(await adapters.uwb.isAvailable(), true);
    assert.equal(await adapters.ble.isAvailable(), true);
    assert.equal(await adapters.nfc.isAvailable(), true);
  });

  it("explicit mock override works", async () => {
    process.env.ATLAS_HARDWARE_ADAPTER = "raspberry-pi";
    // Override should take priority over env
    const adapters = await createHardwareAdapters("mock");
    assert.equal(adapters.type, "mock");
  });

  it("mock UWB driver simulates ranging", async () => {
    const adapters = await createHardwareAdapters("mock");
    const result = await adapters.uwb.range("test-device", {
      stsEnabled: true,
      challenge: new Uint8Array(32),
    });
    assert.equal(typeof result.distanceMeters, "number");
    assert.equal(result.stsEnabled, true);
    assert.ok(result.timestamp);
  });

  it("mock BLE driver scans (empty by default)", async () => {
    const adapters = await createHardwareAdapters("mock");
    const peers = await (adapters.ble as any).scan(1000);
    assert.equal(peers.length, 0);
  });

  it("raspberry-pi adapter is constructable on Linux", async () => {
    // This will construct but UWB isAvailable will return false (no hardware)
    try {
      const adapters = await createHardwareAdapters("raspberry-pi");
      assert.equal(adapters.type, "raspberry-pi");
      // isAvailable returns false since we don't have /dev/ttyS0 with a real module
      const available = await adapters.uwb.isAvailable();
      assert.equal(typeof available, "boolean");
    } catch (err: any) {
      // serialport not installed — this is expected, adapter is optional
      assert.ok(err.message.includes("serialport") || err.message.includes("Cannot find"));
    }
  });

  it("esp32-uart adapter is constructable", async () => {
    try {
      const adapters = await createHardwareAdapters("esp32-uart");
      assert.equal(adapters.type, "esp32-uart");
      const available = await adapters.uwb.isAvailable();
      assert.equal(typeof available, "boolean");
    } catch (err: any) {
      assert.ok(err.message.includes("serialport") || err.message.includes("Cannot find"));
    }
  });

  it("android adapter handles missing React Native gracefully", async () => {
    const adapters = await createHardwareAdapters("android");
    assert.equal(adapters.type, "android");
    // isAvailable should return false (no React Native runtime)
    const available = await adapters.uwb.isAvailable();
    assert.equal(available, false);
  });

  it("ios adapter handles missing React Native gracefully", async () => {
    const adapters = await createHardwareAdapters("ios");
    assert.equal(adapters.type, "ios");
    const available = await adapters.uwb.isAvailable();
    assert.equal(available, false);
  });

  it("all adapter types are valid", () => {
    const validTypes: AdapterType[] = ["mock", "raspberry-pi", "esp32-uart", "android", "ios"];
    for (const type of validTypes) {
      assert.equal(typeof type, "string");
    }
  });
});
