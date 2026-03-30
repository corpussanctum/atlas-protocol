/**
 * Atlas Protocol — Hardware Adapter Factory
 *
 * Auto-detects or manually selects the right UWB + BLE adapter based on
 * environment and available hardware. One env var to switch:
 *
 *   export ATLAS_HARDWARE_ADAPTER=mock|raspberry-pi|esp32-uart|android|ios
 *
 * Default: "mock" (zero-cost development, no hardware needed).
 * Auto-detection: if ATLAS_HARDWARE_ADAPTER is not set and the platform
 * looks like a Raspberry Pi with UWB hardware, auto-selects "raspberry-pi".
 */

import type { UWBDriver, BLEDriver, NFCDriver } from "../types.js";
import { MockUWBDriver, MockBLEDriver, MockNFCDriver } from "../hardware.js";

// ---------------------------------------------------------------------------
// Adapter types
// ---------------------------------------------------------------------------

export type AdapterType = "mock" | "raspberry-pi" | "esp32-uart" | "android" | "ios";

export interface HardwareAdapterSet {
  type: AdapterType;
  uwb: UWBDriver;
  ble: BLEDriver;
  nfc: NFCDriver;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create the hardware adapter set for the current platform.
 *
 * @param override - Force a specific adapter type (ignores env/auto-detect)
 * @returns UWB, BLE, and NFC drivers for the selected platform
 */
export async function createHardwareAdapters(
  override?: AdapterType,
): Promise<HardwareAdapterSet> {
  const type = override ?? detectAdapterType();

  switch (type) {
    case "raspberry-pi":
      return createRaspberryPiAdapters();
    case "esp32-uart":
      return createESP32Adapters();
    case "android":
      return createAndroidAdapters();
    case "ios":
      return createIOSAdapters();
    case "mock":
    default:
      return {
        type: "mock",
        uwb: new MockUWBDriver(),
        ble: new MockBLEDriver(),
        nfc: new MockNFCDriver(),
      };
  }
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

function detectAdapterType(): AdapterType {
  // 1. Explicit env var
  const envAdapter = process.env.ATLAS_HARDWARE_ADAPTER?.toLowerCase();
  if (envAdapter && isValidAdapter(envAdapter)) {
    return envAdapter;
  }

  // 2. Platform auto-detection
  if (typeof process !== "undefined" && process.platform === "linux") {
    return detectLinuxAdapter();
  }

  // 3. Default to mock
  return "mock";
}

function detectLinuxAdapter(): AdapterType {
  try {
    const { existsSync, readFileSync } = require("node:fs");

    // Check for Raspberry Pi
    if (existsSync("/proc/device-tree/model")) {
      const model = readFileSync("/proc/device-tree/model", "utf-8");
      if (model.includes("Raspberry Pi")) {
        // Check for UWB hardware on UART or SPI
        if (existsSync("/dev/ttyS0") || existsSync("/dev/spidev0.0")) {
          return "raspberry-pi";
        }
      }
    }

    // Check for ESP32 on USB
    const { readdirSync } = require("node:fs");
    const devices = readdirSync("/dev").filter(
      (d: string) => d.startsWith("ttyUSB") || d.startsWith("ttyACM"),
    );
    if (devices.length > 0) {
      return "esp32-uart";
    }
  } catch {
    // Fall through to mock
  }

  return "mock";
}

function isValidAdapter(value: string): value is AdapterType {
  return ["mock", "raspberry-pi", "esp32-uart", "android", "ios"].includes(value);
}

// ---------------------------------------------------------------------------
// Platform-specific factory functions
// ---------------------------------------------------------------------------

async function createRaspberryPiAdapters(): Promise<HardwareAdapterSet> {
  // Dynamic import so serialport is only loaded when needed
  const { RaspberryPiUWBDriver, RaspberryPiBLEDriver } = await import("./raspberry-pi.js");
  return {
    type: "raspberry-pi",
    uwb: new RaspberryPiUWBDriver(),
    ble: new RaspberryPiBLEDriver(),
    nfc: new MockNFCDriver(), // NFC via USB reader — future adapter
  };
}

async function createESP32Adapters(): Promise<HardwareAdapterSet> {
  const { ESP32UWBDriver } = await import("./esp32-uart.js");
  return {
    type: "esp32-uart",
    uwb: new ESP32UWBDriver(),
    ble: new MockBLEDriver(), // ESP32 handles BLE internally; host uses mock for scanning
    nfc: new MockNFCDriver(),
  };
}

async function createAndroidAdapters(): Promise<HardwareAdapterSet> {
  const { AndroidUWBDriver, AndroidBLEDriver } = await import("./android-jetpack.js");
  return {
    type: "android",
    uwb: new AndroidUWBDriver(),
    ble: new AndroidBLEDriver(),
    nfc: new MockNFCDriver(), // Android NFC adapter — future
  };
}

async function createIOSAdapters(): Promise<HardwareAdapterSet> {
  const { IOSUWBDriver, IOSBLEDriver } = await import("./ios-nearby.js");
  return {
    type: "ios",
    uwb: new IOSUWBDriver(),
    ble: new IOSBLEDriver(),
    nfc: new MockNFCDriver(), // iOS NFC adapter — future
  };
}

// ---------------------------------------------------------------------------
// Re-exports for convenience
// ---------------------------------------------------------------------------

export { RaspberryPiUWBDriver, RaspberryPiBLEDriver } from "./raspberry-pi.js";
export type { RaspberryPiUWBConfig, RaspberryPiBLEConfig } from "./raspberry-pi.js";
export { ESP32UWBDriver } from "./esp32-uart.js";
export type { ESP32UWBConfig } from "./esp32-uart.js";
export { AndroidUWBDriver, AndroidBLEDriver } from "./android-jetpack.js";
export { IOSUWBDriver, IOSBLEDriver } from "./ios-nearby.js";
