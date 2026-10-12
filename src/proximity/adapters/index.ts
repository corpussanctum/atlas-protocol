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
 * ESP32 is never auto-selected — any USB serial device would match — so it
 * requires ATLAS_HARDWARE_ADAPTER=esp32-uart.
 *
 * An unrecognized ATLAS_HARDWARE_ADAPTER value throws rather than silently
 * falling back to mock drivers.
 */

import { existsSync, readFileSync } from "node:fs";
import type { UWBDriver, BLEDriver, NFCDriver } from "../types.js";
import { MockUWBDriver, MockBLEDriver, MockNFCDriver } from "../hardware.js";

// ---------------------------------------------------------------------------
// Adapter types
// ---------------------------------------------------------------------------

export type AdapterType = "mock" | "raspberry-pi" | "esp32-uart" | "android" | "ios";

export const ADAPTER_TYPES: readonly AdapterType[] = ["mock", "raspberry-pi", "esp32-uart", "android", "ios"];

/** How the adapter type was chosen. */
export type AdapterSource = "override" | "env" | "auto-detect" | "default";

export interface HardwareAdapterSet {
  type: AdapterType;
  source: AdapterSource;
  uwb: UWBDriver;
  ble: BLEDriver;
  nfc: NFCDriver;
}

type DriverSet = Omit<HardwareAdapterSet, "type" | "source">;

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create the hardware adapter set for the current platform.
 *
 * @param override - Force a specific adapter type (ignores env/auto-detect)
 * @returns UWB, BLE, and NFC drivers for the selected platform
 * @throws if ATLAS_HARDWARE_ADAPTER names an unknown adapter, or the
 *   selected platform's drivers cannot be loaded
 */
export async function createHardwareAdapters(
  override?: AdapterType,
): Promise<HardwareAdapterSet> {
  const { type, source } = override
    ? { type: override, source: "override" as const }
    : detectAdapterType();

  let drivers: DriverSet;
  switch (type) {
    case "raspberry-pi":
      drivers = await createRaspberryPiAdapters();
      break;
    case "esp32-uart":
      drivers = await createESP32Adapters();
      break;
    case "android":
      drivers = await createAndroidAdapters();
      break;
    case "ios":
      drivers = await createIOSAdapters();
      break;
    case "mock":
    default:
      drivers = {
        uwb: new MockUWBDriver(),
        ble: new MockBLEDriver(),
        nfc: new MockNFCDriver(),
      };
  }
  return { type, source, ...drivers };
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

function detectAdapterType(): { type: AdapterType; source: AdapterSource } {
  // 1. Explicit env var — a typo must not silently degrade to mock drivers
  const envAdapter = process.env.ATLAS_HARDWARE_ADAPTER?.trim().toLowerCase();
  if (envAdapter) {
    if (!isValidAdapter(envAdapter)) {
      throw new Error(
        `Unknown ATLAS_HARDWARE_ADAPTER "${envAdapter}" (expected one of: ${ADAPTER_TYPES.join(", ")})`,
      );
    }
    return { type: envAdapter, source: "env" };
  }

  // 2. Platform auto-detection
  if (process.platform === "linux" && detectRaspberryPiUWB()) {
    return { type: "raspberry-pi", source: "auto-detect" };
  }

  // 3. Default to mock
  return { type: "mock", source: "default" };
}

function detectRaspberryPiUWB(): boolean {
  try {
    if (!existsSync("/proc/device-tree/model")) return false;
    const model = readFileSync("/proc/device-tree/model", "utf-8");
    // UWB hardware on UART or SPI
    return model.includes("Raspberry Pi") &&
      (existsSync("/dev/ttyS0") || existsSync("/dev/spidev0.0"));
  } catch {
    return false;
  }
}

function isValidAdapter(value: string): value is AdapterType {
  return (ADAPTER_TYPES as readonly string[]).includes(value);
}

// ---------------------------------------------------------------------------
// Platform-specific factory functions
// ---------------------------------------------------------------------------

async function createRaspberryPiAdapters(): Promise<DriverSet> {
  // Dynamic import so serialport is only loaded when needed
  const { RaspberryPiUWBDriver, RaspberryPiBLEDriver } = await import("./raspberry-pi.js");
  return {
    uwb: new RaspberryPiUWBDriver(),
    ble: new RaspberryPiBLEDriver(),
    nfc: new MockNFCDriver(), // NFC via USB reader — future adapter
  };
}

async function createESP32Adapters(): Promise<DriverSet> {
  const { ESP32UWBDriver } = await import("./esp32-uart.js");
  return {
    uwb: new ESP32UWBDriver(),
    ble: new MockBLEDriver(), // ESP32 handles BLE internally; host uses mock for scanning
    nfc: new MockNFCDriver(),
  };
}

async function createAndroidAdapters(): Promise<DriverSet> {
  const { AndroidUWBDriver, AndroidBLEDriver } = await import("./android-jetpack.js");
  return {
    uwb: new AndroidUWBDriver(),
    ble: new AndroidBLEDriver(),
    nfc: new MockNFCDriver(), // Android NFC adapter — future
  };
}

async function createIOSAdapters(): Promise<DriverSet> {
  const { IOSUWBDriver, IOSBLEDriver } = await import("./ios-nearby.js");
  return {
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
