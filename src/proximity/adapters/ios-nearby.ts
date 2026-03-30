/**
 * Atlas Protocol — iOS UWB Adapter (Nearby Interaction)
 *
 * React Native / Capacitor bridge stub for Apple's Nearby Interaction
 * framework (NINearbyObject). Works on:
 *   - iPhone 11+ (U1 chip)
 *   - iPhone 15 Pro+ (U2 chip, FiRa 3.0 compatible)
 *   - Apple Watch Ultra 1/2
 *
 * This module provides the TypeScript interface. The actual UWB calls are
 * bridged to Swift via React Native Native Modules or Expo Modules.
 *
 * Setup:
 *   1. Add the Atlas iOS native module to your RN/Expo project
 *   2. Set ATLAS_HARDWARE_ADAPTER=ios
 *   3. Add NSNearbyInteractionUsageDescription to Info.plist
 *   4. For BLE: add NSBluetoothAlwaysUsageDescription to Info.plist
 *
 * Native module expected interface (Swift side):
 *   AtlasUWB.isAvailable() -> Promise<Bool>
 *   AtlasUWB.range(peerId: String, challengeHex: String, stsEnabled: Bool) -> Promise<RangeResult>
 *   AtlasUWB.send(peerId: String, dataHex: String) -> Promise<Void>
 *   AtlasUWB.receive(peerId: String, timeoutMs: Int) -> Promise<String>
 *
 * Note: Apple's NI framework requires a "session token" exchange before
 * ranging. The native module handles this via the MultipeerConnectivity
 * framework (or your existing BLE channel) as the out-of-band transport.
 */

import type {
  UWBDriver,
  BLEDriver,
  UWBRangingResult,
  BLERangingResult,
  BLEAdvertisement,
  DiscoveredPeer,
} from "../types.js";

// ---------------------------------------------------------------------------
// React Native bridge types
// ---------------------------------------------------------------------------

interface NativeIOSUWBModule {
  isAvailable(): Promise<boolean>;
  range(peerId: string, challengeHex: string, stsEnabled: boolean): Promise<{
    distance: number;
    direction: { x: number; y: number; z: number }; // Apple provides 3D direction
    quality: number;
    stsValid: boolean;
  }>;
  send(peerId: string, dataHex: string): Promise<void>;
  receive(peerId: string, timeoutMs: number): Promise<string>;
}

interface NativeIOSBLEModule {
  isAvailable(): Promise<boolean>;
  startAdvertising(serviceUuid: string, dataHex: string): Promise<void>;
  stopAdvertising(): Promise<void>;
  scan(durationMs: number, filterUuid: string): Promise<Array<{
    deviceId: string; // CBPeripheral identifier
    rssi: number;
    serviceData: string;
  }>>;
  getRssi(deviceId: string): Promise<number>;
}

// ---------------------------------------------------------------------------
// iOS UWB Driver
// ---------------------------------------------------------------------------

export class IOSUWBDriver implements UWBDriver {
  private native: NativeIOSUWBModule | null = null;

  private async getNative(): Promise<NativeIOSUWBModule> {
    if (this.native) return this.native;
    try {
      const { NativeModules } = await import("react-native" as string);
      this.native = NativeModules.AtlasUWB as NativeIOSUWBModule;
      if (!this.native) throw new Error("AtlasUWB native module not found");
      return this.native;
    } catch {
      throw new Error(
        "iOS UWB requires React Native with the AtlasUWB native module. " +
        "See atlas-protocol/examples/ios/ for setup instructions."
      );
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      const native = await this.getNative();
      return native.isAvailable();
    } catch {
      return false;
    }
  }

  async range(
    deviceId: string,
    options: { stsEnabled: boolean; challenge: Uint8Array },
  ): Promise<UWBRangingResult> {
    const native = await this.getNative();
    const challengeHex = Buffer.from(options.challenge).toString("hex");
    const result = await native.range(deviceId, challengeHex, options.stsEnabled);

    return {
      distanceMeters: result.distance,
      stsEnabled: result.stsValid && options.stsEnabled,
      timestamp: new Date().toISOString(),
      challenge: options.challenge,
      remoteDeviceId: deviceId,
      signalQuality: result.quality,
      roundsCompleted: 1, // Apple NI returns continuous updates, we take one
    };
  }

  async send(deviceId: string, data: Uint8Array): Promise<void> {
    const native = await this.getNative();
    await native.send(deviceId, Buffer.from(data).toString("hex"));
  }

  async receive(deviceId: string, timeoutMs: number): Promise<Uint8Array> {
    const native = await this.getNative();
    const hex = await native.receive(deviceId, timeoutMs);
    return Buffer.from(hex, "hex");
  }
}

// ---------------------------------------------------------------------------
// iOS BLE Driver
// ---------------------------------------------------------------------------

export class IOSBLEDriver implements BLEDriver {
  private native: NativeIOSBLEModule | null = null;

  private async getNative(): Promise<NativeIOSBLEModule> {
    if (this.native) return this.native;
    try {
      const { NativeModules } = await import("react-native" as string);
      this.native = NativeModules.AtlasBLE as NativeIOSBLEModule;
      if (!this.native) throw new Error("AtlasBLE native module not found");
      return this.native;
    } catch {
      throw new Error(
        "iOS BLE requires React Native with the AtlasBLE native module."
      );
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      const native = await this.getNative();
      return native.isAvailable();
    } catch {
      return false;
    }
  }

  async startAdvertising(advertisement: BLEAdvertisement): Promise<void> {
    const native = await this.getNative();
    const dataHex = Buffer.from(advertisement.ephemeralPublicKey).toString("hex");
    await native.startAdvertising(advertisement.serviceUuid, dataHex);
  }

  async stopAdvertising(): Promise<void> {
    try {
      const native = await this.getNative();
      await native.stopAdvertising();
    } catch { /* best effort */ }
  }

  async scan(durationMs: number): Promise<DiscoveredPeer[]> {
    const native = await this.getNative();
    const { ATLAS_PROXIMITY_SERVICE_UUID } = await import("../hardware.js");
    const results = await native.scan(durationMs, ATLAS_PROXIMITY_SERVICE_UUID);

    return results.map((r) => ({
      deviceId: r.deviceId,
      agentIdHash: r.serviceData.slice(0, 16),
      ephemeralPublicKey: Buffer.from(r.serviceData.slice(16), "hex"),
      supportedMethods: ["uwb-sts" as const, "ble-rssi" as const],
      maxRangeMeters: 10,
      estimatedDistanceMeters: estimateDistanceFromRssi(r.rssi),
      discoveredAt: new Date().toISOString(),
    }));
  }

  async estimateDistance(deviceId: string): Promise<BLERangingResult> {
    const native = await this.getNative();
    const rssi = await native.getRssi(deviceId);
    const txPower = -59;
    return {
      distanceMeters: estimateDistanceFromRssi(rssi),
      rssi,
      txPower,
      timestamp: new Date().toISOString(),
      remoteAddress: deviceId,
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function estimateDistanceFromRssi(rssi: number, txPower: number = -59): number {
  if (rssi >= 0) return -1;
  const ratio = (txPower - rssi) / (10 * 2.5);
  return Math.round(Math.pow(10, ratio) * 100) / 100;
}
