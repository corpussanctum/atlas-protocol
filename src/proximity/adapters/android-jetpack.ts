/**
 * Atlas Protocol — Android UWB Adapter (Jetpack)
 *
 * React Native / Capacitor bridge stub for Android's UWB Jetpack API
 * (androidx.core.uwb, FiRa 3.0+). Works on supported devices:
 *   - Google Pixel 6 Pro+, Pixel 7+, Pixel 8+
 *   - Samsung Galaxy S21 Ultra+, Z Fold 3+, Note 20 Ultra
 *   - Most 2024+ Android flagships with UWB chipsets
 *
 * This module provides the TypeScript interface. The actual UWB calls are
 * bridged to Kotlin via React Native Native Modules or Capacitor plugins.
 *
 * Setup:
 *   1. Add `react-native-uwb` to your RN project (or Capacitor equivalent)
 *   2. Set ATLAS_HARDWARE_ADAPTER=android
 *   3. The native module handles permissions (NEARBY_WIFI_DEVICES, UWB_RANGING)
 *
 * Native module expected interface (Kotlin/Java side):
 *   NativeModules.AtlasUWB.isAvailable(): Promise<boolean>
 *   NativeModules.AtlasUWB.range(peerId, challengeHex, stsEnabled): Promise<RangeResult>
 *   NativeModules.AtlasUWB.send(peerId, dataHex): Promise<void>
 *   NativeModules.AtlasUWB.receive(peerId, timeoutMs): Promise<string>
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
// React Native bridge type (dynamically imported)
// ---------------------------------------------------------------------------

interface NativeUWBModule {
  isAvailable(): Promise<boolean>;
  range(peerId: string, challengeHex: string, stsEnabled: boolean): Promise<{
    distance: number;
    quality: number;
    stsValid: boolean;
    rounds: number;
  }>;
  send(peerId: string, dataHex: string): Promise<void>;
  receive(peerId: string, timeoutMs: number): Promise<string>;
}

interface NativeBLEModule {
  isAvailable(): Promise<boolean>;
  startAdvertising(serviceUuid: string, dataHex: string): Promise<void>;
  stopAdvertising(): Promise<void>;
  scan(durationMs: number, filterUuid: string): Promise<Array<{
    deviceId: string;
    rssi: number;
    serviceData: string;
  }>>;
  getRssi(deviceId: string): Promise<number>;
}

// ---------------------------------------------------------------------------
// Android UWB Driver
// ---------------------------------------------------------------------------

export class AndroidUWBDriver implements UWBDriver {
  private native: NativeUWBModule | null = null;

  private async getNative(): Promise<NativeUWBModule> {
    if (this.native) return this.native;
    try {
      // Dynamic import — only available in React Native runtime
      const { NativeModules } = await import("react-native" as string);
      this.native = NativeModules.AtlasUWB as NativeUWBModule;
      if (!this.native) throw new Error("AtlasUWB native module not found");
      return this.native;
    } catch {
      throw new Error(
        "Android UWB requires React Native with the AtlasUWB native module. " +
        "See atlas-protocol/examples/android/ for setup instructions."
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
      roundsCompleted: result.rounds,
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
// Android BLE Driver
// ---------------------------------------------------------------------------

export class AndroidBLEDriver implements BLEDriver {
  private native: NativeBLEModule | null = null;

  private async getNative(): Promise<NativeBLEModule> {
    if (this.native) return this.native;
    try {
      const { NativeModules } = await import("react-native" as string);
      this.native = NativeModules.AtlasBLE as NativeBLEModule;
      if (!this.native) throw new Error("AtlasBLE native module not found");
      return this.native;
    } catch {
      throw new Error(
        "Android BLE requires React Native with the AtlasBLE native module."
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
