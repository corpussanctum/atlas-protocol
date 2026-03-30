/**
 * Atlas Protocol — Proximity Hardware Abstraction
 *
 * Platform adapters for UWB, BLE, and NFC. In production, these are backed by
 * real radio hardware (FiRa UWB, BLE 5.4, NFC). For testing and development,
 * the mock implementations simulate ranging with configurable parameters.
 *
 * Spec reference: SPEC.md § 13.2 (UWB IEEE 802.15.4z / FiRa Core 3.0+)
 */

import { randomBytes, randomUUID } from "node:crypto";
import type {
  UWBDriver,
  BLEDriver,
  NFCDriver,
  UWBRangingResult,
  BLERangingResult,
  BLEAdvertisement,
  DiscoveredPeer,
  NFCTapPayload,
} from "./types.js";

// ---------------------------------------------------------------------------
// Atlas BLE Service UUID (registered in spec)
// ---------------------------------------------------------------------------

export const ATLAS_PROXIMITY_SERVICE_UUID = "a71a5000-e2c0-4e9a-b8f3-d3a7c4e0f1b2";

// ---------------------------------------------------------------------------
// Mock UWB Driver — for testing and development
// ---------------------------------------------------------------------------

export interface MockUWBConfig {
  /** Simulated distance in meters */
  simulatedDistance: number;
  /** Simulated signal quality (0-100) */
  simulatedQuality: number;
  /** Whether to simulate STS support */
  stsSupported: boolean;
  /** Whether to simulate hardware failure */
  simulateFailure: boolean;
  /** Simulated latency in ms */
  latencyMs: number;
}

const DEFAULT_MOCK_UWB: MockUWBConfig = {
  simulatedDistance: 3.2,
  simulatedQuality: 92,
  stsSupported: true,
  simulateFailure: false,
  latencyMs: 15,
};

export class MockUWBDriver implements UWBDriver {
  private config: MockUWBConfig;

  constructor(config: Partial<MockUWBConfig> = {}) {
    this.config = { ...DEFAULT_MOCK_UWB, ...config };
  }

  async isAvailable(): Promise<boolean> {
    return !this.config.simulateFailure;
  }

  async range(
    deviceId: string,
    options: { stsEnabled: boolean; challenge: Uint8Array }
  ): Promise<UWBRangingResult> {
    if (this.config.simulateFailure) {
      throw new Error("UWB hardware unavailable");
    }

    // Simulate ranging latency
    if (this.config.latencyMs > 0) {
      await new Promise((r) => setTimeout(r, this.config.latencyMs));
    }

    return {
      distanceMeters: this.config.simulatedDistance,
      stsEnabled: this.config.stsSupported && options.stsEnabled,
      timestamp: new Date().toISOString(),
      challenge: options.challenge,
      remoteDeviceId: deviceId,
      signalQuality: this.config.simulatedQuality,
      roundsCompleted: 3,
    };
  }

  async send(_deviceId: string, _data: Uint8Array): Promise<void> {
    if (this.config.simulateFailure) throw new Error("UWB hardware unavailable");
  }

  async receive(_deviceId: string, _timeoutMs: number): Promise<Uint8Array> {
    if (this.config.simulateFailure) throw new Error("UWB hardware unavailable");
    return new Uint8Array(0);
  }

  /** Update simulation parameters at runtime (for testing) */
  setConfig(config: Partial<MockUWBConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

// ---------------------------------------------------------------------------
// Mock BLE Driver — for testing and development
// ---------------------------------------------------------------------------

export interface MockBLEConfig {
  /** Pre-configured peers that will appear during scans */
  simulatedPeers: DiscoveredPeer[];
  /** Whether to simulate hardware failure */
  simulateFailure: boolean;
}

const DEFAULT_MOCK_BLE: MockBLEConfig = {
  simulatedPeers: [],
  simulateFailure: false,
};

export class MockBLEDriver implements BLEDriver {
  private config: MockBLEConfig;
  private advertising = false;

  constructor(config: Partial<MockBLEConfig> = {}) {
    this.config = { ...DEFAULT_MOCK_BLE, ...config };
  }

  async isAvailable(): Promise<boolean> {
    return !this.config.simulateFailure;
  }

  async startAdvertising(_advertisement: BLEAdvertisement): Promise<void> {
    if (this.config.simulateFailure) throw new Error("BLE hardware unavailable");
    this.advertising = true;
  }

  async stopAdvertising(): Promise<void> {
    this.advertising = false;
  }

  async scan(_durationMs: number): Promise<DiscoveredPeer[]> {
    if (this.config.simulateFailure) throw new Error("BLE hardware unavailable");
    return this.config.simulatedPeers;
  }

  async estimateDistance(deviceId: string): Promise<BLERangingResult> {
    if (this.config.simulateFailure) throw new Error("BLE hardware unavailable");
    const peer = this.config.simulatedPeers.find((p) => p.deviceId === deviceId);
    return {
      distanceMeters: peer?.estimatedDistanceMeters ?? 5.0,
      rssi: -65,
      txPower: -59,
      timestamp: new Date().toISOString(),
      remoteAddress: deviceId,
    };
  }

  /** Add a simulated peer (for testing) */
  addPeer(peer: DiscoveredPeer): void {
    this.config.simulatedPeers.push(peer);
  }

  /** Check if currently advertising */
  isAdvertising(): boolean {
    return this.advertising;
  }
}

// ---------------------------------------------------------------------------
// Mock NFC Driver — for testing and development
// ---------------------------------------------------------------------------

export class MockNFCDriver implements NFCDriver {
  private pendingTap: NFCTapPayload | null = null;
  private available = true;

  constructor(available = true) {
    this.available = available;
  }

  async isAvailable(): Promise<boolean> {
    return this.available;
  }

  async writeTap(payload: NFCTapPayload): Promise<void> {
    if (!this.available) throw new Error("NFC hardware unavailable");
    this.pendingTap = payload;
  }

  async readTap(_timeoutMs: number): Promise<NFCTapPayload | null> {
    if (!this.available) throw new Error("NFC hardware unavailable");
    const tap = this.pendingTap;
    this.pendingTap = null;
    return tap;
  }

  /** Simulate an NFC tap from a remote agent (for testing) */
  simulateTap(payload: NFCTapPayload): void {
    this.pendingTap = payload;
  }
}

// ---------------------------------------------------------------------------
// Hardware availability detection
// ---------------------------------------------------------------------------

export interface HardwareAvailability {
  uwb: boolean;
  ble: boolean;
  nfc: boolean;
}

export async function detectHardware(
  uwb: UWBDriver,
  ble: BLEDriver,
  nfc: NFCDriver
): Promise<HardwareAvailability> {
  const [uwbAvail, bleAvail, nfcAvail] = await Promise.all([
    uwb.isAvailable().catch(() => false),
    ble.isAvailable().catch(() => false),
    nfc.isAvailable().catch(() => false),
  ]);
  return { uwb: uwbAvail, ble: bleAvail, nfc: nfcAvail };
}
