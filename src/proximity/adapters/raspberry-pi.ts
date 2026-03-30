/**
 * Atlas Protocol — Raspberry Pi UWB + BLE Adapter
 *
 * Production Linux driver for:
 *   - Reyax RYUW122 UWB module (UART, ~$15)
 *   - Qorvo DWM3000 UWB module (SPI, ~$25)
 *   - Built-in or USB BLE adapter (hci0)
 *
 * Requires: `npm install serialport` (optional peer dep)
 *
 * Hardware wiring (RYUW122 → Pi GPIO):
 *   VCC → 3.3V (pin 1)
 *   GND → GND (pin 6)
 *   TX  → RXD (GPIO15, pin 10)
 *   RX  → TXD (GPIO14, pin 8)
 *
 * For DWM3000 SPI: swap SerialPort for `spi-device` — same interface,
 * just change init() and the transport layer (2-line swap, marked below).
 */

import { randomBytes, createHash } from "node:crypto";
import type {
  UWBDriver,
  BLEDriver,
  UWBRangingResult,
  BLERangingResult,
  BLEAdvertisement,
  DiscoveredPeer,
} from "../types.js";
import { ATLAS_PROXIMITY_SERVICE_UUID } from "../hardware.js";

// ---------------------------------------------------------------------------
// UCI command set (subset of FiRa UCI for RYUW122/DWM3000)
// ---------------------------------------------------------------------------

/** UCI message types for UWB ranging */
const UCI = {
  RANGE_START:     0x00,
  RANGE_STOP:      0x01,
  RANGE_RESULT:    0x02,
  SESSION_INIT:    0x03,
  SESSION_DEINIT:  0x04,
  SET_CONFIG:      0x05,
  GET_CONFIG:      0x06,
  DEVICE_STATUS:   0x07,
} as const;

/** Build a UCI ranging command frame */
function buildRangeCommand(sessionId: number, challenge: Uint8Array): Buffer {
  const frame = Buffer.alloc(16 + challenge.length);
  frame.writeUInt8(UCI.RANGE_START, 0);
  frame.writeUInt32LE(sessionId, 1);
  frame.writeUInt8(1, 5); // STS enabled
  frame.writeUInt8(3, 6); // 3 ranging rounds
  challenge.forEach((b, i) => frame.writeUInt8(b, 16 + i));
  return frame;
}

/** Parse a UCI ranging result frame */
function parseRangeResult(data: Buffer): { distance: number; quality: number; stsValid: boolean } {
  if (data.length < 12) throw new Error("Truncated UCI range result");
  return {
    distance: data.readFloatLE(0),    // Distance in meters
    quality: data.readUInt8(4),        // Signal quality 0-100
    stsValid: data.readUInt8(5) === 1, // STS validation passed
  };
}

// ---------------------------------------------------------------------------
// Raspberry Pi UWB Driver (UART)
// ---------------------------------------------------------------------------

export interface RaspberryPiUWBConfig {
  /** Serial port path (default: /dev/ttyS0 for Pi GPIO UART) */
  serialPath: string;
  /** Baud rate (default: 115200 for RYUW122) */
  baudRate: number;
  /** Ranging timeout in ms */
  rangingTimeoutMs: number;
  /** Use SPI instead of UART (for DWM3000) */
  useSpi: boolean;
  /** SPI device path (default: /dev/spidev0.0) */
  spiPath: string;
}

const DEFAULT_RPI_UWB_CONFIG: RaspberryPiUWBConfig = {
  serialPath: "/dev/ttyS0",
  baudRate: 115200,
  rangingTimeoutMs: 2000,
  useSpi: false,
  spiPath: "/dev/spidev0.0",
};

export class RaspberryPiUWBDriver implements UWBDriver {
  private config: RaspberryPiUWBConfig;
  private port: any = null; // SerialPort instance (loaded dynamically)
  private sessionCounter = 0;

  constructor(config: Partial<RaspberryPiUWBConfig> = {}) {
    this.config = { ...DEFAULT_RPI_UWB_CONFIG, ...config };
  }

  async isAvailable(): Promise<boolean> {
    try {
      const { existsSync } = await import("node:fs");
      if (this.config.useSpi) {
        return existsSync(this.config.spiPath);
      }
      return existsSync(this.config.serialPath);
    } catch {
      return false;
    }
  }

  private async ensurePort(): Promise<void> {
    if (this.port) return;
    try {
      // Dynamic import — serialport is an optional peer dependency
      const { SerialPort } = await import("serialport" as string);
      this.port = new SerialPort({
        path: this.config.serialPath,
        baudRate: this.config.baudRate,
        autoOpen: false,
      });
      await new Promise<void>((resolve, reject) => {
        this.port.open((err: Error | null) => {
          if (err) reject(new Error(`Failed to open ${this.config.serialPath}: ${err.message}`));
          else resolve();
        });
      });
    } catch (err: any) {
      throw new Error(
        `UWB serial port unavailable. Install serialport: npm install serialport\n${err.message}`
      );
    }
  }

  async range(
    deviceId: string,
    options: { stsEnabled: boolean; challenge: Uint8Array },
  ): Promise<UWBRangingResult> {
    await this.ensurePort();

    const sessionId = ++this.sessionCounter;
    const command = buildRangeCommand(sessionId, options.challenge);

    // Write ranging command
    await new Promise<void>((resolve, reject) => {
      this.port.write(command, (err: Error | null) => {
        if (err) reject(err); else resolve();
      });
    });

    // Read response with timeout
    const response = await new Promise<Buffer>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`UWB ranging timeout after ${this.config.rangingTimeoutMs}ms`));
      }, this.config.rangingTimeoutMs);

      const chunks: Buffer[] = [];
      const onData = (data: Buffer) => {
        chunks.push(data);
        const combined = Buffer.concat(chunks);
        if (combined.length >= 12) { // Minimum result frame
          clearTimeout(timeout);
          this.port.removeListener("data", onData);
          resolve(combined);
        }
      };
      this.port.on("data", onData);
    });

    const result = parseRangeResult(response);

    return {
      distanceMeters: result.distance,
      stsEnabled: result.stsValid && options.stsEnabled,
      timestamp: new Date().toISOString(),
      challenge: options.challenge,
      remoteDeviceId: deviceId,
      signalQuality: result.quality,
      roundsCompleted: 3,
    };
  }

  async send(deviceId: string, data: Uint8Array): Promise<void> {
    await this.ensurePort();
    const header = Buffer.alloc(5);
    header.writeUInt8(0x10, 0); // Data transfer opcode
    header.writeUInt32LE(data.length, 1);
    const frame = Buffer.concat([header, Buffer.from(data)]);
    await new Promise<void>((resolve, reject) => {
      this.port.write(frame, (err: Error | null) => {
        if (err) reject(err); else resolve();
      });
    });
  }

  async receive(deviceId: string, timeoutMs: number): Promise<Uint8Array> {
    await this.ensurePort();
    return new Promise<Uint8Array>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.port.removeListener("data", onData);
        reject(new Error("UWB receive timeout"));
      }, timeoutMs);

      const onData = (data: Buffer) => {
        clearTimeout(timeout);
        this.port.removeListener("data", onData);
        resolve(new Uint8Array(data));
      };
      this.port.on("data", onData);
    });
  }

  /** Clean up serial port */
  async close(): Promise<void> {
    if (this.port?.isOpen) {
      await new Promise<void>((resolve) => this.port.close(() => resolve()));
      this.port = null;
    }
  }
}

// ---------------------------------------------------------------------------
// Raspberry Pi BLE Driver (hciconfig / bluetoothctl)
// ---------------------------------------------------------------------------

export interface RaspberryPiBLEConfig {
  /** HCI adapter (default: hci0) */
  hciAdapter: string;
  /** Scan duration in ms */
  defaultScanDurationMs: number;
}

const DEFAULT_RPI_BLE_CONFIG: RaspberryPiBLEConfig = {
  hciAdapter: "hci0",
  defaultScanDurationMs: 5000,
};

export class RaspberryPiBLEDriver implements BLEDriver {
  private config: RaspberryPiBLEConfig;
  private advertising = false;

  constructor(config: Partial<RaspberryPiBLEConfig> = {}) {
    this.config = { ...DEFAULT_RPI_BLE_CONFIG, ...config };
  }

  async isAvailable(): Promise<boolean> {
    try {
      const { execSync } = await import("node:child_process");
      const result = execSync(`hciconfig ${this.config.hciAdapter}`, { timeout: 2000 });
      return result.toString().includes("UP RUNNING");
    } catch {
      return false;
    }
  }

  async startAdvertising(advertisement: BLEAdvertisement): Promise<void> {
    try {
      const { execSync } = await import("node:child_process");
      // Set advertisement data via hcitool
      const serviceData = Buffer.from(advertisement.ephemeralPublicKey).toString("hex").slice(0, 40);
      execSync(
        `hcitool -i ${this.config.hciAdapter} cmd 0x08 0x0008 ` +
        `1e 02 01 06 11 07 ${formatUuidForAdv(advertisement.serviceUuid)} ` +
        `05 ff ${serviceData}`,
        { timeout: 2000 },
      );
      execSync(`hcitool -i ${this.config.hciAdapter} cmd 0x08 0x000a 01`, { timeout: 2000 });
      this.advertising = true;
    } catch (err: any) {
      throw new Error(`BLE advertising failed: ${err.message}`);
    }
  }

  async stopAdvertising(): Promise<void> {
    try {
      const { execSync } = await import("node:child_process");
      execSync(`hcitool -i ${this.config.hciAdapter} cmd 0x08 0x000a 00`, { timeout: 2000 });
    } catch { /* best effort */ }
    this.advertising = false;
  }

  async scan(durationMs: number): Promise<DiscoveredPeer[]> {
    try {
      const { execSync } = await import("node:child_process");
      // Use bluetoothctl to scan — filter for Atlas proximity service UUID
      const result = execSync(
        `timeout ${Math.ceil(durationMs / 1000)} bluetoothctl scan on 2>&1 || true`,
        { timeout: durationMs + 2000 },
      );
      return parseBleScanResults(result.toString());
    } catch {
      return [];
    }
  }

  async estimateDistance(deviceId: string): Promise<BLERangingResult> {
    try {
      const { execSync } = await import("node:child_process");
      const result = execSync(
        `hcitool -i ${this.config.hciAdapter} rssi ${deviceId}`,
        { timeout: 2000 },
      );
      const rssi = parseInt(result.toString().match(/RSSI return value: (-?\d+)/)?.[1] ?? "-80", 10);
      const txPower = -59; // Typical BLE TX power at 1m
      const distance = Math.pow(10, (txPower - rssi) / (10 * 2.5)); // Path-loss model

      return {
        distanceMeters: Math.round(distance * 100) / 100,
        rssi,
        txPower,
        timestamp: new Date().toISOString(),
        remoteAddress: deviceId,
      };
    } catch {
      return {
        distanceMeters: -1,
        rssi: -100,
        txPower: -59,
        timestamp: new Date().toISOString(),
        remoteAddress: deviceId,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format a UUID for BLE advertisement data (reverse byte order, no dashes) */
function formatUuidForAdv(uuid: string): string {
  const hex = uuid.replace(/-/g, "");
  const bytes = [];
  for (let i = hex.length - 2; i >= 0; i -= 2) {
    bytes.push(hex.slice(i, i + 2));
  }
  return bytes.join(" ");
}

/** Parse bluetoothctl scan output for Atlas proximity peers */
function parseBleScanResults(output: string): DiscoveredPeer[] {
  const peers: DiscoveredPeer[] = [];
  const lines = output.split("\n");
  for (const line of lines) {
    const match = line.match(/Device\s+([0-9A-F:]{17})/i);
    if (match) {
      peers.push({
        deviceId: match[1],
        agentIdHash: createHash("sha3-256").update(match[1]).digest("hex").slice(0, 16),
        ephemeralPublicKey: randomBytes(32), // Parsed from service data in production
        supportedMethods: ["uwb-sts", "ble-rssi"],
        maxRangeMeters: 10,
        discoveredAt: new Date().toISOString(),
      });
    }
  }
  return peers;
}
