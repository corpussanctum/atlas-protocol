/**
 * Atlas Protocol — ESP32 UWB UART Adapter
 *
 * STATUS: UNTESTED REFERENCE DRIVER — structured against datasheet specs
 * but never validated against real hardware. Do not assume production
 * readiness without physical testing. The companion bridge firmware
 * (see examples/hardware/esp32-uwb-bridge/ README) has not been built.
 *
 * Adapter for ESP32-based UWB boards connected via USB serial:
 *   - Makerfabs ESP32 UWB (DW3000, ~$30)
 *   - Ai-Thinker BW16-Kit (DW1000, ~$20)
 *
 * The ESP32 runs a thin bridge firmware that exposes a simple
 * JSON-over-UART protocol:
 *
 *   Host → ESP32: {"cmd":"range","peer":"<id>","challenge":"<hex>","sts":true}
 *   ESP32 → Host: {"dist":3.21,"quality":92,"sts_ok":true,"rounds":3}
 *
 * Requires: `npm install serialport` (optional peer dep)
 */

import { randomBytes } from "node:crypto";
import type {
  UWBDriver,
  UWBRangingResult,
} from "../types.js";

// ---------------------------------------------------------------------------
// ESP32 Bridge Protocol
// ---------------------------------------------------------------------------

interface ESP32Command {
  cmd: "range" | "status" | "data_send" | "data_recv";
  peer?: string;
  challenge?: string;
  sts?: boolean;
  data?: string;
  timeout?: number;
}

interface ESP32RangeResponse {
  dist: number;
  quality: number;
  sts_ok: boolean;
  rounds: number;
  error?: string;
}

interface ESP32StatusResponse {
  ready: boolean;
  chip: string;
  firmware: string;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface ESP32UWBConfig {
  /** USB serial port path (auto-detected on Linux: /dev/ttyUSB0 or /dev/ttyACM0) */
  serialPath: string;
  /** Baud rate (default: 115200) */
  baudRate: number;
  /** Command timeout in ms */
  commandTimeoutMs: number;
  /** Auto-detect serial port */
  autoDetect: boolean;
}

const DEFAULT_ESP32_CONFIG: ESP32UWBConfig = {
  serialPath: "/dev/ttyUSB0",
  baudRate: 115200,
  commandTimeoutMs: 3000,
  autoDetect: true,
};

// ---------------------------------------------------------------------------
// ESP32 UWB Driver
// ---------------------------------------------------------------------------

export class ESP32UWBDriver implements UWBDriver {
  private config: ESP32UWBConfig;
  private port: any = null;
  private lineBuffer = "";

  constructor(config: Partial<ESP32UWBConfig> = {}) {
    this.config = { ...DEFAULT_ESP32_CONFIG, ...config };
  }

  async isAvailable(): Promise<boolean> {
    try {
      const path = this.config.autoDetect
        ? await this.detectSerialPort()
        : this.config.serialPath;

      if (!path) return false;

      const { existsSync } = await import("node:fs");
      return existsSync(path);
    } catch {
      return false;
    }
  }

  private async detectSerialPort(): Promise<string | null> {
    try {
      const { readdirSync } = await import("node:fs");
      const devices = readdirSync("/dev").filter(
        (d) => d.startsWith("ttyUSB") || d.startsWith("ttyACM"),
      );
      if (devices.length > 0) {
        this.config.serialPath = `/dev/${devices[0]}`;
        return this.config.serialPath;
      }
      return null;
    } catch {
      return null;
    }
  }

  private async ensurePort(): Promise<void> {
    if (this.port) return;

    if (this.config.autoDetect) {
      const detected = await this.detectSerialPort();
      if (!detected) throw new Error("No ESP32 UWB device found on USB");
    }

    try {
      const { SerialPort } = await import("serialport" as string);
      this.port = new SerialPort({
        path: this.config.serialPath,
        baudRate: this.config.baudRate,
        autoOpen: false,
      });

      await new Promise<void>((resolve, reject) => {
        this.port.open((err: Error | null) => {
          if (err) reject(new Error(`Failed to open ESP32 at ${this.config.serialPath}: ${err.message}`));
          else resolve();
        });
      });

      // Wait for ESP32 boot + ready signal
      await this.waitForReady();
    } catch (err: any) {
      throw new Error(
        `ESP32 UWB unavailable. Install serialport: npm install serialport\n${err.message}`
      );
    }
  }

  private async waitForReady(): Promise<void> {
    const status = await this.sendCommand<ESP32StatusResponse>({ cmd: "status" });
    if (!status.ready) {
      throw new Error(`ESP32 not ready: chip=${status.chip} fw=${status.firmware}`);
    }
  }

  private async sendCommand<T>(cmd: ESP32Command): Promise<T> {
    await this.ensurePort();
    const json = JSON.stringify(cmd) + "\n";

    return new Promise<T>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.port.removeListener("data", onData);
        reject(new Error(`ESP32 command timeout: ${cmd.cmd}`));
      }, this.config.commandTimeoutMs);

      const onData = (data: Buffer) => {
        this.lineBuffer += data.toString();
        const newlineIdx = this.lineBuffer.indexOf("\n");
        if (newlineIdx !== -1) {
          const line = this.lineBuffer.slice(0, newlineIdx).trim();
          this.lineBuffer = this.lineBuffer.slice(newlineIdx + 1);
          clearTimeout(timeout);
          this.port.removeListener("data", onData);
          try {
            const parsed = JSON.parse(line) as T;
            resolve(parsed);
          } catch {
            reject(new Error(`Invalid ESP32 response: ${line}`));
          }
        }
      };

      this.port.on("data", onData);
      this.port.write(json);
    });
  }

  async range(
    deviceId: string,
    options: { stsEnabled: boolean; challenge: Uint8Array },
  ): Promise<UWBRangingResult> {
    const response = await this.sendCommand<ESP32RangeResponse>({
      cmd: "range",
      peer: deviceId,
      challenge: Buffer.from(options.challenge).toString("hex"),
      sts: options.stsEnabled,
    });

    if (response.error) {
      throw new Error(`ESP32 ranging error: ${response.error}`);
    }

    return {
      distanceMeters: response.dist,
      stsEnabled: response.sts_ok && options.stsEnabled,
      timestamp: new Date().toISOString(),
      challenge: options.challenge,
      remoteDeviceId: deviceId,
      signalQuality: response.quality,
      roundsCompleted: response.rounds,
    };
  }

  async send(deviceId: string, data: Uint8Array): Promise<void> {
    await this.sendCommand({
      cmd: "data_send",
      peer: deviceId,
      data: Buffer.from(data).toString("hex"),
    });
  }

  async receive(deviceId: string, timeoutMs: number): Promise<Uint8Array> {
    const response = await this.sendCommand<{ data: string }>({
      cmd: "data_recv",
      peer: deviceId,
      timeout: timeoutMs,
    });
    return Buffer.from(response.data, "hex");
  }

  /** Clean up serial port */
  async close(): Promise<void> {
    if (this.port?.isOpen) {
      await new Promise<void>((resolve) => this.port.close(() => resolve()));
      this.port = null;
    }
  }
}
