#!/usr/bin/env node

/**
 * Atlas Protocol — Physical Swarm Demo
 *
 * Runs a 3-agent proximity mesh swarm:
 *   Agent A (orchestrator) discovers B + C, establishes secure sessions,
 *   then delegates audio processing tasks with distance-aware parameters.
 *
 * Usage:
 *   # Mock hardware (default — works everywhere)
 *   npx tsx examples/swarm/run-swarm.ts
 *
 *   # Real hardware (Raspberry Pi with UWB)
 *   ATLAS_HARDWARE_ADAPTER=raspberry-pi npx tsx examples/swarm/run-swarm.ts
 *
 *   # ESP32 UWB boards on USB
 *   ATLAS_HARDWARE_ADAPTER=esp32-uart npx tsx examples/swarm/run-swarm.ts
 */

import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { bootAgentA, discoverAndConnect, delegateTask } from "./agent-a.js";
import { bootAgentB } from "./agent-b.js";
import { bootAgentC } from "./agent-c.js";
import { MockBLEDriver } from "../../src/proximity/hardware.js";
import { randomBytes } from "node:crypto";

async function main() {
  console.log("=== Atlas Protocol — Physical Swarm Demo ===\n");

  // Create isolated data dirs for each agent
  const baseDir = mkdtempSync(join(tmpdir(), "atlas-swarm-"));
  const dirA = join(baseDir, "agent-a");
  const dirB = join(baseDir, "agent-b");
  const dirC = join(baseDir, "agent-c");

  const { mkdirSync } = await import("node:fs");
  mkdirSync(dirA, { recursive: true });
  mkdirSync(dirB, { recursive: true });
  mkdirSync(dirC, { recursive: true });

  try {
    // --- Boot all three agents ---
    console.log("--- Booting agents ---\n");

    const [ctxB, ctxC] = await Promise.all([
      bootAgentB(dirB),
      bootAgentC(dirC),
    ]);

    // If using mock hardware, inject the other agents as simulated BLE peers
    const isMock = !process.env.ATLAS_HARDWARE_ADAPTER ||
                   process.env.ATLAS_HARDWARE_ADAPTER === "mock";

    const ctxA = await bootAgentA(dirA);

    if (isMock) {
      console.log("\n[Swarm] Using mock hardware — injecting simulated peers\n");
      // The mock BLE driver needs to know about agents B and C
      // In real hardware, BLE discovery handles this automatically
      const mockBle = (ctxA.mesh as any).deps.ble as MockBLEDriver;
      mockBle.addPeer({
        deviceId: "mock-agent-b",
        agentIdHash: ctxB.credential.agentId.slice(-16),
        ephemeralPublicKey: randomBytes(32),
        supportedMethods: ["uwb-sts"],
        maxRangeMeters: 10,
        estimatedDistanceMeters: 2.5,
        discoveredAt: new Date().toISOString(),
      });
      mockBle.addPeer({
        deviceId: "mock-agent-c",
        agentIdHash: ctxC.credential.agentId.slice(-16),
        ephemeralPublicKey: randomBytes(32),
        supportedMethods: ["uwb-sts"],
        maxRangeMeters: 10,
        estimatedDistanceMeters: 4.8,
        discoveredAt: new Date().toISOString(),
      });
    }

    // --- Discover and connect ---
    console.log("\n--- Establishing proximity mesh ---\n");

    const sessions = await discoverAndConnect(ctxA);
    console.log(`\n[Swarm] ${sessions.length} mesh sessions established\n`);

    // --- Delegate tasks ---
    console.log("--- Delegating tasks ---\n");

    for (const session of sessions) {
      const distance = session.proximityProof.distanceMeters;

      // Reverb intensity based on physical distance (closer = more intimate reverb)
      const reverbIntensity = Math.max(0.1, 1.0 - distance / 10);

      await delegateTask(ctxA, session, {
        type: "audio:apply-reverb",
        params: {
          intensity: reverbIntensity,
          distance,
          method: session.proximityProof.method,
          note: `Distance-aware reverb: ${distance}m → intensity ${reverbIntensity.toFixed(2)}`,
        },
      });
    }

    // --- Summary ---
    console.log("\n--- Swarm Summary ---\n");
    console.log(`  Agents:      3 (orchestrator + renderer + mixer)`);
    console.log(`  Sessions:    ${sessions.length}`);
    console.log(`  Auth method: ML-DSA-65 (post-quantum)`);
    console.log(`  Encryption:  AES-256-GCM over Noise IK`);
    for (const session of sessions) {
      console.log(
        `  Session ${session.sessionId.slice(0, 8)}... → ${session.remoteAgentId} ` +
        `at ${session.proximityProof.distanceMeters}m (${session.proximityProof.method})`
      );
    }

    // --- Cleanup ---
    console.log("\n--- Shutting down ---\n");
    await ctxA.mesh.shutdown();
    await ctxB.mesh.shutdown();
    await ctxC.mesh.shutdown();

    console.log("[Swarm] All agents shut down cleanly.");
    console.log(`[Swarm] Audit logs written to: ${baseDir}/`);

  } catch (err) {
    console.error("Swarm error:", err);
  } finally {
    // Leave the temp dir for audit inspection
    console.log(`\n[Swarm] Data directory: ${baseDir}`);
    console.log("[Swarm] Inspect audit trails with: cat <dir>/audit-agent-*.jsonl | jq .");
  }
}

main().catch(console.error);
