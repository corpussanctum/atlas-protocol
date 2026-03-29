/**
 * Atlas DIDComm Adapter — Peer Store Implementations
 *
 * Two implementations of the PeerStore interface:
 * - FilePeerStore: JSON file-backed with atomic writes and chmod 0600
 * - MockPeerStore: In-memory only, for tests
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { PeerBinding, PeerStore } from "./types.js";

// ---------------------------------------------------------------------------
// FilePeerStore — JSON file-backed persistence
// ---------------------------------------------------------------------------

export class FilePeerStore implements PeerStore {
  private readonly filePath: string;
  private readonly peers: Map<string, PeerBinding> = new Map();

  constructor(dataDir: string) {
    // Auto-create dataDir if missing
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    this.filePath = path.join(dataDir, "didcomm-peers.json");

    // Load existing file if present
    if (fs.existsSync(this.filePath)) {
      this.load();
    }
  }

  async get(peerDid: string): Promise<PeerBinding | undefined> {
    return this.peers.get(peerDid);
  }

  async put(peer: PeerBinding): Promise<void> {
    this.peers.set(peer.peerDid, peer);
    this.save();
  }

  async list(
    filter?: "all" | "approved" | "revoked" | "untrusted",
  ): Promise<PeerBinding[]> {
    const all = Array.from(this.peers.values());
    if (!filter || filter === "all") {
      return all;
    }
    return all.filter((p) => p.trustState === filter);
  }

  async delete(peerDid: string): Promise<void> {
    this.peers.delete(peerDid);
    this.save();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private load(): void {
    try {
      const raw = fs.readFileSync(this.filePath, "utf-8");
      const entries: PeerBinding[] = JSON.parse(raw);
      for (const entry of entries) {
        this.peers.set(entry.peerDid, entry);
      }
    } catch {
      // Corrupt or unreadable file — start with an empty store
      this.peers.clear();
    }
  }

  private save(): void {
    const tmpPath = this.filePath + ".tmp";
    const data = JSON.stringify(Array.from(this.peers.values()), null, 2);

    // Atomic write: write to .tmp, then rename
    fs.writeFileSync(tmpPath, data, { encoding: "utf-8", mode: 0o600 });
    fs.renameSync(tmpPath, this.filePath);
  }
}

// ---------------------------------------------------------------------------
// MockPeerStore — in-memory only (for tests)
// ---------------------------------------------------------------------------

export class MockPeerStore implements PeerStore {
  private readonly peers: Map<string, PeerBinding> = new Map();

  async get(peerDid: string): Promise<PeerBinding | undefined> {
    return this.peers.get(peerDid);
  }

  async put(peer: PeerBinding): Promise<void> {
    this.peers.set(peer.peerDid, peer);
  }

  async list(
    filter?: "all" | "approved" | "revoked" | "untrusted",
  ): Promise<PeerBinding[]> {
    const all = Array.from(this.peers.values());
    if (!filter || filter === "all") {
      return all;
    }
    return all.filter((p) => p.trustState === filter);
  }

  async delete(peerDid: string): Promise<void> {
    this.peers.delete(peerDid);
  }
}
