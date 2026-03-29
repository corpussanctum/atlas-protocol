import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { MockPeerStore, FilePeerStore } from "../src/peer-store.js";
import type { PeerBinding } from "../src/types.js";

function makePeer(overrides?: Partial<PeerBinding>): PeerBinding {
  return {
    peerDid: "did:peer:test-peer",
    trustState: "approved",
    allowedMessageTypes: [],
    allowedDirections: ["send", "receive"],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

describe("MockPeerStore", () => {
  let store: MockPeerStore;

  beforeEach(() => {
    store = new MockPeerStore();
  });

  it("put and get round-trips a peer binding", async () => {
    const peer = makePeer();
    await store.put(peer);
    const got = await store.get("did:peer:test-peer");
    assert.deepEqual(got, peer);
  });

  it("get returns undefined for unknown peer", async () => {
    const got = await store.get("did:peer:unknown");
    assert.equal(got, undefined);
  });

  it("list with no filter returns all peers", async () => {
    await store.put(makePeer({ peerDid: "did:peer:a", trustState: "approved" }));
    await store.put(makePeer({ peerDid: "did:peer:b", trustState: "revoked" }));
    const all = await store.list();
    assert.equal(all.length, 2);
  });

  it("list with 'all' filter returns all peers", async () => {
    await store.put(makePeer({ peerDid: "did:peer:a", trustState: "approved" }));
    await store.put(makePeer({ peerDid: "did:peer:b", trustState: "revoked" }));
    const all = await store.list("all");
    assert.equal(all.length, 2);
  });

  it("list with 'approved' filter returns only approved peers", async () => {
    await store.put(makePeer({ peerDid: "did:peer:a", trustState: "approved" }));
    await store.put(makePeer({ peerDid: "did:peer:b", trustState: "revoked" }));
    await store.put(makePeer({ peerDid: "did:peer:c", trustState: "untrusted" }));
    const approved = await store.list("approved");
    assert.equal(approved.length, 1);
    assert.equal(approved[0].peerDid, "did:peer:a");
  });

  it("list with 'revoked' filter returns only revoked peers", async () => {
    await store.put(makePeer({ peerDid: "did:peer:a", trustState: "approved" }));
    await store.put(makePeer({ peerDid: "did:peer:b", trustState: "revoked" }));
    const revoked = await store.list("revoked");
    assert.equal(revoked.length, 1);
    assert.equal(revoked[0].peerDid, "did:peer:b");
  });

  it("delete removes a peer", async () => {
    await store.put(makePeer());
    await store.delete("did:peer:test-peer");
    const got = await store.get("did:peer:test-peer");
    assert.equal(got, undefined);
  });
});

describe("FilePeerStore", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "atlas-peer-store-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("put persists peer to disk", async () => {
    const store = new FilePeerStore(tmpDir);
    await store.put(makePeer());
    const filePath = path.join(tmpDir, "didcomm-peers.json");
    assert.ok(fs.existsSync(filePath), "Peer file should exist on disk");
    const raw = fs.readFileSync(filePath, "utf-8");
    const data = JSON.parse(raw) as PeerBinding[];
    assert.equal(data.length, 1);
    assert.equal(data[0].peerDid, "did:peer:test-peer");
  });

  it("get loads from a fresh instance (persistence across instances)", async () => {
    const store1 = new FilePeerStore(tmpDir);
    await store1.put(makePeer({ peerDid: "did:peer:persist-test" }));

    // Create a new instance pointing at the same directory
    const store2 = new FilePeerStore(tmpDir);
    const got = await store2.get("did:peer:persist-test");
    assert.ok(got, "Peer should be loadable from new instance");
    assert.equal(got.peerDid, "did:peer:persist-test");
  });

  it("file is created with mode 0600", async () => {
    const store = new FilePeerStore(tmpDir);
    await store.put(makePeer());
    const filePath = path.join(tmpDir, "didcomm-peers.json");
    const stat = fs.statSync(filePath);
    // mode includes file type bits; mask to permission bits only
    const perms = stat.mode & 0o777;
    assert.equal(perms, 0o600, `Expected 0600 permissions, got ${perms.toString(8)}`);
  });

  it("uses atomic write via tmp file (tmp file does not persist)", async () => {
    const store = new FilePeerStore(tmpDir);
    await store.put(makePeer());
    const tmpFilePath = path.join(tmpDir, "didcomm-peers.json.tmp");
    assert.ok(!fs.existsSync(tmpFilePath), "Temp file should not persist after atomic rename");
  });

  it("handles corrupt file gracefully (starts empty)", async () => {
    const filePath = path.join(tmpDir, "didcomm-peers.json");
    fs.writeFileSync(filePath, "THIS IS NOT JSON{{{", "utf-8");

    const store = new FilePeerStore(tmpDir);
    const all = await store.list();
    assert.equal(all.length, 0, "Corrupt file should result in empty store");
  });
});
