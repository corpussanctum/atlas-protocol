/**
 * Tests for the issuer key at rest (#45): wrapped storage under the keystore
 * passphrase, migration from plaintext, and failing loudly instead of
 * regenerating the key.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, copyFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  QuantumSigner,
  IssuerKeyError,
  ISSUER_KEY_FILE,
  ISSUER_KEY_WRAPPED_FILE,
} from "../src/quantum-signer.js";

const PASS = "correct horse battery staple";

let tempDirs: string[] = [];
function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "atlas-issuer-key-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs = [];
});

const plainPath = (dir: string) => join(dir, ISSUER_KEY_FILE);
const wrappedPath = (dir: string) => join(dir, ISSUER_KEY_WRAPPED_FILE);

describe("Issuer key at rest (#45)", () => {
  it("stores a new key wrapped when a passphrase is set, and reloads it after a restart", async () => {
    const dir = makeTempDir();
    const first = await QuantumSigner.create(dir, { passphrase: PASS });
    assert.equal(first.getStatus().key_storage, "wrapped");
    assert.equal(first.getStatus().key_path, wrappedPath(dir));
    assert.ok(!existsSync(plainPath(dir)), "no plaintext key file");
    assert.equal(statSync(wrappedPath(dir)).mode & 0o777, 0o600);

    const file = readFileSync(wrappedPath(dir), "utf-8");
    assert.ok(!/secret_key/.test(file), "no plaintext secret field");

    const payload = Buffer.from("signed before restart");
    const sig = first.sign(payload)!;

    const second = await QuantumSigner.create(dir, { passphrase: PASS });
    assert.equal(second.getPublicKeyHash(), first.getPublicKeyHash());
    assert.equal(second.verify(payload, sig), true);
    const after = Buffer.from("signed after restart");
    assert.equal(first.verify(after, second.sign(after)!), true, "restarted signer uses the same secret key");
  });

  it("migrates an existing plaintext key: same key, wrapped copy, plaintext removed", async () => {
    const dir = makeTempDir();
    const legacy = await QuantumSigner.create(dir);
    assert.equal(legacy.getStatus().key_storage, "plaintext");
    const hash = legacy.getPublicKeyHash();

    const migrated = await QuantumSigner.create(dir, { passphrase: PASS });
    assert.equal(migrated.getPublicKeyHash(), hash, "the issuer key is unchanged");
    assert.equal(migrated.getStatus().key_storage, "wrapped");
    assert.ok(existsSync(wrappedPath(dir)));
    assert.ok(!existsSync(plainPath(dir)), "plaintext removed after a verified wrap");

    const payload = Buffer.from("x");
    assert.equal(legacy.verify(payload, migrated.sign(payload)!), true);
  });

  it("refuses to start with a wrapped key and no passphrase, and never regenerates", async () => {
    const dir = makeTempDir();
    await QuantumSigner.create(dir, { passphrase: PASS });
    const before = readFileSync(wrappedPath(dir), "utf-8");

    await assert.rejects(() => QuantumSigner.create(dir), IssuerKeyError);
    await assert.rejects(() => QuantumSigner.create(dir, { passphrase: "" }), IssuerKeyError);
    assert.equal(readFileSync(wrappedPath(dir), "utf-8"), before);
    assert.ok(!existsSync(plainPath(dir)), "no new plaintext key was generated");
  });

  it("refuses a wrong passphrase or a tampered file, leaving the file untouched", async () => {
    const dir = makeTempDir();
    await QuantumSigner.create(dir, { passphrase: PASS });
    const before = readFileSync(wrappedPath(dir), "utf-8");

    await assert.rejects(() => QuantumSigner.create(dir, { passphrase: "wrong passphrase!" }), /Wrong ATLAS_KEYSTORE_PASSPHRASE/);
    assert.equal(readFileSync(wrappedPath(dir), "utf-8"), before);

    const tampered = JSON.parse(before);
    const ct = Buffer.from(tampered.cipher.ciphertext, "base64");
    ct[0] ^= 1;
    tampered.cipher.ciphertext = ct.toString("base64");
    writeFileSync(wrappedPath(dir), JSON.stringify(tampered));
    await assert.rejects(() => QuantumSigner.create(dir, { passphrase: PASS }), IssuerKeyError);
  });

  it("refuses an unreadable plaintext key instead of regenerating it", async () => {
    const dir = makeTempDir();
    writeFileSync(plainPath(dir), "{ not json");
    await assert.rejects(() => QuantumSigner.create(dir), /unreadable/);
    assert.equal(readFileSync(plainPath(dir), "utf-8"), "{ not json");
  });

  it("finishes an interrupted migration when both copies hold the same key", async () => {
    const dir = makeTempDir();
    const legacy = await QuantumSigner.create(dir);
    const backup = join(dir, "plain.bak");
    copyFileSync(plainPath(dir), backup);
    await QuantumSigner.create(dir, { passphrase: PASS });
    copyFileSync(backup, plainPath(dir)); // crash before the plaintext was removed

    const resumed = await QuantumSigner.create(dir, { passphrase: PASS });
    assert.equal(resumed.getPublicKeyHash(), legacy.getPublicKeyHash());
    assert.ok(!existsSync(plainPath(dir)));
  });

  it("refuses when the plaintext and wrapped files hold different keys", async () => {
    const dir = makeTempDir();
    await QuantumSigner.create(dir, { passphrase: PASS });
    const other = makeTempDir();
    await QuantumSigner.create(other);
    copyFileSync(plainPath(other), plainPath(dir));

    await assert.rejects(() => QuantumSigner.create(dir, { passphrase: PASS }), /different issuer keys/);
    assert.ok(existsSync(plainPath(dir)), "nothing deleted");
  });

  it("re-wraps the new key on rotation; old signatures still verify", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir, { passphrase: PASS });
    const payload = Buffer.from("before rotation");
    const sig = signer.sign(payload)!;
    const prepared = signer.beginRotation();
    signer.commitRotation(prepared);
    assert.ok(!existsSync(plainPath(dir)), "rotation does not write plaintext");

    const restarted = await QuantumSigner.create(dir, { passphrase: PASS });
    assert.equal(restarted.getPublicKeyHash(), prepared.newKeyHash);
    assert.equal(restarted.getStatus().key_storage, "wrapped");
    assert.equal(restarted.verify(payload, sig), true, "archived key still verifies");
  });

  it("rewrap moves the key to a new passphrase", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir, { passphrase: PASS });
    signer.rewrap("a different long passphrase");

    await assert.rejects(() => QuantumSigner.create(dir, { passphrase: PASS }), IssuerKeyError);
    const reopened = await QuantumSigner.create(dir, { passphrase: "a different long passphrase" });
    assert.equal(reopened.getPublicKeyHash(), signer.getPublicKeyHash());
  });

  it("does not expose the secret key on the signer object", async () => {
    const dir = makeTempDir();
    const signer = await QuantumSigner.create(dir, { passphrase: PASS });
    const s = signer as unknown as Record<string, unknown>;
    assert.equal(s.secretKey, undefined);
    assert.equal(s.getSecretKeyRaw, undefined);
    assert.ok(!/secret/i.test(JSON.stringify(signer)));
  });
});
