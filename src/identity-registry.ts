/**
 * Fidelis Channel — Identity Registry (v0.5.0)
 *
 * In-memory registry of agent credentials with JSON file persistence.
 * The gatekeeper's QuantumSigner provides the issuer key for signing
 * new credentials and verifying existing ones.
 *
 * Persistence:
 *   - Storage: <data_dir>/identity-registry.json (chmod 600)
 *   - Auto-save after every mutation (register, revoke)
 *   - Auto-load on initialization if file exists
 *   - Secret keys (agent private keys) are NEVER stored in the registry
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import type { QuantumSigner } from "./quantum-signer.js";
import {
  initAgentIdentity,
  issueCredential,
  verifyCredential,
  revokeCredential as revokeCredentialFn,
} from "./agent-identity.js";
import type {
  AgentCredential,
  CredentialIssueRequest,
  CredentialVerifyResult,
} from "./agent-identity.js";

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export class IdentityRegistry {
  private credentials: Map<string, AgentCredential> = new Map();
  private readonly storagePath: string;
  private readonly signer: QuantumSigner;
  private issuerSecretKey: Uint8Array | null = null;
  private issuerPublicKey: Uint8Array | null = null;
  private _initialized = false;

  private constructor(dataDir: string, signer: QuantumSigner) {
    this.storagePath = join(dataDir, "identity-registry.json");
    this.signer = signer;
  }

  /**
   * Factory: create and initialize the registry.
   */
  static async create(dataDir: string, signer: QuantumSigner): Promise<IdentityRegistry> {
    const registry = new IdentityRegistry(dataDir, signer);
    await registry.initialize();
    return registry;
  }

  private async initialize(): Promise<void> {
    // Initialize ML-DSA-65 for agent identity operations
    await initAgentIdentity();

    // Get the gatekeeper's raw keys for issuing/verifying credentials
    this.issuerSecretKey = this.signer.getSecretKeyRaw();
    this.issuerPublicKey = this.signer.getPublicKeyRaw();

    // Load existing registry from disk
    this.load();
    this._initialized = true;
  }

  get initialized(): boolean {
    return this._initialized;
  }

  /**
   * Issue and store a new credential.
   */
  register(request: CredentialIssueRequest): AgentCredential {
    if (!this.issuerSecretKey) {
      throw new Error("Registry not initialized — issuer key unavailable");
    }

    const credential = issueCredential(request, this.issuerSecretKey);
    this.credentials.set(credential.agentId, credential);
    this.save();

    return credential;
  }

  /**
   * Look up a credential by agentId.
   */
  get(agentId: string): AgentCredential | undefined {
    return this.credentials.get(agentId);
  }

  /**
   * Verify a credential by agentId.
   */
  verify(agentId: string): CredentialVerifyResult {
    const credential = this.credentials.get(agentId);
    if (!credential) {
      return {
        valid: false,
        agentId,
        reason: "Agent not found in registry",
      };
    }

    if (!this.issuerPublicKey) {
      return {
        valid: false,
        agentId,
        reason: "Issuer public key unavailable",
      };
    }

    return verifyCredential(credential, this.issuerPublicKey);
  }

  /**
   * Revoke a credential by agentId.
   */
  revoke(agentId: string, reason: string): boolean {
    const credential = this.credentials.get(agentId);
    if (!credential) return false;

    const revoked = revokeCredentialFn(credential, reason);
    this.credentials.set(agentId, revoked);
    this.save();
    return true;
  }

  /**
   * List credentials, optionally filtered.
   */
  list(filter: "active" | "revoked" | "expired" | "all" = "all"): AgentCredential[] {
    const all = Array.from(this.credentials.values());
    const now = new Date();

    switch (filter) {
      case "active":
        return all.filter(
          (c) => !c.revoked && new Date(c.expiresAt) > now
        );
      case "revoked":
        return all.filter((c) => c.revoked);
      case "expired":
        return all.filter(
          (c) => !c.revoked && new Date(c.expiresAt) <= now
        );
      case "all":
      default:
        return all;
    }
  }

  /**
   * Returns true if the registry has no credentials at all.
   * Used for bootstrap detection — first-run should not self-lock.
   */
  isEmpty(): boolean {
    return this.credentials.size === 0;
  }

  /**
   * Total credential count.
   */
  get size(): number {
    return this.credentials.size;
  }

  /**
   * Persist registry to disk (JSON, chmod 600).
   */
  save(): void {
    const dir = dirname(this.storagePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    // Strip any fields that should never be persisted
    const serializable = Array.from(this.credentials.values());
    writeFileSync(
      this.storagePath,
      JSON.stringify(serializable, null, 2),
      "utf-8"
    );

    try {
      chmodSync(this.storagePath, 0o600);
    } catch {
      // Non-fatal on systems where chmod is restricted
    }
  }

  /**
   * Load registry from disk.
   */
  load(): void {
    if (!existsSync(this.storagePath)) return;

    try {
      const raw = JSON.parse(readFileSync(this.storagePath, "utf-8"));
      if (Array.isArray(raw)) {
        this.credentials.clear();
        for (const cred of raw as AgentCredential[]) {
          if (cred.agentId) {
            this.credentials.set(cred.agentId, cred);
          }
        }
      }
    } catch {
      console.error("[fidelis] WARNING: corrupt identity registry file, starting fresh");
    }
  }
}
