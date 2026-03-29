/**
 * Atlas Protocol — Identity Registry (v0.5.0)
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
  issueCredentialWithKey,
  verifyCredential,
  revokeCredential as revokeCredentialFn,
  validateDelegation,
  delegateCredential,
  delegateCredentialWithKey,
  isDelegatedCredential,
  cascadeRevoke as cascadeRevokeFn,
} from "./agent-identity.js";
import type {
  AgentCredential,
  CredentialIssueRequest,
  CredentialVerifyResult,
  DelegationRequest,
  DelegatedCredential,
} from "./agent-identity.js";

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export class IdentityRegistry {
  private credentials: Map<string, AgentCredential> = new Map();
  /** Parent → children index for efficient delegation tree walks */
  private childrenIndex: Map<string, string[]> = new Map();
  /** Agent secret keys (in-memory only, never persisted) */
  private agentSecretKeys: Map<string, Uint8Array> = new Map();
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

    const { credential, agentSecretKey } = issueCredentialWithKey(
      request,
      this.issuerSecretKey
    );
    this.credentials.set(credential.agentId, credential);
    // Store secret key in-memory for delegation support
    this.agentSecretKeys.set(credential.agentId, agentSecretKey);
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
  list(filter: "active" | "revoked" | "expired" | "delegated" | "all" = "all"): AgentCredential[] {
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
      case "delegated":
        return all.filter((c) => isDelegatedCredential(c));
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

  // =========================================================================
  // Delegation (v0.6.0)
  // =========================================================================

  /**
   * Issue a delegated credential from a parent. Validates the request,
   * issues the child, updates the children index, and persists.
   * Returns the DelegatedCredential (caller must not expose agent secret keys).
   */
  delegate(request: DelegationRequest): DelegatedCredential {
    if (!this.issuerSecretKey) {
      throw new Error("Registry not initialized — issuer key unavailable");
    }

    // Validate (skip TTL check — delegateCredentialWithKey caps TTL automatically)
    const validation = validateDelegation(
      { ...request, ttlHours: undefined },
      this
    );
    if (!validation.valid) {
      throw new Error(`Delegation failed: ${validation.reason}`);
    }

    // Get parent's agent secret key (must be in-memory from registration/delegation)
    const parentSecretKey = this.agentSecretKeys.get(request.parentAgentId);
    if (!parentSecretKey) {
      throw new Error(
        "Parent agent secret key not available — parent was registered in a previous session"
      );
    }

    const { credential, childSecretKey } = delegateCredentialWithKey(
      request,
      parentSecretKey,
      this.issuerSecretKey,
      this
    );

    // Store credential and child secret key (in-memory only)
    this.credentials.set(credential.agentId, credential);
    this.agentSecretKeys.set(credential.agentId, childSecretKey);

    // Update children index
    const parentChildren = this.childrenIndex.get(request.parentAgentId) || [];
    parentChildren.push(credential.agentId);
    this.childrenIndex.set(request.parentAgentId, parentChildren);

    this.save();
    return credential;
  }

  /**
   * Store an agent's secret key in-memory (never persisted).
   * Called after register() or delegate() when the caller needs to
   * enable further delegation from this agent.
   */
  storeAgentSecretKey(agentId: string, secretKey: Uint8Array): void {
    this.agentSecretKeys.set(agentId, secretKey);
  }

  /**
   * Get an agent's secret key from in-memory storage.
   */
  getAgentSecretKey(agentId: string): Uint8Array | undefined {
    return this.agentSecretKeys.get(agentId);
  }

  /**
   * Get direct children of a credential.
   */
  getChildren(parentAgentId: string): AgentCredential[] {
    const childIds = this.childrenIndex.get(parentAgentId) || [];
    return childIds
      .map((id) => this.credentials.get(id))
      .filter((c): c is AgentCredential => c !== undefined);
  }

  /**
   * Get all descendants (recursive) of a credential.
   */
  getDescendants(agentId: string): AgentCredential[] {
    const result: AgentCredential[] = [];
    const children = this.getChildren(agentId);
    for (const child of children) {
      result.push(child);
      result.push(...this.getDescendants(child.agentId));
    }
    return result;
  }

  /**
   * Cascade-revoke a parent and all its descendants.
   * Returns array of all revoked agentIds.
   */
  cascadeRevoke(parentAgentId: string, reason: string): string[] {
    const revoked = cascadeRevokeFn(parentAgentId, reason, this);

    // Clear session keys for revoked agents
    for (const id of revoked) {
      this.agentSecretKeys.delete(id);
    }

    this.save();
    return revoked;
  }

  /**
   * Persist registry to disk (JSON, chmod 600).
   */
  save(): void {
    const dir = dirname(this.storagePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    // Persist credentials + children index (never secret keys)
    const serializable = {
      credentials: Array.from(this.credentials.values()),
      children: Object.fromEntries(this.childrenIndex.entries()),
    };
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

      // Support both old format (array) and new format (object with children index)
      const credArray: AgentCredential[] = Array.isArray(raw)
        ? raw
        : (raw.credentials ?? []);
      const childrenObj: Record<string, string[]> = Array.isArray(raw)
        ? {}
        : (raw.children ?? {});

      this.credentials.clear();
      this.childrenIndex.clear();

      for (const cred of credArray) {
        if (cred.agentId) {
          this.credentials.set(cred.agentId, cred);
        }
      }

      for (const [parentId, childIds] of Object.entries(childrenObj)) {
        this.childrenIndex.set(parentId, childIds);
      }

      // Rebuild children index from credentials if not in persisted data
      if (Object.keys(childrenObj).length === 0) {
        for (const cred of credArray) {
          if (isDelegatedCredential(cred)) {
            const existing = this.childrenIndex.get(cred.delegation.parentId) || [];
            existing.push(cred.agentId);
            this.childrenIndex.set(cred.delegation.parentId, existing);
          }
        }
      }
    } catch {
      console.error("[atlas] WARNING: corrupt identity registry file, starting fresh");
    }
  }
}
