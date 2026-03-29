/**
 * Atlas Protocol — Break-Glass Mechanism (v0.8.0)
 *
 * Provides an emergency override when Telegram is unreachable.
 * Requires physical host access to create a time-limited token file.
 *
 * How it works:
 *   1. Operator creates a token: atlas_break_glass MCP tool (or manual file)
 *      File: <data_dir>/break-glass.token
 *      Content: JSON { created_at, expires_at, reason, token_hash }
 *   2. While the token is valid (not expired), "ask" verdicts bypass Telegram
 *      and are auto-approved with audit trail
 *   3. Every break-glass approval is logged with event BREAK_GLASS_ALLOW
 *   4. Token is single-use per creation — once expired, a new one must be created
 *
 * Security properties:
 *   - Requires file system write access (host-level)
 *   - Time-limited (default: 1 hour, max: 4 hours)
 *   - Token hash prevents replay from audit logs
 *   - All break-glass actions are prominently logged
 *   - Hard-deny rules are NEVER bypassed (only "ask" verdicts)
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, chmodSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BreakGlassToken {
  created_at: string;
  expires_at: string;
  reason: string;
  token_hash: string;
  /** Max requests this token can approve (0 = unlimited) */
  max_requests: number;
  /** How many requests this token has approved so far */
  requests_used: number;
}

export interface BreakGlassStatus {
  active: boolean;
  token?: {
    created_at: string;
    expires_at: string;
    reason: string;
    remaining_seconds: number;
    requests_used: number;
    max_requests: number;
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TOKEN_FILENAME = "break-glass.token";
const DEFAULT_TTL_MINUTES = 60;
const MAX_TTL_MINUTES = 240; // 4 hours max

// ---------------------------------------------------------------------------
// Break-Glass Manager
// ---------------------------------------------------------------------------

export class BreakGlassManager {
  private readonly tokenPath: string;

  constructor(dataDir: string) {
    this.tokenPath = join(dataDir, TOKEN_FILENAME);
  }

  /**
   * Create a new break-glass token. Overwrites any existing token.
   * Returns the token and a verification secret (printed to console only).
   */
  create(reason: string, ttlMinutes: number = DEFAULT_TTL_MINUTES, maxRequests: number = 0): {
    token: BreakGlassToken;
    secret: string;
  } {
    const effectiveTtl = Math.min(Math.max(1, ttlMinutes), MAX_TTL_MINUTES);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + effectiveTtl * 60_000);
    const secret = randomBytes(16).toString("hex");
    const tokenHash = createHash("sha256").update(secret).digest("hex");

    const token: BreakGlassToken = {
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      reason,
      token_hash: tokenHash,
      max_requests: maxRequests,
      requests_used: 0,
    };

    const dir = dirname(this.tokenPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    writeFileSync(this.tokenPath, JSON.stringify(token, null, 2), "utf-8");
    try {
      chmodSync(this.tokenPath, 0o600);
    } catch {
      // Non-fatal on restricted systems
    }

    return { token, secret };
  }

  /**
   * Check if a valid (non-expired) break-glass token exists.
   */
  isActive(): boolean {
    const token = this.read();
    if (!token) return false;
    return new Date(token.expires_at) > new Date();
  }

  /**
   * Read and validate the current token. Returns null if missing/expired/corrupt.
   */
  read(): BreakGlassToken | null {
    if (!existsSync(this.tokenPath)) return null;

    try {
      const raw = JSON.parse(readFileSync(this.tokenPath, "utf-8"));
      if (!raw.created_at || !raw.expires_at || !raw.token_hash) return null;

      const token = raw as BreakGlassToken;

      // Check expiry
      if (new Date(token.expires_at) <= new Date()) {
        // Auto-cleanup expired token
        this.revoke();
        return null;
      }

      // Check request limit
      if (token.max_requests > 0 && token.requests_used >= token.max_requests) {
        this.revoke();
        return null;
      }

      return token;
    } catch {
      return null;
    }
  }

  /**
   * Record a break-glass usage. Increments the request counter.
   */
  recordUsage(): void {
    const token = this.read();
    if (!token) return;

    token.requests_used++;
    writeFileSync(this.tokenPath, JSON.stringify(token, null, 2), "utf-8");
  }

  /**
   * Revoke (delete) the break-glass token.
   */
  revoke(): boolean {
    if (!existsSync(this.tokenPath)) return false;
    try {
      unlinkSync(this.tokenPath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get current break-glass status.
   */
  getStatus(): BreakGlassStatus {
    const token = this.read();
    if (!token) {
      return { active: false };
    }

    const remainingMs = new Date(token.expires_at).getTime() - Date.now();
    return {
      active: true,
      token: {
        created_at: token.created_at,
        expires_at: token.expires_at,
        reason: token.reason,
        remaining_seconds: Math.max(0, Math.round(remainingMs / 1000)),
        requests_used: token.requests_used,
        max_requests: token.max_requests,
      },
    };
  }
}
