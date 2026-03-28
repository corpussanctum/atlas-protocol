/**
 * Fidelis Channel — Configuration
 *
 * Loads config from environment variables and/or a JSON config file.
 * Defaults are conservative: no bot token, no authorized chats, and a fail-closed
 * permission timeout.
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PolicyRule {
  /** Glob pattern matched against tool_name (e.g. "Bash", "Write*") */
  tool_pattern: string;
  /** What to do when the pattern matches */
  action: "deny" | "ask" | "allow";
  /** Human-readable reason surfaced in audit log */
  reason?: string;
}

export interface FidelisConfig {
  // -- Paths -----------------------------------------------------------------
  /** Persistent state directory for config/audit artifacts */
  data_dir: string;
  /** Optional JSON config file path */
  config_path: string;

  // -- Telegram ---------------------------------------------------------------
  /** Telegram bot token from @BotFather */
  telegram_bot_token: string;
  /** Telegram chat ID(s) allowed to issue verdicts */
  telegram_allowed_chat_ids: number[];
  /** Polling interval in ms for Telegram getUpdates */
  telegram_poll_interval_ms: number;

  // -- Timeouts ---------------------------------------------------------------
  /** Seconds to wait for a human verdict before auto-denying (fail-closed) */
  permission_timeout_seconds: number;

  // -- Policy engine ----------------------------------------------------------
  /** Ordered list of policy rules. First match wins. Default = ask. */
  policy_rules: PolicyRule[];

  // -- Audit log --------------------------------------------------------------
  /** Path to the append-only JSONL audit log */
  audit_log_path: string;
  /** HMAC-SHA256 secret for signing audit entries. If empty, entries are unsigned. */
  audit_hmac_secret: string;

  // -- Anomaly detection ------------------------------------------------------
  /** Max permission requests per minute before triggering a velocity alert */
  velocity_limit_per_minute: number;

  // -- Identity / Briefcase -------------------------------------------------
  /** Path to a DIB Briefcase directory. Empty = standalone mode. */
  briefcase_path: string;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

function resolveDataDir(): string {
  return (
    process.env.FIDELIS_DATA_DIR ||
    process.env.CLAUDE_PLUGIN_DATA ||
    join(homedir(), ".fidelis-channel")
  );
}

function defaultConfigPath(dataDir: string): string {
  return process.env.FIDELIS_CONFIG_PATH || join(dataDir, "config.json");
}

function defaultAuditPath(dataDir: string): string {
  return join(dataDir, "audit.jsonl");
}

function parseChatIds(value: string): number[] {
  return value
    .split(",")
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => !Number.isNaN(n));
}

function buildDefaults(): FidelisConfig {
  const dataDir = resolveDataDir();

  return {
    data_dir: dataDir,
    config_path: defaultConfigPath(dataDir),
    telegram_bot_token: "",
    telegram_allowed_chat_ids: [],
    telegram_poll_interval_ms: 1000,
    permission_timeout_seconds: 120,
    policy_rules: [
      // =================================================================
      // HARD DENY — never allowed, no human override via policy engine
      // =================================================================

      // -- Filesystem destruction -----------------------------------------
      {
        tool_pattern: "Bash(rm -rf *)",
        action: "deny",
        reason: "Recursive force-delete blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*rm -rf /*)",
        action: "deny",
        reason: "Root-level recursive delete blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*mkfs*|*wipefs*)",
        action: "deny",
        reason: "Filesystem format/wipe blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*dd if=*of=/dev*)",
        action: "deny",
        reason: "Raw block device write blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*> /dev/sd*|*> /dev/nvme*|*> /dev/vd*)",
        action: "deny",
        reason: "Block device overwrite blocked by Fidelis policy",
      },

      // -- Safety bypass flags --------------------------------------------
      {
        tool_pattern: "Bash(*--skip-verification*)",
        action: "deny",
        reason: "Safety bypass flags blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*--no-verify*)",
        action: "deny",
        reason: "Hook bypass (--no-verify) blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*--no-check*|*--insecure*|*--trust-all*)",
        action: "deny",
        reason: "Security check bypass blocked by Fidelis policy",
      },

      // -- Network exfiltration / C2 -------------------------------------
      {
        tool_pattern: "Bash(*curl*|*wget*|*nc *|*netcat*)",
        action: "deny",
        reason: "Network exfiltration tool blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*scp *|*rsync *|*ftp *|*sftp *)",
        action: "deny",
        reason: "File transfer tool blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*python*http.server*|*python*SimpleHTTP*|*python*-m*http*)",
        action: "deny",
        reason: "Ad-hoc HTTP server blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*socat*|*ncat*|*telnet *)",
        action: "deny",
        reason: "Network socket tool blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*ngrok*|*localtunnel*|*cloudflared*tunnel*)",
        action: "deny",
        reason: "Tunnel/reverse proxy tool blocked by Fidelis policy",
      },

      // -- Credential / secret theft --------------------------------------
      {
        tool_pattern: "Bash(*cat*.env*|*less*.env*|*more*.env*|*head*.env*|*tail*.env*)",
        action: "deny",
        reason: "Direct .env file read via shell blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*cat*.ssh/*|*cat*.gnupg/*|*cat*credentials*|*cat*id_rsa*|*cat*id_ed25519*)",
        action: "deny",
        reason: "Credential/key file read blocked by Fidelis policy",
      },
      {
        tool_pattern: "Read(*.env)",
        action: "deny",
        reason: "Direct .env file read blocked by Fidelis policy",
      },
      {
        tool_pattern: "Read(*/.env*)",
        action: "deny",
        reason: ".env file read blocked by Fidelis policy",
      },
      {
        tool_pattern: "Read(*/.ssh/*)",
        action: "deny",
        reason: "SSH key read blocked by Fidelis policy",
      },
      {
        tool_pattern: "Read(*id_rsa*|*id_ed25519*|*id_ecdsa*)",
        action: "deny",
        reason: "Private key read blocked by Fidelis policy",
      },
      {
        tool_pattern: "Read(*/.gnupg/*)",
        action: "deny",
        reason: "GPG keyring read blocked by Fidelis policy",
      },

      // -- Git destructive operations -------------------------------------
      {
        tool_pattern: "Bash(*git push*--force*|*git push*-f *|*git push*-f)",
        action: "deny",
        reason: "Force push blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*git reset --hard*)",
        action: "deny",
        reason: "Hard reset blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*git clean -fd*|*git clean -fx*|*git clean -xfd*)",
        action: "deny",
        reason: "Git clean (force-delete untracked) blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*git checkout -- .*|*git restore .*)",
        action: "deny",
        reason: "Wholesale working tree discard blocked by Fidelis policy",
      },

      // -- Privilege escalation -------------------------------------------
      {
        tool_pattern: "Bash(*chmod 777*|*chmod -R 777*)",
        action: "deny",
        reason: "World-writable permissions blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*chmod u+s*|*chmod g+s*)",
        action: "deny",
        reason: "SUID/SGID bit manipulation blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*chown root*|*chgrp root*)",
        action: "deny",
        reason: "Ownership change to root blocked by Fidelis policy",
      },

      // -- Firewall / network defense teardown ----------------------------
      {
        tool_pattern: "Bash(*iptables -F*|*iptables --flush*|*ip6tables -F*)",
        action: "deny",
        reason: "Firewall flush blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*ufw disable*|*ufw reset*)",
        action: "deny",
        reason: "UFW disable/reset blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*nft flush*|*nft delete*)",
        action: "deny",
        reason: "nftables flush/delete blocked by Fidelis policy",
      },

      // -- Container escape / infrastructure destruction ------------------
      {
        tool_pattern: "Bash(*docker run*--privileged*)",
        action: "deny",
        reason: "Privileged container launch blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*docker run*--pid=host*|*docker run*--net=host*)",
        action: "deny",
        reason: "Host-namespace container launch blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*docker system prune*)",
        action: "deny",
        reason: "Docker system prune blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*docker rm -f*|*docker kill*)",
        action: "deny",
        reason: "Force container removal/kill blocked by Fidelis policy",
      },

      // -- Crypto-mining / abuse ------------------------------------------
      {
        tool_pattern: "Bash(*xmrig*|*cpuminer*|*minerd*|*cryptonight*)",
        action: "deny",
        reason: "Cryptocurrency miner blocked by Fidelis policy",
      },

      // -- Shell escape / obfuscation vectors -----------------------------
      {
        tool_pattern: "Bash(*bash -c*base64*|*sh -c*base64*)",
        action: "deny",
        reason: "Base64-decoded shell execution blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*eval*$(base64*|*eval*$(curl*)",
        action: "deny",
        reason: "Dynamic eval with network/encoding blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*python*-c*import*socket*|*python*-c*import*subprocess*)",
        action: "deny",
        reason: "Python reverse shell pattern blocked by Fidelis policy",
      },
      {
        tool_pattern: "Bash(*perl*-e*socket*|*ruby*-e*socket*)",
        action: "deny",
        reason: "Scripted reverse shell pattern blocked by Fidelis policy",
      },

      // -- Write to sensitive system paths --------------------------------
      {
        tool_pattern: "Write(/etc/*)",
        action: "deny",
        reason: "Write to /etc blocked by Fidelis policy",
      },
      {
        tool_pattern: "Write(*/.ssh/*)",
        action: "deny",
        reason: "Write to SSH config/keys blocked by Fidelis policy",
      },
      {
        tool_pattern: "Write(*/.bashrc|*/.bash_profile|*/.profile|*/.zshrc)",
        action: "deny",
        reason: "Shell profile modification blocked by Fidelis policy",
      },
      {
        tool_pattern: "Write(*/crontab*|*/cron.d/*)",
        action: "deny",
        reason: "Crontab modification blocked by Fidelis policy",
      },

      // =================================================================
      // ASK — dangerous but sometimes legitimate, require human approval
      // =================================================================

      // -- Service lifecycle (may need for legitimate maintenance) ---------
      {
        tool_pattern: "Bash(*systemctl stop*|*systemctl disable*|*systemctl mask*)",
        action: "ask",
        reason: "Service stop/disable requires operator approval",
      },
      {
        tool_pattern: "Bash(*systemctl restart*|*systemctl reload*)",
        action: "ask",
        reason: "Service restart/reload requires operator approval",
      },

      // -- Docker compose lifecycle ---------------------------------------
      {
        tool_pattern: "Bash(*docker compose down*|*docker compose rm*)",
        action: "ask",
        reason: "Docker compose teardown requires operator approval",
      },
      {
        tool_pattern: "Bash(*docker compose up*|*docker compose restart*)",
        action: "ask",
        reason: "Docker compose lifecycle change requires operator approval",
      },

      // -- Database destructive operations --------------------------------
      {
        tool_pattern: "Bash(*DROP TABLE*|*DROP DATABASE*|*TRUNCATE*|*DELETE FROM*)",
        action: "ask",
        reason: "Destructive SQL operation requires operator approval",
      },

      // -- Package management (supply chain risk) -------------------------
      {
        tool_pattern: "Bash(*npm install*|*pip install*|*apt install*|*apt-get install*)",
        action: "ask",
        reason: "Package installation requires operator approval",
      },

      // -- Git push (any) -------------------------------------------------
      {
        tool_pattern: "Bash(*git push*)",
        action: "ask",
        reason: "Git push requires operator approval",
      },
    ],
    audit_log_path: defaultAuditPath(dataDir),
    audit_hmac_secret: "",
    velocity_limit_per_minute: 30,
    briefcase_path: "",
  };
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

export function loadConfig(): FidelisConfig {
  const config = buildDefaults();

  if (existsSync(config.config_path)) {
    try {
      const raw = JSON.parse(readFileSync(config.config_path, "utf-8")) as Partial<FidelisConfig>;
      Object.assign(config, raw);
    } catch {
      console.error(`[fidelis] Warning: could not parse ${config.config_path}, using defaults`);
    }
  }

  if (process.env.FIDELIS_TELEGRAM_BOT_TOKEN) {
    config.telegram_bot_token = process.env.FIDELIS_TELEGRAM_BOT_TOKEN;
  }
  if (process.env.FIDELIS_TELEGRAM_CHAT_IDS) {
    config.telegram_allowed_chat_ids = parseChatIds(process.env.FIDELIS_TELEGRAM_CHAT_IDS);
  }
  if (process.env.FIDELIS_PERMISSION_TIMEOUT) {
    config.permission_timeout_seconds = parseInt(process.env.FIDELIS_PERMISSION_TIMEOUT, 10) || 120;
  }
  if (process.env.FIDELIS_AUDIT_LOG_PATH) {
    config.audit_log_path = process.env.FIDELIS_AUDIT_LOG_PATH;
  }
  if (process.env.FIDELIS_HMAC_SECRET) {
    config.audit_hmac_secret = process.env.FIDELIS_HMAC_SECRET;
  }
  if (process.env.FIDELIS_VELOCITY_LIMIT) {
    config.velocity_limit_per_minute = parseInt(process.env.FIDELIS_VELOCITY_LIMIT, 10) || 30;
  }
  if (process.env.FIDELIS_POLL_INTERVAL_MS) {
    config.telegram_poll_interval_ms = parseInt(process.env.FIDELIS_POLL_INTERVAL_MS, 10) || 1000;
  }
  if (process.env.FIDELIS_BRIEFCASE_PATH) {
    config.briefcase_path = process.env.FIDELIS_BRIEFCASE_PATH;
  }

  return config;
}
