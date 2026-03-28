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
  /** MITRE ATT&CK technique ID (e.g. "T1059.004") */
  mitre_id?: string;
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
      // All rules tagged with MITRE ATT&CK technique IDs
      // =================================================================

      // -- Filesystem destruction (T1485 Data Destruction) ----------------
      {
        tool_pattern: "Bash(rm -rf *)",
        action: "deny",
        reason: "Recursive force-delete blocked by Fidelis policy",
        mitre_id: "T1485",
      },
      {
        tool_pattern: "Bash(*rm -rf /*)",
        action: "deny",
        reason: "Root-level recursive delete blocked by Fidelis policy",
        mitre_id: "T1485",
      },
      {
        tool_pattern: "Bash(*mkfs*|*wipefs*)",
        action: "deny",
        reason: "Filesystem format/wipe blocked by Fidelis policy",
        mitre_id: "T1561.002",
      },
      {
        tool_pattern: "Bash(*dd if=*of=/dev*)",
        action: "deny",
        reason: "Raw block device write blocked by Fidelis policy",
        mitre_id: "T1561.001",
      },
      {
        tool_pattern: "Bash(*> /dev/sd*|*> /dev/nvme*|*> /dev/vd*)",
        action: "deny",
        reason: "Block device overwrite blocked by Fidelis policy",
        mitre_id: "T1561.001",
      },
      {
        tool_pattern: "Bash(*shred *)",
        action: "deny",
        reason: "Secure file deletion blocked by Fidelis policy",
        mitre_id: "T1070.004",
      },

      // -- Safety bypass flags (T1562.001 Disable or Modify Tools) --------
      {
        tool_pattern: "Bash(*--skip-verification*)",
        action: "deny",
        reason: "Safety bypass flags blocked by Fidelis policy",
        mitre_id: "T1562.001",
      },
      {
        tool_pattern: "Bash(*--no-verify*)",
        action: "deny",
        reason: "Hook bypass (--no-verify) blocked by Fidelis policy",
        mitre_id: "T1562.001",
      },
      {
        tool_pattern: "Bash(*--no-check*|*--insecure*|*--trust-all*)",
        action: "deny",
        reason: "Security check bypass blocked by Fidelis policy",
        mitre_id: "T1562.001",
      },

      // -- Network exfiltration / C2 (T1048 / T1071) ---------------------
      {
        tool_pattern: "Bash(*curl*|*wget*|*nc *|*netcat*)",
        action: "deny",
        reason: "Network exfiltration tool blocked by Fidelis policy",
        mitre_id: "T1048",
      },
      {
        tool_pattern: "Bash(*scp *|*rsync *|*ftp *|*sftp *)",
        action: "deny",
        reason: "File transfer tool blocked by Fidelis policy",
        mitre_id: "T1048.003",
      },
      {
        tool_pattern: "Bash(*python*http.server*|*python*SimpleHTTP*|*python*-m*http*)",
        action: "deny",
        reason: "Ad-hoc HTTP server blocked by Fidelis policy",
        mitre_id: "T1105",
      },
      {
        tool_pattern: "Bash(*socat*|*ncat*|*telnet *)",
        action: "deny",
        reason: "Network socket tool blocked by Fidelis policy",
        mitre_id: "T1095",
      },
      {
        tool_pattern: "Bash(*ngrok*|*localtunnel*|*cloudflared*tunnel*)",
        action: "deny",
        reason: "Tunnel/reverse proxy tool blocked by Fidelis policy",
        mitre_id: "T1572",
      },
      {
        tool_pattern: "Bash(*chisel*|*plink*|*proxychains*)",
        action: "deny",
        reason: "Proxy/tunnel tool blocked by Fidelis policy",
        mitre_id: "T1572",
      },
      {
        tool_pattern: "Bash(*/dev/tcp/*|*/dev/udp/*)",
        action: "deny",
        reason: "Bash /dev/tcp network redirect blocked by Fidelis policy",
        mitre_id: "T1095",
      },
      {
        tool_pattern: "Bash(*openssl*s_client*|*openssl*s_server*)",
        action: "deny",
        reason: "OpenSSL network channel blocked by Fidelis policy",
        mitre_id: "T1573.002",
      },

      // -- Credential / secret theft (T1552) ------------------------------
      {
        tool_pattern: "Bash(*cat*.env*|*less*.env*|*more*.env*|*head*.env*|*tail*.env*)",
        action: "deny",
        reason: "Direct .env file read via shell blocked by Fidelis policy",
        mitre_id: "T1552.001",
      },
      {
        tool_pattern: "Bash(*cat*.ssh/*|*cat*.gnupg/*|*cat*credentials*|*cat*id_rsa*|*cat*id_ed25519*)",
        action: "deny",
        reason: "Credential/key file read blocked by Fidelis policy",
        mitre_id: "T1552.004",
      },
      {
        tool_pattern: "Read(*.env)",
        action: "deny",
        reason: "Direct .env file read blocked by Fidelis policy",
        mitre_id: "T1552.001",
      },
      {
        tool_pattern: "Read(*/.env*)",
        action: "deny",
        reason: ".env file read blocked by Fidelis policy",
        mitre_id: "T1552.001",
      },
      {
        tool_pattern: "Read(*/.ssh/*)",
        action: "deny",
        reason: "SSH key read blocked by Fidelis policy",
        mitre_id: "T1552.004",
      },
      {
        tool_pattern: "Read(*id_rsa*|*id_ed25519*|*id_ecdsa*)",
        action: "deny",
        reason: "Private key read blocked by Fidelis policy",
        mitre_id: "T1552.004",
      },
      {
        tool_pattern: "Read(*/.gnupg/*)",
        action: "deny",
        reason: "GPG keyring read blocked by Fidelis policy",
        mitre_id: "T1552.004",
      },
      {
        tool_pattern: "Bash(*cat*/etc/shadow*|*cat*/etc/passwd*)",
        action: "deny",
        reason: "System credential file read blocked by Fidelis policy",
        mitre_id: "T1003.008",
      },
      {
        tool_pattern: "Read(/etc/shadow)",
        action: "deny",
        reason: "Shadow file read blocked by Fidelis policy",
        mitre_id: "T1003.008",
      },

      // -- Git destructive operations (T1485 / T1565) ---------------------
      {
        tool_pattern: "Bash(*git push*--force*|*git push*-f *|*git push*-f)",
        action: "deny",
        reason: "Force push blocked by Fidelis policy",
        mitre_id: "T1485",
      },
      {
        tool_pattern: "Bash(*git reset --hard*)",
        action: "deny",
        reason: "Hard reset blocked by Fidelis policy",
        mitre_id: "T1485",
      },
      {
        tool_pattern: "Bash(*git clean -fd*|*git clean -fx*|*git clean -xfd*)",
        action: "deny",
        reason: "Git clean (force-delete untracked) blocked by Fidelis policy",
        mitre_id: "T1485",
      },
      {
        tool_pattern: "Bash(*git checkout -- .*|*git restore .*)",
        action: "deny",
        reason: "Wholesale working tree discard blocked by Fidelis policy",
        mitre_id: "T1485",
      },

      // -- Privilege escalation (T1548) -----------------------------------
      {
        tool_pattern: "Bash(*chmod 777*|*chmod -R 777*)",
        action: "deny",
        reason: "World-writable permissions blocked by Fidelis policy",
        mitre_id: "T1222.002",
      },
      {
        tool_pattern: "Bash(*chmod u+s*|*chmod g+s*)",
        action: "deny",
        reason: "SUID/SGID bit manipulation blocked by Fidelis policy",
        mitre_id: "T1548.001",
      },
      {
        tool_pattern: "Bash(*chown root*|*chgrp root*)",
        action: "deny",
        reason: "Ownership change to root blocked by Fidelis policy",
        mitre_id: "T1548",
      },

      // -- Firewall / network defense teardown (T1562.004) ----------------
      {
        tool_pattern: "Bash(*iptables -F*|*iptables --flush*|*ip6tables -F*)",
        action: "deny",
        reason: "Firewall flush blocked by Fidelis policy",
        mitre_id: "T1562.004",
      },
      {
        tool_pattern: "Bash(*ufw disable*|*ufw reset*)",
        action: "deny",
        reason: "UFW disable/reset blocked by Fidelis policy",
        mitre_id: "T1562.004",
      },
      {
        tool_pattern: "Bash(*nft flush*|*nft delete*)",
        action: "deny",
        reason: "nftables flush/delete blocked by Fidelis policy",
        mitre_id: "T1562.004",
      },

      // -- Container escape / infrastructure destruction ------------------
      {
        tool_pattern: "Bash(*docker run*--privileged*)",
        action: "deny",
        reason: "Privileged container launch blocked by Fidelis policy",
        mitre_id: "T1611",
      },
      {
        tool_pattern: "Bash(*docker run*--pid=host*|*docker run*--net=host*)",
        action: "deny",
        reason: "Host-namespace container launch blocked by Fidelis policy",
        mitre_id: "T1611",
      },
      {
        tool_pattern: "Bash(*docker system prune*)",
        action: "deny",
        reason: "Docker system prune blocked by Fidelis policy",
        mitre_id: "T1489",
      },
      {
        tool_pattern: "Bash(*docker rm -f*|*docker kill*)",
        action: "deny",
        reason: "Force container removal/kill blocked by Fidelis policy",
        mitre_id: "T1489",
      },

      // -- Crypto-mining / resource hijacking (T1496) ---------------------
      {
        tool_pattern: "Bash(*xmrig*|*cpuminer*|*minerd*|*cryptonight*)",
        action: "deny",
        reason: "Cryptocurrency miner blocked by Fidelis policy",
        mitre_id: "T1496",
      },

      // -- Shell escape / obfuscation (T1140 / T1059) --------------------
      {
        tool_pattern: "Bash(*bash -c*base64*|*sh -c*base64*)",
        action: "deny",
        reason: "Base64-decoded shell execution blocked by Fidelis policy",
        mitre_id: "T1140",
      },
      {
        tool_pattern: "Bash(*eval*$(base64*|*eval*$(curl*)",
        action: "deny",
        reason: "Dynamic eval with network/encoding blocked by Fidelis policy",
        mitre_id: "T1059.004",
      },
      {
        tool_pattern: "Bash(*python*-c*import*socket*|*python*-c*import*subprocess*)",
        action: "deny",
        reason: "Python reverse shell pattern blocked by Fidelis policy",
        mitre_id: "T1059.006",
      },
      {
        tool_pattern: "Bash(*perl*-e*socket*|*ruby*-e*socket*)",
        action: "deny",
        reason: "Scripted reverse shell pattern blocked by Fidelis policy",
        mitre_id: "T1059",
      },

      // -- Write to sensitive system paths --------------------------------
      {
        tool_pattern: "Write(/etc/*)",
        action: "deny",
        reason: "Write to /etc blocked by Fidelis policy",
        mitre_id: "T1543",
      },
      {
        tool_pattern: "Write(*/.ssh/*)",
        action: "deny",
        reason: "Write to SSH config/keys blocked by Fidelis policy",
        mitre_id: "T1098.004",
      },
      {
        tool_pattern: "Write(*/.bashrc|*/.bash_profile|*/.profile|*/.zshrc)",
        action: "deny",
        reason: "Shell profile modification blocked by Fidelis policy",
        mitre_id: "T1546.004",
      },
      {
        tool_pattern: "Write(*/crontab*|*/cron.d/*)",
        action: "deny",
        reason: "Crontab modification blocked by Fidelis policy",
        mitre_id: "T1053.003",
      },

      // -- Anti-forensics / evidence tampering (T1070) --------------------
      {
        tool_pattern: "Bash(*history -c*|*history -w*|*unset HISTFILE*|*HISTSIZE=0*)",
        action: "deny",
        reason: "Command history clearing blocked by Fidelis policy",
        mitre_id: "T1070.003",
      },
      {
        tool_pattern: "Bash(*>*/.bash_history*|*truncate*history*|*rm*history*)",
        action: "deny",
        reason: "History file tampering blocked by Fidelis policy",
        mitre_id: "T1070.003",
      },
      {
        tool_pattern: "Bash(*journalctl*--rotate*--vacuum*)",
        action: "deny",
        reason: "Journal log rotation/deletion blocked by Fidelis policy",
        mitre_id: "T1070.002",
      },

      // =================================================================
      // OFFENSIVE SECURITY TOOLS (Kali / pentesting / red team)
      // =================================================================

      // -- Reconnaissance / scanning (T1046 / T1595) ----------------------
      {
        tool_pattern: "Bash(*nmap *|*nmap\t*)",
        action: "deny",
        reason: "Network scanner (nmap) blocked by Fidelis policy",
        mitre_id: "T1046",
      },
      {
        tool_pattern: "Bash(*masscan*|*zmap *)",
        action: "deny",
        reason: "Mass port scanner blocked by Fidelis policy",
        mitre_id: "T1046",
      },
      {
        tool_pattern: "Bash(*nikto *|*gobuster*|*dirb *|*dirbuster*|*ffuf *|*feroxbuster*)",
        action: "deny",
        reason: "Web scanner/directory brute-forcer blocked by Fidelis policy",
        mitre_id: "T1595.003",
      },
      {
        tool_pattern: "Bash(*recon-ng*|*theHarvester*|*amass *|*subfinder*)",
        action: "deny",
        reason: "OSINT/reconnaissance framework blocked by Fidelis policy",
        mitre_id: "T1589",
      },
      {
        tool_pattern: "Bash(*enum4linux*|*smbclient*|*smbmap*|*rpcclient*)",
        action: "deny",
        reason: "SMB/RPC enumeration tool blocked by Fidelis policy",
        mitre_id: "T1135",
      },
      {
        tool_pattern: "Bash(*dnsrecon*|*dnsenum*|*fierce *|*dnsmap*)",
        action: "deny",
        reason: "DNS enumeration tool blocked by Fidelis policy",
        mitre_id: "T1018",
      },
      {
        tool_pattern: "Bash(*whatweb*|*wpscan*|*joomscan*|*droopescan*)",
        action: "deny",
        reason: "CMS/web fingerprinting tool blocked by Fidelis policy",
        mitre_id: "T1592.002",
      },

      // -- Exploitation frameworks (T1203 / T1190) ------------------------
      {
        tool_pattern: "Bash(*msfconsole*|*msfvenom*|*meterpreter*|*msf *)",
        action: "deny",
        reason: "Metasploit framework blocked by Fidelis policy",
        mitre_id: "T1203",
      },
      {
        tool_pattern: "Bash(*sqlmap*)",
        action: "deny",
        reason: "SQL injection tool (sqlmap) blocked by Fidelis policy",
        mitre_id: "T1190",
      },
      {
        tool_pattern: "Bash(*exploitdb*|*searchsploit*)",
        action: "deny",
        reason: "Exploit database tool blocked by Fidelis policy",
        mitre_id: "T1588.005",
      },
      {
        tool_pattern: "Bash(*beef-xss*|*xsser*|*xsstrike*)",
        action: "deny",
        reason: "XSS exploitation framework blocked by Fidelis policy",
        mitre_id: "T1189",
      },

      // -- Brute force / credential attacks (T1110) -----------------------
      {
        tool_pattern: "Bash(*hydra *|*hydra\t*)",
        action: "deny",
        reason: "Brute-force tool (Hydra) blocked by Fidelis policy",
        mitre_id: "T1110.001",
      },
      {
        tool_pattern: "Bash(*medusa *|*patator*|*ncrack*|*crowbar*)",
        action: "deny",
        reason: "Brute-force/credential tool blocked by Fidelis policy",
        mitre_id: "T1110",
      },
      {
        tool_pattern: "Bash(*john *|*john\t*|*hashcat*)",
        action: "deny",
        reason: "Password cracking tool blocked by Fidelis policy",
        mitre_id: "T1110.002",
      },
      {
        tool_pattern: "Bash(*ophcrack*|*rainbowcrack*|*l0phtcrack*)",
        action: "deny",
        reason: "Password cracking tool blocked by Fidelis policy",
        mitre_id: "T1110.002",
      },
      {
        tool_pattern: "Bash(*cewl *|*crunch *|*cupp *)",
        action: "deny",
        reason: "Wordlist generator blocked by Fidelis policy",
        mitre_id: "T1110.003",
      },

      // -- Credential dumping / post-exploitation (T1003) -----------------
      {
        tool_pattern: "Bash(*mimikatz*|*kiwi *|*sekurlsa*)",
        action: "deny",
        reason: "Credential dumping tool (Mimikatz) blocked by Fidelis policy",
        mitre_id: "T1003.001",
      },
      {
        tool_pattern: "Bash(*lazagne*|*truffleHog*|*git-secrets*scan*)",
        action: "deny",
        reason: "Credential harvesting tool blocked by Fidelis policy",
        mitre_id: "T1555",
      },
      {
        tool_pattern: "Bash(*impacket*|*secretsdump*|*wmiexec*|*psexec.py*|*smbexec*|*atexec*)",
        action: "deny",
        reason: "Impacket exploitation tool blocked by Fidelis policy",
        mitre_id: "T1021.002",
      },
      {
        tool_pattern: "Bash(*crackmapexec*|*cme *|*netexec*|*nxc *)",
        action: "deny",
        reason: "Network exploitation framework blocked by Fidelis policy",
        mitre_id: "T1021",
      },

      // -- C2 frameworks (T1071 / T1219) ----------------------------------
      {
        tool_pattern: "Bash(*cobaltstrike*|*beacon*|*cobalt*strike*)",
        action: "deny",
        reason: "Cobalt Strike C2 framework blocked by Fidelis policy",
        mitre_id: "T1071.001",
      },
      {
        tool_pattern: "Bash(*sliver *|*sliver-server*|*sliver-client*)",
        action: "deny",
        reason: "Sliver C2 framework blocked by Fidelis policy",
        mitre_id: "T1071.001",
      },
      {
        tool_pattern: "Bash(*empire *|*starkiller*|*covenant*|*havoc *)",
        action: "deny",
        reason: "C2 framework (Empire/Covenant/Havoc) blocked by Fidelis policy",
        mitre_id: "T1071.001",
      },
      {
        tool_pattern: "Bash(*merlin*agent*|*mythic*|*villain*)",
        action: "deny",
        reason: "C2 framework blocked by Fidelis policy",
        mitre_id: "T1071.001",
      },

      // -- Network poisoning / MITM (T1557) -------------------------------
      {
        tool_pattern: "Bash(*responder*|*Responder.py*)",
        action: "deny",
        reason: "LLMNR/NBT-NS poisoner (Responder) blocked by Fidelis policy",
        mitre_id: "T1557.001",
      },
      {
        tool_pattern: "Bash(*ettercap*|*bettercap*|*arpspoof*|*mitmproxy*)",
        action: "deny",
        reason: "MITM/ARP spoofing tool blocked by Fidelis policy",
        mitre_id: "T1557",
      },

      // -- Active Directory / lateral movement (T1087 / T1021) ------------
      {
        tool_pattern: "Bash(*bloodhound*|*sharphound*|*neo4j*bloodhound*)",
        action: "deny",
        reason: "AD enumeration tool (BloodHound) blocked by Fidelis policy",
        mitre_id: "T1087.002",
      },
      {
        tool_pattern: "Bash(*kerbrute*|*rubeus*|*getTGT*|*getST*|*kerberoast*)",
        action: "deny",
        reason: "Kerberos attack tool blocked by Fidelis policy",
        mitre_id: "T1558",
      },
      {
        tool_pattern: "Bash(*evil-winrm*|*winrm*shell*)",
        action: "deny",
        reason: "Remote management exploitation tool blocked by Fidelis policy",
        mitre_id: "T1021.006",
      },

      // -- Privilege escalation enumeration (T1082) -----------------------
      {
        tool_pattern: "Bash(*linpeas*|*winpeas*|*linenum*|*linux-exploit-suggester*)",
        action: "deny",
        reason: "Privilege escalation enumeration tool blocked by Fidelis policy",
        mitre_id: "T1082",
      },
      {
        tool_pattern: "Bash(*pspy*|*linux-smart-enumeration*|*lse.sh*)",
        action: "deny",
        reason: "Process/privilege enumeration tool blocked by Fidelis policy",
        mitre_id: "T1057",
      },

      // -- Wireless / network attacks (T1040 / T1498) ---------------------
      {
        tool_pattern: "Bash(*aircrack*|*airmon*|*airodump*|*aireplay*|*wifite*)",
        action: "deny",
        reason: "Wireless attack tool blocked by Fidelis policy",
        mitre_id: "T1040",
      },
      {
        tool_pattern: "Bash(*hping3*|*scapy*|*tcpreplay*)",
        action: "deny",
        reason: "Packet crafting/injection tool blocked by Fidelis policy",
        mitre_id: "T1498",
      },

      // -- Payload generation / evasion (T1027 / T1587.001) ---------------
      {
        tool_pattern: "Bash(*venom*|*shellter*|*veil *|*veil-evasion*)",
        action: "deny",
        reason: "Payload generator/AV evasion tool blocked by Fidelis policy",
        mitre_id: "T1587.001",
      },
      {
        tool_pattern: "Bash(*upx *|*upx\t*)",
        action: "deny",
        reason: "Binary packer (UPX) blocked by Fidelis policy",
        mitre_id: "T1027.002",
      },

      // -- Reverse engineering / binary exploitation ----------------------
      {
        tool_pattern: "Bash(*gdb*-ex*|*gdb*-batch*run*)",
        action: "deny",
        reason: "Debugger exploitation pattern blocked by Fidelis policy",
        mitre_id: "T1055",
      },
      {
        tool_pattern: "Bash(*ropper*|*ROPgadget*|*pwntools*|*pwn *)",
        action: "deny",
        reason: "Binary exploitation tool blocked by Fidelis policy",
        mitre_id: "T1203",
      },

      // =================================================================
      // ASK — dangerous but sometimes legitimate, require human approval
      // =================================================================

      // -- Service lifecycle (T1489) --------------------------------------
      {
        tool_pattern: "Bash(*systemctl stop*|*systemctl disable*|*systemctl mask*)",
        action: "ask",
        reason: "Service stop/disable requires operator approval",
        mitre_id: "T1489",
      },
      {
        tool_pattern: "Bash(*systemctl restart*|*systemctl reload*)",
        action: "ask",
        reason: "Service restart/reload requires operator approval",
        mitre_id: "T1489",
      },

      // -- Docker compose lifecycle ---------------------------------------
      {
        tool_pattern: "Bash(*docker compose down*|*docker compose rm*)",
        action: "ask",
        reason: "Docker compose teardown requires operator approval",
        mitre_id: "T1489",
      },
      {
        tool_pattern: "Bash(*docker compose up*|*docker compose restart*)",
        action: "ask",
        reason: "Docker compose lifecycle change requires operator approval",
        mitre_id: "T1489",
      },

      // -- Database destructive operations (T1485) ------------------------
      {
        tool_pattern: "Bash(*DROP TABLE*|*DROP DATABASE*|*TRUNCATE*|*DELETE FROM*)",
        action: "ask",
        reason: "Destructive SQL operation requires operator approval",
        mitre_id: "T1485",
      },

      // -- Package management / supply chain (T1195.002) ------------------
      {
        tool_pattern: "Bash(*npm install*|*pip install*|*apt install*|*apt-get install*)",
        action: "ask",
        reason: "Package installation requires operator approval",
        mitre_id: "T1195.002",
      },

      // -- Git push / exfiltration (T1567) --------------------------------
      {
        tool_pattern: "Bash(*git push*)",
        action: "ask",
        reason: "Git push requires operator approval",
        mitre_id: "T1567",
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
