# Changelog

All notable changes to Fidelis Channel are documented in this file.

## [0.4.0] - 2026-03-28

### Added
- **ML-DSA-65 post-quantum signatures** on every audit log entry (FIPS 204)
  - Keypair auto-generated on first run, stored in data directory (chmod 600)
  - Public key hash logged at session start for key pinning
  - Signatures verified during `fidelis_audit_verify`
  - Designed for harvest-now-decrypt-later threat model (10-15+ year non-repudiation)
- **SHA3-256 hash chaining** replaces SHA-256 for quantum-resistant tamper detection
  - Backwards-compatible verifier handles legacy SHA-256 entries
  - `hash_algorithm` field on each entry disambiguates the chain algorithm
- **MITRE ATT&CK enrichment** on every policy decision audit entry
  - `rule_id` field captures the matched policy rule
  - `mitre` object includes technique ID, name, and tactic
  - Static lookup table covers all 65+ techniques in the default ruleset
- **Structured verification stats** from `fidelis_audit_verify`:
  total entries, PQ-signed count, HMAC-signed count, legacy entry count
- New dependency: `@noble/post-quantum` (pure JS ML-DSA-65, no native bindings)
- New source files: `quantum-signer.ts`, `mitre-attack.ts`
- New test suite: `quantum-signer.test.ts` (keypair management, signing, verification, tamper detection)

### Changed
- Version bumped to 0.4.0 (quantum-hardened audit release)
- Audit log entry schema extended with `hash_algorithm`, `rule_id`, `mitre`, `pq_signature` fields
- `fidelis_audit_verify` now reports verification stats (PQ signatures, HMAC, legacy entries)
- `fidelis_status` now includes quantum signing status and audit hash algorithm

### Security
- ML-DSA-65 provides non-repudiation against quantum adversaries
- SHA3-256 chain is resistant to length-extension attacks (unlike SHA-256)
- Keypair file restricted to owner read/write (0600)
- Graceful degradation: if `@noble/post-quantum` is unavailable, entries are unsigned but logging continues

## [0.3.1] - 2026-03-28

### Added
- **MITRE ATT&CK tagging** on all 96 policy rules — 64 unique technique IDs
- **Kali/offensive security tool coverage** — 39 new deny rules covering:
  - Reconnaissance: nmap, masscan, zmap, nikto, gobuster, ffuf, feroxbuster, recon-ng, theHarvester, amass, subfinder
  - SMB/DNS enumeration: enum4linux, smbclient, smbmap, dnsrecon, dnsenum, fierce
  - CMS scanning: wpscan, joomscan, whatweb, droopescan
  - Exploitation frameworks: Metasploit (msfconsole, msfvenom), sqlmap, searchsploit, BeEF, XSSer
  - Brute force: Hydra, Medusa, Patator, ncrack, John the Ripper, Hashcat, ophcrack
  - Wordlist generation: CeWL, Crunch, CUPP
  - Credential dumping: Mimikatz, LaZagne, Impacket (secretsdump, wmiexec, psexec.py), CrackMapExec
  - C2 frameworks: Cobalt Strike, Sliver, Empire, Covenant, Havoc, Merlin, Mythic
  - Network poisoning/MITM: Responder, Ettercap, Bettercap, arpspoof, mitmproxy
  - AD/lateral movement: BloodHound, SharpHound, Kerbrute, Rubeus, Evil-WinRM
  - Privilege escalation enumeration: LinPEAS, WinPEAS, LinEnum, linux-exploit-suggester, pspy
  - Wireless attacks: aircrack-ng, airmon-ng, airodump-ng, wifite
  - Packet crafting: hping3, scapy, tcpreplay
  - Payload generation/evasion: Veil, Shellter, UPX packer
  - Binary exploitation: ROPgadget, pwntools, ropper
- **Anti-forensics detection** — history clearing, HISTFILE unsetting, journal log tampering, shred
- **LOLBin network channels** — /dev/tcp redirects, openssl s_client, chisel, proxychains
- **System credential file protection** — /etc/shadow, /etc/passwd read blocking
- **MITRE ID in Telegram deny notifications** — operators see the ATT&CK technique on every auto-deny
- 54 new tests (145 total, all passing)

### Changed
- Policy engine expanded from 50 to 96 rules (89 hard deny + 7 ask)
- `PolicyRule` interface now includes optional `mitre_id` field

## [0.3.0] - 2026-03-28

### Added
- **Hardened default policy engine** with 50 rules (43 hard deny + 7 ask)
  - Filesystem destruction (rm -rf, mkfs, dd, wipefs)
  - Safety bypass flags (--no-verify, --skip-verification, --insecure)
  - Network exfiltration/C2 (curl, wget, nc, scp, rsync, ftp, socat, ngrok)
  - Credential/secret theft (cat .env, .ssh, id_rsa — both Bash and Read tools)
  - Git destructive operations (force push, hard reset, clean -fd)
  - Privilege escalation (chmod 777, SUID/SGID, chown root)
  - Firewall teardown (iptables -F, ufw disable, nft flush)
  - Container escape (--privileged, --pid=host, --net=host)
  - Docker destruction (rm -f, kill, system prune)
  - Crypto mining (xmrig, cpuminer, minerd)
  - Shell obfuscation (base64 decode+exec, eval+curl)
  - Reverse shell patterns (python/perl/ruby socket)
  - Sensitive path writes (Write to /etc, .ssh, .bashrc, crontab)
- **Ask rules** for operations requiring human approval:
  - systemctl stop/disable/restart/reload
  - docker compose down/up/restart
  - Destructive SQL (DROP TABLE, TRUNCATE, DELETE FROM)
  - Package installation (npm, pip, apt)
  - git push (any)
- 52 new tests covering all hardened default rules
- Repository metadata (homepage, bugs, repository URL) in package.json
- `files` field in package.json for clean npm publishing

### Changed
- Version bumped to 0.3.0 (security-hardened release)
- Plugin manifest now references `.mcp.marketplace.json` (template variables only)

### Security
- Removed `.mcp.json` from git history (contained development credentials)
- Added `.mcp.json` and `.mcp.local.json` to `.gitignore`
- Default policy posture assumes hostile agents, not cooperative ones

## [0.2.2] - 2026-03-27

### Changed
- Synced package and plugin manifest versions
- Removed chat-only citation markup from README
- Reworked test execution: compile-first flow, no `tsx` runtime dependency
- Hardened SessionStart hook with `mkdir -p` for data directory

### Fixed
- Telegram `sendMessage()` now throws on HTTP or API failure
- `requestVerdict()` only waits if at least one prompt was delivered
- Default reply path escapes HTML; `raw_html=true` for intentional rich formatting

## [0.2.0] - 2026-03-26

### Added
- Identity Provider with DIB Briefcase integration
- 7-tier consent model (Public through Sealed)
- Sensitivity classification engine (SSN, email, DOB, diagnosis codes, MRN, crisis content)
- Consent boundary enforcement with `forbidden_tools` per tier
- Audit log field redaction (tier-driven)
- Agent authorization context
- Smuggling/obfuscation detection (base64, hex encoding, eval, pipe chains)
- PII/PHI heuristic detection (SSN, email, phone — always-on)

### Changed
- Cross-LLM review pass: tightened security and plugin conventions

## [0.1.0] - 2026-03-25

### Added
- Initial release
- Fail-closed Telegram permission relay
- Policy engine with glob-pattern rule matching
- Tamper-evident audit log with SHA-256 hash chaining
- Optional HMAC-SHA256 audit signing
- Velocity limiting (requests per minute)
- Anomaly detection (privilege escalation, sensitive access, data exfiltration, destructive git)
- Three MCP tools: `fidelis_reply`, `fidelis_status`, `fidelis_audit_verify`
