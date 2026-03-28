/**
 * Fidelis Channel — MITRE ATT&CK Enrichment
 *
 * Static lookup table mapping technique IDs used in the default policy rules
 * to their human-readable names and tactics. This enables structured audit
 * entries with ATT&CK context without requiring a runtime STIX data dependency.
 *
 * Source: MITRE ATT&CK v16 (Enterprise)
 * https://attack.mitre.org/
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
}

// ---------------------------------------------------------------------------
// Lookup table — all techniques referenced by default policy rules
// ---------------------------------------------------------------------------

const ATTACK_MAP: Record<string, AttackTechnique> = {
  // -- Impact ----------------------------------------------------------------
  "T1485": { id: "T1485", name: "Data Destruction", tactic: "Impact" },
  "T1489": { id: "T1489", name: "Service Stop", tactic: "Impact" },
  "T1496": { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
  "T1498": { id: "T1498", name: "Network Denial of Service", tactic: "Impact" },
  "T1561.001": { id: "T1561.001", name: "Disk Content Wipe", tactic: "Impact" },
  "T1561.002": { id: "T1561.002", name: "Disk Structure Wipe", tactic: "Impact" },

  // -- Defense Evasion -------------------------------------------------------
  "T1070.002": { id: "T1070.002", name: "Clear Linux or Mac System Logs", tactic: "Defense Evasion" },
  "T1070.003": { id: "T1070.003", name: "Clear Command History", tactic: "Defense Evasion" },
  "T1070.004": { id: "T1070.004", name: "File Deletion", tactic: "Defense Evasion" },
  "T1140": { id: "T1140", name: "Deobfuscate/Decode Files or Information", tactic: "Defense Evasion" },
  "T1222.002": { id: "T1222.002", name: "Linux and Mac File and Directory Permissions Modification", tactic: "Defense Evasion" },
  "T1027.002": { id: "T1027.002", name: "Software Packing", tactic: "Defense Evasion" },
  "T1055": { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
  "T1562.001": { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion" },
  "T1562.004": { id: "T1562.004", name: "Disable or Modify System Firewall", tactic: "Defense Evasion" },

  // -- Exfiltration ----------------------------------------------------------
  "T1048": { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  "T1048.003": { id: "T1048.003", name: "Exfiltration Over Unencrypted Non-C2 Protocol", tactic: "Exfiltration" },
  "T1567": { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },

  // -- Command and Control ---------------------------------------------------
  "T1071.001": { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
  "T1095": { id: "T1095", name: "Non-Application Layer Protocol", tactic: "Command and Control" },
  "T1105": { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
  "T1572": { id: "T1572", name: "Protocol Tunneling", tactic: "Command and Control" },
  "T1573.002": { id: "T1573.002", name: "Asymmetric Cryptography", tactic: "Command and Control" },

  // -- Credential Access -----------------------------------------------------
  "T1003.001": { id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access" },
  "T1003.008": { id: "T1003.008", name: "/etc/passwd and /etc/shadow", tactic: "Credential Access" },
  "T1040": { id: "T1040", name: "Network Sniffing", tactic: "Credential Access" },
  "T1110": { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  "T1110.001": { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
  "T1110.002": { id: "T1110.002", name: "Password Cracking", tactic: "Credential Access" },
  "T1110.003": { id: "T1110.003", name: "Password Spraying", tactic: "Credential Access" },
  "T1552.001": { id: "T1552.001", name: "Credentials In Files", tactic: "Credential Access" },
  "T1552.004": { id: "T1552.004", name: "Private Keys", tactic: "Credential Access" },
  "T1555": { id: "T1555", name: "Credentials from Password Stores", tactic: "Credential Access" },
  "T1557": { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access" },
  "T1557.001": { id: "T1557.001", name: "LLMNR/NBT-NS Poisoning and SMB Relay", tactic: "Credential Access" },
  "T1558": { id: "T1558", name: "Steal or Forge Kerberos Tickets", tactic: "Credential Access" },

  // -- Execution -------------------------------------------------------------
  "T1053.003": { id: "T1053.003", name: "Cron", tactic: "Execution" },
  "T1059": { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  "T1059.004": { id: "T1059.004", name: "Unix Shell", tactic: "Execution" },
  "T1059.006": { id: "T1059.006", name: "Python", tactic: "Execution" },
  "T1203": { id: "T1203", name: "Exploitation for Client Execution", tactic: "Execution" },

  // -- Privilege Escalation --------------------------------------------------
  "T1548": { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "T1548.001": { id: "T1548.001", name: "Setuid and Setgid", tactic: "Privilege Escalation" },
  "T1611": { id: "T1611", name: "Escape to Host", tactic: "Privilege Escalation" },

  // -- Persistence -----------------------------------------------------------
  "T1098.004": { id: "T1098.004", name: "SSH Authorized Keys", tactic: "Persistence" },
  "T1543": { id: "T1543", name: "Create or Modify System Process", tactic: "Persistence" },
  "T1546.004": { id: "T1546.004", name: "Unix Shell Configuration Modification", tactic: "Persistence" },

  // -- Discovery -------------------------------------------------------------
  "T1018": { id: "T1018", name: "Remote System Discovery", tactic: "Discovery" },
  "T1046": { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  "T1057": { id: "T1057", name: "Process Discovery", tactic: "Discovery" },
  "T1082": { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  "T1087.002": { id: "T1087.002", name: "Domain Account", tactic: "Discovery" },
  "T1135": { id: "T1135", name: "Network Share Discovery", tactic: "Discovery" },

  // -- Lateral Movement ------------------------------------------------------
  "T1021": { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  "T1021.002": { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement" },
  "T1021.006": { id: "T1021.006", name: "Windows Remote Management", tactic: "Lateral Movement" },

  // -- Initial Access --------------------------------------------------------
  "T1189": { id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" },
  "T1190": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "T1195.002": { id: "T1195.002", name: "Compromise Software Supply Chain", tactic: "Initial Access" },

  // -- Reconnaissance --------------------------------------------------------
  "T1589": { id: "T1589", name: "Gather Victim Identity Information", tactic: "Reconnaissance" },
  "T1592.002": { id: "T1592.002", name: "Software", tactic: "Reconnaissance" },
  "T1595.003": { id: "T1595.003", name: "Wordlist Scanning", tactic: "Reconnaissance" },

  // -- Resource Development --------------------------------------------------
  "T1587.001": { id: "T1587.001", name: "Malware", tactic: "Resource Development" },
  "T1588.005": { id: "T1588.005", name: "Exploits", tactic: "Resource Development" },
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Look up ATT&CK technique metadata by ID.
 * Returns undefined if the technique is not in the lookup table.
 */
export function lookupTechnique(techniqueId: string): AttackTechnique | undefined {
  return ATTACK_MAP[techniqueId];
}

/**
 * Enrich a MITRE technique ID into a full AttackTechnique object.
 * Returns null if the ID is not recognized.
 */
export function enrichMitre(techniqueId: string | undefined): AttackTechnique | null {
  if (!techniqueId) return null;
  return ATTACK_MAP[techniqueId] ?? null;
}
