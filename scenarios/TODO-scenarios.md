# Scenarios — To Do

Simulations not yet run. For each one: run the attack, confirm the alert fires in the dashboard, write the full scenario doc in this folder.

---

## Detection Scenarios

### CloudTrail Logging Disabled → Re-enabled
**MITRE:** T1562.008 — Impair Defenses: Disable Cloud Logs  
**How:** `aws cloudtrail stop-logging --name <trail>`, then `start-logging`  
**Expected detection:** GuardDuty finding or custom CloudTrail rule on `StopLogging` eventName  
**Why it matters:** Attackers disable logging before destructive actions. Detection of this is a high-value signal.

---

### S3 Bucket Policy Change
**MITRE:** T1578 — Modify Cloud Compute Infrastructure  
**How:** `aws s3api put-bucket-policy` with a permissive policy  
**Expected detection:** CloudTrail `PutBucketPolicy` event → custom rule  
**Why it matters:** Misconfigured S3 is one of the most common cloud data exposure vectors.

---

### Lateral Movement via RDP / SMB
**MITRE:** T1021 — Remote Services  
**How:** From DC01, attempt RDP or SMB connection to another host  
**Expected detection:** Wazuh rule on Windows authentication events for RDP sessions, or Suricata (once integrated) for SMB traffic patterns  
**Why it matters:** Post-initial-access, attackers move laterally. Detecting the pivot is critical.

---

### Kerberoasting
**MITRE:** T1558.003 — Steal or Forge Kerberos Tickets  
**How:** `Invoke-Kerberoast` via PowerShell on a domain-joined host — requests TGS tickets for service accounts  
**Expected detection:** High volume of Kerberos TGS requests (Event ID 4769) from a single host in a short window  
**Why it matters:** Classic AD attack. Service account password hashes can be cracked offline.

---

### Pass-the-Hash
**MITRE:** T1550.002 — Use Alternate Authentication Material  
**How:** Mimikatz `sekurlsa::pth` with NTLM hash from a compromised account  
**Expected detection:** Unusual logon type (Event ID 4624, LogonType 9 = NewCredentials) without prior interactive logon  
**Why it matters:** Allows lateral movement without knowing the plaintext password.

---

### Credential Dump (Mimikatz / LSASS)
**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory  
**How:** Mimikatz `sekurlsa::logonpasswords` or `procdump -ma lsass.exe`  
**Expected detection:** Process creation alert (Event ID 4688) with `lsass` in command line, or Wazuh rootcheck / FIM on the output file  
**Why it matters:** Standard post-compromise step. Dumping LSASS gives an attacker all active credential material.

---

## Integration Scenarios

### Suricata Network Detection
**What:** Deploy Suricata IDS alongside Wazuh. Suricata watches raw network traffic at the bridge level; Wazuh ingests Suricata alerts alongside host logs.  
**Detection added:** Network-layer visibility — port scans, C2 callback patterns, malformed packets, known CVE exploitation  
**Setup needed:** Suricata installed on Proxmox host or Wazuh VM with access to the bridge interface. Wazuh Suricata integration configured.

---

### GuardDuty Integration
**What:** Enable AWS GuardDuty and configure Wazuh to ingest GuardDuty findings via the aws-s3 module (findings written to S3) or direct API pull.  
**Detection added:** AWS ML-based threat detection — unusual API calls, crypto mining, compromised EC2 behaviour, credential exfiltration patterns  
**Setup needed:** GuardDuty enabled in the AWS account. Wazuh aws module configured for `guardduty` service type.

---

### Active Response — Automated IP Blocking
**What:** Configure Wazuh Active Response to automatically block a source IP when a brute force threshold is hit (e.g. rule 2502 fires 3 times from same IP in 60s).  
**Effect:** Wazuh runs `firewall-drop` script on the monitored host to add an iptables rule blocking the IP. Alert is generated for the block action.  
**Why it matters:** Turns the SIEM from passive detection to active defence.
