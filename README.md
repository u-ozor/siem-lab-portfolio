# SIEM Homelab

Self-hosted security monitoring environment built on bare-metal Proxmox, with live attack simulation across on-prem and cloud infrastructure.

---

## Stack

Proxmox VE · Ubuntu Server 22.04 · Windows Server 2022 · Wazuh 4.9 (OpenSearch) · Active Directory · AWS (CloudTrail, S3, IAM) · LVM · KVM

---

## What was built

**Infrastructure**
- Bare-metal Proxmox hypervisor on a repurposed laptop — ethernet bridge networking, lid-sleep disabled for 24/7 uptime, static LAN IP
- LVM storage expanded across two physical volumes from unpartitioned disk space, without touching the existing OS partition
- Wazuh all-in-one deployment (manager + indexer + dashboard) on dedicated Ubuntu 22.04 VM — SSL certificate and OpenSearch auth configured end-to-end

**Endpoints**
- Wazuh agent deployed on macOS (Apple Silicon) — live event stream confirmed in dashboard
- Windows Server 2022 VM provisioned as Active Directory Domain Controller (forest `lab.local`, UEFI/Q35, static IP)
- AD structure: OUs for IT Admins, Standard Users, Servers, Workstations; test accounts Alice and Bob; account lockout policy via Default Domain Policy GPO
- Wazuh agent deployed on DC01 — Windows Security Event log pipeline active

**Monitoring**
- File Integrity Monitoring (FIM) watching system binary paths on macOS — integrity events across `/usr/sbin` confirmed in dashboard
- SCA running CIS Apple macOS 15.0 Sequoia Benchmark — identified failing checks, remediated, and confirmed fix via rescan
- OpenSearch ISM retention policy on `wazuh-alerts-*` indices — auto-delete after 30 days
- MITRE ATT&CK tagging and PCI DSS / HIPAA / GDPR / NIST 800-53 compliance attribution on all fired rules

**AWS integration**
- CloudTrail trail (`siem-lab-trail`) logging to S3 across all regions
- Wazuh `aws-s3` wodle configured to pull CloudTrail logs from S3 every 5 minutes — pipeline confirmed end-to-end
- Custom detection rule (rule 100002, level 10, MITRE T1087) written in `local_rules.xml` — elevates built-in level 3 CloudTrail alert to prioritised level 10 with MITRE Discovery tagging

---

## Attack scenarios demonstrated

| Scenario | Technique | MITRE | Rule | Level |
|---|---|---|---|---|
| SSH brute force (Mac → Wazuh VM) | Credential Access | T1110 | 2502 | 10 |
| AD privilege escalation — Bob added to Domain Admins (Event ID 4728) | Defense Evasion, Privilege Escalation | T1484 | 60159 | 12 |
| Account lockout — Bob locked after failed logon loop (Event ID 4740) | — | — | Confirmed in AD (ADUC) | — |
| AWS IAM enumeration via CLI — `list-users`, `list-roles`, `get-caller-identity` | Account Discovery | T1087 | 100002 | 10 |

All alerts confirmed in Wazuh dashboard with full MITRE ATT&CK tactic/technique attribution and compliance framework tags (PCI DSS, HIPAA, GDPR, NIST 800-53).

---

## Screenshots

| # | Description |
|---|---|
| 01 | Wazuh dashboard — initial confirmed load |
| 02–06 | SSH brute force simulation — alert list, terminal, expanded alert detail (rule 2502, T1110, rhost MAC IP) |
| 07–10 | SCA before/after — CIS macOS 15 benchmark, check 35022 remediation confirmed |
| 11 | Proxmox physical console — bare metal boot screen |
| 12 | Wazuh endpoints — macOS agent active |
| 13–14 | Proxmox VM disks + local-lvm storage summary showing multi-PV expansion |
| 15–22 | Windows / AD phase — DC01 agent dashboard, PowerShell attack simulation, Event 4728 alert detail (T1484, level 12, compliance tags), Bob account lockout in ADUC, dual-agent overview |
| 23–32 | AWS phase — CloudTrail pipeline confirmed, IAM enumeration alerts, custom rule 100002 firing at level 10 (T1087, Discovery) |
| 33 | FIM — macOS `/usr/sbin` integrity events confirmed in dashboard, rule 550, level 7 |

---

## Planned extension

**AWS GuardDuty** — ML-based threat detection integrated into Wazuh via the findings feed. GuardDuty would add a second detection layer alongside the CloudTrail rule-based approach: anomaly detection on API behaviour rather than pattern matching on specific event names. Integration is scoped and ready; pending AWS account activation.

Once active, the IAM policy for the `siem-lab` user will be narrowed from `ReadOnlyAccess` to S3 + GuardDuty permissions only.
