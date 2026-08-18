# SIEM Homelab

Self-hosted security monitoring environment built on bare-metal Proxmox, with live attack simulation across on-prem and cloud infrastructure.

---

## Stack

Proxmox VE · Ubuntu Server 22.04 · Docker Compose · Windows Server 2022 · Wazuh 4.9 (OpenSearch) · Active Directory · AWS (CloudTrail, S3, IAM)

---

## What was built

**Infrastructure**
- Bare-metal Proxmox hypervisor on a repurposed laptop — ethernet bridge networking, lid-sleep disabled for 24/7 uptime, static LAN IP
- Wazuh all-in-one stack (manager + indexer + dashboard) running via Docker Compose on a dedicated Ubuntu 22.04 VM

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
- IAM user `siem-lab` scoped to least privilege — `ReadOnlyAccess` detached, replaced with custom policy granting `s3:ListBucket` and `s3:GetObject` on the specific CloudTrail bucket only

---

## Architecture decisions

**Wazuh on Docker Compose, not bare-metal**

The lab started with a bare-metal Wazuh install — manager, indexer, and dashboard installed directly onto the Ubuntu VM. This worked for the initial phases but became increasingly difficult to recover from. The OpenSearch security layer (securityadmin, kibanaserver password sync, cert validation order) had a specific sequence that had to be followed exactly, and any deviation — a password change, a service restart out of order — could break the dashboard in ways that took hours to diagnose. The problem wasn't any single step; it was that the failure modes compounded and the recovery procedure had to be rebuilt from scratch each time.

Migrating to Docker Compose eliminated that class of problem. The stack is now fully declarative — passwords set as environment variables, config files bind-mounted, certs generated once via the official generator image. A broken stack is `docker compose down -v && docker compose up -d`. The custom config (CloudTrail wodle, detection rules) lives in bind-mounted files outside the containers and survives redeployment. The trade-off is that Docker adds an abstraction layer between you and the Wazuh internals, which matters less here than having a lab that's actually usable.

**IAM scoped to least privilege after pipeline confirmation**

The `siem-lab` IAM user started with `ReadOnlyAccess` (broad, AWS-managed) to get the CloudTrail pipeline working end to end first. Once confirmed, the policy was replaced with a custom one granting only `s3:ListBucket` and `s3:GetObject` on the specific CloudTrail bucket. This means IAM enumeration calls now return `AccessDenied` for those credentials — which is correct. The detection rule fires on the CloudTrail event regardless of whether the call succeeded. Locking the service account down after validation is the right posture.

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

## Scope decision — AWS GuardDuty

GuardDuty was evaluated as a second detection layer alongside CloudTrail — ML-based anomaly detection on API behaviour rather than pattern matching on specific event names. Descoped after confirming it is no longer covered under AWS free tier. The CloudTrail rule-based pipeline covers the core detection use case for this lab.
