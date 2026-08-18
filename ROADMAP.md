# SIEM Lab — Roadmap

Tracks what's done, what's in progress, and where this lab is going.

---

## Completed

- [x] Proxmox bare-metal hypervisor on repurposed laptop
- [x] Wazuh stack via Docker Compose (manager + indexer + dashboard)
- [x] Mac agent enrolled and shipping logs
- [x] Windows Server 2022 Domain Controller (DC01) provisioned and agent enrolled
- [x] SSH brute force simulation — Rule 2502, T1110, level 10
- [x] AD privilege escalation simulation — Rule 60159, Event ID 4728, T1484, level 12
- [x] Account lockout simulation — Event ID 4740
- [x] AWS CloudTrail → S3 → Wazuh pipeline
- [x] AWS IAM enumeration simulation — Custom rule 100002, T1087, level 10
- [x] SCA — CIS macOS 15 Sequoia benchmark, full remediation workflow
- [x] IAM user scoped to least privilege (S3 list/get on CloudTrail bucket only)
- [x] ISM policy — auto-delete wazuh-alerts-* indices after 30 days

---

## Planned — Detection & Attack Scenarios

- [ ] CloudTrail logging disabled then re-enabled — T1562 (Impair Defenses)
- [ ] S3 bucket policy change detection — T1578
- [ ] Lateral movement via RDP/SMB — T1021
- [ ] Kerberoasting simulation — T1558
- [ ] Mimikatz / credential dump detection — T1003
- [ ] Pass-the-hash — T1550
- [ ] Wazuh Active Response — automated IP blocking on brute force threshold

---

## Planned — Integrations & Stack

- [ ] Suricata IDS — network-layer detection alongside host-layer Wazuh
- [ ] GuardDuty integration — AWS ML-based findings into Wazuh dashboard
- [ ] MISP threat intel feed — IOC enrichment on alerts
- [ ] Wazuh email / Slack alerting for high-severity rules
- [ ] Second Proxmox node (multi-node cluster experiment)
- [ ] VLAN segmentation on managed switch — isolate lab traffic from home LAN

---

## Descoped

- GuardDuty (for now) — not needed to demonstrate CloudTrail pipeline. Can be added once quota allows.
- Vulnerability detector — disabled permanently. Consumes 20GB+ disk in one session. Not worth the cost for this lab's goals.
