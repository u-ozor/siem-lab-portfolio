# SIEM Lab — Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        HOME LAN (10.0.0.0/24)                    │
│                        Router / DHCP: 10.0.0.1                   │
│                                                                   │
│  ┌────────────────────────────┐   ┌──────────────────────────┐   │
│  │   Mac (10.0.0.102)         │   │   DC01 VM (10.0.0.110)   │   │
│  │   Wazuh Agent 001          │   │   Wazuh Agent 002        │   │
│  │   macOS Sequoia            │   │   Windows Server 2022    │   │
│  │   SCA: CIS macOS benchmark │   │   Active Directory DC    │   │
│  └────────────┬───────────────┘   └────────────┬─────────────┘   │
│               │ TCP 1514                        │ TCP 1514        │
│               │                                 │                 │
│  ┌────────────▼─────────────────────────────────▼─────────────┐  │
│  │            Proxmox Host (10.0.0.107)                        │  │
│  │            USB ethernet → vmbr0 bridge                      │  │
│  │                                                             │  │
│  │   ┌─────────────────────────────────────────────────────┐  │  │
│  │   │              Wazuh VM (10.0.0.105)                  │  │  │
│  │   │              Ubuntu 22.04 LTS                       │  │  │
│  │   │                                                     │  │  │
│  │   │   Docker Compose — single-node stack                │  │  │
│  │   │                                                     │  │  │
│  │   │   ┌─────────────────────────────────────────────┐  │  │  │
│  │   │   │          wazuh.manager                      │  │  │  │
│  │   │   │  :1514 agent log ingestion                  │  │  │  │
│  │   │   │  :1515 agent registration                   │  │  │  │
│  │   │   │  :55000 REST API                            │  │  │  │
│  │   │   │                                             │  │  │  │
│  │   │   │  Rule engine (3000+ built-in rules)         │  │  │  │
│  │   │   │  Custom rule 100002 (CloudTrail IAM)        │  │  │  │
│  │   │   │  aws-s3 wodle (polls S3 every 5 min)        │  │  │  │
│  │   │   └──────────────────┬──────────────────────────┘  │  │  │
│  │   │                      │ fires alerts                 │  │  │
│  │   │   ┌──────────────────▼──────────────────────────┐  │  │  │
│  │   │   │          wazuh.indexer (OpenSearch)          │  │  │  │
│  │   │   │  :9200 REST API                             │  │  │  │
│  │   │   │  Stores all events and alerts               │  │  │  │
│  │   │   │  ISM: auto-delete indices after 30 days     │  │  │  │
│  │   │   └──────────────────┬──────────────────────────┘  │  │  │
│  │   │                      │                              │  │  │
│  │   │   ┌──────────────────▼──────────────────────────┐  │  │  │
│  │   │   │          wazuh.dashboard                    │  │  │  │
│  │   │   │  :443 HTTPS                                 │  │  │  │
│  │   │   │  Browser UI — alerts, queries, dashboards   │  │  │  │
│  │   │   └─────────────────────────────────────────────┘  │  │  │
│  │   └─────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘

AWS Cloud (external)
─────────────────────────────────────────────────────────────────────

  AWS Account
  ├── CloudTrail trail → writes JSON logs to S3 bucket
  └── S3 bucket (CloudTrail logs)
                │
                │ HTTPS poll every 5 minutes
                │ IAM user: siem-lab (s3:ListBucket + s3:GetObject only)
                ▼
  aws-s3 wodle (wazuh.manager)
        │
        ▼
  Rule engine → Rule 100002 fires → level 10 alert, MITRE T1087

─────────────────────────────────────────────────────────────────────

Data Flow Summary
─────────────────

  Agent logs        → manager (TCP 1514) → rule engine → indexer → dashboard
  CloudTrail logs   → S3 → aws-s3 wodle → rule engine → indexer → dashboard
  SCA checks        → agent → manager → indexer → Compliance dashboard
  FIM events        → agent → manager → indexer → Security Events dashboard

MITRE Coverage (lab scenarios)
────────────────────────────────

  T1110  Brute Force             — SSH auth failures, Rule 2502
  T1484  Domain Policy Mod       — AD group change (4728), Rule 60159
  T1087  Account Discovery       — IAM enumeration, Rule 100002
  T1531  Account Access Removal  — Account lockout (4740)
```
