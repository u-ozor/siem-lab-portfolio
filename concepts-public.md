# SIEM Lab — Concepts

Technical explanations of concepts encountered during this build. Focused on detection, cloud integration, and Active Directory — the three domains the lab covers.

---

## What is a SIEM

SIEM (Security Information and Event Management) — a central hub that collects logs from multiple sources, normalises them into a common format, and runs detection rules against them to fire alerts.

In a real SOC, analysts spend most of their day in the SIEM — triaging alerts, hunting threats, correlating events across systems. Building one from scratch demonstrates you understand the workflow from both sides: getting logs in, and writing rules to make sense of them.

---

## Wazuh stack — three components

| Component | What it does |
|---|---|
| **Wazuh Manager** | The brain. Receives logs from agents, runs detection rules, fires alerts. |
| **Wazuh Indexer** | Storage and search engine (OpenSearch). Stores all events and alerts. |
| **Wazuh Dashboard** | Browser UI. Where you view alerts, write queries, build dashboards. |

**Wazuh Agent** — installed on machines you want to monitor. Ships logs, FIM events, and process info to the Manager over TCP 1514.

---

## ossec.conf — what it is and what's in it

`ossec.conf` is the master configuration file for the Wazuh manager. Key sections:

- **`<syscheck>`** — FIM: which paths to watch, scan interval, what events to alert on
- **`<sca>`** — which CIS benchmark policy files to run against endpoints
- **`<wodle name="aws-s3">`** — the CloudTrail pull module. Contains bucket name, credentials, and poll interval. This one block is the entire AWS integration config.
- **`<auth>`** — agent registration settings
- **`<remote>`** — port and protocol agents use to connect (TCP 1514)

`local_rules.xml` is kept separate so Wazuh upgrades update the built-in ruleset without touching your custom rules. Custom rules survive upgrades.

`client.keys` maps agent ID → name → IP → shared secret. Lose it and every agent needs to re-register.

---

## Wodles — Wazuh modules

"Wodle" = Wazuh module. Components that run independently of the main rule engine on their own schedules:

- `aws-s3` — polls S3 for CloudTrail logs every N minutes, parses JSON, hands events to the rule engine
- `vulnerability-detector` — downloads CVE feeds, scans installed packages on agents
- `syscollector` — inventories hardware, OS, packages, and running processes on each agent

Each has a `<disabled>yes/no</disabled>` toggle in ossec.conf.

---

## Custom Wazuh detection rules

Built-in rules live in `/var/ossec/ruleset/rules/` — don't touch these, they get overwritten on upgrades. Custom rules go in `local_rules.xml`.

**Rule structure:**
```xml
<rule id="100002" level="10">
  <if_sid>87701</if_sid>
  <field name="aws.eventName">ListUsers|ListRoles|GetCallerIdentity</field>
  <description>AWS IAM enumeration — account discovery activity</description>
  <mitre>
    <id>T1087</id>
  </mitre>
</rule>
```

**Key fields:**
- `id` — 100000+ for custom rules (below that is reserved)
- `level` — severity 0–15. 7+ surfaces as an alert. 12+ is high severity.
- `if_sid` — chain: fires whenever the referenced rule fires AND field conditions match
- `if_matched_sid` — correlation: fires if the referenced rule fired within a time window
- `frequency` + `timeframe` — fires if the rule triggers N times within X seconds (brute force pattern)

---

## Wazuh rule field naming vs OpenSearch field naming

In rule XML, fields use the raw Wazuh event name — e.g. `aws.eventName`. In the OpenSearch dashboard, the same field appears as `data.aws.eventName`. The `data.` prefix is added by the indexer — it doesn't exist at the rule engine layer.

Copying a field name from the dashboard into a rule `<field>` tag is a common mistake. The rule won't match. Check `/var/ossec/ruleset/rules/0350-amazon_rules.xml` to see what the rule engine actually uses.

---

## Wazuh rootcheck vs FIM

Two separate subsystems:

- **FIM (File Integrity Monitoring)** — watches specific paths for changes (creates, modifies, deletes). Compares checksums. Rules 550–599.
- **Rootcheck** — scans system binaries against a database of known trojan string signatures. Rule 510 = "Trojaned version of file detected."

Rootcheck produces frequent false positives on macOS — its signature database is Linux-tuned and macOS binaries contain strings that match Linux trojan patterns. Validate with `codesign -v /path/to/binary`. Silent = clean, Apple signature valid.

---

## OpenSearch Security — how securityadmin.sh works

`securityadmin.sh` pushes configuration from YAML files on disk to the OpenSearch security index. The security index is the live source of truth — YAML files are what you push from.

Key points:
- Authenticates using the admin certificate, not a password
- Pushing `internal_users.yml` overwrites any API-set passwords — run it last after any password reset sequence, then restart the dashboard
- After running, the dashboard needs a restart; the indexer does not

---

## AWS — core concepts and how they map to the lab

**CloudTrail** — records every API call made in your AWS account: who, what, when, from where. Equivalent to Windows Security Event logs for cloud API actions. Logs dump to an S3 bucket.

**GuardDuty** — analyzes CloudTrail events, VPC Flow Logs, and DNS queries using ML models. Produces findings (pre-analyzed alerts). It watches your account only. Not a SIEM — it produces findings, doesn't store raw logs.

**IAM** — controls who can do what in the account. For a SIEM integration: create a dedicated IAM user with only the permissions needed to pull logs. Nothing more.

**How Wazuh pulls from AWS:**
```
Every 5 minutes:
  aws-s3 wodle authenticates via IAM access key
  → lists new objects in S3 (CloudTrail logs)
  → downloads and parses them
  → passes events through the rule engine
```
No persistent connection. No VPN. Outbound HTTPS only.

---

## S3 IAM — why the ARN appears twice

S3 treats a bucket and its contents as two different resource types in IAM:

- `arn:aws:s3:::bucket-name` — the bucket itself. Needed for `s3:ListBucket`.
- `arn:aws:s3:::bucket-name/*` — the objects inside it. Needed for `s3:GetObject`.

Both must be listed in the policy or one of the actions is denied. This catches people every time — IAM enforces the distinction strictly.

Naming trap: `s3:ListBucket` lists objects *within* a bucket, not buckets themselves. `s3:ListAllMyBuckets` is what lists buckets. The names were set before AWS standardised them.

---

## IAM access keys — two credential types

- IAM username + password = console (browser) login
- Access Key ID + Secret Access Key = programmatic/API access

These are separate systems. A monitoring service account only needs access keys — console access is unnecessary and should not be enabled.

`AKIA` prefix on a key ID = long-term IAM user key. `ASIA` prefix = temporary STS session credentials. The prefix tells AWS the key type before validating it.

The secret key is never transmitted. It's used locally to sign requests via HMAC — AWS verifies the signature server-side by rerunning the same derivation with the stored secret. If the signatures match, the request is authentic.

---

## AWS SigV4 — what it proves

Every AWS API request is signed with HMAC-SHA256 using the secret key. The signature covers the entire request: URL, headers, body, and timestamp.

What this guarantees:
- **Authentication** — only someone with the secret can produce a valid signature
- **Integrity** — any modification to the request in transit produces a different signature, which AWS rejects
- **Replay protection** — timestamp is baked in; AWS rejects requests older than 5 minutes

The secret key never leaves your machine. AWS verifies by rerunning the same signing operation with the key it has stored.

---

## AWS CLI credential storage

| Type | Location |
|---|---|
| Permanent keys (`aws configure`) | `~/.aws/credentials` — plaintext |
| SSO token cache | `~/.aws/sso/cache/` — JSON |

Permanent credentials are plaintext on disk. No keychain, no encryption. If the key leaks, blast radius is whatever the IAM policy allows — which is why scoping permissions matters.

---

## Azure — how it differs for SIEM integration

Azure's stack is designed to stay inside Microsoft. Logs flow into Microsoft Sentinel naturally. For third-party SIEMs like Wazuh, the only clean egress point is Event Hub.

AWS is modular — CloudTrail to S3, external tools plug in via standard reads. Easier to integrate with third-party SIEMs.

---

## Active Directory — core concepts

**What AD is:** Microsoft's identity and access management system. Controls who every user and device on the network is and what they can do.

**Domain:** The logical boundary. Every object inside shares the same directory, same auth rules, same policies. One account works on every domain-joined machine.

**Domain Controller (DC):** The server running AD. Holds the database of every user, computer, group, and policy. All authentication flows through it. Also runs internal DNS for the domain.

**Kerberos:** AD's authentication protocol. On login, the DC issues a Ticket Granting Ticket (TGT). The user presents that ticket to access services — the password only goes to the DC once. Everything else is ticket-based.

**LDAP:** The query language used to talk to AD. When anything asks "is this user in the Admins group" — that's an LDAP query to the DC. SIEMs, VPNs, and ticketing tools commonly authenticate against AD via LDAP.

**Group Policy (GPO):** Rules pushed from the DC to every domain-joined machine automatically. Password complexity, screen lock, software restrictions — configured once on the DC, enforced everywhere. Applied per-OU.

---

## AD OU structure

OU = Organisational Unit. Folders inside the domain for organising objects. GPOs attach to OUs.

Key rule: **computer objects and user objects in separate OUs** — machine policies target computers, account policies target users. Mixing them causes policy misfires.

```
lab.local
├── Domain Controllers
├── Servers
├── Workstations
└── Users
    ├── IT Admins
    └── Standard Users
```

---

## AD as an Identity Provider

The cleaner framing: AD is an **Identity Provider (IdP)** — it vouches for who you are. Services (SIEMs, file shares, VPNs) are relying parties — they trust the IdP's answer instead of managing their own auth.

This is the same concept as modern cloud auth (OAuth, SAML, OIDC). AD over LDAP/Kerberos is the older enterprise version of the same model.

---

## Windows Security Event IDs

| Event ID | What it means |
|---|---|
| **4625** | Failed logon attempt |
| **4728** | Member added to a security-enabled global group (e.g. Domain Admins) |
| **4740** | User account locked out |
| **4624** | Successful logon |
| **4688** | New process created (process creation audit) |

These fire on the Domain Controller. Wazuh reads them via the Windows Event Channel decoder.

**Rule 60159** fires at level 12 for Domain Admins group changes — MITRE T1484, Defense Evasion + Privilege Escalation.

---

## NTDS and SYSVOL

**NTDS:** The AD database file (`ntds.dit`) in `C:\Windows\NTDS\`. Contains every domain object — users, computers, groups, policies. Written to constantly via transaction logs.

**SYSVOL:** Shared folder in `C:\Windows\SYSVOL\` replicated to every DC. Stores Group Policy files and logon scripts. Every domain-joined machine reads GPO settings from SYSVOL.

---

## VLANs vs flat networks

**Flat network** — all devices on one subnet, reachable by each other freely.

**VLAN** — logically separated segments on the same physical hardware using 802.1Q tagging on a managed switch. Devices in different VLANs can't reach each other without going through a controlled chokepoint. Sharing upstream internet doesn't make something a VLAN — explicit configuration and tagging are required.
