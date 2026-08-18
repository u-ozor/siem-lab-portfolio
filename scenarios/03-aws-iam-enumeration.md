# Scenario 03 — AWS IAM Enumeration

**Status:** Completed  
**MITRE:** T1087 — Account Discovery (Discovery)  
**Wazuh Rule:** 100002, Level 10 (custom, chained off built-in CloudTrail rule)  
**Event source:** AWS CloudTrail → S3 → Wazuh aws-s3 wodle  
**Pipeline:** External cloud pull, not agent-based

---

## What Was Simulated

IAM enumeration commands run via the AWS CLI — a standard discovery phase technique. An attacker who has obtained an IAM access key will typically run these to understand the account's identity, what users and roles exist, and what permissions they have before moving to exploitation.

**Attack commands (run on Mac):**
```bash
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local
aws sts get-caller-identity
```

---

## The Detection Pipeline

```
AWS CLI → AWS API → CloudTrail records event → writes to S3 bucket
                                                        ↓
                              aws-s3 wodle polls S3 every 5 minutes
                                                        ↓
                              Wazuh manager parses CloudTrail JSON
                                                        ↓
                              Built-in rule 87701 fires (level 3, any CloudTrail event)
                                                        ↓
                              Custom rule 100002 chains off 87701 (if_sid)
                              Matches: ListUsers, ListRoles, GetCallerIdentity, etc.
                                                        ↓
                              Rule 100002 fires: Level 10, MITRE T1087
```

**Latency:** Up to 5 minutes from CLI command to dashboard alert (CloudTrail aggregates logs and the wodle polls on a schedule, not real-time).

---

## Custom Rule 100002

File: `/var/ossec/etc/rules/local_rules.xml`

```xml
<rule id="100002" level="10">
  <if_sid>87701</if_sid>
  <field name="aws.eventName">ListUsers|ListRoles|ListPolicies|GetCallerIdentity|ListAttachedUserPolicies|ListGroupsForUser</field>
  <description>AWS IAM enumeration - account discovery activity detected</description>
  <mitre>
    <id>T1087</id>
  </mitre>
</rule>
```

**Why `if_sid` (not `if_matched_sid`):** Chain — fires whenever rule 87701 fires AND the field condition matches. No time window needed. Built-in rule 87701 fires at level 3 for any CloudTrail event — too low to surface in a real queue. This rule elevates specific enumeration patterns to level 10, making them page-worthy.

**Why level 10:** In most environments, level 10+ gets analyst attention. Level 3 (the built-in baseline) would generate noise for every console login and routine API call. Targeting specific `eventName` values that represent enumeration behaviour reduces false positives.

**Rule engine field naming:** In the rule XML, `aws.eventName` is correct. In the OpenSearch dashboard, the same field appears as `data.aws.eventName` — the `data.` prefix is added by the indexer. Never copy field names from the dashboard directly into rule XML.

---

## What Fired

```
Rule:              100002
Level:             10
aws.eventName:     ListUsers
aws.userAgent:     aws-cli/2.x
aws.sourceIPAddress: <external IP>

MITRE:             T1087 — Account Discovery
Tactics:           Discovery
```

---

## IAM Scoping (Post-Simulation)

After confirming the pipeline works end to end, the `siem-lab` IAM user was scoped to least privilege:
- Removed: IAM read access
- Retained: `s3:ListBucket` + `s3:GetObject` on the CloudTrail S3 bucket only

**Effect:** `aws iam list-users` now returns `AccessDenied` for the siem-lab credentials. The detection rule still fires regardless — it fires on the CloudTrail event, not on whether the call succeeded. In a real attack, the attacker uses compromised credentials with broader access, not the monitoring service account.

**Why this is the correct posture:** The service account should have only the access it needs (pulling logs). Locking it down after confirming the pipeline is security hygiene, not a limitation.

---

## PICERL

**Prepare**  
CloudTrail trail active, logging to S3. Wazuh aws-s3 wodle configured with IAM access key and bucket name. Custom rule 100002 deployed to `local_rules.xml`. Wazuh manager restarted to load rule.

**Identify**  
Rule 100002 fires at level 10. `aws.eventName: ListUsers` (or ListRoles, etc.) — classic discovery pattern. `aws.sourceIPAddress` — external IP. Key questions: is this IP a known admin location? Is there a sequence of enumeration calls in the same timeframe? Is any escalation following (e.g. `CreateAccessKey`, `AttachUserPolicy`)?

**Contain**  
If the access key is compromised: deactivate it immediately in IAM console. If this is a valid admin, no action on the key — investigate and document.

**Eradicate**  
If compromised key: rotate it. Review CloudTrail for all API activity from that key in the preceding period — look for changes (CreateUser, AttachPolicy) not just reads. Check if any new IAM resources were created.

**Recover**  
Issue new access key if needed. Review and verify IAM policy attachments are unchanged. Ensure no new users, roles, or policies were created.

**Lessons Learned**  
Discovery activity rarely happens alone — it precedes exploitation. Use CloudTrail query to look for escalating patterns: enumeration → access key creation → policy attachment. Consider alerting on `GetCallerIdentity` from unusual IP ranges — it's the first call most automated tools make.

---

## Alert Triage Notes

Discovery-phase alerts are often lower urgency than exploitation alerts, but they're an early warning. The triage question: is this an attacker mapping your environment, or a routine admin task?

Signals that elevate concern:
- IP not in known admin ranges
- Time outside business hours
- Multiple enumeration calls in a short window (ListUsers → ListRoles → ListPolicies = likely automated)
- Followed by write-API calls in the same session (more serious)
- `aws.userAgent` showing unfamiliar tooling or automated frameworks
