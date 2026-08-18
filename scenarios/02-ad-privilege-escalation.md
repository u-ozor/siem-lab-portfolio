# Scenario 02 — AD Privilege Escalation

**Status:** Completed  
**MITRE:** T1484 — Domain Policy Modification (Defense Evasion + Privilege Escalation)  
**Wazuh Rule:** 60159, Level 12  
**Event source:** Windows Security Event Log, Event ID 4728  
**Agent:** DC01 (002), Windows Event Channel decoder

---

## What Was Simulated

A standard domain user (Bob) was added to the Domain Admins group via PowerShell. This is a common privilege escalation path in real-world attacks — once an attacker compromises a low-privilege account, adding it to Domain Admins grants full domain control.

**Attack command (run on DC01):**
```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members bob
```

---

## What Fired

```
Rule:         60159
Level:        12
EventID:      4728

memberName:   CN=Bob,OU=Standard Users,DC=lab,DC=local
targetUserName: Domain Admins
computer:     DC01.lab.local

MITRE:        T1484 — Domain Policy Modification
Tactics:      Defense Evasion, Privilege Escalation
Compliance:   PCI DSS, HIPAA, GDPR, NIST 800-53 tags visible in dashboard
```

**Why level 12:** Domain Admins group change is one of the highest priority events in the Windows ruleset. Built-in rule 60159 targets specifically Event ID 4728 on privileged groups. Level 12 = second-highest tier below critical (15).

---

## PICERL

**Prepare**  
Wazuh agent deployed on DC01 with Windows Security Event log pipeline active (`<localfile>` block for `Security` channel in `ossec.conf`). Rule 60159 is built-in — no custom configuration needed. Account lockout policy configured via GPO (5 attempts).

**Identify**  
Alert fires: Rule 60159, level 12. Event ID 4728 confirms a privileged group membership change. `memberName: CN=Bob,OU=Standard Users,DC=lab,DC=local` — full distinguished name tells you exactly which account, which OU, which domain. `targetUserName: Domain Admins` — highest-privilege built-in group. Timestamp, source host (DC01), and both account names in the alert — everything needed to triage without leaving the dashboard.

Critical question: which session ran the `Add-ADGroupMember` command? Cross-reference Event ID 4624 (logon) records around the same timestamp.

**Contain**  
Disable Bob's account immediately via ADUC (Active Directory Users and Computers) — stops any further use of the elevated access while investigation continues. Do not remove from Domain Admins yet — preserve evidence of the group change for the investigation timeline.

**Eradicate**  
Remove Bob from Domain Admins. Review all Domain Admins members for any other unexpected additions (could be a broader campaign). Check Event ID 4624 logs for any successful logins by Bob after the group change — determine if the elevated access was actually used. Identify the session that ran the command: correlation of Event ID 4688 (process creation) or PowerShell event logs with the same timestamp.

**Recover**  
Re-enable Bob's account after confirming no persistence was left (no new admin accounts created, no scheduled tasks, no GPO changes). Verify Domain Admins is back to expected membership. Confirm Wazuh is still receiving events from DC01.

**Lessons Learned**  
Tighten who can run privilege-escalating PowerShell on the DC — PowerShell Constrained Language Mode or Just Enough Administration (JEA). Alert on any Domain Admins change not tied to a change management ticket. Evaluate tiered admin model: separate standard user accounts from privileged admin accounts (T0/T1/T2 tiers).

---

## Alert Triage Notes

This is the highest-priority scenario in the lab. Level 12 means it would page an on-call analyst in most environments. The triage question is simple: was this authorised? If no change management ticket exists, treat it as a compromise until proven otherwise.

Key data points the Wazuh alert provides immediately:
- **Who:** `memberName` — full distinguished name, no ambiguity
- **What:** `targetUserName: Domain Admins`
- **Where:** `computer: DC01.lab.local`
- **When:** alert timestamp

What the alert can't tell you directly: **why** and **by whom the command was issued** (requires correlating PowerShell logs or Event ID 4688 process creation records in the same time window).
