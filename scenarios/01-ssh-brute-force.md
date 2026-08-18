# Scenario 01 — SSH Brute Force

**Status:** Completed  
**MITRE:** T1110 — Brute Force (Credential Access)  
**Wazuh Rule:** 2502, Level 10  
**Event source:** Linux SSH auth log (`/var/log/auth.log`)

---

## What Was Simulated

A credential stuffing / brute force attack against an SSH service. A bash loop ran repeated failed password attempts against the Wazuh VM from the Mac, using an invalid username to generate clean failure events.

**Attack command (run on Mac):**
```bash
for i in {1..10}; do
  ssh -o "StrictHostKeyChecking=no" -o "BatchMode=yes" wronguser@10.0.0.105 2>/dev/null
done
```

---

## What Fired

```
Rule:     2502
Level:    10
Decoder:  sshd
firedtimes: 6

srcip:    10.0.0.102   (Mac)
dstip:    10.0.0.105   (Wazuh VM)

full_log: Failed password for invalid user wronguser from 10.0.0.102 port 54321 ssh2

MITRE:    T1110 — Brute Force
Tactics:  Credential Access
```

**Why level 10:** Rule 2502 uses `frequency` + `timeframe` — it fires when the same source IP triggers repeated failures within a window. A single failed SSH attempt would be level 5. Six within 60 seconds crosses the threshold.

---

## PICERL

**Prepare**  
Rule 2502 active by default. Wazuh watching `/var/log/auth.log` via the Linux log pipeline. No additional setup needed.

**Identify**  
Rule 2502 fires, level 10. `firedtimes: 6` — six consecutive failures from the same source. `srcip: 10.0.0.102`, invalid username — automated tooling or credential stuffing, not a typo. Key question: did any login succeed after the failures?

**Contain**  
Block source IP via firewall rule or Wazuh Active Response (automated). Check `auth.log` for any `Accepted` entry from the same IP within the window.

**Eradicate**  
Confirm no successful session was established. Review which accounts were targeted — a mix of valid and invalid usernames suggests credential list. If valid accounts were targeted, force password rotation.

**Recover**  
Verify block is in place. Confirm SSH still accepts legitimate keys. Monitor for attempts from new source IPs (attacker pivoting to another exit node).

**Lessons Learned**  
Key-only authentication eliminates password brute force. Rate limiting (`MaxAuthTries` in `sshd_config`) reduces effectiveness of automated tools. Reduce SSH exposure — if not needed externally, firewall port 22 to LAN only.

---

## Alert Triage Notes

This is a textbook Tier 1 triage scenario. The pattern is:
1. Volume — is this 6 failures or 600? Scale changes the response.
2. Timing — consistent interval = automated tool. Irregular = manual.
3. Target — single account = credential stuffing. Many accounts = spray.
4. Outcome — did anything succeed? One `Accepted` after 50 failures is an incident, not noise.

In a production queue this fires constantly from external IPs. The response is usually: confirm no success, document, block, move on. Escalate only on success or targeting of privileged accounts.
