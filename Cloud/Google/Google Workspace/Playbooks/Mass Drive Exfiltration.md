# Playbook — Mass Drive Exfiltration

A user — a **departing insider** or a **compromised account** — bulk-downloads Drive files, or shares the crown-jewels folder externally / "anyone with the link." This playbook establishes what left, by whom, when, and whether it was proven-exfiltrated, then contains and remediates.

> **Tier 2 (cross-service).** Spans Login audit + Drive audit + Drive API. Read **Workspace → Drive & Docs Audit** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Alert Center / DLP** | Bulk external sharing / sensitive-data rule |
| **Drive audit** | Hundreds of `download` events by one user |
| **HR** | A resignation + a spike in file activity |
| **Login audit** | Suspicious login then Drive activity |

## Hypothesis

One actor pulled or exposed a large volume of files. Establish whether it's an insider or a takeover, quantify the files and sensitivity, prove whether data left the org, and contain.

## Step-by-Step Investigation

**1. Classify the actor.** Insider (departing, from a known device) vs compromised (cross the **Login audit** for a suspicious sign-in).

**2. Pull the activity.** Drive audit for the user: `download`, `change_document_visibility`, `change_user_access`, `copy`, `print` in the window.

**3. Quantify.** Count + list of files; flag by sensitivity/DLP label; note shared drives touched.

**4. Map exposure.** External share targets + public/link visibility changes.

```sql
-- mass download by one user (BigQuery Drive logs)
SELECT actor.email, COUNT(*) c FROM `contoso.workspace_logs.drive`
WHERE event.name='download' AND time_usec > UNIX_MICROS(TIMESTAMP '2026-07-01')
GROUP BY actor.email HAVING c > 500 ORDER BY c DESC;
```

## Did Data Actually Leave?

| If you see… | You can conclude |
|-------------|------------------|
| `download` on the files | Content pulled to a device 🎯 |
| `change_document_visibility` → public/link | Reachable by anyone with the URL |
| `change_user_access` → external + later external access | Confirmed data left the org 🎯 |
| `copy`/`print` at volume | Exfil via alternate path |
| Only `view` | Read, no proven copy — scope by sensitivity |

## Decision Points

| Question | If yes → |
|----------|----------|
| Sensitive/regulated data? | Treat as data breach; legal/comms |
| Insider (departing)? | HR/legal loop; preserve for potential litigation |
| Compromised account? | Run **Account Takeover**; cut the session |
| External sharing/public links? | Revoke immediately; identify recipients |

## Contain

- **Insider:** suspend the account; revoke device access.
- **Compromised:** reset password + sign out everywhere; revoke OAuth grants.
- **Revoke exposure:** remove public/link visibility + external grants (Drive API / SIT bulk action); remove external shared-drive members.

## Eradicate

- Remove all attacker/insider-created shares and public links.
- Rotate any **secrets/keys** that were in exposed documents (assume leaked).
- Confirm no residual delegation/OAuth access remains.

## Recover

- Restrict external sharing (allowlist / warn); disable "anyone with the link" for sensitive OUs.
- DLP rules to block external share/download of sensitive content.
- Alert on mass downloads + public-visibility changes.
- Preserve: Drive activity window, file list, external recipients, and content on **Vault hold**.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Hundreds of downloads by one user in a short window | Bulk exfil |
| Public/link visibility on sensitive docs | Data exposure |
| External `change_user_access` grants | Data shared out |
| Mass `copy`/`print` | Exfil evading download alerts |
| Activity around a resignation or suspicious login | Insider / takeover exfil |

## References

- Related notes: **Drive & Docs Audit**, **Login & Auth Audit**, **Account Takeover**, **Alert Center & SIT**
- Drive audit log — https://support.google.com/a/answer/4579696
- Restrict external sharing — https://support.google.com/a/answer/60781
- MITRE ATT&CK: T1530 Data from Cloud Storage / T1567 Exfil Over Web Service — https://attack.mitre.org/techniques/T1530/
