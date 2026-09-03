# Playbook — Password Spray

The patient brute force. Instead of many passwords against one account (which locks out), the attacker tries **one common password against many accounts**, staying under lockout thresholds. This playbook detects the spray, finds which accounts fell, and closes the door.

> **Tier 2 (cross-service).** Sign-in logs + Conditional Access. Read **Entra → Sign-in Logs** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Did Any Account Fall?](#did-any-account-fall)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Identity Protection** | Password-spray risk detection |
| **Sign-in logs** | Many `50126` (invalid credential) failures across many users from few IPs |
| **Defender / Sentinel** | Spray analytics rule |
| **Legacy-auth endpoints** | Spikes on IMAP/SMTP/Autodiscover (favorite spray targets — MFA-free) |

## Hypothesis

An attacker is spraying common passwords across the tenant, favoring **legacy auth** (no MFA). Determine the source(s), whether any account succeeded, and whether success led to a foothold.

## Step-by-Step Investigation

**1. Confirm the spray shape** — one/few IPs, many distinct users, error `50126`:

```kql
SigninLogs
| where ResultType == 50126
| summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, 1h)
| where Users > 10
| order by Users desc
```

**2. Check legacy auth** (the MFA-free path they aim for):

```kql
SigninLogs
| where ClientAppUsed in ("IMAP4","POP3","SMTP","Other clients","Authenticated SMTP")
| summarize by IPAddress, ClientAppUsed, ResultType
```

**3. Find any success from a spray IP** — the accounts that fell:

```kql
SigninLogs
| where IPAddress in (<spray-ips>) and ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, Location
```

**4. For each success, was MFA satisfied?** A password-only success (single-factor / legacy) = compromised account.

## Did Any Account Fall?

| Outcome | Meaning |
|---------|---------|
| Success + MFA challenged & passed elsewhere | Password known but MFA held (still rotate) |
| Success + **single-factor / legacy auth** | 🔴 **Compromised** — the account is in |
| All `50126` / `50053` (lockout) | Spray blocked — rotate any weak passwords anyway |

## Decision Points

| Question | If yes → |
|----------|----------|
| Any single-factor success? | Treat account as compromised; run the full flow |
| Legacy auth in play? | Block legacy auth tenant-wide now |
| Privileged accounts sprayed? | Prioritize; check role/app changes |
| Spray continuing? | Block source IPs/ASNs; enable smart lockout |

## Contain

- Block the spray **source IPs/ASNs** (named location / CA).
- **Block legacy authentication** tenant-wide.
- For any fallen account: revoke tokens + disable + reset.

## Eradicate

- Reset passwords for compromised accounts (and any using the sprayed common password).
- Remove any persistence a successful login established (rules, consent, roles).

## Recover

- Enforce **MFA for all** + **block legacy auth** + **ban common passwords** (password protection).
- Enable **smart lockout** and spray detection alerts.
- Preserve: the spray sign-ins, source IPs, and any successful-login follow-on activity.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Many `50126` across many users from one IP | Password spray |
| Legacy-auth (IMAP/SMTP) success | MFA-free compromise |
| Single-factor success from a spray IP | Account fell |
| Spray targeting admin UPNs | Privileged-account hunt |

## References

- Related notes: **Sign-in Logs**, **Conditional Access & MFA**, **Password Protection**
- Password spray investigation — https://learn.microsoft.com/security/operations/incident-response-playbook-password-spray
- Block legacy auth — https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication
- MITRE ATT&CK: T1110.003 Password Spraying — https://attack.mitre.org/techniques/T1110/003/
