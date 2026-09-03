# Entra Sign-in Logs for DFIR

Sign-in logs are the **first place you look** in almost every Microsoft investigation. They tell you which identity authenticated, from where, into what, and whether MFA/Conditional Access held.

New to the service? Read **What is Entra Sign-in Logs** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading a Sign-in Event](#reading-a-sign-in-event)
- [What to Look For, by Phase](#what-to-look-for-by-phase)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Entra portal** (4 tabs) | Interactive / non-interactive / SP / managed-identity sign-ins | ~30 days | Fast first look |
| **Microsoft Graph** | Same, via `auditLogs/signIns` | ~30 days | Scripted pulls |
| **Log Analytics / Sentinel** | Exported copy, KQL-queryable | Your retention | Long look-back + hunting |

**In SecOps (optional, end of note):** ingests as Azure AD / Entra sign-in logs. Rough UDM landing: principal → `principal.user.userid`, app → `target.application`, source IP → `principal.ip`, result → `security_result`. Confirm against a sample — parsers vary.

## Collect It

**Step 1 — Confirm you have the window.** Retention is short; check export before anything ages out.

```bash
# Is there a diagnostic setting shipping sign-ins to Log Analytics/Sentinel?
az monitor diagnostic-settings list \
  --resource "/tenants/<tenant-id>/providers/microsoft.aadiam" -o table
```

> **Console:** Entra ID → **Diagnostic settings** → is `SignInLogs` (and non-interactive/SP) being exported?

**Step 2 — Pull the identity's sign-ins (all four logs).**

```powershell
# Interactive + non-interactive for a user
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'alice@contoso.com'" -Top 200

# Service-principal sign-ins for an app
Get-MgAuditLogSignIn -Filter "appId eq '<app-guid>' and signInEventTypes/any(t: t eq 'servicePrincipal')"
```

> **Console:** Entra ID → **Sign-in logs** → pick the tab (User / Non-interactive / **Service principal** / Managed identity) → filter by user/app/IP → **Download** (CSV/JSON).

> 🔴 CSV export can render local time while JSON stays UTC — see the export-timezone callout in **Microsoft → 00 Overview & Terminology → Where Evidence Lives** before mixing exports into one timeline.

**Step 3 — Go past 30 days (KQL in Log Analytics/Sentinel).**

```kql
SigninLogs
| where UserPrincipalName == "alice@contoso.com"
| where TimeGenerated > ago(90d)
| project TimeGenerated, AppDisplayName, IPAddress, Location, ResultType, ConditionalAccessStatus
| order by TimeGenerated asc
```

## Investigate on the Platform

The flow — six steps:

| Step | Do this |
|------|---------|
| 1. Check all four logs | Interactive **and** non-interactive **and** SP **and** managed-identity — attackers hide in the last three |
| 2. Build the timeline | Every sign-in for the identity, sorted by time; note IP/geo/ASN/device |
| 3. Spot the anomaly | New country/ASN, impossible travel, new device, legacy client, MFA "by claim" |
| 4. Read the MFA/CA detail | Was MFA actually performed, or satisfied by an existing token? Did CA apply? |
| 5. Follow the token | A stolen token shows up in **non-interactive** sign-ins right after the phish |
| 6. Split human vs app vs resource | Interactive+MFA = person; SP+secret = app; managed identity = a resource |

## Reading a Sign-in Event

Fields that carry most investigations:

| Field | Answers | Notes |
|-------|---------|-------|
| `UserPrincipalName` / `userType` | **Who** | `#EXT#` = guest |
| `AppDisplayName` + `ResourceDisplayName` | **Into what** | Graph/ARM from odd tooling is a flag |
| `IPAddress` + `Location` | **From where** | New geo/ASN, hosting-provider IP |
| `ClientAppUsed` | **With what** | 🔴 IMAP/POP/SMTP/"Other clients" = legacy = MFA bypass |
| `AuthenticationDetails` | **MFA how** | 🔴 "satisfied by claim in token" from a new device = replay |
| `ConditionalAccessStatus` | **Was CA applied** | 🔴 `notApplied`/`failure` on sensitive access |
| `ResultType` (error code) | **Did it work** | `0` success · `50126` spray · `53003` CA block |
| `RiskLevelDuringSignIn` | **IP-verdict** | 🔴 `high`/`medium` |

## What to Look For, by Phase

| Phase | Telltale sign-in signals |
|-------|--------------------------|
| **Initial access** | Success from a new country/ASN; **legacy auth**; sign-in right after an AiTM phishing email |
| **MFA bypass** | MFA "satisfied by claim in token" from a new device; non-interactive sign-in with no interactive parent |
| **App abuse** | New/unusual **service-principal** sign-ins; app calling **Graph** it never called before |
| **Persistence** | Managed-identity or SP sign-ins from new IPs; sign-ins after a password reset (token not revoked) |
| **Brute force / spray** | Many `50126` failures across many users from one IP (spray), or many failures on one user (brute force) |

🔴 A sudden **drop of failures then a success** from the same IP is a spray or brute force finding its mark.

## Hunt at Scale

Work in KQL (Log Analytics/Sentinel) — the richest way to hunt sign-ins.

**Impossible travel / new-country success:**

```kql
SigninLogs
| where ResultType == 0
| summarize Countries = make_set(Location) by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
```

**Legacy-auth (MFA-bypassing) sign-ins:**

```kql
SigninLogs
| where ClientAppUsed in ("IMAP4","POP3","SMTP","Other clients","Authenticated SMTP","Exchange ActiveSync")
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, AppDisplayName
```

**Service-principal sign-ins from new IPs (rogue app / stolen secret):**

```kql
AADServicePrincipalSignInLogs
| summarize IPs = make_set(IPAddress), first=min(TimeGenerated) by ServicePrincipalName, AppId
| where array_length(IPs) > 1
```

**Password-spray shape (many users, one IP, error 50126):**

```kql
SigninLogs
| where ResultType == 50126
| summarize Users = dcount(UserPrincipalName) by IPAddress, bin(TimeGenerated, 1h)
| where Users > 10
```

> **At the very end — SecOps UDM (optional, cross-source retro-hunt):** land the same events to answer "did this IP/app show up elsewhere?" Keep it light; the deep read stays in KQL.

## Respond

Act on the token first — passwords alone don't cut a live session.

| Goal | Action |
|------|--------|
| Kill silent re-auth (the step people forget) | `Revoke-MgUserSignInSession -UserId <upn>` — invalidates refresh tokens |
| Disable the account | `Update-MgUser -UserId <upn> -AccountEnabled:$false` |
| Force fresh MFA | Require MFA re-registration if MFA methods were tampered |
| Contain a rogue app | Disable the **enterprise app**; delete attacker-added secrets/certs |
| Block the source | Add a Conditional Access / named-location block on the IP/ASN |

> 🔴 **Order matters:** revoke tokens **and** disable **before** resetting the password — otherwise a valid refresh token just mints a new session after the reset.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Block legacy authentication** (CA policy) | Removes the biggest MFA-bypass path |
| **Require MFA** for all users + admins (phishing-resistant where possible) | Stops password-only compromise |
| **Conditional Access**: block risky sign-ins, require compliant device for admins | Gates stolen tokens/devices |
| **Export sign-in logs → Sentinel/Log Analytics** (2+ yrs) | Beats the 30-day retention trap |
| **Continuous Access Evaluation (CAE)** | Near-real-time token revocation on risk |
| **Monitor SP + non-interactive logs**, not just interactive | Catches app/token abuse |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Success via IMAP/POP/SMTP/"Other clients" | Legacy auth — MFA bypassed |
| MFA "satisfied by claim in token" from a new device | Token replay (AiTM) |
| Non-interactive sign-in with no interactive parent | Replayed/stolen token |
| New service-principal sign-in IP + new Graph scopes | Rogue app / stolen secret |
| Impossible travel / new-country success | Compromised credentials |
| Many `50126` across many users from one IP | Password spray |
| Sign-in success right after a password reset (no token revoke) | Containment failure — session survived |
| Managed-identity sign-in from an unexpected IP | IMDS/SSRF theft |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the log is + fields | **Sign-in Logs → What is Entra Sign-in Logs** |
| Identity types + token containment | **Microsoft → 01 Entra ID & Identities** |
| The policy that should have blocked it | **Entra → Conditional Access & MFA** |
| The app/consent behind an SP sign-in | **Entra → Applications & Service Principals** |
| A phished-token intrusion | **Entra → Playbooks → Token Theft and AiTM** |
| A password-spray campaign | **Entra → Playbooks → Password Spray** |
| Same identity across clouds | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- Sign-in logs — https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins
- Sign-in error codes — https://learn.microsoft.com/entra/identity-platform/reference-error-codes
- Block legacy authentication — https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication
- Revoke user access — https://learn.microsoft.com/entra/identity/users/users-revoke-access
- Continuous Access Evaluation — https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation
- MITRE ATT&CK: Valid Accounts: Cloud Accounts (T1078.004) — https://attack.mitre.org/techniques/T1078/004/
