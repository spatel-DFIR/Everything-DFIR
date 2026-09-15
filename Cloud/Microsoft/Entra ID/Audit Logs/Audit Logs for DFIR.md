# Entra Audit Logs for DFIR

Once you know *who* signed in (sign-in logs), audit logs tell you *what they changed*. Every persistence and privesc step in a Microsoft breach — a role grant, an app consent, a secret added to a service principal — is a directory change recorded here.

New to the service? Read **What is Entra Audit Logs** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading an Audit Event](#reading-an-audit-event)
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
| **Entra portal** → Audit logs | All directory changes | ~30 days | Fast first look |
| **Graph** `directoryAudits` | Same | ~30 days | Scripted pulls |
| **Log Analytics / Sentinel** (`AuditLogs`) | Exported copy | Your retention | Hunting + long look-back |
| **Unified Audit Log** | Many Entra events too | 180 d–1 yr | 🔴 Longest native look-back |

**In SecOps (optional):** lands as Entra audit; actor → `principal.user.userid`, action → `metadata.product_event_type`, target → `target.resource.name`.

## Collect It

**Pull the changes around the incident window.**

```powershell
# All directory changes initiated by a suspect actor
Get-MgAuditLogDirectoryAudit -Filter "initiatedBy/user/userPrincipalName eq 'alice@contoso.com'" -Top 200

# All role grants in the window
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Add member to role'"

# All app consents / credential adds
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Consent to application' or activityDisplayName eq 'Add service principal credentials'"
```

> **Console:** Entra ID → **Audit logs** → filter by *Activity*, *Initiated by (actor)*, *Target*, and date range → **Download**.

> 🔴 CSV export can render local time while JSON stays UTC — see the export-timezone callout in **Microsoft → 00 Overview & Terminology → Where Evidence Lives** before mixing exports into one timeline.

**Go past 30 days — via the UAL:**

```powershell
Search-UnifiedAuditLog -StartDate 2026-05-01 -EndDate 2026-07-11 \
  -RecordType AzureActiveDirectory -Operations "Add member to role.","Consent to application."
```

## Investigate on the Platform

The flow — five steps:

| Step | Do this |
|------|---------|
| 1. Scope the actor | Pull every change by the compromised identity/app in the window |
| 2. Classify each change | Bucket into persistence / privesc / evasion / federation (table below) |
| 3. Read old→new values | Open `modifiedProperties` — see *exactly* what a policy/role change did |
| 4. Find the "grant" events | Role grants, consents, credential adds — the attacker's foothold-makers |
| 5. Tie to the sign-in | Cross-reference the actor's sign-in log for source IP / token / MFA |

## Reading an Audit Event

| Field | Answers | Notes |
|-------|---------|-------|
| `initiatedBy` | **Who** | user (UPN+OID) or app (SP) — an app initiator can mean automation *or* a rogue app |
| `activityDisplayName` | **What** | The action (see phase table) |
| `targetResources[].displayName` | **On what** | The user/app/role changed |
| `targetResources[].modifiedProperties` | **Exactly what changed** | 🔴 old→new — read this |
| `result` | **Did it work** | `success` / `failure` |
| `additionalDetails` | Context | Sometimes app IDs, correlation IDs |

## What to Look For, by Phase

| Phase | Telltale audit actions |
|-------|------------------------|
| **Privilege escalation** | `Add member to role` (Global Admin / Privileged Role Admin); `Add eligible member to role` |
| **Persistence** | `Add service principal credentials`; `Update application – Certificates and secrets`; `Add owner to application`; `CreateUser` for a backdoor account |
| **App abuse** | `Consent to application`; `Add app role assignment to service principal` (esp. `Mail.Read`/`.All`) |
| **Defense evasion** | `Update/Delete conditional access policy`; disabling MFA methods; `Disable Strong Authentication` |
| **Federation backdoor** | `Set domain authentication`; `Add unverified domain`; new federation trust (🔴 Golden SAML) |
| **Device persistence** | `Register device`; `Add registered owner` |

🔴 A **fresh account** created and then **granted a privileged role** minutes later is a classic backdoor-admin pattern.

## Hunt at Scale

KQL over `AuditLogs`:

**Role grants to privileged roles:**

```kql
AuditLogs
| where OperationName == "Add member to role"
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has_any ("Global Administrator","Privileged Role Administrator","Application Administrator")
| project TimeGenerated, Actor=InitiatedBy, Role, TargetResources
```

**Credentials added to service principals (persistence):**

```kql
AuditLogs
| where OperationName in ("Add service principal credentials","Update application – Certificates and secrets")
| project TimeGenerated, InitiatedBy, TargetResources, Result
```

**App consents to high-risk permissions:**

```kql
AuditLogs
| where OperationName in ("Consent to application","Add app role assignment to service principal")
| where tostring(TargetResources) has_any ("Mail.Read","Mail.ReadWrite","Files.ReadWrite.All","Directory.ReadWrite.All")
| project TimeGenerated, InitiatedBy, TargetResources
```

**Conditional Access weakening:**

```kql
AuditLogs
| where OperationName has "conditional access policy" and OperationName has_any ("Update","Delete")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources
```

> **At the very end — SecOps UDM (optional):** land role-grant / consent events to answer "did this actor change anything elsewhere?" Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Undo a rogue role grant | Remove the member from the role (portal / `Remove-MgDirectoryRoleMemberByRef`) |
| Kill app persistence | Delete attacker-added secrets/certs; disable the enterprise app |
| Revoke illicit consent | Remove the app's permission grants / delete the service principal |
| Restore MFA/CA | Re-enable the disabled Conditional Access policy; restore MFA methods |
| Remove a federation backdoor | Revert the domain authentication / remove the rogue trust; **rotate the token-signing key** |

> 🔴 Removing the role is not enough if the attacker already **added a credential to an app** or **created a backdoor user** — hunt those too. See **Entra → Playbooks → Privileged Role Escalation**.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **PIM** for all privileged roles (JIT, approval, time-boxed) | No standing Global Admins to grant/abuse |
| **Restrict user consent**; require admin consent for risky permissions | Stops illicit consent grants |
| **App governance / workload ID protection** | Flags SP credential adds + risky app behavior |
| **Export `AuditLogs` → Sentinel** (2+ yrs) | Beats 30-day retention |
| **Alert** on Global Admin grants, SP credential adds, CA policy changes | Catch persistence/evasion in real time |
| **Named locations + CA** protecting admin actions | Limits where changes can be made from |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `Add member to role` → Global Administrator | Takeover / privilege escalation |
| `Add service principal credentials` on a trusted app | Persistence — attacker's key in a trusted app |
| `Consent to application` / app-role grant of `*.Read`/`.All` | Illicit consent — tenant-wide access |
| `Update/Delete conditional access policy` | Defense evasion — MFA/CA weakened |
| `Set domain authentication` / new federation trust | Golden SAML / federation backdoor |
| New user created then role-granted within minutes | Backdoor-admin pattern |
| Change initiated by an **app (SP)** you don't recognize | Rogue app acting on the directory |
| `Add owner to application` for an unexpected principal | Persistence via app ownership |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the log is + key actions | **Audit Logs → What is Entra Audit Logs** |
| Who the actor is | **Microsoft → 01 Entra ID & Identities** |
| The sign-in behind the actor | **Entra → Sign-in Logs** |
| Apps / consent / credentials | **Entra → Applications & Service Principals** |
| Roles + PIM | **Entra → Roles & PIM** |
| A full privilege-escalation chain | **Entra → Playbooks → Privileged Role Escalation** |
| A rogue-app chain | **Entra → Playbooks → Illicit Consent Grant** |

## Resources

- Audit logs — https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs
- Audited activities reference — https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities
- App governance — https://learn.microsoft.com/defender-cloud-apps/app-governance-manage-app-governance
- MITRE ATT&CK: Account Manipulation (T1098) — https://attack.mitre.org/techniques/T1098/
