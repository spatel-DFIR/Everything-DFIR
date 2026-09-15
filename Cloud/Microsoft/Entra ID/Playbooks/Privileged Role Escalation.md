# Playbook — Privileged Role Escalation

The attacker turns a foothold into ownership by **acquiring a privileged Entra role** — usually **Global Administrator** — then (often) crossing into Azure via `elevateAccess`. This playbook reconstructs the escalation chain, contains it, and sweeps for the persistence that always comes with it.

> **Tier 2 (cross-service).** Entra roles + audit + sign-in + Azure Activity. Read **Entra → Roles & PIM** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [The Escalation Chain to Reconstruct](#the-escalation-chain-to-reconstruct)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Audit log** | `Add member to role` → Global Administrator / Privileged Role Admin |
| **Alert** | New Global Admin / PIM permanent assignment |
| **Activity Log** | 🔴 `elevateAccess` (GA gained Azure-wide access) |
| **Post-incident** | After a phish/token theft, checking what privilege they gained |

## Hypothesis

An attacker escalated an identity (a compromised admin, a fresh backdoor account, or an app) to a privileged directory role, and may have bridged to Azure. Reconstruct who granted what to whom, and remove both the role and the co-planted persistence.

## Step-by-Step Investigation

**1. Find the role grant.**

```kql
AuditLogs
| where OperationName in ("Add member to role","Add eligible member to role")
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has_any ("Global Administrator","Privileged Role Administrator","Privileged Authentication Administrator")
| project TimeGenerated, Actor=InitiatedBy, Role, Target=TargetResources
```

**2. Trace *how* the granting identity got its power.** Was the actor a recently-compromised admin? An app with `RoleManagement.ReadWrite`? Follow the chain back (table below).

**3. Check for the Azure bridge.**

```kql
AzureActivity
| where OperationNameValue has "elevateAccess"
| project TimeGenerated, Caller, CallerIpAddress
```

**4. Enumerate what the role did.** After the grant, what actions followed — more grants, app credentials, CA changes, backdoor accounts?

## The Escalation Chain to Reconstruct

```
compromised user / token  →  (maybe) app consent w/ RoleManagement  →  Add member to role: Global Admin
                          →  elevateAccess  →  Owner over all Azure subscriptions
                          →  persistence: backdoor account + app secret + weakened CA
```

| Step | Evidence |
|------|----------|
| Initial identity | Sign-in logs (suspicious login/token) |
| Escalation vector | Audit log — consent, app-role grant, or a compromised Priv Role Admin |
| The grant | `Add member to role` |
| Azure bridge | Activity Log `elevateAccess` |
| Persistence | New users, SP credentials, CA/MFA changes |

## Decision Points

| Question | If yes → |
|----------|----------|
| Global Admin granted? | Full-takeover response; sweep everything |
| Granted to a **new/guest/app** identity? | Backdoor — remove + hunt siblings |
| `elevateAccess` present? | Azure is compromised too — pivot to Azure playbooks |
| PIM settings weakened? | Restore approval/MFA; the model was tampered |

## Contain

```powershell
# Remove the rogue role member
Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId <roleId> -DirectoryObjectId <userId>
# Disable + revoke tokens for the escalated identity and the granting identity
Update-MgUser -UserId <upn> -AccountEnabled:$false
Revoke-MgUserSignInSession -UserId <upn>
```
If `elevateAccess` was used, remove the root-scope User Access Administrator assignment in Azure.

## Eradicate

- Remove backdoor accounts and eligible-role persistence.
- Delete attacker-added app secrets/certs and rogue app owners.
- Restore any weakened Conditional Access / MFA / PIM settings.
- Reset all **other** Global Admin credentials (assume the attacker enumerated them).

## Recover

- Rebuild least-privilege admin: **PIM JIT**, minimal permanent GAs, break-glass accounts, phishing-resistant MFA.
- Alert on GA grants + `elevateAccess` going forward.
- Preserve: the grant event, the escalation chain, `elevateAccess`, and all persistence artifacts.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `Add member to role` → Global Admin | Takeover |
| Permanent grant bypassing PIM | Standing backdoor |
| Grant to a fresh/guest/app identity | Backdoor admin |
| `elevateAccess` by a GA | Owns all Azure |
| PIM settings weakened | Evasion |
| Role granted by a service principal | App-driven escalation |

## References

- Related notes: **Roles & PIM**, **Entra → Audit Logs**, **Azure → Azure RBAC**, **Applications & Service Principals**
- Compromised admin response — https://learn.microsoft.com/security/operations/incident-response-playbook-compromised-account
- Elevate access — https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin
- MITRE ATT&CK: T1098.003 Additional Cloud Roles — https://attack.mitre.org/techniques/T1098/003/
