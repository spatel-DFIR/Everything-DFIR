# Playbook — Illicit Consent Grant

The signature cloud-native attack. A user (or admin) is tricked into **consenting** to a malicious OAuth app. No password is stolen and **MFA is never challenged** — the app just gets a **token** to read mail, files, or the directory, and keeps it. This playbook determines **who consented, to what app, what it could reach, what it took, and how to cut it off.**

> **Tier 2 (cross-service).** Spans Entra apps + audit logs + M365. Read **Entra → Applications & Service Principals** first.

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
| **Identity Protection** | Risky app / suspicious consent |
| **Defender / app governance** | New over-privileged app flagged |
| **Audit log** | `Consent to application` / `Add app role assignment to service principal` |
| **User report** | "I clicked a link and approved something for Office" |
| **Unusual mail activity** | Mailbox reads from an app nobody installed |

## Hypothesis

An attacker registered a multi-tenant OAuth app and phished a consent. A **service principal** now exists in the tenant with delegated (one user) or application (tenant-wide) permissions. Establish scope, prove access, and revoke.

## Step-by-Step Investigation

**1. Find the consent event.**

```powershell
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Consent to application'" -Top 50
```
Note the **app**, the **user who consented**, whether it was **admin consent**, and the time.

**2. Inventory the app's permissions.** Delegated (`oauth2PermissionGrants`) vs application (`appRoleAssignments`). 🔴 `Mail.Read`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, `full_access_as_app`.

```powershell
$sp = Get-MgServicePrincipal -Filter "appId eq '<app-guid>'"
Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'"
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
```

**3. Is it multi-tenant / third-party?** A publisher you don't recognize + a mimic name ("Office 365 Enhanced Security") = malicious.

**4. Read the app's sign-ins.** `AADServicePrincipalSignInLogs` — which resources it called (Graph/Exchange), from which IPs, how much.

**5. Scope by permission.** Delegated = *that* user's data. Application = *everyone's*. Set the blast radius accordingly.

## Did Data Actually Leave?

| If the app had… | You can determine |
|-----------------|-------------------|
| `Mail.Read` + **UAL mailbox auditing** | Which mailboxes/items the app read (search UAL by the app's identity) |
| `Files.Read` + SharePoint/OneDrive auditing | Which files it pulled |
| Only the grant, no data-plane audit | 🔴 Only that it *could* read — assume worst for the granted scope |

🔴 Correlate the **app's object ID / appId** against UAL `MailItemsAccessed` / `FileAccessed` events to prove reads.

## Decision Points

| Question | If yes → |
|----------|----------|
| Application (tenant-wide) permission? | Treat as tenant-wide breach; all mail/files in scope |
| Admin consent given? | A privileged account was phished — investigate that admin too |
| Multiple users consented? | Consent-phishing campaign — hunt the app across all users |
| Sensitive scopes (`RoleManagement.ReadWrite`)? | App could self-escalate to Global Admin — check for role grants |

## Contain

```powershell
# Disable the enterprise app immediately
Update-MgServicePrincipal -ServicePrincipalId <sp-id> -AccountEnabled:$false
# Revoke its permission grants
Get-MgOauth2PermissionGrant -Filter "clientId eq '<sp-id>'" | ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
```
Revoke tokens for the user(s) who consented (`Revoke-MgUserSignInSession`).

## Eradicate

- Delete the service principal (capture evidence first: permissions, sign-ins, appId).
- Remove any credentials/owners the app added.
- If it had `RoleManagement`/`Application.ReadWrite`, hunt for **new role grants, backdoor accounts, and app secrets** it may have created.

## Recover

- **Restrict user consent** (admins only / low-risk scopes) + enable admin-consent workflow.
- Rotate anything the app could read (secrets in mailboxes/files).
- Notify affected users; data-breach handling if PII/regulated data was reachable.
- Preserve: the consent event, the app's permissions + sign-ins, and any UAL proof of reads.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `Consent to application` to `Mail.Read`/`.All` app perms | Tenant-wide silent access |
| Multi-tenant app, unknown publisher, mimic name | Malicious app |
| Consent right after a phishing email | Consent phishing |
| SP sign-ins from hosting/anonymized IPs | Attacker-operated app |
| App with `RoleManagement.ReadWrite.Directory` | Self-escalation to Global Admin |

## References

- Related notes: **Applications & Service Principals**, **Entra → Audit Logs**, **M365 → Exchange Online**
- Detect & remediate illicit consent — https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants
- Restrict user consent — https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent
- MITRE ATT&CK: T1528 Steal Application Access Token — https://attack.mitre.org/techniques/T1528/
