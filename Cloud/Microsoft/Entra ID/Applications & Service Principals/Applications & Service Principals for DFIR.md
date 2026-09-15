# Applications & Service Principals for DFIR

Rogue and abused apps are one of the hardest Microsoft compromises to spot: no user, no MFA, sign-ins in a log nobody watches. This note is how you **inventory apps, find the malicious one, prove what it accessed, and cut it off.**

New to this? Read **What is Applications & Service Principals** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [The Rogue-App Triage](#the-rogue-app-triage)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Where |
|--------|--------------|-------|
| **Audit logs** | Consent, credential adds, ownership, app creation | Entra / `AuditLogs` |
| **Service-principal sign-in logs** | The app authenticating (IPs, resources called) | Entra SP tab / `AADServicePrincipalSignInLogs` |
| **Permission grants** | `oauth2PermissionGrants` (delegated) + `appRoleAssignments` (application) | Graph |
| **App/SP objects** | Credentials + their dates, owners, reply URLs | Graph / portal |
| **UAL** | Some app/consent events, longer retention | `Search-UnifiedAuditLog` |

## Collect It

**Inventory a suspect app fully:**

```powershell
# The service principal + its app-only (application) permission grants
$sp = Get-MgServicePrincipal -Filter "appId eq '<app-guid>'"
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id      # application perms
Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'"          # delegated perms

# 🔴 Its credentials — look at CREATION DATES for recently added keys
Get-MgServicePrincipal -ServicePrincipalId $sp.Id | Select-Object -ExpandProperty KeyCredentials
Get-MgServicePrincipal -ServicePrincipalId $sp.Id | Select-Object -ExpandProperty PasswordCredentials

# Owners (persistence)
Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id
```

> **Console:** Entra ID → **Enterprise applications** → the app → **Permissions** (consented scopes), **Certificates & secrets** (via the app registration), **Owners**, **Sign-in logs** (its activity).

**Find every recently-added credential across all apps (persistence sweep):**

```powershell
Get-MgApplication -All | ForEach-Object {
  $_.PasswordCredentials + $_.KeyCredentials | Where-Object { $_.StartDateTime -gt (Get-Date).AddDays(-30) } |
  ForEach-Object { [pscustomobject]@{ App=$app.DisplayName; Added=$_.StartDateTime } }
}
```

## Investigate on the Platform

The flow:

| Step | Do this |
|------|---------|
| 1. Identify the app object | App ID → the service principal in *your* tenant; is it multi-tenant / third-party? |
| 2. Read its permissions | Delegated vs **application**; any high-risk `*.All` scopes? |
| 3. Read its credentials | 🔴 Any secret/cert **added recently** or by an unexpected actor? |
| 4. Read its SP sign-ins | New IPs, new resources called (Graph/Exchange), volume spikes |
| 5. Trace the consent/grant | Audit log: who consented, when, to what |
| 6. Prove access | If it has `Mail.Read`/`Files.*`, correlate with UAL for mailbox/file reads by the app |

## The Rogue-App Triage

Fast signal that an app is malicious:

| Signal | Weight |
|--------|--------|
| Multi-tenant app you don't recognize + admin consent | 🔴 High |
| Application permissions like `Mail.Read`, `Files.ReadWrite.All`, `Directory.ReadWrite.All` | 🔴 High |
| A secret/cert **added recently** by a compromised user | 🔴 High |
| SP signing in from a new/hosting-provider IP | 🔴 Medium |
| App name mimicking a legit product ("0ffice", "Backup") | 🔴 Medium |
| Reply/redirect URL to an unknown domain | Medium |
| Consented by a single user right after a phishing email | 🔴 High |

## Hunt at Scale

**High-risk application permissions across the tenant:**

```kql
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| where tostring(TargetResources) has_any ("Mail.Read","Mail.ReadWrite","Files.ReadWrite.All","Directory.ReadWrite.All","full_access_as_app")
| project TimeGenerated, InitiatedBy, TargetResources
```

**Credentials added to service principals:**

```kql
AuditLogs
| where OperationName in ("Add service principal credentials","Update application – Certificates and secrets")
| project TimeGenerated, Actor=InitiatedBy, App=TargetResources, Result
```

**Service-principal sign-ins from new IPs:**

```kql
AADServicePrincipalSignInLogs
| summarize IPs=make_set(IPAddress), Resources=make_set(ResourceDisplayName) by ServicePrincipalName, AppId
| where array_length(IPs) > 1
```

## Respond

| Goal | Action |
|------|--------|
| Cut the app off immediately | Disable the enterprise app: `Update-MgServicePrincipal -ServicePrincipalId <id> -AccountEnabled:$false` |
| Remove its access | Revoke the app-role assignments + delete `oauth2PermissionGrants` |
| Kill persistence | Delete every attacker-added secret/cert; remove rogue owners |
| Fully remove | Delete the service principal (and app registration if internal) |
| Contain the human | Reset/lock the user who consented; revoke their tokens |

```powershell
# Disable, then strip credentials and grants
Update-MgServicePrincipal -ServicePrincipalId <sp-id> -AccountEnabled:$false
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <sp-id> |
  ForEach-Object { Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <sp-id> -AppRoleAssignmentId $_.Id }
```

> 🔴 Disabling the app stops it now, but **don't delete evidence** before you've captured its permissions, credentials, owners, and sign-in history.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Restrict user consent** (admins only, or low-risk scopes) | Stops consent-phishing at scale |
| **Admin consent workflow** (request/approve) | Human review before grants |
| **App governance / Workload ID Protection** | Detects risky apps + credential adds |
| **Alert** on high-risk app-perm grants + SP credential adds | Catch persistence in real time |
| **Periodic access review** of enterprise apps + their permissions | Prune stale/over-permissioned apps |
| **Prefer certs / managed identities / federated creds** over long-lived secrets | Fewer leakable keys |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Multi-tenant app + admin consent to `*.All` app perms | Tenant-wide silent data access |
| Secret/cert added to an app by a compromised user | Persistence |
| App-only `RoleManagement.ReadWrite.Directory` | App can grant itself Global Admin |
| SP sign-in from a new/hosting IP calling Graph/Exchange | Rogue or hijacked app |
| App consented by one user right after a phish | Illicit consent grant |
| New owner added to a privileged app | Persistence via ownership |
| Reply URL to an unknown external domain | Token exfil path |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the objects are + permissions | **Applications & Service Principals → What is** |
| Identity types + tokens | **Microsoft → 01 Entra ID & Identities** |
| Consent/credential events | **Entra → Audit Logs** |
| App sign-ins | **Entra → Sign-in Logs** |
| A consent-phishing chain | **Entra → Playbooks → Illicit Consent Grant** |
| A credential-add chain | **Entra → Playbooks → Service Principal Credential Abuse** |
| App reading mailboxes | **M365 → Exchange Online** |

## Resources

- Detect & remediate illicit consent grants — https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants
- Restrict user consent — https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent
- App governance — https://learn.microsoft.com/defender-cloud-apps/app-governance-manage-app-governance
- MITRE ATT&CK: Cloud Application Access Token (T1550.001) / Additional Cloud Credentials (T1098.001) — https://attack.mitre.org/techniques/T1098/001/
