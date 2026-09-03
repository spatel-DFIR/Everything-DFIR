# Playbook — Service Principal Credential Abuse

The stealthiest persistence in Entra. An attacker who reaches a privileged identity **adds a client secret or certificate to an existing, trusted, over-permissioned app** — then authenticates as that app any time: **no user, no MFA, sign-ins in a log nobody watches.** This playbook finds the planted credential, proves what the app did, and removes it.

> **Tier 2 (cross-service).** Entra apps + audit + SP sign-in logs. Read **Entra → Applications & Service Principals** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [What Did the App Do?](#what-did-the-app-do)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Audit log** | `Add service principal credentials` / `Update application – Certificates and secrets` |
| **App governance** | New credential on a privileged app |
| **SP sign-in logs** | An app authenticating from a new IP / calling new resources |
| **Post-incident** | After a Global Admin compromise, hunting for what they left behind |

## Hypothesis

An attacker planted a credential in a trusted app to keep app-only access after the user account is cleaned. Find the credential (and its add-time/actor), scope the app's permissions, prove its activity, and remove it.

## Step-by-Step Investigation

**1. Find the credential-add event.**

```powershell
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Add service principal credentials' or activityDisplayName eq 'Update application – Certificates and secrets'" -Top 50
```
Note the **app**, the **actor** who added it, and the **time**.

**2. Inspect the app's credentials** — look for keys with a **recent `StartDateTime`** you can't account for:

```powershell
$sp = Get-MgServicePrincipal -Filter "appId eq '<app-guid>'"
$sp.PasswordCredentials | Select DisplayName, StartDateTime, EndDateTime
$sp.KeyCredentials       | Select DisplayName, StartDateTime, EndDateTime
```

**3. Scope the app's permissions.** How much does this app grant? `Mail.Read`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`? That's the blast radius.

**4. Read the SP sign-ins** — where the credential was used from and what it called:

```kql
AADServicePrincipalSignInLogs
| where AppId == "<app-guid>"
| project TimeGenerated, IPAddress, ResourceDisplayName, ServicePrincipalCredentialKeyId
| order by TimeGenerated asc
```

## What Did the App Do?

| App's permission | Correlate with |
|------------------|----------------|
| `Mail.Read`/`.ReadWrite` | UAL `MailItemsAccessed` by the app's identity |
| `Files/Sites.ReadWrite.All` | UAL SharePoint/OneDrive access by the app |
| `Directory.ReadWrite.All` | Audit log directory changes initiated by the app |
| `RoleManagement.ReadWrite.Directory` | 🔴 Audit log role grants by the app (self-escalation) |

## Decision Points

| Question | If yes → |
|----------|----------|
| Credential added by a compromised admin? | Confirmed persistence — remove + hunt further |
| App has `RoleManagement`/`Application.ReadWrite`? | App could create more backdoors — full sweep |
| Multiple apps touched? | Attacker seeded several — inventory all recent credential adds |
| Federated credential added? | External workload can auth as the app — remove the trust |

## Contain

```powershell
# Remove the attacker's credential (capture its details first)
Remove-MgServicePrincipalPassword -ServicePrincipalId $sp.Id -KeyId <keyId>
# Or disable the app if it's attacker-created
Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AccountEnabled:$false
```

## Eradicate

- Delete every attacker-added secret/cert/federated credential across all apps.
- Remove rogue app **owners** (an owner can just re-add a credential).
- If the app self-granted roles or made backdoor accounts, remove those too.

## Recover

- Rotate legitimate credentials on the affected app (assume the attacker saw them).
- Move to **certificates / managed identities / federated creds**; minimize long-lived secrets.
- Enable **app governance** + alerts on credential adds.
- Preserve: the credential-add event, the app's permissions + SP sign-ins.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Secret/cert added to a privileged app by a compromised user | Persistence |
| SP sign-in from a new/hosting IP after the credential add | Attacker using the planted key |
| App with `RoleManagement.ReadWrite.Directory` | Self-escalation to Global Admin |
| Federated credential added to an app | External auth backdoor |
| New owner on a privileged app | Re-add-credential persistence |

## References

- Related notes: **Applications & Service Principals**, **Entra → Audit Logs**, **Roles & PIM**
- Additional cloud credentials — https://learn.microsoft.com/security/operations/incident-response-playbook-compromised-malicious-app
- App governance — https://learn.microsoft.com/defender-cloud-apps/app-governance-manage-app-governance
- MITRE ATT&CK: T1098.001 Additional Cloud Credentials — https://attack.mitre.org/techniques/T1098/001/
