# Investigating Microsoft (start here)

You've got an alert in a Microsoft environment — a risky sign-in, a suspicious inbox rule, a new app, a VM doing something odd. This note is the **first-hour triage flow**: what to establish, in what order, and which note to open next.

The golden rule for Microsoft: **start in identity.** Because one Entra token opens both M365 and Azure, almost every case begins with "whose identity, and what did it touch?"

## Contents

- [The First Five Questions](#the-first-five-questions)
- [Which World Am I In?](#which-world-am-i-in)
- [The Three Master Logs — Which One Answers What](#the-three-master-logs--which-one-answers-what)
- [Confirm You Even Have Evidence](#confirm-you-even-have-evidence)
- [The Triage Flow](#the-triage-flow)
- [Situation → Open This](#situation--open-this)
- [First-Hour Containment Checklist](#first-hour-containment-checklist)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The First Five Questions

Answer these before you go deep. They scope everything:

| # | Question | Where to look |
|---|----------|---------------|
| 1 | **Which identity?** Member, guest, service principal, or managed identity? | Entra sign-in logs · **01 - Entra ID & Identities** |
| 2 | **Which world?** M365 (email/files), Azure (infra), or the directory itself? | The resource in the alert (see below) |
| 3 | **From where?** IP, geo, ASN, device — known or new? | Sign-in logs → `ipAddress`, location, device |
| 4 | **Was MFA / Conditional Access satisfied — and how?** | Sign-in → `authenticationDetails`, `conditionalAccessStatus` |
| 5 | **Do I even have the logs?** Retention/export configured? | **Confirm evidence** below — do this early |

## Which World Am I In?

The resource in the alert tells you which pillar — and which log — to work:

| If the alert is about… | You're in… | Master log | Start note |
|------------------------|-----------|-----------|-----------|
| A sign-in, MFA, risky user, a role grant, an app/consent | **Entra ID** | Entra sign-in + audit | **Entra → Sign-in Logs** / **Audit Logs** |
| A mailbox, inbox rule, email, SharePoint/OneDrive file, Teams | **M365** | Unified Audit Log | **M365 → Unified Audit Log** |
| A VM, storage account, Key Vault, AKS, a resource create/delete/role assignment | **Azure** | Azure Activity Log | **Azure → Activity Log** |

> Many real cases span **all three** (phished user → mailbox rules → then into Azure). Work them in identity → M365 → Azure order, following the token.

## The Three Master Logs — Which One Answers What

Microsoft splits its audit trail three ways. Point the right question at the right log:

| Question | Log | Read it with |
|----------|-----|-------------|
| "Who signed in, from where, MFA how?" | **Entra sign-in logs** | Entra portal → Sign-in logs · Graph · `SigninLogs` (Log Analytics) |
| "Who changed a user/app/role/consent?" | **Entra audit logs** | Entra portal → Audit logs · `AuditLogs` |
| "What happened in email/files/Teams?" | **Unified Audit Log** | Purview → Audit · `Search-UnifiedAuditLog` |
| "What Azure resource was created/changed/deleted, or role assigned?" | **Azure Activity Log** | Azure portal → Activity log · `az monitor activity-log list` |
| "Which blob/secret was actually read?" | **Azure diagnostic/resource logs** | Log Analytics — *only if enabled* |

> 🔴 Don't fight one log for an answer it doesn't hold. Sign-in logs won't tell you what a mailbox rule did; the UAL won't give you the richest MFA detail. Match the question to the log.

## Confirm You Even Have Evidence

Microsoft's default retention is **short** (Entra 30 days, Activity Log 90 days). **Do this first** — an older incident may have no native logs left:

```bash
# Entra: is auditing being exported anywhere long-term? (look for a diagnostic setting → Log Analytics/Storage)
az monitor diagnostic-settings list --resource "/tenants/<tenant-id>/providers/microsoft.aadiam" 2>/dev/null

# M365: is unified audit logging even ON, and what's the retention?
#   PowerShell (Exchange Online): Get-AdminAuditLogConfig | fl UnifiedAuditLogIngestionEnabled
#   Purview → Audit → check status + any custom retention policies

# Azure Activity Log export (beyond 90 days)?
az monitor diagnostic-settings subscription list --subscription <sub-id> 2>/dev/null
```

> **Console:** Entra → **Diagnostic settings** (is it shipping to Log Analytics/Sentinel/Storage?) · Purview → **Audit** (is it on?) · Azure → Monitor → **Activity log → Export activity logs**. If a **Microsoft Sentinel** workspace exists, that's usually your long-retention gold mine — check it early. 🔴 No export + incident older than default retention = evidence gap; document it and pivot to whatever remains (mailbox contents, endpoint, backups).

## The Triage Flow

| Step | Do this | Note |
|------|---------|------|
| 1. **Confirm logging** | Check retention/export before anything ages out | *Confirm evidence* above |
| 2. **Anchor the identity** | Pull the full sign-in timeline for the user/app. Member, guest, or SP? | **01 - Entra ID & Identities** |
| 3. **Check all four sign-in logs** | Interactive **and** non-interactive **and** service-principal **and** managed-identity | **Entra → Sign-in Logs** |
| 4. **Read the directory changes** | Any role grant, app consent, credential add, new user in the window? | **Entra → Audit Logs** |
| 5. **Follow into M365** | Mailbox rules, forwarding, mass downloads, Teams? | **M365 → Unified Audit Log** |
| 6. **Follow into Azure** | New resource, role assignment, `elevateAccess`, Run Command, managed-identity use? | **Azure → Activity Log** |
| 7. **Split human vs app** | Interactive+MFA = person; SP/secret or non-interactive token = app/automation | **01 - Entra ID & Identities** |
| 8. **Contain the token, not just the account** | Revoke sessions + disable + rotate app secrets | *Checklist* below |

## Situation → Open This

| The alert / symptom is about… | Start here |
|-------------------------------|-----------|
| A risky / impossible-travel sign-in | **[Entra → Sign-in Logs](Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** |
| MFA bypass / token replay / AiTM phishing | **[Token Theft and AiTM](Entra%20ID/Playbooks/Token%20Theft%20and%20AiTM.md)** |
| A new/consented app reading mail or files | **[Illicit Consent Grant](Entra%20ID/Playbooks/Illicit%20Consent%20Grant.md)** · **[Applications & Service Principals](Entra%20ID/Applications%20%26%20Service%20Principals/Applications%20%26%20Service%20Principals%20for%20DFIR.md)** |
| A secret/cert added to an app | **[Service Principal Credential Abuse](Entra%20ID/Playbooks/Service%20Principal%20Credential%20Abuse.md)** |
| A burst of failed logins | **[Password Spray](Entra%20ID/Playbooks/Password%20Spray.md)** |
| Someone got Global Admin / a privileged role | **[Privileged Role Escalation](Entra%20ID/Playbooks/Privileged%20Role%20Escalation.md)** · **[Roles & PIM](Entra%20ID/Roles%20%26%20PIM/Roles%20%26%20PIM%20for%20DFIR.md)** |
| A compromised mailbox / inbox rules / forwarding | **[Business Email Compromise](M365/Exchange%20Online/Playbooks/Business%20Email%20Compromise.md)** · **[Malicious Inbox Rules and Forwarding](M365/Exchange%20Online/Playbooks/Malicious%20Inbox%20Rules%20and%20Forwarding.md)** |
| Mass file download / SharePoint-OneDrive exfil | **[Mass Download Exfiltration](M365/SharePoint%20%26%20OneDrive/Playbooks/Mass%20Download%20Exfiltration.md)** |
| A publicly exposed storage container | **[Exposed Blob Container](Azure/Storage/Playbooks/Exposed%20Blob%20Container.md)** |
| A managed identity / IMDS token stolen | **[Managed Identity Theft via SSRF](Azure/Playbooks/Managed%20Identity%20Theft%20via%20SSRF.md)** |
| A VM running commands / mining | **[Run Command Abuse](Azure/Virtual%20Machines/Playbooks/Run%20Command%20Abuse.md)** · **[Cryptomining Incident](Azure/Playbooks/Cryptomining%20Incident.md)** |
| A new/crypto pod in AKS | **[Malicious Pod and Cryptomining](Azure/AKS/Playbooks/Malicious%20Pod%20and%20Cryptomining.md)** |
| Resources deleted / encrypted | **[Resource Ransomware and Destruction](Azure/Playbooks/Resource%20Ransomware%20and%20Destruction.md)** |

## First-Hour Containment Checklist

Do these to actually cut a compromised identity — **remember tokens outlive passwords**:

```powershell
# 1. Revoke refresh tokens (kills silent re-auth) — the step people forget
Revoke-MgUserSignInSession -UserId alice@contoso.com

# 2. Disable the account
Update-MgUser -UserId alice@contoso.com -AccountEnabled:$false

# 3. Force password reset (after tokens revoked)
# 4. For a rogue app: disable the enterprise app + remove its added credentials
Update-MgServicePrincipal -ServicePrincipalId <sp-oid> -AccountEnabled:$false
```

| Goal | Action |
|------|--------|
| Kill silent re-auth | **Revoke refresh tokens** (`Revoke-MgUserSignInSession`) — *not just* password reset |
| Stop the account | Disable it; require re-registration of MFA if MFA was tampered |
| Neutralize a rogue app | Disable the **enterprise app** + delete attacker-added secrets/certs |
| Kill a stolen managed-identity | Treat the **resource** as compromised; stop/isolate it |
| Close the gap | Enable/extend audit retention → Sentinel/Log Analytics before more ages out |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The layout: tenant, subscriptions, two RBAC worlds | **Microsoft → 00 Overview & Terminology** |
| Who the identities are + tokens | **Microsoft → 01 Entra ID & Identities** |
| The M365 master log | **M365 → Unified Audit Log** |
| The Azure master log | **Azure → Activity Log** |
| The same actor across clouds | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- Entra sign-in logs — https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins
- Search the unified audit log — https://learn.microsoft.com/purview/audit-log-search
- Azure Activity Log — https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log
- Respond to a compromised account — https://learn.microsoft.com/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account
- MITRE ATT&CK Cloud (Office 365 / Entra ID / Azure) — https://attack.mitre.org/matrices/enterprise/cloud/
