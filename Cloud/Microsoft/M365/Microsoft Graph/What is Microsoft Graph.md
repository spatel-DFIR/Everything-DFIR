# What is Microsoft Graph?

**Microsoft Graph** is the **single REST API** to nearly everything Microsoft-cloud — Entra identities, Exchange mail, SharePoint/OneDrive files, Teams, devices, security data. One endpoint (`graph.microsoft.com`), one token, one permission model.

For DFIR it cuts both ways: it's **your best collection tool** (pull sign-ins, audit logs, mailbox rules, files via one API) **and the attacker's favorite weapon** (a consented app or stolen token reads the whole tenant through Graph).

## Contents

- [How It Works](#how-it-works)
- [Why Attackers Love Graph](#why-attackers-love-graph)
- [Delegated vs Application — Again, It Decides Everything](#delegated-vs-application--again-it-decides-everything)
- [How Graph Access Shows Up in Logs](#how-graph-access-shows-up-in-logs)
- [The High-Value Graph Permissions](#the-high-value-graph-permissions)
- [Using Graph as a Responder](#using-graph-as-a-responder)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

A caller (user or app) gets an Entra **token** with **scopes** (permissions), then calls Graph endpoints like `/users`, `/me/messages`, `/auditLogs/signIns`, `/drives`. The token's scopes decide what it can touch.

```
Identity → Entra token (with scopes) → https://graph.microsoft.com/v1.0/<resource>
```

## Why Attackers Love Graph

- **One API for everything** — mail, files, users, groups — no need to learn each service.
- **App-only access** — a consented app calls Graph with **no user and no MFA**.
- **Blends in** — Graph traffic is ubiquitous; malicious calls hide in normal noise.
- **Scriptable at scale** — dump every mailbox/user/file quickly.

> 🔴 The **illicit consent grant** and **service-principal credential abuse** attacks both end in the same place: an app calling **Graph** with high-value permissions. Graph is the *action*; the consent/credential is the *access*.

## Delegated vs Application — Again, It Decides Everything

| | **Delegated** | **Application (app-only)** |
|-|---------------|-----------------------------|
| Calls Graph as | The user + app | The **app alone** |
| MFA | Applies (to the user) | 🔴 None |
| Blast radius | The user's data | 🔴 Tenant-wide |
| Log | User (interactive/non-interactive) sign-in | **Service-principal** sign-in |

See **Entra → 01 Identities** and **Applications & Service Principals** for the full treatment.

## How Graph Access Shows Up in Logs

| You want | Look at |
|----------|---------|
| A user calling Graph | Sign-in logs → `ResourceDisplayName = "Microsoft Graph"` |
| An **app** calling Graph | **Service-principal** sign-in logs, resource = Graph |
| What the app was *allowed* | `appRoleAssignments` (application) / `oauth2PermissionGrants` (delegated) |
| What it *did* (data-plane) | UAL (`MailItemsAccessed`, `FileAccessed`) — if auditing on |

> 🔴 Graph itself doesn't give you a per-call "it read this specific email" log — that comes from the **workload's** audit (UAL). Graph sign-ins tell you *who/what/when*; the UAL tells you *which data*.

## The High-Value Graph Permissions

As **application** permissions, these effectively own the tenant (same list as apps note — worth repeating):

| Permission | Grants |
|-----------|--------|
| `Mail.Read` / `Mail.ReadWrite` | All mailboxes |
| `Files.ReadWrite.All` / `Sites.ReadWrite.All` | All files |
| `Directory.ReadWrite.All` | The directory |
| `User.ReadWrite.All` | Edit/reset users |
| `RoleManagement.ReadWrite.Directory` | 🔴 Grant roles (self-escalate) |
| `Application.ReadWrite.All` | Create apps + add credentials (persistence) |

## Using Graph as a Responder

Graph is your collection engine. Examples used throughout these notes:

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All","Application.Read.All"
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'alice@contoso.com'"
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Add member to role'"
Get-MgServicePrincipal -Filter "appId eq '<guid>'"
```

> Use a **read-only** scoped session for collection; use least-privilege admin for response. Log your own Graph activity — it shows up in the SP/interactive sign-in logs too.

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Microsoft Graph | AWS API (per-service) + SDK | Google Workspace/Cloud APIs |
| Graph app permission | IAM policy on a service | API scope / domain-wide delegation |
| Graph token | STS session | OAuth token |

## Common Use Cases

Your "normal" baseline:

- SaaS integrations + internal automation.
- Backup/security tools reading mail/files via app-only Graph.
- Admin scripting (PowerShell SDK).

## Key Terminology

| Term | Meaning |
|------|---------|
| **Microsoft Graph** | The unified Microsoft-cloud API |
| **Scope / permission** | What a token is allowed to do |
| **Delegated** | Graph call with a user |
| **Application permission** | App-only Graph call |
| **Graph SDK** | Client libraries (incl. PowerShell) |
| **v1.0 / beta** | Graph API versions |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating Graph abuse | **Microsoft Graph → for DFIR** |
| Apps / consent / permissions | **Entra → Applications & Service Principals** |
| App sign-ins | **Entra → Sign-in Logs** |
| What data was actually read | **M365 → Unified Audit Log** |
| The illicit-consent scenario | **Entra → Playbooks → Illicit Consent Grant** |

## Resources

- Microsoft Graph overview — https://learn.microsoft.com/graph/overview
- Graph permissions reference — https://learn.microsoft.com/graph/permissions-reference
- Graph PowerShell SDK — https://learn.microsoft.com/powershell/microsoftgraph/overview
