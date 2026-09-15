# What is Entra Audit Logs?

Entra **audit logs** are the record of **every change to the directory** — a user created, a group modified, a role granted, an app consented, a credential added to a service principal. Where sign-in logs answer *who authenticated*, audit logs answer *what changed*.

Think of them as the **change-control CCTV** for identity. Nearly every persistence and privilege-escalation step in a Microsoft breach is a directory change — and it lands here.

## Contents

- [How It Works](#how-it-works)
- [What It Records vs What It Doesn't](#what-it-records-vs-what-it-doesnt)
- [Where the Logs Live and How You Query Each](#where-the-logs-live-and-how-you-query-each)
- [How to Identify an Audit Event](#how-to-identify-an-audit-event)
- [The Audit Actions That Matter Most](#the-audit-actions-that-matter-most)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Any change made through Entra (portal, Graph, PowerShell) becomes an **audit event** describing the actor, the target, the action, and the result.

| Field group | Contains |
|-------------|----------|
| **initiatedBy** | Who did it — a user (UPN + object ID) or an app (SP) |
| **activityDisplayName** | The action, e.g. `Add member to role`, `Consent to application` |
| **targetResources** | What was changed — the user/app/role, plus old→new values |
| **result** | success / failure |

Two facts for a live case:

- Retention is **~30 days** in Entra — export to **Log Analytics/Sentinel** for longer.
- The **`targetResources[].modifiedProperties`** block holds the **old and new values** — this is where you see *exactly* what a policy or role change did.

## What It Records vs What It Doesn't

| ✅ In the audit log | 🔴 NOT here (look elsewhere) |
|---------------------|------------------------------|
| User/group create/modify/delete | Sign-ins (→ **Sign-in Logs**) |
| Role assignments (`Add member to role`) | Mailbox/file actions (→ **M365 UAL**) |
| App registration / SP create | Azure resource changes (→ **Azure Activity Log**) |
| **Consent** to apps / app role grants | Data reads (blob/secret) (→ diagnostic logs) |
| **Credentials added** to an app/SP | |
| Conditional Access policy changes | |
| Device registration / join | |

## Where the Logs Live and How You Query Each

| Destination | What it is | Look-back | Query with | Best for |
|-------------|-----------|-----------|-----------|----------|
| **Entra portal** | Audit logs blade | ~30 days | Filters (service, activity, actor, target) | Fast first look |
| **Microsoft Graph** | `auditLogs/directoryAudits` | ~30 days | Graph / PowerShell | Scripted pulls |
| **Log Analytics / Sentinel** | Exported copy | Your retention | **KQL** (`AuditLogs`) | Long look-back + hunting |
| **Unified Audit Log** | Many Entra events also flow to the UAL | 180 d–1 yr | `Search-UnifiedAuditLog` | Longest native look-back |

> 🔴 Because Entra audit retention is only 30 days, the **UAL (180 days–1 year)** is often your best native source for older directory changes — Entra `Add member to role`, `Consent to application`, etc. also appear there under record types like `AzureActiveDirectory`.

## How to Identify an Audit Event

- **Entra portal:** Entra ID → **Monitoring → Audit logs**.
- **Graph:** `GET /auditLogs/directoryAudits`.
- **KQL:** table `AuditLogs`.
- Every event has an `initiatedBy`, an `activityDisplayName`, `targetResources[]` (with `modifiedProperties`), and a `result`.

## The Audit Actions That Matter Most

🔴 The directory changes attackers make — memorize these:

| Action (`activityDisplayName`) | What it does | 🔴 Why it matters |
|--------------------------------|--------------|-------------------|
| `Add member to role` | Grants a directory role | **Global Admin** grant = takeover |
| `Add eligible member to role` (PIM) | Makes someone eligible for a role | Standing/eligible privilege |
| `Consent to application` | Grants an app permissions | **Illicit consent** — tenant-wide data access |
| `Add app role assignment to service principal` | App-only permission grant | Silent, MFA-less Graph access |
| `Add service principal credentials` | Adds a secret/cert to an app | **Persistence** — attacker's key in a trusted app |
| `Update application – Certificates and secrets` | Same, on the app registration | Persistence |
| `Add member to group` | Adds to a group | If the group grants access/roles → escalation |
| `Update conditional access policy` / `Delete` | Weakens/removes a CA policy | **Defense evasion** — disabling MFA enforcement |
| `Set domain authentication` / `Add unverified domain` | Federation change | **Golden SAML** / federation backdoor |
| `Add owner to application/service principal` | New app owner | Persistence — owner can add creds |
| `Register device` / `Add registered owner` | Device join | PRT/device-based persistence |
| `Disable Strong Authentication` / MFA method changes | MFA tampering | Weakening auth |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Entra audit logs | CloudTrail (IAM management events) | Cloud Audit Logs (Admin Activity) |
| `Add member to role` | `AttachUserPolicy` / `AddUserToGroup` | `setIamPolicy` |
| `Consent to application` | (OAuth app grant) | OAuth token grant |
| `Add service principal credentials` | `CreateAccessKey` | SA key create |

## Common Use Cases

Your "normal" baseline:

- **Change auditing** — who created/modified an identity or app.
- **Access reviews** — role and group membership history.
- **App governance** — consent and credential changes.
- **Compliance** — a record of directory changes.

## Key Terminology

| Term | Meaning |
|------|---------|
| **initiatedBy** | The actor (user or app) that made the change |
| **activityDisplayName** | The action performed |
| **targetResources** | The objects that were changed |
| **modifiedProperties** | The old→new values of the change |
| **directoryAudits** | The Graph API for audit events |
| **PIM** | Privileged Identity Management (just-in-time roles) |
| **Consent** | Granting an app permission to data |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating directory changes in a case | **Audit Logs → Audit Logs for DFIR** |
| Who the actor is (user vs SP) | **Microsoft → 01 Entra ID & Identities** |
| Who authenticated (the sign-in side) | **Entra → Sign-in Logs** |
| Apps / consent / credentials in depth | **Entra → Applications & Service Principals** |
| Roles + PIM | **Entra → Roles & PIM** |

## Resources

- Audit logs concept — https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs
- directoryAudits Graph API — https://learn.microsoft.com/graph/api/resources/directoryaudit
- What activities are audited — https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities
