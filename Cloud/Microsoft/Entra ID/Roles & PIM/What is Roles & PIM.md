# What is Entra Roles & PIM?

**Entra roles** (directory roles) are the permissions that govern the **directory and M365** — who can manage users, apps, Exchange, Conditional Access, and (at the top) *everything*. **PIM (Privileged Identity Management)** is the just-in-time system that makes those roles **eligible** instead of **always-on**, so admins activate them only when needed.

This is one of the **two RBAC worlds** (see **00 - Overview**). Entra roles ≠ Azure RBAC roles — this note is the **directory** side.

## Contents

- [How It Works](#how-it-works)
- [Entra Roles vs Azure RBAC — Don't Confuse Them](#entra-roles-vs-azure-rbac--dont-confuse-them)
- [The Roles That Matter Most](#the-roles-that-matter-most)
- [PIM — Eligible vs Active](#pim--eligible-vs-active)
- [The Global Admin → Azure Bridge](#the-global-admin--azure-bridge)
- [How to Identify Role Activity in Evidence](#how-to-identify-role-activity-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

A role bundles permissions. An identity gets a role by **assignment** (permanent) or, with PIM, by being made **eligible** and then **activating** it.

```
Identity  →  assigned a role (permanent)          →  has the permissions now
          →  OR eligible (PIM) → activate → active →  has the permissions for a time-boxed window
```

Roles can be scoped **tenant-wide** or to an **administrative unit** (a slice of users/groups).

## Entra Roles vs Azure RBAC — Don't Confuse Them

The distinction that trips up every responder:

| | **Entra roles** (this note) | **Azure RBAC** |
|-|------------------------------|-----------------|
| Govern | Directory + M365 | Azure resources |
| Top role | **Global Administrator** | **Owner** (at mgmt-group/subscription) |
| Assigned via | Entra roles / **PIM for Entra roles** | Azure role assignments / **PIM for Azure resources** |
| Logged in | **Entra audit log** (`Add member to role`) | **Azure Activity Log** (`roleAssignments/write`) |

> 🔴 A **Global Administrator is not automatically an Azure Owner** — until they use `elevateAccess` (below). Always ask which world a role grant was in.

## The Roles That Matter Most

| Role | Grants | 🔴 On a case |
|------|--------|-------------|
| **Global Administrator** | Everything in the directory + M365 | Full takeover; the crown jewel |
| **Privileged Role Administrator** | Grant/manage **other roles** (incl. Global Admin) | Escalation to anything |
| **Application Administrator** / **Cloud App Admin** | Manage apps + **add app credentials** | 🔴 Add a secret to a privileged app → app-only takeover |
| **Privileged Authentication Administrator** | Reset **any** user's MFA/creds (incl. Global Admins) | Account takeover of admins |
| **User Administrator** | Manage users, reset most passwords | Account takeover of non-admins |
| **Exchange / SharePoint Administrator** | Full mail / file control | Mailbox + file access at scale |
| **Conditional Access Administrator** | Edit CA policies | 🔴 Disable MFA enforcement (evasion) |
| **Hybrid Identity Administrator** | Manage sync/federation | 🔴 Federation backdoor / Golden SAML |

## PIM — Eligible vs Active

PIM's whole point is **no standing privilege**. Know the states:

| State | Meaning | 🔴 Watch |
|-------|---------|----------|
| **Permanent (active)** | The identity holds the role all the time | Standing privilege — highest risk; should be rare |
| **Eligible** | The identity *can* activate the role (JIT) | An unexpected new eligibility is persistence |
| **Active (activated)** | Currently using an eligible role | Note the justification / approval |

PIM adds **approval, MFA-on-activation, time limits, and justification**. Its activation events are strong evidence: *who activated what, when, why, approved by whom.*

> 🔴 An attacker who reaches **Privileged Role Admin** can make themselves (or a backdoor account) **eligible or permanently assigned** to Global Admin. A new **permanent** Global Admin assignment (bypassing PIM's JIT model) is a loud signal.

## The Global Admin → Azure Bridge

The one escalation that crosses the two RBAC worlds:

> 🔴 A **Global Administrator** can toggle **`Microsoft.Authorization/elevateAccess`** — granting themselves **User Access Administrator at the root scope over every Azure subscription.** This turns "owns the directory" into "owns all infrastructure." It appears in the **Azure Activity Log** (not the Entra audit log). **Always check for `elevateAccess`** when a Global Admin is compromised. See **Azure → Azure RBAC**.

## How to Identify Role Activity in Evidence

- **Portal:** Entra ID → **Roles and administrators** (assignments) · **Identity Governance → PIM** (eligibility/activations).
- **Graph:** `roleManagement/directory/roleAssignments`, `roleEligibilityScheduleInstances`, `roleAssignmentScheduleInstances`.
- **Audit log:** `Add member to role`, `Add eligible member to role`, `Add member to role (PIM activated)`.

## Common Operations You Will See

| Operation (audit log) | What it does | Watch? |
|-----------------------|--------------|--------|
| `Add member to role` | Permanent role grant | 🔴 Global Admin / Priv Role Admin |
| `Add eligible member to role` | PIM eligibility granted | 🔴 unexpected new eligibility |
| `Add member to role (PIM activated)` | An eligible role activated | Normal, but read the justification |
| `Remove member from role` | Role removed | Attacker cleanup, or your remediation |
| `Update role setting` (PIM) | Weaken PIM (no MFA/approval) | 🔴 defense evasion |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Global Administrator | Org management-account admin | Org Admin |
| Entra role assignment | IAM policy attachment | IAM role binding |
| PIM (JIT roles) | IAM Identity Center + temporary elevation | IAM Conditions / PAM |
| Eligible role | (no direct equal) | Privileged Access Manager grant |
| `elevateAccess` bridge | (no direct equal) | (org-level grant) |

## Common Use Cases

Your "normal" baseline:

- **Least-privilege admin** via scoped roles + PIM.
- **JIT elevation** for occasional admin tasks.
- **Access reviews** to prune standing admins.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Directory role** | An Entra role governing the directory/M365 |
| **Global Administrator** | The top directory role |
| **PIM** | Privileged Identity Management (JIT roles) |
| **Eligible** | Can activate a role on demand |
| **Active** | Currently holding/using a role |
| **Permanent assignment** | Standing (always-on) role |
| **Administrative unit** | A scope limiting a role to some users/groups |
| **elevateAccess** | GA toggle to gain Azure-wide access |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating role abuse | **Roles & PIM → for DFIR** |
| Who the actor is | **Microsoft → 01 Entra ID & Identities** |
| Role-grant events | **Entra → Audit Logs** |
| The Azure side of RBAC | **Azure → Azure RBAC** |
| A full escalation chain | **Entra → Playbooks → Privileged Role Escalation** |

## Resources

- Entra built-in roles — https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
- PIM overview — https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure
- Entra roles vs Azure roles — https://learn.microsoft.com/entra/identity/role-based-access-control/concept-understand-roles
- Elevate access — https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin
