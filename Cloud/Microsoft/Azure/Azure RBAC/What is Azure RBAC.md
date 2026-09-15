# What is Azure RBAC?

**Azure RBAC (Role-Based Access Control)** is the permission system for **Azure resources** — it decides who can create a VM, read a storage account's keys, or own a subscription. A **role assignment** = a **principal** (who) + a **role** (what) + a **scope** (where).

🔴 This is **one of the two RBAC worlds.** Azure RBAC governs **resources**; **Entra roles** govern the **directory + M365**. They are separate systems with separate logs. Confusing them is the most common Microsoft-IR mistake — this note keeps them straight.

## Contents

- [How It Works](#how-it-works)
- [Azure RBAC vs Entra Roles — The Two Worlds](#azure-rbac-vs-entra-roles--the-two-worlds)
- [The Anatomy of a Role Assignment](#the-anatomy-of-a-role-assignment)
- [Scope and Inheritance](#scope-and-inheritance)
- [The Roles That Matter Most](#the-roles-that-matter-most)
- [The elevateAccess Bridge](#the-elevateaccess-bridge)
- [How to Identify RBAC Activity](#how-to-identify-rbac-activity)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

When a principal calls ARM to do something, Azure checks: is there a **role assignment** granting that action at (or above) the resource's scope? Deny by default; an assignment must exist.

```
Principal (user/group/SP/managed identity)  +  Role (Owner/Contributor/…)  +  Scope (mgmt group/sub/RG/resource)
                                             = a role assignment (the grant)
```

## Azure RBAC vs Entra Roles — The Two Worlds

Memorize this table; it prevents the classic mistake:

| | **Azure RBAC** (this note) | **Entra roles** |
|-|-----------------------------|------------------|
| Governs | **Azure resources** (VMs, storage, vaults) | **Directory + M365** (users, apps, Exchange) |
| Top role | **Owner** (at a broad scope) | **Global Administrator** |
| Scope | Management group / subscription / RG / resource | Tenant (or admin unit) |
| Assigned via | Azure role assignments / **PIM for Azure resources** | Entra roles / **PIM for Entra roles** |
| Logged in | **Azure Activity Log** (`roleAssignments/write`) | **Entra audit log** (`Add member to role`) |

> 🔴 A **Global Admin is not an Owner** of Azure resources, and an **Owner** of a subscription is not a Global Admin. Different powers, different logs. When someone says "admin," ask: *of the directory, or of the resources?*

## The Anatomy of a Role Assignment

| Part | Example | Investigative value |
|------|---------|---------------------|
| **Principal** | A user, group, **service principal**, or **managed identity** | 🔴 SP/managed-identity grants are easy to miss |
| **Role** | Owner, Contributor, Reader, User Access Administrator, or a **custom role** | Owner/UAA = escalation |
| **Scope** | `/subscriptions/<id>` or `/subscriptions/<id>/resourceGroups/<rg>` | Broad scope = big blast radius |

> 🔴 **User Access Administrator (UAA)** can grant *other* roles — a stealthy escalation role. **Custom roles** with `Microsoft.Authorization/*/write` or `*/action` can hide Owner-like power under an innocent name — always read a custom role's actions.

## Scope and Inheritance

Assignments **inherit downward**:

```
Management group   ← assign here → inherited by ALL subscriptions under it (huge)
└── Subscription   ← assign here → inherited by all RGs/resources
    └── Resource group
        └── Resource
```

> 🔴 An attacker granting **Owner at the management-group or subscription** scope owns everything beneath it. Always note **at what scope** a grant was made — a resource-level grant is contained; a management-group grant is catastrophic.

## The Roles That Matter Most

| Role | Grants | 🔴 On a case |
|------|--------|-------------|
| **Owner** | Full control **incl. granting access** | Takeover at its scope |
| **User Access Administrator** | Manage access (grant roles) | Stealth escalation |
| **Contributor** | Manage resources, **but not grant access** | Can run VM commands, read keys, delete — still dangerous |
| **Custom role w/ `Authorization/*/write`** | Assign roles | Hidden Owner-equivalent |
| **Storage Blob Data Owner/Contributor** | Read/write blob **data** | Data-plane access to storage |
| **Key Vault Administrator / Secrets User** | Read secrets | Credential access |

## The elevateAccess Bridge

The one escalation that crosses the two worlds:

> 🔴 A **Global Administrator** can call **`Microsoft.Authorization/elevateAccess`**, which grants them **User Access Administrator at the root scope (`/`)** — i.e. the ability to assign themselves **Owner over every subscription in the tenant.** This turns directory admin into infrastructure owner. It appears in the **Azure Activity Log** (`Microsoft.Authorization/elevateAccess/action`). **Always check for it** when a GA is compromised or a broad Azure takeover is suspected. See **Entra → Roles & PIM**.

## How to Identify RBAC Activity

- **Portal:** a resource/sub → **Access control (IAM)** → *Role assignments*.
- **CLI:** `az role assignment list --all`, `az role definition list`.
- **Activity Log:** `Microsoft.Authorization/roleAssignments/write`, `.../elevateAccess/action`.
- **KQL:** `AzureActivity | where OperationNameValue has "roleAssignments/write"`.

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Azure RBAC | IAM (per account) | Cloud IAM |
| Role assignment | Policy attachment | IAM binding |
| Owner | Administrator | Owner |
| User Access Administrator | IAM full access | Security Admin |
| Management-group scope | OU / Org | Folder / Org |
| PIM for Azure | IAM Identity Center + temp elevation | PAM |

## Common Use Cases

Your "normal" baseline:

- Least-privilege resource access by team/environment.
- Contributor for app teams, Reader for auditors.
- Managed identities granted narrow data-plane roles.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Role assignment** | A grant: principal + role + scope |
| **Role definition** | The set of allowed actions (built-in or custom) |
| **Scope** | Where the grant applies (mgmt group → resource) |
| **Owner** | Full control incl. granting access |
| **User Access Administrator** | Can grant roles |
| **Custom role** | An org-defined set of actions |
| **PIM for Azure resources** | JIT Azure role activation |
| **elevateAccess** | GA toggle → root-scope access |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating RBAC abuse | **Azure RBAC → for DFIR** |
| The control-plane log | **Azure → Activity Log** |
| The Entra-roles side | **Entra → Roles & PIM** |
| Who the principal is | **Microsoft → 01 Entra ID & Identities** |
| The layout (scopes) | **Microsoft → 00 Overview & Terminology** |

## Resources

- Azure RBAC overview — https://learn.microsoft.com/azure/role-based-access-control/overview
- Azure roles vs Entra roles — https://learn.microsoft.com/entra/identity/role-based-access-control/concept-understand-roles
- Elevate access — https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin
- Built-in roles — https://learn.microsoft.com/azure/role-based-access-control/built-in-roles
