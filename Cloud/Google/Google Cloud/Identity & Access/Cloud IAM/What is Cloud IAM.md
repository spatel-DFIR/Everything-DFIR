# What is Cloud IAM?

**Cloud IAM (Identity and Access Management)** decides **who can do what on which GCP resource.** It binds **members** (users, groups, service accounts, federated identities) to **roles** (bundles of permissions) on a **resource** (org, folder, project, or single resource), and those bindings **inherit down** the hierarchy.

Almost every GCP attack ends in IAM: the attacker wants a durable identity, more permissions, or a service account to impersonate. This note is the model; **Cloud IAM for DFIR** is the hunt.

## Contents

- [How It Works](#how-it-works)
- [The Building Blocks](#the-building-blocks)
- [Roles — Basic, Predefined, Custom](#roles--basic-predefined-custom)
- [Allow Policies, Deny Policies, Conditions](#allow-policies-deny-policies-conditions)
- [Inheritance — Why Scope Matters](#inheritance--why-scope-matters)
- [The Privilege-Escalation Permissions](#the-privilege-escalation-permissions)
- [How to Identify IAM in Evidence](#how-to-identify-iam-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Request → Authenticate (who?) → Authorize: does an ALLOW binding grant the needed
          permission on this resource (or an ancestor), and no DENY policy block it?
```

- IAM is **additive**: a principal's effective access is the **union** of all bindings that apply — including those **inherited** from parent folders/org.
- There is **no AWS-style default explicit-deny**; **IAM Deny policies** exist but are a separate, less-common construct.
- Every policy change is a **`SetIamPolicy`** in the Admin Activity audit log.

## The Building Blocks

| Block | What it is | 🔴 Attacker interest |
|-------|-----------|---------------------|
| **Member / principal** | A user, group, **service account**, or federated identity | Add themselves / an external account |
| **Role** | A bundle of permissions (Basic/Predefined/Custom) | Grant themselves a broad role |
| **Binding** | `member → role` **on a resource** | Add a binding = grant access |
| **Allow policy** | The set of bindings on a resource | Edited via `SetIamPolicy` |
| **Deny policy** | Explicit denials (separate) | Remove a deny to unblock |
| **Service account** | A workload identity (see 01) | Impersonate / mint a key |

## Roles — Basic, Predefined, Custom

| Type | Examples | 🔴 Note |
|------|----------|---------|
| **Basic** | **Owner**, **Editor**, **Viewer** | 🔴 Dangerously broad; **Editor** is the default SA role and can modify almost everything |
| **Predefined** | `roles/storage.admin`, `roles/compute.admin`, `roles/iam.securityAdmin` | Service-scoped; still powerful ones |
| **Custom** | Org/project-defined | 🔴 `iam.roles.update` lets an attacker widen a custom role quietly |

> 🔴 **Owner** on a project lets a principal do anything in it *and* grant others access. **Owner/Editor** grants are the ones to scrutinize first.

## Allow Policies, Deny Policies, Conditions

- **Allow policy** — the bindings that grant access (the common one).
- **Deny policy** — explicit denials that override allows (evaluated first); rarer.
- **IAM Conditions** — attribute constraints on a binding (time, resource, IP). 🔴 A too-loose or removed condition can silently broaden access.

## Inheritance — Why Scope Matters

```
Organization   ─ binding here inherits to EVERYTHING
└── Folder      ─ inherits to all projects under it
    └── Project ─ inherits to all resources in it
        └── Resource ─ binding here is narrowest
```

> 🔴 The **scope** of a grant is everything. `roles/owner` at the **organization** node = owns all infrastructure. Always check *at what level* a `SetIamPolicy` was made — a project-level Owner is bad; an org-level Owner is catastrophic.

## The Privilege-Escalation Permissions

🔴 GCP has well-known privesc primitives — watch for a principal **granting itself** or **using** these:

| Permission / role | The escalation |
|-------------------|----------------|
| `iam.serviceAccountKeys.create` | Mint a long-lived key for a more-privileged SA |
| `iam.serviceAccounts.getAccessToken` (TokenCreator) | Impersonate a more-privileged SA |
| `iam.serviceAccounts.actAs` + a deploy service | Attach a privileged SA to a VM/Function/Cloud Run you control |
| `iam.roles.update` | Add permissions to a custom role you hold |
| `resourcemanager.projects.setIamPolicy` | Grant yourself Owner |
| `resourcemanager.organizations.setIamPolicy` → `organizationAdmin` | 🔴 Own the whole org (the Super-Admin→GCP pivot) |
| `cloudfunctions.functions.create` + `actAs` | Run code as a privileged SA |

> These map to the **privilege-escalation playbook** and the classic public GCP privesc research. See **GCP → Playbooks → IAM Privilege Escalation**.

## How to Identify IAM in Evidence

- **`SetIamPolicy`** in Admin Activity = a binding changed (read `request.policy.bindings`).
- **Members** are emails; **roles** are `roles/...`; **resources** are the org/folder/project/resource path.
- **Analysis tools:** Policy Analyzer ("who can access what"), Policy Troubleshooter ("why did this allow/deny"), Recommender (over-grants).

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Cloud IAM | IAM | Azure RBAC |
| Member/principal | Principal | Security principal |
| Role (predefined/custom) | Managed/inline policy | Role definition |
| Binding | Policy attachment | Role assignment |
| Basic role Owner/Editor | `AdministratorAccess` | Owner/Contributor |
| `SetIamPolicy` | `AttachRolePolicy` / trust edit | `roleAssignments/write` |
| Org-level Owner | Org management account | Owner at management-group root |
| IAM Conditions | IAM policy conditions | Azure ABAC conditions |

## Common Use Cases

Your "normal": humans access via **groups + predefined roles**; workloads use **service accounts** with scoped roles; deploys via CI service accounts. 🔴 A mature org avoids **Basic roles** and **user-managed keys**. So a *new* Owner grant, a *new* SA key, or an *external* member is unusual by itself.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Member/principal** | Who a binding grants to |
| **Role** | A bundle of permissions |
| **Binding** | member → role on a resource |
| **Allow/Deny policy** | Grants / explicit denials |
| **IAM Condition** | Attribute constraint on a binding |
| **Basic role** | Owner/Editor/Viewer (broad) |
| **Inheritance** | Grants flow down the hierarchy |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating IAM abuse in a case | **Cloud IAM → for DFIR** |
| Who the principals are | **Google → 01 Google Identities** |
| Service accounts, keys, impersonation | **GCP → Service Accounts** |
| Federated external identities | **GCP → Workload Identity Federation** |
| Org-wide guardrails | **GCP → Organization Policy** |
| Privilege escalation end to end | **GCP → Playbooks → IAM Privilege Escalation** |

## Resources

- IAM overview — https://cloud.google.com/iam/docs/overview
- Roles & permissions — https://cloud.google.com/iam/docs/roles-overview
- IAM Deny / Conditions — https://cloud.google.com/iam/docs/deny-overview
- Policy Analyzer / Troubleshooter — https://cloud.google.com/policy-intelligence/docs
- Understanding IAM privilege escalation (research) — https://cloud.google.com/iam/docs/best-practices-service-accounts
