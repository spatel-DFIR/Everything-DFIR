# What is a Service Account?

A **service account (SA)** is a **non-human identity** for a workload — an app, a VM, a function, a pipeline. It has an email (`…@<project>.iam.gserviceaccount.com`), it holds IAM roles, and it authenticates **without a person or MFA**. SAs are the identities attackers most want: they blend into automation, a **user-managed key never expires**, and a default SA is often over-privileged.

This is the service-level companion to **01 - Google Identities** (which is the cross-cutting decoder). Here we go deep on **keys vs impersonation vs attachment** and how to hunt them.

## Contents

- [How It Works](#how-it-works)
- [The Three Ways an SA Is Used](#the-three-ways-an-sa-is-used)
- [Keys — User-Managed vs Google-Managed](#keys--user-managed-vs-google-managed)
- [Impersonation and actAs](#impersonation-and-actas)
- [Default Service Accounts](#default-service-accounts)
- [Domain-Wide Delegation](#domain-wide-delegation)
- [How to Identify SA Use in Evidence](#how-to-identify-sa-use-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

An SA is created in a project (`gcloud iam service-accounts create`). It gets IAM roles (what it can do) and can be **used** by workloads three ways — each leaves a different trace and needs a different containment.

```
Service account (identity + roles)
├── Attached to a resource (VM/Function/Run)  → workload gets tokens via metadata, no key
├── Impersonated (generateAccessToken/signJwt) → caller gets a short-lived token
└── Authenticated with a downloaded KEY (JSON) → whoever holds the key IS the SA  🔴
```

## The Three Ways an SA Is Used

| Method | How | Trace | Contain by |
|--------|-----|-------|-----------|
| **Attachment** (`actAs`) | SA attached to a VM/Function/Run; workload reads tokens from the metadata server | Actions from the resource's SA | Fix the resource; rotate SA |
| **Impersonation** | A principal with **TokenCreator** calls `generateAccessToken` | `serviceAccountDelegationInfo` in the log | Remove the TokenCreator binding |
| **Key** | A downloaded **JSON key** signs for tokens | `serviceAccountKeyName` in the log | **Delete the key** |

## Keys — User-Managed vs Google-Managed

| Key type | Who controls | Lifetime | 🔴 Risk |
|----------|--------------|----------|---------|
| **User-managed** | You (download a JSON file) | 🔴 **Never expires** until deleted | The leaked-in-git classic; standing skeleton key |
| **Google-managed** | Google (used for impersonation/attachment) | Auto-rotated | Low — you never hold it |

> 🔴 **User-managed keys are the biggest SA risk.** Best practice is **no downloaded keys** — use attachment, impersonation, or Workload Identity Federation. So a **`CreateServiceAccountKey`** event, especially on a privileged SA, is a top persistence red flag. An SA can have up to 10 keys — an attacker adds *one more* and blends in.

## Impersonation and actAs

- **Impersonation** (`roles/iam.serviceAccountTokenCreator`): a principal mints a **short-lived token** for the SA (`generateAccessToken`, `signJwt`, `signBlob`, `getOpenIdToken`). This is the ASIA-analog — short-lived, but re-mintable while the grant stands.
- **actAs** (`roles/iam.serviceAccountUser`): the right to **attach** an SA to a new resource (deploy a VM/Function that *runs as* the SA). 🔴 `actAs` + a compute-deploy permission = run code as a privileged SA.

> 🔴 Containment differs: deleting a key stops key-based use, but if the attacker had **TokenCreator**, they can keep minting tokens until you **remove that binding**. See **01 - Google Identities → SA Keys vs Impersonation**.

## Default Service Accounts

| Default SA | Email | 🔴 |
|-----------|-------|----|
| **Compute Engine default** | `<project-number>-compute@developer.gserviceaccount.com` | Historically **Editor** on the project + attached to every VM = huge blast radius via metadata theft |
| **App Engine / Cloud Functions default** | `<project-id>@appspot.gserviceaccount.com` | Similar over-privilege |

> 🔴 The Compute default SA is the most-abused GCP identity. If a VM is compromised and runs as it, the attacker gets **project-wide Editor** via the metadata server. Disable default-SA auto-grants; attach a **least-privilege** SA instead. See **GCP → Compute Engine**.

## Domain-Wide Delegation

An SA can be authorized (in the **Workspace Admin console**) to **impersonate Workspace users** for OAuth scopes — reading any user's Gmail/Drive. 🔴 A GCP SA holding a **Workspace-wide** key. Enumerate SAs with DWD as standing risk. See **01** and **Workspace → OAuth & Third-Party Apps**.

## How to Identify SA Use in Evidence

- **In audit logs:** `principalEmail` ends `…iam.gserviceaccount.com`; `serviceAccountKeyName` (key used) or `serviceAccountDelegationInfo` (impersonation).
- **Enumerate SAs + keys:** `gcloud iam service-accounts list`; `... keys list --iam-account=<sa>`.
- **Who can impersonate an SA:** the SA's IAM policy — members with `TokenCreator`/`serviceAccountUser`.

## Common Operations You Will See

| methodName | What it does | 🔴 |
|-----------|--------------|----|
| `CreateServiceAccount` | New SA | Backdoor identity |
| `CreateServiceAccountKey` | Mint a JSON key | Persistence |
| `GenerateAccessToken` / `SignJwt` | Impersonate the SA | Lateral movement |
| `SetIAMPolicy` on an SA (add TokenCreator/actAs) | Grant impersonation | Privesc setup |
| `EnableServiceAccount` / `DisableServiceAccount` | Toggle SA | Evasion / re-enable |
| `AUTHORIZE_API_CLIENT_ACCESS` (Workspace admin log) | Grant DWD | Workspace bridge |

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Service account | IAM role (assumed by workloads) | Service principal / managed identity |
| User-managed key | Access key (`AKIA`) | Client secret |
| Impersonation token | STS session (`ASIA`) | OAuth access token |
| `actAs` / attachment | PassRole / instance profile | Managed identity assignment |
| Default Compute SA | EC2 default instance role | VM managed identity |
| Domain-wide delegation | (no direct equal) | App-only Graph perms |

## Key Terminology

| Term | Meaning |
|------|---------|
| **Service account** | A workload identity |
| **User-managed key** | A downloaded JSON key (long-lived) |
| **Impersonation** | Minting a short-lived token for an SA |
| **TokenCreator** | The role that allows impersonation |
| **actAs / serviceAccountUser** | The right to attach an SA to a resource |
| **Default SA** | Auto-created Compute/App Engine SA |
| **DWD** | Domain-wide delegation into Workspace |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating SA abuse in a case | **Service Accounts → for DFIR** |
| The identity decoder (keys/impersonation/tokens) | **Google → 01 Google Identities** |
| IAM roles + privesc | **GCP → Cloud IAM** |
| Keyless federation | **GCP → Workload Identity Federation** |
| Metadata token theft | **GCP → Compute Engine** · **Playbooks → Metadata SSRF to SA Token Theft** |
| Key-abuse intrusion | **GCP → Playbooks → Service Account Key Abuse** |

## Resources

- Service accounts overview — https://cloud.google.com/iam/docs/service-account-overview
- Keys create/delete — https://cloud.google.com/iam/docs/keys-create-delete
- Short-lived credentials / impersonation — https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- Best practices for SAs — https://cloud.google.com/iam/docs/best-practices-service-accounts
- Domain-wide delegation — https://support.google.com/a/answer/162106
