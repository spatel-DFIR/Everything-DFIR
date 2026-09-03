# What is Workload Identity Federation?

**Workload Identity Federation (WIF)** lets an **external identity** — a workload in AWS or Azure, a GitHub Actions pipeline, or any OIDC/SAML provider — **impersonate a GCP service account without a downloaded key.** It's the keyless, modern way to give outside workloads GCP access. It's also the GCP twin of AWS OIDC trust abuse: a **loose trust condition** lets the *wrong* external identity in.

## Contents

- [How It Works](#how-it-works)
- [The Pieces](#the-pieces)
- [Where Abuse Happens — Attribute Conditions](#where-abuse-happens--attribute-conditions)
- [How to Identify WIF in Evidence](#how-to-identify-wif-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
External workload (GitHub Actions / AWS / Azure / OIDC)
   → presents its own token to Google STS (sts.googleapis.com)
   → token exchanged (if attribute conditions pass) for a federated identity
   → federated identity impersonates a GCP service account (roles/iam.workloadIdentityUser)
   → acts in GCP as that SA — no key ever downloaded
```

## The Pieces

| Piece | What it is |
|-------|-----------|
| **Workload Identity Pool** | A container for external identities |
| **Pool Provider** | Defines the trusted external IdP (OIDC/AWS/SAML) + **attribute mapping** + **attribute conditions** |
| **Attribute mapping** | Maps external token claims → Google attributes (`google.subject`, `attribute.repository`…) |
| **Attribute condition** | 🔴 The trust gate — which external identities may exchange |
| **`workloadIdentityUser`** | The role letting the federated identity impersonate a specific SA |

## Where Abuse Happens — Attribute Conditions

🔴 The security of WIF is the **attribute condition**. If it's missing or too broad, the wrong external identity can impersonate your SA:

| Weak setup | Consequence |
|-----------|-------------|
| GitHub provider with **no `repository`/`repository_owner` condition** | *Any* GitHub repo's Actions can impersonate the SA (the classic OIDC-trust-abuse) |
| AWS provider trusting a whole account, not a role | Any principal in that AWS account can exchange |
| Overly broad `google.subject` mapping | Many external subjects map in |

> 🔴 This is the exact GCP analog of an over-permissive AWS `AssumeRoleWithWebIdentity` trust policy. Audit every pool provider's condition; scope it to the specific repo/branch/role.

## How to Identify WIF in Evidence

- **In audit logs:** the caller shows a **`principalSubject`** like `principal://iam.googleapis.com/projects/<n>/locations/global/workloadIdentityPools/<pool>/subject/<subject>`.
- **STS exchange:** `sts.googleapis.com` token-exchange events.
- **Config:** `gcloud iam workload-identity-pools list` / `... providers describe` (read the attribute condition).

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Workload Identity Federation | `AssumeRoleWithWebIdentity` (OIDC) | Federated credentials (workload identity) |
| Pool provider condition | OIDC trust policy `sub`/`aud` conditions | Federated credential subject/audience |
| `workloadIdentityUser` on SA | Role trust policy | App federated credential |
| STS token exchange | STS AssumeRole | Token request |

## Common Use Cases

Your "normal": **GitHub Actions** deploying to GCP keylessly; **multi-cloud** workloads in AWS/Azure calling GCP; on-prem OIDC workloads. The job is to confirm each provider's condition is tightly scoped.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Workload Identity Pool** | Container for external identities |
| **Pool Provider** | The trusted external IdP config |
| **Attribute mapping** | External claims → Google attributes |
| **Attribute condition** | The trust gate |
| **STS token exchange** | The exchange of external token for a federated one |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating WIF abuse | **Workload Identity Federation → for DFIR** |
| The SA being impersonated | **GCP → Service Accounts** |
| The identity decoder | **Google → 01 Google Identities** |
| CI/CD trust in general | **GCP → Cloud IAM** |

## Resources

- Workload Identity Federation — https://cloud.google.com/iam/docs/workload-identity-federation
- Attribute mappings & conditions — https://cloud.google.com/iam/docs/workload-identity-federation#mapping
- Configure with GitHub Actions — https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines
