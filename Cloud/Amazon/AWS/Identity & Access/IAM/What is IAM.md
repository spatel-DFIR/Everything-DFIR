# What is IAM?

**IAM (Identity and Access Management)** is the service that holds every **user, group, role, and policy** in an AWS account — and decides whether any given API call is allowed.

If CloudTrail is the CCTV, **IAM is the lock system.** Almost every AWS attack ends in IAM: the attacker wants a durable identity, more permissions, or a role to assume. This note teaches you what the pieces are so **IAM for DFIR** can teach you to investigate them.

## Contents

- [How It Works](#how-it-works)
- [The Building Blocks](#the-building-blocks)
- [Policies — Where Permissions Actually Live](#policies--where-permissions-actually-live)
- [The IAM Artifacts You'll Collect](#the-iam-artifacts-youll-collect)
- [How to Identify IAM in Evidence](#how-to-identify-iam-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Every API call to AWS is **authenticated** (who are you?) then **authorized** (are you allowed?). IAM owns the authorization decision.

```
Request  →  Authenticate (creds valid?)  →  Authorize (policies allow?)  →  Allow / Deny
                                              │
                                              └─ evaluates: identity policy + resource policy
                                                 + permissions boundary + SCP + session policy
```

IAM is **global** (not regional) and **free**. Its events log to **`us-east-1`**. There is one IAM per account — it does *not* span accounts (that's what roles + trust policies are for).

## The Building Blocks

| Block | What it is | Has credentials? | 🔴 Attacker interest |
|-------|-----------|------------------|---------------------|
| **User** | A named long-term identity (human or app) | ✅ password and/or access keys | Create a backdoor user; add keys to an existing one |
| **Group** | A bucket of users sharing policies | ❌ | Add themselves to an admin group |
| **Role** | Permissions **assumable** by trusted principals — no standing creds | ❌ (assumed → temp creds) | Assume it; or edit its **trust policy** to allow themselves |
| **Policy** | The JSON that grants/denies actions | ❌ | Attach admin; rewrite a policy version |
| **Instance profile** | A wrapper that hands a role to an EC2 instance | ❌ | The thing IMDS theft steals from |
| **Identity provider** | A SAML/OIDC federation config | ❌ | Add a rogue IdP → federate in as anyone |

> Deep identity-type detail (user vs role vs assumed-role vs federated, and how each reads in a log) is in **01 - IAM & Identities**. This note is about IAM *as a service* you investigate.

## Policies — Where Permissions Actually Live

A policy is JSON. You'll read many; learn the five fields:

```jsonc
{
  "Effect": "Allow",                       // Allow or Deny (Deny always wins)
  "Action": ["s3:GetObject", "s3:PutObject"],  // which API calls
  "Resource": "arn:aws:s3:::crown-jewels/*",   // on which resources
  "Condition": { "IpAddress": { "aws:SourceIp": "10.0.0.0/8" } },  // optional guardrails
  "Principal": { "AWS": "arn:aws:iam::999…:root" }  // (resource/trust policies only) WHO
}
```

**Policy families** — where a policy is attached changes what it does:

| Family | Attaches to | Purpose |
|--------|-------------|---------|
| **Managed policy** (AWS or customer) | Many identities | Reusable grants; `AdministratorAccess` is the famous AWS-managed one |
| **Inline policy** | One user/role/group | A one-off grant embedded in the identity — 🔴 easy to hide a backdoor here |
| **Resource-based policy** | A resource (bucket, role trust, KMS key) | Grants *to* the resource, incl. **cross-account** |
| **Permissions boundary** | A user/role | A **ceiling** — can't exceed it no matter the grants |
| **SCP** | An OU/account | An **org-wide ceiling** (see 00 Overview) |

> 🔴 **Policy versions.** A managed policy keeps up to 5 versions; only one is *default*. `CreatePolicyVersion` + `SetDefaultPolicyVersion` lets an attacker **swap in a permissive version and swap back later** — the current version can look innocent while the abuse happened under a different one. Always list versions, not just the current.

## The IAM Artifacts You'll Collect

IAM produces static, snapshot-style evidence you pull directly — not just CloudTrail events:

| Artifact | What it tells you | How to get it |
|----------|-------------------|---------------|
| **Credential report** | CSV of every user: key age, last used, MFA, password age | `aws iam generate-credential-report` → `get-credential-report` |
| **Access key last-used** | When/where/what service a key last called | `aws iam get-access-key-last-used` |
| **Access Advisor** | Services an identity actually used (vs is allowed) | `aws iam generate-service-last-accessed-details` |
| **Account authorization details** | Full dump: all users/roles/policies/attachments | `aws iam get-account-authorization-details` |
| **Account summary** | Counts + settings (MFA on root? key rotation?) | `aws iam get-account-summary` |

> The **credential report** is the single best first pull in an IAM case — one CSV shows every credential's age, last use, and MFA status, so backdoor keys and dormant-turned-active users jump out. See **IAM for DFIR**.

## How to Identify IAM in Evidence

**ARNs (note the blank region — IAM is global):**

| Thing | ARN shape |
|-------|-----------|
| User | `arn:aws:iam::123456789012:user/alice` |
| Group | `arn:aws:iam::123456789012:group/admins` |
| Role | `arn:aws:iam::123456789012:role/deploy` |
| Managed policy | `arn:aws:iam::123456789012:policy/my-policy` |
| AWS-managed policy | `arn:aws:iam::aws:policy/AdministratorAccess` |
| Instance profile | `arn:aws:iam::123456789012:instance-profile/web` |
| Identity provider (SAML) | `arn:aws:iam::123456789012:saml-provider/Okta` |

**Principal-ID prefixes** (in `userIdentity.principalId`): `AIDA`=user, `AROA`=role, `AKIA`=long-term key, `ASIA`=temp key. See **01 - IAM & Identities**.

**`eventSource`:** `iam.amazonaws.com` (and `sts.amazonaws.com` for the STS side).

## Common Operations You Will See

The IAM API actions you audit. 🔴 marks the ones that create identities, grant power, or open trust — the attacker's toolkit.

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateUser` / `DeleteUser` | Add/remove a user | 🔴 backdoor identity |
| `CreateAccessKey` | Mint a new access key for a user | 🔴 persistence (esp. on *another* user) |
| `CreateLoginProfile` / `UpdateLoginProfile` | Set/change a console password | 🔴 gives a service user interactive login |
| `AttachUserPolicy` / `AttachRolePolicy` | Attach a managed policy | 🔴 esp. `AdministratorAccess` |
| `PutUserPolicy` / `PutRolePolicy` | Add an **inline** policy | 🔴 hidden backdoor grant |
| `CreatePolicyVersion` / `SetDefaultPolicyVersion` | Change what a managed policy allows | 🔴 quiet privilege change |
| `AddUserToGroup` | Put a user in a (possibly admin) group | 🔴 privesc |
| `CreateRole` / `UpdateAssumeRolePolicy` | Create a role / change **who can assume it** | 🔴 trust-policy backdoor |
| `PassRole` | Hand a role to a service (EC2/Lambda) | 🔴 privesc primitive when paired with compute |
| `CreateSAMLProvider` / `CreateOpenIDConnectProvider` | Add a federation IdP | 🔴 rogue IdP = "log in as anyone" |
| `DeleteUserPermissionsBoundary` | Remove a permissions ceiling | 🔴 uncaps an identity |
| `CreateVirtualMFADevice` / `DeactivateMFADevice` | Change MFA | 🔴 removing MFA to persist |
| `ListUsers` / `GetAccountAuthorizationDetails` | Enumerate identities | Recon (normal for tools too) |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| IAM (per account) | Entra ID + Azure RBAC | Cloud IAM |
| User | Entra user | Google user |
| Group | Entra group | Google group |
| Role (assumable) | Service principal / managed identity | Service account |
| Managed/inline policy | Role assignment / custom role | IAM policy binding / custom role |
| Permissions boundary | — (closest: Azure Policy) | — |
| Identity provider (SAML/OIDC) | External IdP federation | Workforce/Workload Identity Federation |
| Credential report | Entra sign-in/credential reports | IAM policy analyzer / recommender |

## Common Use Cases

Why orgs use IAM (your "normal" baseline):

- **Human access** — usually via **roles + SSO**, not standing users.
- **Workload access** — EC2/Lambda/ECS assume roles via instance profiles / execution roles.
- **Cross-account access** — one account's role trusts another account.
- **CI/CD** — pipelines federate via OIDC (e.g. GitHub Actions) to assume deploy roles.
- **Break-glass** — a tightly-watched emergency admin path.

> 🔴 A mature org has **few or zero IAM users** (SSO instead) and **no long-term keys**. So a *new* IAM user or a *new* `AKIA` key is unusual by itself — a strong signal.

## Key Terminology

| Term | Meaning |
|------|---------|
| **User** | Long-term named identity |
| **Group** | Collection of users sharing policies |
| **Role** | Assumable permission set, no standing creds |
| **Trust policy** | Who is allowed to assume a role |
| **Permissions policy** | What an identity/role can do |
| **Managed policy** | Reusable policy (AWS- or customer-managed) |
| **Inline policy** | Policy embedded in one identity |
| **Permissions boundary** | Ceiling on an identity's max permissions |
| **Instance profile** | Wrapper delivering a role to EC2 |
| **Access key** | `AKIA…` long-term credential pair |
| **Credential report** | CSV of all users' credential status |
| **Access Advisor** | Report of services an identity actually used |
| **PassRole** | Granting a service the right to use a role |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating IAM abuse in a case | **IAM → IAM for DFIR** |
| Reading identity types in any log | **AWS → 01 IAM & Identities** |
| The temporary-session side (AssumeRole) | **AWS → Identity & Access → STS** |
| SSO / permission sets | **AWS → Identity & Access → IAM Identity Center** |
| Org-wide guardrails (SCPs) | **AWS → Identity & Access → Organizations** |
| The audit trail of all IAM actions | **AWS → Logging & Monitoring → CloudTrail** |

## Resources

- IAM identities — https://docs.aws.amazon.com/IAM/latest/UserGuide/id.html
- Policies and permissions — https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
- Getting credential reports — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
- Policy versioning — https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html
- IAM security best practices — https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
