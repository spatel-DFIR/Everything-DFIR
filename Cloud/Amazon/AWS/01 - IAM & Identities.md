# AWS IAM & Identities

Every AWS event answers one question first: **who did this?** But "who" in AWS is subtle — the same human can appear as five different identity types depending on how they authenticated.

This note is the **decoder ring for the `who`.** It teaches you to look at a CloudTrail `userIdentity` block and instantly say: *root, or a user, or a role someone assumed, or a service acting on its own.* Get this right and the rest of the investigation falls into place. Get it wrong and you chase the wrong principal.

## Contents

- [Why This Note Exists](#why-this-note-exists)
- [The Identity Types at a Glance](#the-identity-types-at-a-glance)
- [How You Authenticate to AWS](#how-you-authenticate-to-aws)
- [Users vs Roles — The Core Distinction](#users-vs-roles--the-core-distinction)
- [Long-Term vs Temporary Credentials](#long-term-vs-temporary-credentials)
- [Credentials & Keys — Every Type and How to Tell Them Apart](#credentials--keys--every-type-and-how-to-tell-them-apart)
- [Reading the userIdentity Block](#reading-the-useridentity-block)
- [The Six userIdentity Types Decoded](#the-six-useridentity-types-decoded)
- [Access Keys — AKIA vs ASIA](#access-keys--akia-vs-asia)
- [Following a Role Chain](#following-a-role-chain)
- [Federation and SSO Identities](#federation-and-sso-identities)
- [Permissions — How Access Is Actually Decided](#permissions--how-access-is-actually-decided)
- [Red Flags](#red-flags)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why This Note Exists

An attacker rarely stays one identity. A typical chain looks like:

```
leaked IAM user key (AKIA…)  →  AssumeRole  →  temporary session (ASIA…)  →  acts as an admin role
```

If you can't tell a **user** from an **assumed role** from a **service**, you can't follow that chain — and you can't answer "who is the human behind this?" This note makes that chain readable.

## The Identity Types at a Glance

| Identity type | What it is | Credential | Lives where | 🔴 In logs (`userIdentity.type`) |
|---------------|-----------|-----------|-------------|------------------------------|
| **Root user** | The account owner | Email + password (+ optional keys) | The account itself | `Root` |
| **IAM user** | A named long-lived identity for a human or app | Password (console) and/or access keys | IAM, per account | `IAMUser` |
| **IAM role** | A set of permissions **anyone trusted can assume** — no permanent creds | Assumed → temporary creds | IAM, per account | (seen as `AssumedRole` when used) |
| **Assumed-role session** | The **temporary** identity you get after assuming a role | Temporary STS creds (`ASIA…`) | STS-minted, time-limited | `AssumedRole` |
| **Federated user** | An external identity (SSO / SAML / OIDC) mapped to a role | Temporary creds | External IdP → STS | `AssumedRole` / `FederatedUser` / `WebIdentityUser` |
| **AWS service** | An AWS service acting on your behalf | Managed internally | AWS | `AWSService` |
| **Service-linked role** | A role AWS creates for a service to use | Assumed by the service | IAM | `AssumedRole` (with a service session) |

> The two you'll spend most time on: **`IAMUser`** (a long-term identity — often the *first* thing compromised via a leaked key) and **`AssumedRole`** (a temporary identity — what an attacker *pivots into*).

## How You Authenticate to AWS

Before the identity types make sense, understand the **doors** — the ways a human or a piece of code proves who it is to AWS. Every door produces a different credential and a different log signature. Start here:

| Method | Who uses it | What they present | How it looks in the log |
|--------|-------------|-------------------|-------------------------|
| **Console password (+MFA)** | A human, in the browser | Email/username + password, then an MFA code | `ConsoleLogin` event; `userIdentity.type` = `IAMUser` or `Root` |
| **Access key** | CLI / SDK / an app | An **access key ID + secret** that *signs* each request (SigV4). Nothing is "logged in" — every call is individually signed | `accessKeyId` starts **`AKIA`** (long-term) |
| **Assumed role (STS)** | Anyone the role trusts | Calls `AssumeRole` (using some *other* credential) → gets **temporary** creds | `AssumeRole` event, then `accessKeyId` **`ASIA`** + a session token |
| **Federation / SSO** | Enterprise users via an IdP | A SAML/OIDC assertion from Okta/Entra/etc. → STS mints a session | `AssumeRoleWithSAML` / `AssumeRoleWithWebIdentity`; `AWSReservedSSO_*` roles |
| **Instance/'workload' role (IMDS)** | Code running on EC2/Lambda/ECS | Nothing — the platform hands the workload temporary role creds via the metadata service | `AssumedRole`, session name = the instance ID; 🔴 stolen via SSRF |
| **Root credentials** | The account owner (should be almost never) | The root email + password (+MFA) | `userIdentity.type` = `Root` — near-silent normally |

Two things to lock in from this table, because they drive every AWS investigation:

- **AWS is request-signed, not session-based for programmatic access.** With an access key there is no "login" event — each API call is signed independently. So the *first* time you'll see a leaked key is when it *does something*, not when it "logs in."
- **Almost every door ultimately produces one of two credential shapes:** a **long-term access key (`AKIA`)** or a **temporary STS session (`ASIA` + session token)**. Master that one distinction (next two sections) and you can read any AWS credential.

## Users vs Roles — The Core Distinction

This is the concept people get wrong. Burn it in:

| | IAM **User** | IAM **Role** |
|-|--------------|--------------|
| **Has permanent credentials?** | ✅ Yes — password / access keys | ❌ No — nobody "logs in as" a role |
| **Who uses it?** | One specific human or app | **Anyone the role trusts** — a user, a service, another account, an SSO login |
| **How it's used** | Authenticate directly | **Assume** it → get temporary creds |
| **Best practice** | Minimize; prefer roles | The preferred way to grant access |
| **Analogy** | A named employee badge | A **hat anyone authorized can put on** — while wearing it they have its powers |

**A role has two policy sides — both matter to you:**

- **Trust policy** — *who is allowed to assume this role* (the "who can wear the hat"). 🔴 An over-broad trust policy (e.g. trusts `*` or an external account) is a privilege-escalation and cross-account-access path.
- **Permissions policy** — *what the role can do* once assumed.

> 🔴 When you investigate a role, always read its **trust policy**. "How did the attacker get to assume this admin role?" is answered there.

## Long-Term vs Temporary Credentials

The credential *type* tells you how the identity authenticated — and how you contain it.

| | Long-term credentials | Temporary credentials |
|-|----------------------|----------------------|
| **Belongs to** | IAM user (or root) | Assumed role / federated session |
| **Access key prefix** | **`AKIA…`** | **`ASIA…`** |
| **Expires?** | ❌ No — valid until deleted/rotated | ✅ Yes — 15 min to 36 hrs |
| **Includes a session token?** | No | ✅ Yes (`x-amz-security-token`) |
| **How you kill it** | Deactivate/delete the key | **Revoke the role's sessions** (deny by `aws:TokenIssueTime`); the key alone can't be "deleted" |
| **🔴 Risk** | Leaks and lives forever in code/git/laptops | Short-lived but minted *from* something — find the source |

> 🔴 **Containment differs.** Disabling an `AKIA` key stops that user. But if the attacker already ran `AssumeRole`, they hold an `ASIA` session that **keeps working until it expires** — you must *revoke the role sessions*, not just the key. See **STS** and **CloudTrail → Respond**.

## Credentials & Keys — Every Type and How to Tell Them Apart

AWS has more than just "the access key." On a case you need to recognize *every* credential type, tell it from the others at a glance, and know how to kill it. This is the full catalog — from basics to the ones people miss:

| Credential / key | What it is | How to spot it | Lifetime | Kill it by | ≈ Azure | ≈ GCP |
|------------------|-----------|----------------|----------|-----------|---------|-------|
| **Root email + password** | The account owner's login | `userIdentity.type = Root` | Until changed | Reset + MFA; lock away | Global Admin creds | Super Admin creds |
| **IAM user password** | A human's console login | `ConsoleLogin` by an `IAMUser` | Until changed | Reset / disable profile | Entra user password | Google user password |
| **Access key (ID + secret)** | Long-term programmatic key | `accessKeyId` = **`AKIA…`** | ♾ Never expires until deleted | Deactivate/delete the key | **SP client secret** | **SA key (JSON)** |
| **STS temporary credentials** | Short-term session (key + secret + **session token**) | `accessKeyId` = **`ASIA…`** + `x-amz-security-token` | 15 min–36 h | **Revoke role sessions** (deleting a key won't) | **OAuth access token** | **Short-lived SA token** |
| **MFA device / code** | Second factor | `mfaAuthenticated: true`; `AssumeRole` w/ `serialNumber` | Per session | Deregister the device | Entra MFA method | Google 2SV |
| **EC2 key pair (`.pem`)** | SSH/RDP key for the **guest OS** — *not* an AWS API credential | `CreateKeyPair`/`ImportKeyPair`; used at the OS, not in CloudTrail API auth | Until removed | Remove from `authorized_keys`; rotate | VM SSH key / password | OS Login / SSH key |
| **Pre-signed URL** | A time-limited URL with **signed credentials embedded** (usually for S3) | `X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Expires` in a URL | Minutes–hours (set at creation) | Expires; rotate the signing key | SAS token | Signed URL |
| **SSO / bearer token (Identity Center)** | The token behind a federated console/CLI session | `AWSReservedSSO_*` role; upstream IdP sign-in | Session length | Revoke SSO session + sessions | PRT / OAuth token | Workforce token |
| **Web-identity / SAML assertion** | An OIDC/SAML token exchanged for a role | `AssumeRoleWithWebIdentity` / `…WithSAML` | Exchanged immediately for STS creds | Fix trust policy; revoke sessions | Federated credential | WIF token |

> 🔴 **The one distinction that matters most — access key vs STS token.** Both are an ID + secret, but:
> - **`AKIA` = long-term access key.** Belongs to an **IAM user**. Never expires. No session token. Leaks in git and lives forever. *Its Azure twin is a **service-principal client secret**; its GCP twin is a **service-account key (JSON)**.*
> - **`ASIA` = temporary STS session.** Minted by `AssumeRole` (or federation/IMDS). Expires. **Always** carries a session token (`x-amz-security-token`). *Its Azure twin is an **OAuth access token**; its GCP twin is a **short-lived SA impersonation token**.*
>
> Tell them apart in one glance: **`AKIA` → no session token, permanent, contain by deleting the key. `ASIA` → has a session token, expires, contain by revoking the role's sessions.** Getting this wrong is the classic containment failure (see the callout above).

> **STS in one line for cross-cloud readers:** **STS** is AWS's *temporary-credential broker*. Its equivalent is **Azure's token endpoint / OAuth token service** and **GCP's `generateAccessToken` (SA impersonation)**. "An `ASIA` session" ≈ "an OAuth access token" ≈ "a short-lived SA token." See **Cloud → 06 Cloud Service Equivalents** for the full side-by-side.

## Reading the userIdentity Block

Every CloudTrail event carries a `userIdentity` block. Here's a real-ish one for an **IAM user** action:

```jsonc
"userIdentity": {
  "type": "IAMUser",
  "principalId": "AIDACKCEVSQ6C2EXAMPLE",
  "arn": "arn:aws:iam::123456789012:user/alice",
  "accountId": "123456789012",
  "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "userName": "alice"
}
```

And here's one for an **assumed role** — note the extra `sessionContext`:

```jsonc
"userIdentity": {
  "type": "AssumedRole",
  "principalId": "AROACKCEVSQ6C2EXAMPLE:i-0abc123",   // roleId : session-name
  "arn": "arn:aws:sts::123456789012:assumed-role/app-server/i-0abc123",
  "accountId": "123456789012",
  "accessKeyId": "ASIAY34FZKBOKMYEXAMPLE",             // ASIA = temporary
  "sessionContext": {
    "sessionIssuer": {                                  // 🔴 the ROLE that was assumed
      "type": "Role",
      "arn": "arn:aws:iam::123456789012:role/app-server",
      "userName": "app-server"
    },
    "attributes": {
      "creationDate": "2026-07-09T14:02:11Z",
      "mfaAuthenticated": "false"                       // 🔴 was MFA used?
    }
  }
}
```

**The fields that carry the investigation:**

| Field | Tells you | Watch for |
|-------|-----------|-----------|
| `type` | The identity category | 🔴 `Root` at all; `AssumedRole` you didn't expect |
| `arn` | The full identity name | The `assumed-role/<role>/<session>` shape |
| `principalId` | Stable ID (`AIDA…` user, `AROA…` role, `<roleId>:<session>`) | Ties a session back to a role |
| `accessKeyId` | The key used — `AKIA` (long) vs `ASIA` (temp) | 🔴 `ASIA` with no matching `AssumeRole` in your logs |
| `sessionContext.sessionIssuer.arn` | **Which role** was assumed | The privilege the attacker gained |
| `sessionContext.attributes.mfaAuthenticated` | Was MFA satisfied | 🔴 `false` on a sensitive role/action |
| `invokedBy` | An AWS service made the call | `*.amazonaws.com` = service-initiated, not human |

## The Six userIdentity Types Decoded

| `type` | Means | Typical `arn` | Notes for the analyst |
|--------|-------|---------------|-----------------------|
| **`Root`** | The account root user | `arn:aws:iam::123456789012:root` | 🔴 Almost always investigate. No `userName`. |
| **`IAMUser`** | A long-term IAM user | `…:user/alice` | Has `userName` + usually `accessKeyId` (`AKIA`). The classic leaked-key victim. |
| **`AssumedRole`** | Someone/something assumed a role | `…:assumed-role/<role>/<session>` | The `sessionIssuer` is the role; the session name is a big lead. |
| **`FederatedUser`** | A `GetFederationToken` session | `…:federated-user/<name>` | Rarer; a long-term user minted a federated session. |
| **`AWSService`** | An AWS service acting on its own | `ec2.amazonaws.com` (in `invokedBy`) | Normal automation — but confirm the action fits the service. |
| **`WebIdentityUser` / `SAMLUser`** | OIDC / SAML federation | varies | SSO logins, workload identity (e.g. GitHub Actions OIDC). |

> **`AWSServiceEvent` / `invokedBy`:** when you see `invokedBy: "ec2.amazonaws.com"` or a `sourceIPAddress` that is a service name (not an IP), the *service* did it, not a person. Legitimate — but attackers abuse trusted services too (e.g. a Lambda assuming a role), so still confirm the action makes sense.

## Access Keys — AKIA vs ASIA

The 20-character key ID's **prefix** is a fast tell:

| Prefix | Type | Meaning | On a case |
|--------|------|---------|-----------|
| **`AKIA`** | Long-term | IAM user access key | Never expires → 🔴 the leaked-in-git classic. Deactivate to contain. |
| **`ASIA`** | Temporary | STS session key | Expires; always paired with a session token. 🔴 An `ASIA` with **no matching `AssumeRole` you can find** means the session was minted outside your logging window/region — widen the search. |
| **`AIDA`** | (not a key) | The `principalId` of a **user** | Appears in `principalId`, not `accessKeyId` |
| **`AROA`** | (not a key) | The `principalId` of a **role** | Ties sessions back to their role |
| **`ASCA` / `ANPA` / others** | Various | Other resource principal IDs | Reference only |

> 🔴 **The pivot in one line:** a leaked **`AKIA`** key runs `AssumeRole`, producing an **`ASIA`** session, which then acts as a role. Tie the `ASIA` session back to the `AKIA` user via the `AssumeRole` event's `sourceIdentity` / `accessKeyId`.

## Following a Role Chain

Roles can be assumed *by* roles — "role chaining." Reconstruct it in order:

| Step | What you look for | Field |
|------|-------------------|-------|
| 1 | The original identity (user/key/SSO) | `userIdentity` on the first event |
| 2 | The `AssumeRole` call itself | `eventName = AssumeRole`, `requestParameters.roleArn` |
| 3 | The session it minted | `responseElements.credentials.accessKeyId` (an `ASIA`) |
| 4 | What the session did next | Filter later events by that `ASIA` / session ARN |
| 5 | Any *further* `AssumeRole` from that session | Repeat — chains can be several hops |

> **`sourceIdentity`** — if your org sets it on `AssumeRole`, it **propagates through the whole chain** and survives every hop. It is the single best field for tying a temporary session all the way back to the human. Recommend enabling it (see Harden guidance in **STS**).

## Federation and SSO Identities

Most enterprises don't create IAM users per person — they **federate** an external identity provider (IdP). Know the shapes:

| Mechanism | What it is | How it appears |
|-----------|-----------|----------------|
| **IAM Identity Center (SSO)** | AWS's own SSO, front-ends an IdP (Okta/Entra/etc.) | `AssumedRole` into a *permission-set* role; look for `AWSReservedSSO_…` role names |
| **SAML federation** | Enterprise IdP → `AssumeRoleWithSAML` | `type: SAMLUser` / `AssumedRole`; `AssumeRoleWithSAML` events |
| **OIDC / Web identity** | OIDC IdP → `AssumeRoleWithWebIdentity` | `type: WebIdentityUser`; used by workloads (e.g. **GitHub Actions**, **EKS IRSA**) |
| **Cognito** | Customer/app-user identities | Identity-pool roles; see **Cognito** note |

> 🔴 **`AWSReservedSSO_<permission-set>_<hash>`** role names mean the actor came in through IAM Identity Center. To find the *human*, pivot to the **Identity Center sign-in logs** and the upstream IdP — CloudTrail alone stops at the permission-set role. See **IAM Identity Center**.
>
> 🔴 **OIDC trust abuse:** an over-permissive `AssumeRoleWithWebIdentity` trust policy (e.g. a GitHub OIDC condition that isn't scoped to your repo) lets *anyone's* pipeline assume your role. This is a real, current attack path.

## Permissions — How Access Is Actually Decided

You don't need to be a policy author, but you must understand *why an action succeeded or was denied* — it tells you what the attacker could reach.

**Policy types, in the order they constrain access:**

| Policy type | Attaches to | Effect |
|-------------|-------------|--------|
| **Identity-based policy** | A user / group / role | Grants (or denies) what that identity can do |
| **Resource-based policy** | A resource (S3 bucket, KMS key, role trust) | Grants access *to the resource*, incl. cross-account |
| **Permissions boundary** | A user / role | A *ceiling* — max permissions regardless of grants |
| **Service Control Policy (SCP)** | An OU / account | An org-wide *ceiling* — can block even admins |
| **Session policy** | Passed at `AssumeRole` time | Further narrows a single session |

**The one rule that matters on a case:** access is denied by default; an **explicit `Deny` anywhere always wins**; otherwise an `Allow` must exist *and* survive every boundary/SCP.

> 🔴 Watch for attackers who **widen** permissions: `AttachUserPolicy`/`PutUserPolicy` adding `AdministratorAccess`, `CreatePolicyVersion` quietly rewriting a policy, `DeleteUserPermissionsBoundary` removing a ceiling, or `PutRolePolicy` editing a trust policy to add themselves. A **burst of `AccessDenied` then a sudden success** is privilege escalation in progress.

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `userIdentity.type = Root` doing anything | Root should be silent; near-certain incident or policy break |
| `CreateAccessKey` / `CreateLoginProfile` on an identity that shouldn't need it | Persistence — attacker minting their own creds |
| `AttachUserPolicy` / `PutUserPolicy` adding admin | Privilege escalation |
| `CreatePolicyVersion` / `SetDefaultPolicyVersion` | Quiet policy rewrite — read the new version |
| `UpdateAssumeRolePolicy` / `PutRolePolicy` on a trust policy | Attacker adding themselves as a trusted principal |
| `AssumedRole` with `mfaAuthenticated: false` on a sensitive role | MFA bypassed or not required |
| `ASIA…` session activity with no `AssumeRole` you can find | Session minted outside your logging scope — widen window/region |
| `AssumeRoleWithWebIdentity` from an unexpected OIDC subject | Over-broad trust policy abused (e.g. foreign CI) |
| New `AWSReservedSSO_…` activity from a new IP/geo | SSO account compromise — check the IdP |
| Access keys older than your rotation policy | Standing risk; `AKIA` never expires |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| IAM user | Entra ID user | Google user |
| IAM role (assumed) | Managed identity / service principal | Service account (impersonated) |
| Assumed-role session (`ASIA`) | OAuth access token | Short-lived SA token |
| STS `AssumeRole` | Token request / OBO flow | `generateAccessToken` / impersonation |
| IAM Identity Center | Entra ID SSO | Cloud Identity / Workforce Identity |
| Trust policy | Federated credentials / RBAC assignment | IAM policy binding + workload-identity pool |
| SCP | Azure Policy | Organization Policy |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| How accounts/Orgs/regions/ARNs fit together | **AWS → 00 Overview & Terminology** |
| Where these identities show up in the audit log | **AWS → Logging & Monitoring → CloudTrail** |
| The service that mints temporary sessions | **AWS → Identity & Access → STS** |
| Managing the users/roles/policies themselves | **AWS → Identity & Access → IAM** |
| SSO / permission-set logins | **AWS → Identity & Access → IAM Identity Center** |
| A full leaked-key → role-assumption intrusion | **AWS → Playbooks → Leaked Access Key** |
| Same human pivoting across clouds | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- IAM identities (users, groups, roles) — https://docs.aws.amazon.com/IAM/latest/UserGuide/id.html
- CloudTrail `userIdentity` element — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
- IAM unique identifiers (AIDA/AROA/AKIA/ASIA prefixes) — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
- Temporary security credentials (STS) — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html
- Policy evaluation logic — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- Roles terms and concepts — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html
