# What is IAM Identity Center?

**IAM Identity Center** (formerly **AWS SSO**) is how most enterprises give humans access to AWS. Instead of an IAM user per person per account, people **sign in once** through a company identity provider (Okta, Entra ID, Google, or the built-in directory) and get a menu of accounts and roles.

For an investigator, one fact dominates: **CloudTrail sees the *permission-set role*, not the person.** To find the human, you follow Identity Center's own logs up to the IdP. This note explains that path.

## Contents

- [How It Works](#how-it-works)
- [The Pieces](#the-pieces)
- [The Identity Chain — Where the Human Lives](#the-identity-chain--where-the-human-lives)
- [How to Identify Identity Center in Evidence](#how-to-identify-identity-center-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Person → signs in at the SSO portal → (IdP authenticates: Okta / Entra / built-in)
       → picks an Account + Permission Set
       → Identity Center calls AssumeRole on a matching role in that account
       → gets ASIA temp creds → acts in the account
```

- Identity Center **federates** an upstream IdP and maps SSO users/groups to **permission sets** in specific accounts.
- Each permission set becomes an IAM **role** in each assigned account, named `AWSReservedSSO_<permission-set>_<hash>`.
- Sign-ins are **short-lived sessions**; there are no standing access keys for the human.

## The Pieces

| Piece | What it is | 🔴 Attacker interest |
|-------|-----------|---------------------|
| **Identity source** | Where users authenticate (external IdP or built-in directory) | Compromise the IdP = compromise AWS |
| **Users / groups** | The SSO principals | Add a rogue user; add self to an admin group |
| **Permission set** | A reusable role template (policies) deployed to accounts | Widen a permission set's policies |
| **Account assignment** | A (user/group × permission set × account) grant | Assign self admin in a target account |
| **Permission-set role** | The `AWSReservedSSO_…` IAM role assumed at login | What you actually see in CloudTrail |

## The Identity Chain — Where the Human Lives

This is the whole reason the note exists. To attribute an SSO action to a person, you climb three rungs:

| Rung | Log | What it tells you |
|------|-----|-------------------|
| 1. **The action** | CloudTrail (target account) | An `AWSReservedSSO_Admin_abc123` role did X — but *who*? |
| 2. **The SSO sign-in** | Identity Center CloudTrail / sign-in logs | Which SSO **user** authenticated and assumed that permission set |
| 3. **The authentication** | The **upstream IdP** (Okta/Entra) logs | The real person, device, MFA, IP, and any IdP-side compromise |

> 🔴 **Stop at rung 1 and you'll blame a role, not a human.** Every SSO investigation must pivot to the Identity Center logs and then the IdP. If the IdP is external, that's a *different console/team* — know where to ask.

## How to Identify Identity Center in Evidence

- 🔴 **Role names:** `AWSReservedSSO_<PermissionSetName>_<16-hex>` — an instant "this came through SSO" tell.
- **`eventSource`:** `sso.amazonaws.com`, `sso-directory.amazonaws.com`, `identitystore.amazonaws.com` for admin actions; `signin.amazonaws.com` for the portal login.
- **ARNs:**

| Thing | ARN shape |
|-------|-----------|
| Permission-set role (in an account) | `arn:aws:iam::<acct>:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_<name>_<hash>` |
| Permission set | `arn:aws:sso:::permissionSet/ssoins-<id>/ps-<id>` |
| Identity Store user | `arn:aws:identitystore:::user/<id>` |

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `Authenticate` / portal `ConsoleLogin` | An SSO sign-in | 🔴 new IP/geo/device |
| `CreateUser` / `CreateGroup` (identity store) | Add SSO principal | 🔴 rogue user |
| `AddMemberToGroup` | Put a user in a (admin) group | 🔴 privesc |
| `CreatePermissionSet` / `PutInlinePolicyToPermissionSet` | New/edited permission set | 🔴 widening access |
| `AttachManagedPolicyToPermissionSet` | Add policies (e.g. admin) to a set | 🔴 privesc |
| `CreateAccountAssignment` | Grant a principal a permission set in an account | 🔴 self-assign admin |
| `ProvisionPermissionSet` | Push the set's changes to accounts | Follows the above |
| `UpdateInstanceAccessControlAttributeConfiguration` | ABAC attribute changes | Access-model change |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| IAM Identity Center | Entra ID (SSO) | Workforce Identity / Cloud Identity |
| Permission set | Directory role / RBAC role | IAM role granted via group |
| Account assignment | Role assignment (scope) | IAM binding at project/folder |
| Identity source (external IdP) | Federated IdP | External IdP via Workforce pool |
| `AWSReservedSSO_` role | — (token-based) | — (token-based) |

## Common Use Cases

Your "normal":

- **All human access** to all accounts, centrally — the modern default.
- **Group-based access** — SSO groups map to permission sets; access follows HR/IdP group membership.
- **Just-in-time-ish** short sessions rather than standing keys.
- **CLI access** via `aws sso login` (still short-lived).

> 🔴 In an Identity-Center shop, a *new IAM user* or *new long-term `AKIA` key* is abnormal — access is supposed to come through SSO. Treat standing IAM creds as suspicious by default.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Identity source** | Where SSO users authenticate (external IdP or built-in) |
| **Permission set** | Reusable role template deployed to accounts |
| **Account assignment** | Grant of (principal × permission set × account) |
| **Permission-set role** | The `AWSReservedSSO_…` IAM role assumed at login |
| **Identity store** | Identity Center's directory of users/groups |
| **SSO portal** | The web menu of accounts/roles a user sees |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating SSO compromise | **IAM Identity Center → IAM Identity Center for DFIR** |
| The AssumeRole under every login | **AWS → Identity & Access → STS** |
| Identity types & permission-set roles in logs | **AWS → 01 IAM & Identities** |
| The upstream tenant (if Entra) | **Microsoft → Azure / Entra ID** |
| Cross-cloud identity pivots | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- What is IAM Identity Center — https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html
- Permission sets — https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html
- Logging Identity Center with CloudTrail — https://docs.aws.amazon.com/singlesignon/latest/userguide/logging-using-cloudtrail.html
