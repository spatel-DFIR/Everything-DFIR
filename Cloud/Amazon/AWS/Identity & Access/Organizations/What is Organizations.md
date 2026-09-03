# What is AWS Organizations?

**AWS Organizations** ties many AWS accounts into one governed tree. It is where **org-wide guardrails (SCPs)**, **centralized logging**, and the all-powerful **management account** live.

For DFIR, Organizations matters two ways: it's a **defensive superpower** (one SCP can block an attacker in every account; one org trail logs them all) and a **top-tier target** (own the management account and you own everything).

## Contents

- [How It Works](#how-it-works)
- [The Pieces](#the-pieces)
- [Service Control Policies (SCPs)](#service-control-policies-scps)
- [Why the Management Account Is Crown Jewels](#why-the-management-account-is-crown-jewels)
- [How to Identify Organizations in Evidence](#how-to-identify-organizations-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Organization (root)
├── Management account         ← owns the Org; pays; can do org-wide things
├── OU: Security               ← houses the log-archive + audit accounts
│   ├── Log Archive account    ← the locked bucket every trail writes to
│   └── Audit account          ← delegated admin for GuardDuty/Config/etc.
├── OU: Production
│   └── prod-app account
└── OU: Sandbox
    └── dev accounts
```

- **Central logging:** an **organization trail** created in the management (or delegated) account captures **every member account's** CloudTrail into one bucket.
- **Central guardrails:** **SCPs** attached to the root/OUs set the *maximum* permissions for every account beneath.
- **Delegated administration:** security services (GuardDuty, Security Hub, Config, Access Analyzer) can be centrally managed from a chosen *audit* account.

## The Pieces

| Piece | What it is | 🔴 DFIR relevance |
|-------|-----------|-------------------|
| **Management account** | Owns the Org | Compromise = total; should run almost no workloads |
| **Member account** | Any non-management account | The normal blast-radius unit |
| **OU** | A folder grouping accounts | Where SCPs attach |
| **SCP** | Org-wide permission guardrail | Can block *or*, if edited, unblock attacker actions |
| **Organization trail** | One CloudTrail for all accounts | Your single best evidence source |
| **Delegated admin** | A member account running a security service org-wide | Where you triage GuardDuty/Config centrally |
| **Trusted access / service-linked** | Services allowed to operate org-wide | Abuse = org-wide reach |

## Service Control Policies (SCPs)

SCPs are **guardrails, not grants** — they set the ceiling; they never give permissions. An action is allowed only if the identity's policies *and* every SCP above it allow it.

| SCP truth | Meaning on a case |
|-----------|-------------------|
| SCPs don't affect the **management account** | 🔴 Guardrails you rely on don't protect the mgmt account itself |
| An explicit `Deny` in an SCP beats any Allow below | A good SCP can stop an attacker who holds admin creds |
| Editing an SCP is a high-privilege act | 🔴 `UpdatePolicy`/`DetachPolicy` weakening a guardrail = attacker clearing their path |

**The defensive pattern you want to see (and check for):** an SCP that **denies** `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `guardduty:DeleteDetector`, `config:StopConfigurationRecorder`, etc., across the whole Org — so no member-account attacker can blind logging.

> 🔴 On a case, **read the SCPs early.** They tell you what the attacker *couldn't* do (narrowing hypotheses) and whether someone *weakened* one (a defense-evasion signal).

## Why the Management Account Is Crown Jewels

| Capability from the management account | Why it's catastrophic |
|----------------------------------------|-----------------------|
| Create/close member accounts | Spin up hidden accounts; destroy evidence |
| Edit SCPs | Remove every org-wide guardrail |
| Assume `OrganizationAccountAccessRole` into any member | Admin into *every* account by design |
| Change the org trail | Blind logging org-wide |
| Manage delegated admins | Disable/relocate security tooling |

> 🔴 **`OrganizationAccountAccessRole`** exists in member accounts and trusts the management account. It's the intended admin path — and a prime attacker pivot. Any assume of it deserves scrutiny.

## How to Identify Organizations in Evidence

- **`eventSource`:** `organizations.amazonaws.com`.
- **ARNs:**

| Thing | ARN shape |
|-------|-----------|
| Account | `arn:aws:organizations::<mgmt>:account/o-<org>/<acct-id>` |
| OU | `arn:aws:organizations::<mgmt>:ou/o-<org>/ou-<id>` |
| SCP (policy) | `arn:aws:organizations::<mgmt>:policy/o-<org>/service_control_policy/p-<id>` |
| Root | `arn:aws:organizations::<mgmt>:root/o-<org>/r-<id>` |

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateAccount` / `CloseAccount` | Add/remove a member account | 🔴 hidden account / evidence destruction |
| `InviteAccountToOrganization` / `AcceptHandshake` | Bring an account in | Ownership change |
| `LeaveOrganization` / `RemoveAccountFromOrganization` | Detach an account | 🔴 escaping central logging/SCPs |
| `CreatePolicy` / `UpdatePolicy` (SCP) | Create/change a guardrail | 🔴 weakening controls |
| `AttachPolicy` / `DetachPolicy` | Apply/remove an SCP | 🔴 `DetachPolicy` removes protection |
| `EnableAWSServiceAccess` / `RegisterDelegatedAdministrator` | Grant org-wide service reach | 🔴 abuse = org-wide access |
| `DescribeOrganization` / `ListAccounts` | Enumerate the Org | Recon |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| Organization | Tenant + Management Groups | Organization |
| OU | Management Group | Folder |
| Member account | Subscription | Project |
| SCP | Azure Policy (deny) | Organization Policy |
| Organization trail | Tenant-level diagnostic settings | Org-level aggregated audit sink |
| Management account | Root management group / Global Admin | Org admin |

## Common Use Cases

Your "normal":

- **Multi-account structure** — separate accounts per team/env, grouped by OU.
- **Central security** — log-archive + audit accounts; org trail; delegated GuardDuty/Config.
- **Guardrails** — SCPs enforcing region locks, denying dangerous actions, requiring encryption.
- **Consolidated billing.**

## Key Terminology

| Term | Meaning |
|------|---------|
| **Management account** | The account that owns the Org |
| **Member account** | Any other account in the Org |
| **OU** | Organizational Unit — a folder of accounts |
| **SCP** | Service Control Policy — permission ceiling |
| **Organization trail** | One CloudTrail spanning all accounts |
| **Delegated administrator** | A member account managing a service org-wide |
| **Trusted access** | A service allowed to act across the Org |
| **`OrganizationAccountAccessRole`** | Default role letting the mgmt account admin members |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating org-level abuse | **Organizations → Organizations for DFIR** |
| Accounts/OUs/regions basics | **AWS → 00 Overview & Terminology** |
| The org trail deep dive | **AWS → Logging & Monitoring → CloudTrail** |
| Cross-account role assumption | **AWS → Identity & Access → STS** |

## Resources

- Organizations concepts — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html
- Service Control Policies — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- Logging Organizations with CloudTrail — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security_incident-response.html
- Best practices for the management account — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html
