# What is Conditional Access & MFA?

**Conditional Access (CA)** is Entra's **policy engine** — the "if this, then that" rules that decide whether a sign-in is allowed, blocked, or forced to do more (MFA, a compliant device). **MFA** (multi-factor authentication) is the most common *control* those policies enforce.

Together they are the **gate** every token passes through. On a case, they answer two questions: *should this sign-in have been stopped?* and *why wasn't it?*

## Contents

- [How It Works](#how-it-works)
- [The Anatomy of a Policy](#the-anatomy-of-a-policy)
- [MFA — The Methods and Their Strength](#mfa--the-methods-and-their-strength)
- [How CA Shows Up in a Sign-in](#how-ca-shows-up-in-a-sign-in)
- [The Ways Attackers Beat It](#the-ways-attackers-beat-it)
- [How to Identify CA in Evidence](#how-to-identify-ca-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

At every sign-in, Entra evaluates all CA policies. Each policy is **assignments** (who/what it applies to) + **conditions** (the signals) + **access controls** (what to require or block).

```
Sign-in  →  Which policies apply? (user, app, platform, location, risk)
         →  Conditions met?       (managed device? trusted IP? risky?)
         →  Controls              →  Grant (maybe require MFA / compliant device)  OR  Block
```

The outcome is stamped on the sign-in event as `conditionalAccessStatus` and a per-policy result.

## The Anatomy of a Policy

| Part | Examples | Why the analyst cares |
|------|----------|-----------------------|
| **Assignments — users** | All users, a group, guests, directory roles | 🔴 An **exclusion** (a user/group left out) is a common bypass and a hiding spot |
| **Assignments — apps** | All cloud apps, or specific ones | A policy scoped to few apps leaves gaps |
| **Conditions** | Sign-in risk, device platform, **location**, client app | Trusted-location or platform gaps get abused |
| **Grant controls** | Require MFA, require compliant/hybrid-joined device, require phishing-resistant | Weak controls (password only) = weak gate |
| **Session controls** | Sign-in frequency, app-enforced restrictions, CAE | Long sessions = long-lived stolen tokens |
| **State** | On / Off / Report-only | 🔴 A policy flipped **Off** or left **report-only** enforces nothing |

> 🔴 **Exclusions and "Off/Report-only" are where attackers live.** When you review why a bad sign-in wasn't blocked, check whether the user was **excluded**, whether the policy was **disabled**, and whether **legacy auth** dodged it entirely.

## MFA — The Methods and Their Strength

Not all MFA is equal. Strength matters because attackers defeat the weak kinds:

| Method | Strength | 🔴 Weakness |
|--------|----------|-------------|
| **FIDO2 / passkeys, Windows Hello, cert-based** | **Phishing-resistant** (strongest) | Very hard to phish/replay |
| **Authenticator app — number matching** | Strong | Resistant to MFA-fatigue |
| **Authenticator push (plain approve)** | Medium | 🔴 **MFA fatigue / prompt bombing** |
| **SMS / voice call** | Weak | 🔴 SIM-swap, interception |
| **Legacy auth (IMAP/POP/SMTP)** | **None** | 🔴 **Bypasses MFA entirely** |

> 🔴 **AiTM phishing beats even strong MFA at the token level** — it lets the user complete MFA, then steals the resulting token. Phishing-resistant methods (FIDO2) + token-binding + CAE are the real defense. See **Entra → Playbooks → Token Theft and AiTM**.

## How CA Shows Up in a Sign-in

On each sign-in event:

| Field | Meaning |
|-------|---------|
| `conditionalAccessStatus` | `success` (controls satisfied) / `failure` (blocked) / `notApplied` (no policy matched) |
| `appliedConditionalAccessPolicies[]` | Each policy + its result (`success`/`failure`/`notApplied`/`notEnabled`) |
| `authenticationRequirement` | `multiFactorAuthentication` vs `singleFactorAuthentication` |
| `authenticationDetails` | The methods used and whether they were **performed** or **satisfied by a prior token** |

> 🔴 `conditionalAccessStatus = notApplied` on a **sensitive** sign-in means **no policy caught it** — a coverage gap. `authenticationRequirement = singleFactorAuthentication` on admin access is a red flag.

## The Ways Attackers Beat It

| Technique | How it dodges CA/MFA |
|-----------|----------------------|
| **Legacy auth** | Old protocols don't support modern auth → MFA never enforced |
| **Token theft (AiTM)** | User does MFA; attacker replays the resulting token |
| **Policy exclusions** | Attacker (or their account) is in an excluded group |
| **Disabling/weakening policy** | `Update/Delete conditional access policy` (an audit-log event) |
| **Service principals** | App-only auth — most CA doesn't apply to SPs |
| **Trusted location abuse** | Signing in from (or spoofing) a "trusted" IP that skips MFA |
| **MFA fatigue** | Push-bombing until the user approves |

## How to Identify CA in Evidence

- **Portal:** Entra ID → **Protection → Conditional Access** (policies) · Sign-in logs → a sign-in's **Conditional Access** tab.
- **Graph:** `identity/conditionalAccess/policies`; sign-in `appliedConditionalAccessPolicies`.
- **Audit log:** `Update/Add/Delete conditional access policy`.
- **KQL:** `SigninLogs | mv-expand ConditionalAccessPolicies`.

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Conditional Access | IAM policy conditions / SCP (partial) | Context-Aware Access / Access Levels |
| MFA enforcement | IAM MFA conditions | 2-Step Verification enforcement |
| Compliant-device control | (no direct equal) | Endpoint verification |
| Named/trusted locations | `aws:SourceIp` conditions | Access Context Manager |

## Common Use Cases

Your "normal" baseline:

- **Require MFA** for everyone / admins.
- **Block legacy auth** tenant-wide.
- **Require compliant device** for sensitive apps.
- **Block or step-up** on risk / untrusted locations.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Conditional Access (CA)** | The policy engine gating sign-ins |
| **Assignment** | Who/what a policy applies to |
| **Grant control** | What a policy requires (MFA, compliant device) |
| **Session control** | Sign-in frequency, CAE, app restrictions |
| **Report-only** | A policy that logs what it *would* do but doesn't enforce |
| **Exclusion** | A user/group left out of a policy |
| **Phishing-resistant MFA** | FIDO2, passkeys, Windows Hello, certs |
| **CAE** | Continuous Access Evaluation — near-real-time token revocation |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating CA/MFA in a case | **Conditional Access & MFA → for DFIR** |
| The sign-in that CA evaluated | **Entra → Sign-in Logs** |
| CA policy *changes* | **Entra → Audit Logs** |
| Token replay that beats MFA | **Entra → Playbooks → Token Theft and AiTM** |
| Risk signals CA can consume | **Entra → Identity Protection** |

## Resources

- Conditional Access overview — https://learn.microsoft.com/entra/identity/conditional-access/overview
- Authentication methods & strength — https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods
- Block legacy authentication — https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication
- Phishing-resistant MFA — https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless
