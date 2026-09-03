# What is Cognito?

**Cognito** is AWS's **customer identity** service — the sign-up/sign-in system for *your application's end users* (not your employees). If a web or mobile app lets people register and log in, Cognito is often what's behind it.

Two very different halves live under one name, and confusing them causes bad investigations:

- **User Pools** = the **directory + login** (usernames, passwords, MFA, hosted UI, tokens).
- **Identity Pools** = the **bridge to AWS** (exchange a login for temporary AWS credentials via STS).

## Contents

- [How It Works](#how-it-works)
- [User Pools vs Identity Pools](#user-pools-vs-identity-pools)
- [The Dangerous Part — Identity Pools to AWS Creds](#the-dangerous-part--identity-pools-to-aws-creds)
- [How to Identify Cognito in Evidence](#how-to-identify-cognito-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
End user → signs up / signs in at a User Pool  →  gets ID + Access + Refresh tokens (JWT)
                                                │
                        (optional) Identity Pool exchanges that token
                                                ▼
                              STS → temporary AWS creds (ASIA…) tied to an IAM role
                                                ▼
                              app calls AWS (e.g. S3, DynamoDB) as that role
```

- **User Pools** authenticate people and issue **JWT tokens**. That's usually the end of it for a pure app login.
- **Identity Pools** (a.k.a. *federated identities*) turn an authenticated (or even *un*authenticated) user into **real AWS credentials** with an IAM role attached. This is where cloud-impacting risk lives.

## User Pools vs Identity Pools

| | **User Pool** | **Identity Pool** |
|-|---------------|-------------------|
| Job | Directory + authentication | Hand out AWS credentials |
| Output | JWT tokens (ID/Access/Refresh) | STS temp creds (`ASIA…`) + IAM role |
| Analogy | The login form + user database | The valet that gives app users an AWS badge |
| ID shape | `us-east-1_XXXXXXXXX` | `us-east-1:<uuid>` |
| 🔴 Risk | Account takeover, weak sign-up policy | **Over-permissioned role → app users act in your AWS account** |

## The Dangerous Part — Identity Pools to AWS Creds

Identity Pools have two role slots, and one is a classic misconfiguration:

| Role | Who gets it | 🔴 The trap |
|------|-------------|-------------|
| **Authenticated role** | Users who logged in | Over-broad policy = every app user can reach more of AWS than intended |
| **Unauthenticated (guest) role** | **Anyone**, no login required | 🔴 If enabled + over-permissioned, *anonymous internet users* get AWS creds that can read S3, query DynamoDB, etc. |

> 🔴 **The signature attack:** an attacker finds the identity-pool ID (it's shipped in the app's client-side code), calls `GetId` + `GetCredentialsForIdentity` **unauthenticated**, and receives `ASIA` creds for the guest role — then uses whatever that role allows. If the guest role is too broad, that's direct AWS access with no login. Always check the unauth role's policy.

## How to Identify Cognito in Evidence

- **`eventSource`:** `cognito-idp.amazonaws.com` (User Pools), `cognito-identity.amazonaws.com` (Identity Pools).
- **IDs:** User Pool `us-east-1_ABC123`; Identity Pool `us-east-1:11111111-2222-...`.
- **In downstream events:** an Identity-Pool-minted session shows as `type: AssumedRole` / `WebIdentityUser` with the identity pool's authenticated/unauthenticated role — an `ASIA` session originating from Cognito.

## Common Operations You Will See

| Operation | Pool | What it does | Watch? |
|-----------|------|--------------|--------|
| `SignUp` / `AdminCreateUser` | User | Register a user | 🔴 self-signup abuse / mass registration |
| `InitiateAuth` / `AdminInitiateAuth` | User | Log in | 🔴 credential stuffing (spikes) |
| `ForgotPassword` / `ConfirmForgotPassword` | User | Password reset | 🔴 account-takeover flow abuse |
| `AdminSetUserPassword` / `AdminUpdateUserAttributes` | User | Admin changes a user | 🔴 takeover / email swap |
| `UpdateUserPool` (policies, triggers) | User | Change pool config/Lambda triggers | 🔴 weaken MFA; malicious trigger |
| `GetId` / `GetCredentialsForIdentity` | Identity | Exchange login → AWS creds | 🔴 unauth abuse if guest enabled |
| `SetIdentityPoolRoles` | Identity | Change which roles users get | 🔴 point users at a broader role |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| Cognito User Pool | Entra **External ID** / Azure AD B2C | Identity Platform / Firebase Auth |
| Cognito Identity Pool | — (token → resource via RBAC) | Workload/Workforce Identity + Firebase |
| Guest (unauth) role | Anonymous access (rare) | Firebase anonymous auth |

## Common Use Cases

Your "normal":

- **App/customer login** — the sign-in for a SaaS or mobile app.
- **Social/enterprise federation** — "log in with Google/Apple/SAML."
- **Direct AWS access for app users** — an app that lets users upload to *their own* S3 prefix via identity-pool creds.

## Key Terminology

| Term | Meaning |
|------|---------|
| **User Pool** | Directory + authentication; issues JWTs |
| **Identity Pool** | Exchanges a login for AWS temp creds |
| **Authenticated role** | IAM role for logged-in identity-pool users |
| **Unauthenticated (guest) role** | IAM role for anonymous identity-pool users |
| **App client** | The application registered with a user pool |
| **Hosted UI** | Cognito's ready-made login pages |
| **Lambda trigger** | Custom code run on auth events (pre/post sign-up, etc.) |
| **JWT** | The signed ID/Access/Refresh tokens |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating Cognito abuse | **Cognito → Cognito for DFIR** |
| The AWS creds it mints (STS) | **AWS → Identity & Access → STS** |
| The roles those creds carry | **AWS → Identity & Access → IAM** |
| What the app users then reach | **AWS → Storage → S3**, **Databases → DynamoDB** |

## Resources

- What is Amazon Cognito — https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html
- Identity pools (federated identities) — https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html
- Role-based access control for identity pools — https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html
- Logging Cognito API calls with CloudTrail — https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html
