# Cognito for DFIR

Cognito incidents come in two flavors: **application account-takeover** (attackers abusing your app's login) and **AWS-account exposure** (an identity pool handing out over-permissioned AWS creds). Know which half you're in before you dig.

New to the service? Read **What is Cognito** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate](#investigate)
- [The Two Attack Patterns](#the-two-attack-patterns)
- [Reading the Logs](#reading-the-logs)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Cognito answers **"is someone abusing our app's login, and can an app user (or an anonymous one) reach our AWS resources?"** The second question is the one that turns an app bug into a cloud breach.

## Evidence It Produces

| Evidence | What it gives you | Where |
|----------|-------------------|-------|
| `cognito-idp.*` events | Sign-ups, logins, resets, admin changes, pool config | CloudTrail |
| `cognito-identity.*` events | `GetId` / `GetCredentialsForIdentity` (creds handed out) | CloudTrail |
| Downstream `ASIA` activity | What the minted creds actually did in AWS | CloudTrail (filter the identity-pool role) |
| Pool configuration | MFA settings, guest-access enabled, role mappings, Lambda triggers | `cognito-idp` / `cognito-identity` API |
| App-side / WAF logs | Auth attempt volume, IPs (for stuffing/takeover) | Your app + WAF, not just AWS |

> ⚠️ **Coverage caveat:** user-pool *authentication* events (`InitiateAuth`, etc.) are high-volume and **not always fully in CloudTrail** — lean on **CloudWatch metrics**, WAF, and your application logs for login-abuse patterns. Config changes *are* in CloudTrail.

## Collect It

```bash
# Enumerate pools
aws cognito-idp list-user-pools --max-results 50
aws cognito-identity list-identity-pools --max-results 50

# User-pool posture: MFA, password policy, triggers
aws cognito-idp describe-user-pool --user-pool-id us-east-1_ABC123
aws cognito-idp list-users --user-pool-id us-east-1_ABC123    # look for mass/rogue sign-ups

# 🔴 Identity-pool posture: is guest access on? which roles?
aws cognito-identity describe-identity-pool --identity-pool-id us-east-1:xxxx
aws cognito-identity get-identity-pool-roles --identity-pool-id us-east-1:xxxx
# → then read the AUTH and UNAUTH role policies in IAM
```

> **Console:** Cognito → **User pools** (Sign-in, MFA, App clients, Triggers) / **Identity pools** (User access → *Guest access* toggle + role assignment).

## Investigate

| Step | Do this |
|------|---------|
| 1 | Decide the flavor: app takeover (user pool) vs AWS exposure (identity pool) |
| 2 | **Identity pool:** is **guest access enabled**? Read the unauth *and* auth role policies — what can they reach? |
| 3 | Pull `GetCredentialsForIdentity` events; correlate the minted `ASIA` role to downstream S3/DynamoDB/etc. activity |
| 4 | **User pool:** review `SignUp`/`AdminCreateUser` for mass/rogue accounts; `UpdateUserPool` for weakened MFA or new Lambda triggers |
| 5 | Pull login-abuse signal from CloudWatch/WAF/app logs (volume, IPs, geos) |

## The Two Attack Patterns

**Pattern A — Anonymous AWS access via a guest identity pool:**

```
Attacker reads identity-pool ID from app's client-side JS
  → cognito-identity GetId  (no login)
  → GetCredentialsForIdentity → ASIA creds for the UNAUTH role
  → uses whatever that role allows (often S3 list/get, DynamoDB scan)
```

Signature: `GetCredentialsForIdentity` at volume from varied IPs, then `ASIA` activity by the identity pool's **unauthenticated** role.

**Pattern B — App account takeover:**

```
Credential stuffing / weak reset → InitiateAuth success from attacker IP
  → (optional) AdminUpdateUserAttributes to swap email → ForgotPassword to seize
  → act as the victim in the app; if identity pool attached, also get AWS creds
```

Signature: login spikes, resets, email-attribute changes, MFA disabled on the pool.

## Reading the Logs

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | Which Cognito action | `GetCredentialsForIdentity`, `SetIdentityPoolRoles`, `UpdateUserPool` |
| `additionalEventData` / `requestParameters` | Pool ID, identity ID | The pool involved |
| Downstream `userIdentity.sessionIssuer` | The auth/unauth role | 🔴 unauth role doing anything sensitive |
| `sourceIPAddress` | Where creds were requested from | Volume from many IPs (automation) |

## Hunt at Scale

**In-platform — Athena / Lake:**

```sql
-- Anonymous credential issuance + what the guest role then did
SELECT eventtime, eventname, sourceipaddress,
       json_extract_scalar(requestparameters,'$.identityPoolId') AS pool
FROM cloudtrail_logs
WHERE eventsource = 'cognito-identity.amazonaws.com'
  AND eventname = 'GetCredentialsForIdentity'
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "GetCredentialsForIdentity" OR metadata.product_event_type = "UpdateUserPool"
```

## Respond

| Goal | Action |
|------|--------|
| Stop anonymous AWS access | **Disable guest access** on the identity pool; tighten the unauth role to near-nothing |
| Shrink blast radius | Scope the auth/unauth role policies to least privilege immediately |
| Contain takeovers | Force password resets; sign out users globally (`AdminUserGlobalSignOut`); revoke tokens |
| Re-secure the pool | Re-enable/enforce MFA; review Lambda triggers for malicious code |
| Kill minted sessions | Revoke the identity-pool role's sessions (deny by `TokenIssueTime`) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Disable unauthenticated (guest) access** unless truly required | Removes anonymous AWS-cred issuance |
| **Least-privilege** auth/unauth roles, scoped by `${cognito-identity.amazonaws.com:sub}` | App users reach only *their* data |
| **Enforce MFA** + strong password policy on user pools | Blocks stuffing/takeover |
| **Advanced Security** (compromised-cred + adaptive auth) | Auto-blocks risky logins |
| **WAF** on the hosted UI / app; rate-limit auth | Throttles stuffing |
| **Alert** on `SetIdentityPoolRoles`, `UpdateUserPool`, guest-access enable | Detect config weakening |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Identity pool with **guest access enabled** + a broad unauth role | Anonymous AWS access |
| `GetCredentialsForIdentity` volume from many IPs | Automated abuse of the cred bridge |
| The unauth/auth role doing sensitive S3/DynamoDB/KMS actions | App-user creds over-reaching |
| `SetIdentityPoolRoles` pointing users at a broader role | Privilege escalation of app users |
| `UpdateUserPool` disabling MFA / adding a Lambda trigger | Weakened auth or malicious hook |
| Login/reset spikes, `AdminUpdateUserAttributes` email swaps | Account takeover in progress |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Cognito is (pools explained) | **Cognito → What is Cognito** |
| The STS creds it mints | **AWS → Identity & Access → STS** |
| The roles those creds carry | **AWS → Identity & Access → IAM** |
| What app users then read | **AWS → Storage → S3**, **Databases → DynamoDB** |
| Web-layer abuse in front of it | **AWS → Networking → API Gateway** |

## Resources

- Role-based access control for identity pools — https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html
- Cognito advanced security — https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-advanced-security.html
- Logging with CloudTrail — https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html
- MITRE ATT&CK: Valid Accounts – Cloud (T1078.004) — https://attack.mitre.org/techniques/T1078/004/
