# IAM for DFIR

Almost every AWS intrusion touches IAM. The attacker who lands with one stolen credential wants three things: **a durable identity** (persistence), **more permissions** (privilege escalation), and **a role to pivot into** (lateral movement). All three happen in IAM.

New to the service? Read **What is IAM** and **01 - IAM & Identities** first. This note is the *how*.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Finding Persistence — Backdoor Identities](#finding-persistence--backdoor-identities)
- [Finding Privilege Escalation](#finding-privilege-escalation)
- [Reading IAM Events](#reading-iam-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

IAM answers **"what can this identity do, what did it change, and did it plant a way back in?"** A leaked key is only the front door — the damage is what they did to IAM once inside.

## Evidence It Produces

Two kinds: **live config** (pull it now) and **CloudTrail events** (the history of changes).

| Evidence | What it gives you | Retention |
|----------|-------------------|-----------|
| **Credential report** | Every user's key age, last-used, MFA, password status | Live snapshot (regenerate anytime) |
| **Account authorization details** | Full users/roles/groups/policies + attachments | Live snapshot |
| **Access-key last-used** | When & from what service a key last called | Live snapshot |
| **CloudTrail `iam.*` / `sts.*` events** | Every create/attach/assume, who did it, when | Trail retention (S3/Lake); 90d in Event history |

**In SecOps (end-of-note aid only):** `AWS_CLOUDTRAIL`, filter `metadata.product_event_type` to IAM actions; principal → `principal.user.userid`.

## Collect It

**Pull the credential report first — it's the fastest scoping win.**

```bash
# Generate (async) then fetch the CSV of all users' credential status
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d > cred_report.csv
```

Columns to read immediately: `access_key_1_active`, `access_key_1_last_used_date`, `mfa_active`, `password_last_used`, `user_creation_time`.

> **Console:** IAM → **Credential report** → *Download report*. IAM → **Users** → each user's *Security credentials* tab shows keys, MFA, last-used.

**Snapshot the whole authorization model** (great for a diff against a known-good baseline):

```bash
aws iam get-account-authorization-details > iam_full_dump.json
aws iam get-account-summary            # counts: users, MFA devices, keys
```

**Pull a specific identity under suspicion:**

```bash
aws iam get-user --user-name <user>
aws iam list-access-keys --user-name <user>
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>            # inline policies (backdoors hide here)
aws iam get-access-key-last-used --access-key-id AKIA... # where/when a key last called from
```

**IAM Policy Simulator** — simulates whether a given policy actually allows/denies a specific action, without the identity taking any real action. Useful pre-incident (validate a policy before attaching it) and mid-investigation (verify whether an attacker's assumed identity's permissions actually matched what its policy would grant, or whether they escalated beyond it):

```bash
aws iam simulate-principal-policy --policy-source-arn <arn> --action-names <action>
```

## Investigate on the Platform

The flow — five moves:

| Step | Do this |
|------|---------|
| 1. Snapshot | Pull the credential report + full auth dump *now* (before you change anything) |
| 2. Timeline the identity | CloudTrail: every `iam.*`/`sts.*` action by the suspect user/key/role, sorted by `eventTime` |
| 3. Hunt persistence | New users, new keys, new login profiles, new roles — see below |
| 4. Hunt privesc | Policy attaches, inline policies, policy-version swaps, group adds, trust-policy edits |
| 5. Map the blast radius | What can each touched identity now reach? Which roles does it trust/assume? |

## Finding Persistence — Backdoor Identities

Attackers create a way back in that survives you rotating the original key. Hunt each:

| Persistence trick | CloudTrail signature | How to spot the survivor |
|-------------------|----------------------|--------------------------|
| **Backdoor IAM user** | `CreateUser` → `CreateAccessKey` → `AttachUserPolicy` | Cred report: a user created *during* the incident window |
| **Extra key on a real user** | `CreateAccessKey` on an existing (esp. service) user | Cred report: a user with **2 active keys**, one brand new |
| **Console password on a service user** | `CreateLoginProfile` on a user that never had one | Users with both keys *and* a recent login profile |
| **NotAction / wildcard inline policy** | `PutUserPolicy` with `"Action":"*"` | List inline policies; read the JSON |
| **Role with a wide trust policy** | `CreateRole` / `UpdateAssumeRolePolicy` trusting `*` or an external acct | Read every role's trust policy |
| **Rogue identity provider** | `CreateSAMLProvider` / `CreateOpenIDConnectProvider` | List IdPs; anything you don't recognize = 🔴 |
| **MFA removed** | `DeactivateMFADevice` then persistence | Cred report `mfa_active=false` on a privileged user |

> 🔴 **The tell that beats them all:** a **second active access key** on an account that only ever used one, created in your incident window. Attackers add a key rather than steal the existing one because it survives a naive "rotate the leaked key" response.

## Finding Privilege Escalation

If the landed identity wasn't admin, it tried to *become* admin. AWS has well-known privesc primitives — each is a specific API pattern. Hunt these:

| Privesc path | The move | API calls to hunt |
|--------------|----------|-------------------|
| **Attach admin policy** | Give self `AdministratorAccess` | `AttachUserPolicy` / `AttachGroupPolicy` |
| **Inline self-grant** | Embed an allow-`*` policy | `PutUserPolicy` / `PutRolePolicy` / `PutGroupPolicy` |
| **Policy version swap** | Set an old permissive version default | `CreatePolicyVersion` + `SetDefaultPolicyVersion` |
| **Join an admin group** | Add self to a powerful group | `AddUserToGroup` |
| **PassRole + launch compute** | Pass an admin role to a new EC2/Lambda you control | `PassRole` + `RunInstances` / `CreateFunction` |
| **PassRole + Lambda** | Create a function with an admin role, invoke it | `CreateFunction` + `PassRole` + `Invoke` |
| **Update assumable role** | Edit a role's trust to allow self, then assume | `UpdateAssumeRolePolicy` + `AssumeRole` |
| **Create a new admin role** | New role, admin policy, assume it | `CreateRole` + `AttachRolePolicy` + `AssumeRole` |
| **Remove the ceiling** | Delete a permissions boundary | `DeleteUserPermissionsBoundary` |

> 🔴 **The universal tell:** a **burst of `AccessDenied` followed by a sudden success**. The attacker is probing what they can do (denies), finds a privesc primitive, uses it (success), then acts with new power. Grep your timeline for the pivot moment.
>
> 🔴 **`iam:PassRole` is the crown-jewel primitive.** By itself it does nothing, but combined with the ability to launch a compute resource, it lets a low-priv identity hand *itself* an admin role via EC2/Lambda/ECS. Any `PassRole` to a high-privilege role by a non-admin identity deserves a hard look.

## Reading IAM Events

The fields that carry an IAM investigation:

| Field | Answers | Notes |
|-------|---------|-------|
| `userIdentity` | **Who** made the change | See 01 Identities; watch for `Root` |
| `eventName` | **What** IAM action | Map to persistence/privesc tables above |
| `requestParameters` | **The target & payload** | `userName`, `policyArn`, `policyDocument`, `roleName` |
| `responseElements` | **What was minted** | 🔴 `accessKey.accessKeyId` on `CreateAccessKey` = the new backdoor key |
| `sourceIPAddress` + `userAgent` | **From where / with what** | Script vs console; new IP/geo |
| `errorCode` | **Did it work** | `AccessDenied` bursts = enumeration |

**Worked example — spotting a minted backdoor key:**

```jsonc
{
  "eventName": "CreateAccessKey",
  "userIdentity": { "type": "IAMUser", "userName": "ci-deploy" },   // acted-as
  "requestParameters": { "userName": "ci-deploy" },                 // 🔴 for ITSELF or another?
  "responseElements": { "accessKey": {
      "accessKeyId": "AKIA_NEW_BACKDOOR",                           // 🔴 the survivor
      "status": "Active" } }
}
```

> If `requestParameters.userName` ≠ the acting identity, someone minted a key **for a different user** — a classic lateral-persistence move.

## Hunt at Scale

**In-platform — Athena / CloudTrail Lake (SQL):**

```sql
-- Every identity-creating / permission-granting action in the window
SELECT eventtime, useridentity.arn, eventname,
       json_extract_scalar(requestparameters,'$.userName') AS target
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN ('CreateUser','CreateAccessKey','CreateLoginProfile',
                    'AttachUserPolicy','PutUserPolicy','CreatePolicyVersion',
                    'AddUserToGroup','UpdateAssumeRolePolicy','CreateSAMLProvider')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional cross-account sweep):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "CreateAccessKey" OR metadata.product_event_type = "AttachUserPolicy"
```

## Respond

Order matters: **stop the active session, then remove the standing access, then close the persistence.**

| Goal | Action |
|------|--------|
| Deactivate a leaked long-term key | `aws iam update-access-key --user-name <u> --access-key-id AKIA... --status Inactive` |
| Kill live temp sessions from a role | IAM → Role → **Revoke active sessions** (adds a deny-by-`TokenIssueTime` inline policy) |
| Fast-quarantine an identity | `aws iam attach-user-policy --user-name <u> --policy-arn arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3` |
| Remove a backdoor user | Delete keys + login profile + inline policies, then `delete-user` (collect first) |
| Undo a privesc | Detach the attacker's policy; delete rogue policy versions; fix the trust policy |
| Remove a rogue IdP | `aws iam delete-saml-provider` / `delete-open-id-connect-provider` |
| Force re-auth everywhere | Rotate keys, reset console passwords, re-enroll MFA on affected users |

> 🔴 **Don't stop at the leaked key.** If you deactivate `AKIA...` but leave the backdoor user, the extra key, or the edited trust policy, the attacker walks right back in. Work the full persistence list from *Finding Persistence* above before you call it contained.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Move humans to SSO** (IAM Identity Center); delete standing IAM users | No long-term creds to leak |
| **Eliminate long-term keys**; use roles + short-lived creds | `AKIA` keys never expire |
| **MFA on every user**, enforced by policy; hardware MFA for admins | Stops stolen-password reuse |
| **Permissions boundaries** on all human/CI roles | Caps blast radius even if a policy is over-granted |
| **SCPs** denying `iam:CreateUser`, `CreateAccessKey`, `Create*Provider` outside break-glass | Removes the persistence primitives org-wide |
| **Access Analyzer** on; review external/cross-account access | Finds unintended trust |
| **Alert** on `CreateAccessKey`, `AttachUserPolicy`, `UpdateAssumeRolePolicy`, `CreateLoginProfile` | Catch persistence/privesc in real time |
| **Rotate & prune** keys (credential report); remove unused identities | Shrinks attack surface |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| New IAM user created in the incident window | Backdoor identity |
| Second active access key on a user (esp. service account) | Key-add persistence that survives rotation |
| `CreateLoginProfile` on a user that never logged in interactively | Attacker enabling console access |
| `AttachUserPolicy` of `AdministratorAccess` | Privilege escalation |
| `CreatePolicyVersion` + `SetDefaultPolicyVersion` | Quiet policy rewrite — read all versions |
| `UpdateAssumeRolePolicy` adding a new/external trusted principal | Trust-policy backdoor |
| `CreateSAMLProvider` / `CreateOpenIDConnectProvider` you don't recognize | Rogue federation = "log in as anyone" |
| `iam:PassRole` to a privileged role by a non-admin | Privesc via compute |
| `DeactivateMFADevice` / `DeleteVirtualMFADevice` before other changes | MFA stripping to persist |
| Burst of `AccessDenied` then a sudden success | Live privilege-escalation probing |
| Root user doing IAM actions | Should never happen outside break-glass |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the service/pieces are | **IAM → What is IAM** |
| Reading identity types | **AWS → 01 IAM & Identities** |
| Temporary sessions & AssumeRole | **AWS → Identity & Access → STS** |
| SSO permission-set logins | **AWS → Identity & Access → IAM Identity Center** |
| The audit trail feeding all of this | **AWS → Logging & Monitoring → CloudTrail** |
| A full leaked-key intrusion, end to end | **AWS → Playbooks → Leaked Access Key** |
| Privesc via IMDS role theft | **AWS → Playbooks → IMDS SSRF to Role Theft** |

## Resources

- IAM security best practices — https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- Getting credential reports — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
- `get-account-authorization-details` — https://docs.aws.amazon.com/cli/latest/reference/iam/get-account-authorization-details.html
- Compromised-credentials quarantine policy — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_managed-vs-inline.html
- IAM Access Analyzer — https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- MITRE ATT&CK: Cloud Account Manipulation (T1098) — https://attack.mitre.org/techniques/T1098/
