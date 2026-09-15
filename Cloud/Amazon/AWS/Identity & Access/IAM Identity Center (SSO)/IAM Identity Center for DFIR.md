# IAM Identity Center for DFIR

When the alert involves an `AWSReservedSSO_…` role, you're in Identity Center territory. The job is to **turn a permission-set role back into a named human**, then decide whether the SSO layer, the IdP, or a single session is compromised.

New to the service? Read **What is IAM Identity Center** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Role Back to Human](#investigate--role-back-to-human)
- [What Attackers Do Here](#what-attackers-do-here)
- [Reading the Logs](#reading-the-logs)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Identity Center answers **"which human is behind this SSO role, and did someone tamper with who-can-access-what?"** Miss this layer and you'll chase a role name forever.

## Evidence It Produces

| Evidence | What it gives you | Where |
|----------|-------------------|-------|
| Portal sign-in events | Who logged into SSO, IP, time | CloudTrail `signin.amazonaws.com` / Identity Center logs |
| `sso.*` / `identitystore.*` admin events | Permission-set & assignment changes | CloudTrail (mgmt account usually) |
| Permission-set role assumes | The `AssumeRole` per login | CloudTrail (target account) |
| **Upstream IdP logs** | The real authentication (device, MFA, geo) | Okta / Entra / Google console — **not** AWS |

> 🔴 Identity Center admin events typically log in the **management/delegated-admin account**, while the *usage* (role assumes, actions) logs in the **target account**. You need both.

## Collect It

```bash
# List the permission sets and who/what they map to
aws sso-admin list-instances
aws sso-admin list-permission-sets --instance-arn <ins-arn>
aws sso-admin list-account-assignments \
  --instance-arn <ins-arn> --account-id <acct> --permission-set-arn <ps-arn>

# Enumerate SSO users/groups (identity store)
aws identitystore list-users  --identity-store-id <d-xxxx>
aws identitystore list-groups --identity-store-id <d-xxxx>
aws identitystore list-group-memberships --identity-store-id <d-xxxx> --group-id <id>
```

> **Console:** IAM Identity Center → **Users / Groups**, **Permission sets**, **AWS accounts** (assignments). Sign-in activity: the Identity Center console + the upstream IdP's log.

## Investigate — Role Back to Human

The core procedure — climb the chain:

| Step | Do this |
|------|---------|
| 1 | In the target account's CloudTrail, note the `AWSReservedSSO_<set>_<hash>` role and the `roleSessionName` (usually the SSO username/email) |
| 2 | Pivot to Identity Center sign-in logs: find the `Authenticate`/portal login for that user at that time — get IP, session |
| 3 | Pivot to the **upstream IdP** (Okta/Entra): confirm the authentication — device, MFA method, geo, impossible-travel, any IdP-side alert |
| 4 | Decide the scope: one stolen session? the IdP account? or SSO-admin tampering? |
| 5 | If admin tampering: pull `sso.*`/`identitystore.*` events in the mgmt account for new users, group adds, permission-set edits, self-assignments |

> **The `roleSessionName` shortcut:** Identity Center usually sets the session name to the user's email/username — so a target-account event often *already names the human*. Confirm it against the sign-in log; attackers with SSO-admin rights could create sessions under other names.

## What Attackers Do Here

| Move | Signature | Impact |
|------|-----------|--------|
| Ride a stolen SSO session | Portal login from new IP/device, then role assume | Access without touching AWS creds |
| Add a rogue SSO user | `CreateUser` (identity store) | Persistent human identity |
| Self-join an admin group | `AddMemberToGroup` | Privesc across all accounts the group can reach |
| Widen a permission set | `AttachManagedPolicyToPermissionSet` (admin) / `PutInlinePolicyToPermissionSet` | Everyone with that set gains power |
| Self-assign admin in a target account | `CreateAccountAssignment` + `ProvisionPermissionSet` | Direct route into a chosen account |
| Compromise the IdP itself | (in IdP logs) new MFA, new app, directory sync change | Owns the front door to all of AWS |

## Reading the Logs

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `userIdentity` (target acct) | The `AWSReservedSSO_` role + session | The permission set in play |
| `roleSessionName` | Usually the SSO user/email | Mismatch vs sign-in log |
| Sign-in `sourceIPAddress` / geo | Where the human logged in | New country/ASN, impossible travel |
| `sso.*` `requestParameters` | Which set/assignment changed | Admin-level tampering |
| IdP MFA fields | How they authenticated | MFA push-bombing, new factor enrolled |

## Hunt at Scale

**In-platform — Athena / Lake (SQL):**

```sql
-- SSO admin changes to access mappings
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource IN ('sso.amazonaws.com','identitystore.amazonaws.com')
  AND eventname IN ('CreateAccountAssignment','AttachManagedPolicyToPermissionSet',
                    'PutInlinePolicyToPermissionSet','AddMemberToGroup','CreateUser')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "CreateAccountAssignment"
```

## Respond

| Goal | Action |
|------|--------|
| Kill a live SSO session | Console: Identity Center → Users → **Delete active sessions** for the user |
| Disable a compromised SSO user | Deactivate in the identity source (external IdP if federated) |
| Revoke assumed permission-set sessions | Revoke sessions on the `AWSReservedSSO_` role in the target account (deny by `TokenIssueTime`) |
| Undo tampering | Remove rogue assignments/users; revert permission-set policy changes; re-provision |
| Contain the IdP | Force IdP-side password reset + MFA re-enrollment; revoke IdP tokens |

> 🔴 If the **upstream IdP** is compromised, fixing AWS alone is not containment — the attacker just logs back in. Coordinate with whoever owns the IdP immediately.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Phishing-resistant MFA** (FIDO2) at the IdP | Stops SSO session/credential theft |
| **Short SSO session duration** + `aws sso login` re-auth | Shrinks stolen-session window |
| **Least-privilege permission sets**; separate admin sets, tightly assigned | Limits blast radius |
| **Alert** on `CreateAccountAssignment`, permission-set policy edits, new SSO users | Real-time privesc detection |
| **Delegate admin** off the management account; log both | Cleaner, monitored admin surface |
| **Kill standing IAM users/keys** in favor of SSO everywhere | One monitored access path |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| SSO portal login from new country/ASN/device | Stolen session or IdP compromise |
| `roleSessionName` not matching any real sign-in | Session forged by an SSO-admin attacker |
| New identity-store user/group created | Persistent rogue identity |
| `AddMemberToGroup` into an admin-mapped group | Privilege escalation |
| Permission set gaining `AdministratorAccess` | Everyone with it just got admin |
| `CreateAccountAssignment` granting self access | Direct route into a target account |
| A new IAM user/`AKIA` key appearing in an SSO-only org | Off-path persistence |
| IdP-side: new MFA factor, new OAuth app, sync change | Front-door compromise |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Identity Center is | **IAM Identity Center → What is IAM Identity Center** |
| The AssumeRole under every login | **AWS → Identity & Access → STS** |
| Identity types in logs | **AWS → 01 IAM & Identities** |
| The Entra/Okta side (if federated) | **Microsoft → Azure**, or your IdP notes |
| Cross-cloud identity pivots | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- Logging Identity Center with CloudTrail — https://docs.aws.amazon.com/singlesignon/latest/userguide/logging-using-cloudtrail.html
- Managing SSO sessions — https://docs.aws.amazon.com/singlesignon/latest/userguide/authconcept.html
- Identity Store API — https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html
- MITRE ATT&CK: Valid Accounts – Cloud Accounts (T1078.004) — https://attack.mitre.org/techniques/T1078/004/
