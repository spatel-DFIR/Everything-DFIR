# Playbook — Privilege Escalation to Admin

The attacker landed with **limited** permissions and wants **admin**. AWS has well-known privesc primitives — specific IAM/compute API patterns that turn a low-priv identity into a powerful one. This playbook detects the escalation and unwinds it.

> **Tier 2 (cross-service).** Touches IAM, STS, EC2/Lambda (PassRole), CloudTrail. Read **IAM for DFIR** (privesc paths) and **01 IAM & Identities**.

## Contents

- [Attack Chain](#attack-chain)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [The Privesc Primitives](#the-privesc-primitives)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Attack Chain

```
Low-priv identity (leaked key / app role / SSO user)
   → enumerates its own permissions (lots of AccessDenied while probing)
   → finds a privesc primitive (see table)
   → uses it to grant itself admin OR assume a powerful role
   → acts with new power (persistence, exfil, impact)
```

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **GuardDuty** | `PrivilegeEscalation:IAMUser/AdministrativePermissions` |
| **CloudTrail alert** | `AttachUserPolicy` of `AdministratorAccess`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy` |
| **The AccessDenied→success pivot** | A burst of denies then a sudden powerful action |
| **A new admin identity** | Someone/something now has more than it should |

## Hypothesis

An identity escalated its privileges. Find the exact primitive used, the moment of escalation, everything it did with the new power, and revert both the grant and the downstream actions.

## The Privesc Primitives

Hunt each in the timeline (full detail in **IAM for DFIR**):

| Primitive | API pattern |
|-----------|-------------|
| Attach admin policy | `AttachUserPolicy` / `AttachGroupPolicy` (AdministratorAccess) |
| Inline self-grant | `PutUserPolicy` / `PutRolePolicy` (`Action: *`) |
| Policy-version swap | `CreatePolicyVersion` + `SetDefaultPolicyVersion` |
| Join admin group | `AddUserToGroup` |
| **PassRole + compute** | `iam:PassRole` (admin role) + `RunInstances`/`CreateFunction` |
| Edit assumable-role trust | `UpdateAssumeRolePolicy` + `AssumeRole` |
| New admin role | `CreateRole` + `AttachRolePolicy` + `AssumeRole` |
| Remove the ceiling | `DeleteUserPermissionsBoundary` |

## Step-by-Step Investigation

**1. Find the pivot moment.** In the identity's timeline, look for the **`AccessDenied` burst → sudden success** — that's the escalation. Note the exact `eventName`.

**2. Identify the primitive.** Match the successful event to the table above. Read its `requestParameters` (which policy/role/group).

**3. Read what changed.**
- Policy attach/inline: read the policy JSON — how much power did they grant?
- Policy-version swap: `aws iam get-policy-version` on **every** version, not just default — the abuse may be under a non-default version.
- Trust-policy edit: `aws iam get-role --query Role.AssumeRolePolicyDocument` — who did they add?

**4. Follow the new power.** After the escalation timestamp, what did the identity (or the role it assumed) do? Persistence, exfil, impact — build that timeline (→ Investigating AWS).

**5. PassRole cases.** If `PassRole` + `RunInstances`/`CreateFunction` — the attacker created compute carrying an admin role, then used it. Find that instance/function and what its role did.

## Decision Points

| Question | If yes → |
|----------|----------|
| Which primitive? | Determines exactly what to revert |
| Policy-version swap? | Check all versions; delete the malicious one |
| Did they assume a role? | Revoke that role's sessions too |
| Did they create compute (PassRole)? | Kill the instance/function + revoke its role sessions |
| Persistence after escalation? | Work the full persistence list (→ IAM) |

## Contain

```bash
# 1. Cut the identity (deactivate key / revoke sessions / quarantine)
# 2. Immediately remove the escalated grant:
aws iam detach-user-policy --user-name <u> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user-policy   --user-name <u> --policy-name <inline>
# 3. Revoke sessions of any role they assumed / compute they launched
```

## Eradicate

- Revert **every** grant: detached/inline policies, malicious policy versions, group memberships, trust-policy edits, restored permissions boundaries.
- Kill compute created via PassRole and revoke its role sessions.
- Remove downstream persistence (new users/keys/roles/providers).
- Fix the entry vector that gave them the initial low-priv foothold.

## Recover

- Restore least-privilege on the affected identity and any policy they rewrote.
- Verify no residual admin remains (`get-account-authorization-details` diff vs baseline).
- Preserve: the escalation event + downstream timeline.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `AccessDenied` burst then a sudden success | Live escalation |
| `AttachUserPolicy` AdministratorAccess | Direct admin grant |
| `CreatePolicyVersion` + `SetDefaultPolicyVersion` | Quiet policy rewrite |
| `UpdateAssumeRolePolicy` adding a principal | Trust-policy backdoor |
| `iam:PassRole` (admin) + `RunInstances`/`CreateFunction` | PassRole privesc |
| `DeleteUserPermissionsBoundary` | Ceiling removed |

## References

- Related notes: **IAM for DFIR**, **STS for DFIR**, **01 IAM & Identities**, **Leaked Access Key**
- IAM policy evaluation logic — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- MITRE ATT&CK: Account Manipulation (T1098) / Cloud Accounts (T1078.004) — https://attack.mitre.org/techniques/T1098/
