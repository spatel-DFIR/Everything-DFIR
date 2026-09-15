# Organizations for DFIR

Organizations shows up in a case two ways: as the **lens** you investigate *through* (the org trail sees every account; SCPs bound what was possible) and as a **target** (weakening a guardrail, escaping the Org, or pivoting from the management account).

New to the service? Read **What is Organizations** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate](#investigate)
- [Attacks Against the Org Layer](#attacks-against-the-org-layer)
- [Reading the Logs](#reading-the-logs)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

The org layer answers **"could a guardrail have stopped this, did someone weaken one, and is the compromise contained to one account or spreading across the Org?"**

## Evidence It Produces

| Evidence | What it gives you | Where |
|----------|-------------------|-------|
| `organizations.*` events | Account/SCP/delegated-admin changes | CloudTrail (management account) |
| The **org trail** | Every member account's activity in one place | The log-archive S3 bucket / Lake |
| SCP definitions | What was and wasn't possible | `organizations` API / console |
| Account list & OU structure | Scope of the environment | `list-accounts`, `list-organizational-units-for-parent` |

> 🔴 Org-management events log in the **management account** — make sure you have visibility there, not just the compromised member account.

## Collect It

```bash
# The shape of the Org
aws organizations describe-organization
aws organizations list-accounts --query 'Accounts[].{Id:Id,Name:Name,Status:Status}' --output table
aws organizations list-roots

# SCPs and where they attach
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations list-policies-for-target --target-id <ou-or-acct> --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id p-xxxx        # read the JSON

# Delegated admins & trusted services (org-wide reach)
aws organizations list-delegated-administrators
aws organizations list-aws-service-access-for-organization
```

> **Console:** AWS Organizations → **AWS accounts** (tree), **Policies → Service control policies**, **Services** (trusted access / delegated admin).

## Investigate

| Step | Do this |
|------|---------|
| 1 | Confirm the **org trail** exists and covers your window (see CloudTrail); it's your cross-account view |
| 2 | Read the **SCPs** — what could the attacker's identity *not* do? This prunes hypotheses fast |
| 3 | Timeline `organizations.*` events: any SCP edits/detaches, new accounts, delegated-admin changes, accounts leaving |
| 4 | Check for **cross-account pivots**: assumes of `OrganizationAccountAccessRole` or other cross-account roles |
| 5 | If the **management account** is implicated, treat it as a full-org incident |

## Attacks Against the Org Layer

| Move | Signature | Impact |
|------|-----------|--------|
| Weaken a guardrail | `UpdatePolicy` / `DetachPolicy` on an SCP | Removes org-wide protection (e.g. the StopLogging deny) |
| Create a hidden account | `CreateAccount` | A place to hide resources/costs outside normal monitoring |
| Escape the Org | `LeaveOrganization` / `RemoveAccountFromOrganization` | Account exits central logging + SCPs |
| Abuse delegated admin | `RegisterDelegatedAdministrator` / `EnableAWSServiceAccess` | Org-wide reach via a security service |
| Pivot from management | Assume `OrganizationAccountAccessRole` into members | Admin into every account by design |
| Tamper with the org trail | `UpdateTrail` / `StopLogging` on the org trail | Blind every account at once |

## Reading the Logs

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `userIdentity` | Who (esp. management-account identities) | Root / mgmt-account admins |
| `eventName` | Which org action | SCP edits, account create/leave |
| `requestParameters.policyId` / `targetId` | Which SCP, applied where | Guardrail on a production OU being detached |
| `sourceIPAddress` / `userAgent` | From where / with what | New IP; scripted |
| `recipientAccountId` | Which account it affected | The blast-radius account |

## Hunt at Scale

**In-platform — Athena / Lake over the org trail:**

```sql
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'organizations.amazonaws.com'
  AND eventname IN ('UpdatePolicy','DetachPolicy','CreateAccount','LeaveOrganization',
                    'RemoveAccountFromOrganization','RegisterDelegatedAdministrator')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "DetachPolicy" OR metadata.product_event_type = "CreateAccount"
```

## Respond

| Goal | Action |
|------|--------|
| Restore a weakened guardrail | Re-attach / revert the SCP; verify with `list-policies-for-target` |
| Contain a compromised management account | Rotate root, revoke sessions, review all `organizations.*` activity — this is a top-severity event |
| Stop cross-account spread | Revoke `OrganizationAccountAccessRole` sessions; tighten its trust |
| Re-secure delegated admins | Remove rogue delegated admins; re-register the intended one |
| Re-enable org logging | Restart/repair the org trail |

> 🔴 A **management-account compromise is org-wide by definition.** Don't scope it to one account — assume every member account is reachable and triage accordingly.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **SCP denying** `StopLogging`/`DeleteTrail`/`DeleteDetector`/`StopConfigurationRecorder` org-wide | No member attacker can blind controls |
| **Lock the management account** — no workloads, few humans, hardware-MFA root | Shrinks the crown-jewel surface |
| **Delegate security admin** to an audit account; centralize GuardDuty/Config/Security Hub | Monitored, least-privilege admin |
| **Alert** on `DetachPolicy`, `UpdatePolicy`, `CreateAccount`, `LeaveOrganization` | Catch guardrail tampering live |
| **Restrict `LeaveOrganization`** via SCP | Prevents accounts escaping governance |
| **Tighten `OrganizationAccountAccessRole`** trust + alert on its assume | Controls the org-wide admin path |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `DetachPolicy` / `UpdatePolicy` weakening an SCP | Attacker clearing org-wide guardrails |
| `CreateAccount` you didn't plan | Hidden resources / cost |
| `LeaveOrganization` / `RemoveAccountFromOrganization` | Escaping central logging + SCPs |
| Assume of `OrganizationAccountAccessRole` from an unexpected identity | Org-wide pivot |
| New delegated administrator / `EnableAWSServiceAccess` | Org-wide reach granted |
| Any management-account activity you can't attribute | Crown-jewel compromise |
| Org trail `StopLogging` / `UpdateTrail` | Blinding every account at once |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Organizations is | **Organizations → What is Organizations** |
| Accounts/OUs/regions basics | **AWS → 00 Overview & Terminology** |
| The org trail | **AWS → Logging & Monitoring → CloudTrail** |
| Cross-account assumes | **AWS → Identity & Access → STS** |
| Centralized threat detection | **AWS → Security & Detection → GuardDuty** |

## Resources

- Service Control Policies — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- Best practices for the management account — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html
- Organizations API reference — https://docs.aws.amazon.com/organizations/latest/APIReference/Welcome.html
- MITRE ATT&CK: Impair Defenses (T1562) — https://attack.mitre.org/techniques/T1562/
