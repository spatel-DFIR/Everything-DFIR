# Secrets Manager for DFIR

When a principal is compromised, Secrets Manager is one of the first places an attacker goes — it's where the *next* set of credentials lives (databases, SaaS, partner APIs). A single `GetSecretValue` can widen an incident from "one leaked key" to "the whole environment." This note is how you scope that: read the retrieval events in CloudTrail, decide which secrets are burned, and cut off both the access and the persistence.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading the Log](#reading-the-log)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig / Harden](#fix-the-misconfig--harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

- **It's the pivot store.** Secrets here unlock databases and third parties — reading them turns a foothold into lateral movement and data access.
- **Retrieval is logged; the value isn't.** CloudTrail records *who read which secret when* by default — enough to scope exactly what to rotate.
- **Cross-account and destruction risks.** A resource-policy change hands secrets to another account; `DeleteSecret` / disrupted rotation are tamper/destruction moves.

## Evidence It Produces

| Evidence | Where | Default | Notes |
|----------|-------|---------|-------|
| **Retrieval events** (`GetSecretValue`, `BatchGetSecretValue`) | CloudTrail | ✅ On | Who/when/which secret ARN/from where. **No value.** The scoping backbone. |
| **Management events** (`PutResourcePolicy`, `PutSecretValue`, `DeleteSecret`, `ReplicateSecretToRegions`, `RotateSecret`) | CloudTrail | ✅ On | Tamper, cross-account, exfil, destruction. |
| **Recon events** (`ListSecrets`, `DescribeSecret`) | CloudTrail | ✅ On | Enumeration before a harvest. |
| **KMS `Decrypt`** | CloudTrail (KMS) | ✅ On | Second breadcrumb — each read decrypts via the wrapping key; `encryptionContext` names the secret. |
| **Secret metadata & policy** | `DescribeSecret`, `GetResourcePolicy` | ✅ On (current) | Current rotation/policy/replication state. |
| **Rotation Lambda logs** | CloudWatch Logs | If enabled | Tamper with the rotation function shows here. |

## Collect It

**Inventory secrets (and spot anything replicated/pending deletion):**
```bash
aws secretsmanager list-secrets \
  --query 'SecretList[].{Name:Name,ARN:ARN,Rotation:RotationEnabled,Replicated:length(ReplicationStatus),DeletedDate:DeletedDate}' \
  --output table
```
*Console:* Secrets Manager → **Secrets** (the list shows rotation + replication).

**Every retrieval in the window (the scope of what's burned):**
```bash
for e in GetSecretValue BatchGetSecretValue; do
  echo "== $e =="; aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$e --max-results 50
done
```

**Tamper / cross-account / destruction events:**
```bash
for e in PutResourcePolicy PutSecretValue DeleteSecret ReplicateSecretToRegions; do
  echo "== $e =="; aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$e --max-results 20
done
```

**Current policy on a suspect secret:**
```bash
aws secretsmanager get-resource-policy --secret-id <name-or-arn>
```

## Investigate on the Platform

1. **What did the compromised principal read?** Timeline every `GetSecretValue`/`BatchGetSecretValue` by the actor. Each secret ARN read = **burned**; list them for rotation.
2. **Was it a harvest?** Many reads in a short window, or a `BatchGetSecretValue`, or `ListSecrets` immediately followed by reads = deliberate credential harvesting, not app behavior.
3. **Was a resource policy widened?** For each `PutResourcePolicy`, check for a **new external `Principal`** (another account) or `"*"`. That's cross-account theft — secrets are readable outside your account until you revert it.
4. **Was a secret exfiltrated by replication or tampered?** `ReplicateSecretToRegions` (copied elsewhere), `PutSecretValue`/`UpdateSecret` (attacker planted their own value or overwrote), `DeleteSecret` (destruction — note the recovery window).
5. **Rotation abuse?** `CancelRotateSecret` (keeps a stolen cred valid) or edits to the rotation Lambda (interception of every future value).
6. **Cross-check KMS.** The matching `Decrypt` events (with `encryptionContext` naming the secret) corroborate reads and can reveal access that used the key directly.
7. **Attribute the principal.** Decode `userIdentity` (AKIA/ASIA, role session → **01 IAM & Identities**); note `sourceIPAddress`/`userAgent`.

## Reading the Log

| Field | Tells you | Watch for |
|-------|-----------|-----------|
| `eventName` | The action | 🔴 `GetSecretValue`, `BatchGetSecretValue`, `PutResourcePolicy` |
| `requestParameters.secretId` | Which secret | Map to what it unlocks (DB/SaaS) |
| `requestParameters.versionStage` | Which version read | `AWSPREVIOUS` = grabbing an older cred |
| `userIdentity` | Who | 🔴 human/role that isn't the app; new principal |
| `sourceIPAddress` / `userAgent` | From where / with what | 🔴 new IP/geo; not the app host |
| `requestParameters.resourcePolicy` (on `PutResourcePolicy`) | New policy | 🔴 external `Principal` / `"*"` |
| `errorCode` | Denied attempts | `AccessDenied` bursts before success = probing |

## Hunt at Scale

**Bulk secret reads by a single principal (CloudTrail Lake / Athena):**
```sql
SELECT userIdentity.arn AS who, sourceIPAddress,
       COUNT(*) AS reads, MIN(eventTime), MAX(eventTime)
FROM cloudtrail
WHERE eventName IN ('GetSecretValue','BatchGetSecretValue')
GROUP BY userIdentity.arn, sourceIPAddress
ORDER BY reads DESC;
```

**Cross-account / destructive changes:**
```sql
SELECT eventTime, eventName, userIdentity.arn,
       element_at(requestParameters, 'secretId') AS secret
FROM cloudtrail
WHERE eventSource = 'secretsmanager.amazonaws.com'
  AND eventName IN ('PutResourcePolicy','DeleteSecret','ReplicateSecretToRegions','PutSecretValue')
ORDER BY eventTime DESC;
```

**SecOps (UDM) — land it, then look for the same actor elsewhere:**

| UDM field | Secrets Manager value |
|-----------|----------------------|
| `metadata.product_event_type` | `GetSecretValue` / `BatchGetSecretValue` |
| `principal.user.userid` | `userIdentity.arn` |
| `principal.ip` | `sourceIPAddress` |
| `target.resource.name` | secret ARN |

```
metadata.log_type="AWS_CLOUDTRAIL"
(metadata.product_event_type="GetSecretValue" OR metadata.product_event_type="BatchGetSecretValue")
principal.ip != <known_app_ranges>
```

## Respond

**Rotate everything that was read** — treat every secret in the actor's `GetSecretValue` list as compromised. Rotate at the *source* (change the DB password / revoke the API key), not just in Secrets Manager:
```bash
aws secretsmanager rotate-secret --secret-id <name-or-arn>   # if a rotation Lambda exists
```

**Revert illicit sharing / tampering:**
```bash
aws secretsmanager delete-resource-policy --secret-id <name-or-arn>   # remove external grant
# or put back a known-good resource policy
aws secretsmanager restore-secret --secret-id <name-or-arn>           # undo a pending delete
```

**Cut the principal's access** — strip `secretsmanager:GetSecretValue`, then **revoke the actor's temporary sessions** (an `ASIA` keeps working until you do → **STS → Respond**).

**Assess downstream.** For each burned secret, investigate what those credentials could reach (the DB, the SaaS tenant) — the incident often continues *there*.

## Fix the Misconfig / Harden

| Fix | How | Verify |
|-----|-----|--------|
| **Least-privilege reads** | Scope `GetSecretValue` to the specific app role and specific secret ARNs; no wildcard secret access | Simulate; a low-priv role gets `AccessDenied` |
| **Block cross-account widening** | SCP/condition denying `PutResourcePolicy` that adds principals outside `aws:PrincipalOrgID` | Test policy edit → denied |
| **Tight KMS key** | Wrap secrets with a customer-managed key with a narrow key policy (defense in depth) | `DescribeSecret` shows the CMK; KMS policy scoped |
| **Enable rotation** | Turn on rotation so a stolen value has a short shelf life | `RotationEnabled = true` |
| **Alarm the danger ops** | Detection on `BatchGetSecretValue`, `PutResourcePolicy`, `DeleteSecret`, `ReplicateSecretToRegions`, and high-volume `GetSecretValue` | Test event triggers alert |
| **Private access** | VPC endpoint for `secretsmanager`; deny public retrieval paths | Endpoint present; app reads privately |
| **Deletion guardrail** | SCP denying `DeleteSecret` except break-glass; keep the recovery window generous | Delete attempt → denied |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `GetSecretValue` by a human/role that isn't the owning app | Credential theft |
| `BatchGetSecretValue` or many `GetSecretValue` in a short window | Bulk harvest |
| `ListSecrets` → immediate reads | Enumerate-then-steal |
| `PutResourcePolicy` adding an external account / `"*"` | Cross-account secret theft |
| `ReplicateSecretToRegions` to an unused region | Exfil/stash |
| `PutSecretValue` / `UpdateSecret` by an unexpected principal | Planted or overwritten secret |
| `DeleteSecret` outside decommissioning | Destruction |
| `CancelRotateSecret` / rotation-Lambda edits | Keeping a stolen cred alive / interception |
| Reads from a new IP/geo | Off-host retrieval |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Secrets Manager is and how access is decided | **What is Secrets Manager** |
| The KMS key that wraps every secret | **AWS → Data Protection → KMS** |
| The *other* secret store to sweep too | **AWS → Compute → Systems Manager (SSM)** (Parameter Store) |
| Who read it + revoking their session | **AWS → 01 IAM & Identities** · **STS** |
| The foothold that led here | **AWS → Playbooks → Leaked Access Key** · **Persistence and Backdoor Hunt** |
| The same service in Azure | **Azure → Key Vault → Key Vault for DFIR** |

## Resources

- Retrieving secrets — https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets.html
- Monitoring with CloudTrail — https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring-cloudtrail.html
- Resource-based policies (cross-account) — https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-based-policies.html
- Deleting & restoring secrets — https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_delete-secret.html
- MITRE ATT&CK: Unsecured Credentials – Cloud Secrets Management Stores (T1552.006) — https://attack.mitre.org/techniques/T1552/006/
