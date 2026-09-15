# KMS for DFIR

KMS shows up in two kinds of case: **destruction** (an attacker disables or schedules deletion of a key, making the data it protects unrecoverable — cloud ransomware without any malware) and **theft** (an attacker widens a key policy or creates a grant so *they* can decrypt your data). The good news: KMS is chatty — even `Decrypt` is logged by default — so with CloudTrail you can reconstruct exactly what happened to every key.

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

- **Key deletion/disable = irreversible data loss.** No decryptor to buy — the math is gone. This is a top data-destruction and ransomware vector.
- **Key-policy / grant changes = silent data theft.** Adding an external account or a grant lets someone decrypt your storage without ever touching the objects' ACLs.
- **KMS logs its own use.** `Decrypt`, `GenerateDataKey`, `Encrypt`, `ReEncrypt` are in CloudTrail — you can see *who decrypted what and when*, with `encryptionContext` naming the resource.

## Evidence It Produces

| Evidence | Where | Default | Notes |
|----------|-------|---------|-------|
| **KMS management events** (`ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`, `CreateGrant`, `CreateKey`…) | CloudTrail | ✅ On | The destruction/theft actions. |
| **KMS use events** (`Decrypt`, `GenerateDataKey`, `Encrypt`, `ReEncrypt`) | CloudTrail | ✅ On | Rare gift — data-plane visibility by default; `encryptionContext` ties to the resource. |
| **Key state & metadata** | `DescribeKey`, KMS console | ✅ On (current state) | `KeyState = PendingDeletion / Disabled`; `DeletionDate`. |
| **Grants list** | `ListGrants` | ✅ On | Who currently holds delegated key permissions. |
| **Key policy** | `GetKeyPolicy` | ✅ On (current) | The *current* policy; use CloudTrail `PutKeyPolicy` to see *changes*. |
| **AWS Config** | Config timeline | If enabled | Point-in-time key config history (policy, rotation, state). |

> 🔴 The **waiting period is your window.** `ScheduleKeyDeletion` doesn't delete immediately — it sets a 7–30 day timer. If you catch it in time, `CancelKeyDeletion` saves the data. Check every key's `KeyState` early.

## Collect It

**Inventory keys and their state (find anything pending deletion or disabled):**
```bash
aws kms list-keys --query 'Keys[].KeyId' --output text | tr '\t' '\n' | while read k; do
  aws kms describe-key --key-id "$k" \
    --query 'KeyMetadata.{Id:KeyId,State:KeyState,Del:DeletionDate,Mgr:KeyManager}' --output json
done
```
*Console:* KMS → **Customer managed keys** → the **Status** column (`Pending deletion` / `Disabled` stand out).

**The dangerous events in CloudTrail:**
```bash
for e in ScheduleKeyDeletion DisableKey PutKeyPolicy CreateGrant ImportKeyMaterial; do
  echo "== $e =="; aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$e --max-results 20
done
```

**Current grants and policy on a suspect key:**
```bash
aws kms list-grants --key-id <id>
aws kms get-key-policy --key-id <id> --policy-name default --output text
```

## Investigate on the Platform

1. **Any key pending deletion or disabled?** From the inventory above, list keys with `KeyState` = `PendingDeletion` or `Disabled`. For each, find the `ScheduleKeyDeletion`/`DisableKey` event → `userIdentity`, time, IP. If it's not a documented decommission, it's an incident — and the clock is running.
2. **What did that key protect?** Map the key to resources (S3 buckets with SSE-KMS on it, EBS volumes, RDS, secrets). Deleting/disabling it breaks all of them.
3. **Was a key policy widened?** For each `PutKeyPolicy`, diff old vs new — look for a **new external `Principal`** (another account ID) or `"AWS":"*"`. That's cross-account decrypt.
4. **Were grants created?** `CreateGrant` events → the `granteePrincipal`. A grant to an unfamiliar role/account = stealthy access.
5. **What was decrypted?** Timeline `Decrypt`/`GenerateDataKey` by the suspect principal. `encryptionContext` names the resource (e.g. the S3 object ARN) — that's your data-access record. Bulk `Decrypt` across many contexts = data harvesting.
6. **Re-encryption?** `ReEncrypt` or `GenerateDataKey` against an **attacker-created key** (look for a fresh `CreateKey` by the same actor) = ransomware pattern (your data re-wrapped under their key).
7. **Attribute the principal.** Decode `userIdentity` (AKIA/ASIA, role session → **01 IAM & Identities**); pull `sourceIPAddress`/`userAgent`.

## Reading the Log

| Field | Tells you | Watch for |
|-------|-----------|-----------|
| `eventName` | The KMS action | 🔴 `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`, `CreateGrant` |
| `requestParameters.keyId` | Which key | Map to the data it protects |
| `requestParameters.encryptionContext` | The resource using the key (on `Decrypt`/`GenerateDataKey`) | Ties use to an S3 object/volume/secret |
| `requestParameters.granteePrincipal` | Who a grant was given to | 🔴 unfamiliar account/role |
| `requestParameters.policy` (on `PutKeyPolicy`) | The new key policy | 🔴 external `Principal` / `"*"` |
| `requestParameters.pendingWindowInDays` | Deletion timer | The window to `CancelKeyDeletion` |
| `userIdentity` / `sourceIPAddress` | Who + from where | 🔴 human principal on a service key; new IP/geo |
| `errorCode` | Denied attempts | A burst of `AccessDenied` then success = probing |

## Hunt at Scale

**Destruction & policy-tamper events (CloudTrail Lake / Athena):**
```sql
SELECT eventTime, eventName, userIdentity.arn AS who, sourceIPAddress,
       element_at(requestParameters, 'keyId') AS key
FROM cloudtrail
WHERE eventSource = 'kms.amazonaws.com'
  AND eventName IN ('ScheduleKeyDeletion','DisableKey','PutKeyPolicy','CreateGrant','ImportKeyMaterial')
ORDER BY eventTime DESC;
```

**Bulk decrypt by a single principal (data harvesting):**
```sql
SELECT userIdentity.arn, COUNT(*) AS decrypts, MIN(eventTime), MAX(eventTime)
FROM cloudtrail
WHERE eventName = 'Decrypt'
GROUP BY userIdentity.arn
ORDER BY decrypts DESC;
```

**SecOps (UDM) — land it and check for the same actor elsewhere:**

| UDM field | KMS value |
|-----------|-----------|
| `metadata.product_event_type` | `ScheduleKeyDeletion` / `Decrypt` … |
| `principal.user.userid` | `userIdentity.arn` |
| `principal.ip` | `sourceIPAddress` |
| `target.resource.name` | key ARN |

```
metadata.log_type="AWS_CLOUDTRAIL"
(metadata.product_event_type="ScheduleKeyDeletion" OR metadata.product_event_type="DisableKey" OR metadata.product_event_type="PutKeyPolicy")
```

## Respond

**Stop the destruction (if inside the window):**
```bash
aws kms cancel-key-deletion --key-id <id>      # pulls it back from PendingDeletion
aws kms enable-key --key-id <id>               # re-enable a disabled key
```

**Cut illicit access:**
```bash
aws kms revoke-grant --key-id <id> --grant-id <grantId>     # kill a rogue grant
aws kms put-key-policy --key-id <id> --policy-name default \
  --policy file://known-good-policy.json                    # restore the policy (removes external principal)
```
Then **revoke the actor's sessions** (an `ASIA` keeps working until you do → **STS → Respond**) and strip their KMS permissions.

**Preserve & assess.** Record which resources the key protected and every `Decrypt`/`encryptionContext` by the actor — that is your data-exfil scope. Rotate/re-key any secret whose wrapping key was touched.

## Fix the Misconfig / Harden

| Fix | How | Verify |
|-----|-----|--------|
| **Guardrail against deletion** | SCP denying `kms:ScheduleKeyDeletion`/`kms:DisableKey` except a break-glass role | Attempt as a normal admin → denied |
| **Longer deletion window** | Set `--pending-window-in-days 30` on important keys | `DescribeKey` shows a 30-day timer |
| **Least-privilege key policy** | Grant use to specific service roles only; keep the account-root delegation deliberate, not blanket | Simulate; no external principals present |
| **Block cross-account widening** | SCP condition denying `kms:PutKeyPolicy` that adds principals outside the org (`aws:PrincipalOrgID`) | Test policy edit → denied |
| **Enable rotation** | `enable-key-rotation` on customer-managed keys | `GetKeyRotationStatus` = true |
| **Alarm the danger ops** | EventBridge/GuardDuty + detection on `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`, `CreateGrant` | Test event triggers alert |
| **Config + multi-Region trail** | Track key config drift; ensure KMS events are captured everywhere | Config rule + trail cover all regions |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `ScheduleKeyDeletion` outside a documented decommission | Data destruction in progress — cancel now |
| `DisableKey` on a key protecting live data | Instant loss of access (ransomware) |
| `PutKeyPolicy` adding an external account / `"*"` | Cross-account decrypt — data theft |
| `CreateGrant` to an unfamiliar principal | Stealthy decrypt access |
| Fresh `CreateKey` + `ReEncrypt` of your data | Re-encrypt-to-attacker-key ransomware |
| Bulk `Decrypt` by a human principal / new IP | Data harvesting |
| `DisableKeyRotation` / `ImportKeyMaterial` unexpectedly | Weakening or key substitution |
| `Decrypt` with `encryptionContext` for data the caller never uses | Access outside normal pattern |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What KMS is and how key policy works | **What is KMS** |
| Full destruction/ransom scenario | **AWS → Playbooks → Ransomware and Data Destruction** |
| Secrets wrapped by KMS | **AWS → Data Protection → Secrets Manager** · **SSM Parameter Store** |
| Encrypted storage that breaks if a key dies | **AWS → Storage → S3 / EBS** · **Databases → RDS** |
| Who the calling principal is + session revocation | **AWS → 01 IAM & Identities** · **STS** |
| The same service in Azure | **Azure → Key Vault → Key Vault for DFIR** |

## Resources

- Deleting KMS keys (and the waiting period) — https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html
- Logging KMS API calls with CloudTrail — https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html
- Key policies & cross-account access — https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html
- Grants — https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
- Monitoring KMS (EventBridge/CloudWatch) — https://docs.aws.amazon.com/kms/latest/developerguide/monitoring-overview.html
- MITRE ATT&CK: Data Encrypted for Impact (T1486) / Data Destruction (T1485) — https://attack.mitre.org/techniques/T1486/
