# Playbook — Ransomware & Data Destruction

An attacker with sufficient permissions **encrypts or deletes your data** and demands payment — or just destroys to cause damage. In AWS this rarely looks like on-host ransomware; it's **cloud-native**: re-encrypting S3 with a key you don't control, deleting snapshots/backups, or KMS key sabotage.

> **Tier 2 (cross-service).** Touches S3, EBS, RDS, KMS, IAM, CloudTrail. Read **S3 for DFIR**, **EBS for DFIR**, **RDS for DFIR**.

## Contents

- [Attack Chain](#attack-chain)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Attack Chain

```
Attacker gains data-plane access (stolen creds / over-broad role)
   → removes the safety nets FIRST: suspend S3 versioning, delete snapshots/backups,
     disable deletion protection
   → destroys/encrypts:
       • S3: overwrite objects with attacker-KMS/SSE-C encryption, or DeleteObject en masse
       • EBS/RDS: delete volumes/snapshots; DeleteDBInstance (skip final snapshot)
       • KMS: ScheduleKeyDeletion / DisableKey / edit key policy → data unreadable
   → ransom note (often a new S3 object / bucket name)
```

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **App outage** | Data suddenly unreadable / missing |
| **A ransom note** | An object/bucket named `READ_ME` / `RECOVER_YOUR_FILES` |
| **GuardDuty / CloudWatch** | Mass delete/put; `S3` object-tampering; metrics drop |
| **Backup failures** | Snapshots/backups gone |
| **KMS alarms** | Key disabled / scheduled for deletion |

## Hypothesis

An attacker with data-plane access is destroying or locking data and likely disabled recovery first. Confirm scope, **preserve what remains**, identify what's recoverable, and cut the actor.

## Step-by-Step Investigation

**1. Confirm the destruction method and scope.** Timeline the actor's data-plane events (→ S3/EBS/RDS for DFIR):
- S3: `DeleteObject`/`DeleteObjects`, `PutObject` with `x-amz-server-side-encryption-customer-*` (SSE-C) or a foreign KMS key.
- EBS/RDS: `DeleteSnapshot`, `DeleteVolume`, `DeleteDBInstance`.
- KMS: `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`.

**2. Check whether the safety nets were removed first** (the tell that this was deliberate):
- `PutBucketVersioning` (Suspended)
- `DeleteBackupVault` / backup deletions
- `ModifyDBInstance` disabling deletion protection

**3. Determine what's recoverable.**
- S3 **versioning on**? Prior versions may survive `DeleteObject` (adds a delete marker, doesn't erase). Check for **noncurrent versions**.
- **Object Lock / MFA-delete**? Objects may be immune.
- EBS/RDS **automated backups** in another vault/account?
- **AWS Backup** copies, cross-region/cross-account?

**4. KMS check.** If a key was scheduled for deletion, there's a **waiting period (7–30 days)** — you can **cancel** the deletion and recover. This is time-critical.

**5. Identify the actor + entry.** Who did it, from where, with what creds → route to the entry playbook (leaked key / privesc / SSO).

## Decision Points

| Question | If yes → |
|----------|----------|
| Was a KMS key scheduled for deletion? | 🔴 **Cancel it immediately** — recovery window is closing |
| Is S3 versioning/Object Lock on? | Recover from prior versions before anything else |
| Were backups deleted? | Check other vaults/accounts/regions; AWS Backup |
| Safety nets removed first? | Deliberate ransomware — full IR, not accident |
| Should you pay? | Business/legal/law-enforcement decision — recovery from backups is the goal |

## Contain

```bash
# 1. Cut the actor's access NOW (deactivate key / revoke sessions / quarantine identity)

# 2. CANCEL any pending KMS key deletion (time-critical recovery)
aws kms cancel-key-deletion --key-id <key-id>
aws kms enable-key --key-id <key-id>

# 3. Stop further destruction: lock bucket policies, remove the actor's data-plane permissions,
#    enable deletion protection on remaining resources
```

> 🔴 **Preserve before you clean.** Snapshot the *current* (damaged) state and export logs — you need the evidence and may need to prove what was lost.

## Eradicate

- Remove the actor's access and **all** persistence (→ IAM for DFIR).
- Re-secure KMS key policies; re-enable keys wrongly disabled.
- Fix the entry vector (leaked key / privesc / exposed service).

## Recover

- Restore data from the **best surviving source**: S3 prior versions / Object Lock copies, EBS/RDS backups, AWS Backup, cross-account copies.
- Rebuild affected services.
- **Report** to leadership/legal; engage law enforcement if extortion is involved; contact AWS Support.
- Preserve the full timeline (who deleted what, when) for the record.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `PutBucketVersioning` Suspended, then mass `DeleteObject`/`PutObject` | Ransomware disabling recovery first |
| S3 `PutObject` with SSE-C / foreign KMS key | Attacker-controlled encryption |
| `ScheduleKeyDeletion` / `DisableKey` / `PutKeyPolicy` | KMS sabotage — data lock |
| `DeleteSnapshot` / `DeleteDBInstance` (skip final) | Backup/DB destruction |
| Backup vault deletions | Removing recovery |
| A `READ_ME`/ransom object appearing | Extortion note |

## References

- Related notes: **S3 for DFIR**, **EBS for DFIR**, **RDS for DFIR**, **IAM for DFIR**, **KMS for DFIR** (key deletion/policy sabotage in depth)
- S3 Object Lock — https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- Cancel KMS key deletion — https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html
- AWS Backup — https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html
- MITRE ATT&CK: Data Destruction (T1485) / Data Encrypted for Impact (T1486) — https://attack.mitre.org/techniques/T1485/
