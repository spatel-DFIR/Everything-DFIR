# Playbook — S3 Data Exfiltration

An attacker **with credentials** (leaked key, stolen role, IMDS theft) reads or copies data **out** of your buckets. Unlike the exposed-bucket case, the bucket may stay private — the attacker uses *authorized* API calls. This playbook scopes what left and cuts the actor.

> **Tier 1 (single-service).** S3-focused; ties to IAM/STS (the identity) and the entry playbook. Read **S3 for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [The Exfil Techniques](#the-exfil-techniques)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Quantify the Loss](#quantify-the-loss)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **GuardDuty** | `Exfiltration:S3/ObjectRead.Unusual`, `Discovery:S3/...`, IMDS exfil finding |
| **CloudTrail / metrics** | Bulk `GetObject`/`CopyObject`; `NetworkOut` spike from an instance |
| **Cost anomaly** | Data-transfer-out charges spike |
| **Replication config change** | `PutBucketReplication` to an unknown bucket |

## Hypothesis

A credentialed actor is pulling data from S3. Identify the identity, scope which objects/buckets were read or copied, quantify the loss, and cut the actor + fix the credential source.

## The Exfil Techniques

| Technique | Signature |
|-----------|-----------|
| **Bulk download** | Many `GetObject` across keys, short time, one identity |
| **Server-side copy to attacker bucket** | `CopyObject` with an external-account destination |
| **Replication pipeline** | `PutBucketReplication` → attacker/other-account bucket (silent, ongoing) |
| **Make-public then read** | `PutBucketPolicy`/BPA-off, then anonymous reads (→ Exposed Bucket) |
| **Snapshot/DB-adjacent** | Data pulled via EBS/RDS snapshot share instead (→ those playbooks) |

## Step-by-Step Investigation

**1. Identify the actor.** From the alert: the identity/key/role and its source IP. Is it a leaked `AKIA`, a stolen role session (`ASIA`), or an instance role used externally (→ IMDS SSRF)?

**2. Pull the object-access timeline** (needs **data events**):

```sql
-- Athena over data events: bulk reads by the actor
SELECT eventtime, json_extract_scalar(requestparameters,'$.bucketName') AS bucket,
       json_extract_scalar(requestparameters,'$.key') AS key,
       cast(json_extract_scalar(additionaleventdata,'$.bytesTransferredOut') AS bigint) AS bytes_out
FROM cloudtrail_logs
WHERE eventname IN ('GetObject','CopyObject') AND useridentity.arn = '<actor-arn>'
  AND eventtime > '2026-07-09' ORDER BY eventtime;
```

**3. Check for a copy/replication pipeline.** `CopyObject` to an external destination; `PutBucketReplication` rules → foreign buckets. These exfil data without a `GetObject` per file.

**4. Confirm the destination.** External account ID on `CopyObject`/replication, or a non-AWS source IP on `GetObject` = data leaving your control.

## Quantify the Loss

| If you had… | You can say |
|-------------|-------------|
| **Data events** | Exact objects + total `bytesTransferredOut` per identity 🎯 |
| **Server access logs** | Best-effort object list + requester |
| **Only metrics** | `BytesDownloaded`/`NetworkOut` volume — *how much*, not *which* |
| **Nothing** | 🔴 Scope by what the identity's permissions *could* read; assume worst case |

> 🔴 Report honestly: without data events you often can only bound the loss by the actor's *permissions*, not prove the exact objects. That's the strongest argument for enabling data events on crown-jewel buckets.

## Decision Points

| Question | If yes → |
|----------|----------|
| Data events on? | Prove exact objects/bytes; else scope by permissions |
| Copy/replication to another account? | Data is in an account you can't reach — treat as lost; rotate secrets in it |
| IMDS/role theft the source? | Run the IMDS SSRF playbook too |
| Sensitive data (PII/secrets)? | Data-breach handling |
| Ongoing (replication rule)? | Kill the pipeline first |

## Contain

```bash
# 1. Cut the actor (deactivate key / revoke role sessions / quarantine identity)
# 2. Kill any exfil pipeline
aws s3api delete-bucket-replication --bucket <b>            # remove rogue replication
# 3. Tighten the bucket policy to your VPC/identities only; remove cross-account grants
```

## Eradicate

- Remove the actor's access + all persistence (→ Persistence Hunt).
- Delete rogue replication rules / cross-account grants.
- Fix the entry (leaked key / IMDS / privesc — route to that playbook).
- Enable **data events** if they weren't on.

## Recover

- Rotate any **secrets/credentials** contained in the exfiltrated objects.
- Data-breach process for exposed PII (legal/comms/regulatory).
- Preserve: the object-access timeline, byte counts, destination evidence, GuardDuty findings.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Bulk `GetObject` by one identity in a short window | Data exfiltration |
| `CopyObject` to an external-account bucket | Server-side exfil |
| `PutBucketReplication` to an unknown bucket | Silent, ongoing exfil pipeline |
| Instance role reading buckets from a non-AWS IP | IMDS-stolen creds exfil |
| `NetworkOut` / data-transfer cost spike | Bulk egress |
| Sensitive bucket with no data events | Unprovable loss — hardening gap |

## References

- Related notes: **S3 for DFIR**, **IMDS SSRF to Role Theft**, **Leaked Access Key**, **IAM for DFIR**
- Logging data events — https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html
- MITRE ATT&CK: Data from Cloud Storage (T1530), Transfer Data to Cloud Account (T1537) — https://attack.mitre.org/techniques/T1530/
