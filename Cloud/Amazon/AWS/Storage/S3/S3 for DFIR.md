# S3 for DFIR

S3 shows up in cases as the **thing that got exposed, exfiltrated, or ransomed** — and as the **place your logs live**. This note is how you investigate S3 access, determine what data actually left, and lock it down.

New to the service? Read **What is S3** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Three Scenarios](#investigate--three-scenarios)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Reading S3 Events](#reading-s3-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

S3 answers **"was this bucket exposed, what was read or destroyed, and by whom?"** The hard part is that the *reads* are only visible if data events (or access logs) were enabled — so scoping data loss depends entirely on prior logging.

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| **CloudTrail management events** | Bucket/policy/BPA/versioning changes + actor | ✅ On |
| **CloudTrail data events** | Object-level `GetObject`/`PutObject`/`Delete` + identity | 🔴 Off — must enable |
| **S3 server access logs** | Best-effort per-request logs (incl. some anonymous access) | Off; cheaper alt to data events |
| **Bucket state** | Current policy, ACL, BPA, versioning, replication | Live pull |
| **Object versions** | Prior/deleted object versions (if versioning on) | If enabled |

## Collect It

```bash
# Current exposure posture of a bucket
aws s3api get-bucket-policy            --bucket <b>    # who can access
aws s3api get-bucket-acl               --bucket <b>    # legacy public grants
aws s3api get-public-access-block      --bucket <b>    # is the safety net on?
aws s3api get-bucket-versioning        --bucket <b>    # ransomware/delete safety net
aws s3api get-bucket-replication       --bucket <b> 2>/dev/null  # exfil pipeline?
aws s3api get-bucket-logging           --bucket <b>    # are access logs on?

# Who touched the bucket config? (mgmt events, always available)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<b> --max-results 50
```

> **Console:** S3 → bucket → **Permissions** (policy, ACL, BPA), **Properties** (versioning, logging, replication). The bucket's *Access* column shows "Public" at a glance.

## Investigate — Three Scenarios

**1. Public exposure ("leaky bucket"):**

| Step | Do this |
|------|---------|
| 1 | Confirm current state: is BPA off? is the policy/ACL public or cross-account? |
| 2 | Find *when* it went public — **Config timeline** on the bucket, or CloudTrail `PutBucketPolicy`/`PutPublicAccessBlock`/`PutBucketAcl` |
| 3 | Identify *who* made it public (the actor on that event) — accident vs attacker |
| 4 | Determine *what was read while public* → see **Did Data Actually Leave?** |

**2. Exfiltration (attacker with creds pulling data):**

| Step | Do this |
|------|---------|
| 1 | Pull data events for the bucket: `GetObject`/`CopyObject` by the suspect identity |
| 2 | Look for **bulk reads** (many keys, short time) and **`CopyObject` to another bucket/account** |
| 3 | Check `PutBucketReplication` — a replication rule is a silent exfil pipeline |
| 4 | Quantify: sum bytes / count objects touched |

**3. Ransomware / destruction:**

| Step | Do this |
|------|---------|
| 1 | Look for mass `DeleteObject`/`PutObject` (attacker overwriting/encrypting) |
| 2 | Check if **versioning was suspended** first (`PutBucketVersioning`) — removes recovery |
| 3 | Check **KMS** — SSE-C or a new key can lock you out (see EBS/KMS patterns) |
| 4 | If versioning survived, recover from prior versions |

## Did Data Actually Leave?

The question everyone asks. Your answer depends on what was logged:

| If you had… | You can determine |
|-------------|-------------------|
| **CloudTrail data events** | Exactly which objects were read, by whom, from where 🎯 |
| **S3 server access logs** | Which objects were requested (incl. some anonymous), best-effort |
| **Neither** | 🔴 Only that the bucket *was reachable* — not what was read. Scope by *sensitivity of bucket contents* + assume worst case |

> 🔴 **Be honest in the report.** "We cannot confirm exfiltration because object-level logging was disabled" is a valid — and common — finding. It's also the strongest argument for enabling data events going forward.

## Reading S3 Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The operation | `GetObject` bulk, `PutBucketPolicy`, `DeleteObject` mass |
| `userIdentity` | Who | Anonymous (`Anonymous`)? external account? |
| `requestParameters.bucketName` + `.key` | Which object | Crown-jewel keys |
| `sourceIPAddress` | From where | External IP; not your VPC |
| `additionalEventData.bytesTransferredOut` | How much left | Big = exfil |
| `requestParameters.x-amz-server-side-encryption-*` | Encryption used | SSE-C / new KMS = ransomware tell |

> 🔴 `userIdentity` showing **`Anonymous`** or an **external `accountId`** on data events means the internet or another account read your objects — direct exposure proof.

## Hunt at Scale

**In-platform — Athena over data events (or a data-events table):**

```sql
-- Bulk object reads by identity (exfil hunt)
SELECT useridentity.arn, count(*) AS gets,
       sum(cast(json_extract_scalar(additionaleventdata,'$.bytesTransferredOut') AS bigint)) AS bytes_out
FROM cloudtrail_logs
WHERE eventname = 'GetObject' AND json_extract_scalar(requestparameters,'$.bucketName') = 'crown-jewels'
  AND eventtime > '2026-07-09'
GROUP BY useridentity.arn ORDER BY gets DESC;

-- Who made buckets public / cross-account?
SELECT eventtime, useridentity.arn, eventname,
       json_extract_scalar(requestparameters,'$.bucketName') AS bucket
FROM cloudtrail_logs
WHERE eventname IN ('PutBucketPolicy','PutBucketAcl','PutPublicAccessBlock')
  AND eventtime > '2026-07-01' ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "PutBucketPolicy" OR metadata.product_event_type = "GetObject"
```

## Respond

| Goal | Action |
|------|--------|
| Re-privatize immediately | `aws s3api put-public-access-block` (all four flags `true`); remove public policy/ACL grants |
| Cut cross-account/attacker access | Remove the offending `PutBucketPolicy` statements |
| Kill an exfil pipeline | Delete rogue replication rules |
| Stop destruction / enable recovery | Re-enable versioning; enable Object Lock on critical buckets |
| Preserve evidence | Copy relevant logs/objects out; **snapshot bucket policy + object versions** before changes |
| Contain the identity | Deactivate key / revoke sessions (→ IAM / STS for DFIR) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Account-level Block Public Access = ON** | No bucket can be made public by accident |
| **Enable data events** on crown-jewel buckets/prefixes | You can answer "what left" next time |
| **Versioning + Object Lock (compliance mode)** on critical buckets | Ransomware/delete-proof |
| **SSE-KMS** with tight key policies; deny SSE-C | Prevents attacker-controlled encryption |
| **`aws:SecureTransport` + `aws:SourceVpce` conditions** in bucket policies | Only your VPC/TLS reaches the data |
| **Macie** on sensitive buckets | Flags exposed PII/secrets — see **AWS → Security & Detection → Macie for DFIR** |
| **SCP/alert** on `PutPublicAccessBlock`(off), `PutBucketPolicy`, `PutBucketVersioning`(suspend) | Catch exposure/ransomware setup live |
| **Lifecycle**: don't auto-expire security logs; lock the log bucket | Evidence survives |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `PutPublicAccessBlock` disabling BPA | Safety net removed — exposure incoming |
| `PutBucketPolicy`/`PutBucketAcl` granting `*`/`AllUsers` | Bucket made public |
| Bucket policy trusting an external account | Cross-account exfil path |
| Data events showing `Anonymous`/external reads | Confirmed exposure/exfil |
| Bulk `GetObject`/`CopyObject` by one identity | Data exfiltration |
| `PutBucketReplication` to an unknown bucket | Silent exfil pipeline |
| `PutBucketVersioning` suspend + mass `DeleteObject`/`PutObject` | Ransomware / destruction |
| Data events not enabled on a sensitive bucket | Can't scope loss — hardening gap |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What S3 is + access layers | **S3 → What is S3** |
| Exposed-bucket walk-through | **S3 → Playbooks → Exposed S3 Bucket** |
| Exfiltration walk-through | **S3 → Playbooks → S3 Data Exfiltration** |
| Who did it (identity) | **AWS → 01 IAM & Identities**, **IAM for DFIR** |
| When it changed (timeline) | **AWS → Security & Detection → Config** |
| Managed exfil/exposure findings | **AWS → Security & Detection → GuardDuty** |
| What sensitive data was actually in the exposed bucket | **AWS → Security & Detection → Macie for DFIR** |
| The KMS key protecting the objects (SSE-KMS / ransom) | **AWS → Data Protection → KMS** |

## Resources

- Logging data events for S3 — https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html
- Blocking public access — https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- Using S3 Object Lock — https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- S3 security best practices — https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- MITRE ATT&CK: Data from Cloud Storage (T1530) — https://attack.mitre.org/techniques/T1530/
