# Playbook — Exposed S3 Bucket

The classic "leaky bucket." A bucket becomes **publicly readable** (or over-shared to another account), and sensitive data is exposed to the internet. This playbook determines **when it went public, who made it public, what was read while it was open, and how to lock it down**.

> **Tier 1 (single-service).** S3-focused; pulls in Config (timeline) and CloudTrail (actor). Read **S3 for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **GuardDuty** | `Policy:S3/BucketAnonymousAccessGranted`, `Discovery:S3/MaliciousIPCaller` |
| **AWS Config** | `s3-bucket-public-read-prohibited` non-compliant |
| **Macie** | Sensitive data in a public bucket — see **AWS → Security & Detection → Macie for DFIR** |
| **External report** | A researcher/customer found your data online |
| **Security Hub** | S3 public-access control failing |

## Hypothesis

A bucket was exposed publicly or cross-account — by accident or by an attacker. Establish the exposure window, attribute the change, quantify what was accessible and what was read, then re-privatize.

## Step-by-Step Investigation

**1. Confirm current exposure.**

```bash
aws s3api get-public-access-block   --bucket <b>   # is the safety net on?
aws s3api get-bucket-policy         --bucket <b>   # Principal:"*"? external account?
aws s3api get-bucket-acl            --bucket <b>   # AllUsers / AuthenticatedUsers grants?
```

**2. When did it go public?** Use the **Config timeline** on the bucket (before/after), or CloudTrail:

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<b> \
  --max-results 50   # look for PutBucketPolicy / PutPublicAccessBlock / PutBucketAcl
```

**3. Who exposed it?** The `userIdentity` on that event. Accident (a known admin/IaC change) vs attacker (unexpected identity/IP) changes your response.

**4. What was in the bucket?** Inventory the contents / sensitivity (PII, secrets, backups). This bounds the impact even if you can't prove reads.

**5. What was read while public?** → next section.

## Did Data Actually Leave?

| If you had… | You can determine |
|-------------|-------------------|
| **CloudTrail data events** on the bucket | Exactly which objects were read, by whom (incl. `Anonymous`), from where 🎯 |
| **S3 server access logs** | Best-effort requests (incl. anonymous) — object keys + IPs |
| **Neither** | 🔴 Only that it *was* reachable during `[went-public, re-privatized]`. Scope by content sensitivity; assume worst case |

🔴 `userIdentity: Anonymous` or an external `accountId` on data events = **confirmed** internet/cross-account reads.

## Decision Points

| Question | If yes → |
|----------|----------|
| Accident or attacker? | Attacker → run the full compromise workflow; accident → fix + review process |
| Data events available? | Prove exactly what was read; else assume worst |
| Sensitive data in the bucket? | Treat as a data-breach; notify per policy/legal |
| Cross-account (not public)? | Identify the external account; is it yours or an attacker's? |
| Presigned URLs in play? | Their GETs may not be in CloudTrail — consider them a gap |

## Contain

```bash
# Re-privatize immediately: turn ALL four public-access-block flags on
aws s3api put-public-access-block --bucket <b> --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
# Remove the public/over-shared statements from the bucket policy; remove public ACL grants
```

## Eradicate

- Remove every public/over-broad grant (policy + ACL).
- If an **attacker** made it public: cut their identity (→ IAM/Leaked Key) and hunt persistence.
- Turn on **data events** now so the next event is answerable.

## Recover

- Re-privatize + verify with Config (`s3-bucket-public-read-prohibited` compliant).
- Rotate any **secrets** that were in the exposed bucket (assume they leaked).
- Data-breach handling: legal/comms/regulatory notification if PII was exposed.
- Preserve: the exposure-change event, the exposure window, and any access-log/data-event evidence of reads.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `PutPublicAccessBlock` disabling BPA | Safety net removed |
| `PutBucketPolicy`/`PutBucketAcl` granting `*`/`AllUsers` | Bucket made public |
| Bucket policy trusting an external account | Cross-account exposure |
| Data events showing `Anonymous`/external reads | Confirmed access |
| Sensitive content + no data events | Unprovable loss — assume worst |

## References

- Related notes: **S3 for DFIR**, **Config for DFIR**, **IAM for DFIR**, **Leaked Access Key**
- Blocking public access — https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- Logging data events — https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html
- MITRE ATT&CK: Data from Cloud Storage (T1530) — https://attack.mitre.org/techniques/T1530/
