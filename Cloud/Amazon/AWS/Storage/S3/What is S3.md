# What is S3?

**S3 (Simple Storage Service)** is AWS's **object storage** — files ("objects") in **buckets**. It holds everything: backups, data lakes, static websites, app assets, and — critically — **CloudTrail's own logs**.

S3 is the **#1 data-exfiltration target** in AWS, the usual **ransomware** target, and the source of countless **public-bucket** breaches. It's also where much of your *evidence* lives. You'll investigate S3 both as a victim and as a log store.

## Contents

- [How It Works](#how-it-works)
- [How Access Is Controlled (Four Layers)](#how-access-is-controlled-four-layers)
- [Public vs Private — Where Breaches Come From](#public-vs-private--where-breaches-come-from)
- [The Logging Gotcha — Data Events](#the-logging-gotcha--data-events)
- [How to Identify S3 in Evidence](#how-to-identify-s3-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Bucket (globally-unique name, lives in ONE region)
  └── Object (a file) — identified by its KEY (path-like: reports/q3/data.csv)
        ├── versions (if versioning on)
        ├── metadata + tags
        └── storage class (Standard, IA, Glacier…)
```

- **Bucket names are globally unique** across all of AWS; the bucket lives in one region but the namespace is global.
- Objects are retrieved by **key** (the "path"). There are no real folders — the `/` in a key is just a convention.
- S3 is **strongly consistent** and extremely durable; it's regional per bucket.

## How Access Is Controlled (Four Layers)

Access to an object is the **combination** of four things. To understand *why something was reachable*, check all four:

| Layer | What it is | 🔴 Attack angle |
|-------|-----------|-----------------|
| **IAM policies** | What an identity is allowed to do to S3 | Over-broad `s3:*` grants |
| **Bucket policy** | Resource-based policy on the bucket (incl. cross-account & public) | 🔴 `Principal:"*"` = public; cross-account to attacker |
| **ACLs** (legacy) | Per-bucket/object grants | 🔴 `AllUsers`/`AuthenticatedUsers` grant = public |
| **Block Public Access (BPA)** | A master switch that *overrides* policy/ACL to keep buckets private | 🔴 Disabling BPA is the precursor to exposure |

> **Block Public Access is the safety net.** When on (account- or bucket-level), it blocks public grants regardless of policy/ACL. 🔴 A `PutPublicAccessBlock` that *disables* it, followed by a permissive `PutBucketPolicy`, is the classic "make it public" sequence.

## Public vs Private — Where Breaches Come From

The infamous "leaky S3 bucket" happens one of these ways:

| Cause | Signature |
|-------|-----------|
| BPA disabled + public bucket policy | `PutPublicAccessBlock` (off) → `PutBucketPolicy` (`Principal:*`) |
| Public ACL grant | `PutBucketAcl` / `PutObjectAcl` granting `AllUsers` |
| Over-broad cross-account policy | `PutBucketPolicy` trusting an external/attacker account |
| Presigned URL abuse | A long-lived presigned URL leaked (no CloudTrail on the GET itself) |
| Static website hosting misread as "safe public" | Whole bucket world-readable |

> 🔴 Public exposure often **isn't** an "attack" event in CloudTrail at all — the *exposure* is the `PutBucketPolicy`/`PutPublicAccessBlock`, but the *reads by the internet* only show up if **data events** are enabled. That's the next section.

## The Logging Gotcha — Data Events

This is the single most important S3-forensics fact:

| Event class | Example | Logged by default? |
|-------------|---------|--------------------|
| **Management** (control plane) | `CreateBucket`, `PutBucketPolicy`, `DeleteBucket` | ✅ Yes |
| **Data** (data plane) | `GetObject`, `PutObject`, `DeleteObject` | 🔴 **No** — must enable data events |

> 🔴 **Without S3 data events, you can prove someone made a bucket public but NOT which objects the internet (or the attacker) read.** "What was exfiltrated?" is unanswerable unless data events (or **server access logs**) were on beforehand. Enable data events on crown-jewel buckets *now* — it's the difference between "we were exposed" and "here's exactly what left."

**Two ways to log object access:**

| Source | What it gives | Trade-off |
|--------|---------------|-----------|
| **CloudTrail data events** | Rich, identity-attributed object access | Extra cost; must enable per bucket/prefix |
| **S3 server access logs** | Best-effort request logs to another bucket | Cheaper, but delayed, less structured, no identity richness |

## How to Identify S3 in Evidence

**ARNs (blank region AND account — S3 is a global namespace):**

| Thing | ARN shape |
|-------|-----------|
| Bucket | `arn:aws:s3:::my-bucket` |
| Object | `arn:aws:s3:::my-bucket/reports/q3.csv` |
| Access point | `arn:aws:s3:us-east-1:<acct>:accesspoint/<name>` |

- **`eventSource`:** `s3.amazonaws.com`.
- **In a data event**, the object is in `requestParameters.bucketName` + `requestParameters.key`.

## Common Operations You Will See

| Operation | Class | What it does | Watch? |
|-----------|-------|--------------|--------|
| `CreateBucket` / `DeleteBucket` | Mgmt | Create/remove a bucket | 🔴 delete = data destruction |
| `PutBucketPolicy` / `PutBucketAcl` | Mgmt | Change who can access | 🔴 public/cross-account |
| `PutPublicAccessBlock` (disable) | Mgmt | Remove the public-access safety net | 🔴 precursor to exposure |
| `GetObject` / `HeadObject` | Data | Read an object | 🔴 bulk = exfil (if logged) |
| `PutObject` | Data | Write an object | 🔴 mass writes = ransomware |
| `DeleteObject` / `DeleteObjects` | Data | Delete objects | 🔴 destruction / ransomware |
| `CopyObject` | Data | Server-side copy | 🔴 exfil to attacker bucket |
| `PutBucketVersioning` (suspend) | Mgmt | Turn off versioning | 🔴 removes the ransomware safety net |
| `PutBucketReplication` | Mgmt | Replicate to another bucket | 🔴 exfil pipeline |
| `PutBucketLifecycle` | Mgmt | Auto-expire objects | 🔴 evidence expiry |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| S3 bucket | Blob container (Storage Account) | Cloud Storage bucket |
| Object / key | Blob | Object |
| Bucket policy | Container/account access policy | Bucket IAM policy |
| Block Public Access | "Allow blob public access" toggle | Public access prevention |
| Data events | Storage diagnostic logs | Data Access audit logs |

## Common Use Cases

Your "normal":

- **Backups, data lakes, app assets, static sites.**
- **Log storage** — CloudTrail, Config, VPC Flow, ELB logs all land in S3.
- **Data pipelines** — cross-account/cross-region replication.
- **Presigned URLs** — temporary object access for apps.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Bucket** | A container of objects (globally-unique name, one region) |
| **Object / key** | A stored file / its path-like identifier |
| **Block Public Access (BPA)** | The master switch overriding policy/ACL to stay private |
| **Bucket policy** | Resource-based policy (cross-account/public capable) |
| **ACL** | Legacy per-bucket/object grants |
| **Versioning** | Keeps old object versions (ransomware/delete safety net) |
| **Data event** | CloudTrail logging of object-level access (off by default) |
| **Server access logs** | Best-effort per-request S3 logs |
| **Presigned URL** | A time-limited signed link to an object |
| **Access point** | A named endpoint with its own policy |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating S3 abuse | **S3 → S3 for DFIR** |
| Exposed-bucket scenario | **S3 → Playbooks → Exposed S3 Bucket** |
| Exfiltration scenario | **S3 → Playbooks → S3 Data Exfiltration** |
| The audit log + data events | **AWS → Logging & Monitoring → CloudTrail** |
| The identities doing the access | **AWS → 01 IAM & Identities** |
| When the bucket went public (timeline) | **AWS → Security & Detection → Config** |

## Resources

- What is S3 — https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html
- Blocking public access — https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- Logging data events — https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html
- Server access logging — https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html
- S3 security best practices — https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
