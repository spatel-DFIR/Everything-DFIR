# What is Cloud Storage (GCS)?

**Cloud Storage (GCS)** is GCP's object store — buckets of objects (files), the equivalent of AWS S3 and Azure Blob Storage. It's the #1 GCP **data-exposure and exfiltration** surface: a bucket made public, or objects pulled by a stolen credential.

## Contents

- [How It Works](#how-it-works)
- [Access Control — IAM vs ACLs](#access-control--iam-vs-acls)
- [How Buckets Become Public](#how-buckets-become-public)
- [How to Identify GCS in Evidence](#how-to-identify-gcs-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [The Data-Access Logging Gap](#the-data-access-logging-gap)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- A **bucket** (globally unique name) holds **objects**; buckets live in a project.
- Access is controlled by **IAM** (bucket/project level) and/or **ACLs** (per-object, legacy).
- **Object reads/writes** are data-plane; **bucket config** (IAM, public settings) is control-plane.

## Access Control — IAM vs ACLs

| Model | What it is | 🔴 |
|-------|-----------|----|
| **Uniform bucket-level access (IAM)** | IAM only, no per-object ACLs (recommended) | Cleaner to audit |
| **Fine-grained (ACLs)** | Per-object ACLs *plus* IAM | 🔴 Easy to mis-share a single object publicly |
| **Public via IAM** | `allUsers` / `allAuthenticatedUsers` as a member | 🔴 Internet-readable |

## How Buckets Become Public

🔴 A bucket/object is exposed when:

| Change | Result |
|--------|--------|
| IAM binding adds **`allUsers`** (any role, e.g. `storage.objectViewer`) | Anyone on the internet can read |
| IAM binding adds **`allAuthenticatedUsers`** | Any Google account can read |
| Object **ACL** grants `allUsers` | That object is public |
| **Public Access Prevention** disabled | The above becomes possible |

## How to Identify GCS in Evidence

- **Resource name:** `//storage.googleapis.com/projects/_/buckets/<bucket>` (buckets are global → `_`).
- **Config events (Admin Activity):** `storage.setIamPermissions`, `storage.buckets.update`.
- **Data events (Data Access, if enabled):** `storage.objects.get`, `storage.objects.list`, `storage.objects.create`.
- **`principalEmail` = `allUsers`/anonymous** on a read = public access occurred.

## Common Operations You Will See

| methodName | What it does | 🔴 |
|-----------|--------------|----|
| `storage.setIamPermissions` | Change bucket/object IAM | 🔴 add `allUsers` = public |
| `storage.buckets.update` | Change bucket config (PAP, logging) | 🔴 disable public-access prevention |
| `storage.objects.get` | Read an object | 🔴 at volume / anonymous = exfil |
| `storage.objects.list` | Enumerate objects | Recon |
| `storage.objects.create/delete` | Write/delete | 🔴 tamper / ransomware |
| `storage.buckets.delete` | Delete a bucket | 🔴 destruction |

## The Data-Access Logging Gap

🔴 **`storage.objects.get` (reads) are Data Access logs — OFF by default.** Without them, you can prove a bucket *was* public (config event) but **not which objects were read**. Enable `DATA_READ` for Storage on sensitive projects; otherwise scope by content sensitivity and assume worst case. This is the GCP twin of the S3-without-data-events blind spot.

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Cloud Storage (GCS) | S3 | Blob Storage |
| Bucket | Bucket | Container |
| `allUsers` public | Public ACL / bucket policy `*` | Anonymous/public container |
| Public Access Prevention | S3 Block Public Access | Storage public-access disabled |
| Data Access logs | S3 data events | Storage diagnostic logs |
| Signed URL | Presigned URL | SAS token |

## Common Use Cases

Your "normal": app data, backups, static assets, data-lake staging. Some buckets are *intentionally* public (a website's assets). The job is to spot **unintended** exposure of sensitive data and **abnormal reads**.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Bucket / object** | Container / file |
| **Uniform bucket-level access** | IAM-only access (no ACLs) |
| **ACL** | Legacy per-object access grant |
| **Public Access Prevention (PAP)** | Blocks public exposure |
| **`allUsers` / `allAuthenticatedUsers`** | The public IAM members |
| **Signed URL** | Time-limited object access link |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating GCS exposure/exfil | **Cloud Storage → for DFIR** |
| The public-bucket scenario | **Cloud Storage → Playbooks → Public GCS Bucket** |
| Who touched the bucket | **GCP → Cloud Audit Logs** · **Google → 01 Identities** |
| The guardrail that blocks it | **GCP → Organization Policy** |

## Resources

- Cloud Storage overview — https://cloud.google.com/storage/docs/introduction
- Public access prevention — https://cloud.google.com/storage/docs/public-access-prevention
- Uniform bucket-level access — https://cloud.google.com/storage/docs/uniform-bucket-level-access
- Storage audit logging — https://cloud.google.com/storage/docs/audit-logging
