# What is Azure Storage?

**Azure Storage** is Azure's object/file store. Its most DFIR-relevant part is **Blob storage** — the Azure equivalent of **S3** — plus **Files, Queues, and Tables**. It holds backups, logs, app data, and datasets, which makes it a prime **exfiltration** and **public-exposure** target.

The recurring Azure storage incident is the same as the AWS "leaky bucket": a **container made publicly readable**, or over-shared via a **SAS token**.

## Contents

- [How It Works](#how-it-works)
- [The Four Services in a Storage Account](#the-four-services-in-a-storage-account)
- [The Four Ways to Access Storage — and Their Risks](#the-four-ways-to-access-storage--and-their-risks)
- [Public Access — The Leaky-Container Problem](#public-access--the-leaky-container-problem)
- [SAS Tokens — The Sneaky Exposure](#sas-tokens--the-sneaky-exposure)
- [The Data-Plane Logging Catch](#the-data-plane-logging-catch)
- [How to Identify Storage in Evidence](#how-to-identify-storage-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

A **storage account** contains services; **Blob** stores objects in **containers**. Access is controlled by account **keys**, **SAS tokens**, **Entra RBAC (data roles)**, or **anonymous public access**.

```
Storage account → Blob service → Container → Blob (object)
Access via: account keys | SAS token | Entra RBAC data role | anonymous public
```

## The Four Services in a Storage Account

| Service | Holds | DFIR note |
|---------|-------|-----------|
| **Blob** | Objects (files, backups, logs) | The S3 analog; main exfil/exposure target |
| **Files** | SMB/NFS file shares | Lateral movement, share access |
| **Queues** | Messages | Rarely primary, but data can leak |
| **Tables** | NoSQL key-value | App data |

## The Four Ways to Access Storage — and Their Risks

🔴 Know these — each has a different theft path and a different log tell:

| Method | What it is | 🔴 Risk |
|--------|-----------|---------|
| **Account keys** | Two all-powerful keys per account | Full access; leak = total compromise; `listKeys` grabs them |
| **SAS token** | A signed URL granting scoped, time-boxed access | Leaks in code/links; often over-broad + long-lived; **hard to revoke** |
| **Entra RBAC (data roles)** | e.g. Storage Blob Data Reader/Contributor | The good way — auditable, revocable |
| **Anonymous public access** | Container set to public read | 🔴 The "leaky container" — no auth at all |

## Public Access — The Leaky-Container Problem

A container's public-access level:

| Level | Who can read |
|-------|--------------|
| **Private** | Only authorized (keys/SAS/RBAC) — the safe default |
| **Blob** | 🔴 Anyone, anonymously, if they know the blob URL |
| **Container** | 🔴 Anyone can **list + read** every blob |

> 🔴 `Container`-level public access is the worst: an attacker who finds the account name can **enumerate and download everything**. This is the direct Azure equivalent of a public S3 bucket. **Storage accounts also have an account-level "allow blob public access" switch** — disabling it neutralizes all container public settings at once.

## SAS Tokens — The Sneaky Exposure

A **Shared Access Signature** is a signed URL: `https://acct.blob.core.windows.net/container/blob?sv=...&sig=...`. It grants whatever it was signed for.

🔴 Why they're dangerous on a case:
- They **bypass RBAC** — anyone with the URL has access, no sign-in.
- They're often **over-scoped** (whole account) and **long-lived** (years).
- **Account-key-signed SAS can't be individually revoked** — you must **rotate the account key** to kill them all.
- Their use may **not appear** in control-plane logs — you need **storage data-plane logging**.

## The Data-Plane Logging Catch

Same blind spot as everywhere in Azure:

| Plane | Logged | Example |
|-------|--------|---------|
| **Control plane** (Activity Log, default on) | ✅ | Create account, `listKeys`, change public access |
| **Data plane** (Storage diagnostic logs, **OFF by default**) | 🔴 | Read/download a **blob** (`GetBlob`) |

> 🔴 Without **storage diagnostic logging** (`StorageRead`/`StorageWrite`) enabled and sent to Log Analytics, you can see the container was *made* public but **not which blobs were downloaded** — the exfil blind spot. Turn it on for sensitive accounts.

## How to Identify Storage in Evidence

- **Resource ID:** `/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<name>`.
- **Blob URL:** `https://<account>.blob.core.windows.net/<container>/<blob>`.
- **Activity Log:** `Microsoft.Storage/storageAccounts/*`.
- **Data-plane:** `StorageBlobLogs` (Log Analytics) if enabled.

## Common Operations You Will See

| Operation | 🔴 Watch |
|-----------|---------|
| `storageAccounts/listKeys/action` | Grabbing account keys |
| `storageAccounts/write` (public access on) | Exposure |
| `blobServices/containers/write` (public level) | Container made public |
| `GetBlob` / `ListBlobs` (data plane) | Reads / enumeration |
| `storageAccounts/regenerateKey` | Key rotation (yours, or attacker locking you out) |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Blob Storage | S3 | Cloud Storage (GCS) |
| Container | Bucket | Bucket |
| SAS token | Presigned URL | Signed URL |
| Account key | (root-ish access key) | HMAC key |
| Anonymous public access | S3 public bucket/object | GCS public object |
| Storage diagnostic logs | S3 data events | Data Access logs |

## Key Terminology

| Term | Meaning |
|------|---------|
| **Storage account** | The top-level storage container |
| **Container** | A blob namespace (like an S3 bucket) |
| **Blob** | An object |
| **Account key** | An all-powerful account credential |
| **SAS token** | A signed, scoped, time-boxed access URL |
| **Public access level** | Private / Blob / Container |
| **Data-plane logging** | Diagnostic logs for reads/writes |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating storage exposure/exfil | **Storage → for DFIR** |
| The control-plane log | **Azure → Activity Log** |
| Who accessed it (identity/key/SAS) | **Microsoft → 01 Entra ID & Identities** |
| The exposed-container scenario | **Storage → Playbooks → Exposed Blob Container** |

## Resources

- Blob storage overview — https://learn.microsoft.com/azure/storage/blobs/storage-blobs-introduction
- Prevent anonymous public access — https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent
- SAS overview — https://learn.microsoft.com/azure/storage/common/storage-sas-overview
- Storage monitoring/logs — https://learn.microsoft.com/azure/storage/blobs/monitor-blob-storage
