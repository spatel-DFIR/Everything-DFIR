# What is Filestore?

**Filestore** is GCP's managed **NFS file storage** — a shared, POSIX-compliant file system that GCE VMs and GKE pods mount over the network, the equivalent of AWS EFS or Azure Files. Unlike Cloud Storage (an object store accessed via API calls), Filestore instances are mounted as a regular network file share — clients read/write files with ordinary filesystem calls (`open`, `read`, `write`), not `storage.objects.get`.

🔴 **The single most important DFIR fact about Filestore:** Cloud Audit Logs only record **instance-level** operations (create/delete/patch/snapshot). There is **no API-level logging of file reads, writes, deletes, or renames on the NFS share itself** — because clients never call a Google API to touch a file, they just do normal NFS I/O against the mounted export. See **The File-Operation Logging Gap** below.

## Contents

- [How It Works](#how-it-works)
- [Access Control](#access-control)
- [How to Identify Filestore in Evidence](#how-to-identify-filestore-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [The File-Operation Logging Gap](#the-file-operation-logging-gap)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- A **Filestore instance** is provisioned in a project/zone (or region, for High Scale/Enterprise tiers) with one or more **file shares**.
- Each share is exported over **NFSv3** (or NFSv4.1 for newer tiers) onto a VPC network.
- Clients — GCE VMs, GKE pods (via the Filestore CSI driver), on-prem hosts over Interconnect/VPN — **mount** the share (`mount -t nfs <ip>:/<share> /mnt/...`) and then use it like any local filesystem.
- Tiers: **Basic** (HDD/SSD), **Zonal**, **Enterprise**, **High Scale** — differ in performance/replication, not in logging behavior.
- Backups/point-in-time recovery are handled via **Filestore backups** and **snapshots**, separate resources from the instance itself.

## Access Control

| Layer | What it controls | 🔴 |
|-------|-------------------|----|
| **IAM** | Who can create/delete/patch/snapshot the *instance* (control plane) | Standard Cloud Audit Logs coverage |
| **VPC / firewall rules** | Which networks/hosts can reach the NFS port (2049) and mount the export | The real access boundary for file-level access |
| **NFS export options / POSIX permissions** | Once mounted, standard Unix UID/GID/mode bits control per-file access | 🔴 Enforced entirely on the client side — Google has no visibility into who reads what |

There is no per-file IAM or ACL layer comparable to GCS object ACLs. Whoever can mount the share and has matching POSIX permissions can read/write/delete files, invisibly to Google.

## How to Identify Filestore in Evidence

- **Resource name:** `projects/<project>/locations/<zone>/instances/<instance>`.
- **Service name in Cloud Audit Logs:** `file.googleapis.com`.
- **Config/lifecycle events (Admin Activity — always on):** `google.cloud.filestore.v1.CloudFilestoreManager.CreateInstance`, `...DeleteInstance`, `...UpdateInstance`, `...CreateSnapshot`/`...CreateBackup`.
- **No data-plane events exist for this service** — there is nothing equivalent to GCS's Data Access log category for file I/O.
- On the client side: the NFS mount shows up in `mount` output / `/etc/fstab` / `/proc/mounts` on the mounting VM, and as a `PersistentVolume` backed by the Filestore CSI driver in GKE.

## Common Operations You Will See

| methodName | What it does | 🔴 |
|-----------|--------------|----|
| `CreateInstance` | Provision a new Filestore instance/share | Baseline — confirm who/when |
| `UpdateInstance` / `PatchInstance` | Change instance config (size, network, tier) | 🔴 Network change can widen who can mount |
| `DeleteInstance` | Destroy the instance **and its data** | 🔴 Impact / anti-forensics — data is gone unless a backup/snapshot exists |
| `CreateSnapshot` / `CreateBackup` | Point-in-time copy of the share | Your acquisition path — see **Filestore for DFIR** |
| `DeleteBackup` / `DeleteSnapshot` | Remove a recovery point | 🔴 Attacker covering tracks / destroying rollback options |
| `RestoreInstance` | Restore from backup | Recovery action, also worth reviewing for legitimacy |

None of these tell you what changed *inside* the file share — only that the instance (or its snapshot/backup) was touched.

## The File-Operation Logging Gap

🔴 **This is the gap you must know about *before* the incident, not discover mid-investigation.**

| | Cloud Storage (GCS) | Filestore |
|---|---|---|
| Instance/bucket-level config changes | Admin Activity (always on) | Admin Activity (always on) |
| Individual object/file read/write/delete | **Data Access logs** (`storage.objects.get/create/delete`) — off by default, but **can be turned on** | 🔴 **Does not exist as a loggable event, at any setting.** Google never sees the NFS I/O — it's a network filesystem protocol operation between the client and the storage backend, not an API call |
| Best available file-level evidence | Enable Data Access logging | 🔴 **None from Google.** You are entirely dependent on the client (mounting VM/pod) |

Why: GCS reads/writes are always Google API calls (`storage.googleapis.com`), so Cloud Audit Logs *can* capture them if you enable Data Access. Filestore reads/writes are raw **NFS protocol** operations against a mounted export — there is no API call per file operation for Cloud Audit Logs to hook into, on any tier, with any setting enabled. This is a structural limitation, not a misconfiguration you can fix by flipping a logging toggle.

**Practical consequence:** for "who read/modified/deleted this specific file," Filestore's own logs cannot answer the question — full stop. You must fall back to:

- **Host-side evidence** on the VM(s)/pod(s) that mounted the share: filesystem timestamps (mtime/ctime/atime — note `noatime` mount option may suppress atime), auditd/`ausyscall` NFS file access rules, EDR file-access telemetry, shell history, application-level logs.
- **Filestore instance snapshots/backups** for content-level diffing between two points in time (see **Filestore for DFIR → Snapshot-Based Acquisition**).
- **VPC Flow Logs** for *who connected* to the NFS port — network-level, not file-level, but it scopes which hosts could have touched the share.

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|---------------|-----|-----------|
| Filestore | EFS (NFS) / FSx | Azure Files |
| No file-operation audit logs | EFS: no file-operation CloudTrail data events either (same structural gap) | Azure Files: Storage Analytics logging is similarly limited for SMB/NFS-level ops vs. REST API access |

🔴 This is a **cross-cloud pattern**, not a GCP-only quirk: managed NFS/SMB file services generally lack the object-store-style data-access logging that S3/GCS/Blob provide, because the protocol itself (NFS/SMB) bypasses the cloud API. Always confirm this gap exists on whichever managed file service you're investigating.

## Common Use Cases

Shared/persistent storage for workloads that need a POSIX filesystem rather than an object store: lift-and-shift NFS workloads, shared home directories, render farms, CI build caches, GKE `ReadWriteMany` persistent volumes, SAP/enterprise app file shares.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Instance** | The provisioned Filestore resource (control-plane object) |
| **File share** | The exported NFS mount point within an instance |
| **Tier** | Basic HDD/SSD, Zonal, Enterprise, High Scale — performance/replication class |
| **Snapshot** | Point-in-time, instance-local copy of the share |
| **Backup** | Region-durable, longer-retained copy of the share (survives instance deletion) |
| **Filestore CSI driver** | The GKE component that mounts a share as a `PersistentVolume` |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a Filestore case | **Filestore → Filestore for DFIR** |
| The object-storage contrast (what logging *can* look like) | **Cloud Storage → What is Cloud Storage** |
| Who could reach the NFS port | **GCP → VPC Flow Logs** |
| The VM/pod mounting the share | **GCP → Compute Engine** / **Container → GKE** |
| Audit log fundamentals | **GCP → Cloud Audit Logs** |

## Resources

- Filestore overview — https://cloud.google.com/filestore/docs/overview
- Filestore audit logging — https://cloud.google.com/filestore/docs/audit-logging
- Filestore backups — https://cloud.google.com/filestore/docs/backups
- Filestore snapshots — https://cloud.google.com/filestore/docs/snapshots
