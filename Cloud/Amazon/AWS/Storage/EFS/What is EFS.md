# What is EFS?

**EFS (Elastic File System)** is AWS's **managed NFS** — a shared filesystem that many EC2 instances (and Lambda/ECS) can mount at once over the network. Where EBS is a disk for *one* instance and S3 is object storage, EFS is a **POSIX filesystem shared across many hosts**.

For DFIR, EFS matters as a **shared data store** (whatever sensitive files live on it are reachable by every host that can mount it) and because its exposure is governed by **network reach (mount targets + security groups)**, not a bucket policy.

## Contents

- [How It Works](#how-it-works)
- [How Access Is Controlled](#how-access-is-controlled)
- [How to Identify EFS in Evidence](#how-to-identify-efs-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
File system (fs-…)  →  Mount targets (one per subnet/AZ, each with a security group)
   → instances in the VPC mount it via NFS (nfs://…:/) → shared POSIX files
   → Access points impose a user/path per application
```

- **Regional**, spanning AZs via **mount targets** (an ENI per subnet).
- Accessed over **NFS (port 2049)** from within the VPC — reach is a *network* question.
- Encrypted at rest (KMS) and, optionally, in transit (TLS).

## How Access Is Controlled

Unlike S3, EFS exposure is mostly about **who can reach the mount target on the network**:

| Layer | Controls | 🔴 Risk |
|-------|----------|---------|
| **Mount-target security group** | Which hosts can reach NFS/2049 | 🔴 SG open to a wide CIDR = any compromised host mounts it |
| **File system policy** (resource policy) | IAM-level mount/root controls | Over-broad = cross-account/broad mount |
| **Access points** | Enforce a POSIX user + root directory per app | Bypassed/over-privileged AP = broad file access |
| **POSIX permissions** | Standard file ownership/mode on the data | Same as any Unix FS |

> 🔴 The EFS exposure question is usually **"which security groups/subnets can reach the mount targets, and is any of that too wide?"** A compromised instance that can mount EFS reads *all* the shared data its POSIX access allows.

## How to Identify EFS in Evidence

- **`eventSource`:** `elasticfilesystem.amazonaws.com`.
- **ARNs:** `arn:aws:elasticfilesystem:<region>:<acct>:file-system/fs-…`.
- **Data access is NFS**, not an AWS API — so file reads/writes are **not in CloudTrail**; you rely on host-side and network evidence.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateFileSystem` / `DeleteFileSystem` | Create/remove an FS | 🔴 delete = data destruction |
| `CreateMountTarget` | Expose the FS in a subnet | 🔴 new reachability |
| `ModifyMountTargetSecurityGroups` | Change who can reach NFS | 🔴 widening access |
| `PutFileSystemPolicy` | Set the resource policy | 🔴 cross-account/broad mount |
| `CreateAccessPoint` | Add an enforced user/path | 🔴 over-privileged AP |
| `PutBackupPolicy` / AWS Backup | Backups of the FS | Recovery / potential exfil via backup share |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| EFS | Azure Files (NFS/SMB) | Filestore |
| Mount target | Private endpoint / share | Filestore instance |
| Access point | — | — |
| File system policy | Storage account network rules | IAM on Filestore |

## Common Use Cases

Your "normal":

- **Shared application data** across a fleet (CMS uploads, home dirs, shared config).
- **Container/Lambda shared storage.**
- **Lift-and-shift** apps expecting a POSIX filesystem.

## Key Terminology

| Term | Meaning |
|------|---------|
| **File system (fs-…)** | The EFS instance |
| **Mount target** | Per-subnet ENI + SG exposing NFS |
| **Access point** | Enforced POSIX user + root dir per app |
| **File system policy** | Resource policy for mount/root controls |
| **NFS (2049)** | The protocol/port hosts mount over |
| **Encryption in transit** | Optional TLS for NFS |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating EFS access/exposure | **EFS → EFS for DFIR** |
| The hosts that mount it | **AWS → Compute → EC2** |
| The network reach (SGs/subnets) | **AWS → Networking → VPC** |
| Object-storage exfil (contrast) | **AWS → Storage → S3** |

## Resources

- What is EFS — https://docs.aws.amazon.com/efs/latest/ug/whatisefs.html
- EFS security (SGs, policy) — https://docs.aws.amazon.com/efs/latest/ug/security-considerations.html
- Access points — https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html
- Logging with CloudTrail — https://docs.aws.amazon.com/efs/latest/ug/logging-using-cloudtrail.html
