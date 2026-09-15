# What is EBS?

**EBS (Elastic Block Store)** provides the **virtual disks** attached to EC2 instances — the volumes where the OS, apps, and data live. Its defining forensic feature is the **snapshot**: a point-in-time copy of a volume, stored in S3-backed storage.

Snapshots are a double-edged sword. They're how you **image a disk for forensics** — *and* how an attacker **exfiltrates a whole disk** by sharing a snapshot to their own account.

## Contents

- [How It Works](#how-it-works)
- [Snapshots — Forensic Tool and Exfil Vector](#snapshots--forensic-tool-and-exfil-vector)
- [Encryption](#encryption)
- [How to Identify EBS in Evidence](#how-to-identify-ebs-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Volume (vol-…) attached to an instance  →  Snapshot (snap-…) = point-in-time copy
   Snapshot → new Volume (any AZ)  →  attach to a forensic instance  →  analyze on-disk
   Snapshot can also be SHARED (to an account) or made PUBLIC, and COPIED cross-region
```

- **Volumes** are AZ-scoped; **snapshots** are region-scoped and can be copied across regions/accounts.
- Snapshots are **incremental** but restore as full volumes.
- A snapshot is a **complete disk image** — everything on the volume, including secrets and unallocated data.

## Snapshots — Forensic Tool and Exfil Vector

Same feature, two very different uses:

| Use | How | Who |
|-----|-----|-----|
| **Forensic imaging** | Snapshot the victim volume → create a volume from it → attach to a clean forensic box → analyze read-only | You |
| **Disk exfiltration** | Snapshot the target volume → `ModifySnapshotAttribute` to **share it to the attacker's account** (or make public) → restore it there | 🔴 Attacker |

> 🔴 **`ModifySnapshotAttribute` adding an external account (or `all`/public) is a top-tier exfil red flag.** The attacker doesn't need to copy files out over the network — they just share the disk image and read it at leisure in their own account. Watch for it, and watch for `CreateSnapshot` immediately followed by a share.

## Encryption

| State | Meaning |
|-------|---------|
| **Encrypted volume/snapshot (SSE with KMS)** | Sharing it also requires sharing the **KMS key** — encryption limits exfil |
| **Unencrypted** | 🔴 A shared snapshot is readable by the recipient with no key |
| **Default encryption (account setting)** | Forces new volumes/snapshots to be encrypted |

> 🔴 **Encryption is a real exfil control here:** an attacker who shares an *encrypted* snapshot still can't read it without the KMS key. This is why "encrypt EBS by default + tight KMS key policies" is a meaningful hardening step, not just compliance.

## How to Identify EBS in Evidence

- **`eventSource`:** `ec2.amazonaws.com` (EBS lives under the EC2 API).
- **ARNs:** volume `arn:aws:ec2:<region>:<acct>:volume/vol-…`; snapshot `…:snapshot/snap-…`.
- **The exfil tell:** `ModifySnapshotAttribute` with `createVolumePermission` adding an `userId` (account) or `group: all`.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateSnapshot` / `CreateSnapshots` | Snapshot a volume | Normal (backups) — 🔴 if followed by a share |
| `ModifySnapshotAttribute` | Change who can access a snapshot | 🔴 share to external account / public |
| `CopySnapshot` | Copy (cross-region/account) | 🔴 staging for exfil |
| `CreateVolume` (from snapshot) | Restore a snapshot to a volume | Forensic use — or attacker restoring stolen disk |
| `DeleteSnapshot` / `DeleteVolume` | Delete | 🔴 evidence destruction |
| `DetachVolume` / `AttachVolume` | Move a volume between instances | 🔴 attaching victim disk to attacker box |
| `ResetSnapshotAttribute` | Remove sharing | Cleanup (yours or theirs) |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| EBS volume | Managed Disk | Persistent Disk |
| EBS snapshot | Disk snapshot | Disk snapshot / image |
| Share snapshot to account | Grant SAS / copy across subscription | Share image / snapshot |
| Default encryption | SSE / disk encryption | CMEK / default encryption |

## Common Use Cases

Your "normal":

- **Instance disks** — root + data volumes.
- **Backups** — scheduled snapshots (via Data Lifecycle Manager / AWS Backup).
- **Volume migration** — restore/move data between instances/AZs.
- **Golden images** — snapshots feeding AMIs.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Volume** | A virtual disk (AZ-scoped) |
| **Snapshot** | A point-in-time copy of a volume (region-scoped) |
| **`createVolumePermission`** | The snapshot attribute controlling who can restore it |
| **Encrypted volume** | KMS-encrypted at rest |
| **Default encryption** | Account setting forcing encryption |
| **DLM / AWS Backup** | Managed snapshot scheduling |
| **AMI** | A bootable image built on snapshots |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Snapshot forensics + exfil investigation | **EBS → EBS for DFIR** |
| The instances these disks attach to | **AWS → Compute → EC2** |
| Who shared/created (identity) | **AWS → 01 IAM & Identities** |
| Encryption keys | **AWS → (KMS via IAM/Storage notes)** |
| Managed exfil findings | **AWS → Security & Detection → GuardDuty** |

## Resources

- Amazon EBS — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AmazonEBS.html
- Share an EBS snapshot — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html
- EBS encryption — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
- Create EBS snapshots — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-creating-snapshot.html
