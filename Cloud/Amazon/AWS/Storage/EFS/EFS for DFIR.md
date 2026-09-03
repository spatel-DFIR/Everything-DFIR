# EFS for DFIR

EFS investigations hinge on one thing CloudTrail can't see: **file access happens over NFS, not an AWS API.** So you scope EFS by **who could mount it** (network + policy) and confirm activity from the **host and network** sides.

New to the service? Read **What is EFS** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate](#investigate)
- [Reading the Events](#reading-the-events)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

EFS answers **"what shared data could a compromised host reach, and did anyone widen that reach?"** Because reads/writes are NFS, the control-plane evidence is about *exposure changes*, and the data-access evidence is *host-side*.

## Evidence It Produces

| Evidence | Gives you | Where |
|----------|-----------|-------|
| CloudTrail `elasticfilesystem.*` | FS/mount-target/policy/AP changes + actor | CloudTrail (control plane only) |
| Mount-target SGs + subnets | Who can reach NFS | `describe-mount-targets` |
| File system policy + access points | IAM-level mount/root controls | API / console |
| **Host-side NFS activity** | Actual file reads/writes | The mounting instances' OS logs / disk (→ EC2) |
| **VPC Flow Logs** | Traffic to mount targets on 2049 | → VPC Flow Logs |

## Collect It

```bash
# The file systems and their exposure
aws efs describe-file-systems --query 'FileSystems[].{Id:FileSystemId,Name:Name,Enc:Encrypted}'
aws efs describe-mount-targets --file-system-id fs-0abc123
aws efs describe-mount-target-security-groups --mount-target-id fsmt-0abc123   # 🔴 who can reach NFS
aws efs describe-file-system-policy --file-system-id fs-0abc123 2>/dev/null
aws efs describe-access-points --file-system-id fs-0abc123

# Who changed EFS exposure?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyMountTargetSecurityGroups --max-results 30
```

> **Console:** EFS → file system → **Network** (mount targets + SGs), **File system policy**, **Access points**.

## Investigate

| Step | Do this |
|------|---------|
| 1. Map reach | Which subnets/SGs can hit the mount targets on 2049? Is any of it too wide? |
| 2. Config changes | `ModifyMountTargetSecurityGroups`, `PutFileSystemPolicy`, `CreateMountTarget`, `CreateAccessPoint` in the window |
| 3. Identify who could mount | Every instance in a subnet+SG with NFS reach — a compromised one of those read the data |
| 4. Host-side confirm | On the suspected mounting host(s), check mounts (`/proc/mounts`), NFS access, and disk artifacts (→ EC2 snapshot forensics) |
| 5. Network confirm | VPC Flow Logs: unexpected sources connecting to mount targets on 2049 |

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The action | `ModifyMountTargetSecurityGroups`, `PutFileSystemPolicy`, `CreateMountTarget` |
| `requestParameters.securityGroups` | New NFS-reach SGs | 🔴 wider CIDRs / new SGs |
| `requestParameters.policy` | FS resource policy | 🔴 cross-account/broad mount |
| `userIdentity` | Who | Unexpected identity |

## Respond

| Goal | Action |
|------|--------|
| Cut over-wide access | Tighten mount-target SGs to only the intended hosts |
| Enforce IAM controls | Put a restrictive file-system policy (require TLS, specific roles) |
| Contain a mounting host | Isolate the compromised instance (→ EC2 for DFIR) |
| Assess data loss | Determine what's on the FS and which hosts could read it |
| Preserve | Snapshot (via AWS Backup) the FS state; capture the mounting host's disk |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Tight mount-target SGs** — only the app's instances/subnets | Fewest hosts can mount |
| **File system policy** requiring TLS + specific roles; deny anonymous | IAM-level mount control |
| **Access points** per app with least-privilege POSIX user/root | Apps see only their subtree |
| **Encrypt in transit + at rest** (KMS) | Confidentiality on the wire and disk |
| **Alert** on `ModifyMountTargetSecurityGroups`, `PutFileSystemPolicy` | Catch exposure widening |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Mount-target SG widened to a broad CIDR | Any compromised host can mount the shared data |
| `PutFileSystemPolicy` allowing cross-account/broad mount | Broader exposure |
| New mount target in an unexpected subnet | New reachability |
| Unexpected sources on 2049 in Flow Logs | Someone mounting who shouldn't |
| Unencrypted FS holding sensitive data | No transit/at-rest protection |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What EFS is | **EFS → What is EFS** |
| The hosts that mount it (disk forensics) | **AWS → Compute → EC2** |
| The network reach you'll tighten | **AWS → Networking → VPC** |
| NFS traffic evidence | **AWS → Logging & Monitoring → VPC Flow Logs** |

## Resources

- EFS security considerations — https://docs.aws.amazon.com/efs/latest/ug/security-considerations.html
- Access points — https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html
- EFS file-system policies — https://docs.aws.amazon.com/efs/latest/ug/iam-access-control-nfs-efs.html
- MITRE ATT&CK: Data from Network Shared Drive (T1039) — https://attack.mitre.org/techniques/T1039/
