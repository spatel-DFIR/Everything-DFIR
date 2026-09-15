# EBS for DFIR

EBS is both a **target** (attackers exfiltrate disks by sharing snapshots) and your **primary forensic-imaging mechanism** (snapshot the victim volume and analyze it). This note covers both: hunting snapshot-sharing exfil, and doing snapshot forensics correctly.

New to the service? Read **What is EBS** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Snapshot Forensics — The Right Way](#snapshot-forensics--the-right-way)
- [Investigating Snapshot Exfiltration](#investigating-snapshot-exfiltration)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

EBS answers **"did someone copy a disk out, and how do I image the victim disk for analysis?"** Snapshot sharing is a quiet, network-free way to steal an entire filesystem — and snapshots are how you preserve host evidence in the cloud.

## Evidence It Produces

| Evidence | Gives you | Where |
|----------|-----------|-------|
| CloudTrail `CreateSnapshot`/`ModifySnapshotAttribute`/`CopySnapshot` | Snapshot activity + actor | CloudTrail |
| Snapshot attributes | Who a snapshot is shared with | `describe-snapshot-attribute` |
| The snapshot itself | A full disk image for forensics | You create/restore it |
| Volume attachment history | Which instance a disk was on | `describe-volumes`, Config timeline |

## Collect It

```bash
# Snapshots in the account + who they're shared with
aws ec2 describe-snapshots --owner-ids self \
  --query 'Snapshots[].{Id:SnapshotId,Vol:VolumeId,Started:StartTime,Enc:Encrypted}' --output table

# 🔴 Is a snapshot shared externally or public?
aws ec2 describe-snapshot-attribute --snapshot-id snap-0abc123 --attribute createVolumePermission
#  → look for UserId (external account) or Group: all (public)

# Who shared/created snapshots? (mgmt events)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifySnapshotAttribute --max-results 50
```

> **Console:** EC2 → **Snapshots** → select → *Permissions* tab (private/specific accounts/public). EC2 → **Volumes** for attachments.

## Snapshot Forensics — The Right Way

The cloud-native disk-imaging procedure (also in **EC2 for DFIR**):

| Step | Command / action |
|------|------------------|
| 1. Snapshot the victim volume(s) | `aws ec2 create-snapshot --volume-id vol-… --description "IR-<case> …"` — tag with the case |
| 2. (Optional) Copy to a forensics account | `aws ec2 copy-snapshot` into an isolated IR account/region |
| 3. Create a volume from the snapshot | `aws ec2 create-volume --snapshot-id snap-… --availability-zone <same AZ as forensic box>` |
| 4. Attach to a clean forensic instance | `aws ec2 attach-volume …` then mount **read-only** (`mount -o ro,noload`) |
| 5. Analyze | Timeline the filesystem: webshells, cron/systemd, bash history, `/tmp` payloads, added SSH keys, logs |
| 6. Preserve | Keep the original snapshot immutable + tagged; record hashes of extracted artifacts |

> 🔴 **Mount read-only** and analyze a *copy* — never the live volume. Keep the pristine snapshot as the evidence master. Prefer a **dedicated forensics account** so analysis can't touch production.

**EBS Direct APIs — triage without provisioning a volume:** `ListSnapshotBlocks` and `GetSnapshotBlock` let you read specific blocks of a snapshot directly via API — no volume creation, attachment, or mounting required. A real triage-acceleration technique on a large disk when you only need specific data (a known file's blocks, a changed-blocks diff between two snapshots) rather than a full restore.

```bash
aws ebs list-snapshot-blocks --snapshot-id snap-0abc123
aws ebs get-snapshot-block --snapshot-id snap-0abc123 --block-index <n> --block-token <token>
```

## Investigating Snapshot Exfiltration

The attacker's disk-theft path and how to catch it:

```
CreateSnapshot (of the target volume)
   → ModifySnapshotAttribute  (share to attacker's accountId, or make public)
   → [in attacker account] CreateVolume from the shared snapshot → read everything
```

| Check | How |
|-------|-----|
| Any snapshot shared to an **external account**? | `describe-snapshot-attribute` across all snapshots; CloudTrail `ModifySnapshotAttribute` |
| Any snapshot made **public**? | Same — `Group: all` |
| `CreateSnapshot` **immediately followed by a share** | CloudTrail timeline correlation |
| `CopySnapshot` to another region/account | CloudTrail — staging for exfil |
| Was it **encrypted**? | If yes, sharing without the KMS key limits the damage |

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The action | `ModifySnapshotAttribute`, `CreateSnapshot`, `CopySnapshot` |
| `requestParameters.createVolumePermission` | Who it's shared with | 🔴 `add` with an external `userId` or `group: all` |
| `requestParameters.snapshotId` / `volumeId` | Which disk | Map to the affected instance |
| `userIdentity` | Who shared it | Unexpected identity |
| `sourceIPAddress` | From where | External / scripted |

## Hunt at Scale

**In-platform — Athena / Lake:**

```sql
-- Snapshots shared externally or made public
SELECT eventtime, useridentity.arn,
       json_extract_scalar(requestparameters,'$.snapshotId') AS snap,
       requestparameters
FROM cloudtrail_logs
WHERE eventname = 'ModifySnapshotAttribute'
  AND requestparameters LIKE '%createVolumePermission%'
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "ModifySnapshotAttribute"
```

## Respond

| Goal | Action |
|------|--------|
| Cut the exfil | `aws ec2 reset-snapshot-attribute` / `modify-snapshot-attribute --remove` to unshare; make private |
| Assess the loss | What was on that volume? Assume the recipient read it (esp. if unencrypted) |
| Preserve for the case | Keep the snapshot; note the sharing event as the exfil proof |
| Contain the actor | Deactivate key / revoke sessions (→ IAM/STS) |
| Delete attacker copies | You can't reach their account — treat data as compromised; rotate secrets on that disk |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **EBS default encryption ON** + tight KMS key policies | Shared snapshots are useless without the key |
| **SCP denying** `ec2:ModifySnapshotAttribute` externally / `CreateVolumePermission=all` | Blocks the share-out exfil |
| **Block public sharing** account-wide (Snapshot public-access block) | No accidental/malicious public snapshots |
| **Alert** on `ModifySnapshotAttribute`, `CopySnapshot` to other accounts | Catch exfil live |
| **Dedicated forensics account** + pre-built IR tooling | Fast, clean imaging when it's needed |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `ModifySnapshotAttribute` sharing a snapshot to an external account | Disk exfiltration |
| A snapshot made public (`group: all`) | Whole disk exposed to the internet |
| `CreateSnapshot` → share, back to back | Deliberate disk theft |
| `CopySnapshot` cross-account/region unexpectedly | Exfil staging |
| Unencrypted snapshots of sensitive volumes | Nothing stopping a share-read |
| `DeleteSnapshot`/`DeleteVolume` of evidence | Destruction |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What EBS is + snapshots | **EBS → What is EBS** |
| The instances + full host response | **AWS → Compute → EC2** |
| Who did it | **AWS → 01 IAM & Identities**, **IAM for DFIR** |
| S3-side data exfil | **AWS → Storage → S3** |
| Managed exfil findings | **AWS → Security & Detection → GuardDuty** |
| The KMS key that encrypts the volume/snapshot | **AWS → Data Protection → KMS** |

## Resources

- Share an EBS snapshot — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html
- Block public access for snapshots — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-snapshots.html
- EBS encryption — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
- MITRE ATT&CK: Transfer Data to Cloud Account (T1537) — https://attack.mitre.org/techniques/T1537/
