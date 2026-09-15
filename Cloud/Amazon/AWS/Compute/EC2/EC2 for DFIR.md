# EC2 for DFIR

A compromised EC2 instance is where cloud IR meets classic host forensics. You have two evidence planes: the **cloud side** (who launched/changed it, what its role did) and the **host side** (the disk and memory, captured via snapshots). And you have a containment problem: **isolate without tipping off** or destroying evidence.

New to the service? Read **What is EC2** first — especially the IMDS section.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [EC2 Instance Connect vs SSM — Two Different SSH-less Paths](#ec2-instance-connect-vs-ssm--two-different-ssh-less-paths)
- [The Golden Rule of Instance Response](#the-golden-rule-of-instance-response)
- [Collect It — Cloud Side](#collect-it--cloud-side)
- [Collect It — Host Side (Snapshot Forensics)](#collect-it--host-side-snapshot-forensics)
- [Investigate](#investigate)
- [Detecting IMDS Credential Theft](#detecting-imds-credential-theft)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond — Isolate the Right Way](#respond--isolate-the-right-way)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

EC2 answers **"what happened on this box, what did its role creds do, and how do I contain it without losing evidence?"** It's often the pivot point between an external intrusion and full account compromise (via stolen role creds).

## Evidence It Produces

| Evidence | Gives you | Where |
|----------|-----------|-------|
| CloudTrail `ec2.*` | Launch/terminate/SG/keypair/snapshot/user-data changes + actor | CloudTrail |
| The instance's **role session** activity | What the box's creds did in AWS | CloudTrail (filter `assumed-role/<role>/<instance-id>`) |
| **EBS snapshot** | The disk — full host forensics | You create it |
| **Memory capture** | Volatile evidence (if you can grab it live) | SSM / manual before termination |
| **VPC Flow Logs** | The instance's network behavior (C2/exfil) | → VPC Flow Logs |
| **CloudWatch/OS logs** | In-guest logs *if the agent was installed* | → CloudWatch |
| Console screenshot / system log | Quick state without touching the box | `get-console-screenshot` |

## EC2 Instance Connect vs SSM — Two Different SSH-less Paths

Don't confuse them: **SSM Session Manager** gives an interactive shell with no key at all (→ **Systems Manager (SSM)**). **EC2 Instance Connect** is different — it's AWS pushing a **temporary SSH public key** to the instance's `~/.ssh/authorized_keys` via API for a **~60-second window**, then the caller connects over **normal SSH**.

| | EC2 Instance Connect | SSM Session Manager |
|---|---|---|
| Mechanism | AWS-issued temp SSH key pushed via API | Agent-brokered shell, no SSH at all |
| CloudTrail event | `SendSSHPublicKey` | `StartSession` |
| What lands on the host | A real (if short-lived) entry in `authorized_keys` | Nothing SSH-related |
| Session transport | Standard SSH (port 22) | SSM agent channel |

> 🔴 **Abuse pattern:** an attacker with the right IAM permission calls `ec2-instance-connect:SendSSHPublicKey` to push their own key, then connects **normally over SSH**. The only cloud-side trace is the `SendSSHPublicKey` CloudTrail event — the SSH session itself looks like any other login on the host, with no obvious host-side artifact tying it back to the API call. Always check CloudTrail for `SendSSHPublicKey` when investigating an SSH session you can't otherwise explain.

## The Golden Rule of Instance Response

> 🔴 **Capture before you kill.** A terminated instance with a deleted volume is *gone forever* — no re-imaging, no "pull it from backup." **Snapshot the EBS volume(s) (and grab memory if you can) BEFORE termination.** Isolation ≠ termination.

## Collect It — Cloud Side

```bash
# The instance's full current state
aws ec2 describe-instances --instance-ids i-0abc123 \
  --query 'Reservations[].Instances[].{State:State.Name,AZ:Placement.AvailabilityZone,
           Role:IamInstanceProfile.Arn,SGs:SecurityGroups,KeyName:KeyName,
           IMDS:MetadataOptions.HttpTokens}'   # HttpTokens=required means IMDSv2 enforced

# 🔴 Was IMDSv1 allowed? (SSRF exposure)
aws ec2 describe-instances --instance-ids i-0abc123 \
  --query 'Reservations[].Instances[].MetadataOptions'

# Read user-data (persistence spot)
aws ec2 describe-instance-attribute --instance-id i-0abc123 --attribute userData \
  --query 'UserData.Value' --output text | base64 -d

# Quick look without touching the box
aws ec2 get-console-screenshot --instance-id i-0abc123 --output text
aws ec2 get-console-output --instance-id i-0abc123

# What did this instance's ROLE do in AWS?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-0abc123 --max-results 50
```

## Collect It — Host Side (Snapshot Forensics)

The cloud-native way to image a disk:

```bash
# 1. Snapshot every volume on the instance (do this FIRST)
aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=i-0abc123 \
  --query 'Volumes[].VolumeId' --output text
aws ec2 create-snapshot --volume-id vol-0abc123 \
  --description "IR-<case> i-0abc123 $(date -u +%FT%TZ)" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Case,Value=IR-1234}]'

# 2. Create an analysis volume FROM the snapshot, in the SAME AZ as your forensic box
aws ec2 create-volume --snapshot-id snap-0abc123 --availability-zone us-east-1a

# 3. Attach it to a clean, isolated forensic instance (read-only mount) and analyze on-disk
```

> **Console:** EC2 → Instances → select → **Storage** tab → each volume → *Create snapshot*. Then EC2 → Snapshots → *Create volume* → attach to your forensic instance.
>
> 🔴 **Memory first if the box is live and you can reach it:** use SSM (`AWS-RunShellScript` / a memory-capture doc, e.g. LiME/AVML) to grab RAM *before* you stop the instance — stopping loses volatile state. Only then snapshot + isolate.

## Investigate

| Step | Do this |
|------|---------|
| 1. Cloud provenance | `RunInstances` — who launched it, from what AMI, in what region? Legit or attacker-spun? |
| 2. Config tampering | New keypairs, SG rules opened, user-data changed, IMDS re-loosened |
| 3. Role activity | Filter CloudTrail by the instance's role session — did its creds do things *the app never should*? |
| 4. Credential theft | Was the role used from **outside AWS**? (GuardDuty finding + external source IP) |
| 5. Network | VPC Flow Logs for the ENI — C2, exfil, scanning, mining ports |
| 6. SSM execution | 🔴 Was code run **without SSH**? Check CloudTrail for `SendCommand`/`StartSession` targeting this instance — a common SSH-less RCE path (→ **Systems Manager (SSM)**) |
| 7. Host forensics | Snapshot → analyze disk: webshells, cron, bash history, `/tmp` payloads, added SSH keys, `amazon-ssm-agent.log` |

## Detecting IMDS Credential Theft

The signature attack — confirm it precisely:

| Signal | Where |
|--------|-------|
| GuardDuty `InstanceCredentialExfiltration.OutsideAWS` | The definitive alert |
| The role session (`assumed-role/<role>/i-…`) used from an **external IP** | CloudTrail: compare `sourceIPAddress` to the instance's own AWS IPs |
| Actions **inconsistent with the app** (e.g. a web server's role suddenly enumerating IAM/S3) | CloudTrail behavior vs baseline |
| Web-app logs showing an **SSRF to 169.254.169.254** | In-guest logs / WAF / ALB logs |
| IMDSv1 was allowed (`HttpTokens: optional`) | `describe-instances` MetadataOptions |

> 🔴 The instance-role session **works from anywhere** until it expires or you revoke it. Deactivating a key won't help (it's a role session) — you must **revoke the role's sessions** (→ STS for DFIR) *and* fix the instance.

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The EC2 action | `RunInstances` (mass), `AuthorizeSecurityGroupIngress` (0.0.0.0/0), `ModifyInstanceMetadataOptions` |
| `userIdentity` | Who did it | Unexpected identity launching/changing instances |
| `requestParameters.instanceType` + `.imageId` | Size + AMI | 🔴 GPU/large types = mining; unknown AMI |
| `responseElements.instancesSet` | The new instance IDs | Track what was created |
| `sourceIPAddress` (on the role session) | Where creds were used | 🔴 outside AWS = theft |

## Hunt at Scale

**In-platform — Athena / Lake:**

```sql
-- Suspicious instance launches (mining hunt): big types, odd regions
SELECT eventtime, useridentity.arn, awsregion,
       json_extract_scalar(requestparameters,'$.instanceType') AS itype,
       json_extract_scalar(requestparameters,'$.imageId') AS ami
FROM cloudtrail_logs
WHERE eventname = 'RunInstances' AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "RunInstances" OR metadata.product_event_type = "ModifyInstanceMetadataOptions"
```

## Respond — Isolate the Right Way

| Step | Action |
|------|--------|
| 1. Capture | Memory (if live) → **snapshot all volumes** → console screenshot |
| 2. Isolate (don't terminate) | Swap to a **quarantine SG** with no ingress/egress (or egress only to your forensic tooling); keep the box alive for memory/live triage |
| 3. Cut the creds | **Revoke the instance role's sessions**; if it can't be revoked cleanly, detach/replace the instance profile |
| 4. Preserve | Tag snapshots with the case; protect from lifecycle deletion |
| 5. Eradicate | Rebuild from a known-good AMI; rotate anything the box could read (secrets, keys) |
| 6. Remove persistence | Kill attacker keypairs, user-data backdoors, cron/systemd on disk |

> **Isolation SG pattern:** create an empty security group (no rules) and replace the instance's SGs with it — stateful SGs then drop established connections' return traffic, cutting C2 while the box stays up for analysis.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Require IMDSv2** (`HttpTokens=required`) + **hop limit 1** everywhere | Kills the SSRF→role-theft path |
| **No stored `AKIA` keys on disk**; roles + Secrets Manager only | Nothing to steal from the box |
| **Least-privilege instance roles**; no `*` | Small blast radius if creds leak |
| **Tight SGs**; no `0.0.0.0/0` on 22/3389; SSM instead of SSH | Fewer entry points |
| **SCP/alert** on `ModifyInstanceMetadataOptions`, `RunInstances` in unused regions, SG-open-to-world | Catch mining / IMDS loosening |
| **CloudWatch Agent** for OS logs; **GuardDuty Runtime Monitoring** | In-guest visibility next time |
| **Golden AMIs**, patched + scanned | No backdoored images |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Instance role creds used from **outside AWS** | IMDS/SSRF credential theft |
| `RunInstances` of large/GPU types or in unused regions | Crypto-mining |
| `AuthorizeSecurityGroupIngress` opening 22/3389 to `0.0.0.0/0` | Exposing entry |
| New `CreateKeyPair`/`ImportKeyPair` on a prod box | SSH persistence |
| `ModifyInstanceAttribute` changing user-data | Boot-time backdoor |
| `ModifyInstanceMetadataOptions` re-allowing IMDSv1 | Re-opening the SSRF path |
| `ModifySnapshotAttribute` sharing a snapshot externally | Disk-image exfil (→ EBS) |
| Instance role doing actions unlike the app (IAM/S3 enum) | Stolen-cred abuse |
| `TerminateInstances` before you captured | Evidence destruction |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What EC2 is + IMDS | **EC2 → What is EC2** |
| IMDS SSRF → role theft, end to end | **AWS → Playbooks → IMDS SSRF to Role Theft** |
| Disk/snapshot exfil & sharing | **AWS → Storage → EBS** |
| Revoking the stolen role session | **AWS → Identity & Access → STS** |
| Network C2/exfil confirmation | **AWS → Logging & Monitoring → VPC Flow Logs** |
| The finding that flags it | **AWS → Security & Detection → GuardDuty** |
| SSH-less command execution on the box | **AWS → Compute → Systems Manager (SSM)** · **Playbooks → SSM Run Command & Session Abuse** |

## Resources

- Use IMDSv2 — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Create EBS snapshots — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-creating-snapshot.html
- Forensic investigation environment on AWS (guidance) — https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/forensics.html
- Run commands with SSM — https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html
- MITRE ATT&CK: Unsecured Credentials – Cloud Instance Metadata API (T1552.005) — https://attack.mitre.org/techniques/T1552/005/
