# Evidence Acquisition in the Cloud

Cloud evidence **deletes itself** — instances terminate, containers exit, tokens expire, logs age out, and attackers clean up. This note is the cross-provider method for **capturing evidence before it's gone**, in the right order, without destroying it in the process. It's the "collect it" chapter that sits above every service note's own collection steps.

## Contents

- [The Golden Rules](#the-golden-rules)
- [Order of Volatility (Cloud Edition)](#order-of-volatility-cloud-edition)
- [Capture vs Contain — Sequencing](#capture-vs-contain--sequencing)
- [What to Collect, by Evidence Type](#what-to-collect-by-evidence-type)
- [Compute: Snapshot & Memory](#compute-snapshot--memory)
- [Logs: Export Before They Age Out](#logs-export-before-they-age-out)
- [Identity & Credentials](#identity--credentials)
- [Ephemeral Compute (Containers & Serverless)](#ephemeral-compute-containers--serverless)
- [Chain of Custody in the Cloud](#chain-of-custody-in-the-cloud)
- [Per-Provider Collection Cheat-Sheet](#per-provider-collection-cheat-sheet)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Golden Rules

1. **Preserve before you touch.** Snapshot before you isolate or terminate; export logs before retention or an attacker removes them.
2. **Isolate, don't power off.** Powering off a cloud VM loses memory and can trip attacker dead-man logic; **network-isolate** instead and capture live.
3. **Copy the account's own evidence out.** If the account is compromised, its logs and snapshots are at risk — replicate to a **separate, trusted forensics account/project** with tight access.
4. **Work read-only, note every action.** Your own API calls land in the same audit log — use a **named, dedicated IR principal** so responders are distinguishable from the adversary.
5. **Region- and scope-complete.** Sweep **all regions** and all accounts/subscriptions/projects — attackers hide in the ones you don't watch.

## Order of Volatility (Cloud Edition)

Grab from top down — the top vanishes in minutes:

| Rank | Evidence | Typical lifetime | Why first |
|------|----------|------------------|-----------|
| 1 | **Running ephemeral compute** (container task, serverless, spot) | Seconds–minutes | Gone at next scale-in/exit |
| 2 | **Memory of a live instance** | Until stop/terminate | Lost on power-off |
| 3 | **Temporary credentials** (STS/OAuth/SA tokens) | 15 min–hours | Expire; capture the *mint* event + revoke |
| 4 | **Short-retention logs** (SSM history, session lists, native buffers) | Hours–days | Age out silently |
| 5 | **Attacker-mutable state** (resources, findings, log config) | Until they delete it | Cleanup/anti-forensics |
| 6 | **Disk / snapshots** | Persistent-ish | Still capture before termination |
| 7 | **Long-retention audit logs** (in a trail/sink) | Weeks–years | Most durable — but verify it was on |

## Capture vs Contain — Sequencing

The tension: isolation protects the environment but can destroy evidence. Decide per artifact:

| Situation | Do this order |
|-----------|---------------|
| Live instance, suspected memory-resident implant | **Capture memory → snapshot disk → isolate** |
| Active data exfil in progress | **Isolate/cut first** (stop the bleed) → then capture |
| Credential actively used | **Revoke session** *and* record the mint event; then scope |
| Ephemeral task about to scale in | **Capture now** (you may not get a second chance) |

> 🔴 State the trade-off out loud in the ticket. "We isolated before imaging memory to stop exfil; memory not captured" is a defensible, documented decision. Silent evidence loss is not.

## What to Collect, by Evidence Type

| Evidence | AWS | Azure | Google |
|----------|-----|-------|--------|
| Control-plane audit | CloudTrail export (S3/Lake) | Activity Log export | Cloud Audit Logs → sink/BigQuery |
| Identity/sign-in | Identity Center + console logs | Entra Sign-in/Audit export | Login/Auth audit export |
| Disk image | **EBS snapshot** → copy to IR account | **Managed disk snapshot** | **Persistent Disk snapshot** |
| Memory | In-guest capture tool via SSM/agent | Run Command / agent | OS Login + capture tool |
| Network | VPC Flow Logs | NSG Flow Logs | VPC Flow Logs |
| Config timeline | AWS Config | Resource Graph / Activity | Asset Inventory |
| Secrets touched | Secrets Manager/KMS events | Key Vault logs | Secret Manager / KMS audit |

## Compute: Snapshot & Memory

The correct disk-forensics pattern is the same idea in all three clouds:

1. **Snapshot the volume** (don't detach the original from a running box first if you want memory).
2. **Copy the snapshot to the trusted IR account/project** (cross-account/-project share), so the compromised environment can't tamper with it.
3. **Create a volume from the copy, attach to a clean analysis instance**, mount **read-only**, then carve as usual (webshells, cron/launchd, shell history, `/tmp`, added keys, `amazon-ssm-agent.log`).
4. **Memory:** capture live from inside the guest (via the platform's exec channel — SSM/Run Command/OS Login) before stop/terminate.

> Encrypted volumes need the **KMS/Key Vault/Cloud KMS key** shared to the IR account too, or the copy is unreadable. Confirm key access as part of the plan.

→ Provider depth: **AWS EBS for DFIR**, **EC2 for DFIR** · **Azure Virtual Machines** · **Google Compute Engine**.

## Logs: Export Before They Age Out

- **Confirm the log existed and was on** across your entire window and scope *first* — absence is itself a finding (→ defense-evasion).
- **Export a frozen copy** to the IR store (S3/Storage Account/GCS in the trusted project) so retention or tampering can't shrink your evidence.
- **Widen scope:** global-service events land in one region (AWS `us-east-1`); org trails/sinks aggregate accounts — pull those.
- **Capture native-buffer logs early** (SSM command/session history, ~30 days) — they don't live in your long-term trail unless routed.

## Identity & Credentials

- **Record the mint event** for every suspicious temp session (the `AssumeRole` / token request / `generateAccessToken`) — it ties the session back to the human/source.
- **Snapshot current IAM state**: users, roles, keys, policies, trust policies, federation providers, service accounts/keys — attackers plant persistence here.
- **List active sessions/tokens** before revoking, so you know what you cut.

## Ephemeral Compute (Containers & Serverless)

Hardest to capture — plan for it:

| Target | Grab | Note |
|--------|------|------|
| **K8s pod (EKS/AKS/GKE)** | `kubectl` describe/logs, node it ran on, image digest, control-plane **audit log** | Pod may be gone; the audit log persists |
| **Container task (ECS/Fargate/Cloud Run/ACI)** | Task definition, image, env, CloudWatch/Cloud Logging output | No SSH; rely on task metadata + logs |
| **Function (Lambda/Functions/Cloud Functions)** | Code/zip, config, env vars, invocation logs, trigger | Capture the **deployed package** and the trigger that fired it |

> 🔴 For serverless/containers there is often **no host to image** — the audit log, the deployed artifact, and the platform logs *are* the evidence. Enable and export those.

## Chain of Custody in the Cloud

- **Dedicated IR account/project** with logging on, MFA, and least-privilege responder roles.
- **Immutable storage** for evidence (Object Lock / immutable blob / bucket retention) so copies can't be altered.
- **Record hashes** of exported snapshots/log files; note who collected what, when, from where.
- **Distinguish responder activity** — a named IR principal means your reads don't get confused with the adversary's in the audit log.

## Per-Provider Collection Cheat-Sheet

**AWS**
```bash
aws ec2 create-snapshot --volume-id vol-0abc --description "IR-<case>"
aws ec2 modify-snapshot-attribute --snapshot-id snap-0abc --create-volume-permission Add=[{UserId=<IR-acct>}]
aws cloudtrail lookup-events --start-time <t0> --end-time <t1>   # or export the trail/Lake
```
**Azure**
```bash
az snapshot create -g <rg> -n ir-<case> --source <diskId>
az monitor activity-log list --start-time <t0> --end-time <t1>
# Entra: export Sign-in/Audit logs (Graph / Log Analytics)
```
**Google Cloud**
```bash
gcloud compute disks snapshot <disk> --snapshot-names=ir-<case> --zone=<z>
gcloud logging read 'logName:"cloudaudit.googleapis.com"' --freshness=30d --format=json > audit.json
```

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Why cloud evidence is pre-decided / ephemeral | **00 Cloud Fundamentals** |
| Whose credentials to preserve/revoke | **01 Cloud Identity and Federation** |
| Building the timeline from what you collected | **03 Cross-Cloud Correlation** |
| Provider disk/host collection | **AWS EBS/EC2** · **Azure Virtual Machines** · **Google Compute Engine** |
| Confirming logging wasn't disabled | **AWS → Playbooks → Defense Evasion** |

## Resources

- AWS forensics / snapshot sharing — https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/forensics.html
- Azure VM snapshot for IR — https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk
- Google Cloud disk snapshots — https://cloud.google.com/compute/docs/disks/create-snapshots
- NIST SP 800-86 (order of volatility / forensics) — https://csrc.nist.gov/pubs/sp/800/86/final
