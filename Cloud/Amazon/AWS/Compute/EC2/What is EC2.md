# What is EC2?

**EC2 (Elastic Compute Cloud)** is AWS's **virtual machines**. An **instance** is a running server — the cloud equivalent of a box you'd image and triage on-prem. But EC2 comes with cloud-only attack surface, and one piece dominates DFIR: the **Instance Metadata Service (IMDS)**, the mechanism attackers use to steal the instance's IAM role credentials.

You'll investigate EC2 two ways: as a **host** (disk/memory forensics via snapshots) and as an **identity source** (the role creds it carries).

## Contents

- [How It Works](#how-it-works)
- [The Anatomy of an Instance](#the-anatomy-of-an-instance)
- [IMDS — The Most Important Thing to Understand](#imds--the-most-important-thing-to-understand)
- [IMDSv1 vs IMDSv2](#imdsv1-vs-imdsv2)
- [How Instances Get Credentials](#how-instances-get-credentials)
- [How to Identify EC2 in Evidence](#how-to-identify-ec2-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
AMI (image) + Instance type (size) + Key pair (SSH) + Security group (firewall)
   + Instance profile (an IAM role)  →  launched into a Subnet/VPC  →  running INSTANCE
                                                     │
                                    each instance has IMDS at 169.254.169.254
                                    (serves identity + the role's temp creds)
```

- An instance runs from an **AMI** (a machine image), sized by **instance type**, on **EBS volumes** (its disks).
- It sits in a **subnet/VPC**, firewalled by **security groups**, reachable via a **key pair** (SSH) or SSM.
- It usually carries an **instance profile** = an IAM **role**, so code on the box can call AWS without stored keys.

## The Anatomy of an Instance

| Piece | What it is | DFIR relevance |
|-------|-----------|----------------|
| **Instance ID** | `i-0abc123…` | Your primary anchor |
| **AMI** | The image it booted from | 🔴 a malicious/backdoored AMI = compromise at birth |
| **EBS volumes** | The disks | Snapshot these for disk forensics |
| **Security groups** | Stateful firewall | 🔴 world-open ports = entry; used for isolation |
| **Key pair** | SSH access | 🔴 attacker-added key = persistence |
| **Instance profile / role** | The IAM role it carries | 🔴 the creds IMDS theft steals |
| **User data** | Boot-time script | 🔴 a favorite persistence/backdoor spot |
| **IMDS** | Metadata service at `169.254.169.254` | The role-cred vending machine |

## IMDS — The Most Important Thing to Understand

Every instance can reach a link-local endpoint, **`169.254.169.254`**, that serves metadata *about that instance* — including **temporary credentials for its IAM role**:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
   → { "AccessKeyId":"ASIA…", "SecretAccessKey":"…", "Token":"…", "Expiration":"…" }
```

🔴 **This is the crown-jewel attack.** If an attacker can make the instance fetch that URL — via **SSRF** in a web app, or by running code on the box (RCE, webshell) — they get the role's `ASIA` credentials and can use them **from anywhere**. That's the mechanism behind the classic AWS breach (e.g. the 2019 Capital One incident).

**The tell in the cloud logs:** the stolen `ASIA` creds get used from an IP **outside AWS** → GuardDuty raises `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`. See **EC2 for DFIR** and the **IMDS SSRF** playbook.

## IMDSv1 vs IMDSv2

The single most important EC2 hardening fact:

| | **IMDSv1** | **IMDSv2** |
|-|-----------|-----------|
| How it works | Simple GET request | Requires a **session token** (PUT first, then GET with token) |
| SSRF-resistant? | 🔴 No — a basic SSRF can hit it | ✅ Yes — the PUT + header requirement defeats most SSRF |
| Hop limit | n/a | Default limit 1 (blocks container/proxy relays) |
| Recommendation | 🔴 Disable it | **Require IMDSv2** everywhere |

> 🔴 **"Require IMDSv2" (and hop-limit 1) is the highest-value EC2 hardening.** It closes the SSRF→role-theft path that causes the worst AWS breaches. On any case involving an instance, check whether IMDSv1 was still allowed.

## How Instances Get Credentials

| Mechanism | What it is | 🔴 Abuse |
|-----------|-----------|----------|
| **Instance profile → role** | The blessed way: no stored keys, creds via IMDS | Stolen via IMDS SSRF/RCE |
| **Stored access keys on disk** | Someone put `AKIA` keys in a file/env | 🔴 anti-pattern; leaks with the box |
| **User data secrets** | Secrets baked into boot script | 🔴 readable via IMDS `/user-data` |
| **SSM Parameter Store / Secrets Manager** | Fetched at runtime | Better, but the role can read them |

## How to Identify EC2 in Evidence

- **`eventSource`:** `ec2.amazonaws.com`.
- **ARNs:** `arn:aws:ec2:<region>:<acct>:instance/i-0abc123`.
- **In role-cred theft:** the session shows as `assumed-role/<instance-role>/<instance-id>` — the **session name is the instance ID**, tying creds to the box.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `RunInstances` | Launch instances | 🔴 mass launch = cryptomining; new region |
| `TerminateInstances` | Destroy instances | 🔴 evidence destruction |
| `CreateKeyPair` / `ImportKeyPair` | Add SSH keys | 🔴 persistence |
| `AuthorizeSecurityGroupIngress` | Open a firewall port | 🔴 `0.0.0.0/0` on 22/3389 |
| `ModifyInstanceAttribute` (userData) | Change boot script | 🔴 persistence via user data |
| `CreateSnapshot` / `ModifySnapshotAttribute` | Snapshot / share a disk | 🔴 share = exfil (see EBS) |
| `GetPasswordData` | Retrieve Windows admin password | 🔴 credential access |
| `CreateImage` | Make an AMI from an instance | Exfil of a whole disk image |
| `ModifyInstanceMetadataOptions` | Change IMDS settings | 🔴 re-enabling IMDSv1 |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| EC2 instance | Virtual Machine | Compute Engine instance |
| IMDS (169.254.169.254) | Azure IMDS (169.254.169.254) | GCE metadata server |
| Instance profile / role | Managed identity | Attached service account |
| AMI | VM image | Machine image |
| Security group | NSG | Firewall rule |
| Key pair | SSH key / admin creds | SSH key (OS Login) |

## Common Use Cases

Your "normal":

- **App/web servers, batch/compute, build agents.**
- **Auto Scaling groups** — instances launched/terminated automatically (baseline churn).
- **Bastion/jump hosts** — watched SSH entry points.
- **Roles for workload access** — instance profiles calling S3/DynamoDB/etc.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Instance** | A running virtual machine (`i-…`) |
| **AMI** | The image an instance boots from |
| **EBS volume** | An instance's virtual disk |
| **Instance profile** | The wrapper delivering an IAM role to an instance |
| **IMDS** | Instance Metadata Service (`169.254.169.254`) |
| **IMDSv2** | Session-token-protected IMDS (SSRF-resistant) |
| **Security group** | Stateful per-instance firewall |
| **User data** | Boot-time script/config |
| **Key pair** | SSH public/private key for access |
| **SSM** | Systems Manager — agent-based access/automation |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a compromised instance | **EC2 → EC2 for DFIR** |
| IMDS SSRF → role theft walk-through | **AWS → Playbooks → IMDS SSRF to Role Theft** |
| The disks (snapshot forensics) | **AWS → Storage → EBS** |
| The role creds it carries | **AWS → Identity & Access → STS**, **IAM** |
| Network exposure / traffic | **AWS → Networking → VPC**, **VPC Flow Logs** |
| Instance findings (mining/C2) | **AWS → Security & Detection → GuardDuty** |

## Resources

- What is EC2 — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html
- Instance Metadata Service (IMDS) — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- Use IMDSv2 — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- IAM roles for EC2 — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
