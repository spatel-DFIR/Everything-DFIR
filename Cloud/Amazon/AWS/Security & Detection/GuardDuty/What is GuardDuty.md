# What is GuardDuty?

**GuardDuty** is AWS's **managed threat-detection service.** It continuously reads your CloudTrail, VPC Flow Logs, and DNS logs (plus optional add-ons) and raises **findings** — "this looks like an attack" — without you writing any detections.

For an analyst, GuardDuty is often **where the case starts**: a finding fires, and your job is to confirm, scope, and respond. It's the closest thing AWS has to a built-in EDR/NDR for the account.

## Contents

- [How It Works](#how-it-works)
- [What It Watches (Data Sources)](#what-it-watches-data-sources)
- [Anatomy of a Finding](#anatomy-of-a-finding)
- [Finding Types Worth Knowing](#finding-types-worth-knowing)
- [How to Identify GuardDuty in Evidence](#how-to-identify-guardduty-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
CloudTrail + VPC Flow + DNS  (+ optional: S3, EKS, Malware, RDS, Lambda, Runtime)
        │  GuardDuty analyzes continuously (ML + threat intel + rules)
        ▼
     FINDING  ── severity, type, resource, actor, evidence ──►  Console / EventBridge / Security Hub
```

- **No agents, no log plumbing** — GuardDuty reads the logs *independently*, so it still works even if an attacker deletes your trail's S3 files (it consumes the CloudTrail *event stream* directly).
- It's **regional** and **per-account**, but can be run **org-wide** from a delegated admin account, aggregating every account's findings in one place.
- Findings carry a **severity** (Low / Medium / High) and a **finding type** string that tells you exactly what pattern matched.

## What It Watches (Data Sources)

| Source | Catches | Default |
|--------|---------|---------|
| **CloudTrail management events** | IAM abuse, recon, defense evasion, unusual API use | ✅ Core |
| **VPC Flow Logs** | C2, port scans, crypto-mining traffic, Tor | ✅ Core |
| **DNS logs** | Malware domains, DGA, DNS exfil | ✅ Core |
| **S3 protection** (data events) | Suspicious S3 access/exfil | Add-on |
| **EKS protection** (audit + runtime) | Kubernetes attacks | Add-on |
| **Malware Protection** | Malware on EBS volumes / S3 uploads | Add-on |
| **RDS protection** | Anomalous DB logins | Add-on |
| **Lambda protection** | Malicious network activity from functions | Add-on |
| **Runtime Monitoring** | On-host process/network behavior (EC2/EKS/ECS) | Add-on |

> 🔴 The **core three are free-ish and on**; the add-ons are where deep coverage (S3 exfil, Kubernetes, malware, runtime) lives. Knowing which are enabled tells you what GuardDuty *could* have seen.

## Anatomy of a Finding

Every finding answers the DFIR questions in one JSON object:

| Part | Field | Answers |
|------|-------|---------|
| **What** | `type` | The attack pattern (e.g. `UnauthorizedAccess:IAMUser/...`) |
| **How bad** | `severity` | 1–3.9 Low · 4–6.9 Medium · 7–8.9 High |
| **Who** | `resource` + `service.action` | The affected resource + the actor (IP, user, role) |
| **Evidence** | `service.additionalInfo`, `service.action.*` | The API call, remote IP, threat-intel hit |
| **When** | `service.eventFirstSeen` / `eventLastSeen` | First and last observation |
| **How often** | `service.count` | Repeat count |

> The finding **type string** is structured: `ThreatPurpose:ResourceType/ThreatFamilyName.DetectionMechanism!Artifact`. Read it left to right and you know the story before opening details.

## Finding Types Worth Knowing

A representative set (there are ~100+; these are the ones you'll actually see):

| Finding type | Means |
|--------------|-------|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | 🔴 EC2 role creds used from **outside AWS** — classic IMDS/SSRF theft |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | API calls from a known-bad IP |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Suspicious console login |
| `Recon:IAMUser/MaliciousIPCaller` | Recon from a bad IP |
| `Discovery:S3/MaliciousIPCaller` | S3 enumeration from a bad IP |
| `Exfiltration:S3/ObjectRead.Unusual` | 🔴 Unusual bulk S3 reads |
| `PrivilegeEscalation:IAMUser/AdministrativePermissions` | Identity granted admin |
| `Persistence:IAMUser/AnomalousBehavior` | Unusual IAM changes (new users/keys) |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | 🔴 Instance talking to a mining pool |
| `Backdoor:EC2/C&CActivity.B!DNS` | Instance contacting C2 |
| `Trojan:EC2/DNSDataExfiltration` | DNS-tunnel exfil |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | 🔴 CloudTrail turned off |
| `Impact:EC2/PortSweep` | Instance scanning others |
| `Policy:S3/BucketAnonymousAccessGranted` | Bucket made public |

## How to Identify GuardDuty in Evidence

- **`eventSource`:** `guardduty.amazonaws.com` (for admin/config actions).
- **Finding IDs:** long hex strings; a **detector ID** identifies the GuardDuty instance per region.
- **ARNs:** `arn:aws:guardduty:<region>:<acct>:detector/<detector-id>/finding/<finding-id>`.
- Findings arrive via **EventBridge** (`source: aws.guardduty`, `detail-type: GuardDuty Finding`) — that's how they wire into automation and SecOps.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateDetector` / `DeleteDetector` | Turn GuardDuty on/off | 🔴 `DeleteDetector` = blinding |
| `UpdateDetector` | Change data sources / cadence | 🔴 disabling sources |
| `CreateFilter` + `CreateSuppressionRule` | Auto-archive findings | 🔴 attacker suppressing their own alerts |
| `UpdateFindingsFeedback` / `ArchiveFindings` | Mark findings useful/archived | 🔴 mass-archiving |
| `CreateIPSet` / `UpdateIPSet` (trusted list) | Whitelist IPs from detection | 🔴 whitelisting attacker IP |
| `DisassociateMembers` / `DeleteMembers` | Remove accounts from org GuardDuty | 🔴 dropping coverage |
| `ListFindings` / `GetFindings` | Read findings | Normal analyst use |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| GuardDuty | Microsoft Defender for Cloud | Security Command Center + Event Threat Detection |
| Finding | Security alert | Finding |
| Detector | Defender plan | SCC service enablement |
| Runtime Monitoring | Defender for Servers (MDE) | SCC / GKE runtime |

## Common Use Cases

Your "normal":

- **Always-on threat detection** with zero tuning — the baseline every account should have.
- **Org-wide** findings aggregated in a security/audit account.
- **Auto-response** — findings → EventBridge → Lambda/SSM to isolate an instance or disable a key.
- **A tripwire on logging tamper** — the `CloudTrailLoggingDisabled` finding catches the classic evasion.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Finding** | A raised detection with type, severity, evidence |
| **Detector** | The GuardDuty instance (per region, per account) |
| **Finding type** | Structured string naming the attack pattern |
| **Severity** | Low (1–3.9) / Medium (4–6.9) / High (7–8.9) |
| **Data source / feature** | What GuardDuty ingests (CloudTrail, Flow, DNS, add-ons) |
| **Suppression rule / filter** | Auto-archives matching findings |
| **Trusted IP list** | IPs excluded from detection |
| **Delegated admin** | The account managing GuardDuty org-wide |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Working a GuardDuty finding in a case | **GuardDuty → GuardDuty for DFIR** |
| The API actions behind IAM findings | **AWS → Identity & Access → IAM** |
| The traffic behind network findings | **AWS → Logging & Monitoring → VPC Flow Logs** |
| Instance findings (mining/C2/IMDS) | **AWS → Compute → EC2** |
| Aggregating findings across tools | **AWS → Security & Detection → Security Hub** |

## Resources

- What is GuardDuty — https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html
- Finding types — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
- Finding format — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html
- Remediating findings — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html
