# Investigating AWS — Start Here

An alert just fired, or someone said "I think we're compromised in AWS." **This note is where you start.** It gives you the first-hour triage flow and routes you into the deeper service notes.

You don't need to memorize AWS. You need a **repeatable orientation**: confirm what you're logged into, confirm logging is intact, pull the identity's timeline, and classify what you see. Everything else is depth.

## Contents

- [First, Get Oriented](#first-get-oriented)
- [The First-Hour Triage Flow](#the-first-hour-triage-flow)
- [Step 0 — Do No Harm](#step-0--do-no-harm)
- [Step 1 — Confirm Where You Are](#step-1--confirm-where-you-are)
- [Step 2 — Confirm Logging Is Intact](#step-2--confirm-logging-is-intact)
- [Step 3 — Scope the Identity](#step-3--scope-the-identity)
- [Step 4 — Classify the Activity](#step-4--classify-the-activity)
- [Step 5 — Sweep for Blind Spots](#step-5--sweep-for-blind-spots)
- [Alert-to-Note Router](#alert-to-note-router)
- [The Minimum Toolkit](#the-minimum-toolkit)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## First, Get Oriented

Before touching the environment, know these four things about *this* case:

| Question | Why it matters | Where to find it |
|----------|----------------|------------------|
| **Which account(s)?** | Scopes everything; cross-account = signal | Alert; `aws sts get-caller-identity` |
| **What identity is implicated?** | The thing you'll build a timeline for | The alert (user, role, key, IP) |
| **Is this an Org or a standalone account?** | Org-wide trail & SCPs change your options | `aws organizations describe-organization` |
| **What's the access model?** | IAM users vs SSO changes where "the human" lives | Ask; look for `AWSReservedSSO_` roles |

> New to how AWS is laid out? Read **00 - Overview & Terminology** and **01 - IAM & Identities** first — this note assumes them.

## The First-Hour Triage Flow

```
        ┌──────────────────────────────────────────────┐
        │  ALERT / SUSPICION IN AWS                     │
        └───────────────────┬──────────────────────────┘
                            ▼
   0. DO NO HARM ─ get read access; preserve, don't tamper
                            ▼
   1. WHERE AM I ─ account, region(s), org?           → 00 Overview
                            ▼
   2. IS LOGGING INTACT ─ trails on? any StopLogging?  → CloudTrail
        │  (gap found) ──────────────► pivot to GuardDuty / VPC Flow / Config
                            ▼
   3. SCOPE THE IDENTITY ─ full timeline for user/key/IP → CloudTrail + 01 Identities
                            ▼
   4. CLASSIFY ─ recon? persistence? privesc? exfil? evasion?
                            ▼
   5. SWEEP BLIND SPOTS ─ all regions, all accounts, other creds minted
                            ▼
        ┌──────────────────────────────────────────────┐
        │  → CONTAIN → ERADICATE → HARDEN  (service notes + Playbooks) │
        └──────────────────────────────────────────────┘
```

## Step 0 — Do No Harm

Cloud evidence is fragile and cheap for an attacker to destroy. Protect it *before* you dig.

- **Get read-only access** for the investigation (a `SecurityAudit` / `ViewOnlyAccess` role). Don't investigate as the compromised identity.
- **Don't tip off the attacker** with noisy changes until you've decided on containment timing.
- **Preserve first:** confirm CloudTrail S3 logs and GuardDuty findings won't expire mid-case. Copy logs out if a lifecycle rule or short retention is a risk.
- 🔴 **Never delete the compromised resource before you've collected from it** — an EBS snapshot or a memory capture of an EC2 box is gone forever once terminated.

## Step 1 — Confirm Where You Are

```bash
# Who am I / which account am I in?
aws sts get-caller-identity
#  → { "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/IR", "UserId": "..." }

# Is this account part of an Organization? (changes trail + SCP options)
aws organizations describe-organization 2>/dev/null \
  --query '{MgmtAccount:MasterAccountId,FeatureSet:FeatureSet}'

# Which regions are even enabled for this account?
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```

> **Console:** account ID is top-right; the region picker is beside it; **AWS Organizations** console shows the account tree. **IAM → Dashboard** shows the sign-in URL and whether Identity Center is in use.

## Step 2 — Confirm Logging Is Intact

**This is the make-or-break step.** If logging was off or stopped during your window, your CloudTrail timeline has holes — you must know that before you trust it.

```bash
# What trails exist and what do they cover?
aws cloudtrail describe-trails \
  --query 'trailList[].{Name:Name,Multi:IsMultiRegionTrail,Org:IsOrganizationTrail,Bucket:S3BucketName}' \
  --output table

# 🔴 Is each trail logging now — and did it ever stop?
aws cloudtrail get-trail-status --name <trail> \
  --query '{Logging:IsLogging,Stopped:TimeLoggingStopped,Started:TimeLoggingStarted}'

# 🔴 Did anyone try to blind logging during the incident?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging --max-results 20
# (repeat for DeleteTrail, PutEventSelectors, UpdateTrail)
```

> **Console:** CloudTrail → **Trails** → open each → check *Logging ON* + multi-region + org. CloudTrail → **Event history** → filter Event name = `StopLogging`.

**Decision:** if there's a gap, don't stop — **pivot to evidence that survives CloudTrail tampering**: GuardDuty findings, VPC Flow Logs, AWS Config timeline, and the resources' own state. See the router below.

## Step 3 — Scope the Identity

Build the **complete timeline** for whatever the alert named — a user, an access key, a role, or an IP.

```bash
# Everything a user did (last 90 days, mgmt events)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<user> --max-results 50

# Everything a specific (leaked) key did
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... --max-results 50

# Beyond 90 days → query the S3 logs or CloudTrail Lake (SQL). See CloudTrail for DFIR.
```

Then **sort by `eventTime`** and read it as a story: first seen → what they touched → did it work (`errorCode`) → human or script (`userAgent`) → did they assume a role (pivot via **01 - IAM & Identities**).

> **Console:** CloudTrail → **Event history** → filter by *User name* / *Access key ID* → **Download events** for offline timeline building.

## Step 4 — Classify the Activity

Bucket every action into a phase. This turns a wall of API calls into an attack narrative.

| Phase | Telltale API calls | Go deeper |
|-------|--------------------|-----------|
| **Recon / enum** | `GetCallerIdentity`, walls of `List*` / `Describe*` / `Get*`, bursts of `AccessDenied` | CloudTrail for DFIR |
| **Persistence** | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `CreateRole`, `PutUserPolicy` | IAM, 01 Identities |
| **Privilege escalation** | `AttachUserPolicy` (admin), `CreatePolicyVersion`, `UpdateAssumeRolePolicy`, `PassRole` | IAM |
| **Credential access** | `AssumeRole`, `GetSessionToken`, `GetSecretValue`, `Decrypt`, IMDS role theft | STS, Secrets, EC2 |
| **Lateral / cross-account** | `AssumeRole` into other accounts, `ModifySnapshotAttribute` (share out) | STS, EBS |
| **Exfiltration** | S3 `GetObject`/`CopyObject` (data events), `PutBucketPolicy` (make public), snapshot sharing | S3, EBS |
| **Impact** | `RunInstances` (mining), `Delete*`, ransomware via KMS, `PutBucketPolicy` | EC2, S3, GuardDuty |
| **Defense evasion** | 🔴 `StopLogging`, `DeleteTrail`, `DeleteFlowLogs`, GuardDuty `DeleteDetector` | CloudTrail, GuardDuty |

## Step 5 — Sweep for Blind Spots

Attackers hide where you're not looking. Before you call scope "done":

- 🔴 **All regions.** Re-run enumeration across *every* region, not just your main one — mining and backdoor identities love unused regions.
- 🔴 **All accounts.** In an Org, did the identity pivot to another account via `AssumeRole`? Check the org trail.
- 🔴 **Other creds minted.** Did they `CreateAccessKey`, `CreateLoginProfile`, `CreateUser`, or add an SSH key / EC2 key pair? Each is a persistence foothold you must also kill.
- 🔴 **Standing access changes.** New IAM users/roles, edited trust policies, new identity-provider federation, Lambda functions or EventBridge rules that re-create access.
- 🔴 **The credential's source.** A leaked key came from *somewhere* — git, a laptop, a CI variable, an SSRF-able EC2. Fix the source or it recurs.

## Alert-to-Note Router

Jump straight to the right note based on what fired.

| The alert / symptom is about… | Start at |
|-------------------------------|----------|
| A suspicious API-call timeline / "who did X" | **CloudTrail for DFIR** |
| A leaked/abused access key | **Playbooks → Leaked Access Key** |
| An IAM user/role/policy change | **IAM for DFIR** |
| A temporary session (`ASIA`) / role assumption | **STS**, **01 Identities** |
| SSO / permission-set login | **IAM Identity Center** |
| A public or exfiltrated S3 bucket | **S3 for DFIR**, **Playbooks → Exposed S3 Bucket** |
| An EC2 box behaving oddly / mining / SSRF | **EC2 for DFIR**, **Playbooks → IMDS SSRF to Role Theft** |
| A GuardDuty finding | **GuardDuty for DFIR** |
| Strange network traffic / C2 / port scan | **VPC Flow Logs for DFIR** |
| A Lambda doing something odd | **Lambda for DFIR** |
| A DB accessed/dumped | **RDS / DynamoDB for DFIR** |
| A config drift / "when did this change?" | **AWS Config for DFIR** |
| Cross-cloud pivot | **Cloud → 03 Cross-Cloud Correlation** |

## The Minimum Toolkit

What to have ready before a cloud case:

| Need | Have |
|------|------|
| Read-only investigation access | An IR role with `SecurityAudit` + `ViewOnlyAccess` in every account |
| A place to work | `aws` CLI configured, or **CloudShell**; `jq` for JSON |
| A way past 90 days | CloudTrail **Lake** or Athena over the S3 logs |
| Cross-region reach | A loop over `describe-regions`, or a multi-region trail already in place |
| Managed leads | GuardDuty enabled org-wide (pre-triaged findings) |
| A timeline tool | Anything that sorts events by `eventTime` (jq, a notebook, SecOps) |
| Cross-source correlation in one schema | **Security Lake** — OCSF-normalized CloudTrail/VPC Flow/DNS/GuardDuty, queryable via Athena (see **Logging & Monitoring → Security Lake**) |

> 🔴 If any of these is missing *now*, note it as a **hardening finding** — the next incident will be blind in the same way.

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| How accounts/regions/ARNs work | **AWS → 00 Overview & Terminology** |
| Decoding the `who` in every event | **AWS → 01 IAM & Identities** |
| The audit-log deep dive | **AWS → Logging & Monitoring → CloudTrail** |
| Managed findings that pre-triage cases | **AWS → Security & Detection → GuardDuty** |
| Full attack walk-throughs | **AWS → Playbooks** |
| The whole cloud-DFIR method | **Cloud → 02 Evidence Acquisition in the Cloud** |

## Resources

- AWS incident response guide (official) — https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html
- CloudTrail `lookup-events` — https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html
- `sts get-caller-identity` — https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html
- MITRE ATT&CK Cloud (IaaS) matrix — https://attack.mitre.org/matrices/enterprise/cloud/iaas/
