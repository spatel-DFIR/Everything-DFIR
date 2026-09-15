# AWS Overview & Terminology

Before you investigate anything in AWS, you need the map: **how an AWS environment is laid out, what the pieces are called, and how each piece shows up in a log.**

This note is that map. Read it once and the service notes will make sense. Keep it open on your first AWS case.

## Contents

- [The One-Paragraph Mental Model](#the-one-paragraph-mental-model)
- [The Account Is the Boundary](#the-account-is-the-boundary)
- [The Organization Hierarchy](#the-organization-hierarchy)
- [Regions and Availability Zones](#regions-and-availability-zones)
- [Global vs Regional — Where Evidence Lives](#global-vs-regional--where-evidence-lives)
- [ARNs — How to Read Any Resource Name](#arns--how-to-read-any-resource-name)
- [How People and Code Reach AWS](#how-people-and-code-reach-aws)
- [The Shared Responsibility Model](#the-shared-responsibility-model)
- [Control Plane vs Data Plane](#control-plane-vs-data-plane)
- [Cross-Provider Terminology](#cross-provider-terminology)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The One-Paragraph Mental Model

AWS is a set of **services** (S3, EC2, IAM…) you drive by making **API calls**. Every call is made *by* an **identity** (a user, a role, a service), *against* a **resource** (a bucket, an instance), *inside* an **account**, *in* a **region**. **CloudTrail records the call.** Get comfortable with those five words — identity, action, resource, account, region — and every AWS log will read the same way.

## The Account Is the Boundary

An **AWS account** is the fundamental unit. It is:

- A **security boundary** — resources in one account are isolated from another by default.
- A **billing boundary** — one bill per account.
- Identified by a **12-digit account ID** (e.g. `123456789012`). You will see this number *everywhere* — in ARNs, in log events, in bucket paths.

> 🔴 On a case, the **account ID is your first anchor.** "Which account did this happen in?" scopes everything else. Cross-account activity (an identity in account A acting on account B) is a major investigative signal.

Large organizations do **not** run one giant account. They run **many** — often one per team, app, or environment (dev/stage/prod) — tied together under **AWS Organizations** (next section). A single company can have hundreds of accounts.

**The root user.** Every account is created with one all-powerful **root user** (the email address that opened the account). It can do *anything* and cannot be restricted by IAM policy. Best practice is to lock it away and never use it.

> 🔴 **Any `userIdentity.type = Root` activity is a top-tier red flag** unless you have a documented break-glass reason. Root should be near-silent in logs.

## The Organization Hierarchy

**AWS Organizations** ties many accounts into one tree with central governance.

```
Organization (root)
└── Organizational Unit (OU)   ← e.g. "Production", "Sandbox"
    └── Account                ← the security/billing boundary
        └── Region             ← e.g. us-east-1
            └── Resource        ← e.g. an S3 bucket, an EC2 instance
```

| Layer | What it is | Why the analyst cares |
|-------|-----------|-----------------------|
| **Organization** | The whole company's tree of accounts | Scope of an **org-wide CloudTrail** and **SCPs** |
| **Management account** | The account that *owns* the Org (formerly "master/payer") | 🔴 Most powerful account; compromise here = everything |
| **Organizational Unit (OU)** | A folder grouping accounts | Where **Service Control Policies** attach |
| **Member account** | Any account in the Org that isn't the management account | The normal blast-radius unit |
| **Service Control Policy (SCP)** | A guardrail that sets the *maximum* permissions for accounts in an OU | An SCP can block an attacker even with admin creds — or, if edited, *un*-block them |

> **Investigative value:** an **organization trail** logs every account into one place, and an SCP can deny dangerous actions (like `cloudtrail:StopLogging`) across the whole company. Both are things you check early — see **02 - Investigating AWS**.

## Regions and Availability Zones

AWS runs in physically separate **regions** around the world. Each region is fully isolated from the others.

| Term | What it is | Example |
|------|-----------|---------|
| **Region** | An isolated geographic area with its own copy of services | `us-east-1` (N. Virginia), `eu-west-1` (Ireland) |
| **Availability Zone (AZ)** | One or more datacenters inside a region | `us-east-1a`, `us-east-1b` |
| **Region code** | The short string you'll read in ARNs and logs | `us-east-1`, `ap-southeast-2` |

Two facts that matter on a case:

- **Resources are region-scoped.** An EC2 instance in `us-east-1` does not exist in `eu-west-1`. To see it, you must look in the right region (CLI: `--region`; console: the region picker, top-right).
- 🔴 **Attackers hide in unused regions.** A company that only operates in `us-east-1` won't notice cryptomining spun up in `ap-south-1`. **Always sweep all regions.** GuardDuty and a multi-region CloudTrail see every region at once — a single-region trail does not.

**`us-east-1` is special.** It is the default/home region: **global services report their events there**, and some things (IAM, the account's billing) only live there. When in doubt, look in `us-east-1` too.

## Global vs Regional — Where Evidence Lives

Knowing whether a service is *global* or *regional* tells you **where its logs land** and **where to point your CLI**.

| Scope | Services | Where their CloudTrail events land |
|-------|----------|-----------------------------------|
| **Global** | IAM, STS*, CloudFront, Route 53, WAF (for CloudFront), Organizations, Account/Billing | **`us-east-1`** (regardless of where the caller was) |
| **Regional** | EC2, S3**, Lambda, RDS, VPC, GuardDuty, most everything else | The region the action happened in |

\* **STS** has both a *global* endpoint (`sts.amazonaws.com`, logs to `us-east-1`) and *regional* endpoints (`sts.eu-west-1.amazonaws.com`, log to that region). This trips people up — see **STS** note.
\** **S3** is regional per bucket, but the namespace is global (bucket names are globally unique).

> 🔴 **Consequence for logging:** if your CloudTrail is single-region on `eu-west-1`, you **miss all IAM and STS global events** (they go to `us-east-1`). This is why "multi-region trail" is a non-negotiable baseline.

## ARNs — How to Read Any Resource Name

An **ARN** (Amazon Resource Name) uniquely identifies every resource. You will read hundreds of them. Learn the anatomy once:

```
arn:partition:service:region:account-id:resource-type/resource-id
 │      │        │       │        │            │
 │      │        │       │        │            └─ what & which: user/alice, instance/i-0abc…
 │      │        │       │        └─ the 12-digit account ID
 │      │        │       └─ us-east-1  (BLANK for global services like IAM/S3)
 │      │        └─ iam, s3, ec2, lambda…
 │      └─ aws (commercial) · aws-cn (China) · aws-us-gov (GovCloud)
 └─ always the literal "arn"
```

Worked examples — memorize the shapes:

| ARN | What it is |
|-----|-----------|
| `arn:aws:iam::123456789012:user/alice` | IAM user **alice** (note the **blank region** — IAM is global) |
| `arn:aws:iam::123456789012:role/deploy` | IAM role **deploy** |
| `arn:aws:sts::123456789012:assumed-role/deploy/i-0abc123` | A **temporary session** from assuming `deploy` |
| `arn:aws:s3:::my-bucket/reports/q3.pdf` | An S3 object (**blank region AND account** for S3) |
| `arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456` | An EC2 instance in `us-east-1` |
| `arn:aws:lambda:us-east-1:123456789012:function:billing-cron` | A Lambda function |

> 🔴 The **`assumed-role/<role>/<session-name>`** shape is one of the most important things to recognize. It means someone (or something) **assumed a role** and is now acting *as* it. The session name is often an EC2 instance ID, a username, or an attacker-chosen string — a huge lead. See **01 - IAM & Identities** and **STS**.

## How People and Code Reach AWS

Every action arrives through one of these front doors. The **`userAgent`** field in CloudTrail tells you which — and *that* separates a human from a script.

| Access path | What it is | `userAgent` tell |
|-------------|-----------|------------------|
| **Management Console** | The web GUI at `console.aws.amazon.com` | Browser string, or `AWS Internal`, or `signin.amazonaws.com` for the login itself |
| **AWS CLI** | The `aws` command-line tool | `aws-cli/2.x …` |
| **SDKs** | Code using boto3 (Python), etc. | `Boto3/…`, `aws-sdk-go/…`, `aws-sdk-js/…` |
| **CloudShell** | A browser-based shell AWS hosts | `aws-cli/…` from an AWS IP |
| **Direct HTTPS API** | Raw signed requests to the service endpoint | Custom/absent — 🔴 unusual tooling is a flag |
| **Infrastructure-as-Code** | Terraform, CloudFormation, CDK | `terraform/…`, `cloudformation.amazonaws.com`, etc. |

> **Human vs script is a core triage question.** A `ConsoleLogin` followed by browser-`userAgent` clicks is a person. A burst of `boto3` calls at machine speed is automation — either legitimate CI/CD or an attacker's script. See **CloudTrail for DFIR**.

## The Shared Responsibility Model

AWS splits security into **"of the cloud"** (their job) and **"in the cloud"** (yours). This tells you **what evidence even exists.**

| | AWS's responsibility ("of the cloud") | Your responsibility ("in the cloud") |
|-|----------------------------------------|--------------------------------------|
| **Covers** | Hardware, hypervisor, physical DCs, managed-service internals | Your data, IAM config, network rules, guest OS, app code |
| **You get logs for…** | Very little — you don't see the hypervisor | **Everything on your side**: CloudTrail, VPC Flow, OS logs you enable |
| **Investigative meaning** | You **cannot** ask AWS for hypervisor forensics on a normal incident | You **must** have turned on the logs *before* the incident — CloudTrail, flow logs, GuardDuty |

> 🔴 **The hard lesson:** if data events weren't enabled, "which objects did they read from S3?" is **unanswerable** — the evidence was never created. Cloud forensics is *pre-decided* by what logging you turned on. Hardening = making sure future-you has evidence.

## Control Plane vs Data Plane

This one distinction explains most "why can't I see it?" gaps.

| Plane | What it is | Logged by default? | Example |
|-------|-----------|--------------------|---------|
| **Control plane** | Managing the resource itself | ✅ CloudTrail **management events** (on by default) | `RunInstances`, `CreateBucket`, `AttachUserPolicy` |
| **Data plane** | Using what's inside the resource | 🔴 CloudTrail **data events** (OFF by default) | S3 `GetObject`, Lambda `Invoke`, DynamoDB `GetItem` |

> 🔴 The classic blind spot: you can see someone *created* access to a bucket (control plane, logged) but **not which objects they read** (data plane, off by default). Enable data events on crown-jewel resources. See **CloudTrail** and **S3**.

## Cross-Provider Terminology

If you know one cloud, this table ports your instinct to the others.

| Concept | AWS | Azure | Google Cloud |
|---------|-----|-------|--------------|
| Top of the tree | **Organization** | **Management Group / Tenant** | **Organization** |
| Grouping folder | **Organizational Unit (OU)** | **Management Group** | **Folder** |
| Billing/isolation unit | **Account** | **Subscription** | **Project** |
| Identity directory | **IAM** (per account) | **Entra ID** (per tenant) | **Cloud IAM + Cloud Identity** |
| Human/app identity | **IAM user / role** | **User / service principal / managed identity** | **User / service account** |
| Temp credentials | **STS** assumed-role session | **OAuth token** | **Short-lived SA token** |
| Guardrail policy | **SCP** | **Azure Policy** | **Organization Policy** |
| Audit log | **CloudTrail** | **Activity Log** | **Cloud Audit Logs (Admin Activity)** |
| Data-access log | CloudTrail **data events** | **Resource/diagnostic logs** | Cloud Audit Logs **Data Access** |
| Network flow log | **VPC Flow Logs** | **NSG Flow Logs** | **VPC Flow Logs** |
| Managed threat detection | **GuardDuty** | **Defender for Cloud** | **Security Command Center** |
| Object storage | **S3** | **Blob Storage** | **Cloud Storage (GCS)** |
| Virtual machine | **EC2** | **Virtual Machine** | **Compute Engine** |
| Serverless function | **Lambda** | **Azure Functions** | **Cloud Functions** |
| Region | **Region** | **Region** | **Region** |
| Resource name | **ARN** | **Resource ID** | **Resource name / full path** |

> Full detail lives in **Cloud → 06 Cloud Service Equivalents**. This table is the quick-glance version.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Account** | The 12-digit security & billing boundary |
| **Account ID** | The 12-digit number identifying an account |
| **Root user** | The all-powerful original account owner (🔴 should be silent) |
| **Organization (Org)** | A tree of accounts under central governance |
| **Management account** | The account that owns the Org (most powerful) |
| **OU** | Organizational Unit — a folder of accounts |
| **SCP** | Service Control Policy — a permissions guardrail |
| **Region** | An isolated geographic area (`us-east-1`) |
| **Availability Zone** | A datacenter cluster within a region |
| **ARN** | Amazon Resource Name — the unique ID of any resource |
| **Partition** | `aws` / `aws-cn` / `aws-us-gov` |
| **Principal** | Any identity that can make a request (user, role, service, account) |
| **Control plane** | Managing resources (logged by default) |
| **Data plane** | Using resource contents (data events, off by default) |
| **Service** | An AWS product (S3, EC2, IAM…) you call via API |
| **Endpoint** | The URL a service listens on (`ec2.us-east-1.amazonaws.com`) |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Who the identities are (user vs role vs token) | **AWS → 01 IAM & Identities** |
| Where to start a case + the triage flow | **AWS → 02 Investigating AWS (start here)** |
| The audit log that records all of this | **AWS → Logging & Monitoring → CloudTrail** |
| The equivalents in other clouds | **Cloud → 06 Cloud Service Equivalents** |
| How AWS maps to attacker techniques | **Cloud → 00b ATT&CK Cloud to Evidence Map** |

## Resources

- What is AWS / global infrastructure — https://aws.amazon.com/about-aws/global-infrastructure/
- AWS Organizations terminology — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html
- ARN reference — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
- Regions and Availability Zones — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html
- Shared Responsibility Model — https://aws.amazon.com/compliance/shared-responsibility-model/
- Service endpoints and quotas — https://docs.aws.amazon.com/general/latest/gr/aws-service-information.html
