# Cloud Fundamentals

This is the shared mental model for **cloud DFIR across AWS, Azure/Microsoft 365, and Google Cloud/Workspace**. Read it once and the per-provider sections all read the same way. It exists because the three clouds differ in vocabulary but are **the same shape underneath** — learn the shape and you can investigate any of them.

If you're heading straight into one provider, open its own `00`/`01`/`02` foundation notes. This note is the layer *above* those.

## Contents

- [How Cloud DFIR Is Different](#how-cloud-dfir-is-different)
- [The Universal Model — Five Words](#the-universal-model--five-words)
- [Control Plane vs Data Plane (Everywhere)](#control-plane-vs-data-plane-everywhere)
- [Shared Responsibility (Everywhere)](#shared-responsibility-everywhere)
- [The Three Clouds at a Glance](#the-three-clouds-at-a-glance)
- [Where Evidence Lives — and Where It Doesn't](#where-evidence-lives--and-where-it-doesnt)
- [Ephemerality — The Clock Is Always Running](#ephemerality--the-clock-is-always-running)
- [Identity Is the New Perimeter](#identity-is-the-new-perimeter)
- [What's the Same, What Differs](#whats-the-same-what-differs)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How Cloud DFIR Is Different

If your instinct comes from host/endpoint forensics, five things change:

| On a host you… | In the cloud you… |
|----------------|-------------------|
| Image the disk, carve the filesystem | Read an **API audit log** — the primary evidence is *who called what* |
| Own all the evidence | Only get what **you turned on before the incident** (shared responsibility) |
| Have time — the disk persists | Race the clock — instances, containers, and tokens **vanish** |
| Chase a process/user on one box | Chase an **identity** that can act on everything at once, from anywhere |
| Work network + OS logs | Work **control-plane logs, identity logs, and (if enabled) data-plane logs** |

> 🔴 **The single most important cloud-DFIR truth:** *cloud forensics is pre-decided by your logging.* "Which objects did they read?" is only answerable if data-plane logging was on **before** the attack. Hardening = making sure future-you has evidence.

## The Universal Model — Five Words

Every cloud action, in every provider, is the same sentence:

> An **identity** performs an **action** on a **resource**, inside an **account/project/subscription**, in a **region**.

And a **control-plane audit log records the call.** Internalize those five nouns and every cloud log reads the same:

| Noun | AWS | Azure / Entra | Google Cloud |
|------|-----|---------------|--------------|
| **Identity** | IAM user / role / assumed-role session | User / service principal / managed identity | User / service account |
| **Action** | API call (`s3:GetObject`) | Operation (`Microsoft.Storage/...`) | Method (`storage.objects.get`) |
| **Resource** | ARN | Resource ID | Resource full name |
| **Account boundary** | Account (12-digit) | Subscription / tenant | Project |
| **Region** | Region | Region | Region / location |
| **The audit log** | **CloudTrail** | **Activity Log / Entra logs / Unified Audit Log** | **Cloud Audit Logs** |

## Control Plane vs Data Plane (Everywhere)

This one distinction explains most "why can't I see it?" gaps in *any* cloud.

| Plane | What it is | Logged by default? | Example |
|-------|-----------|--------------------|---------|
| **Control plane** | Managing the resource | ✅ Yes | Create/delete a bucket, attach a policy, launch a VM |
| **Data plane** | Using what's *inside* the resource | 🔴 Usually **off** | Read an object, decrypt a secret, query a row |

| Provider | Control-plane log | Data-plane log (must enable) |
|----------|-------------------|------------------------------|
| **AWS** | CloudTrail management events | CloudTrail **data events** |
| **Azure** | Activity Log | **Resource/diagnostic logs** (per service) |
| **Microsoft 365** | Unified Audit Log | (mostly on, but mailbox auditing / detailed logs vary) |
| **Google Cloud** | Cloud Audit Logs **Admin Activity** | Cloud Audit Logs **Data Access** |

> 🔴 The classic blind spot in every cloud: you can prove someone *gained access* to a store (control plane, logged) but not *what they read* (data plane, often off). Always establish, per resource, whether data-plane logging was on across your window.

## Shared Responsibility (Everywhere)

The provider secures the cloud *of* the platform (hardware, hypervisor, managed-service internals); **you** secure what's *in* it (identity config, data, network rules, app code). For the analyst this means: you **cannot** ask the provider for hypervisor forensics on a normal incident, and you only have the logs you enabled. The more managed the service (VM → container → serverless), the **less host evidence** you get and the more you rely on the audit log.

### IaaS / PaaS / SaaS — Where the Line Sits

The service model *is* the shared-responsibility split, made concrete. Same principle above, three fixed points on the spectrum:

| Model | Example services | Customer owns | Provider owns | DFIR/evidence implication |
|-------|-------------------|----------------|----------------|----------------------------|
| **IaaS** | EC2, Azure VMs, Compute Engine | OS, patching, identity config, data, network rules, app code | Hardware, hypervisor, physical/network infra | You can get **host-level artifacts** (disk snapshot, memory, OS/agent logs) in addition to the audit log |
| **PaaS** | Lambda/Azure Functions/Cloud Functions, RDS, App Engine | Identity config, data, app code/config | OS, runtime, patching, hardware, hypervisor | **No OS to image** — evidence is the audit log + service-specific logs (e.g., function invocation logs, DB audit logs) the provider exposes |
| **SaaS** | M365/Exchange Online, Google Workspace, Salesforce | Data, user/access config (within the app) | Everything else — app code, runtime, OS, hardware | **Entirely dependent on the provider's audit logs** (e.g., Unified Audit Log, Workspace Alert Center) — nothing to acquire outside what the vendor chose to log |

## The Three Clouds at a Glance

| | **AWS** | **Microsoft (Entra / Azure / M365)** | **Google (Cloud / Workspace)** |
|-|---------|--------------------------------------|-------------------------------|
| **Top of tree** | Organization | Tenant (+ Management Groups) | Organization |
| **Grouping** | Organizational Unit (OU) | Management Group | Folder |
| **Isolation unit** | Account | Subscription | Project |
| **Identity fabric** | IAM (per account) | **Entra ID** (per tenant) | **Cloud Identity** |
| **Human/app identity** | User / role | User / service principal / managed identity | User / service account |
| **Temp credential** | STS `ASIA` session | OAuth access token | Short-lived SA token |
| **Control-plane log** | CloudTrail | Activity Log + Entra Audit/Sign-in + UAL | Cloud Audit Logs |
| **Threat detection** | GuardDuty | Defender for Cloud / XDR | Security Command Center |
| **Guardrail policy** | SCP | Azure Policy | Organization Policy |
| **Metadata endpoint** | IMDS `169.254.169.254` | IMDS `169.254.169.254` | metadata `169.254.169.254` / `metadata.google.internal` |

## Where Evidence Lives — and Where It Doesn't

| Evidence type | Where to get it | Gotcha |
|---------------|-----------------|--------|
| **Who did what** (control plane) | The provider's audit log | Region/scope: a single-region or single-account trail misses the rest |
| **Sign-ins / auth** | Identity logs (Entra Sign-in, AWS Console/SSO, Google Login audit) | Federated logins may need the **upstream IdP** too |
| **Data access** | Data-plane logs — *if enabled* | Often off; may never have existed |
| **Network** | Flow logs (VPC/NSG) | Metadata only — no payload; sampling |
| **Host** | Disk snapshot + memory, before termination | Ephemeral compute may be gone already |
| **The token/creds** | The identity that minted them | Temp sessions expire; capture the mint event |

## Ephemerality — The Clock Is Always Running

Cloud evidence deletes itself. Prioritize by volatility:

1. **Running compute** — a container/serverless task or spot instance may live minutes. Capture *now* (→ **02 Evidence Acquisition**).
2. **Temporary credentials** — STS/OAuth/SA tokens expire in minutes to hours. Record the mint event and revoke.
3. **Auto-expiring logs** — some logs (SSM command history, session lists, provider-native buffers) have short retention.
4. **Attacker cleanup** — deleted resources, disabled logging, purged findings.

> Decide **capture vs contain** early: sometimes you snapshot before you isolate, because isolation (or the attacker) destroys the evidence.

## Identity Is the New Perimeter

There is no firewall around "the cloud." The boundary is **identity**: a valid credential from anywhere is inside. Consequences that shape every investigation:

- The **first question is always "who?"** — decode the identity block before anything else (→ **01 Cloud Identity and Federation**).
- **Federation blurs the boundary further** — one SSO/IdP identity can hold keys to multiple clouds (→ **03 Cross-Cloud Correlation**).
- **Temporary credentials** dominate — follow the mint-and-use chain (`AKIA→AssumeRole→ASIA`, token requests, SA impersonation).
- **Containment = the credential *and* the persistence** — killing the entry credential without hunting backdoors is the #1 cloud-IR failure.

## What's the Same, What Differs

**Same in every cloud:** the five-word model; a control-plane audit log; the control/data-plane split; shared responsibility; identity-as-perimeter; temporary-credential pivots; a metadata service at `169.254.169.254` reachable by SSRF; storage-exposure, cryptomining, and identity-compromise as the top incident types.

**Differs:** vocabulary (account vs subscription vs project); how identity federation is wired; which logs are on by default; native query language (**CloudTrail Lake/Athena SQL** vs **KQL** vs **Log Explorer/BigQuery**); how you revoke a session; retention defaults.

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The "who" across all three clouds | **01 Cloud Identity and Federation** |
| Capturing evidence before it vanishes | **02 Evidence Acquisition in the Cloud** |
| One actor pivoting across providers | **03 Cross-Cloud Correlation** |
| Landing all three into SecOps + detections | **04 SecOps Detection & Response Engineering** |
| Who attacks cloud and how | **05 Cloud Threat Landscape** |
| The full AWS↔Azure↔GCP service map | **06 Cloud Service Equivalents** |
| Technique → evidence per provider | **00b ATT&CK Cloud to Evidence Map** |
| The provider specifics | **Amazon/AWS → 00** · **Microsoft → 00** · **Google → 00** |

## Resources

- MITRE ATT&CK Cloud matrix — https://attack.mitre.org/matrices/enterprise/cloud/
- AWS Security Incident Response Guide — https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html
- Microsoft Incident Response playbooks — https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks
- Google Cloud security best practices / IR — https://cloud.google.com/security/best-practices
