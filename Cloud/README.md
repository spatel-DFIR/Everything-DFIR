# Cloud DFIR Field Reference

Read-it-mid-incident reference for investigating AWS, Microsoft (Entra / Azure / M365), and Google (Cloud / Workspace) environments. Covers cloud-native attack patterns, authentication/authorization abuse, cross-cloud lateral movement, and evidence acquisition at cloud scale. Every note focuses on native platform tools (AWS CLI, Azure CLI, Graph API, gcloud) and native log queries (CloudTrail, KQL, Log Explorer), not SIEM translation layers.

> Part of the [Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../LICENSE).

---

## Quick Navigation: Start Here

**For new users:** Read the shared foundation notes first, then dive into your provider:

1. **[00 - Cloud Fundamentals](00%20-%20Cloud%20Fundamentals.md)** — Control/data plane, shared responsibility, the three clouds at a glance
2. **[01 - Cloud Identity and Federation](01%20-%20Cloud%20Identity%20and%20Federation.md)** — Identity types and federation across providers
3. **[02 - Evidence Acquisition in the Cloud](02%20-%20Evidence%20Acquisition%20in%20the%20Cloud.md)** — Order of volatility, preservation before analysis, per-provider collection
4. Then your provider's `00/01/02` foundation notes (AWS, Microsoft, Google)

**Responding to an incident now?** Use the router tables below to jump straight to your scenario.

---

## Module Status

- ✅ **In Depth:** 233+ markdown files across three providers (AWS 27 services, Microsoft 63 notes, Google 64 notes); cross-cloud bridges for all 6 provider pairs; multi-cloud playbooks
- 🟡 **Evolving:** SecOps landing playbooks (SIEM/UDM ingestion), advanced threat-hunting query libraries
- ⏳ **Deferred:** Real-time alerting pipeline templates, container-native cloud forensics expansion

---

## Module Structure

```
Cloud/ (233 files total)
├── README.md ⭐ START HERE
│   ├── Quick Navigation Table (7 scenarios)
│   ├── Shared Foundation Notes (8 topics)
│   └── Provider-Specific Navigation
├── 00 - Cloud Fundamentals.md ⭐ ENTRY POINT
│   └── Control/data plane, shared responsibility model
├── 00b - ATT&CK Cloud to Evidence Map.md
│   └── MITRE Technique → Evidence (per provider)
├── 01 - Cloud Identity and Federation.md
│   └── Identity types, federation, SSO abuse
├── 02 - Evidence Acquisition in the Cloud.md
│   └── Order of volatility, log preservation workflows
├── 03 - Cross-Cloud Correlation.md
│   └── Lateral movement across providers, timeline anchors
├── 04 - SecOps Detection & Response Engineering.md
│   └── SIEM/UDM ingestion, detection rules
├── 05 - Cloud Threat Landscape.md
│   └── Attack patterns, threat-informed prioritization
├── 06 - Cloud Service Equivalents.md
│   └── AWS ↔ Azure ↔ GCP service mapping
├── Amazon/AWS/ ⭐ AWS PROVIDER
│   ├── README.md (scenario router + module status)
│   ├── 00–02 - AWS Fundamentals
│   └── Service-Specific Notes (IAM, CloudTrail, S3, EC2, Lambda, KMS, RDS, VPC, EKS, ECS, etc.)
├── Microsoft/ ⭐ AZURE/M365 PROVIDER
│   ├── README.md (scenario router + module status)
│   ├── 00–02 - Microsoft Fundamentals
│   └── Service-Specific Notes (Entra ID, Azure resources, M365 audit, Exchange, SharePoint, Teams)
├── Google/ ⭐ GCP/WORKSPACE PROVIDER
│   ├── README.md (scenario router + module status)
│   ├── 00–02 - Google Fundamentals
│   └── Service-Specific Notes (GCP resources, Workspace audit, BigQuery, Pub/Sub, Cloud SQL, etc.)
├── Cross-Cloud Investigations/
│   ├── AWS-Azure bridge notes, AWS-GCP, Azure-GCP (all 6 directional pairs)
│   └── Multi-Cloud Intrusion Playbook
├── Cloud Posters/ (13 PDFs)
│   └── SANS & community reference materials (see README.md in folder)
└── PLANNING.md (historical archive — build decisions documented)
```

---

## How This Platform Is Organized

**Shared Foundation (00–06):** Fundamentals, identity/federation, evidence acquisition, cross-cloud correlation, threat landscape, and service-equivalence mapping — apply across all three providers.

**Provider-Specific Sections (AWS/Microsoft/Google):** Each provider has its own README with platform-specific IAM, logging, and service deep-dives. Navigate by investigative goal (identity compromise, resource access abuse, data exfiltration) rather than service list.

**Cross-Cloud Investigations:** Bridge notes for all 6 provider-pair combinations (AWS↔Azure, AWS↔GCP, Azure↔GCP, etc.) showing evidence collection from both source and destination perspectives.

**Multi-Cloud Playbooks:** End-to-end scenarios (one actor across multiple clouds, federated identity attacks) that synthesize evidence and detection across providers.

**Evidence Acquisition:** Per-provider collection workflows, considering order of volatility and preservation (logs vanish fast in cloud — capture before analysis).

---

## Situation Router: Find Your Notes

| Scenario | Start Here | Then Read |
|----------|-----------|-----------|
| **AWS (single provider)** | [AWS README](Amazon/AWS/README.md) | Service-specific note (IAM, CloudTrail, S3, EC2, Lambda, etc.) |
| **Azure / M365 / Entra** | [Microsoft README](Microsoft/README.md) | Service-specific note (Entra ID, Azure resources, M365 audit, etc.) |
| **Google Cloud / Workspace** | [Google README](Google/README.md) | Service-specific note (GCP resources, Workspace audit, etc.) |
| **Federated identity / SSO compromise** | [01 - Cloud Identity and Federation](01%20-%20Cloud%20Identity%20and%20Federation.md) | Provider-specific identity notes |
| **Same actor across two clouds** | [03 - Cross-Cloud Correlation](03%20-%20Cross-Cloud%20Correlation.md) | Bridge note for your provider pair |
| **Actor in three+ clouds** | [Multi-Cloud Intrusion Playbook](Cross-Cloud%20Investigations/Multi-Cloud%20Intrusion%20Playbook.md) | Coordination logic + provider-specific notes |
| **"What's the Azure equivalent of this AWS service?"** | [06 - Cloud Service Equivalents](06%20-%20Cloud%20Service%20Equivalents%20(AWS%20%E2%86%94%20Azure%20%E2%86%94%20GCP).md) | Service-specific deep-dive |
| **"Where's the evidence for technique T?"** | [00b - ATT&CK Cloud to Evidence Map](00b%20-%20ATT%26CK%20Cloud%20to%20Evidence%20Map.md) | MITRE technique → evidence location, per provider |

---

## Shared Foundation Notes

| Note | Focus |
|------|-------|
| **[00 - Cloud Fundamentals](00%20-%20Cloud%20Fundamentals.md)** | Control/data plane, shared responsibility, AWS/Azure/GCP architecture |
| **[00b - ATT&CK Cloud to Evidence Map](00b%20-%20ATT%26CK%20Cloud%20to%20Evidence%20Map.md)** | Technique → evidence, per provider (reverse lookup) |
| **[01 - Cloud Identity and Federation](01%20-%20Cloud%20Identity%20and%20Federation.md)** | Identity types, federation, workload identity, SSO abuse |
| **[02 - Evidence Acquisition in the Cloud](02%20-%20Evidence%20Acquisition%20in%20the%20Cloud.md)** | Order of volatility, log preservation, per-provider acquisition workflows |
| **[03 - Cross-Cloud Correlation](03%20-%20Cross-Cloud%20Correlation.md)** | Lateral movement across providers, evidence correlation, timeline anchors |
| **[04 - SecOps Detection & Response](04%20-%20SecOps%20Detection%20%26%20Response%20Engineering.md)** | SIEM/UDM ingestion, cross-cloud detection rules |
| **[05 - Cloud Threat Landscape](05%20-%20Cloud%20Threat%20Landscape.md)** | Attack patterns, threat groups, threat-informed investigation prioritization |
| **[06 - Cloud Service Equivalents](06%20-%20Cloud%20Service%20Equivalents%20(AWS%20%E2%86%94%20Azure%20%E2%86%94%20GCP).md)** | Full AWS ↔ Azure ↔ GCP service mapping |

---

## Providers & Deep-Dives

| Provider | Covers |
|----------|--------|
| **[AWS / Amazon](Amazon/AWS/README.md)** | IAM/STS/SSO, CloudTrail, GuardDuty, S3/EBS/EFS, EC2, Lambda, Systems Manager, KMS/Secrets Manager, VPC, RDS, DynamoDB, EKS, ECS, Fargate |
| **[Microsoft (Entra / Azure / M365)](Microsoft/README.md)** | Entra ID, Azure resources, M365 audit logs, Exchange, SharePoint, Teams |
| **[Google (Cloud / Workspace)](Google/README.md)** | Google Cloud Platform (GCP), Google Workspace, identity, audit logs |

---

## Conventions & Voice

- **Quick Triage** block first — native CLI commands (aws, az, gcloud) for immediate hypothesis testing
- Platform-native log queries (CloudTrail, KQL, Log Explorer) are primary; SIEM translation is secondary
- 🔴 marks high-value / red-flag items — easily missed evidence or high-confidence indicators
- Commands are blank-line separated; tables explain what output means and how to interpret it
- MITRE ATT&CK technique IDs are tagged per note (verify against current Cloud matrix)
- Provider-specific differences (AWS-only, Azure-only, etc.) are called out explicitly

---

## Disclaimers & Scope

- **Field reference, not substitute for understanding.** Verify API behavior and log format against your specific cloud version and region — APIs and audit log schemas evolve.
- **Built from cloud provider documentation and public incident response research.** Not affiliated with or endorsing any vendor or training provider.
- **Scope:** Cloud-native evidence and platform-specific investigation (AWS CloudTrail, Azure Audit Logs, GCP Activity Logs). Compute-side evidence (EC2 forensics, etc.) is cross-linked to Linux/Windows/macOS sections. Container forensics are in [Container/](../Container/README.md).

---

## License

The notes in this repository are released under the [MIT License](../LICENSE).
