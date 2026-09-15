# Google Cloud (GCP) — DFIR

The **infrastructure** half of Google: an **Organization → folders → projects → resources** tree of Compute, Storage, GKE, BigQuery, and more, all riding on **Cloud Identity**. Master log: **Cloud Audit Logs** (Admin Activity / Data Access / System Event / Policy Denied), read in **Logging → Logs Explorer**, `gcloud logging read`, or a **BigQuery** sink.

> Start with the platform foundation notes: **[00 Overview & Terminology](../00%20-%20Google%20Cloud%20%26%20Workspace%20Overview%20%26%20Terminology.md)** · **[01 Google Identities](../01%20-%20Google%20Identities.md)** · **[02 Investigating Google](../02%20-%20Investigating%20Google%20(start%20here).md)**.

## Services by Category

| Category | Services |
|----------|----------|
| **Logging & Monitoring** | [Cloud Audit Logs](Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/What%20is%20Cloud%20Audit%20Logs.md) · [VPC Flow Logs](Logging%20%26%20Monitoring/VPC%20Flow%20Logs/What%20is%20VPC%20Flow%20Logs.md) · [Cloud Logging](Logging%20%26%20Monitoring/Cloud%20Logging/What%20is%20Cloud%20Logging.md) |
| **Identity & Access** | [Cloud IAM](Identity%20%26%20Access/Cloud%20IAM/What%20is%20Cloud%20IAM.md) · [Service Accounts](Identity%20%26%20Access/Service%20Accounts/What%20is%20a%20Service%20Account.md) · [Workload Identity Federation](Identity%20%26%20Access/Workload%20Identity%20Federation/What%20is%20Workload%20Identity%20Federation.md) · [Organization Policy](Identity%20%26%20Access/Organization%20Policy/What%20is%20Organization%20Policy.md) |
| **Security & Detection** | [Security Command Center](Security%20%26%20Detection/Security%20Command%20Center/What%20is%20Security%20Command%20Center.md) |
| **Storage** | [Cloud Storage](Storage/Cloud%20Storage/What%20is%20Cloud%20Storage.md) (+Public GCS Bucket) |
| **Compute** | [Compute Engine](Compute/Compute%20Engine/What%20is%20Compute%20Engine.md) · [Cloud Functions](Compute/Cloud%20Functions/What%20is%20Cloud%20Functions.md) |
| **Networking** | [VPC](Networking/VPC/What%20is%20VPC.md) · [Cloud Load Balancing](Networking/Cloud%20Load%20Balancing/What%20is%20Cloud%20Load%20Balancing.md) |
| **Databases** | [Cloud SQL](Databases/Cloud%20SQL/What%20is%20Cloud%20SQL.md) · [BigQuery](Databases/BigQuery/What%20is%20BigQuery.md) |
| **Serverless & Containers** | [GKE](Serverless%20%26%20Containers/GKE/What%20is%20GKE.md) (+Malicious Pod) · [Cloud Run](Serverless%20%26%20Containers/Cloud%20Run/What%20is%20Cloud%20Run.md) |

Each service folder holds **What is `<svc>`** + **`<svc>` for DFIR** (and **Playbooks/** where a single-service scenario warrants it).

## Playbooks

| Scenario | Open |
|----------|------|
| A leaked / minted SA key | [Service Account Key Abuse](Playbooks/Service%20Account%20Key%20Abuse.md) |
| SSRF/RCE → stolen metadata SA token | [Metadata SSRF to SA Token Theft](Playbooks/Metadata%20SSRF%20to%20SA%20Token%20Theft.md) |
| SA impersonation / token abuse | [Service Account Impersonation & Token Abuse](Playbooks/Service%20Account%20Impersonation%20%26%20Token%20Abuse.md) |
| A cost/CPU spike from mining | [Cryptomining Incident](Playbooks/Cryptomining%20Incident.md) |
| Someone climbed to Owner / org-admin | [IAM Privilege Escalation](Playbooks/IAM%20Privilege%20Escalation.md) |
| Data pulled from GCS/BigQuery/SQL | [Data Exfiltration](Playbooks/Data%20Exfiltration.md) |
| A public GCS bucket | [Public GCS Bucket](Storage/Cloud%20Storage/Playbooks/Public%20GCS%20Bucket.md) |
| A new/crypto pod in GKE | [Malicious Pod and Cryptomining](Serverless%20%26%20Containers/GKE/Playbooks/Malicious%20Pod%20and%20Cryptomining.md) |

## Structure

```
Google Cloud/
├── Logging & Monitoring/    { Cloud Audit Logs · VPC Flow Logs · Cloud Logging }
├── Identity & Access/       { Cloud IAM · Service Accounts · Workload Identity Federation · Org Policy }
├── Security & Detection/    { Security Command Center }
├── Storage/                 { Cloud Storage (+Playbook) }
├── Compute/                 { Compute Engine · Cloud Functions }
├── Networking/              { VPC · Cloud Load Balancing }
├── Databases/               { Cloud SQL · BigQuery }
├── Serverless & Containers/ { GKE (+Playbook) · Cloud Run }
└── Playbooks/               ← tier-2 cross-service chains
```

## Recurring Themes

1. **Start in identity** — one credential (a user, or a stolen SA key) opens the whole project; classify **key vs impersonation vs attached** early.
2. **Keys/tokens outlive passwords** — delete SA keys, remove impersonation grants; don't just reset the user.
3. **The Data Access blind spot** — reads are **off by default** (except BigQuery); enable them or you can't prove what was read.
4. **The metadata server** — a VM/pod's attached SA token is one SSRF away; the default Compute SA (Editor) makes it catastrophic.
5. **Retention & routing** — `_Default` is 30 days; route logs to a **locked BigQuery/SecOps sink** or the evidence is gone.

## Related

- **[Google Workspace](../Google%20Workspace/README.md)** — the SaaS half (same identity fabric; DWD is the bridge)
- **[Google → 01 Google Identities](../01%20-%20Google%20Identities.md)** — SA keys, impersonation, tokens
- **[Amazon/AWS](../../Amazon/AWS/README.md)** · **[Microsoft/Azure](../../Microsoft/Azure/README.md)** — the equivalent IaaS field guides
- **Container →** the core Kubernetes/Docker forensics notes (cross-linked from GKE)
- **External:** [Google Cloud security best practices](https://cloud.google.com/security/best-practices) · [MITRE ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
