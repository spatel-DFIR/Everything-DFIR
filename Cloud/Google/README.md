# Google Cloud DFIR Field Reference

Hands-on reference for investigating Google Workspace and Google Cloud (GCP) environments. Covers Cloud Identity, user/service account compromise, OAuth consent-grant attacks, mailbox takeover, IAM privilege escalation, data exfiltration, and cross-cloud lateral movement. Primary lens: native consoles (Cloud Console, Admin Console), CLI tools (gcloud, gsutil, bq), and native log queries (Logging, Log Explorer, BigQuery).

> Part of the [Cloud / Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../../../LICENSE).

---

## Architecture: One Directory, Two Clouds

```
        ┌──────────────────────── Cloud Identity (one directory, your domain) ─────────────────────┐
        │                                                                                           │
        │   Cloud Identity  ── the identity backbone ── one account opens both clouds below         │
        │      │                                                                                    │
        │      ├──► Google Workspace   (SaaS: Gmail, Drive/Docs, Meet, Calendar, Chat)              │
        │      └──► Google Cloud/GCP   (IaaS/PaaS: Organization → folders → projects → resources)   │
        └───────────────────────────────────────────────────────────────────────────────────────────┘
```

**Core principle:** Cloud Identity is the front door to both Workspace and GCP. Almost every Google incident starts with identity compromise. Start your investigation in [01 - Google Identities](01%20-%20Google%20Identities.md).

---

## Quick Navigation: Start Here

**For new users:** Read the three foundation notes in order, then navigate to services by scenario:

1. **[00 - Google Cloud & Workspace Overview & Terminology](00%20-%20Google%20Cloud%20%26%20Workspace%20Overview%20%26%20Terminology.md)** — Organization/folder/project hierarchy, Cloud Identity, two admin worlds, three master logs
2. **[01 - Google Identities](01%20-%20Google%20Identities.md)** — Identity types (user, service account), keys (long-lived) vs tokens (short-lived), domain-wide delegation, federation
3. **[02 - Investigating Google (start here)](02%20-%20Investigating%20Google%20(start%20here).md)** — First-hour triage flow across both clouds

**Responding to an incident now?** Use the scenario router below to jump straight to your situation.

---

## Module Status

- ✅ **Complete:** 55+ investigation notes covering Google Workspace (Admin Audit, Login & Auth, Gmail, Drive, OAuth, Alert Center) and Google Cloud (Cloud Audit Logs, VPC Flow, Cloud Logging, IAM, Service Accounts, Workload Identity Federation, Org Policy, Cloud Security Command Center, storage, compute, databases, GKE, Cloud Run); 15+ playbooks for cross-service attack scenarios
- Coverage includes identity/token compromise, OAuth consent-grant abuse, mailbox takeover, privilege escalation (Super Admin / Org Admin), data exfiltration, cryptojacking, and lateral movement
- All MITRE ATT&CK Cloud techniques referenced; cross-linked to Linux/Windows notes for compute-side investigation (Compute Engine, GKE, Cloud SQL)

---

## The Two Pillars

| Pillar | What it is | Master log | Open |
|--------|-----------|-----------|------|
| **[Google Workspace](Google%20Workspace/README.md)** | The SaaS suite (mail, files, chat) | Workspace audit logs | Admin Audit · Login & Auth · Gmail · Drive & Docs · OAuth & Third-Party Apps · Alert Center |
| **[Google Cloud (GCP)](Google%20Cloud/README.md)** | The infrastructure cloud | Cloud Audit Logs | Cloud Audit Logs · VPC Flow · Cloud Logging · Cloud IAM · Service Accounts · Workload Identity Federation · Org Policy · SCC · Cloud Storage · Compute Engine · Cloud Functions · VPC · Load Balancing · Cloud SQL · BigQuery · GKE · Cloud Run |

## Situation → Open This

| The alert / symptom is about… | Start here |
|-------------------------------|-----------|
| A suspicious login / MFA bypass / session theft | **[Workspace → Login & Auth Audit](Google%20Workspace/Login%20%26%20Auth%20Audit/Login%20%26%20Auth%20Audit%20for%20DFIR.md)** · **[Account Takeover](Google%20Workspace/Playbooks/Account%20Takeover.md)** |
| A consented app reading mail/Drive | **[Illicit OAuth Grant](Google%20Workspace/Playbooks/Illicit%20OAuth%20Grant.md)** |
| A compromised mailbox / forwarding | **[BEC and Mail Forwarding](Google%20Workspace/Playbooks/BEC%20and%20Mail%20Forwarding.md)** |
| Mass file download / exfil | **[Mass Drive Exfiltration](Google%20Workspace/Playbooks/Mass%20Drive%20Exfiltration.md)** |
| A new SA key / stolen SA credential | **[Service Account Key Abuse](Google%20Cloud/Playbooks/Service%20Account%20Key%20Abuse.md)** |
| A stolen metadata token (SSRF) | **[Metadata SSRF to SA Token Theft](Google%20Cloud/Playbooks/Metadata%20SSRF%20to%20SA%20Token%20Theft.md)** |
| An Owner / org-admin grant | **[IAM Privilege Escalation](Google%20Cloud/Playbooks/IAM%20Privilege%20Escalation.md)** |
| A public GCS bucket | **[Public GCS Bucket](Google%20Cloud/Storage/Cloud%20Storage/Playbooks/Public%20GCS%20Bucket.md)** |
| A crypto pod in GKE / mining | **[Malicious Pod and Cryptomining](Google%20Cloud/Serverless%20%26%20Containers/GKE/Playbooks/Malicious%20Pod%20and%20Cryptomining.md)** · **[Cryptomining Incident](Google%20Cloud/Playbooks/Cryptomining%20Incident.md)** |

## Structure

```
Google/
├── 00 - Google Cloud & Workspace Overview & Terminology.md   ← org, projects, two admin worlds, logs
├── 01 - Google Identities.md                                 ← the "who" decoder ring + keys/tokens
├── 02 - Investigating Google (start here).md                 ← first-hour triage flow
├── Google Workspace/  { Admin Audit · Login & Auth · Gmail · Drive & Docs · OAuth & Apps · Alert Center + Playbooks }
└── Google Cloud/      { Cloud Audit Logs · VPC Flow · Cloud Logging · IAM · Service Accounts · WIF · Org Policy ·
                         SCC · GCS · Compute · Functions · VPC · LB · Cloud SQL · BigQuery · GKE · Cloud Run + Playbooks }
```

## The Five Recurring Themes

Patterns across nearly every Google case — internalize these:

1. **Identity is the front door** — one account opens Workspace *and* GCP; start every case in identity.
2. **Keys and tokens outlive passwords** — you must **delete SA keys** and **remove impersonation grants**, not just reset the password.
3. **The two admin worlds** — Super Admin (directory) ≠ Org Admin (GCP); the bridge is a Super Admin granting org-level IAM (and domain-wide delegation bridges GCP SAs into Workspace data).
4. **Mind the data-plane blind spot** — **Data Access logging is OFF by default**; object/row reads are invisible until you enable it.
5. **Retention & routing** — `_Default` 30d, Workspace ~6mo; route logs to a **sink** (BigQuery/GCS/SecOps) or the evidence is gone.

## Related

- **[Cloud → 00 Cloud Fundamentals](../00%20-%20Cloud%20Fundamentals.md)** · **[06 Cloud Service Equivalents](../06%20-%20Cloud%20Service%20Equivalents%20(AWS%20%E2%86%94%20Azure%20%E2%86%94%20GCP).md)** — cross-cloud context
- **[Cloud → 03 Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** — the same actor pivoting across providers
- **[Amazon/AWS](../Amazon/AWS/README.md)** · **[Microsoft](../Microsoft/README.md)** — the other platform field guides (same shape)
- **Container →** the core Kubernetes/Docker forensics notes (cross-linked from GKE)
- **External:** [Google Cloud security best practices](https://cloud.google.com/security/best-practices) · [MITRE ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
