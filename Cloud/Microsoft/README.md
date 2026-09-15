# Microsoft Cloud DFIR Field Reference

Hands-on reference for investigating Entra ID, Microsoft 365, and Azure environments. Covers identity compromise, consent-grant attacks, mailbox access, privilege escalation, data exfiltration, and cross-cloud lateral movement. Primary lens: native portals (Entra, Purview, Azure), CLI tools (az, Graph, Exchange PowerShell), and native log queries (KQL in Log Analytics/Sentinel).

> Part of the [Cloud / Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../../../LICENSE).

---

## Architecture: One Tenant, Three Worlds

```
        ┌──────────────────────────── Tenant (one Entra directory) ────────────────────────────┐
        │                                                                                        │
        │   Entra ID  ── the identity backbone ── one token opens both clouds below              │
        │      │                                                                                 │
        │      ├──► Microsoft 365   (SaaS: Exchange, SharePoint/OneDrive, Teams)                 │
        │      └──► Azure           (IaaS/PaaS: subscriptions, VMs, storage, Key Vault, AKS)     │
        └────────────────────────────────────────────────────────────────────────────────────────┘
```

**Core principle:** Entra ID is the front door to both M365 and Azure. Almost every Microsoft incident starts with identity compromise. Start your investigation in [01 - Entra ID & Identities](01%20-%20Entra%20ID%20%26%20Identities.md).

---

## Quick Navigation: Start Here

**For new users:** Read the three foundation notes in order, then navigate to services by scenario:

1. **[00 - Microsoft Cloud Overview & Terminology](00%20-%20Microsoft%20Cloud%20Overview%20%26%20Terminology.md)** — Tenant architecture, subscriptions, two RBAC worlds, three master logs
2. **[01 - Entra ID & Identities](01%20-%20Entra%20ID%20%26%20Identities.md)** — Identity types (user, guest, service principal, managed identity), tokens (access/refresh/PRT)
3. **[02 - Investigating Microsoft (start here)](02%20-%20Investigating%20Microsoft%20(start%20here).md)** — First-hour triage flow across all three pillars

**Responding to an incident now?** Use the scenario router below to jump straight to your situation.

---

## Module Status

- ✅ **Complete:** 60+ investigation notes covering Entra ID, Microsoft 365 (Exchange, SharePoint, Teams, Graph), and Azure (Activity Log, RBAC, Managed Identities, Storage, VMs, Key Vault, AKS, Defender); 25+ playbooks for cross-service attack scenarios
- Coverage includes identity/token compromise, consent-grant abuse, mailbox takeover, privilege escalation (Global Admin / Owner), data exfiltration, cryptojacking, and lateral movement
- All MITRE ATT&CK Cloud techniques referenced; cross-linked to Linux/Windows notes for compute-side investigation (VMs, AKS, SQL)

---

## The Three Pillars

| Pillar | What it is | Master log | Open |
|--------|-----------|-----------|------|
| **[Entra ID](Entra%20ID/README.md)** | The identity directory (front door to both clouds) | Entra sign-in + audit logs | Sign-in Logs · Audit Logs · Conditional Access & MFA · Applications & Service Principals · Roles & PIM · Identity Protection |
| **[M365](M365/README.md)** | The SaaS suite (email, files, chat) | Unified Audit Log | Unified Audit Log · Exchange Online · SharePoint & OneDrive · Teams · Microsoft Graph · Purview & eDiscovery |
| **[Azure](Azure/README.md)** | The infrastructure cloud | Azure Activity Log | Activity Log · Azure RBAC · Managed Identities · Defender for Cloud · Storage · VMs · Key Vault · NSG Flow Logs · AKS |

## Situation → Open This

| The alert / symptom is about… | Start here |
|-------------------------------|-----------|
| A risky sign-in / MFA bypass / token replay | **[Entra → Sign-in Logs](Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** · **[Token Theft and AiTM](Entra%20ID/Playbooks/Token%20Theft%20and%20AiTM.md)** |
| A consented app reading mail/files | **[Illicit Consent Grant](Entra%20ID/Playbooks/Illicit%20Consent%20Grant.md)** |
| Someone got Global Admin | **[Privileged Role Escalation](Entra%20ID/Playbooks/Privileged%20Role%20Escalation.md)** |
| A compromised mailbox / payment fraud | **[Business Email Compromise](M365/Exchange%20Online/Playbooks/Business%20Email%20Compromise.md)** |
| Mass file download / exfil | **[Mass Download Exfiltration](M365/SharePoint%20%26%20OneDrive/Playbooks/Mass%20Download%20Exfiltration.md)** |
| An Owner grant / `elevateAccess` | **[Azure RBAC](Azure/Azure%20RBAC/Azure%20RBAC%20for%20DFIR.md)** |
| A stolen managed identity (SSRF) | **[Managed Identity Theft via SSRF](Azure/Playbooks/Managed%20Identity%20Theft%20via%20SSRF.md)** |
| A public storage container | **[Exposed Blob Container](Azure/Storage/Playbooks/Exposed%20Blob%20Container.md)** |
| A crypto pod in AKS / mining | **[Malicious Pod and Cryptomining](Azure/AKS/Playbooks/Malicious%20Pod%20and%20Cryptomining.md)** · **[Cryptomining Incident](Azure/Playbooks/Cryptomining%20Incident.md)** |

## Structure

```
Microsoft/
├── 00 - Microsoft Cloud Overview & Terminology.md   ← tenant, subs, two RBAC worlds, three logs
├── 01 - Entra ID & Identities.md                    ← the "who" decoder ring + tokens
├── 02 - Investigating Microsoft (start here).md     ← first-hour triage flow
├── Entra ID/   { Sign-in · Audit · CA & MFA · Apps & SPs · Roles & PIM · Identity Protection + Playbooks }
├── M365/       { UAL · Exchange · SharePoint/OneDrive · Teams · Graph · Purview + Playbooks }
└── Azure/      { Activity Log · RBAC · Managed Identities · Defender · Storage · VMs · Key Vault · NSG · AKS + Playbooks }
```

## The Five Recurring Themes

Patterns across nearly every Microsoft case — internalize these:

1. **Identity is the front door** — one Entra token opens M365 *and* Azure; start every case in identity.
2. **Tokens outlive passwords** — you must **revoke refresh tokens**, not just reset the password.
3. **The two RBAC worlds** — Global Admin (directory) ≠ Owner (Azure); the bridge is `elevateAccess`.
4. **Mind the data-plane blind spot** — reads (mail, blob, secret) need advanced/diagnostic logging you must enable.
5. **Short retention** — Entra 30d, Activity Log 90d, UAL 180d–1yr; export to Sentinel or the evidence is gone.

## Related

- **[Cloud → 00 Cloud Fundamentals](../00%20-%20Cloud%20Fundamentals.md)** · **[06 Cloud Service Equivalents](../06%20-%20Cloud%20Service%20Equivalents%20(AWS%20%E2%86%94%20Azure%20%E2%86%94%20GCP).md)** — cross-cloud context
- **[Cloud → 03 Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** — the same actor pivoting across providers
- **[Amazon/AWS](../Amazon/AWS/README.md)** — the AWS field guide (same shape)
- **Container →** the core Kubernetes/Docker forensics notes (cross-linked from AKS)
- **External:** [Microsoft incident response playbooks](https://learn.microsoft.com/security/operations/incident-response-playbooks) · [MITRE ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
