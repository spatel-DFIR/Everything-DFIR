# Azure DFIR Field Guide

**Azure** is Microsoft's **infrastructure cloud** — subscriptions full of VMs, storage, databases, key vaults, and Kubernetes, all fronted by **Entra ID**. Where M365 is the SaaS side, Azure is where attackers **run compute, steal secrets, mine crypto, and destroy resources.**

Written for the full range from associate analyst to principal DFIR consultant. Primary lens = hands-on the platform (Azure portal, `az` CLI, KQL in Log Analytics/Sentinel); SecOps UDM appears only as a small end-of-note aid.

## How to Use This Guide

**New to Azure DFIR?** Start with the Microsoft-level foundation, then the **Activity Log** (the master control-plane log):

1. **[00 - Microsoft Cloud Overview](../00%20-%20Microsoft%20Cloud%20Overview%20%26%20Terminology.md)** — tenant, subscriptions, the **two RBAC worlds**, where each log lives.
2. **[01 - Entra ID & Identities](../01%20-%20Entra%20ID%20%26%20Identities.md)** — user vs SP vs **managed identity**, tokens.
3. **[Activity Log](Activity%20Log/Activity%20Log%20for%20DFIR.md)** — the master Azure control-plane log.

**Working an incident?** Jump from the router below.

## Situation → Open This

| The alert / symptom is about… | Start here |
|-------------------------------|-----------|
| A suspicious Azure resource-change timeline | **[Activity Log for DFIR](Activity%20Log/Activity%20Log%20for%20DFIR.md)** |
| An Owner/role grant or `elevateAccess` | **[Azure RBAC for DFIR](Azure%20RBAC/Azure%20RBAC%20for%20DFIR.md)** |
| A managed-identity / IMDS token stolen | **[Managed Identity Theft via SSRF](Playbooks/Managed%20Identity%20Theft%20via%20SSRF.md)** · **[Managed Identities for DFIR](Managed%20Identities/Managed%20Identities%20for%20DFIR.md)** |
| A publicly exposed storage container | **[Exposed Blob Container](Storage/Playbooks/Exposed%20Blob%20Container.md)** · **[Storage for DFIR](Storage/Storage%20for%20DFIR.md)** |
| A VM running commands / suspicious code | **[Run Command Abuse](Virtual%20Machines/Playbooks/Run%20Command%20Abuse.md)** · **[Virtual Machines for DFIR](Virtual%20Machines/Virtual%20Machines%20for%20DFIR.md)** |
| Secrets accessed / a looted vault | **[Key Vault for DFIR](Key%20Vault/Key%20Vault%20for%20DFIR.md)** |
| A cost / CPU spike (mining) | **[Cryptomining Incident](Playbooks/Cryptomining%20Incident.md)** |
| A new / crypto pod in AKS | **[Malicious Pod and Cryptomining](AKS/Playbooks/Malicious%20Pod%20and%20Cryptomining.md)** · **[AKS for DFIR](AKS/AKS%20for%20DFIR.md)** |
| Resources deleted / encrypted | **[Resource Ransomware and Destruction](Playbooks/Resource%20Ransomware%20and%20Destruction.md)** |
| Strange network traffic / C2 | **[NSG Flow Logs for DFIR](NSG%20Flow%20Logs/NSG%20Flow%20Logs%20for%20DFIR.md)** |
| A Defender for Cloud alert | **[Microsoft Defender for Cloud for DFIR](Microsoft%20Defender%20for%20Cloud/Microsoft%20Defender%20for%20Cloud%20for%20DFIR.md)** |

## Structure

```
Microsoft/Azure/
├── Activity Log/               ← the control-plane master log (start here)
├── Azure RBAC/                 ← resource permissions + the two RBAC worlds + elevateAccess
├── Managed Identities/         ← identities for resources + IMDS (169.254.169.254)
├── Microsoft Defender for Cloud/ ← posture (CSPM) + threat alerts (CWPP)
├── Storage/                    ← Blob storage; +Playbook: Exposed Blob Container
├── Virtual Machines/           ← IaaS compute; +Playbook: Run Command Abuse
├── Key Vault/                  ← secrets store (the data-plane logging catch)
├── NSG Flow Logs/              ← network flows (VPC-Flow-Logs equivalent)
├── AKS/                        ← managed Kubernetes; +Playbook: Malicious Pod & Cryptomining
└── Playbooks/                  ← Managed Identity Theft via SSRF · Cryptomining · Resource Ransomware
```

Each service folder holds **What is `<svc>`** + **`<svc>` for DFIR** (and **Playbooks/** where a scenario warrants it).

## Coverage

| Category | Services |
|----------|----------|
| **Logging & Monitoring** | Activity Log, NSG Flow Logs |
| **Identity & Access** | Azure RBAC, Managed Identities |
| **Security & Detection** | Microsoft Defender for Cloud |
| **Storage** | Storage (Blob) |
| **Compute** | Virtual Machines |
| **Secrets** | Key Vault |
| **Serverless & Containers** | AKS |

## The Recurring Themes

1. **Control plane vs data plane** — the Activity Log shows *management*; reads (blob/secret) need **diagnostic logging** you must enable.
2. **The two RBAC worlds** — Owner (Azure) ≠ Global Admin (directory); the bridge is `elevateAccess`.
3. **Managed identity = IMDS prize** — SSRF/RCE on a resource steals its token; the identity's RBAC is the blast radius.
4. **Short retention** — Activity Log 90 days; export to Sentinel before it ages out.
5. **AKS is two worlds** — Kubernetes RBAC + audit logs *and* Entra/Azure RBAC + Activity Log; know cluster/node/pod.

## Related

- **[Entra ID](../Entra%20ID/)** — the identity front door (almost every Azure case starts there)
- **[M365](../M365/)** — the SaaS side the same tenant fronts
- **[Microsoft → 00/01/02 foundation notes](../)**
- **Container →** the core Kubernetes forensics notes (cross-linked from AKS)
- **External:** [Azure Activity Log](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log) · [Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/) · [MITRE ATT&CK Cloud (IaaS)](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
