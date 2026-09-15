# Microsoft 365 DFIR Field Guide

**Microsoft 365** is the **SaaS productivity suite** — Exchange Online (email), SharePoint/OneDrive (files), Teams (chat), all fronted by **Entra ID**. It's where most Microsoft compromises *pay off*: read the mail, hide the tracks, forward the data, exfiltrate the files.

Written for the full range from associate analyst to principal DFIR consultant. Primary lens = hands-on the platform (Purview Audit, Exchange/Graph PowerShell, admin centers, KQL in Sentinel); SecOps UDM appears only as a small end-of-note aid.

## How to Use This Guide

**New to M365 DFIR?** Start with the Microsoft-level foundation, then the **Unified Audit Log** (the master M365 log):

1. **[00 - Microsoft Cloud Overview](../00%20-%20Microsoft%20Cloud%20Overview%20%26%20Terminology.md)** · **[01 - Entra ID & Identities](../01%20-%20Entra%20ID%20%26%20Identities.md)** · **[02 - Investigating Microsoft](../02%20-%20Investigating%20Microsoft%20(start%20here).md)**
2. **[Unified Audit Log](Unified%20Audit%20Log/Unified%20Audit%20Log%20for%20DFIR.md)** — the one log that spans all M365 workloads.

**Working an incident?** Jump from the router below.

## Situation → Open This

| The alert / symptom is about… | Start here |
|-------------------------------|-----------|
| A suspicious M365 activity timeline / "who did X" | **[Unified Audit Log for DFIR](Unified%20Audit%20Log/Unified%20Audit%20Log%20for%20DFIR.md)** |
| A compromised mailbox / payment fraud | **[Business Email Compromise](Exchange%20Online/Playbooks/Business%20Email%20Compromise.md)** |
| Inbox rules / auto-forwarding | **[Malicious Inbox Rules and Forwarding](Exchange%20Online/Playbooks/Malicious%20Inbox%20Rules%20and%20Forwarding.md)** · **[Exchange Online for DFIR](Exchange%20Online/Exchange%20Online%20for%20DFIR.md)** |
| Mass file download / data exfil | **[Mass Download Exfiltration](SharePoint%20%26%20OneDrive/Playbooks/Mass%20Download%20Exfiltration.md)** · **[SharePoint & OneDrive for DFIR](SharePoint%20%26%20OneDrive/SharePoint%20%26%20OneDrive%20for%20DFIR.md)** |
| Public / anonymous sharing links | **[SharePoint & OneDrive for DFIR](SharePoint%20%26%20OneDrive/SharePoint%20%26%20OneDrive%20for%20DFIR.md)** |
| Teams phishing / external access / rogue app | **[Teams for DFIR](Teams/Teams%20for%20DFIR.md)** |
| An app reading mail/files via Graph | **[Microsoft Graph for DFIR](Microsoft%20Graph/Microsoft%20Graph%20for%20DFIR.md)** · **[Illicit Consent Grant](../Entra%20ID/Playbooks/Illicit%20Consent%20Grant.md)** |
| Preserving evidence / recovering content | **[Purview & eDiscovery for DFIR](Purview%20%26%20eDiscovery/Purview%20%26%20eDiscovery%20for%20DFIR.md)** |

## Structure

```
Microsoft/M365/
├── Unified Audit Log/          ← the master M365 log (start here)
├── Exchange Online/            ← email; +Playbooks: BEC, Malicious Inbox Rules & Forwarding
├── SharePoint & OneDrive/      ← files; +Playbook: Mass Download Exfiltration
├── Teams/                      ← chat/collaboration (delivery + data store)
├── Microsoft Graph/            ← the unified API (collection + attacker path)
└── Purview & eDiscovery/       ← preserve evidence, recover content, classify impact
```

Each service folder holds **What is `<svc>`** + **`<svc>` for DFIR** (and **Playbooks/** where a scenario warrants it).

## Coverage

| Service | Answers |
|---------|---------|
| **Unified Audit Log** | What any identity did across all M365 workloads |
| **Exchange Online** | Mailbox rules, forwarding, delegation, reads, sends (BEC) |
| **SharePoint & OneDrive** | File access, downloads, sharing links, exposure (exfil) |
| **Teams** | Collaboration as a delivery channel + data store; external access |
| **Microsoft Graph** | The unified API — your collection engine and the attacker's data path |
| **Purview & eDiscovery** | Preserve (holds), recover content, classify (DLP/labels), audit retention |

## The Recurring Themes

1. **The UAL is the anchor** — one log across email/files/Teams/Entra; check it's *on* first.
2. **Mind the read blind spot** — proving mail/files were *read* needs advanced audit (`MailItemsAccessed`).
3. **Persistence hides in mailboxes** — inbox rules, forwarding, delegation survive a password reset.
4. **Data leaves via files** — downloads, sync, anonymous links, external guests.
5. **Preserve before you clean** — holds first, or the attacker destroys the evidence.

## Related

- **[Entra ID](../Entra%20ID/)** — the identity front door (almost every M365 case starts there)
- **[Azure](../Azure/)** — the infrastructure cloud the same tenant fronts
- **[Microsoft → 00/01/02 foundation notes](../)**
- **External:** [Search the audit log](https://learn.microsoft.com/purview/audit-log-search) · [Respond to a compromised account](https://learn.microsoft.com/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account) · [MITRE ATT&CK Cloud (Office 365)](https://attack.mitre.org/matrices/enterprise/cloud/office-365/)
