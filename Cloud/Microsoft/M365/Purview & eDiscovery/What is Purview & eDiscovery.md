# What is Purview & eDiscovery?

**Microsoft Purview** is M365's **compliance and data-governance suite**. For DFIR, three of its capabilities matter most:

- **Audit** — the engine behind the Unified Audit Log (retention, advanced audit).
- **eDiscovery / Content Search** — find and **export the actual content** (emails, files, Teams messages) an attacker touched.
- **DLP + sensitivity labels** — what data was sensitive, and what movement was blocked/flagged.

Where the UAL tells you *what happened*, eDiscovery lets you recover *what was in it* — and put it on **hold** so it can't be destroyed.

## Contents

- [How It Works](#how-it-works)
- [The Three Capabilities You'll Use](#the-three-capabilities-youll-use)
- [Content Search & eDiscovery](#content-search--ediscovery)
- [Holds — Preserving Evidence](#holds--preserving-evidence)
- [Audit Retention & Advanced Audit](#audit-retention--advanced-audit)
- [DLP & Sensitivity Labels](#dlp--sensitivity-labels)
- [How to Identify Purview Activity](#how-to-identify-purview-activity)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Purview sits across all M365 workloads. It **indexes content** for search, **retains** audit + content, applies **labels/DLP**, and lets investigators **search, hold, and export** at tenant scale.

## The Three Capabilities You'll Use

| Capability | Answers | On a case |
|-----------|---------|-----------|
| **Audit** | What actions happened | Retention + `MailItemsAccessed` (see UAL note) |
| **eDiscovery / Content Search** | What was *in* the mail/files/messages | Recover exfiltrated content; scope a breach |
| **DLP / labels** | What was sensitive; what was blocked | Classify impact; find what should've been stopped |

## Content Search & eDiscovery

Three tiers:

| Tool | Scope | Use |
|------|-------|-----|
| **Content Search** | KQL-style search across mailboxes/sites/Teams | Quick "find all mail with X" |
| **eDiscovery (Standard)** | Cases + holds + export | Structured investigation |
| **eDiscovery (Premium)** | + review sets, analytics, custodians | Large/legal investigations |

```powershell
# Content search across a compromised user's mailbox + OneDrive (Security & Compliance PowerShell)
New-ComplianceSearch -Name "IR-alice" -ExchangeLocation alice@contoso.com -SharePointLocation https://contoso-my.sharepoint.com/personal/alice_contoso_com
Start-ComplianceSearch -Identity "IR-alice"
```

> **Console:** Purview → **eDiscovery** → create a case → add custodians → search → **export**. This is how you recover the *content* of what the attacker read/sent.

## Holds — Preserving Evidence

🔴 The single most important IR action in Purview: **put custodians on hold before you clean up**, so the attacker (or auto-purge) can't destroy evidence.

| Hold type | Effect |
|-----------|--------|
| **eDiscovery hold** | Preserves a custodian's mail/files/Teams for a case |
| **Litigation hold** (mailbox) | Preserves all mailbox content, incl. deleted |
| **Retention policy** | Org-wide preserve/delete rules |

> Put affected mailboxes on **litigation hold** and custodians in an **eDiscovery case hold** at the *start* of a BEC/exfil investigation — deleted items and edited messages are then recoverable.

## Audit Retention & Advanced Audit

- **Audit (Standard):** 180 days retention.
- **Audit (Premium/E5):** 1 year (up to 10 with add-on) + high-value events like **`MailItemsAccessed`**, `Send`, `SearchQueryInitiatedExchange`.
- **Audit retention policies** let you keep specific record types longer.

> 🔴 Advanced Audit is what makes "was the mail actually read?" answerable. Confirm the tenant's audit tier early — it decides your evidence.

## DLP & Sensitivity Labels

| Feature | DFIR use |
|---------|----------|
| **Sensitivity labels** | Tells you which exfiltrated files were confidential/regulated |
| **DLP policies** | May have **blocked or logged** the attacker's data movement — check DLP alerts |
| **Content explorer** | Where sensitive data lives (scope of exposure) |

## How to Identify Purview Activity

- **Portal:** Purview compliance portal (Audit, eDiscovery, DLP, Information Protection).
- **PowerShell:** Security & Compliance PowerShell (`New-ComplianceSearch`, `Set-Mailbox -LitigationHoldEnabled`).
- **UAL:** eDiscovery/search actions are themselves audited (watch for **attacker** searches — reconnaissance).

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Purview eDiscovery | (no direct equal) | Google Vault |
| Litigation hold | S3 Object Lock (rough) | Vault hold |
| DLP | Macie (rough) | Cloud DLP |
| Audit retention | CloudTrail retention | Log retention |

## Key Terminology

| Term | Meaning |
|------|---------|
| **Content Search** | Cross-workload content query |
| **eDiscovery case** | A structured investigation container |
| **Custodian** | A person whose data is in scope |
| **Hold** | Preservation of content |
| **Litigation hold** | Full-mailbox preservation |
| **Advanced Audit** | E5 tier with high-value events |
| **DLP** | Data Loss Prevention policies |
| **Sensitivity label** | A classification tag on data |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Using Purview in a case | **Purview & eDiscovery → for DFIR** |
| The audit log it powers | **M365 → Unified Audit Log** |
| Mailbox content recovery | **M365 → Exchange Online** |
| File exfil scope | **M365 → SharePoint & OneDrive** |

## Resources

- Purview overview — https://learn.microsoft.com/purview/purview
- eDiscovery — https://learn.microsoft.com/purview/ediscovery
- Advanced audit — https://learn.microsoft.com/purview/audit-solutions-overview
- Retention & holds — https://learn.microsoft.com/purview/retention
