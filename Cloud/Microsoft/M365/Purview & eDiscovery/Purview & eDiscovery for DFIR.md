# Purview & eDiscovery for DFIR

Purview is how you **preserve evidence, recover the content** an attacker touched, and **classify the impact**. In a BEC or exfil case it's the difference between "we think mail was read" and "here is exactly what was in it."

New to the service? Read **What is Purview & eDiscovery** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [The First Move: Preserve](#the-first-move-preserve)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there |
|--------|--------------|
| **Content Search / eDiscovery** | The actual mail/files/Teams content |
| **Holds** | Preserved (incl. deleted) content |
| **DLP alerts** | Sensitive-data movement that was flagged/blocked |
| **Sensitivity labels** | Classification of exfiltrated data |
| **UAL** | eDiscovery/search actions (incl. attacker recon) |

## The First Move: Preserve

🔴 **Before you clean up, hold the evidence.** Do this at the *start* of a BEC/exfil case:

```powershell
# Litigation hold on a compromised mailbox (preserves deleted/edited items)
Set-Mailbox alice@contoso.com -LitigationHoldEnabled $true -LitigationHoldDuration 365
```

> **Console:** Purview → **eDiscovery** → new case → add **custodians** → apply **hold**. Holds preserve content the attacker may try to delete (fraud replies, sent items).

## Collect It

**Search the compromised user's content:**

```powershell
New-ComplianceSearch -Name "IR-alice" \
  -ExchangeLocation alice@contoso.com \
  -SharePointLocation https://contoso-my.sharepoint.com/personal/alice_contoso_com \
  -ContentMatchQuery 'subject:"invoice" OR "wire transfer"'
Start-ComplianceSearch -Identity "IR-alice"
Get-ComplianceSearch "IR-alice" | fl Items, Status
New-ComplianceSearchAction -SearchName "IR-alice" -Export
```

> **Console:** Purview → eDiscovery → case → **Searches** → build a KQL query → run → **Export** results.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Preserve | Holds on all involved custodians (mail + OneDrive + Teams) |
| 2. Recover content | Content search for the threads/files the UAL flagged |
| 3. Classify | Sensitivity labels / DLP → what was confidential/regulated |
| 4. Check attacker recon | UAL for **attacker-run** searches (`SearchQueryInitiatedExchange`) — what they hunted for |
| 5. Bound the breach | Content + labels → the data-breach scope for legal/notification |

## Hunt at Scale

**Attacker mailbox searches (recon for finance/creds):**

```kql
OfficeActivity
| where Operation == "SearchQueryInitiatedExchange"
| project TimeGenerated, UserId, ClientIP, Query=OfficeObjectId
```

**DLP alerts around the incident window:**

```kql
// via the DLP/Defender portal; correlate sensitive-data hits with the actor
CloudAppEvents
| where ActionType has "DLP"
| project Timestamp, AccountDisplayName, RawEventData
```

## Respond

| Goal | Action |
|------|--------|
| Preserve | Litigation + eDiscovery holds on all custodians |
| Recover | Content-search export of touched mail/files |
| Scope the breach | Labels + DLP → regulated data affected |
| Support legal | Provide exported evidence + hold documentation |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable advanced audit** (`MailItemsAccessed`, `Send`, searches) | Prove reads + recon |
| **Audit retention policies** (extend high-value record types) | Beat the 180-day default |
| **DLP policies** on sensitive data | Block/flag exfil |
| **Default litigation hold** for VIP/finance mailboxes | Evidence always preserved |
| **Sensitivity labels** applied to sensitive data | Fast impact scoping |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Attacker-run mailbox searches for "invoice"/"password" | Targeted recon |
| DLP alerts on sensitive data movement | Exfil of regulated data |
| eDiscovery/search by an unexpected admin | Insider misuse of investigation tools |
| No holds + active deletion by attacker | Evidence being destroyed — hold now |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Purview offers | **Purview & eDiscovery → What is** |
| The audit log it powers | **M365 → Unified Audit Log** |
| Mailbox content + BEC | **M365 → Exchange Online** |
| File exfil scope | **M365 → SharePoint & OneDrive** |

## Resources

- eDiscovery — https://learn.microsoft.com/purview/ediscovery
- Content search — https://learn.microsoft.com/purview/ediscovery-content-search
- Litigation hold — https://learn.microsoft.com/purview/ediscovery-create-a-litigation-hold
- DLP — https://learn.microsoft.com/purview/dlp-learn-about-dlp
