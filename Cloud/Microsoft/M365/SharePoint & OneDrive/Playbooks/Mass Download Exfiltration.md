# Playbook — Mass Download Exfiltration

A compromised account (or a departing insider) pulls files at scale from SharePoint/OneDrive — via bulk download, sync-client full download, or by opening the data to anonymous links. This playbook quantifies **what left, to where, and how much**, then contains the exposure.

> **Tier 1 (single-service).** SharePoint/OneDrive-focused; pulls in Entra sign-ins. Read **M365 → SharePoint & OneDrive for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Quantify the Loss](#quantify-the-loss)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Defender / MDCA** | Mass-download / unusual-file-activity alert |
| **UAL** | `FileDownloaded`/`FileSyncDownloadedFull` spike from one user/IP |
| **DLP** | Sensitive files moved/shared |
| **HR** | Departing employee / insider concern |

## Hypothesis

An identity is exfiltrating files at scale — compromised account or insider. Establish the actor, the volume, the specific files (especially sensitive ones), and the channel (download vs sync vs anonymous link vs external share).

## Step-by-Step Investigation

**1. Confirm the volume + actor.**

```kql
OfficeActivity
| where Operation in ("FileDownloaded","FileSyncDownloadedFull")
| summarize Files=count(), Sites=dcount(Site_Url), IPs=make_set(ClientIP) by UserId, bin(TimeGenerated,1h)
| where Files > 100
```

**2. Identify the channel.** Bulk `FileDownloaded` (browser), `FileSyncDownloadedFull` (sync client to a device), `AnonymousLinkCreated` (opened to the internet), or external `SharingInvitationCreated` (to a guest).

**3. Enumerate the files.** Expand `AuditData` for file names/paths; prioritize by **sensitivity label / DLP**.

**4. Compromise vs insider?** Cross the actor's **Entra sign-in logs** — new IP/token = compromise; normal corporate device = likely insider.

**5. Find any exposure that outlives the actor** — anonymous links / external shares that keep data reachable after you disable the account.

## Quantify the Loss

| Question | Evidence |
|----------|----------|
| How many files, from which sites? | UAL download counts + `Site_Url` |
| Which sensitive files? | Sensitivity labels / DLP hits |
| Download vs view? | `FileDownloaded`/sync (taken) vs `FileAccessed` (viewed) |
| To where? | Device (sync), IP (browser), external guest, anonymous URL |
| Still exposed? | Live anonymous links / guest grants |

## Decision Points

| Question | If yes → |
|----------|----------|
| Compromised account? | Cut identity; run the account-compromise flow |
| Insider? | Coordinate with HR/legal; preserve evidence quietly |
| Sensitive/regulated data? | Data-breach handling; notify per policy |
| Anonymous links created? | Public exposure — revoke immediately |
| Sync to an unmanaged device? | Consider remote wipe / device block |

## Contain

- Revoke the identity's tokens + disable the account.
- Remove all **anonymous/external sharing links** the actor created.
- Block/deregister the **sync device** if bulk sync occurred.
- Suspend external sharing on affected sites if needed.

## Eradicate

- Revoke any guest access granted.
- Remove attacker persistence if it's a compromise (rules/apps/roles).
- Reset creds + MFA for a compromised account.

## Recover

- Restrict anonymous links + external sharing tenant-wide.
- Enable **CA download-block on unmanaged devices** + DLP.
- Data-breach/legal process for sensitive data.
- Preserve: the download events, file list, destinations, and any sharing artifacts.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `FileSyncDownloadedFull` of whole libraries | Bulk sync exfil |
| Hundreds of `FileDownloaded` in an hour | Mass download |
| Anonymous links on sensitive files | Public exposure |
| External guest bulk-downloading | Data leaving the tenant |
| Downloads from a new IP after a risky sign-in | Compromise-driven exfil |

## References

- Related notes: **SharePoint & OneDrive**, **Unified Audit Log**, **Sign-in Logs**, **Purview & eDiscovery**
- Investigate data exfiltration (MDCA) — https://learn.microsoft.com/defender-cloud-apps/investigate-anomaly-alerts
- Block download on unmanaged devices — https://learn.microsoft.com/sharepoint/control-access-from-unmanaged-devices
- MITRE ATT&CK: T1530 Data from Cloud Storage / T1567 Exfiltration Over Web Service — https://attack.mitre.org/techniques/T1567/
