# SharePoint & OneDrive for DFIR

When data leaves M365, it usually leaves here — mass downloads, anonymous links, external guests. This note is how you **quantify what was accessed and downloaded, find the exposure, and lock the data back down.**

New to the service? Read **What is SharePoint & OneDrive** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Notes |
|--------|--------------|-------|
| **UAL** (SPO/ODB) | File access/download/share/delete | The primary evidence |
| **Sharing config** | Current links + external access | SharePoint admin / Graph |
| **DLP / sensitivity labels** | What was sensitive | Purview |
| **Sync client logs** | Endpoint-side bulk sync | Device forensics |

## Collect It

**Pull the identity's file activity:**

```powershell
Search-UnifiedAuditLog -StartDate .. -EndDate .. -UserIds alice@contoso.com \
  -Operations "FileAccessed","FileDownloaded","FileSyncDownloadedFull","AnonymousLinkCreated","SharingInvitationCreated","FileDeleted" \
  -ResultSize 5000 | Export-Csv sp_activity.csv -NoTypeInformation
```

> **Console:** Purview → **Audit** → filter by user + SharePoint/OneDrive activities + date; SharePoint admin center → **Sites → Sharing** for current links.

**Find current anonymous / external sharing (exposure):**

```kql
OfficeActivity
| where Operation in ("AnonymousLinkCreated","SharingInvitationCreated","AddedToSecureLink")
| project TimeGenerated, UserId, ClientIP, SourceFileName=OfficeObjectId, Operation
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Scope the identity/app | Full file timeline; note `ClientIP` and volume |
| 2. Separate access from download | `FileAccessed` (viewed) vs `FileDownloaded`/`FileSyncDownloadedFull` (taken) |
| 3. Find the exposure | Anonymous links, external invites, site-admin adds |
| 4. Assess sensitivity | Sensitivity labels / DLP — what data was in scope |
| 5. Tie to the intrusion | The activity's IP/time → the compromising sign-in |

## Did Data Actually Leave?

| If you see… | Conclusion |
|-------------|------------|
| `FileDownloaded` / `FileSyncDownloadedFull` at volume | 🎯 Confirmed exfil — enumerate the files |
| `AnonymousLinkCreated` on sensitive files | Reachable by anyone with the URL — assume exposed |
| Only `FileAccessed` | Viewed in-browser; download not proven, but treat sensitive data as read |
| External `SharingInvitationCreated` | Data shared to a specific outside identity |

🔴 `FileSyncDownloadedFull` = the OneDrive **sync client pulled the whole library** to a device — a big, easily-missed exfil channel.

## Hunt at Scale

**Mass download by one user/app:**

```kql
OfficeActivity
| where Operation in ("FileDownloaded","FileSyncDownloadedFull")
| summarize Files=count(), Sites=dcount(Site_Url) by UserId, ClientIP, bin(TimeGenerated, 1h)
| where Files > 100
| order by Files desc
```

**Anonymous links on many files:**

```kql
OfficeActivity
| where Operation == "AnonymousLinkCreated"
| summarize count() by UserId, bin(TimeGenerated, 1d)
| where count_ > 20
```

**External guest downloads:**

```kql
OfficeActivity
| where Operation == "FileDownloaded" and UserId has "#EXT#"
| project TimeGenerated, UserId, ClientIP, OfficeObjectId
```

## Respond

| Goal | Action |
|------|--------|
| Cut the identity | Revoke tokens + disable |
| Kill exposure | Remove anonymous/external links; revoke external guest access |
| Stop sync exfil | Block the device; revoke sessions; consider selective wipe |
| Preserve | Put affected sites/drives on **eDiscovery hold**; export the UAL |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Restrict anonymous ("anyone") links** org-wide | Kills the public-exposure path |
| **Limit external sharing** to allowlisted domains | Controls guest access |
| **DLP policies + sensitivity labels** | Block/alert on sensitive-data movement |
| **Conditional Access: block download on unmanaged devices** (app-enforced) | Stops browser exfil |
| **Alert** on mass downloads + anonymous-link creation | Catch exfil early |
| **Enable advanced audit + export to Sentinel** | Retention + hunting |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `FileSyncDownloadedFull` / bulk `FileDownloaded` | Mass exfil |
| `AnonymousLinkCreated` on sensitive files | Public exposure |
| External guest downloading at volume | Data leaving to outside |
| `SiteCollectionAdminAdded` (unexpected) | Site takeover |
| Mass `FileDeleted`/recycle | Destruction |
| Downloads from a new IP right after a risky sign-in | Compromise-driven exfil |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What SPO/ODB are + sharing | **SharePoint & OneDrive → What is** |
| The master M365 log | **M365 → Unified Audit Log** |
| The compromising sign-in | **Entra → Sign-in Logs** |
| Mass-download scenario | **SharePoint & OneDrive → Playbooks → Mass Download Exfiltration** |
| Data classification / hold | **M365 → Purview & eDiscovery** |

## Resources

- SharePoint/OneDrive audit activities — https://learn.microsoft.com/purview/audit-log-activities#file-and-page-activities
- Limit external sharing — https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off
- Block download on unmanaged devices — https://learn.microsoft.com/sharepoint/control-access-from-unmanaged-devices
- MITRE ATT&CK: T1530 Data from Cloud Storage — https://attack.mitre.org/techniques/T1530/
