# What is Microsoft Teams?

**Microsoft Teams** is M365's **collaboration hub** — chat, channels, meetings, calls, and files. For DFIR it matters two ways: it's a **phishing/malware delivery channel** (external chat, malicious links/files) and a **data store** (channel files live in SharePoint; chat/1:1 files live in OneDrive), so its evidence spans Teams, SharePoint, OneDrive, and Entra.

## Contents

- [How It Works](#how-it-works)
- [Where Teams Data Actually Lives](#where-teams-data-actually-lives)
- [The Attack Surface](#the-attack-surface)
- [The Evidence Teams Produces](#the-evidence-teams-produces)
- [How to Identify Teams Activity](#how-to-identify-teams-activity)
- [The Operations That Matter Most](#the-operations-that-matter-most)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

A **team** is a group with **channels**; each team is backed by a **Microsoft 365 Group** (and thus an Entra group, a SharePoint site, and a mailbox). Members chat in channels or 1:1; files shared in a channel land in that team's SharePoint site; files in a chat land in the sender's OneDrive.

## Where Teams Data Actually Lives

🔴 The key forensic fact — Teams isn't one store, it's several:

| Content | Actually stored in |
|---------|--------------------|
| Channel messages | A hidden mailbox (group) + compliance store |
| 1:1 / group chat messages | Participants' mailboxes (compliance) |
| **Channel files** | The team's **SharePoint** site |
| **Chat files** | The sender's **OneDrive** |
| Meeting recordings | OneDrive / SharePoint |

> So to fully investigate Teams you pull from **UAL (Teams), SharePoint/OneDrive audit, and eDiscovery** (for message content).

## The Attack Surface

| Vector | What it looks like |
|--------|--------------------|
| **External access / federation** | Outside users chatting in (phishing via Teams) 🔴 |
| **Malicious files/links** | Malware or credential-phish shared in chat |
| **Guest added to a team** | External identity gains access to team data |
| **Data exfil** | Channel/chat files pulled (→ SharePoint/OneDrive) |
| **App/bot abuse** | A malicious Teams app added |

## The Evidence Teams Produces

| Evidence | UAL Operation |
|----------|---------------|
| Member/guest added | `MemberAdded`, `TeamsSessionStarted` |
| Team/channel created/deleted | `TeamCreated`, `ChannelAdded`, `ChannelDeleted` |
| External/federation settings changed | `TeamSettingChanged` |
| App added | `AppInstalled`, `BotAddedToTeam` |
| Message activity (limited in UAL) | `MessageSent` (content via eDiscovery) |

## How to Identify Teams Activity

- **UAL:** RecordType `MicrosoftTeams`.
- **Portal:** Teams admin center; Purview eDiscovery for message content.
- **KQL:** `OfficeActivity | where Workload == "MicrosoftTeams"`.

## The Operations That Matter Most

| Operation | 🔴 Watch |
|-----------|---------|
| `MemberAdded` (guest/external) | External access to team data |
| `TeamSettingChanged` (external access on) | Opening the tenant to outside chat |
| `AppInstalled` / `BotAddedToTeam` | Malicious app/bot |
| `ChannelDeleted` / `TeamDeleted` | Destruction / cleanup |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Teams | Chime (rough) | Google Chat / Meet |
| Channel files → SharePoint | — | Chat files → Drive |

## Common Use Cases

Your "normal" baseline:

- Internal team chat + meetings.
- Some external federation with partners (baseline it).
- Line-of-business Teams apps.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Team** | A group with channels (backed by an M365 Group) |
| **Channel** | A conversation/file space in a team |
| **Guest** | An external member |
| **External access / federation** | Chat with outside tenants |
| **M365 Group** | The identity/group backing a team |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating Teams in a case | **Teams → for DFIR** |
| The master M365 log | **M365 → Unified Audit Log** |
| Where channel/chat files live | **M365 → SharePoint & OneDrive** |
| Message content recovery | **M365 → Purview & eDiscovery** |

## Resources

- Teams security guide — https://learn.microsoft.com/microsoftteams/teams-security-guide
- Teams activity in the audit log — https://learn.microsoft.com/purview/audit-log-activities#microsoft-teams-activities
- Where Teams data is stored — https://learn.microsoft.com/microsoftteams/location-of-data-in-teams
