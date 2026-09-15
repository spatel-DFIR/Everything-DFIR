# Microsoft Teams for DFIR

Teams shows up in cases as a **delivery channel** (external phishing, malicious files) and a **data store**. This note is how you investigate Teams activity, recover message content, and contain external access.

New to the service? Read **What is Microsoft Teams** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Recovering Message Content](#recovering-message-content)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there |
|--------|--------------|
| **UAL** (`MicrosoftTeams`) | Membership, settings, apps, channel lifecycle |
| **SharePoint/OneDrive audit** | Channel/chat file activity |
| **eDiscovery** | Message content (chat + channel) |
| **Teams admin center** | Current external-access + guest settings |

## Collect It

```powershell
Search-UnifiedAuditLog -StartDate .. -EndDate .. -RecordType MicrosoftTeams \
  -Operations "MemberAdded","TeamSettingChanged","AppInstalled","BotAddedToTeam","ChannelDeleted"
```

> **Console:** Teams admin center → **Users / Teams / External access**; Purview **eDiscovery** for message content.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Delivery or storage? | Phishing via chat (delivery) vs data pulled from files (storage) |
| 2. External access | Was federation/guest access on? Who external chatted/joined? |
| 3. Guest additions | `MemberAdded` for `#EXT#` identities on sensitive teams |
| 4. Malicious apps/bots | `AppInstalled`/`BotAddedToTeam` — unknown publishers |
| 5. Follow files | Channel/chat files → SharePoint/OneDrive audit for downloads |

## Recovering Message Content

🔴 UAL shows *that* messages happened, not their text. For content:

- **Purview eDiscovery** (content search) across the involved users/teams.
- Channel messages → the team's group mailbox; 1:1 → participants' mailboxes.
- Put custodians on **hold** before content ages/gets deleted.

## Hunt at Scale

**External guests added to teams:**

```kql
OfficeActivity
| where Workload == "MicrosoftTeams" and Operation == "MemberAdded"
| where Members has "#EXT#"
| project TimeGenerated, UserId, TeamName, Members
```

**Teams apps/bots installed:**

```kql
OfficeActivity
| where Workload == "MicrosoftTeams" and Operation in ("AppInstalled","BotAddedToTeam")
| project TimeGenerated, UserId, AddOnName=OfficeObjectId
```

## Respond

| Goal | Action |
|------|--------|
| Remove external access | Turn off/scope federation + guest access |
| Kick rogue guests | Remove external members from teams |
| Remove malicious apps | Uninstall the app/bot; block it org-wide |
| Preserve content | eDiscovery hold on involved users/teams |
| Cut the identity | Revoke tokens + disable if a member is compromised |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Restrict external access/federation** to allowlisted domains | Cuts Teams phishing |
| **Control guest access** + review guests | Limits external data reach |
| **App permission policies** (allowlist apps) | Stops rogue apps/bots |
| **Safe Links/Safe Attachments for Teams** | Scans malicious links/files |
| **Alert** on external adds + app installs | Early warning |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| External access enabled + outside chat | Teams phishing channel |
| `#EXT#` guest added to a sensitive team | External data access |
| Unknown app/bot installed | Rogue app |
| Channel/team deleted | Destruction / cleanup |
| Chat files pulled at volume | Exfil (→ SharePoint/OneDrive) |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Teams is + data locations | **Teams → What is** |
| The master M365 log | **M365 → Unified Audit Log** |
| Channel/chat file exfil | **M365 → SharePoint & OneDrive** |
| Message content recovery | **M365 → Purview & eDiscovery** |

## Resources

- Teams security guide — https://learn.microsoft.com/microsoftteams/teams-security-guide
- Manage external access — https://learn.microsoft.com/microsoftteams/manage-external-access
- eDiscovery for Teams — https://learn.microsoft.com/purview/ediscovery-teams-investigation
- MITRE ATT&CK: T1566 Phishing — https://attack.mitre.org/techniques/T1566/
