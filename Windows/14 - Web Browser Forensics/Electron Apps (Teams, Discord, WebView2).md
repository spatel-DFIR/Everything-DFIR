# Electron Apps (Teams, Discord, WebView2)

Not every artifact set that "looks like a browser profile" on disk actually belongs to a browser. A large and growing share of modern Windows desktop applications — Microsoft Teams, Discord, Slack, Visual Studio Code, and dozens of others — are **Electron apps**: a packaged bundle of Chromium (for rendering/UI) plus Node.js (for native OS access — filesystem, notifications, system tray, auto-update) plus the vendor's own application code, shipped as a single installable that *feels* like a native program but is, under the hood, a web page running inside an embedded copy of Chrome. A closely related but architecturally distinct category is **WebView2**, Microsoft's embeddable Chromium-based rendering control — used by apps that need to display web content inside an otherwise-native (often non-Electron, non-web-framework) application without shipping a full Electron stack.

The forensic payoff of recognizing this: **everything this repo's Chromium note already covers — SQLite `Cookies`, LevelDB-backed `Local Storage`/`IndexedDB`, the Simple Cache format, the WebKit-epoch timestamp convention — applies here too, because it's the literal same rendering engine writing the literal same file formats.** This note does not re-derive any of that; every time a shared artifact type comes up below, it points back to **Chromium (Chrome & Edge).md** (this subfolder) for the field-level detail. What this note adds is everything that *isn't* shared: where these apps put their data (no unified `User Data\<Profile>\` model — every Electron app is its own island), and the app-specific layer bolted on top of the Chromium foundation (chat messages, contacts, call logs, native app logs) that a generic web page would never generate.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Electron in One Paragraph — What's the Same, What's Different](#electron-in-one-paragraph--whats-the-same-what-different)
- [Microsoft Teams](#microsoft-teams)
- [Discord](#discord)
- [WebView2](#webview2)
- [General Electron-Hunting Methodology](#general-electron-hunting-methodology)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across known and unknown Electron/WebView2 apps — no third-party tool required. PowerShell has no native LevelDB/SQLite provider, so these commands locate, date-stamp, and hash artifact folders/files rather than reading conversation content out of them; that part still needs Hindsight or a raw LevelDB/SQLite reader (see Tooling below and Chromium (Chrome & Edge).md for the shared parsing approach).

```powershell
# EBWebView folders host-wide - the single strongest WebView2 signature, surfaces host apps not named in this note
Get-ChildItem "$env:SystemDrive\Users\*\AppData\Local\*" -Filter EBWebView -Recurse -Directory -ErrorAction SilentlyContinue

# app.asar files host-wide - the single strongest Electron-packaging signature, catches apps this note doesn't name
Get-ChildItem "$env:SystemDrive\Users\*\AppData\*","$env:ProgramFiles","${env:ProgramFiles(x86)}" -Filter app.asar -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, CreationTime

# Teams and Discord Chromium artifact presence/last-write per Windows user - recency triage without opening LevelDB/SQLite
Get-ChildItem "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Teams","$env:SystemDrive\Users\*\AppData\Roaming\discord" -Include Cookies,'Local Storage','IndexedDB','logs.txt' -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length

# Discord present at all - unauthorized-communication-app red flag in a corporate environment, presence alone is the finding
Test-Path "$env:SystemDrive\Users\*\AppData\Roaming\discord" | Where-Object { $_ }

# Electron/WebView2-hosting processes running right now - explains a locked-file read and flags a live-response window to close the app first
Get-Process Teams,Discord,msedgewebview2 -ErrorAction SilentlyContinue | Select-Object Name, Id, Path, StartTime

# Every EBWebView/Local Storage/IndexedDB folder under AppData not already tied to a known browser or app named in this note - the generic-Electron-app fallback sweep
Get-ChildItem "$env:SystemDrive\Users\*\AppData\Local\*","$env:SystemDrive\Users\*\AppData\Roaming\*" -Directory -ErrorAction SilentlyContinue |
    Where-Object { (Test-Path (Join-Path $_.FullName 'Local Storage\leveldb')) -or (Test-Path (Join-Path $_.FullName 'IndexedDB')) } |
    Select-Object FullName

# Cross-host sweep for unauthorized Discord/Electron-app presence across an estate - fast triage before pulling artifacts from every box
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock { Test-Path "$env:AppData\discord" }
```

## Electron in One Paragraph — What's the Same, What's Different

| | Traditional browser (Chrome/Edge, see Chromium note) | Electron app |
|---|---|---|
| Rendering engine | Chromium | Also Chromium (embedded) |
| Native OS access | Sandboxed, mediated through browser APIs | Direct — Node.js runtime gives the app filesystem/process/native-UI access a web page could never have |
| Profile model | `User Data\<Profile>\` — multiple named profiles under one browser install | No equivalent multi-profile model in the browser sense — one app install generally maps to one data folder per Windows user, though the app itself may support signing into different accounts within that single folder |
| Data root | `%LocalAppData%\<Vendor>\<Browser>\User Data\` | Varies by app — commonly `%AppData%\<AppName>\` or `%LocalAppData%\<AppName>\`, vendor-chosen, no repo-wide standard |
| Shared Chromium artifacts (Cookies, Local Storage, IndexedDB, Cache) | ✅ native | ✅ same file formats, same parsing approach — cross-reference Chromium note |
| App-specific artifacts (chat history caches, contact lists, call logs, native app logs) | Not applicable — a browser doesn't have "its own" chat data | ✅ this is the part unique to each Electron app, layered on top of the shared Chromium storage |

The practical rule: **when you find `Local Storage\leveldb\`, `IndexedDB\`, `Cookies`, or a `Cache\`/`Code Cache\` folder inside some app's `%AppData%\` or `%LocalAppData%\` directory, you're looking at Chromium — parse it exactly like you would a browser profile.** The only things this note adds per-app are (1) where that folder actually lives, and (2) what app-specific data sits alongside it that a generic Chromium parser won't know to look for.

## Microsoft Teams

Per this repo's `Cloud/Microsoft/M365/Teams/Teams for DFIR.md`, Teams is already covered from the **server-side/M365 admin lens** (Unified Audit Log, eDiscovery, admin-center controls) — this section is the **local-disk** counterpart: what's recoverable directly off the endpoint, independent of cloud access or retention.

🔴 **Two Teams generations exist, and they are architecturally different enough to matter.** Microsoft has been transitioning users from the original Electron-based "Classic" Teams client to a rebuilt **"New Teams"** client (rollout beginning roughly 2023) that Microsoft has described as built on WebView2 rather than a full Electron stack. This is a genuinely recent, still-evolving transition — I don't have high confidence in New Teams' exact current data path, artifact set, or how far the rollout/deprecation of Classic Teams has progressed as of this note's writing. Treat the two as **separate artifact sets you must verify against the specific build installed on the host in front of you**, rather than assuming one supersedes the other cleanly. What follows is Classic Teams, where the artifact locations are better established; for New Teams, expect a WebView2-style `EBWebView`-adjacent layout (see the WebView2 section below) but confirm empirically before relying on an assumed path.

**Classic Teams — `%AppData%\Microsoft\Teams\`:**

| Artifact | Notes |
|---|---|
| `Cookies`, `Local Storage\leveldb\`, `IndexedDB\` | Standard Chromium/Electron artifacts — same SQLite/LevelDB formats and parsing approach as the Chromium note. Not Teams-specific in format, just Teams-specific in location |
| `IndexedDB\` (Teams-specific content) | This is the artifact worth calling out with real weight: Teams has historically used its local IndexedDB store to cache a substantial amount of conversation-relevant data — chat messages, contacts, and calendar information — readable directly from the LevelDB-backed store without any server-side or Cloud/M365 access. I'm reasonably confident in this general fact (a locally-cached message store is a well-known characteristic of the Classic Teams client), but **I don't have confident, current knowledge of the exact object-store/database names inside IndexedDB** — Teams-internal schema details are the kind of thing that shifts across app updates and isn't something to assert precisely without verifying against the build in hand. Treat "IndexedDB may contain a recoverable local cache of chat content" as the operative, high-value takeaway; treat any specific object-store name as something to confirm empirically or via a current parser, not something to trust from memory |
| `logs.txt` (exact filename may vary by build — verify against the version in hand) | A native, Node.js-side application log distinct from anything Chromium-side — historically has held connection, call, and meeting-join event traces at the application layer, i.e. evidence generated by Teams' own code rather than by the embedded web page. Useful for pinning down call/meeting timing independent of the M365-side call-record artifacts covered in the Cloud Teams note |

🔴 **The local IndexedDB cache can outlive server-side retention.** If a Cloud/M365-side investigation via UAL/eDiscovery (see `Cloud/Microsoft/M365/Teams/Teams for DFIR.md`) comes up empty or short on a conversation — purged past retention, tenant misconfiguration, or simply not yet ingested — the endpoint's local Teams IndexedDB cache is a real, distinct place to look for surviving content. This is a genuinely valuable "check if it survived locally" pattern worth remembering specifically for Teams.

To locate and hash Classic Teams' Chromium-format stores and its native `logs.txt` using PowerShell, note that PowerShell can confirm presence, size, and recency but cannot read rows out of `Cookies` (SQLite) or `IndexedDB\`/`Local Storage\leveldb\` (LevelDB) — that parsing step is the Chromium note's territory (or Hindsight, see Tooling):

```powershell
Get-ChildItem "$env:AppData\Microsoft\Teams" -Include Cookies,'Local Storage','IndexedDB','logs.txt' -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length, @{N='SHA256';E={ if (-not $_.PSIsContainer) { (Get-FileHash $_.FullName).Hash } }}
```

Parse `logs.txt`, which is a native, Node.js-side app log (not Chromium-formatted). It's plain text and directly `Select-String`-able for connection/call/meeting-join traces without any SQLite/LevelDB tooling:

```powershell
Select-String -Path "$env:AppData\Microsoft\Teams\logs.txt" -Pattern 'call|meeting|join' -ErrorAction SilentlyContinue |
    Select-Object LineNumber, Line
```

**`ms_teams_parser.exe`** — named explicitly in the SANS FOR500 personal index (`SANS FOR500 Index _final.xlsx`) as a Teams-analysis tool, listed directly alongside "Microsoft Teams Analysis" as a topic and, in a separate index entry, grouped with Discord/WebView2/LevelDB-database content and the RabbitHole tool (see below) — i.e. it's referenced in FOR500 course materials specifically in the context of parsing Teams' local IndexedDB/LevelDB artifact set into readable output. Beyond that, I don't have confident knowledge of this tool's exact author, current maintenance status, or precise output format/capabilities, and I'm not going to invent them. If you need to actually use it mid-engagement, verify current availability and behavior before relying on it — treat its inclusion here as "this is a named tool the course points to for this exact problem," not a vetted capability description.

## Discord

`%AppData%\discord\` follows the same Electron-standard layout: `Cookies`, `Local Storage\leveldb\`, `IndexedDB\`, `Cache\`/`Code Cache\` — all standard Chromium artifacts, cross-reference the Chromium note for format and parsing approach. Discord's `Cache\`/`Code Cache\` folders are where locally-viewed images and attachments from channels the user has browsed can turn up, in the same Simple Cache format the Chromium note describes.

🔴 **Discord is meaningfully more server-reliant than Teams for message history.** Where Classic Teams' IndexedDB reportedly caches a real slice of conversation content locally (see above), Discord's own message history is generally **not** stored locally in a comparably rich, queryable form — Discord's client architecture leans on fetching history from its servers on demand rather than maintaining a deep local cache of past messages. I'm reasonably confident in this general contrast (it's a commonly cited difference between the two clients' local-forensic value), but if message-content recovery is the actual goal of an engagement, don't assume Discord's disk artifacts will deliver what Teams' sometimes can — verify what's actually present in `IndexedDB\` on the specific host before building an investigative plan around it, and expect to need Discord's own server-side/account-level data (API token abuse, Discord's own account-activity export, or legal process) far sooner than you would for Teams.

To locate, size, and hash Discord's Chromium-format stores, including `Cache\`/`Code Cache\` where locally-viewed channel images/attachments land, use PowerShell — though PowerShell can't read row-level content out of any of these (SQLite/LevelDB/Simple Cache — see the Chromium note for parsing):

```powershell
Get-ChildItem "$env:AppData\discord" -Include Cookies,'Local Storage','IndexedDB','Cache','Code Cache' -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length
```

A sparse or absent `IndexedDB\` next to a substantial `Cache\`/`Code Cache\` is consistent with Discord's behavior (fetching history from its servers rather than caching it deeply). Compare object counts as a cheap sanity check before assuming message content is locally recoverable:

```powershell
'IndexedDB','Cache' | ForEach-Object {
    $path = "$env:AppData\discord\$_"
    [PSCustomObject]@{ Store = $_; ObjectCount = (Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue).Count }
}
```

## WebView2

WebView2 is **not** a full Electron app — it's Microsoft's embeddable Chromium-based control, used by host applications (which may be written in any native framework — .NET, Win32, UWP, etc.) that need to render some slice of web content without shipping a whole separate Chromium+Node.js stack the way Electron does. Confirmed and plausible examples of WebView2 usage include parts of Windows 11's own shell UI and various Microsoft 365/Office app components; many third-party desktop apps also embed it for a single "mini browser" feature (an in-app help panel, a login flow, an embedded dashboard) rather than being fundamentally web-based end to end. I'm not confident enough in a fully current, comprehensive list of every WebView2-hosting app to assert one — treat "WebView2 usage is broader than most analysts expect" as the operative point, and identify it per-host empirically (see below) rather than from a fixed list.

**The identifying signature:** WebView2 data lives under **`%LocalAppData%\<HostAppName>\EBWebView\`** — a distinct naming convention from both Electron's `%AppData%\<AppName>\` pattern and a traditional browser's `User Data\<Profile>\` pattern. Finding an `EBWebView` folder under some application's data directory is, by itself, strong confirmation that the application embeds WebView2 rather than being either a native app with no web-rendering component or a full standalone Electron app. Once you're inside `EBWebView\`, the same underlying Chromium artifact types apply — `Cookies`, `Local Storage\leveldb\`, `IndexedDB\` — cross-reference the Chromium note for format.

🔴 **Identifying *which* installed applications on a host use WebView2 can require active enumeration, since it's an embedded component rather than a standalone visible "browser."** A practical approach: walk the installed-application list (or just `%LocalAppData%\` and `%AppData%\` directly) looking for `EBWebView` subfolders — its presence under an unexpected host app is itself worth investigating (what feature in that app actually renders web content, and why).

To use an active-enumeration approach to walk `%LocalAppData%\` for any `EBWebView` folder and name the host app it belongs to, use PowerShell:

```powershell
Get-ChildItem "$env:LocalAppData\*" -Filter EBWebView -Recurse -Directory -ErrorAction SilentlyContinue |
    Select-Object @{N='HostApp';E={ Split-Path (Split-Path $_.FullName -Parent) -Leaf }}, FullName, LastWriteTime
```

Once an `EBWebView` folder is found, apply the same locate/hash approach as any Chromium store. Presence and recency only are retrievable; row-level content still needs a SQLite/LevelDB-aware tool:

```powershell
Get-ChildItem "$env:LocalAppData\<HostAppName>\EBWebView" -Include Cookies,'Local Storage','IndexedDB' -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, Length
```

## General Electron-Hunting Methodology

Teams, Discord, and WebView2 are the three named in this note's scope, but there are, realistically, hundreds of Electron apps in the wild (Slack, VS Code, Signal Desktop, many others), and an analyst will regularly encounter one that isn't specifically documented anywhere in this repo. Recognize the pattern instead of memorizing an app list:

| Signal | What it tells you |
|---|---|
| `Local Storage\`, `IndexedDB\`, `Cookies`, `Cache\`/`Code Cache\` folders under `%AppData%\<AppName>\` or `%LocalAppData%\<AppName>\` | The telltale Chromium storage layout — strong indicator the app is Electron-based (or WebView2-embedding) even if you've never heard of it |
| `resources\app.asar` in the app's install directory | The single strongest, most distinctive signature. `.asar` is Electron's own packaged-application-archive format for bundling the app's JS/HTML/CSS source — it is essentially unique to Electron packaging, so its presence is close to definitive confirmation you're looking at a full Electron app (as opposed to a WebView2-only host) |
| A renamed/rebranded Chromium binary (`electron.exe` or an app-branded executable that is, under the hood, a Chromium build) in the install directory | Corroborating signature alongside `app.asar` |
| `EBWebView\` subfolder specifically (rather than a general `Local Storage`/`IndexedDB` layout directly under the app's own data root) | Points to WebView2 rather than full Electron — see above |
| Chromium-internal temp/lock artifacts (e.g. shared-memory-backed temp files Chromium creates during operation) present alongside the above | Additional corroboration you're dealing with a live/recently-live Chromium instance under that app |

When you hit an app not named anywhere in this note, this checklist is the fallback: confirm the Chromium signature, locate its data root, apply the Chromium note's artifact-parsing knowledge to whatever SQLite/LevelDB stores you find, and expect an app-specific layer on top that you may need to inspect manually (see Tooling below on the state of app-specific parser coverage).

To run the full signal checklist above against one app's data root (so an unnamed app can be triaged in one pass rather than checking each signal by hand), use PowerShell:

```powershell
function Test-ElectronSignature ([string]$AppDataRoot, [string]$InstallDir) {
    [PSCustomObject]@{
        AppDataRoot     = $AppDataRoot
        ChromiumStorage = (Test-Path (Join-Path $AppDataRoot 'Local Storage\leveldb')) -or (Test-Path (Join-Path $AppDataRoot 'IndexedDB'))
        HasEBWebView    = Test-Path (Join-Path $AppDataRoot 'EBWebView')
        HasAsar         = if ($InstallDir) { [bool](Get-ChildItem $InstallDir -Filter app.asar -Recurse -ErrorAction SilentlyContinue) } else { $null }
    }
}
Test-ElectronSignature -AppDataRoot "$env:AppData\SomeApp" -InstallDir "$env:ProgramFiles\SomeApp"
```

## Tooling

| Tool | Use |
|---|---|
| **Hindsight** (obelisk) | Same tool as the Chromium note — since Electron apps and WebView2 use the identical LevelDB/SQLite Chromium storage formats, Hindsight's History/Cookies/Local Storage/IndexedDB parsing generally applies here too, once pointed at the app's data folder instead of a browser `User Data\<Profile>\` path. Worth trying first even for an app not named in this note |
| **DB Browser for SQLite** | Manual inspection of any SQLite-format store an Electron app uses (`Cookies` and any app-specific SQLite databases layered on top) — same role as in the Chromium note |
| **KAPE** | Confirm whether current KAPE targets include Electron-app-specific collection (Teams/Discord paths) beyond the generic browser targets — worth checking your current target list rather than assuming coverage |
| **`ms_teams_parser.exe`** | Teams-specific, named in the SANS FOR500 index — see Microsoft Teams section above for the honest limits of what's confirmed about it |
| **RabbitHole** | Named in the SANS FOR500 index directly alongside Discord/WebView2/LevelDB-database content, suggesting it's aimed at general Electron-app or LevelDB/IndexedDB artifact parsing rather than being Teams-specific. Beyond that grouping, I don't have confident knowledge of its precise scope (which apps/artifact types it targets), its author, or its current maintenance status — I'm stating what the index's grouping implies and explicitly not inventing capability details beyond that. Verify current availability and actual scope before relying on it in an engagement |

**Overall tooling-maturity honesty check:** Electron-app-specific forensic tooling is, on the whole, **less mature and more fragmented** than mainstream-browser tooling. Chrome/Edge get dedicated, actively maintained parsers (Hindsight foremost) because they're two of the most-used applications on Earth; a given Electron app might have zero purpose-built parsers, one narrowly-scoped community tool, or (for Teams specifically) the two named tools above. For anything outside Teams/Discord/WebView2, expect to fall back on manual LevelDB/IndexedDB inspection with a generic tool (Hindsight if it handles the layout, a raw LevelDB reader otherwise) rather than finding an app-specific parser — budget the extra time this implies.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Teams `IndexedDB` content (chat/contact/calendar cache) present locally for a conversation that the M365-side UAL/eDiscovery investigation (`Cloud/Microsoft/M365/Teams/Teams for DFIR.md`) shows as purged, missing, or outside retention | Local cache outliving server-side retention — check the endpoint before concluding the content is gone |
| An Electron app's data folder present for an application that isn't authorized under corporate policy (Discord in a corporate environment is the classic example) | Unauthorized communication/file-transfer channel — a plausible data-exfiltration or unsanctioned-communication vector, worth flagging even absent other compromise indicators (cross-reference MITRE ATT&CK T1567 if exfil is in scope) |
| `app.asar` modification timestamp inconsistent with the application's known install/update history | A real, if advanced, technique — a tampered or repackaged Electron app with its bundled JS/HTML modified after the fact. Worth a closer look at the app's integrity if this timestamp doesn't line up |
| `EBWebView\` folder present under a host application the analyst didn't expect to be rendering embedded web content | Worth investigating what feature in that app actually triggers WebView2 use, and why |

To flag `app.asar` files whose modification time postdates the host app's own install directory creation time (the tamper/repackage signal called out above), use PowerShell:

```powershell
Get-ChildItem "$env:ProgramFiles","${env:ProgramFiles(x86)}" -Filter app.asar -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $installDir = Get-Item ($_.FullName -replace '\\resources\\app\.asar$', '')
    if ($_.LastWriteTime -gt $installDir.CreationTime) {
        [PSCustomObject]@{ Asar = $_.FullName; AsarModified = $_.LastWriteTime; InstallDirCreated = $installDir.CreationTime }
    }
}
```

## Correlate With

| To go deeper on… | Open |
|---|---|
| Shared Chromium storage formats (SQLite/LevelDB, WebKit-epoch timestamps, Simple Cache) underlying every artifact in this note | Chromium (Chrome & Edge).md (this subfolder) — the foundation this note builds on, referenced throughout |
| Teams from the M365 admin/server-side lens — UAL, eDiscovery, admin-center controls, external-access hardening | `Cloud/Microsoft/M365/Teams/Teams for DFIR.md` and `What is Teams.md` |
| Cloud/'s broader M365 coverage, for other Microsoft 365 services Teams data may touch (SharePoint/OneDrive file activity behind shared channel files) | `Cloud/`'s M365 coverage generally |
| Teams-as-communication-platform overlap with mailbox/message-content recovery methodology | Email Forensics (note 15, forward reference — not yet written) |
| Recovering artifacts from memory or unallocated space when disk-resident Electron/WebView2 data has been cleared | Private Browsing & Anti-Forensic Recovery.md (this subfolder, not yet written) |
| Unauthorized-app-as-persistence/exfil-channel pattern, alongside OS-level persistence mechanisms | Persistence Mechanisms family (note 10) |
| Malicious browser extensions as a comparable "runs inside Chromium but isn't core browser code" persistence/exfil vector | Chromium (Chrome & Edge).md, Extensions section |

## Resources

- SANS FOR500 poster and `SANS FOR500 Index _final.xlsx` — coverage checklist; the index specifically pairs "Microsoft Teams Analysis" with `ms_teams_parser.exe`, and separately groups Discord/WebView2/LevelDB-database content with both RabbitHole and `ms_teams_parser.exe` — used here as sourcing for which named tools to include, not as a prose source
- Electron's official documentation on `.asar` archive format and application packaging — https://www.electronjs.org/docs/latest/tutorial/application-distribution
- MITRE ATT&CK T1567 (Exfiltration Over Web Service) — https://attack.mitre.org/techniques/T1567/ — relevant to the unauthorized-communication-app red flag above
