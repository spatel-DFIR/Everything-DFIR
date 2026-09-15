# Recent Items and SharedFileList

macOS tracks **recently opened documents, applications, connected servers, and Finder favorites** in **SharedFileList** files (`.sfl2`/`.sfl3`/`.sfl4`) plus a legacy `recentitems.plist`. These reveal **user intent and activity** — what was opened, and 🔴 critically, **which network servers/hosts the user connected to** (SMB/AFP/SSH — a lateral-movement and data-access lead).

> 🔴 `RecentServers` / `FavoriteVolumes` are the high-value ones: they record **"Connect to Server" targets and mounted shares** — exactly what you want when chasing where a user reached out on the network. Recent documents/apps establish what files and tools were used.

## Contents
- [Quick Triage](#quick-triage)
- [Where It Lives](#where-it-lives)
- [The SharedFileList Files](#the-sharedfilelist-files)
- [Format and Parsing](#format-and-parsing)
- [Per-App Recent Documents](#per-app-recent-documents)
- [Legacy Recent Items](#legacy-recent-items)
- [Scenarios](#scenarios)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# List the SharedFileList store
ls -la ~/Library/Application\ Support/com.apple.sharedfilelist/

# Per-app recent documents
ls -la ~/Library/Application\ Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments/

# Parse with a tool (binary NSKeyedArchiver — see Format and Parsing)
python3 mac_apt.py -o out -x DMG image.dmg RECENTITEMS
```

---

## Where It Lives

| Path | Holds |
|---|---|
| 🔴 `~/Library/Application Support/com.apple.sharedfilelist/` | SharedFileList `.sfl2`/`.sfl3`/`.sfl4` files |
| `…/com.apple.LSSharedFileList.ApplicationRecentDocuments/` | Per-app recent docs (one file per bundle ID) |
| `~/Library/Preferences/com.apple.recentitems.plist` | Legacy recent-items (older macOS) |

> The extension version tracks the macOS version: **`.sfl2`** → **`.sfl3`** → **`.sfl4`** (newer). A volume may have several versions side by side.

---

## The SharedFileList Files

| File | Holds |
|---|---|
| 🔴 `…RecentServers.sfl*` | **"Connect to Server" targets** (SMB/AFP/SSH URLs) |
| `…RecentHosts.sfl*` | Recently contacted hosts |
| `…FavoriteVolumes.sfl*` | Mounted/favorite volumes (incl. network shares, externals) |
| 🔴 `…RecentDocuments.sfl*` | Recently opened documents (full paths) |
| `…RecentApplications.sfl*` | Recently launched apps |
| `…FavoriteItems.sfl*` | Finder **sidebar** favorites |
| `…ProjectsItems.sfl*` / `iCloudItems.sfl*` | Stacks / iCloud items |

🔴 `RecentServers`/`RecentHosts` = a record of **remote systems the user reached** — pivot for lateral movement and data staging.

---

## Format and Parsing

`.sfl*` files are **binary plists** containing an **NSKeyedArchiver** blob, and each item embeds a **bookmark** (alias) that holds the **full path, volume name/UUID, and creation/access info** — rich, even for items no longer present.

```bash
# Peek (shows the NSKeyedArchiver structure; paths often visible)
plutil -p ~/Library/Application\ Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers.sfl3 2>/dev/null

strings ~/Library/Application\ Support/com.apple.sharedfilelist/*.sfl* | grep -iE 'smb://|afp://|ssh://|/Volumes/|/Users/'
```

| Tool | Notes |
|---|---|
| 🔴 **mac_apt** (`RECENTITEMS`) | Parses sfl + bookmarks into the DB |
| `sfl`/bookmark parsers | Decode NSKeyedArchiver + the embedded bookmark blob |
| Commercial suites | Built-in recent-items parsing |

> A raw `plutil` shows the archive; properly resolving the **bookmark** (for the full path/volume) usually needs a dedicated parser.

---

## Per-App Recent Documents

```bash
ls -la ~/Library/Application\ Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments/

#   one file per app, e.g. com.microsoft.Word.sfl3, com.apple.TextEdit.sfl3
```

🔴 Shows **which files each application** recently opened — ties a document to the app (and app to the user activity timeline).

---

## Legacy Recent Items

```bash
plutil -p ~/Library/Preferences/com.apple.recentitems.plist 2>/dev/null
```

> Present on older/upgraded systems; same idea, simpler plist format.

---

## Scenarios

🔴 When SharedFileList cracks a case:

- **Lateral movement / share access** — `RecentServers`/`RecentHosts` list the **SMB/AFP/SSH "Connect to Server" targets** the user reached; pivot to those hosts and to network logs.
- **Insider data access** — `RecentDocuments` (and per-app recent docs) name the **sensitive files the user opened**, tying file → app → activity.
- **Removable / network media used** — `FavoriteVolumes` records externals and mounted shares.
- **Leads on deleted files** — the embedded **bookmark** holds the full path/volume even for items no longer present.

> How to read it: a raw `plutil`/`strings` exposes the URLs and paths, but to resolve the full **bookmark** (path + volume UUID + dates) reliably, run a bookmark/`sfl` parser or mac_apt's `RECENTITEMS`.

---

## Correlate With

| To answer | Pivot to |
|---|---|
| Was a recent doc opened / when? | Program Execution Evidence; knowledgeC; Quick Look |
| Servers the user connected to | Wi-Fi/Network logs; mount history (USB & Device History) |
| A recent file now deleted | Trash; FSEvents; Spotlight |
| App that opened it | knowledgeC `/app/usage`; Unified Logs |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `RecentServers` with an **unexpected SMB/SSH target** | Lateral movement / data access |
| Recent documents of **sensitive/exfil** files | Files the user opened (intent) |
| Recent applications = hacking/exfil tools | Tooling used on the box |
| FavoriteVolumes including an unknown external/share | Removable/network media used |
| Recent items referencing **deleted** paths | What existed before cleanup |
| Bookmark pointing to another user's/host's volume | Cross-system access |

---

## Resources

- mac_apt (`RECENTITEMS` plugin): https://github.com/ydkhatri/mac_apt
- Apple Bookmark / NSKeyedArchiver format references
