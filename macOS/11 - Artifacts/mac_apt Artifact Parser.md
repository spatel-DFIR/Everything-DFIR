# mac_apt Artifact Parser

**mac_apt** (macOS Artifact Parsing Tool, by Yogesh Khatri) is the Swiss-army knife that **parses a broad array of macOS artifacts in one pass** — plists, SQLite databases, logs, browser data, and dozens more — writing results to a **SQLite database** (and optionally **Excel**). It covers the "additional artifacts" beyond the core set (RecentItems, Safari, Spotlight, Notifications, iDevice backups, AutoStart/persistence, and many others), so you can triage an image fast, then **supplement with manual checks**.

> 🔴 Workflow: run `mac_apt` against a disk image (or mounted volume) with `ALL` plugins → get one queryable `mac_apt.db` + spreadsheets covering the whole system → pivot to the per-artifact notes for deep-dive and validation. It's a force multiplier, **not** a replacement for understanding the artifacts.

## Contents
- [Quick Triage](#quick-triage)
- [What mac_apt Is](#what-mac_apt-is)
- [Installation Installer Script](#installation-installer-script)
- [Installation arm64 Release](#installation-arm64-release)
- [Running mac_apt](#running-mac_apt)
- [Input Types and Options](#input-types-and-options)
- [Output](#output)
- [Notable Plugins](#notable-plugins)
- [Running Specific Plugins](#running-specific-plugins)
- [Lower-Volume Artifacts Parsed Here](#lower-volume-artifacts-parsed-here)
- [Triage Priorities and Gotchas](#triage-priorities-and-gotchas)
- [Red Flags in the Output](#red-flags-in-the-output)
- [Resources](#resources)

---

## Quick Triage

```bash
# Process an image, extract ALL artifacts → SQLite + Excel
python3 mac_apt.py -o /evidence/out -x DMG /evidence/acquisition1.dmg ALL

# Explore the results
sqlite3 /evidence/out/mac_apt.db ".tables"

open /evidence/out/*.xlsx
```

---

## What mac_apt Is

- Open-source, actively developed Python tool that runs **plugins** against a macOS source and normalizes the findings into a single **SQLite DB** (+ optional `.xlsx`).
- Handles the parsing grunt-work across **plists, SQLite, Unified Logs, FSEvents, browser stores, backups**, etc. — countless files in one run.
- Variants: `mac_apt.py` (full disk-image processing), artifact-only / mounted modes, and `ios_apt.py` for iOS images.

> ⚠️ Under active development — plugin names and capabilities change. Run it with no args (or `-h`) to see the **current** plugin list for your version.

---

## Installation Installer Script

13Cubed provides a **customized installer** (fixes an issue on certain macOS versions — prefer it over the official repo script).

```bash
# Download the installer script (13Cubed customized):
#   https://github.com/13Cubed/install_mac_apt/blob/main/mac_apt_Install_macOS.sh

# Make it executable
chmod 755 mac_apt_Install_macOS.sh

# Run it
./mac_apt_Install_macOS.sh

# Activate the Python virtual environment it created
cd /path/to/mac_apt
source env/bin/activate

# Verify (expect usage info + an error about missing required arguments)
python3 mac_apt.py
```

---

## Installation arm64 Release

Alternate: a prebuilt **arm64 app** (no Python venv needed).

```bash
# After downloading & decompressing the arm64 release, strip quarantine
xattr -dr com.apple.quarantine /path/to/mac_apt_arm64.app

# Enter the app's binary directory
cd /path/to/mac_apt_arm64.app/Contents/MacOS

# Verify (expect usage info + missing-arguments error)
./mac_apt
```

> 🔴 Tip: drag the `.app` into Terminal to auto-fill its path. Removing quarantine is required because the app was downloaded (Gatekeeper would otherwise block it).

---

## Running mac_apt

**Installer-script (venv) build:**

```bash
cd /path/to/mac_apt
source env/bin/activate

python3 mac_apt.py -o /path/to/output -x DMG /path/to/image ALL
```

**arm64 release build:**

```bash
cd /path/to/mac_apt_arm64.app/Contents/MacOS

./mac_apt -o /path/to/output -x SPARSE /path/to/image ALL
```

> ⚠️ Release versions currently support **uncompressed** DMGs only (compressed-DMG code is in the repo but not the release) — for the arm64 release use a **`sparseimage`** (hence `-x SPARSE`).

---

## Input Types and Options

```
mac_apt.py -o <output> [-x] <INPUT_TYPE> <image_path> <PLUGIN ...|ALL>
```

| Option | Meaning |
|---|---|
| `-o <path>` | Output directory (created if missing) |
| `-x` | Also write **Excel** spreadsheets (default = SQLite DB only; with `-x` = both) |
| `<INPUT_TYPE>` | Source format (below) |
| `ALL` / `PLUGIN...` | Run every plugin, or named plugins |

**Input types:** `DMG` · `SPARSE` · `DD` (raw) · `E01` · `AFF4` · `VMDK` · `VR` (VeraCrypt) · `AXIOMZIP` · `UAC` · `MOUNTED` (an already-mounted volume/path).

> Use `MOUNTED` to run against a mounted image or a **live** system path; use `E01`/`DD`/`AFF4` for standard forensic images.

---

## Output

In `-o <output>` you'll find:

| Item | Holds |
|---|---|
| 🔴 `mac_apt.db` | **SQLite** DB — one table per plugin/artifact (query with `sqlite3`/DB Browser) |
| `*.xlsx` | Excel spreadsheets (only with `-x`) — quick browsing per artifact |
| `Export/` | Files mac_apt extracted (e.g. copies of parsed artifacts) |
| `Logs/` | mac_apt's own run log (what ran, errors, coverage) |

```bash
sqlite3 /evidence/out/mac_apt.db ".tables"

sqlite3 /evidence/out/mac_apt.db "SELECT * FROM RecentItems LIMIT 20;"
```

---

## Notable Plugins

A representative high-value set (names are the plugin args; the full list evolves — check `mac_apt.py -h`):

| Area | Plugins | Yields |
|---|---|---|
| 🔴 User activity | `RECENTITEMS`, `SAVEDSTATE`, `SPOTLIGHT`, `SPOTLIGHTSHORTCUTS`, `SCREENTIME`, `KNOWLEDGEC`, `NOTIFICATIONS`, `DOCKITEMS` | Recently opened files/apps/servers, usage timeline |
| 🔴 Browsers | `SAFARI`, `CHROMIUM`, `FIREFOX`, `COOKIES` | History, downloads, cookies, search terms |
| 🔴 Persistence | `AUTOSTART` | LaunchAgents/Daemons, login items, cron, etc. |
| System | `BASICINFO`, `USERS`, `NETWORKING`, `WIFI`, `BLUETOOTH`, `INSTALLHISTORY` | OS/version, accounts, networks, installs |
| Security | `QUARANTINE`, `TCC`, `SUDOLASTRUN`, `UNIFIEDLOGS` | Download provenance, privacy grants, sudo, logs |
| Files/FS | `FSEVENTS`, `DOCUMENTREVISIONS`, `NETUSAGE` | File change history, versions, per-app net usage |
| Comms | `NOTES`, `MESSAGES`/`IMESSAGE`, `INETACCOUNTS` | Notes, chats, configured mail/accounts |
| Mobile | `IDEVICEBACKUPS` | iPhone/iPad backups stored on the Mac |

> Many of these map to notes in this vault (FSEvents, knowledgeC, Quarantine, Unified Logs, Users) — mac_apt is the **bulk extractor**; the notes are the **interpretation**.

---

## Running Specific Plugins

Faster than `ALL` when you know what you want — pass plugin names instead:

```bash
python3 mac_apt.py -o /evidence/out -x DMG /evidence/image.dmg SAFARI SPOTLIGHT RECENTITEMS QUARANTINE

# Persistence + provenance focused triage
python3 mac_apt.py -o /evidence/out -x E01 /evidence/case.E01 AUTOSTART QUARANTINE INSTALLHISTORY UNIFIEDLOGS

# List available plugins for your version
python3 mac_apt.py -h
```

---

## Lower-Volume Artifacts Parsed Here

These are worth checking but lower-volume — mac_apt extracts them in one pass (plugin in **bold**). Each entry: where it lives, **how to read it**, and **when it matters**. (Cross-reference the timestamp epochs in *Cross-Artifact Correlation*; Cocoa/Mac-absolute = `+ 978307200`.)

### Notifications — delivered alert content  · plugin **NOTIFICATIONS**
- **Where:** `~/Library/Group Containers/group.com.apple.usernoted/db2/db` (SQLite; copy `-wal`/`-shm`).
- **Read:** the `record` table joins to `app`; the juicy part is the `data` column — a **binary plist** (NSKeyedArchiver) holding the notification **title/body**. Decode it (mac_apt does; or `plutil` the extracted blob). `delivered_date` is Cocoa epoch.
- **When it matters:** recover **message previews, 2FA codes, app alerts + timing** even after the source app's data is cleared.

### Accounts — configured online identities  · plugin **INETACCOUNTS**
- **Where:** `~/Library/Accounts/Accounts4.sqlite` (older `Accounts3`).
- **Read:** `ZACCOUNT` (description, username, date) joined to `ZACCOUNTTYPE` (`com.apple.account.Google/.Exchange/.iCloud/…`). Dates Cocoa epoch.
- **When it matters:** a **personal cloud account on a corporate Mac** = exfil/sync vector; an **account added near the incident** = attacker-configured sync; identity **attribution**.

### iOS Device Backups — a phone on the Mac  · plugin **IDEVICEBACKUPS**
- **Where:** `~/Library/Application Support/MobileSync/Backup/<UDID>/`.
- **Read:** `Info.plist` = device **name/serial/IMEI/phone#/iOS/installed apps/last-backup**; `Manifest.plist` = `IsEncrypted`; `Manifest.db` `Files` table = domain + relativePath → SHA1-named file. Full content via **iLEAPP/MVT**.
- **When it matters:** an **unexpected device backed up** = data source / exfil; **attribution**; an **encrypted** backup (needs the backup password) actually holds *more* (keychain, health).

### Document Revisions — prior file versions  · (no dedicated plugin — read directly)
- **Where:** `/System/Volumes/Data/.DocumentRevisions-V100/db-V1/db.sqlite` (+ version files; root-restricted).
- **Read:** query `generations` (document, time, storage id) → match to the stored **version file** to recover that past document state.
- **When it matters:** recover a document's **original content before it was altered/sanitized**, or a **deleted** doc's prior version (tampering, fraud).

```bash
# Notifications — apps + delivery times
sqlite3 ~/Library/Group\ Containers/group.com.apple.usernoted/db2/db "SELECT a.identifier, datetime(r.delivered_date+978307200,'unixepoch') FROM record r JOIN app a ON r.app_id=a.app_id ORDER BY r.delivered_date DESC LIMIT 20;"

# Accounts — configured identities
sqlite3 ~/Library/Accounts/Accounts4.sqlite "SELECT ZACCOUNTDESCRIPTION, ZUSERNAME, datetime(ZDATE+978307200,'unixepoch') FROM ZACCOUNT ORDER BY ZDATE DESC;"

# iOS backups — device info
plutil -p ~/Library/Application\ Support/MobileSync/Backup/*/Info.plist 2>/dev/null | grep -iE 'Device Name|Serial|IMEI|Phone|Product Version|Last Backup'

# Document Revisions — version index (root)
sudo sqlite3 /System/Volumes/Data/.DocumentRevisions-V100/db-V1/db.sqlite "SELECT * FROM generations LIMIT 20;"
```

---

## Triage Priorities and Gotchas

🔴 What to open first in the output:
1. `AUTOSTART` — persistence (what runs at boot/login).
2. `QUARANTINE` + `INSTALLHISTORY` — what was downloaded/installed and from where.
3. `RECENTITEMS` + `SAFARI`/browsers — user activity & intent.
4. `UNIFIEDLOGS` + `FSEVENTS` — timeline & file activity.
5. `USERS` + `SUDOLASTRUN` — accounts & escalation.

Gotchas:
- **Active development** → screen/output may differ from any guide; trust the live `-h` plugin list.
- Release build = **uncompressed DMG / sparseimage** only (use the venv build or convert).
- It **parses**, it doesn't **interpret** — validate key findings manually (timestamps/epochs, false positives).
- Run against a **forensic image or copy**, not the live evidence drive, when possible.
- Big images = long runtimes; scope with specific plugins for fast triage.

---

## Red Flags in the Output

| 🔴 Plugin finding | Likely meaning |
|---|---|
| `AUTOSTART` entry pointing to `/tmp`, `~/Library`, odd binary | Malware persistence |
| `QUARANTINE` download from a suspicious host | Payload provenance |
| `RECENTITEMS` referencing sensitive/exfil paths or servers | User accessed/staged data |
| `INSTALLHISTORY` of an unexpected package/profile | Unauthorized software |
| `SAFARI`/browser history to malicious domains | Initial access / C2 |
| `IDEVICEBACKUPS` present | A phone was backed up to this Mac (data source) |
| `TCC` grant of FDA/Screen Recording to an odd app | Spyware capability |
| `SUDOLASTRUN` / `USERS` anomalies | Escalation / backdoor account |

---

## Resources

- 13Cubed customized installer script: https://github.com/13Cubed/install_mac_apt/blob/main/mac_apt_Install_macOS.sh
- mac_apt (official repo + releases, Yogesh Khatri): https://github.com/ydkhatri/mac_apt
