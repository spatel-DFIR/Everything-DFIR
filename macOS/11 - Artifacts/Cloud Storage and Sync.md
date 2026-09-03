# Cloud Storage and Sync

The enterprise **exfiltration and staging** surface, and an identity goldmine. Every sync client — iCloud Drive, OneDrive, Google Drive, Dropbox, Box — leaves local databases, logs, and a mirror/placeholder tree that reveal **which accounts/tenants are signed in, what synced, when, and whether files were uploaded off-box**. Modern macOS (Ventura+) funnels third-party clients through **File Provider** into `~/Library/CloudStorage/`, which makes enumeration uniform.

> 🔴 Two IR questions this answers: **exfil** ("did corporate data leave via a personal cloud?") and **identity** ("what accounts/tenants does this user have?"). The signed-in **account/tenant name** alone often exposes shadow-IT and the blast radius; the sync logs give upload timestamps.

## Contents
- [Quick Triage](#quick-triage)
- [The CloudStorage / File Provider Layer](#the-cloudstorage--file-provider-layer)
- [iCloud Drive](#icloud-drive)
- [OneDrive](#onedrive)
- [Google Drive](#google-drive)
- [Dropbox](#dropbox)
- [Box](#box)
- [Placeholders vs Materialized Files](#placeholders-vs-materialized-files)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Every third-party cloud signed in (the folder name reveals account/tenant)
ls -la ~/Library/CloudStorage/ 2>/dev/null
# e.g. OneDrive-Contoso, GoogleDrive-user@corp.com, Box-Box, Dropbox

# iCloud account + local iCloud Drive root
defaults read MobileMeAccounts 2>/dev/null | grep -iE 'AccountID|DisplayName'
ls -la ~/Library/Mobile\ Documents/com~apple~CloudDocs 2>/dev/null

# File Provider domains (which providers/accounts are registered)
fileproviderctl dump 2>/dev/null | grep -iE 'domain|display|identifier' | head -40

# Recently synced/uploaded files across all clients (behavioral — exfil window)
find ~/Library/CloudStorage ~/Library/Mobile\ Documents -type f -mtime -7 2>/dev/null | head -50

# Sync engine logs (upload evidence)
ls -la ~/Library/Logs/OneDrive 2>/dev/null
ls -la ~/Library/Application\ Support/Google/DriveFS 2>/dev/null
```

---

## The CloudStorage / File Provider Layer

Since macOS 12.3, third-party sync clients register as **File Provider** extensions and their trees live under `~/Library/CloudStorage/<Provider>-<Account>`. The folder name is the fastest attribution you get.

```bash
ls -la ~/Library/CloudStorage/
fileproviderctl dump | less        # registered domains, accounts, sync state (verbose)
```

| Folder name pattern | Account/tenant exposed |
|---|---|
| `OneDrive-<TenantName>` | The **org tenant** (business) — reveals employer/shadow-IT |
| `OneDrive-Personal` | Consumer MSA |
| `GoogleDrive-<email>` | Google account email |
| `Box-Box` / `Box-<name>` | Box account |
| `Dropbox` | Dropbox account (detail in its own DBs) |

---

## iCloud Drive

```bash
# Account
defaults read MobileMeAccounts 2>/dev/null            # AccountID (Apple ID), services enabled
# Local iCloud Drive + per-app iCloud containers
ls -la ~/Library/Mobile\ Documents/                    # com~apple~CloudDocs + app~ containers
ls -la ~/Library/Mobile\ Documents/com~apple~CloudDocs
# Sync engine (bird/CloudDocs) state + logs
ls -la ~/Library/Application\ Support/CloudDocs/session/db/   # client.db, server.db, etc.
brctl status 2>/dev/null                               # ubiquity/CloudDocs sync status
brctl log --wait --shorten 2>/dev/null                 # live sync log (Ctrl-C)
log show --last 1d --predicate 'subsystem == "com.apple.bird"' 2>/dev/null | tail -40
```

| Path | Value |
|---|---|
| `~/Library/Mobile Documents/com~apple~CloudDocs` | The user-visible iCloud Drive |
| `~/Library/Mobile Documents/<app~containers>` | Per-app iCloud data (e.g., `com~apple~Preview`) |
| `~/Library/Application Support/CloudDocs/session/db/client.db` | SQLite sync state — file inventory & timestamps |
| `MobileMeAccounts` (pref domain) | Apple ID + which iCloud services are on |

---

## OneDrive

```bash
ls -la ~/Library/CloudStorage/OneDrive-*                       # modern (File Provider)
ls -la ~/OneDrive* 2>/dev/null                                 # legacy sync root
# Settings + per-account sync DBs
ls -la ~/Library/Application\ Support/OneDrive/settings/       # <cid>/ dirs, *.ini, *.dat
# Logs = upload/download evidence + account/tenant
ls -la ~/Library/Logs/OneDrive/
grep -riE 'tenant|@|Business|Personal' ~/Library/Application\ Support/OneDrive/settings/*/*.ini 2>/dev/null | head
```

The `settings/<cid>/` folders (one per signed-in account) hold `global.ini`, `<cid>.ini`, and `.dat` sync databases listing every synced item. The tenant name in `CloudStorage/OneDrive-<Tenant>` and the logs tie the box to an **org**.

---

## Google Drive

Google **Drive for Desktop** (formerly File Stream). Mirror/stream tree under CloudStorage; metadata under Application Support.

```bash
ls -la ~/Library/CloudStorage/GoogleDrive-*                    # mounted account tree
ls -la ~/Library/Application\ Support/Google/DriveFS/          # <account_id>/ per account
# Per-account metadata + content cache (SQLite)
ls -la ~/Library/Application\ Support/Google/DriveFS/<account_id>/
#   metadata_sqlite_db, content_cache/, logs
sqlite3 ~/Library/Application\ Support/Google/DriveFS/<account_id>/metadata_sqlite_db \
  ".tables" 2>/dev/null
```

The numeric `<account_id>` maps to a Google account; the metadata DB enumerates mirrored files (names, ids, sizes, timestamps) even for stream-only (not downloaded) items — proving what the user had access to.

---

## Dropbox

```bash
ls -la ~/Library/CloudStorage/Dropbox* ~/Dropbox 2>/dev/null   # sync root (location varies)
ls -la ~/.dropbox/ ~/.dropbox/instance1/ 2>/dev/null           # host.db, config.dbx (encrypted), instance dirs
ls -la ~/Library/Application\ Support/Dropbox/ 2>/dev/null     # logs, settings
```

`~/.dropbox/host.db` (base64) confirms the linked account/host; `instance*/` holds per-account sync state. Newer Dropbox uses File Provider under `CloudStorage/`. Config databases are encrypted, but **presence + timestamps + the sync-root file listing** still show what was synced.

---

## Box

```bash
ls -la ~/Library/CloudStorage/Box-*                            # Box Drive (File Provider)
ls -la ~/Library/Application\ Support/Box/Box/ 2>/dev/null     # streem/ DBs, logs
ls -la ~/Library/Logs/Box/ 2>/dev/null
```

Box Drive keeps a local metadata store and logs under `Application Support/Box/Box/` — enumerate for account and synced-item history.

---

## Placeholders vs Materialized Files

Sync clients use **dataless placeholders** (metadata present, content not downloaded). The forensic distinction matters: a placeholder proves *access/visibility*; a materialized file proves the **content was on this Mac** (and could be exfiltrated).

```bash
# Dataless files carry the SF_DATALESS flag; ls -O shows BSD flags
ls -lO ~/Library/CloudStorage/OneDrive-*/somefile 2>/dev/null   # 'dataless' in flags = placeholder
# Force-evaluate broadly with find on size vs on-disk blocks, or check File Provider state
fileproviderctl dump | grep -iE 'materiali|dataless|evict' | head
```

> Opening/reading a placeholder **triggers a download** — avoid materializing evidence you're only enumerating. Read metadata (`ls`, DBs, `fileproviderctl`), not the file bodies.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Corporate files materialized in a **personal** cloud account tree | Exfil to personal storage |
| A `CloudStorage/OneDrive-<Tenant>` / `GoogleDrive-<email>` you don't expect | Shadow IT / unauthorized account / attacker's drop |
| Mass file writes into a sync root just before a departure or the incident window | Staged bulk exfiltration |
| Sync logs showing a burst of uploads to an unfamiliar account | Data theft in progress |
| A newly linked cloud account around the compromise time | Attacker exfil channel setup |
| Sensitive files **materialized** (not placeholders) then deleted locally | Downloaded, copied out, cleaned up |
| Cloud client running as/for an account that isn't the logged-in user | Account takeover / rogue linkage |

---

## Resources
- `man` pages: `brctl(1)`, `fileproviderctl(1)`, `defaults(1)`, `sqlite3(1)`
- [`Application and Container Data`](<Application and Container Data.md>) — the sync client's own app data/logs
- [`File System Events (FSEvents)`](<File System Events (FSEvents).md>) — corroborate the local file activity behind a sync
- [`00 - Cross-Artifact Correlation`](<../00 - Cross-Artifact Correlation.md>) — the exfil playbook
