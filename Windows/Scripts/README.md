# Windows DFIR Triage Scripts

Read-only triage scripts for **live Windows investigations** — built to run over EDR Real-Time
Response (RTR) or an interactive session on a host you can't disturb. Most tools here rebrand a
prior ad hoc one-off into an evidence-weighted triage tool (`hunt_persistence.ps1` is a ground-up
build instead — see its own changelog), sharing one doctrine: **flag on evidence, enumerate
everything else.** **Each lives in its own folder with its own README.**

> Part of the Windows DFIR Field Reference. Siblings: [`macOS/scripts/`](../../macOS/scripts/README.md),
> [`Linux/scripts/`](../../Linux/scripts/README.md) — same house style, same doctrine, different OS.

| Script | Answers | Folder |
|---|---|---|
| **`hunt_eventlogs.ps1`** | *What logs exist, and what's in them?* Inventory of every event log (record count, oldest/newest event, UTC) — plus a timeframe-correct keyword/regex/level hunt across all of them. | [`event_logs/`](event_logs/README.md) |
| **`hunt_lnk.ps1`** | *Is a shortcut file hiding something?* Bulk sweep of `.lnk` files (profiles, all-users Startup, removable drives) scored for LOLBin payloads, double-extension masquerade, dangling targets, icon spoofing — plus a single-file deep-dive that extracts MS-SHLLINK binary forensics (creating machine's NetBIOS name, NIC MAC, volume serial) that COM never exposes. | [`lnk_files/`](lnk_files/README.md) |
| **`hunt_recyclebin.ps1`** | *What was deleted, and does the deletion pattern look off?* Full `$I`/`$R` deleted-file timeline across every fixed volume, plus an anomaly queue for orphaned metadata/content, impossible timestamps, suspicious original file types, and mass-delete clustering. | [`recycle_bin/`](recycle_bin/README.md) |
| **`hunt_persistence.ps1`** | *What's set up to survive a reboot/logon, and does any of it look tampered with?* Read-only sweep of 42 MITRE ATT&CK TA0003 technique families (Run keys, services, scheduled tasks, WMI subscriptions, Winlogon/LSA/IFEO tamper, COM hijacking, Office trust abuse, and more) — always-shown inventory grouped by module, plus an evidence-weighted anomaly queue. | [`persistence/`](persistence/README.md) |

## Shared design

- **Flag on evidence, enumerate everything else.** A mechanism/hit *existing* is never the signal
  by itself — weighted evidence stacks into `[HIGH]`/`[NOTABLE]` tiers; plain enumeration (every
  log, every LNK, every deleted item) is always shown in full alongside the anomaly queue, never
  hidden behind it.
- **RTR-safe by construction.** Every script here is read-only, console-output only, single
  self-contained `.ps1` with no external module dependencies, PowerShell 5.1-compatible (these run
  unmodified via EDR live-response shells against production client hosts — no elevation is
  required to run, and every script detects elevation and degrades gracefully rather than failing).
  **CSV/JSON export is a deliberate, permanent scope cut** across all four tools, not a
  not-yet-implemented feature — no file is ever written to the host; if you need structured
  output, capture it at the console/RTR layer.
- **Self-documenting.** Every script prints a runtime banner (version, author, UTC timestamp,
  hostname, the effective command line) so a saved RTR transcript explains itself, plus
  comment-based help (`Get-Help .\script.ps1 -Full`) and a `-Help` switch.
- **Author:** Suvas Patel · **current version:** all four tools are `v1.0` (see each folder's
  README changelog for build history and the exact bug list fixed).

## Quick start

```powershell
# What logs exist on this host, and what's their UTC time range?
.\event_logs\hunt_eventlogs.ps1

# Hunt for a keyword across all logs in the last 3 days
.\event_logs\hunt_eventlogs.ps1 -Keywords '.msi' -Days 3

# Sweep every profile + removable drive for suspicious shortcuts
.\lnk_files\hunt_lnk.ps1

# Deep-dive a single suspicious shortcut (full COM + binary MS-SHLLINK metadata)
.\lnk_files\hunt_lnk.ps1 -Path 'C:\Users\victim\Desktop\Invoice.pdf.lnk'

# Fast Recycle Bin timeline across every fixed volume (no hashing)
.\recycle_bin\hunt_recyclebin.ps1

# Deep pass with hashing, scoped to an incident window (enables deletion-cluster detection)
.\recycle_bin\hunt_recyclebin.ps1 -Hash -Since 2026-07-01

# Fast-tier persistence sweep (32 of 42 modules; default, no elevation required)
.\persistence\hunt_persistence.ps1

# Full sweep including Deep-tier modules (COM hijack, Office add-ins, SYSVOL GPO, BITS jobs, ...)
.\persistence\hunt_persistence.ps1 -Deep -MinSeverity High
```

See each folder's README for the full options reference, scoring tables, "reading a finding"
examples, and validation checklists.
