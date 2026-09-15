# Additional Topics and Tools

Final logging data sources and utilities that complement the command-line `log` workflow: **Spotlight** indexing (file/usage evidence), the **auditd / OpenBSM** subsystem (low-level security auditing — the closest macOS has to a process-exec audit), assorted miscellaneous logs, and the three GUI log browsers — **Console**, **Ulbow**, and **Consolation**. Use these so no evidence is overlooked.

> 🔴 OpenBSM (`auditd`) is the one source that can record **process execution, exec args, and per-syscall auth** — the gap Unified Logs leaves. If it's enabled, `/var/audit` is gold. Spotlight metadata can reveal files (and their origins/usage) even after deletion of the original.

## Contents
- [Quick Triage](#quick-triage)
- [Spotlight Indexing](#spotlight-indexing)
- [auditd and OpenBSM](#auditd-and-openbsm)
- [Miscellaneous Logs and Locations](#miscellaneous-logs-and-locations)
- [GUI Tool Console](#gui-tool-console)
- [GUI Tool Ulbow](#gui-tool-ulbow)
- [GUI Tool Consolation](#gui-tool-consolation)
- [Choosing an Approach](#choosing-an-approach)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
sudo praudit -l /var/audit/current 2>/dev/null | grep -i exec      # exec audit (if enabled)

mdls /path/to/suspect_file                                         # provenance / usage

tail -n 50 /var/log/install.log                                    # recent installs

last; pmset -g log | grep -Ei 'Wake|Shutdown|Start'
```

---

## Spotlight Indexing

Spotlight (`mds`/`mdworker`) indexes file metadata into per-volume stores. The metadata can place files on the system, show usage, and survive deletion of the original content. *(Full artifact details — store location, `kMDItem` attributes, offline parsing — are in the dedicated **Spotlight** note under Artifacts.)*

```bash
# Query the index (like Spotlight search)
mdfind "kMDItemDisplayName == '*.app'"

mdfind -onlyin ~/Downloads "malware"

# Dump all metadata for a file (incl. where-from, dates, usage)
mdls /path/to/file

# Spotlight daemon log activity (process-based)
log show --predicate 'process == "mds" OR process == "mdworker" OR process == "mds_stores"' --last 24h

# Spotlight metadata via subsystem (indexing / metadata-server events)
log show --predicate 'subsystem == "com.apple.spotlightindex" OR subsystem == "com.apple.metadata"' --info --last 24h
```
> Subsystem names vary by macOS version (`com.apple.spotlightindex`, `com.apple.metadata`, `com.apple.metadata.mds`) — query both process and subsystem to be safe.

| Artifact | Path | Holds |
|---|---|---|
| 🔴 Spotlight store | `/.Spotlight-V100/` (per volume; also user dirs) | Indexed metadata DB |
| `mdls` fields | — | `kMDItemWhereFroms` (download URL), `kMDItemLastUsedDate`, content dates, content type |

🔴 DFIR value: `kMDItemWhereFroms`/`kMDItemDownloadedDate` corroborate download provenance (cross-ref quarantine); `kMDItemLastUsedDate` shows **when a file was opened**; the index may retain entries for files now deleted.

---

## auditd and OpenBSM

OpenBSM is the BSM audit subsystem (`auditd` + `audit`), writing binary audit trails to `/var/audit`. It can capture exec, file access, logins, and privilege use at the syscall level.

```bash
# Is auditing running / what's its state
sudo audit -t                       # query the daemon (or: sudo launchctl list | grep auditd)

cat /etc/security/audit_control      # policy: flags, dir, retention

# Read the current/active audit trail (binary → text)
sudo praudit -l /var/audit/current

sudo praudit -l /var/audit/<timestamp>.<timestamp>

# Filter the trail for events of interest (e.g. exec, by user)
sudo praudit /var/audit/current | grep -i "exec"
```

| Artifact | Path | Holds |
|---|---|---|
| 🔴 Audit trails | `/var/audit/` | Binary BSM records (exec, file, login, privilege) |
| Audit config | `/etc/security/audit_control`, `audit_user`, `audit_class`, `audit_event` | What's audited, retention, flags |

> ⚠️ Auditing is **often minimal or off** by default on modern macOS, and Apple has signaled OpenBSM deprecation in favor of **Endpoint Security (ES)**. If `/var/audit` exists and is populated, parse it — it fills the exec-logging gap Unified Logs leaves. For live/EDR-grade exec telemetry, an Endpoint Security–based agent is the modern path.

🔴 Watch for: `auditd` recently **stopped**, `audit_control` flags reduced, or `/var/audit` trails **deleted** — anti-forensics on the highest-fidelity source.

---

## Miscellaneous Logs and Locations

| Source | Path / command | Value |
|---|---|---|
| Install history | `/var/log/install.log` | Package/OS installs & updates (long retention) |
| App install timeline | `system_profiler SPInstallHistoryDataType` | What was installed and when |
| Login history | `last`, `last -t`, `/var/run/utmpx` | Console/remote login sessions |
| Power/boot history | `pmset -g log` | Sleep/wake/shutdown/boot (cross-ref System & Kernel) |
| Knowledge / usage | `~/Library/Application Support/Knowledge/knowledgeC.db` | App focus/usage, device events |
| FSEvents | `/.fseventsd/` | File-system change history |
| 🔴 **Time Machine** | `tmutil` ; subsystem `com.apple.TimeMachine` | Backup history/destinations; reveals what was backed up & when (recover deleted data from backups) |
| **DiagnosticMessages** | `/var/log/DiagnosticMessages/` | Older **ASL** diagnostic-message reports (`*.asl`) — parse with `syslog -f`; useful on upgraded systems (cross-ref Legacy Logs) |
| sysdiagnose | `sudo sysdiagnose` / **⇧⌃⌥⌘ + .** | One-shot bundle of logs + diagnostics |

```bash
# Time Machine: backup history + destinations + (local) snapshots
tmutil listbackups                         # completed backups on the destination
tmutil destinationinfo                     # configured backup target(s)
tmutil listlocalsnapshots /                # local APFS snapshots (cross-ref APFS)
log show --predicate 'subsystem == "com.apple.TimeMachine"' --info --last 7d

# DiagnosticMessages (legacy ASL diagnostic reports)
ls -lh /var/log/DiagnosticMessages/
syslog -f /var/log/DiagnosticMessages/*.asl 2>/dev/null | tail -n 50
```

> 🔴 Time Machine is a recovery goldmine: a backup (or its **local snapshots**) can resurrect files/states an attacker deleted or altered on the live volume. Always check for a TM destination and enumerate snapshots.

---

## GUI Tool Console

Apple's built-in log viewer (`/System/Applications/Utilities/Console.app`).

- Browses live Unified Log stream and `DiagnosticReports`/crash logs.
- Filtering by process/subsystem/text; "Start streaming" for live capture.
- 🔴 Limitation: **can't query historical persisted log well** and is **slow** on large data sets — fine for quick/live looks, weak for deep historical triage. Use `log show` or the tools below for that.

---

## GUI Tool Ulbow

The Eclectic Light Company's Unified Log browser.

- Fast historical **`log show`**-style queries with a real UI (predicates, time ranges, levels incl. info/debug).
- Opens collected **`.logarchive`** bundles for offline analysis.
- Far better than Console for **historical** Unified Log investigation.

---

## GUI Tool Consolation

Also from The Eclectic Light Company — long-standing Unified Log query GUI.

- Predicate builder, time-window selection, save/export results.
- Good for analysts who want `log`'s power without crafting predicates by hand.
- Pairs with **T2M2** (log-problem analysis) and **XProCheck** (XProtect/Remediator report viewer) from the same author.

---

## Choosing an Approach

| Need | Best tool |
|---|---|
| Scripted/repeatable historical query | `log show --predicate` (CLI) |
| Live tail during IR | `log stream` / Console |
| Friendly historical browsing | Ulbow / Consolation |
| Offline analysis of collected logs | `log --archive` / Ulbow on a `.logarchive` |
| Process-exec / syscall detail | OpenBSM `/var/audit` (if on) / Endpoint Security agent |
| File presence/usage/provenance | Spotlight `mdls`/`mdfind` |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `auditd` stopped / `/var/audit` trails deleted | Anti-forensics on highest-fidelity source |
| `audit_control` flags reduced | Logging quietly weakened |
| Spotlight `kMDItemWhereFroms` showing download from a malicious host | Payload provenance |
| `mdls` last-used dates contradicting the user's account | Hidden file usage |
| `install.log` showing an unexpected package/profile install | Unauthorized software / persistence |
| Spotlight indexing **disabled** (`mdutil -s /`) for a volume | Hiding files from search/timeline |
| sysdiagnose/diagnostic captures the analyst didn't run | Possible attacker recon of system state |

---

## Resources

- 🔴 macOS Log Cheat Sheet (13cubed): https://cdn.13cubed.com/downloads/macos_log_cheat_sheet.pdf
- Ulbow and Consolation (The Eclectic Light Company): https://eclecticlight.co/downloads/
- The Eclectic Light Company – log utilities overview: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
