# Cross-Artifact Correlation

A **playbook** view of the Windows module. Pick the investigative **goal** (or an attacker **technique**), get the **artifacts to pull and the order** to combine them. Windows is unusually generous with overlapping artifacts — the same event (a program running, a file being opened, a device being plugged in) is often recorded by three or four independent subsystems, none of which was designed for forensics and each with its own blind spots. This note maps goals → sources and points at the **`🎯 Hunt Evil`** block in each topic note for the fast-start commands; the field-by-field detail, interpretation pitfalls, and full PowerShell layers live in the topic notes themselves.

> 🔴 Golden rule: **no single Windows artifact proves execution or presence on its own — corroborate across ≥2 independent sources before you write a finding down.** ShimCache can be populated without execution. Prefetch can be absent because the feature is off. Amcache can survive a Prefetch wipe. Convert every timestamp to **UTC** before you compare across sources (Security-log times are already UTC internally but rendered in local time by most viewers; NTFS/FILETIME values are UTC; browser epochs are not FILETIME — see the conversion table below). And capture the **volatile tier before you image or reboot** — RAM, network state, and live registry hives with volatile subkeys don't survive a power-off.

## Contents

- [First Five Minutes](#first-five-minutes)
- [Order of Volatility](#order-of-volatility)
- [Timestamp Epochs and Conversions](#timestamp-epochs-and-conversions)
- [OS/Version Fingerprint](#osversion-fingerprint)
- [Prove Program Execution](#prove-program-execution)
- [Recover a Deleted File](#recover-a-deleted-file)
- [Persistence Sweep](#persistence-sweep)
- [Intrusion from Initial Access](#intrusion-from-initial-access)
- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)
- [Credential Theft](#credential-theft)
- [Anti-Forensics and Tampering](#anti-forensics-and-tampering)
- [Data Exfiltration](#data-exfiltration)
- [Active Directory / Domain Compromise](#active-directory--domain-compromise)
- [Ransomware](#ransomware)
- [Live vs Offline-Image Cheatsheet](#live-vs-offline-image-cheatsheet)

## First Five Minutes

Full triage sequencing and the volatile-collection order live in **16 - Live Response and Volatile Data.md** (its `🎯 Hunt Evil` block is the fast-start source) — this is just the first-touch context every subsequent step depends on.

```powershell
# Context - record ALL of this before touching anything (governs how every other timestamp is read)
Get-Date -Format o; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, CSName
whoami /all; query user

# Capture volatile state (lost on reboot) - see Live Response note for the full priority order
Get-Process | Select-Object Id, ParentId, Path, StartTime, CommandLine | Export-Csv .\ps.csv -NoTypeInformation
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

# The cheap high-yield anomaly checks
Get-CimInstance Win32_Process | Where-Object { $_.Name -notin (Get-Content .\known_good.txt) }
Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName, TaskPath
```

## Order of Volatility

Collect most-volatile first — each step down survives longer, and rebooting/imaging first destroys everything above it.

| # | Tier | Note | Gone on reboot? |
|---|------|------|-----------------|
| 1 | **RAM** (full memory image) | 17/Memory Acquisition Fundamentals | ✅ yes |
| 2 | **Process/network live state** (handles, DLLs, connections, ARP) | 16 - Live Response and Volatile Data | ✅ yes |
| 3 | **Live registry** (volatile subkeys, in-use hive locks) | 04 - Registry Forensics Fundamentals (Live vs Offline Hives) | ✅ some keys yes |
| 4 | **Event logs (buffered/not yet flushed)** | 11 - Event Log Analysis | ⚠️ partial |
| 5 | **Offline disk** (NTFS, registry hives at rest, artifact stores) | 02 - Evidence Acquisition & Imaging; NTFS/00 - NTFS Deep Dive Overview | ❌ persists |

## Timestamp Epochs and Conversions

🔴 Windows hosts one of the widest timestamp-format zoos in DFIR — every artifact family below uses a different one, and mixing them without converting is the single most common Windows timeline error.

| Source | Format | Convert |
|--------|--------|---------|
| NTFS `$STANDARD_INFORMATION`/`$FILE_NAME`, most registry `LastWriteTime` values | **FILETIME** — 100-nanosecond intervals since 1601-01-01 00:00:00 UTC | `[DateTime]::FromFileTimeUtc($filetime)` |
| Event Log (EVTX) `TimeCreated` | FILETIME internally, rendered **local time** by default in Event Viewer/`Get-WinEvent` unless you request UTC | `Get-WinEvent ... | Select @{n='UTC';e={$_.TimeCreated.ToUniversalTime()}}` |
| Chromium (Chrome/Edge) History/Cookies (`visit_time`, `expires_utc`) | **WebKit/Chrome epoch** — microseconds since 1601-01-01 UTC (same epoch year as FILETIME, different unit — do not conflate) | see 14/Chromium (Chrome & Edge).md conversion function |
| Firefox `moz_places`/`moz_historyvisits` (`visit_date`) | **PRTime** — microseconds since 1970-01-01 UTC | see 14/Firefox.md — do not apply the Chromium formula |
| Unix-epoch values surfaced by cross-platform/cloud-sync tooling (e.g. some cloud-storage client DBs, some malware config) | seconds or milliseconds since 1970-01-01 UTC | `[DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime` |
| Prefetch embedded run timestamps (via PECmd, not raw PowerShell) | FILETIME | handled by PECmd's output; treat as UTC |
| `$MFT` and `$LogFile`/`$UsnJrnl` records | FILETIME | see NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes; NTFS/05 - $LogFile; NTFS/06 - $UsnJrnl |

> The classic mistake on Windows specifically: pulling a Chrome `visit_time` and a Firefox `visit_date` into the same spreadsheet and applying one conversion formula to both — same unit (microseconds), different epoch year, off by decades with no error thrown. See 14/Chromium and 14/Firefox for the full pitfall writeup.

## OS/Version Fingerprint

Which build you're on decides which artifacts even exist (Prefetch defaults, ShimCache format, Amcache presence, event-log schema). Full version-delta tables live in **01 - Windows OS Fundamentals & Versions.md**.

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, BuildNumber, OSArchitecture
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName, DisplayVersion, CurrentBuild, UBR
```

| Family | Fingerprint source | Note |
|--------|--------------------|------|
| Client (XP/7/8/8.1/10/11) vs Server | `Caption`/`ProductName` above | 01 - Windows OS Fundamentals & Versions |
| Feature-update level (10 1809+, 11 22H2, etc.) | `DisplayVersion`/`CurrentBuild`/`UBR` | 01 - Windows OS Fundamentals & Versions (Feature-Update Forensic Residue) |
| Domain-joined vs workgroup | `Get-CimInstance Win32_ComputerSystem` (`PartOfDomain`) | 05b - Active Directory & Domain Forensic Artifacts |

## Prove Program Execution

**ATT&CK:** T1059 (Command and Scripting Interpreter) · T1204 (User Execution)

This is the classic Windows correlation story — no single artifact in this family is conclusive alone, and each has a different blind spot. Full side-by-side comparison (what each proves, timestamp precision, retention window, anti-forensic resistance) lives in **06/Amcache.md** ("Amcache vs ShimCache vs Prefetch") — start there for the family-wide picture, then pull individually.

| Order | Source (note) | What it gives | Blind spot |
|-------|---------------|----------------|------------|
| 1 | **06/Prefetch.md** | Up to 8 run timestamps + run count, strongest "this actually executed" signal on client OS | Off by default on Server; capped at 8 runs; can be disabled/cleared |
| 2 | **06/Amcache.md** | First-execution/install evidence (file path, hash, compile timestamp) that often survives Prefetch deletion | Presence can predate actual execution (e.g. install without run) |
| 3 | **06/ShimCache (AppCompatCache).md** | Path + last-modified time for a huge population of touched binaries, no execution-timestamp precision post-XP | Presence ≠ execution — populated on file access checks too |
| 4 | **06/BAM-DAM.md** | Per-user last-execution timestamp from the Background Activity Moderator, independent registry source | Only tracks recent activity; overwritten on next run |
| 5 | **06/UserAssist.md** | GUI-launched program run count + last-run time, tied to the user who launched it | Only catches Explorer-launched GUI apps, not CLI/service-spawned |
| 6 | **16 - Live Response and Volatile Data.md** | What's running right now — recovers a deleted-on-disk binary still mapped by a live process | Gone once the process exits or host reboots |
| 7 | **11 - Event Log Analysis.md** (Sysmon Event ID 1 / Security 4688 if enabled) | Full command line + parent process, if process-creation auditing was turned on before the incident | Off by default — only useful if pre-enabled |
| 8 | **17/Memory Analysis (Processes, Injection, Rootkits).md** | Confirms a process was resident in memory even if every disk-side artifact above was wiped | Requires a memory capture taken while the process was live |

## Recover a Deleted File

**ATT&CK:** T1070.004 (File Deletion)

| Order | Source (note) | What it gives |
|-------|---------------|----------------|
| 1 | **08 - Deleted Items and File Existence.md** (Recycle Bin `$I`/`$R` pairs) | Original path, deletion time, and often the file content itself |
| 2 | **08 - Deleted Items and File Existence.md** (Thumbcache / Windows.edb) | Thumbnail or indexed metadata surviving after the source file and Recycle Bin entry are both gone |
| 3 | **NTFS/07 - File Deletion Mechanics.md** ($MFT orphan entries, $LogFile/$UsnJrnl) | Filesystem-level record of the deletion/rename even without file content |
| 4 | **19 - Anti-Forensics and Evidence Destruction.md** (Volume Shadow Copy analysis) | A pre-deletion copy of the file from a VSS snapshot, if one exists |
| 5 | **16 - Live Response and Volatile Data.md** | Recovers a file still open/mapped by a running process before it's fully gone |

## Persistence Sweep

**ATT&CK:** T1547 (Boot/Logon Autostart) · T1053 (Scheduled Task/Job) · T1543 (Create/Modify System Process) · T1546.003 (WMI Event Subscription) · T1574.001/.002 (DLL Search Order Hijacking/Side-Loading)

| Mechanism | Note (in 10 - Persistence Mechanisms/) |
|-----------|------------------------------------------|
| Run / RunOnce and related autostart registry keys | Autostart (Run-RunOnce) Keys |
| Windows Services | Services |
| Scheduled Tasks | Scheduled Tasks |
| WMI permanent event subscriptions | WMI Event Consumers |
| DLL search-order hijacking / side-loading | DLL Hijacking |

> Corroborate any hit against the **Prove Program Execution** family above (has it actually run since being planted?), the file's own MFT `$STANDARD_INFORMATION`/`$FILE_NAME` timestamp pair (NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes — a mismatch is a timestomp tell), and 11 - Event Log Analysis (Task Scheduler / Service Control Manager operational events recording when the mechanism was created).

## Intrusion from Initial Access

**ATT&CK:** T1078 (Valid Accounts) · T1110 (Brute Force) · T1566 (Phishing) · T1190 (Exploit Public-Facing Application)

| Order | Source (note) | What it gives |
|-------|---------------|----------------|
| 1 | **05 - Users, Groups & Authentication.md** (Logon Types, 4624/4625) | The entry logon — type, source IP, account, success/fail pattern |
| 2 | **11 - Event Log Analysis.md** | Corroborating operational-log events around the same window (RDP/TS, PowerShell, WinRM) |
| 3 | **Threat Landscape and Playbooks/RDP Brute-Force and Foothold Playbook.md** or **Phishing and BEC Initial Access Playbook.md** | End-to-end scenario walkthrough matching the observed access vector |
| 4 | **06 - Evidence of Program Execution/** family | What ran immediately after the foothold logon |
| 5 | **10 - Persistence Mechanisms/** | What the intruder planted to survive the session ending |
| 6 | **18 - Timeline Analysis.md** | Order the full chain, anchored on the entry logon event |

## Lateral Movement

**ATT&CK:** T1021 (Remote Services — RDP/SMB/WinRM) · T1047 (WMI) · T1550.002 (Pass the Hash)

Full source→network→destination framework and comparison table by technique (RDP, PsExec, WMI, PowerShell Remoting, remote scheduled tasks/services, `net use`) live in **12 - Lateral Movement.md** — this is the golden note for this scenario end to end, its own `🎯 Hunt Evil` block is the fast-start source.

| Source (note) | What it gives |
|---------------|----------------|
| **05 - Users, Groups & Authentication.md** (4648 explicit credentials) | The lateral-movement tell — credentials used that differ from the logged-on session |
| **12 - Lateral Movement.md** | Technique-specific source/destination event, registry, and filesystem tables |
| **11 - Event Log Analysis.md** | RDP/TS operational logs, WinRM operational logs, corroborating Security-log logon types |
| **09 - Removable Device (USB) Forensics.md** / **13 - Cloud Storage Artifacts.../** | Rule out non-network pivot paths (physical media, sync-folder drop) before concluding network lateral movement |

## Privilege Escalation

**ATT&CK:** T1548 (Abuse Elevation Control Mechanism) · T1134 (Access Token Manipulation) · T1068 (Exploitation for Privilege Escalation)

| Source (note) | What it gives |
|---------------|----------------|
| **05 - Users, Groups & Authentication.md** | Group membership changes, 4672 (special privileges assigned), new local admin creation |
| **04 - Registry Forensics Fundamentals.md** | UAC configuration, service/task ACL weaknesses recorded in hive permissions |
| **10/Services.md**, **10/Scheduled Tasks.md** | Misconfigured service/task binaries or ACLs used as an escalation primitive |
| **11 - Event Log Analysis.md** | 4672, 4673/4674 (privileged operation), process-creation events around the escalation moment |
| **17/Memory Analysis (Processes, Injection, Rootkits).md** | Token manipulation / injection evidence if disk-side artifacts don't explain the jump |

## Credential Theft

**ATT&CK:** T1003 (OS Credential Dumping) · T1558 (Steal or Forge Kerberos Tickets) · T1552 (Unsecured Credentials)

| Source (note) | What it gives |
|---------------|----------------|
| **05 - Users, Groups & Authentication.md** | SAM hive account structure, logon-type anomalies consistent with replayed credentials |
| **05b - Active Directory & Domain Forensic Artifacts.md** | Kerberos abuse signatures (Golden/Silver Ticket, DCSync/replication abuse) |
| **06/Prefetch.md**, **06/Amcache.md**, **06/ShimCache (AppCompatCache).md** | Execution evidence for known dumping tools (renamed or not — hash-based correlation) |
| **17/Memory Analysis (Processes, Injection, Rootkits).md** | LSASS access/injection evidence — the memory-side proof a dumper actually touched credentials |
| **11 - Event Log Analysis.md** | 4648 (explicit creds), LSASS process-access events if Sysmon/advanced auditing was enabled |

## Anti-Forensics and Tampering

**ATT&CK:** T1070 (Indicator Removal) · T1070.001 (Clear Windows Event Logs) · T1070.006 (Timestomp) · T1070.004 (File Deletion)

| Tell | Where to look (note) |
|------|----------------------|
| Consolidated hunt for all of these | **19 - Anti-Forensics and Evidence Destruction.md** |
| Event logs cleared (1102 Security log cleared, 104 System log cleared) | 11 - Event Log Analysis.md |
| `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamp mismatch (timestomping) | NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md; 19 - Anti-Forensics (Timestomping Detection) |
| Volume Shadow Copies deleted (`vssadmin delete shadows`, common ransomware precursor) | 19 - Anti-Forensics (Volume Shadow Copy Analysis); Threat Landscape/Ransomware Playbook |
| Execution artifacts present but Prefetch/ShimCache selectively missing | 06/Amcache.md (Anti-Forensic Angle); 06/ShimCache (Anti-Forensic Angle) |
| Recycle Bin emptied / `$I`/`$R` pairs deliberately deleted | 08 - Deleted Items and File Existence.md |
| $LogFile/$UsnJrnl gaps or truncation | NTFS/05 - $LogFile; NTFS/06 - $UsnJrnl; 19 - Anti-Forensics |

## Data Exfiltration

**ATT&CK:** T1567 (Exfiltration Over Web Service) · T1052 (Exfiltration Over Physical Medium) · T1041 (Exfiltration Over C2 Channel)

| Angle | Source (note) | What it gives |
|-------|---------------|----------------|
| Cloud sync | **13 - Cloud Storage Artifacts (Local Evidence)/** (OneDrive, Google Drive for Desktop, Box Drive, Dropbox) | Local sync-client evidence of what was staged into a synced folder; cross-link to `Cloud/` for the server-side log |
| Removable media | **09 - Removable Device (USB) Forensics.md** | Device connection window + Object Access auditing (4663/4656) for actual file copy evidence |
| Browser upload | **14 - Web Browser Forensics/Chromium (Chrome & Edge).md**, **Firefox.md** | Upload-capable form-POST/download-history evidence, webmail/file-sharing site visits |
| Email | **15 - Email Forensics.md** | Large attachments sent, forwarding rules, OST/PST evidence of staged messages |
| Network | **16 - Live Response and Volatile Data.md**, **12 - Lateral Movement.md** | Live egress connections; corroborate with firewall/proxy logs outside this module's scope |

## Active Directory / Domain Compromise

**ATT&CK:** T1078.002 (Domain Accounts) · T1484 (Group Policy Modification) · T1207 (DCSync)

Full Kerberos-abuse signatures, replication-metadata timelining, and domain-trust/SID-history abuse live in **05b - Active Directory & Domain Forensic Artifacts.md** — start there for any domain-scoped investigation, its own `🎯 Hunt Evil` block is the fast-start source. GPO forensics — fundamentals, storage/replication, content, DC-side and domain-joined-host investigation, and abuse/hunting — has its own standalone **GPO/** folder, starting at `GPO/00`.

| Source (note) | What it gives |
|---------------|----------------|
| **05b - Active Directory & Domain Forensic Artifacts.md** | Kerberos ticket abuse, DCSync/replication abuse, trust/SID-history abuse |
| **GPO/ folder** (starting at `GPO/00`) | GPO tampering — fundamentals/LSDOU, SYSVOL/AD-object storage, content (Registry.pol/GPP/cpassword), DC-side and domain-joined-host investigation, T1484.001 hunting |
| **11 - Event Log Analysis.md** | Domain-controller-side Security log events (4768/4769/4776 Kerberos, 4662 directory-object access) |
| **05 - Users, Groups & Authentication.md** | Local-host side of the same authentication events for cross-host corroboration |
| **12 - Lateral Movement.md** | How domain credentials were used to move once obtained |

## Ransomware

**ATT&CK:** T1486 (Data Encrypted for Impact) · T1490 (Inhibit System Recovery)

Full scenario framing, deployment-mechanism investigation, shadow-copy/backup destruction confirmation, and encryptor IOC extraction live in **Threat Landscape and Playbooks/Ransomware Playbook.md** — this is the golden note for a live ransomware case, its own `🎯 Hunt Evil` block is the fast-start source.

| Order | Source (note) | What it gives |
|-------|---------------|----------------|
| 1 | **Threat Landscape and Playbooks/Ransomware Playbook.md** | End-to-end scenario, immediate triage priorities, response sequence |
| 2 | **10 - Persistence Mechanisms/** + **06 - Evidence of Program Execution/** | The deployment mechanism and encryptor execution evidence |
| 3 | **19 - Anti-Forensics and Evidence Destruction.md** | Confirming shadow-copy/backup deletion |
| 4 | **12 - Lateral Movement.md**, **05b - Active Directory & Domain Forensic Artifacts.md** | How the actor reached the encrypted hosts and whether the domain itself was compromised first |
| 5 | **21 - Remediation and Containment.md** | Containment and remediation sequencing once scope is understood |

## Live vs Offline-Image Cheatsheet

| Evidence | Live host | Offline image |
|----------|-----------|----------------|
| Processes, network connections, loaded modules | ✅ only source | ❌ gone (unless a memory image was captured) |
| RAM | ✅ acquire now | ❌ unless already captured |
| Volatile registry subkeys (e.g. in-memory-only state, current hardware profile) | ✅ | ❌ |
| NTFS ($MFT, $LogFile, $UsnJrnl), registry hives at rest | ✅ | ✅ |
| Event logs (EVTX) | ✅ `Get-WinEvent` | ✅ mount image, point `-Path` at the offline `.evtx` files |
| Prefetch, ShimCache, Amcache, BAM/DAM, UserAssist, Jump Lists, SRUM | ✅ | ✅ — all disk/hive-resident |
| Recycle Bin, Thumbcache, Windows.edb | ✅ | ✅ |
| USB/device registry artifacts | ✅ | ✅ |
| Browser history/cache/cookies (SQLite/LevelDB/ESE) | ✅ (copy around file locks) | ✅ — no lock issue on a mounted image |
| Volume Shadow Copies | ✅ (`vssadmin list shadows`, mount) | ✅ if the VSC store itself was imaged |
| Deleted files not in Recycle Bin | ✅ `lsof`-equivalent via open handles | ✅ carving/MFT-orphan recovery only |

> Detailed commands, interpretation tables, and red flags for each source are in its own topic note — each note's `🎯 Hunt Evil` block is the fast-start command set for that artifact. This page is the index that tells you **which notes to open** for the case in front of you.
