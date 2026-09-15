# Windows DFIR Field Reference

Hands-on host-level forensic analysis for Windows — exact file paths, registry keys, event IDs, and OS-version deltas from XP through Windows 11 Server. Designed for use during live investigations, triage, and active incidents. Every note opens with Quick Triage (native PowerShell one-liners), then deepens through artifact mechanics, interpretation, and remediation.

> Part of the [Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../LICENSE).

---

## Quick Navigation: Start Here

**For new users:** Start with [`00 - Cross-Artifact Correlation`](<00 - Cross-Artifact Correlation.md>) — pick your investigative goal (program execution, persistence, lateral movement, timeline reconstruction) and it tells you which notes to open in order. [`00b - ATT&CK Windows to Evidence Map`](<00b - ATT&CK Windows to Evidence Map.md>) is the reverse lookup (MITRE technique → evidence location).

**Common Scenarios — which notes to open:**

| Scenario | Start With | Then Read |
|----------|-----------|-----------|
| **Ransomware incident** | [Ransomware Playbook](<Threat Landscape and Playbooks/Ransomware Playbook.md>) | [Timeline Analysis](<18 - Timeline Analysis.md>), [NTFS Deep Dive](<NTFS/00 - NTFS Deep Dive Overview.md>), [Services](<10 - Persistence Mechanisms/Services.md>), [File Server](<23 - Special Services/File Server Forensics.md>) |
| **Lateral movement / lateral recon** | [Lateral Movement](<12 - Lateral Movement.md>) → source/target logs | [Event Log Analysis](<11 - Event Log Analysis.md>), [Kerberos Ticket Abuse](<23 - Special Services/Kerberos Ticket Abuse Investigation.md>), [Active Directory](<05b - Active Directory & Domain Forensic Artifacts.md>) |
| **Suspected persistence / backdoor** | [10 - Persistence Mechanisms](<10 - Persistence Mechanisms/Autostart (Run-RunOnce) Keys.md>) (start with family table) | [Scheduled Tasks](<10 - Persistence Mechanisms/Scheduled Tasks.md>), [Services](<10 - Persistence Mechanisms/Services.md>), [WMI Event Consumers](<10 - Persistence Mechanisms/WMI Event Consumers.md>), [GPO Abuse](<GPO/05 - GPO Abuse, Hunting and Detection.md>) |
| **RDP brute-force / foothold** | [RDP Brute-Force Playbook](<Threat Landscape and Playbooks/RDP Brute-Force and Foothold Playbook.md>) | [Event Log Analysis](<11 - Event Log Analysis.md>), [Users & Auth](<05 - Users, Groups & Authentication.md>), [Timeline](<18 - Timeline Analysis.md>) |
| **Phishing / email compromise** | [Phishing & BEC Playbook](<Threat Landscape and Playbooks/Phishing and BEC Initial Access Playbook.md>) | [Email Forensics](<15 - Email Forensics.md>), [Event Log Analysis](<11 - Event Log Analysis.md>), [Users & Auth](<05 - Users, Groups & Authentication.md>) |
| **Program execution timeline** | [Evidence of Program Execution](<06 - Evidence of Program Execution/Prefetch.md>) | [Amcache](<06 - Evidence of Program Execution/Amcache.md>), [SRUM](<06 - Evidence of Program Execution/SRUM.md>), [ShimCache](<06 - Evidence of Program Execution/ShimCache (AppCompatCache).md>), [Timeline](<18 - Timeline Analysis.md>) |
| **Hidden/suspicious process detection** | [Memory Analysis](<17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md>) | [Volatility 3 Reference](<17 - Memory Forensics/Volatility 3 - Complete Reference Guide.md>), [Program Execution](<06 - Evidence of Program Execution/Prefetch.md>), [Event Logs](<11 - Event Log Analysis.md>) |
| **Credential theft / dumping** | [Memory Analysis](<17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md>) | [Event Log Analysis](<11 - Event Log Analysis.md>), [Users & Auth](<05 - Users, Groups & Authentication.md>) |
| **Anti-forensics / evidence destruction** | [Anti-Forensics](<19 - Anti-Forensics and Evidence Destruction.md>) | [Timeline](<18 - Timeline Analysis.md>), [NTFS](<NTFS/00 - NTFS Deep Dive Overview.md>), [Event Log](<11 - Event Log Analysis.md>) |
| **Domain compromise / GPO abuse** | [GPO Fundamentals](<GPO/00 - GPO Fundamentals and Architecture.md>) | [DC Forensics](<23 - Special Services/Domain Controller — Role-Specific Forensics.md>), [GPO Abuse & Detection](<GPO/05 - GPO Abuse, Hunting and Detection.md>) |

**Tip:** Use GitHub anchors to jump within notes; in Obsidian, use the **Outline** panel.

---

## How This Platform Is Organized

Windows notes fall into three categories:

**1. Atomic Reference Notes (01–22):** Each covers a distinct artifact family or investigation technique. Designed to open during triage as evidence surfaces. Start with the appropriate note for your current finding; the Cross-Artifact Correlation note (00) tells you the reading order for a given investigative goal.

**2. Deep-Dive Folders (NTFS/, GPO/):** Multi-note sequences covering complex, byte-level structures. Read 00→final in order on first pass; after that, use as reference by jumping to specific sections.

**3. Playbooks (Threat Landscape and Playbooks/):** End-to-end scenarios (ransomware, RDP brute-force, phishing) that synthesize evidence from atomic notes into a structured investigation workflow. Open when you know the threat type.

**Cross-Platform Links:** Browser and cloud-storage local artifacts (Chrome, OneDrive) are covered here (filesystem/registry/database level). Server-side evidence (CloudTrail, M365 audit) lives in [Cloud/](../Cloud/README.md). For WSL investigations, see [WSL/02](../WSL/02%20-%20Investigating%20Linux%20Inside%20WSL.md).

---

## Module Status

- ✅ **In Depth:** 100 markdown files across 22 core sections + 3 deep-dive folders (NTFS, GPO, Threat Landscape); playbooks for ransomware, RDP, phishing, supply-chain, persistence, and more
- 🟡 **Evolving:** Special Services (23) – role-specific forensics expanding for additional server roles
- ⏳ **Deferred:** Enterprise Sigma rules, EDR-bypass patterns, advanced threat-hunting scripts

---

## Module Structure

```
Windows/ (100 files total)
├── README.md (188 lines) ⭐ START HERE
│   ├── Quick Navigation Table (8 scenarios)
│   ├── Scope Clarity (3 note categories)
│   └── Module Status & Contents
├── 00 - Cross-Artifact Correlation.md (251 lines) ⭐ ENTRY POINT
│   └── Goal-driven playbook & evidence priority
├── 00b - ATT&CK Windows to Evidence Map.md (160 lines)
│   └── MITRE Technique → Evidence lookup
├── 01–09, 11–22 - Core Investigation Notes (3–7 KB each)
│   └── Atomic reference notes (artifacts, logs, auth, execution, persistence, etc.)
├── NTFS/ ⭐ DEEP DIVE
│   ├── 00 - NTFS Deep Dive Overview.md
│   ├── 01–07 - Structural & Timestamp Deep-Dive
│   └── Focus: MFT, $LogFile, $UsnJrnl, file deletion recovery
├── GPO/ ⭐ DEEP DIVE
│   ├── 00 - GPO Fundamentals and Architecture.md
│   ├── 01–05 - Registry, Storage, Investigation Workflows
│   └── Focus: Group Policy as attack surface (T1484.001)
├── 23 - Special Services/
│   └── IIS, Exchange, SQL, SCCM, DC, File Server, Kerberos
├── Threat Landscape and Playbooks/
│   └── Ransomware, RDP, Phishing, GPO Abuse, Supply-Chain, Commodity Malware, DCSync, Insider, LOLBIN Abuse
├── Windows Posters/ (22 PDFs)
│   └── SANS & community reference materials (see README.md in folder)
└── Scripts/ (10 files)
    └── PowerShell hunting scripts for live DFIR
```

---

## Contents

### Start Here
- [00 - Cross-Artifact Correlation](<00 - Cross-Artifact Correlation.md>) — goal-driven case playbook, order of volatility, timestamp-epoch conversions, OS/version fingerprint
- [00b - ATT&CK Windows to Evidence Map](<00b - ATT&CK Windows to Evidence Map.md>) — MITRE technique → evidence (reverse lookup)

### Core Windows
- [01 - Windows OS Fundamentals & Versions](<01 - Windows OS Fundamentals & Versions.md>) — session model, core process tree, "know normal," XP–Win11/Server version landscape
- [02 - Evidence Acquisition & Imaging](<02 - Evidence Acquisition & Imaging.md>) — Digital Investigation Plan, live-vs-dead-box, KAPE/Arsenal Image Mounter/WinPMEM, encryption detection
- [04 - Registry Forensics Fundamentals](<04 - Registry Forensics Fundamentals.md>) — hive files, live vs offline hives, transaction-log replay, key LastWrite mechanics
- [05 - Users, Groups & Authentication](<05 - Users, Groups & Authentication.md>) — SAM hive, well-known RIDs, logon-type interpretation, core Security-log auth events
- [05b - Active Directory & Domain Forensic Artifacts](<05b - Active Directory & Domain Forensic Artifacts.md>) — Kerberos mechanics, DC-side event IDs, ticket-abuse techniques, DCSync/replication

### GPO/ - Group Policy Object Forensics Deep Dive
Basic → advanced field guide to Group Policy — the mechanism that's simultaneously an organization's baseline-enforcement tool and (per MITRE T1484.001) one of the highest-leverage domain-wide attack techniques available to a privileged attacker. Read 00→05 in order the first time through; after that, use it as a reference, entering directly at the DC-side (03) or domain-joined-host-side (04) investigation notes depending on your vantage point.
- [00 - GPO Fundamentals and Architecture](<GPO/00 - GPO Fundamentals and Architecture.md>) — **start here**: GPT/GPC duality, local vs domain GPO, LSDOU precedence, inheritance/Block Inheritance/Enforced, security filtering, WMI filters, loopback processing
- [01 - Storage, Replication and Version Synchronization](<GPO/01 - Storage, Replication and Version Synchronization.md>) — full SYSVOL/GPT folder tree, GPC AD-object attributes, FRS vs DFSR, GPT/GPC version-desync detection
- [02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates)](<GPO/02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>) — `Registry.pol` binary format, Client-Side Extensions, the GPP file family and the legacy `cpassword`/MS14-025 flaw, `GptTmpl.inf`, ADMX/ADML
- [03 - Domain Controller GPO Investigation](<GPO/03 - Domain Controller GPO Investigation.md>) — DC/AD-object-side workflow: enumeration, `gpLink` scope resolution, malicious-change detection, event 5136, `repadmin /showobjmeta`, GPO backup/restore evidence
- [04 - Domain-Joined Host GPO Investigation](<GPO/04 - Domain-Joined Host GPO Investigation.md>) — endpoint-side workflow: `gpresult`/RSoP, local GPO cache artifacts, `Microsoft-Windows-GroupPolicy/Operational` event log, Group Policy History registry key, staleness detection
- [05 - GPO Abuse, Hunting and Detection](<GPO/05 - GPO Abuse, Hunting and Detection.md>) — capstone: T1484.001 full technique, mass-deployment ransomware pattern, consolidated end-to-end detection workflow, GPP cpassword hunting, remediation

### NTFS/ - NTFS Structural & Timestamp Deep Dive
Basic → advanced field guide to NTFS internals — the byte-level structure beneath every artifact note elsewhere in this module. Sleuth-Kit/Eric-Zimmerman-tool-first, not PowerShell-first, since raw `$MFT`/`$LogFile`/`$UsnJrnl` binary structure sits below what native cmdlets reach. Read 00→07 in order the first time through; after that, use it as a reference.
- [00 - NTFS Deep Dive Overview](<NTFS/00 - NTFS Deep Dive Overview.md>) — **start here**: database-vs-chain mental model, NTFS metadata-file roster, MFT Zone, hex-editor primer, tool roster
- [01 - MFT Entry Structure and Attributes](<NTFS/01 - MFT Entry Structure and Attributes.md>) — record header, sequence numbers/FRN, attribute types, `$ATTRIBUTE_LIST`, `istat`
- [02 - $STANDARD_INFORMATION and $FILE_NAME Attributes](<NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md>) — byte-level $SI/$FN fields, full MACE/MACB behavior-by-operation chart (Win10/Win11), $SI-vs-$FN timestomping detection, exiftool
- [03 - $DATA Attribute and Resident vs Non-Resident Files](<NTFS/03 - $DATA Attribute and Resident vs Non-Resident Files.md>) — resident vs non-resident content, `icat` extraction, Zone.Identifier/Mark of the Web
- [04 - $I30 Directory Index and B-Trees](<NTFS/04 - $I30 Directory Index and B-Trees.md>) — directory B-tree structure, INDX-record slack, deleted-filename recovery from a live directory
- [05 - $LogFile (NTFS Transaction Journal)](<NTFS/05 - $LogFile (NTFS Transaction Journal).md>) — low-level crash-consistency journal, RCRD pages/LSNs, LogFileParser
- [06 - $UsnJrnl (USN Change Journal)](<NTFS/06 - $UsnJrnl (USN Change Journal).md>) — high-level change-tracking journal, reason codes, ransomware blast-radius scoping
- [07 - File Deletion Mechanics](<NTFS/07 - File Deletion Mechanics.md>) — synthesis: what survives at each stage of deletion, Recycle Bin `$R`/`$I` pair, COW/VSS, carving strategy, SSD/TRIM, string-vs-indexed search

### 06 - Evidence of Program Execution
Eight artifacts that each answer "did this program run?" with a different confidence level — opens with a family-wide comparison table.
- [Prefetch](<06 - Evidence of Program Execution/Prefetch.md>) — **start here**: full execution-evidence family comparison, then `.pf` field-by-field detail
- [ShimCache (AppCompatCache)](<06 - Evidence of Program Execution/ShimCache (AppCompatCache).md>) — proves presence/evaluation, not execution
- [Amcache](<06 - Evidence of Program Execution/Amcache.md>) — SHA-1 hash, size, compile-time, publisher metadata for threat-intel pivoting
- [BAM/DAM](<06 - Evidence of Program Execution/BAM-DAM.md>) — power-management byproduct, which user ran what and when, most recently
- [UserAssist](<06 - Evidence of Program Execution/UserAssist.md>) — GUI double-click record with run count and focus-time (user-intent angle)
- [Jump Lists](<06 - Evidence of Program Execution/Jump Lists.md>) — taskbar per-app/per-user "recently used" record
- [SRUM](<06 - Evidence of Program Execution/SRUM.md>) — 30–60 day CPU/network usage history, the family's longest memory
- [Task Bar Feature Usage & CapabilityAccessManager](<06 - Evidence of Program Execution/Task Bar Feature Usage & CapabilityAccessManager.md>) — Win10 1903+ taskbar-interaction and mic/camera/location access logs

### 07-09 - User Activity & Devices
- [07 - File and Folder Opening (User Activity)](<07 - File and Folder Opening (User Activity).md>) — Shellbags, RecentDocs, Office MRU, LNK files, TypedPaths, WordWheelQuery
- [08 - Deleted Items and File Existence](<08 - Deleted Items and File Existence.md>) — Recycle Bin, Thumbs.db/Thumbcache, Windows Search Database — the "chain of survivability"
- [09 - Removable Device (USB) Forensics](<09 - Removable Device (USB) Forensics.md>) — USBSTOR/SCSI/MTP keys, setupapi.log, connection timestamps, drive-letter mapping

### 10 - Persistence Mechanisms
One note per mechanism, each covering how the persistence works, host-evidence footprint, and (for Services/Scheduled Tasks/WMI) the remote-execution/lateral-movement angle summarized before deferring to note 12.
- [Autostart (Run/RunOnce) Keys](<10 - Persistence Mechanisms/Autostart (Run-RunOnce) Keys.md>) — **start here**: family orientation table, then Run/RunOnce mechanics
- [Services](<10 - Persistence Mechanisms/Services.md>) — SCM-managed autostart, plus `sc create`/PsExec remote-execution angle
- [Scheduled Tasks](<10 - Persistence Mechanisms/Scheduled Tasks.md>) — Task Scheduler triggers, XML/registry footprint, plus `schtasks /s` remote angle
- [WMI Event Consumers](<10 - Persistence Mechanisms/WMI Event Consumers.md>) — permanent event subscriptions in the WMI repository, highest-stealth mechanism in the family
- [DLL Hijacking](<10 - Persistence Mechanisms/DLL Hijacking.md>) — loader search-order abuse, usually layered on another mechanism's launcher

### 11-12 - Logs & Movement
- [11 - Event Log Analysis](<11 - Event Log Analysis.md>) — .evtx mechanics, Security/System/Application event-ID tables, PowerShell/WinRM/TS/WMI-Activity operational logs
- [12 - Lateral Movement](<12 - Lateral Movement.md>) — RDP, PsExec/SMB, WMI, PowerShell Remoting, remote tasks/services, `net use` — unified source/destination comparison

### 13 - Cloud Storage Artifacts (Local Evidence)
Local-host "evidence on disk" lens only; cross-links to `Cloud/` for the server-side lens.
- [OneDrive](<13 - Cloud Storage Artifacts (Local Evidence)/OneDrive.md>) — built-in Win10+ sync client, common insider-exfiltration channel
- [Google Drive for Desktop](<13 - Cloud Storage Artifacts (Local Evidence)/Google Drive for Desktop.md>) — Drive for Desktop local artifacts
- [Box Drive](<13 - Cloud Storage Artifacts (Local Evidence)/Box Drive.md>) — stream-only client, local content presence is always conditional
- [Dropbox](<13 - Cloud Storage Artifacts (Local Evidence)/Dropbox.md>) — oldest client covered, `.dbx`-era through SQLCipher-encrypted local databases

### 14 - Web Browser Forensics
- [Chromium (Chrome & Edge)](<14 - Web Browser Forensics/Chromium (Chrome & Edge).md>) — SQLite + LevelDB artifact model shared by Chrome and modern Edge; longest note in the subfolder
- [Firefox](<14 - Web Browser Forensics/Firefox.md>) — Gecko engine, `places.sqlite`, contrasted against the Chromium note
- [Internet Explorer & Legacy Edge](<14 - Web Browser Forensics/Internet Explorer & Legacy Edge.md>) — IE11/EdgeHTML artifacts, still relevant via Chromium Edge's IE mode
- [Private Browsing & Anti-Forensic Recovery](<14 - Web Browser Forensics/Private Browsing & Anti-Forensic Recovery.md>) — synthesis note: where evidence survives private browsing, SQLite/ESE recovery
- [Electron Apps (Teams, Discord, WebView2)](<14 - Web Browser Forensics/Electron Apps (Teams, Discord, WebView2).md>) — Chromium-under-the-hood apps, app-specific chat/call/log artifacts

### 15-16 - Email & Live Response
- [15 - Email Forensics](<15 - Email Forensics.md>) — OST/PST local artifacts (full depth), Exchange Server EDB/STM (real coverage), M365/Workspace (cross-linked)
- [16 - Live Response and Volatile Data](<16 - Live Response and Volatile Data.md>) — collection methodology/sequencing on a still-running host, mirrors Linux/10

### 17 - Memory Forensics
- [Volatility 3 - Complete Reference Guide](<17 - Memory Forensics/Volatility 3 - Complete Reference Guide.md>) — **primary reference**: command-by-command Volatility 3 syntax, plugin discovery, output interpretation, common workflows
- [Memory Analysis (Processes, Injection, Rootkits)](<17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md>) — **operational guide**: enterprise DFIR workflow for detecting hidden processes, code injection, rootkits, and credential theft; references Volatility 3 for exact command syntax
- [Memory Acquisition Fundamentals](<17 - Memory Forensics/Memory Acquisition Fundamentals.md>) — RAM capture methods, pagefile/hiberfil/swapfile, memory carving, acquisition sequencing

### Response and Timelining
- [18 - Timeline Analysis](<18 - Timeline Analysis.md>) — super-timeline methodology, normalizing/merging/reading cross-source chronologies
- [19 - Anti-Forensics and Evidence Destruction](<19 - Anti-Forensics and Evidence Destruction.md>) — timestomping, shadow-copy deletion, $LogFile/$UsnJrnl tamper detection
- [20 - Threat Hunting Methodology and Intelligence](<20 - Threat Hunting Methodology and Intelligence.md>) — IR lifecycle, hunting disciplines, kill chain, ATT&CK — feeds 00b
- [21 - Remediation and Containment](<21 - Remediation and Containment.md>) — disable-before-delete, host isolation without losing volatile evidence, credential reset, verify-clean
- [22 - Enterprise Management and Baseline](<22 - Enterprise Management and Baseline.md>) — fleet-wide baselining discipline, golden-image/Autoruns diffing, post-incident drift restoration (GPO forensics now lives in its own `GPO/` folder)

### 23 - Special Services
Role-specific, hands-on investigation field guides for server roles — one level more operational than the reference notes above: each opens with a step-by-step **Investigation Workflow** (enumerate the role's footprint → find the logs → read them → hunt commands → persistence patterns) rather than the flatter artifact-reference shape used by `01`-`22`. New territory in this module except where noted.
- [IIS - Web Server Forensics](<23 - Special Services/IIS - Web Server Forensics.md>) — sites/pools/bindings, W3C log hunting (user-agents, IPs, time windows, string search), web shell detection, `w3wp.exe → cmd.exe`
- [Microsoft Exchange Server Forensics](<23 - Special Services/Microsoft Exchange Server Forensics.md>) — HttpProxy/Message Tracking logs, ProxyLogon/ProxyShell-class log signatures, hidden inbox-rule BEC persistence; complements 15's format/e-discovery lens
- [SQL Server Forensics](<23 - Special Services/SQL Server Forensics.md>) — `xp_cmdshell`/CLR/OLE Automation backdoors, linked-server pivoting, Agent Job & startup-procedure persistence, `sqlservr.exe → cmd.exe`
- [SCCM (Configuration Manager) Forensics](<23 - Special Services/SCCM (Configuration Manager) Forensics.md>) — SCCM as an attack platform: deployment abuse, Run Scripts/CMPivot, NAA credential theft, OSD task-sequence credentials
- [Domain Controller — Role-Specific Forensics](<23 - Special Services/Domain Controller — Role-Specific Forensics.md>) — what's different because the box *is* a DC: NTDS.dit acquisition, SYSVOL/DFSR, rogue-DC/DCShadow detection; additive to 05b, not a duplicate
- [File Server Forensics](<23 - Special Services/File Server Forensics.md>) — share/NTFS dual-permission model, DFS path-resolution trap, object-access auditing, mass-access/mass-rename ransomware-recon detection; file-server-side complement to the Ransomware Playbook
- [Kerberos Ticket Abuse Investigation](<23 - Special Services/Kerberos Ticket Abuse Investigation.md>) — live host/ticket-level investigation workflow (`klist`, Golden/Silver Ticket, Pass-the-Ticket, delegation abuse, estate-wide Kerberoasting sweep); operational companion to 05b's fundamentals/detection catalog, not a re-explanation

### Threat Landscape and Playbooks
- [Windows Malware and Threat Landscape](<Threat Landscape and Playbooks/Windows Malware and Threat Landscape.md>) — survey/landing page mapping threat categories to detection depth elsewhere in the module
- [Ransomware Playbook](<Threat Landscape and Playbooks/Ransomware Playbook.md>) — tactical sequence from first report through fleet-wide scoping and recovery
- [RDP Brute-Force and Foothold Playbook](<Threat Landscape and Playbooks/RDP Brute-Force and Foothold Playbook.md>) — detecting the brute-force-to-success pivot and scoping the foothold
- [Phishing and BEC Initial Access Playbook](<Threat Landscape and Playbooks/Phishing and BEC Initial Access Playbook.md>) — malware-delivery and pure-BEC shapes, inbox-rule abuse
- [WIP Progress - Playbook Ideas](<Threat Landscape and Playbooks/WIP Progress - Playbook Ideas.md>) — backlog

---

## Conventions & Voice

- **Quick Triage** block near the top of every note — 4–8 native PowerShell one-liners for fast live-session triage, no third-party modules required
- Most notes also layer **Basic → Interpret → Advanced → Remediate** PowerShell subsections — view the raw artifact, decode it, hunt across hosts via `Invoke-Command`/CIM, then remediate (as a distinct step after evidence capture)
- 🔴 marks high-value / red-flag items — easily missed indicators or high-confidence evidence
- Commands are blank-line separated; tables explain what output means and how to interpret it
- MITRE ATT&CK technique IDs are tagged per note (verify against current Enterprise matrix)
- OS-version deltas (XP / Win7 / Win8 / Win10 / Win11 / Server) are called out whenever they change a path, registry key, or event ID
- Named tools are first-class: Eric Zimmerman suite (RECmd, MFTECmd, JLECmd, PECmd, LECmd, Registry Explorer), KAPE, Arsenal Image Mounter, Autopsy, FTK, X-Ways, AXIOM

---

## Disclaimers & Scope

- **Field reference, not substitute for understanding.** Verify artifact behavior against the specific Windows build in front of you — paths, registry keys, and event IDs evolve.
- **Built from Windows internals research and public DFIR sources.** Bundled SANS FOR500/FOR508 posters are a coverage checklist reference; not affiliated with or endorsing any vendor or training provider.
- **Scope:** Host-level forensic analysis with exact file paths, registry keys, event IDs, and OS-version deltas from XP through Windows 11 Server. Enterprise hunting scripts (Sigma, LOLBAS) are deferred. Browser/cloud-storage local artifacts are covered here; server-side evidence (CloudTrail, M365 audit) is in [Cloud/](../Cloud/README.md).

---

## License

The notes in this repository are released under the [MIT License](../LICENSE). The bundled SANS FOR500/FOR508 reference PDFs are **not** covered by this license and remain under their original authors' rights.
