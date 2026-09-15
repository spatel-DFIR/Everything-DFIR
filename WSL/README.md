# WSL (Windows Subsystem for Linux) DFIR Field Reference

A hands-on **WSL-specific Digital Forensics & Incident Response** reference — focused on answering **"What is WSL, and how is it different?"** rather than duplicating Windows and Linux DFIR. Every note cross-references the Windows and Linux sections, so you spend your time on WSL-specific challenges: cross-OS investigation, artifact acquisition, interop pivots, and EDR evasion patterns.

> Part of the [Everything-DFIR](../README.md) repository (Windows · Linux · macOS · Container · Cloud).

> **Start with [01 - WSL Artifacts on the Windows Host](<01 - WSL Artifacts on the Windows Host.md>)** if you've found WSL on a system and need to understand its footprint. Then use [02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>) to dive into the distro's filesystem. For registry-level details, see [03 - WSL Registry & Configuration Deep-Dive](<03 - WSL Registry & Configuration Deep-Dive.md>). For active hunting, see [04 - WSL-Specific Hunting & Detection](<04 - WSL-Specific Hunting & Detection.md>).

---

## Module Status

- **✅ In Depth:** 4 comprehensive notes (50+ KB total) covering Windows-host artifacts, Linux-inside-distro investigation, registry deep-dive (complete LXSS reference), and WSL-specific hunting & detection with 200+ cross-references
- **Focus:** WSL-specific forensics — explains **what's different** from standard Windows/Linux, not duplicate coverage

---

## Quick Navigation: Start Here

**If you've found WSL on a system:**

| Scenario | Start With | Then Read |
|----------|-----------|-----------|
| "I found WSL, now what?" | [01 - WSL Artifacts on the Windows Host](<01 - WSL Artifacts on the Windows Host.md>) — vhdx location, registry inventory, event logs | [02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>) — mount the vhdx, check for persistence and cross-OS activity |
| "I'm analyzing a distro's filesystem" | [02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>) | [Linux → 04 - Shells and Command History](<../Linux/04 - Shells and Command History.md>) for shell history; [Linux → 09 - Persistence Mechanisms](<../Linux/09 - Persistence Mechanisms>) for persistence checks (note: some don't apply in WSL) |
| "Registry analysis: distro hunting" | [03 - WSL Registry & Configuration Deep-Dive](<03 - WSL Registry & Configuration Deep-Dive.md>) | [Windows → 04 - Registry Forensics Fundamentals](<../Windows/04 - Registry Forensics Fundamentals.md>) for hive acquisition |
| "Active hunt: suspicious WSL activity" | [04 - WSL-Specific Hunting & Detection](<04 - WSL-Specific Hunting & Detection.md>) | [Windows → 11 - Event Log Analysis](<../Windows/11 - Event Log Analysis.md>) for LxssManager / Hyper-V event interpretation |
| "Timeline correlation: Windows + Linux events" | [01](<01 - WSL Artifacts on the Windows Host.md>) + [02](<02 - Investigating Linux Inside WSL.md>) + [Windows → 18 - Timeline Analysis](<../Windows/18 - Timeline Analysis.md>) | Build vhdx timeline with [Linux → 13 - Timelining](<../Linux/13 - Timelining.md>) |

**Tip:** WSL notes use GitHub-style anchors for in-note jumping. In Obsidian, use the **Outline** panel.

---

## Scope: What This Module Covers (and What It Doesn't)

### ✅ We Cover

1. **WSL architecture:** WSL1 vs WSL2 storage differences, vhdx format, interop bridge, `/mnt/c` access
2. **Windows-side forensics:** LXSS registry keys, vhdx location and access patterns, event logs, prefetch analysis
3. **Linux-side forensics (distro):** Unique WSL differences (init, systemd status, `/etc/wsl.conf` persistence, shell-startup priority)
4. **Cross-OS activity:** Detecting interop pivots (Linux→Windows .exe execution, Windows→Linux command execution), file access across the boundary
5. **Registry deep-dive:** Complete LXSS key reference, Flags bits, detecting unauthorized distro installation
6. **Hunting & detection:** VHD access patterns, registry change detection, process ancestry, timeline correlation

### ❌ We Don't Duplicate

- **Windows-only forensics:** Registry hive structure, NTFS deep-dive, GPO, AD, event log filtering → See [Windows/](../Windows/)
- **Linux-only forensics:** ext4 internals, systemd units, cron, PAM, SELinux → See [Linux/](../Linux/)
- **General Linux tools:** Volatility, tcpdump, audit framework → See Linux notes + Linux RTR scripts

**In short:** WSL notes answer **"How is WSL different?"** and cross-link you to Windows/Linux for the "how do I analyze this artifact?" details.

---

## Contents

### 1. **[01 - WSL Artifacts on the Windows Host](<01 - WSL Artifacts on the Windows Host.md>)**

**What to read this for:** You need to find a WSL installation on a Windows box, locate the distro's vhdx or rootfs, understand its configuration, and collect it as evidence.

- **WSL1 vs WSL2 comparison:** storage, filesystem, evidence location
- **LXSS registry keys:** where distros are registered, what each key means
- **VHD location:** where `ext4.vhdx` lives (Store-installed vs imported)
- **Mounting the distro offline:** extracting the Linux filesystem from Windows
- **Windows-side execution traces:** Prefetch, event logs, launcher artifacts
- **Interop boundary:** cross-OS process execution and pivot opportunities

**Cross-reference highlights:**
- [Windows → 04 - Registry Forensics Fundamentals](<../Windows/04 - Registry Forensics Fundamentals.md>) — for HKEY_LOCAL_MACHINE hive parsing
- [Windows → 11 - Event Log Analysis](<../Windows/11 - Event Log Analysis.md>) — for LxssManager / Hyper-V events
- [Linux → 12 - Evidence Collection and Triage](<../Linux/12 - Evidence Collection and Triage.md>) — for vhdx acquisition workflow
- [03 - WSL Registry & Configuration Deep-Dive](<03 - WSL Registry & Configuration Deep-Dive.md>) — for detailed registry key reference

---

### 2. **[02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>)**

**What to read this for:** You're inside (or have mounted) a WSL distro's filesystem and want to run standard Linux DFIR — but need to know the WSL-specific caveats.

- **Confirming you're in WSL:** kernel banner, `/init`, environment variables
- **WSL1 vs WSL2 differences:** capabilities, proc filesystems, kernel artifacts
- **Init and systemd:** WSL default (no systemd), how to detect if it's enabled
- **The `/mnt/c` boundary:** Windows filesystem access from Linux, interop execution
- **WSL-native persistence:** `[boot] command=`, shell startup (cron often doesn't run)
- **Networking:** localhost forwarding, DNS control points

**Cross-reference highlights:**
- [Linux → 04 - Shells and Command History](<../Linux/04 - Shells and Command History.md>) — for shell history analysis (prioritize bash_history in WSL)
- [Linux → 09 - Persistence Mechanisms → Cron and at Jobs](<../Linux/09 - Persistence Mechanisms/Cron and at Jobs.md>) — **WSL note:** cron often doesn't run; check `[boot] command=` and shell startup first
- [Linux → 09 - Persistence Mechanisms → Systemd Units](<../Linux/09 - Persistence Mechanisms/Systemd Units Timers and Generators.md>) — only applies if `[boot] systemd=true`
- [Linux → 11b - ELF and Malware Triage](<../Linux/11b - ELF and Malware Triage.md>) — for analyzing payloads found in the distro (Windows EDR can't see them)
- [01 - WSL Artifacts on the Windows Host](<01 - WSL Artifacts on the Windows Host.md>) — for the Windows-host side of the same investigation

---

### 3. **[03 - WSL Registry & Configuration Deep-Dive](<03 - WSL Registry & Configuration Deep-Dive.md>)**

**What to read this for:** You need deep registry knowledge: parsing LXSS keys offline, detecting unauthorized distro installation or configuration changes, understanding Flags bits and State values.

- **Complete LXSS key reference:** every value in the registry, what it means, forensic significance
- **Flags bit interpretation:** interop, mount settings, metadata handling
- **State values:** detecting incomplete/corrupted distro registrations
- **Global WSL config:** `.wslconfig` (Windows side) vs `wsl.conf` (inside distro)
- **Detecting unauthorized imports:** non-Store distros, unusual BasePaths, root-default UIDs
- **Registry acquisition workflow:** offline parsing, PowerShell queries, RegRipper

**Cross-reference highlights:**
- [Windows → 04 - Registry Forensics Fundamentals](<../Windows/04 - Registry Forensics Fundamentals.md>) — for hive structure, LastWrite mechanics, offline registry analysis
- [Windows → 18 - Timeline Analysis](<../Windows/18 - Timeline Analysis.md>) — for correlating registry LastWrite with timeline events
- [01 - WSL Artifacts on the Windows Host](<01 - WSL Artifacts on the Windows Host.md>) — quick reference to registry keys (full deep-dive here)
- [02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>) — for `/etc/wsl.conf` inspection (inside the distro)

---

### 4. **[04 - WSL-Specific Hunting & Detection](<04 - WSL-Specific Hunting & Detection.md>)**

**What to read this for:** Active threat hunt — detecting WSL installation, cross-OS pivots, suspicious process ancestry, registry tampering, unauthorized persistence, and EDR evasion patterns.

- **VHD access patterns:** forensic timestamps reveal active distro use
- **Registry hunting:** detecting new distros, non-Store installations, config tampering
- **Process ancestry:** wsl.exe spawning cmd.exe = interop pivot
- **Event log hunting:** LxssManager, Hyper-V, process-creation events
- **Cross-OS activity:** Linux launching Windows .exe, Windows accessing `/mnt/c`
- **Persistence hunting:** `[boot] command=`, shell startup files, systemd units (if enabled)
- **Timeline correlation:** tying Windows events to Linux filesystem activity

**Includes:**
- PowerShell hunting queries (registry scan, process hunt, event filtering)
- Timeline correlation techniques
- Full hunting checklist
- Cross-reference to Windows/Linux for detailed interpretation

**Cross-reference highlights:**
- [Windows → 06 - Evidence of Program Execution → Prefetch](<../Windows/06 - Evidence of Program Execution/Prefetch.md>) — wsl.exe execution timeline
- [Windows → 11 - Event Log Analysis](<../Windows/11 - Event Log Analysis.md>) — LxssManager / Hyper-V event ID interpretation
- [Linux → 13 - Timelining](<../Linux/13 - Timelining.md>) — for building ext4 timeline from mounted vhdx
- [02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>) — for inside-distro persistence hunting

---

## Common Investigation Paths

### Scenario: "Malware Found Running in WSL"

1. Start: [01 - WSL Artifacts on the Windows Host](<01 - WSL Artifacts on the Windows Host.md>) → locate the vhdx
2. Mount the vhdx, then: [02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>) → confirm you're in WSL, check init/systemd, investigate payload
3. Payload analysis: [Linux → 11b - ELF and Malware Triage](<../Linux/11b - ELF and Malware Triage.md>) → static/dynamic analysis (Windows EDR can't see it)
4. Timeline: [Linux → 13 - Timelining](<../Linux/13 - Timelining.md>) + [Windows → 18 - Timeline Analysis](<../Windows/18 - Timeline Analysis.md>) → correlate creation time, execution, exfiltration

### Scenario: "Suspicious Process Ancestry: cmd.exe Parent is bash.exe"

1. Start: [04 - WSL-Specific Hunting & Detection](<04 - WSL-Specific Hunting & Detection.md>) → Process Ancestry & Interop Pivots section
2. Trace: [Windows → 06 - Evidence of Program Execution](<../Windows/06 - Evidence of Program Execution/Prefetch.md>) → find bash.exe / wsl.exe Prefetch
3. Timeline: [Windows → 18 - Timeline Analysis](<../Windows/18 - Timeline Analysis.md>) → when did the interop pivot occur? Any preceding commands?
4. Linux-side: [02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>) → inspect shell history for the command that spawned cmd.exe

### Scenario: "Registry Hunt: Find Unauthorized Distros"

1. Start: [03 - WSL Registry & Configuration Deep-Dive](<03 - WSL Registry & Configuration Deep-Dive.md>) → Detecting Unauthorized Distro Installation section
2. Acquire: [Windows → 04 - Registry Forensics Fundamentals](<../Windows/04 - Registry Forensics Fundamentals.md>) → export NTUSER.DAT, parse offline
3. Check: Flags, DefaultUid, BasePath, PackageFamilyName for red flags
4. Correlate: [04 - WSL-Specific Hunting & Detection](<04 - WSL-Specific Hunting & Detection.md>) → Registry Change Detection section; timeline against creation date

---

## Key Concepts: What's Different in WSL

### 1. **Two Filesystems, One Investigation**

- **Windows side:** NTFS, MFT, registry (tracked by Windows tools)
- **Linux side:** ext4 inside a vhdx (invisible to Windows without mounting)

**WSL-specific challenge:** Evidence is split. A malware incident needs investigation on **both** sides: when did wsl.exe launch? (Windows). What did the payload do inside Linux? (Inside distro, via vhdx mount).

### 2. **Init and Systemd: Usually Missing**

- Windows: PID 1 is `C:\Windows\System32\smss.exe` (Session Manager)
- Linux normally: PID 1 is `systemd`
- **WSL default:** PID 1 is Microsoft's `/init` (not systemd)

**WSL-specific challenge:** Standard Linux persistence vectors (systemd units, cron) often don't work. Instead, prioritize `[boot] command=` and shell startup files.

### 3. **Interop: The Cross-OS Pivot**

Windows→Linux: `wsl.exe -e /bin/bash -c '...'`  
Linux→Windows: `powershell.exe` launched from inside the distro

**WSL-specific challenge:** An attacker can use WSL to evade Windows EDR (run malware in Linux), then pivot back to Windows via interop (execute PowerShell, access `C:\Users` via `/mnt/c`). Detection requires monitoring **both OS boundaries**.

### 4. **EDR Blindness**

Windows EDR typically **cannot see** inside the Linux VM:
- No process enumeration (bash.exe looks like one process to Windows)
- No file access logging (ext4 is opaque)
- No memory inspection (no Windows debugger hooks into the Linux VM)

**WSL-specific challenge:** A malware campaign running entirely inside WSL is **invisible to Windows tooling**. You must image the vhdx and analyze it on Linux.

---

## Forensic Workflow: A Complete WSL Investigation

### Phase 1: Triage (Live Host)

```
1. List all distros (registry scan)
2. Check for unusual BasePaths, DefaultUid, missing PackageFamilyName
3. Check vhdx LastWriteTime (recent = active)
4. Acquire event logs (LxssManager, Hyper-V, process creation)
```

**Key files to collect:**
- `NTUSER.DAT` (per user)
- `%LOCALAPPDATA%\Packages\*\LocalState\ext4.vhdx`
- `.wslconfig` (if present)
- Event logs: System, Security, Applications and Services/Microsoft/Windows/Hyper-V*

### Phase 2: Registry Analysis

```
1. Parse LXSS keys offline (see 03 - Registry Deep-Dive)
2. Check LastWrite times vs incident timeline
3. Correlate with Windows event log for installation/config changes
```

**Key artifacts:**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\{GUID}`
- Flags, DefaultUid, BasePath, State, PackageFamilyName

### Phase 3: VHD Acquisition and Mount

```
1. Image the vhdx (read-only)
2. Mount the ext4 filesystem
3. Verify you're in WSL (kernel banner, /init, environment)
```

**See:** [01 - WSL Artifacts on the Windows Host](<01 - WSL Artifacts on the Windows Host.md>) → Mounting the Distro Offline

### Phase 4: Linux-Side Investigation

```
1. Check /etc/wsl.conf for [boot] command= persistence
2. Inspect shell history (~/.bash_history) for suspicious commands
3. Check for malware binaries, exfil tools, persistence mechanisms
4. Timeline the ext4 filesystem
```

**See:** [02 - Investigating Linux Inside WSL](<02 - Investigating Linux Inside WSL.md>)

### Phase 5: Timeline Correlation

```
1. Build Windows timeline (Prefetch, MFT, event logs)
2. Build Linux timeline (ext4 mtime/ctime)
3. Correlate events across the boundary
4. Identify attack sequence
```

**See:** [Windows → 18 - Timeline Analysis](<../Windows/18 - Timeline Analysis.md>) + [Linux → 13 - Timelining](<../Linux/13 - Timelining.md>)

---

## References and Links

- **Microsoft WSL Documentation:** https://learn.microsoft.com/windows/wsl/
- **WSL Configuration Reference (.wslconfig, wsl.conf):** https://learn.microsoft.com/windows/wsl/wsl-config
- **MITRE ATT&CK T1564.008 (Masquerading via WSL):** https://attack.mitre.org/techniques/T1564/008/
- **SANS DFIR Checklists:** https://www.sans.org/white-papers/
- **Eric Zimmerman Tools (RegRipper, PECmd, etc.):** https://ericzimmerman.github.io/

---

## How This Module Relates to Other Sections

**Windows/** — Use for registry analysis, event log interpretation, process execution timeline, NTFS forensics  
**Linux/** — Use for ext4 analysis, persistence mechanisms, shell history, timelining once the vhdx is mounted  
**Container/** — WSL is not a container, but similar cross-OS challenges apply  
**Cloud/** — Cloud storage accessed from WSL (e.g., AWS CLI inside the distro) may leave artifacts in both places

---

## Module History

- **Initial release (Jul 2024):** 2 foundational notes covering Windows-host and Linux-inside-distro investigation
- **Redesign (Aug 2024):** Refactored to focus on **"what is WSL and how is it different?"** with enhanced cross-referencing, added registry deep-dive (File 3) and hunting/detection (File 4), updated README with scope and navigation

**Status:** Comprehensive coverage of WSL-specific DFIR. For general Windows/Linux forensics, see those sections.
