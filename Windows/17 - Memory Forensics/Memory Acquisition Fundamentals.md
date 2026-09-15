# Memory Acquisition Fundamentals

Memory (RAM) is the highest-priority *capturable* volatile evidence on a live Windows host (note 16's order of volatility places it at position 2, right after CPU/cache state that cannot practically be captured at all). It can hold running malware and injected code that never touches disk, decrypted credentials and encryption keys, live network-connection state, and process context that no disk-based artifact can fully reconstruct after the fact. This note's job is narrow and mechanical: how to *get* memory evidence — from a live RAM capture or from the memory-adjacent files already sitting on disk — and how to do basic recovery (carving) against it when a clean structured image isn't available. What to actually *do* with a clean memory image once acquired (process trees, code injection, hidden processes, rootkits) is the sibling note's job entirely — see **Memory Analysis (Processes, Injection, Rootkits)**.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Why Memory Matters](#why-memory-matters)
- [Memory-Adjacent Files Already on Disk](#memory-adjacent-files-already-on-disk)
  - [pagefile.sys](#pagefilesys)
  - [hiberfil.sys](#hiberfilsys)
  - [swapfile.sys](#swapfilesys)
- [Logical vs Physical Memory Imaging](#logical-vs-physical-memory-imaging)
- [Memory Carving](#memory-carving)
- [Acquisition Tooling](#acquisition-tooling)
- [Red Flags](#red-flags)
- [Tooling Summary](#tooling-summary)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage — no third-party module required. PowerShell has no cmdlet that captures physical RAM itself (that's WinPMEM/Magnet RAM Capture/DumpIt territory, see Acquisition Tooling below); its role here is confirming acquisition preconditions *before* a capture tool runs, and hashing the resulting image *after* it does.

```powershell
# hiberfil.sys and pagefile.sys presence/size at the system-drive root - confirm before assuming either exists
Get-Item 'C:\hiberfil.sys', 'C:\pagefile.sys' -Force -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime

# swapfile.sys presence - Windows 8/8.1+, less consistently documented than the other two
Get-Item 'C:\swapfile.sys' -Force -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime

# Installed RAM - sizes the expected physical image and rules out a capture that's suspiciously smaller than total RAM
Get-CimInstance Win32_ComputerSystem | Select-Object @{N='TotalRAM_GB';E={[math]::Round($_.TotalPhysicalMemory / 1GB, 2)}}

# Free space on the target drive for the dump - a physical capture needs room roughly equal to installed RAM
Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{N='FreeGB';E={[math]::Round($_.Free / 1GB, 2)}}

# BitLocker status on the system volume - affects acquisition strategy, since memory may hold the only recoverable key material
Get-BitLockerVolume -MountPoint C: | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod

# Hash the acquired image for chain of custody - run this against the capture output once acquisition finishes
Get-FileHash -Algorithm SHA256 -Path 'E:\evidence\host01.mem'
```

## Why Memory Matters

A disk image is a record of what a system decided to *write down*. Memory is a record of what a system is *actually doing* — the running process list, injected/fileless code that may never touch disk at all, decrypted credential material, active network sockets, and unlocked encryption keys (BitLocker, VeraCrypt) that exist nowhere else once the volume re-locks. None of that survives a power-off. That's why note 16 places memory capture at step 2 of live response, immediately after establishing scope — before extensive live-command interaction, because every command run afterward risks displacing the very pages under investigation. This note covers how that capture (and its on-disk fallbacks) actually work; the SANS FOR508-level work of interpreting what's inside a captured image belongs to the sibling note.

## Memory-Adjacent Files Already on Disk

Before any live acquisition tool is ever run, three ordinary files that may already sit on a **powered-off disk** hold memory-related content — no kernel driver, no running system, and no live-response window required. This is genuinely valuable evidence independent of (and sometimes containing *more* historical data than) a live RAM capture taken later, because these files can retain fragments from processes and states that no longer exist in current live RAM at all.

| File | What triggers its creation | What it contains | Typical location | Key caveat |
|---|---|---|---|---|
| `pagefile.sys` | Windows' virtual-memory manager paging out RAM pages under memory pressure | Fragments of process memory — including data from processes that have since **exited** | `C:\pagefile.sys` (root of system drive, hidden system file) | Can be disabled entirely or resized down (rare but possible) — check its actual presence/size rather than assume it exists; locked while Windows is running |
| `hiberfil.sys` | System entering hibernation | A **compressed, point-in-time snapshot of physical RAM** at the moment of hibernation | `C:\hiberfil.sys` (root of system drive) | Compressed with Windows' own hibernation-specific format — raw string-searching mostly fails without decompression via a purpose-built parser; may persist after resume in some configurations (hedge — exact clear-on-resume behavior varies by version/config) |
| `swapfile.sys` | Windows 8/8.1+ (hedge on exact version floor) — Store/UWP app memory management | App-specific suspend-to-disk data for Modern/UWP apps, distinct purpose from `pagefile.sys`'s general-purpose paging | `C:\swapfile.sys` (root of system drive) | Narrower and less-documented than the other two — treat exact current relevance/behavior with appropriate hedging |

### pagefile.sys

When physical RAM is under pressure, Windows' memory manager pages out — writes to disk — pages it judges less likely to be needed soon. The forensic payoff is that fragments of process memory, including data belonging to processes that have since terminated, can persist in `pagefile.sys` long after that process is gone from live RAM. A live RAM capture only shows what's resident *right now*; `pagefile.sys` can hold history a live capture never will. It's a fixed-size or system-managed file at the root of the system drive, and Windows locks it while running — reading it requires either an offline/dead-box read (note 02 covers the live-vs-dead-box acquisition tradeoff generally) or a live-imaging tool with the driver-level access needed to read a locked system file.

To understand why `pagefile.sys` might be absent, small, or spread across multiple volumes, check the configured paging policy from the registry rather than just noting the file's current size (see the Hunt Evil block above for the raw presence/size check):

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name PagingFiles -ErrorAction SilentlyContinue
```

### hiberfil.sys

Hibernation writes a full (compressed) snapshot of physical RAM to disk so the system can resume exactly where it left off — which makes `hiberfil.sys` essentially a **point-in-time memory image that's already sitting on disk**, no live capture needed. The critical forensic point: a system that has since resumed from hibernation and continued running can still leave `hiberfil.sys` on disk (Windows doesn't necessarily clear it immediately on resume in every configuration — this varies by version and power-management settings, hedge accordingly), meaning an analyst can sometimes recover a memory snapshot from *before* the system's current live state simply by examining `hiberfil.sys`, even with no live RAM capture available at all. The catch is that the file is compressed using Windows' own hibernation-format compression — raw `strings`/grep against it will mostly come back empty until it's decompressed through a parser that understands the hibernation-file format (see Acquisition Tooling below).

Cross-check the hibernation power setting against actual `hiberfil.sys` presence to detect mismatches that represent Red Flags (enabled with no file, or a file present with hibernation reportedly off):

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction SilentlyContinue
Test-Path 'C:\hiberfil.sys'
```

PowerShell cannot decompress or parse the hibernation-format content itself — no native cmdlet understands it. That parsing task belongs to Volatility or `hibr2bin`-style tooling (see Acquisition Tooling below); PowerShell's role is limited to confirming the file exists and is worth pulling.

### swapfile.sys

A newer addition (Windows 8/8.1 and later — hedge on the exact version floor) used specifically for Windows Store/UWP app memory management, distinct in purpose from `pagefile.sys`'s general-purpose paging role. It's the third member of this file family and worth checking for completeness, but its exact current behavior and forensic yield are less commonly documented than the other two — treat findings here with appropriate caution rather than assuming parity with `pagefile.sys`.

## Logical vs Physical Memory Imaging

| | Physical acquisition | Logical / process-level acquisition |
|---|---|---|
| **Scope** | The raw physical address space of the machine — every byte of installed RAM: kernel memory, unmapped/free pages, and all process address spaces as the OS actually laid them out | One specific process's virtual address space only, as that process sees it |
| **Output** | Flat raw image (`.raw`/`.mem`/`.dmp`-style), or a structured container format — WinPMEM's native output is **AFF4** (Advanced Forensic Format 4); some tools produce a Microsoft crash-dump-style `.dmp` | A smaller, process-scoped memory dump |
| **Speed / footprint** | Slower, larger — captures the full RAM footprint of the machine | Faster, smaller, more targeted |
| **What it misses** | Nothing in principle — full physical layout preserved | Kernel-level context and any other process's memory — everything outside the targeted process |
| **When it's the right call** | Unknown scope, suspected rootkit/kernel-level compromise, unclear which process(es) matter — most IR scenarios default here | Rapid triage of one specific, already-identified suspicious process on a huge-RAM production server where a full physical capture would take too long or be too disruptive |

Most full memory-forensics workflows (Volatility and similar — see the sibling Memory Analysis note) expect a **physical** capture as input, since structural analysis (process lists, injected code, hidden processes) relies on being able to walk kernel data structures that only a physical image preserves.

To decide whether a full physical capture is warranted or a single process's footprint is small/isolated enough for a logical process-scoped dump, check working-set size per process as a triage input:

```powershell
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 20 Name, Id, @{N='WorkingSet_MB';E={[math]::Round($_.WorkingSet64 / 1MB, 2)}}
```

PowerShell has no cmdlet that performs memory acquisition itself, logical or physical — it only informs the decision of which acquisition path to take before reaching for WinPMEM/Magnet RAM Capture/DumpIt (Acquisition Tooling below).

🔴 **Unavoidable caveat, state it plainly rather than gloss over it:** any live memory-acquisition tool itself consumes memory and CPU to run. Its own process, buffers, and any pages it causes to be paged in or out **displace some of the very memory being captured**. This is a well-known, structural limitation of live memory forensics, not a tooling defect — acquire early, with a trusted minimal-footprint tool, and document that the acquisition itself is a live action on the system under investigation (note 16 makes the same point about live-response tooling generally).

## Memory Carving

Not every situation hands an analyst a clean, structurally intact memory image. Raw carved fragments, a corrupted capture, or unallocated disk space that once held paged-out memory content can all still yield meaningful data through **string-search and signature-based carving** — recovering content without needing to parse the OS's own memory data structures at all. This is the fallback technique when a structured image isn't available or isn't fully intact; the sibling **Memory Analysis** note covers the more powerful *structured* alternative (Volatility-style process/injection-aware parsing) for when a clean, parseable image is on hand.

Signature/carving targets worth searching for directly within a raw memory dump, `pagefile.sys`, or `hiberfil.sys` content (once decompressed):

| Signature | Indicates |
|---|---|
| `MZ` / `PE` header | Executable/DLL fragment |
| `PK\x03\x04` | Embedded zip / Office document content |
| `%PDF` | PDF fragment |
| `http://` / `https://` patterns | URL/browsing-activity fragments (see note 14's Private Browsing & Anti-Forensic Recovery note for this technique's application to browser data specifically) |

Tools:

- **`strings`** — generic first-pass raw string extraction against any binary blob, including a memory dump, `pagefile.sys`, or decompressed `hiberfil.sys` content.
- **`bstrings`** (Eric Zimmerman) — a more general binary-string-search tool than the rest of the Zimmerman suite (which is mostly registry/EVTX-focused elsewhere in this module); applicable here for pattern-based searching across raw memory content.
- **PhotoRec / Scalpel**-style generic file carvers — signature-based carving tools normally associated with disk carving apply equally to raw memory dumps or memory-adjacent files, using the same header-signature logic.

When a dedicated carving tool isn't available, `Select-String` serves as a native, if limited, stand-in for `strings` to pull printable-text matches for carving signatures directly out of a raw dump or decompressed `hiberfil.sys` content:

```powershell
Select-String -Path 'E:\evidence\host01.mem' -Pattern 'MZ', 'PK\x03\x04', '%PDF', 'https?://' -AllMatches
```

This approach has genuine limitations compared to purpose-built carving tools — `Select-String` isn't offset-aware for binary signatures the way `bstrings` or PhotoRec are, and it will choke on very large images. Treat it as an emergency fallback for quick triage, not a substitute for dedicated carving tools. Structured, offset-and-context-aware carving of process and injection artifacts inside an already-parsed image belongs to the sibling **Memory Analysis** note.

## Acquisition Tooling

Note 02 names WinPMEM and Magnet RAM Capture at a high level as part of general acquisition strategy. This section goes deeper on the acquisition mechanics specifically.

- **WinPMEM** — open-source, loads a signed kernel driver to access physical memory directly. Native output format is **AFF4**, which is Volatility-compatible (see sibling Memory Analysis note for what happens after acquisition). The kernel driver's presence is itself detectable by security tooling or evasive malware watching for forensic tooling (note 02's live-system caveat).
- **Magnet RAM Capture** — free, GUI-driven, simpler alternative to WinPMEM; also driver-based, straightforward for field triage.
- **FTK Imager** — primarily a disk-imaging tool (established elsewhere in this module), but also has a memory-capture capability, worth naming since it's already part of this module's tool-mapping convention.
- **DumpIt** — a simple, single-click memory-capture tool (Comae/Magnet lineage), name if confident, useful when field simplicity matters more than format flexibility.
- **Decompressing `hiberfil.sys`** — requires a parser that understands the hibernation-file format; Volatility's own hibernation-conversion tooling (or a dedicated `hibr2bin`-style converter) is the general category here — hedge on the exact current tool name/version, confirm against the sibling Memory Analysis note or current Volatility documentation before relying on a specific plugin name.
- **Reading a locked `pagefile.sys`** — via offline/dead-box access (simplest and most reliable), or a live-imaging tool with the driver-level access needed to read a locked system file (note 02's live-vs-dead-box tradeoffs apply directly here).

PowerShell has no native cmdlet for physical RAM acquisition — there is no `Get-PhysicalMemory` or equivalent, which is exactly why WinPMEM, Magnet RAM Capture, FTK Imager, and DumpIt exist as dedicated, driver-backed tools. PowerShell's role is limited to launching and logging the acquisition step, and confirming the acquired output afterward.

To confirm whether a memory-acquisition tool's kernel driver is currently loaded (the same detectability concern mentioned in the prose above):

```powershell
Get-CimInstance Win32_SystemDriver | Where-Object Name -match 'winpmem|pmem'
```

Alternatively, run an external acquisition tool from PowerShell and capture start/end time and exit code as part of the chain-of-custody record. This documents the acquisition step itself and allows you to separate your own tooling from attacker activity (as noted in the Red Flags section):

```powershell
$start = Get-Date
$proc = Start-Process -FilePath 'C:\Tools\winpmem.exe' -ArgumentList '-o E:\evidence\host01.mem' -Wait -PassThru
[PSCustomObject]@{ StartTime = $start; EndTime = Get-Date; ExitCode = $proc.ExitCode }
```

Hash the resulting image using the same `Get-FileHash` command shown in the Hunt Evil block above once acquisition completes.

## Red Flags

| Observation | Why it matters |
|---|---|
| 🔴 `pagefile.sys` unusually small or absent on a system where it should be present | Could indicate a deliberate anti-forensic configuration change — or simply a system-management choice (e.g., large-RAM server tuned to minimize paging). Worth asking why, not an automatic finding. |
| 🔴 `hiberfil.sys` absent on a system with hibernation enabled in its power settings | Worth investigating why — could indicate the file was cleared, hibernation was recently disabled, or the setting doesn't match actual behavior. |
| 🔴 Memory-acquisition tool's own execution evidence (Prefetch/ShimCache/Amcache — note 06) not distinguished from attacker tooling | Your own tools leave traces too — note 16 makes this same point for live-response commands generally; document every acquisition step so it can be separated from adversary activity during analysis. |
| 🔴 Memory capture taken late in the response timeline, after extensive live-command interaction | Less reliable than one taken early — note 16's sequencing places memory capture at step 2, before the volatile tier is disturbed by further live commands. |

## Tooling Summary

| Tool | Purpose |
|---|---|
| **WinPMEM** | Physical RAM capture, AFF4 output, Volatility-compatible |
| **Magnet RAM Capture** | Physical RAM capture, free GUI-driven alternative |
| **FTK Imager** | Disk imaging suite with a memory-capture capability |
| **DumpIt** | Simple single-click memory capture |
| Volatility hibernation-conversion / `hibr2bin`-style tooling | Decompress `hiberfil.sys` into an analyzable format (hedge on exact current tool name) |
| Offline/dead-box read, or driver-level live-imaging access | Read a locked `pagefile.sys` |
| `strings` / `bstrings` (Eric Zimmerman) | Generic string-search carving against raw memory/pagefile/hiberfil content |
| PhotoRec / Scalpel | Signature-based file carving, applies to memory dumps as well as disk |

## Correlate With

| Question | See |
|---|---|
| What's the broader live-vs-dead-box acquisition strategy, and how do WinPMEM/Magnet RAM Capture fit into general evidence acquisition? | **02 - Evidence Acquisition & Imaging** |
| Where does memory capture fall in live-response sequencing, and why capture it early? | **16 - Live Response and Volatile Data** |
| How do I analyze a clean, structured memory image for processes, code injection, or rootkits? | **Memory Analysis (Processes, Injection, Rootkits)** (sibling note) |
| How does pagefile/hiberfil carving apply specifically to recovering private-browsing activity? | **14/Private Browsing & Anti-Forensic Recovery** |
| How do I distinguish my own acquisition tool's execution traces from attacker tooling? | **06 - Evidence of Program Execution** (Prefetch/ShimCache/Amcache) |

## Resources

- SANS FOR500 poster/index — used as a coverage-checklist only for this note's scope (memory acquisition, pagefile/hiberfil/swapfile, logical vs physical imaging, carving); no verbatim reproduction.
- WinPMEM — https://github.com/Velocidex/WinPmem
- Volatility Foundation — https://www.volatilityfoundation.org/ (structured analysis depth belongs to the sibling Memory Analysis note; forward-referenced here)
- Magnet Forensics — DumpIt / RAM Capture product pages, https://www.magnetforensics.com/resources/magnet-ram-capture/
