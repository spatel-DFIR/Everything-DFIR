# Evidence Acquisition & Imaging

Every artifact note that follows this one assumes the evidence is already in hand — a disk image, a memory capture, a triage collection. This note is where that evidence comes from: how an examiner scopes the exam before touching anything, when to pull the plug versus work a live system, and the toolchain (KAPE, Arsenal Image Mounter, WinPMEM, Magnet RAM Capture, the encryption-detection tools) that turns "a suspect machine" into admissible, analyzable evidence. Get this stage wrong and nothing downstream can be trusted — an unplanned reboot destroys memory permanently, and an undetected encrypted volume can make an entire disk image worthless.

> 🔴 Decide **encryption status and live-vs-dead** *before* you touch the box. Both decisions are effectively one-way: reboot or shut down an unencrypted-but-still-running BitLocker/FileVault-style volume and you may never see the plaintext keys in memory again; image a live host without checking for full-disk encryption first and you can burn hours acquiring a disk you can't read.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [The Digital Investigation Plan](#the-digital-investigation-plan)
- [Order of Volatility on Windows](#order-of-volatility-on-windows)
- [Live vs Dead-Box Acquisition](#live-vs-dead-box-acquisition)
- [Decision Flow: Encryption, Live or Dead, What First](#decision-flow-encryption-live-or-dead-what-first)
- [Disk Encryption Detection and Recovery](#disk-encryption-detection-and-recovery)
- [Triage Imaging with KAPE](#triage-imaging-with-kape)
- [Mounting Images with Arsenal Image Mounter](#mounting-images-with-arsenal-image-mounter)
- [Memory Acquisition](#memory-acquisition)
- [Static Memory-Adjacent Sources](#static-memory-adjacent-sources)
- [Chain of Custody for Windows Acquisition](#chain-of-custody-for-windows-acquisition)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for the moments before and during acquisition — no third-party tools, safe to paste into a live session while the DIP/encryption/live-vs-dead call is still being made:

```powershell
# Encryption status on every volume - the single fact the live-vs-dead decision hinges on
Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage

# Every visible volume - scope what acquisition even needs to cover before choosing a method
Get-Volume | Select-Object DriveLetter,FileSystemType,HealthStatus,SizeRemaining

# Physical disk inventory - surfaces offline/hidden disks that need separate handling
Get-Disk | Select-Object Number,FriendlyName,Size,PartitionStyle,IsOffline

# Case-file identification captured in one shot at first contact
Get-ComputerInfo | Select-Object CsName,WindowsProductName,OsVersion,CsSystemBootStatus

# System uptime - how long the box has been running informs the live-vs-dead call
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# Confirm the memory-adjacent files exist before assuming a dead-box exam has nothing to offer
Test-Path C:\hiberfil.sys,C:\pagefile.sys,C:\swapfile.sys

# Hash a collected artifact immediately - chain of custody starts at the moment of acquisition
Get-FileHash -Path <path-to-image-or-export> -Algorithm SHA256

# One-shot volatile process snapshot if a live triage window opens before any shutdown decision
Get-Process | Sort-Object WS -Descending | Select-Object -First 15 Name,Id,WS
```

## The Digital Investigation Plan

Before any tool touches the subject system, a competent exam starts with a **Digital Investigation Plan (DIP)** — a short, written scoping exercise that answers four questions:

| Question | Why it drives acquisition choices |
|----------|-----------------------------------|
| What am I trying to prove or disprove? | Determines whether you need a full bit-for-bit image (litigation, unknown scope) or a fast triage collection (contain-and-scale IR) |
| What is the legal/authorization scope? | Determines which hosts, accounts, and data types you're authorized to touch — acquiring outside scope can taint the whole exam |
| What is the order of volatility for this host? | Determines whether memory/network state must be captured before the disk, or whether the disk is already the only thing left |
| What is the chain-of-custody requirement? | Determines whether you need write-blocked forensic imaging with full documentation, or a lighter enterprise-IR evidence trail is sufficient |

The DIP is not paperwork for its own sake — it is the thing that stops an examiner from making the single most common acquisition mistake: **doing the technically-interesting collection instead of the correct one for the goal.** A criminal case bound for court needs a defensible, write-blocked, hash-verified image with a documented chain of custody. An active-intrusion IR engagement where the priority is "contain and scope" needs speed — a KAPE triage collection and a memory capture, not a three-hour full-disk image while the intruder is still on the network.

**Chain of custody, specifically for Windows acquisition decisions**, means documenting at minimum: who acquired what, from which host (hostname, serial, asset tag), at what time (UTC), using which tool and version, and the hash of every artifact collected. This documentation starts at the DIP stage, not after imaging — note the system's power state, screen state, and any visible encryption prompts *before* you decide your acquisition method, because that observation is itself part of the record and often drives the live-vs-dead decision below.

## Order of Volatility on Windows

Windows has its own order-of-volatility profile, distinct from a Linux host — the working set in RAM, network connection state, and (critically for Windows) any encryption keys unlocked in memory are the most fragile:

1. **RAM** — running processes, network connections, encryption keys for mounted BitLocker/third-party encrypted volumes, injected code, malware that never touches disk.
2. **Network state** — active connections, ARP cache, DNS cache, routing table (captured live, before disconnection or shutdown).
3. **Logged-on sessions** — interactive and RDP sessions, mapped drives, open handles.
4. **Registry hives currently loaded in memory** — some keys (e.g., `HKEY_CURRENT_USER` for a session, in-memory-only registry state) are more current live than what's flushed to the hive file on disk.
5. **Disk** — the least volatile; an unpowered disk is stable indefinitely and can wait, but only after the above are captured if they're needed for the case.

The practical consequence: on a live, in-scope Windows host, memory and network state are captured *before* the acquisition method (live imaging, dead-box shutdown) is even decided, because that decision itself can destroy them.

## Live vs Dead-Box Acquisition

| Factor | Live acquisition | Dead-box (power off, then image) |
|--------|-------------------|-----------------------------------|
| Memory contents | Preserved (captured directly) | **Lost** — RAM is volatile, gone at power-off |
| Encryption keys (BitLocker, VeraCrypt, etc.) unlocked in memory | Recoverable from a memory capture | **Lost** — volume re-locks, keys must come from recovery key/TPM instead |
| Network connections / working set | Visible and capturable | Lost |
| Forensic soundness of the disk image | Lower — live filesystem changes during acquisition (open handles, running processes writing to disk) | Highest — disk is static, no filesystem in flux |
| Anti-forensic/malware detection risk | Higher — a live acquisition tool or its kernel driver can be seen/blocked by the very malware you're chasing, and sophisticated malware can detect and react to memory-imaging attempts | None — the malware is not executing |
| Speed / disruption to the business | Faster, no downtime | Requires downtime; may not be tenable for a production server |
| Best suited for | Active intrusion where memory/session state has evidentiary value, or systems that legitimately cannot go down (domain controllers, servers) | Cases needing maximum forensic soundness (litigation), or where the host is already off / disposable |

There is no universally "correct" choice — it is a DIP-driven tradeoff. A ransomware-affected server mid-encryption or a host suspected of holding a memory-resident implant is a strong case for live acquisition (memory first). A machine already powered off when responders arrive, or a case where defensibility in court outweighs volatile data, is a dead-box case — do not power it on.

🔴 Never power on a system that was found off, and never let a live system reboot "just to see" before capturing memory — both actions destroy volatile evidence that cannot be recreated.

### PowerShell

To confirm the box is actually live and how long it's been up before deciding a live acquisition is even on the table:

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object CSName,LastBootUpTime,LocalDateTime
```

To determine who's logged on right now — information that matters for the live-vs-dead call, since an interactive attacker session is a strong argument to capture memory before anything else:

```powershell
query user 2>$null
Get-CimInstance Win32_LogonSession | Select-Object LogonId,LogonType,StartTime
```

To check boot/logon state across a fleet before triaging which hosts warrant live acquisition versus dead-box handling (full volatile-data collection itself belongs in **Live Response and Volatile Data**, not here):

```powershell
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    Get-CimInstance Win32_OperatingSystem | Select-Object CSName,LastBootUpTime
} | Export-Csv .\uptime-triage.csv -NoTypeInformation
```

## Decision Flow: Encryption, Live or Dead, What First

A compact decision path an examiner can walk through at the scene, before any tool is run:

```
                         ┌─────────────────────────────┐
                         │ System encountered — running │
                         │ or powered off?               │
                         └───────────────┬───────────────┘
                       running ──────────┴────────── powered off
                          │                                │
                          ▼                                ▼
          ┌───────────────────────────┐      ┌───────────────────────────────┐
          │ Check for full-disk        │      │ Check for BitLocker/encrypted  │
          │ encryption (BitLocker      │      │ volume signatures BEFORE       │
          │ prompt, EDD/Encrypted Disk │      │ imaging (EDD, Elcomsoft         │
          │ Hunter, visible TPM/PIN)   │      │ Encrypted Disk Hunter against    │
          └──────────────┬─────────────┘      │ the connected/write-blocked     │
                          │                     │ media)                         │
             encrypted ───┴─── not encrypted    └───────────────┬────────────────┘
                │                    │                    encrypted ┴ not encrypted
                ▼                    ▼                       │              │
   ┌─────────────────────┐  ┌──────────────────┐             ▼              ▼
   │ Capture memory FIRST │  │ Capture memory,   │  ┌────────────────────┐ ┌───────────────┐
   │ (keys live only in   │  │ then triage/full  │  │ Recover key: TPM /  │ │ Standard        │
   │ RAM) — WinPMEM /     │  │ image as scope     │  │ recovery key/AD /   │ │ write-blocked   │
   │ Magnet RAM Capture   │  │ requires           │  │ Passware/EDD, THEN  │ │ image (dd/E01), │
   └──────────┬───────────┘  └──────────────────┘  │ image                │ │ no key needed   │
              │                                     └────────────────────┘ └───────────────┘
              ▼
   ┌─────────────────────────┐
   │ Then triage image (KAPE) │
   │ or full image while the  │
   │ volume is still unlocked │
   └─────────────────────────┘
```

The single fact this flow is built around: **encryption detection must happen before the live-vs-dead decision is finalized**, because an encrypted live system is the one scenario where powering off is nearly always wrong — you may lose the only chance to capture the unlock key from memory.

## Disk Encryption Detection and Recovery

Detecting an encrypted volume and actually recovering its contents are two different problems, and the index/tooling reflects that split:

| Tool | Purpose | Detect or decrypt? |
|------|---------|---------------------|
| **Magnet Forensics Encrypted Disk Detector (EDD)** | Free, fast scan of local/attached volumes for signs of full-disk encryption (BitLocker, PGP, TrueCrypt/VeraCrypt, Safeboot, SafeGuard) | Detect only — flags what needs a decryption workflow |
| **Elcomsoft Encrypted Disk Hunter** | Similar detection-focused tool, scans local and remote/mounted drives for encrypted-container/full-disk-encryption signatures | Detect only |
| **Elcomsoft Disk Decryptor (EDD)** | Decrypts/mounts BitLocker, PGP, and TrueCrypt/VeraCrypt volumes when given the password, recovery key, or an extracted key from a memory image | Decrypt (given key material) |
| **Passware Kit** | Broad password-recovery and decryption suite — attacks passwords for encrypted disks, files, and can pull keys/artifacts from a memory image to unlock BitLocker | Decrypt (recovery/brute-force + memory-assisted) |

Practical acquisition-order implication: run a detection pass (EDD or Elcomsoft Encrypted Disk Hunter) as the very first step against any disk you're about to image — connected via write-blocker for a dead-box exam, or in place for a live triage. If encryption is present, decide immediately whether the decryption key is obtainable (BitLocker recovery key in Active Directory/Entra ID or Microsoft account escrow, TPM-backed auto-unlock, or a key still resident in RAM on a live system) before committing to a dead-box shutdown that could make that key permanently unreachable.

🔴 A BitLocker-protected system found already powered off, with no escrowed recovery key available, may be unrecoverable — this is the scenario the live/dead-box decision flow above exists to prevent: check for encryption while the system is still live and the key may still be in memory.

### PowerShell

To check native BitLocker status without requiring EDD/Elcomsoft for a first-pass check on a live host:

```powershell
Get-BitLockerVolume
```

To narrow to the fields that actually drive the acquisition decision — protection state, how much of the volume is encrypted, and what key protectors exist:

```powershell
Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,
    @{N='KeyProtectors';E={($_.KeyProtector).KeyProtectorType -join ','}}
```

To sweep BitLocker status across multiple hosts before deciding which ones need a live memory-first acquisition, and export the result for the case file:

```powershell
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus,EncryptionPercentage
} | Export-Csv .\bitlocker-triage.csv -NoTypeInformation
```

## Triage Imaging with KAPE

**KAPE (Kroll Artifact Parser and Extractor)**, from Eric Zimmerman/Kroll, is the modern standard for rapid enterprise triage collection — it has largely replaced "always image the whole disk" as first response in IR engagements where speed and scale matter more than forensic completeness of every byte.

KAPE has two collection concepts that are easy to conflate:

| Concept | What it does | Example |
|---------|---------------|---------|
| **Targets** | Define *what to collect* — a curated list of files/paths/registry hives known to hold forensic value (browser artifacts, event logs, registry hives, Prefetch, `$MFT`, etc.) | `!SANS_Triage`, `RegistryHives`, `EventLogs` |
| **Modules** | Define *what to run against what was collected* — post-processing that parses the raw artifacts into readable output, typically invoking other Eric Zimmerman tools | `RECmd`, `MFTECmd`, `PECmd`, `JLECmd` |

Conceptually, an invocation separates source, destination, and the target/module pairing (exact flags vary by KAPE version — treat this as the shape, not a copy-paste command):

```
kape.exe --tsource C: --tdest D:\triage --target !SANS_Triage --mdest D:\triage_processed --module !EZParser
```

Why KAPE over full imaging for enterprise IR: a full disk image of a modern multi-terabyte endpoint can take hours and requires an equally large destination; a KAPE triage pull of the forensically valuable subset (often under a few GB) completes in minutes and can be run against dozens of endpoints in parallel, remotely (via `gkape`'s GUI, PowerShell remoting, or an EDR's live-response console). The tradeoff is coverage — KAPE only collects what its targets define, so if the exam later needs something outside that set (e.g., unallocated space for carving), a full image is still required. Many shops run KAPE triage first for speed and scope, then decide whether a full image is warranted based on what triage reveals.

### PowerShell

To confirm the source volume KAPE is about to target actually exists and has room for the collection before kicking it off:

```powershell
Get-Volume -DriveLetter C | Select-Object DriveLetter,SizeRemaining,Size
```

KAPE itself has no native PowerShell equivalent since it's a curated third-party target/module engine, but PSRemoting is a native way to push it across a fleet without a GUI, complementing rather than replacing it:

```powershell
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    & 'C:\KAPE\kape.exe' --tsource C: --tdest 'D:\triage' --target '!SANS_Triage' `
        --mdest 'D:\triage_processed' --module '!EZParser'
}
```

## Mounting Images with Arsenal Image Mounter

**Arsenal Image Mounter** mounts a forensic disk image (raw/dd, E01, VHD/VHDX, and others) as a real Windows volume or physical disk — the OS sees it as an actual disk, letting native Windows tools and any third-party forensic tool that expects a live filesystem operate directly against the mounted evidence without first extracting files or converting formats.

| Benefit | Why it matters for analysis |
|---------|------------------------------|
| Mounts as a complete disk, not just a volume | Tools that need low-level disk structures (partition tables, unallocated space) work correctly, not just file-level tools |
| Read-only / write-cache modes | Evidence integrity preserved — writes go to a cache file, never back to the source image |
| Native OS + third-party tool compatibility | Any Windows-native tool (Explorer, `MFTECmd`, indexing tools, even AV/EDR scanners) can run against the image directly, no separate extraction step |
| Supports common evidence formats | Raw/dd, EnCase E01/Ex01, VHD/VHDX, and virtual machine disk formats without conversion |

This is fundamentally different from **write-blocked physical acquisition**, which is the *acquisition* step — connecting the original physical media through a hardware write-blocker to create the image in the first place, guaranteeing the source is never altered during imaging. Arsenal Image Mounter operates entirely *after* that image already exists; it never touches original evidence, only the image file, and its own read-only/write-cache behavior is what keeps the image itself unaltered during analysis. Think of write-blocking as protecting the source during acquisition, and Arsenal Image Mounter as protecting the image during analysis.

### PowerShell

Once Arsenal Image Mounter attaches an image, it appears as an ordinary disk/volume — confirm it mounted read-only before pointing any tool at it:

```powershell
Get-Disk | Select-Object Number,FriendlyName,OperationalStatus,IsReadOnly
Get-Volume | Select-Object DriveLetter,FileSystemType,DriveType,HealthStatus
```

## Memory Acquisition

Memory capture matters because it holds the evidence disk imaging fundamentally cannot: running process state, network connections, in-memory-only malware, and — critical to the encryption decision above — encryption keys for any volume currently unlocked.

| Tool | Capture type | Notes |
|------|---------------|-------|
| **WinPMEM** | Physical memory acquisition (raw dump of physical RAM via a kernel driver) | Open-source, loads a signed kernel driver to access physical memory directly — the driver's presence is itself detectable by security tooling or evasive malware watching for it |
| **Magnet RAM Capture** | Physical memory acquisition | Free GUI/CLI tool from Magnet Forensics, similarly driver-based, straightforward for triage use in the field |

**Physical vs logical acquisition**: a *physical* memory acquisition captures the raw contents of RAM as the hardware sees it — every byte, including data not currently mapped to any live process, which is what allows recovery of terminated-process remnants and unallocated memory pages. A *logical* acquisition only captures the memory mapped into a specific process's address space (or a specific structure), which is faster and smaller but misses everything outside that scope — most full memory-forensics workflows (subsequent analysis via Volatility, MemProcFS, AXIOM) expect a physical capture.

🔴 **Live-system caveat**: any memory-acquisition tool running on a live host is itself running code on a potentially compromised system — its kernel driver can be blocked, subverted, or used as a detection trigger by sophisticated malware watching for forensic tooling, and the act of acquiring memory necessarily perturbs the very memory being captured (new pages allocated for the tool's own execution). Acquire memory as early and as cleanly as possible, with a trusted, minimal-footprint tool, and document that the acquisition itself is a live action on the system under investigation.

The actual parsing/analysis of a captured memory image (process trees, injected code, hidden processes, rootkit detection) is out of scope for this note — see the forward reference to **Memory Forensics** in Correlate With below; tools named here for that later stage include AXIOM, Volatility, and MemProcFS.

## Static Memory-Adjacent Sources

Not every memory-adjacent artifact requires a live acquisition tool at all — three files on a **powered-off disk** hold memory-related data an examiner can pull during a purely dead-box exam:

| File | What it holds |
|------|----------------|
| `hiberfil.sys` | A compressed snapshot of RAM taken at hibernation — effectively a point-in-time memory image sitting on disk, parseable with the same memory-forensics tooling used for a live capture (after decompression) |
| `pagefile.sys` | Pages swapped out of physical RAM under memory pressure — fragments of process memory, strings, sometimes credential material, recoverable even though it's not a complete memory image |
| `swapfile.sys` | Windows 8+ addition, used specifically for Modern/UWP app suspend-to-disk data — a narrower but sometimes overlooked source of app-specific in-memory state |

These three matter precisely because they require **no live acquisition tool, no kernel driver, and no running system** — they are ordinary files recoverable from a standard dead-box disk image, which makes them the fallback source of memory-adjacent evidence when live acquisition was never possible (system found already off, or acquired dead-box for forensic-soundness reasons).

### PowerShell

To confirm which of the three files actually exist and get their sizes before assuming any of them are available — keeping in mind that `swapfile.sys` is Windows 8+ only and any of the three can be disabled by configuration:

```powershell
Get-Item C:\hiberfil.sys,C:\pagefile.sys,C:\swapfile.sys -Force -ErrorAction SilentlyContinue |
    Select-Object Name,Length,LastWriteTime
```

A zero-byte or missing `hiberfil.sys` means hibernation is disabled and this source is off the table for this exam. Rather than assuming from file presence alone, check the setting directly:

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction SilentlyContinue).HibernateEnabled
```

## Chain of Custody for Windows Acquisition

Applying the general chain-of-custody principle specifically to the acquisition decisions above:

- Document the system's power state and any visible encryption prompt **at first contact**, before any acquisition method is chosen — this observation directly justifies the live-vs-dead decision later.
- Record which tool (and version) performed each acquisition step — WinPMEM/Magnet RAM Capture for memory, KAPE for triage, `dd`/E01 imaging tool for a full disk — and the hash of each output.
- If a live acquisition tool's kernel driver load could plausibly be detected by the malware under investigation, note that risk explicitly in the record — it affects how the resulting evidence (and any subsequent attacker reaction) should be interpreted.
- For encrypted volumes, document exactly how the decryption key was obtained (AD/Entra ID escrow, TPM auto-unlock, memory extraction, Passware/EDD recovery) — this is as evidentially significant as the acquisition itself.

### PowerShell

To capture the host-identification fields the chain-of-custody record needs in one command at first contact:

```powershell
Get-ComputerInfo | Select-Object CsName,WindowsProductName,OsVersion,TimeZone
(Get-CimInstance Win32_BIOS).SerialNumber
```

To hash every collected artifact and assemble a manifest for the case file, rather than hashing files one at a time by hand:

```powershell
Get-ChildItem D:\triage -Recurse -File |
    Get-FileHash -Algorithm SHA256 |
    Select-Object Path,Hash |
    Export-Csv D:\triage_processed\acquisition-manifest.csv -NoTypeInformation
```

## Getting Max Value

- **Run the DIP before touching the system** — it decides whether the case needs a full forensic image or a fast KAPE triage, and that decision should never be made reflexively.
- **Check for encryption before deciding live vs dead-box** — an encrypted live system is the strongest argument for capturing memory before any shutdown.
- **KAPE targets vs modules is the whole model** — targets collect, modules process; most enterprise IR triage now runs this way instead of full imaging.
- **Arsenal Image Mounter turns an image into a native disk** — use it to run any Windows-native or third-party tool directly against evidence without extraction.
- **`hiberfil.sys`/`pagefile.sys`/`swapfile.sys` are free memory evidence on a dead disk** — always pull them even when no live memory capture was possible.
- **Physical memory acquisition, not logical, is what full memory-forensics tooling expects** — confirm WinPMEM/Magnet RAM Capture ran in physical mode.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| What NTFS structures does a mounted/imaged disk actually contain? | **NTFS/00 - NTFS Deep Dive Overview** |
| What volatile data should be captured live, beyond memory? | **Live Response and Volatile Data** |
| How do I analyze a captured memory image for processes/injection/rootkits? | **Memory Forensics** |
| Where do BitLocker/user artifacts live once the disk is mounted? | **Registry Forensics Fundamentals**, **Users, Groups & Authentication** |
| How does this compare to cloud-hosted evidence acquisition? | `Cloud/` — EC2/Azure VM snapshot-based acquisition notes |

## Scenarios

- **Live server, suspected active intrusion, BitLocker-protected:** capture memory first (WinPMEM), extract the key if needed, then KAPE triage — do not shut down.
- **Workstation found already powered off, litigation case:** write-blocked full image (`dd`/E01); run Encrypted Disk Hunter/EDD against the connected drive before committing to imaging.
- **Fleet-wide IR engagement, dozens of endpoints:** KAPE triage (targets + modules) pushed remotely, full imaging reserved only for the hosts triage flags as central to the intrusion.
- **Analyst needs to run Autopsy/FTK against an E01 without extracting files:** mount the E01 with Arsenal Image Mounter and point the tool at the mounted volume directly.
- **No live acquisition was possible, memory-adjacent evidence still needed:** pull `hiberfil.sys`/`pagefile.sys`/`swapfile.sys` from the dead-box image instead.

## Red Flags

| Finding | Why it matters |
|---------|-----------------|
| System powered off with BitLocker and no escrowed recovery key | Decryption key may be permanently unreachable |
| Memory acquisition skipped on a live, encrypted, still-running system | Lost the only chance to recover the unlock key from RAM |
| Full disk image attempted before an encryption-detection pass | Hours spent imaging a volume that may be unreadable without a key |
| KAPE targets chosen without considering the DIP's actual scope | Triage collection misses the artifact the case actually needs |
| Evidence written back to the subject's own disk during acquisition | Overwrites unallocated space, spoliation risk |
| No documented chain of custody for how an encryption key was obtained | Undermines evidentiary weight of the decrypted contents |
| Live memory-acquisition tool's kernel driver load unnoted in the record | Missed opportunity to assess anti-forensic/detection risk to the investigation |

## Resources

- KAPE (Kroll Artifact Parser and Extractor) and the Eric Zimmerman tool suite — https://www.kroll.com/kape
- Arsenal Image Mounter — https://arsenalrecon.com/products/arsenal-image-mounter
- WinPMEM — https://github.com/Velocidex/WinPmem
- Magnet RAM Capture — https://www.magnetforensics.com/resources/magnet-ram-capture/
- Magnet Forensics Encrypted Disk Detector — https://www.magnetforensics.com/resources/encrypted-disk-detector/
- Elcomsoft Encrypted Disk Hunter / Elcomsoft Disk Decryptor — https://www.elcomsoft.com
- Passware Kit Forensic — https://www.passware.com
- MITRE ATT&CK: T1486 (Data Encrypted for Impact), T1027 (Obfuscated Files or Information — anti-forensic tooling detection), T1070 (Indicator Removal)
