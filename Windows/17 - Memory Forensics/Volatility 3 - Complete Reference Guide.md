# Volatility 3 - Complete Reference Guide

A comprehensive, command-by-command reference for Volatility 3 memory forensics. All examples use actual Volatility 3 syntax and plugin names; this is the operational reference for real engagements, not version-agnostic hedging.

## Contents

- [Installation & Setup](#installation--setup)
- [Plugin Discovery & Info](#plugin-discovery--info)
- [Process Analysis Plugins](#process-analysis-plugins)
  - [pslist — Process List (Linked List Walk)](#pslist--process-list-linked-list-walk)
  - [psscan — Process Scan (Pool Signature Scan)](#psscan--process-scan-pool-signature-scan)
  - [pstree — Process Tree (Parent/Child Reconstruction)](#pstree--process-tree-parentchild-reconstruction)
  - [psxview — Process Cross-View (List Discrepancies)](#psxview--process-cross-view-list-discrepancies)
- [Memory & Injection Detection](#memory--injection-detection)
  - [malfind — Injected Code Detection](#malfind--injected-code-detection)
  - [hollowfind — Process Hollowing Detection](#hollowfind--process-hollowing-detection)
  - [modscan — Module Scan (DLL Enumeration)](#modscan--module-scan-dll-enumeration)
- [Network Analysis](#network-analysis)
  - [netscan — Network Connections & Listeners](#netscan--network-connections--listeners)
  - [sockets — Socket Objects](#sockets--socket-objects)
- [Thread & Handle Analysis](#thread--handle-analysis)
  - [threads — Thread Enumeration](#threads--thread-enumeration)
  - [handles — Handle Enumeration](#handles--handle-enumeration)
- [Driver & Rootkit Detection](#driver--rootkit-detection)
  - [driverscan — Driver Enumeration](#driverscan--driver-enumeration)
  - [ssdt — System Service Descriptor Table](#ssdt--system-service-descriptor-table)
- [Registry Analysis](#registry-analysis)
  - [hivelist — Registry Hive Enumeration](#hivelist--registry-hive-enumeration)
  - [printkey — Registry Key Reading](#printkey--registry-key-reading)
- [String Searching & Signatures](#string-searching--signatures)
  - [strings — String Extraction](#strings--string-extraction)
  - [yarascan — YARA Rule Scanning](#yarascan--yara-rule-scanning)
- [Memory Dump & Extraction](#memory-dump--extraction)
  - [memdump — Process Memory Extraction](#memdump--process-memory-extraction)
  - [dlllist — DLL Enumeration (Per-Process)](#dlllist--dll-enumeration-per-process)
- [Common Workflows](#common-workflows)
- [Output Interpretation](#output-interpretation)
- [Troubleshooting](#troubleshooting)

---

## Installation & Setup

### Linux / macOS

```bash
# Install via pip
pip3 install volatility3

# Verify installation
vol -h

# Check version
vol --version
```

### Windows

```batch
REM Install via pip
pip install volatility3

REM Or download pre-built binary from Volatility Foundation
REM https://downloads.volatilityfoundation.org/

REM Verify installation
vol -h
```

### Syntax Overview

**Basic invocation:**
```bash
vol -f <memory_image> -p <plugin_name> [options]
```

**Common flags:**
- `-f` or `--file` — Path to memory image (required)
- `-p` or `--plugin` — Plugin to run (optional; `vol plugins list` to enumerate)
- `-o` or `--output` — Output format (text, json, csv)
- `--dump-dir` — Directory for extracted files (used by plugins like `memdump`)
- `-v` or `--verbose` — Increased output verbosity
- `-r` or `--renderer` — Output renderer (usually `text` or `json`)

**Example basic run:**
```bash
vol -f memory.dmp windows.pslist
```

---

## Plugin Discovery & Info

### List All Available Plugins

```bash
vol plugins list
```

**Output example:**
```
Plugin                                        Providers                                          
windows.cmdline                               x86 (Intel), x64 (Intel)                           
windows.dlllist                               x86 (Intel), x64 (Intel)                           
windows.driverscan                            x86 (Intel), x64 (Intel)                           
windows.filescan                              x86 (Intel), x64 (Intel)                           
windows.handles                               x86 (Intel), x64 (Intel)                           
windows.hollowfind                            x86 (Intel), x64 (Intel)                           
windows.malfind                               x86 (Intel), x64 (Intel)                           
windows.netscan                               x86 (Intel), x64 (Intel)                           
windows.pslist                                x86 (Intel), x64 (Intel)                           
windows.psscan                                x86 (Intel), x64 (Intel)                           
windows.pstree                                x86 (Intel), x64 (Intel)                           
windows.psxview                               x86 (Intel), x64 (Intel)                           
windows.registry.printkey                     x86 (Intel), x64 (Intel)                           
windows.sockets                               x86 (Intel), x64 (Intel)                           
windows.strings                               x86 (Intel), x64 (Intel)                           
windows.threads                               x86 (Intel), x64 (Intel)                           
windows.yarascan                              x86 (Intel), x64 (Intel)                           
[... many more ...]
```

### Get Plugin Help

```bash
vol -f memory.dmp -p windows.pslist -h
```

This shows the plugin's specific options and usage. Most plugins have no additional options; process-filtering plugins (like `pslist`) often accept optional PID or name filters.

---

## Process Analysis Plugins

### pslist — Process List (Linked List Walk)

**What it does:** Walks the Windows kernel's EPROCESS linked list — the same structure `tasklist`, Task Manager, and `Get-Process` walk. Fast, but **blind to DKOM-hidden processes**.

**Syntax:**
```bash
vol -f memory.dmp windows.pslist
```

**Optional filters:**
```bash
# Filter by PID
vol -f memory.dmp windows.pslist --pid 1234

# Filter by process name
vol -f memory.dmp windows.pslist -n svchost.exe

# Verbose (shows all threads/handles per process)
vol -f memory.dmp windows.pslist -v
```

**Output example:**
```
PID     PPID    ImageFileName   Offset(V)       Offset(P)       CreateTime                      ExitTime        
4       0       System          0xd64002d0      0x2d0   2024-01-15 08:23:14.000000  
612     4       smss.exe        0xd64ab930      0xab930 2024-01-15 08:23:14.000000  
848     612     csrss.exe       0xd6478640      0x478640        2024-01-15 08:23:14.000000  
864     612     wininit.exe     0xd647cb30      0x47cb30        2024-01-15 08:23:14.000000  
916     864     services.exe    0xd64815f0      0x815f0 2024-01-15 08:23:14.000000  
932     864     lsass.exe       0xd6483610      0x83610 2024-01-15 08:23:15.000000  
1284    916     svchost.exe     0xd64a2720      0xa2720 2024-01-15 08:23:16.000000  
2154    1284    rundll32.exe    0xd6511a30      0x511a30        2024-01-15 08:26:45.000000
```

**Key columns:**
- **PID** — Process ID
- **PPID** — Parent PID (compare against known process trees from note 01)
- **ImageFileName** — Process name
- **Offset(V) / Offset(P)** — Virtual and physical memory addresses of the EPROCESS structure
- **CreateTime / ExitTime** — Process start/exit timestamps

**Interpretation:**
- If a process shows in `pslist` but has an unexpected parent (e.g., `notepad.exe` spawned by `System` instead of `explorer.exe`), that's a red flag for PPID spoofing or process tree manipulation.
- Any process spawned from `lsass.exe` is a high-confidence credential-access indicator (see Credential Theft section).

---

### psscan — Process Scan (Pool Signature Scan)

**What it does:** Pool-scans the raw memory image for EPROCESS structure signatures, independent of linked-list membership. Finds linked processes (like `pslist`), unlinked/DKOM-hidden processes, and recently-terminated processes still resident in memory.

**Syntax:**
```bash
vol -f memory.dmp windows.psscan
```

**Optional filters (same as pslist):**
```bash
vol -f memory.dmp windows.psscan --pid 1234
vol -f memory.dmp windows.psscan -n malware.exe
```

**Output example:**
```
PID     PPID    ImageFileName   Offset(V)       Offset(P)       CreateTime                      ExitTime        
4       0       System          0xd64002d0      0x2d0   2024-01-15 08:23:14.000000  
612     4       smss.exe        0xd64ab930      0xab930 2024-01-15 08:23:14.000000  
848     612     csrss.exe       0xd6478640      0x478640        2024-01-15 08:23:14.000000  
864     612     wininit.exe     0xd647cb30      0x47cb30        2024-01-15 08:23:14.000000  
916     864     services.exe    0xd64815f0      0x815f0 2024-01-15 08:23:14.000000  
932     864     lsass.exe       0xd6483610      0x83610 2024-01-15 08:23:15.000000  
1284    916     svchost.exe     0xd64a2720      0xa2720 2024-01-15 08:23:16.000000  
5821    1284    rundll32.exe    0xd6651c40      0x651c40        2024-01-15 08:32:12.000000     2024-01-15 08:35:08.000000
8456    892     hidden_malware  0xd67a3e50      0x7a3e50        2024-01-15 08:30:22.000000  
```

**Key difference from `pslist`:**
- Includes processes not in the linked list (row with `hidden_malware` in this example)
- Includes exited processes with non-zero `ExitTime` (like `rundll32.exe` above)

**Critical interpretation:**
- **Process in `psscan` but NOT in `pslist`** = **DKOM or rootkit hiding**. This is near-definitive evidence of process-list unlinking.
- **Process with non-zero `ExitTime` in `psscan`** = terminated process; corroborate its context before treating it as active malware.

**Comparison workflow:**
```bash
# Save both to files for easy comparison
vol -f memory.dmp windows.pslist > pslist.txt
vol -f memory.dmp windows.psscan > psscan.txt

# Find PIDs in psscan but not in pslist (manual or via diff/grep)
grep -oP "^(\d+)" psscan.txt | sort | uniq > psscan_pids.txt
grep -oP "^(\d+)" pslist.txt | sort | uniq > pslist_pids.txt
comm -23 psscan_pids.txt pslist_pids.txt  # PIDs in psscan only
```

---

### pstree — Process Tree (Parent/Child Reconstruction)

**What it does:** Walks the EPROCESS linked list (same as `pslist`) but renders parent/child relationships as a tree, making process lineage immediately visible.

**Syntax:**
```bash
vol -f memory.dmp windows.pstree
```

**Output example:**
```
4       System  
 | 612  smss.exe
 |  | 848  csrss.exe
 |  | 864  wininit.exe
 |  |  | 916  services.exe
 |  |  | 932  lsass.exe
 |  |  | 1056 fontdrvhost.exe
 | 1284 svchost.exe
 |  | 2154 rundll32.exe
 | 1456 svchost.exe
 | 2012 explorer.exe
 |  | 3344 chrome.exe
 |  | 3788 chrome.exe
 |  | 4156 notepad.exe
 | 5892 powershell.exe
 |  | 6120 cmd.exe
 |  |  | 6344 whoami.exe
```

**Interpretation:**
- Compare this tree structure against note 01's "normal process tree" baseline.
- Look for:
  - Processes spawned from `lsass.exe` (credential access indicators)
  - Unusual parents (e.g., `calc.exe` spawning `powershell.exe`, or `System` spawning user-mode executables)
  - Children of unexpected parents (e.g., `svchost.exe` spawning an arbitrary .exe)

---

### psxview — Process Cross-View (List Discrepancies)

**What it does:** Compares process discovery across multiple methods (linked list, pool scan, various kernel handles) in a single view, highlighting discrepancies.

**Syntax:**
```bash
vol -f memory.dmp windows.psxview
```

**Output example:**
```
PID     PPID    ImageFileName   pslist  psscan  thrdproc        pspcid  csrss   session 
4       0       System          True    True    True    True    True    True
612     4       smss.exe        True    True    True    True    True    True
848     612     csrss.exe       True    True    True    True    True    True
932     864     lsass.exe       True    True    True    True    True    True
1284    916     svchost.exe     True    True    True    True    True    True
8456    892     hidden_malware  False   True    False   False   False   False
```

**Critical interpretation:**
- **False in pslist column, True in psscan column** = **DKOM or rootkit hiding** (process unlinked from kernel list)
- **False in thrdproc** = Process has no active threads (likely terminated)
- **False in csrss** = Process is not registered with the session manager (rootkit indicator)

This is the highest-level summary for detecting hidden processes without having to manually diff `pslist` and `psscan`.

---

## Memory & Injection Detection

### malfind — Injected Code Detection

**What it does:** Scans every process's memory regions for suspicious patterns:
1. Regions marked `PAGE_EXECUTE_READWRITE` (RWX) — writable and executable simultaneously
2. PE headers (MZ signature) in unbacked memory
3. Executable regions with mismatched protections

**Syntax:**
```bash
# Scan all processes
vol -f memory.dmp windows.malfind

# Scan specific process by PID
vol -f memory.dmp windows.malfind --pid 2154

# Scan by process name
vol -f memory.dmp windows.malfind -n rundll32.exe

# Dump suspicious regions to disk
vol -f memory.dmp windows.malfind --dump-dir ./extracted/
```

**Output example:**
```
PID     Process ImageFileName   Start VAddr       End VAddr       VSize   Tag     Protect Commit  Type
2154    rundll32.exe    0x390000        0x3a0000        0x10000 VadS    PAGE_EXECUTE_READWRITE  0x10000 MemPrivate
        0x390000        50 4d 5a 90 00 03 00 00 04 00 00 00 0f 00 00 00  PZ........

2154    rundll32.exe    0x3a0000        0x3b5000        0x15000 VadS    PAGE_EXECUTE_READWRITE  0x15000 MemPrivate

3344    chrome.exe      0x70000000      0x701c0000      0x1c0000        VadS    PAGE_EXECUTE_READWRITE  0x1c0000 MemPrivate
        0x70000000      4a 49 54 00 15 00 00 00 84 3c 00 00 4c 00 00 00  JIT....

4156    notepad.exe     0x140000000     0x14000d000     0xd000  VadS    PAGE_READWRITE  0xd000 MemPrivate
        (No RWX in this process; considered clean)
```

**Interpretation:**
- **RWX regions are the smoking gun for injection** — legitimate code is almost never simultaneously writable and executable.
- **PE header in unbacked memory** — malicious binary manually mapped/hollowed.
- **Not all RWX is malicious** — JIT compilers (JavaScript engines, .NET JIT) legitimately use RWX; `chrome.exe` and `dotnet.exe` naturally show RWX regions. Context and process name matter.

**Follow-up actions:**
- Dump the region and analyze with a disassembler
- Check if the parent process is expected to have JIT code (browsers, VMs, .NET runtime)
- Correlate with network/file activity from that process

---

### hollowfind — Process Hollowing Detection

**What it does:** Detects process hollowing by comparing in-memory PE image against the on-disk executable. Looks for:
1. Mismatched PE headers between memory and disk
2. Memory regions with permissions inconsistent with a normal image
3. Unmapped sections or reallocated memory

**Syntax:**
```bash
# Scan all processes
vol -f memory.dmp windows.hollowfind

# Scan specific PID
vol -f memory.dmp windows.hollowfind --pid 2154

# Dump hollowed regions
vol -f memory.dmp windows.hollowfind --dump-dir ./extracted/
```

**Output example:**
```
PID     Process ImageFileName   Address        Protection      Reason
2154    rundll32.exe    0x400000        PAGE_READWRITE  Unmapped section (expected PAGE_READONLY)
        Expected disk image at C:\Windows\System32\rundll32.exe does not match memory image

5892    powershell.exe  0x140000000     PAGE_EXECUTE_READWRITE  Reallocated memory region (original page freed)
        Memory page overwritten with non-PE content
```

**Interpretation:**
- **Unmapped or mismatched sections** = **Hollowing confirmed** — the on-disk executable and in-memory image don't match
- **Reallocated region** = Original memory has been freed and reused; memory dump is less conclusive (process may have legitimately freed sections)

---

### modscan — Module Scan (DLL Enumeration)

**What it does:** Pool-scans for loaded DLL structures (LDR_DATA_TABLE_ENTRY) independent of the process's module-list walk. Finds:
1. DLLs loaded through normal `LoadLibrary` (like `dlllist`)
2. DLLs unlinked from the process's module list (rootkit indicator)
3. Recently-unloaded DLLs still resident in memory

**Syntax:**
```bash
# Scan all modules in all processes
vol -f memory.dmp windows.modscan

# Filter by DLL name
vol -f memory.dmp windows.modscan -n malicious.dll

# Verbose output
vol -f memory.dmp windows.modscan -v
```

**Output example:**
```
Offset(V)       ImageFileName   ModuleName      Base    Size    Path
0xd6511a30      rundll32.exe    ntdll.dll       0x77dc0000      0x1a0000 C:\Windows\System32\ntdll.dll
0xd6511a48      rundll32.exe    kernel32.dll    0x75b00000      0x190000 C:\Windows\System32\kernel32.dll
0xd6511a60      rundll32.exe    malicious.dll   0x10000000      0x50000 C:\Users\admin\AppData\Local\malicious.dll
```

---

## Network Analysis

### netscan — Network Connections & Listeners

**What it does:** Scans for network connection objects (`_TCP_ENDPOINT` structures) in memory, regardless of whether the connection is still active or visible in a live `netstat`. Shows:
1. Established TCP connections
2. Listening ports
3. UDP connections
4. Connections that were open but are now closed (still resident in memory)

**Syntax:**
```bash
# All connections
vol -f memory.dmp windows.netscan

# Specific PID
vol -f memory.dmp windows.netscan --pid 2154

# Export to CSV for easier analysis
vol -f memory.dmp windows.netscan -r csv > connections.csv
```

**Output example:**
```
Offset(V)       Proto   LocalAddr       LocalPort       RemoteAddr      RemotePort      State   PID     Owner
0xd6511a30      TCPv4   192.168.1.50    53421   45.33.32.156    443     ESTABLISHED     2154    rundll32.exe
0xd6511a48      TCPv4   192.168.1.50    53422   10.0.0.5        8888    ESTABLISHED     5892    powershell.exe
0xd6511a60      TCPv4   192.168.1.50    53423   192.0.2.100     4444    TIME_WAIT       3344    explorer.exe
0xd6511a78      TCPv4   192.168.1.50    445     0.0.0.0 0       LISTEN  916     services.exe
0xd6511a90      UDPv4   192.168.1.50    53      0.0.0.0 0       (UDP state)     932     lsass.exe
```

**Interpretation:**
- **Unexpected listening ports** — Services listening on non-standard ports (8888, 4444) often indicate backdoors or C2 listeners
- **Remote connections from unexpected processes** — `explorer.exe` making direct TCP connections to external IPs is suspicious
- **TIME_WAIT connections** — Connections already closed but still in memory; corroborate with network artifacts (note 19)
- **Mismatch with live `netstat`** — Connection visible in `netscan` but not in a live netstat means the connection was hidden (rootkit or process termination)

---

### sockets — Socket Objects

**What it does:** Enumerates socket structures directly (lower-level than `netscan`), useful for detecting raw sockets and non-standard protocols.

**Syntax:**
```bash
vol -f memory.dmp windows.sockets
```

---

## Thread & Handle Analysis

### threads — Thread Enumeration

**What it does:** Lists all threads across all processes, including:
1. Thread ID (TID)
2. Entry point (where the thread will/did execute)
3. Thread state (Running, Waiting, etc.)
4. Owning process

**Syntax:**
```bash
# All threads
vol -f memory.dmp windows.threads

# Specific process
vol -f memory.dmp windows.threads --pid 2154

# Show only running threads
vol -f memory.dmp windows.threads | grep Running
```

**Output example:**
```
PID     PPID    ImageFileName   TID     Offset(V)       State   CreateTime                      ExitTime
2154    1284    rundll32.exe    5124    0xd6511a30      Terminated      2024-01-15 08:26:45.000000 2024-01-15 08:27:12.000000
2154    1284    rundll32.exe    5128    0xd6511a48      Running 2024-01-15 08:26:46.000000
2154    1284    rundll32.exe    5132    0xd6511a60      Waiting 2024-01-15 08:26:47.000000
```

**Interpretation:**
- **Terminated threads in `psscan`-only processes** — Process was hidden but was actually running active threads
- **Mismatch between thread count in `pslist` and actual thread count** — Rootkit hiding threads

---

### handles — Handle Enumeration

**What it does:** Lists all open handles per process, including:
1. Handle type (File, Key, Mutant, Event, etc.)
2. Handle object address
3. Access rights
4. Object name

**Syntax:**
```bash
# All handles in all processes
vol -f memory.dmp windows.handles

# Specific process
vol -f memory.dmp windows.handles --pid 932

# Filter by handle type
vol -f memory.dmp windows.handles | grep lsass
```

**Output example (focusing on lsass.exe):**
```
PID     Process ImageFileName   Handle  Offset(V)       Type    Name/Details
932     lsass.exe       0x10    0xd6483610      Process System
932     lsass.exe       0x14    0xd6483628      File    C:\Windows\Prefetch\LSASS.EXE-XXXX.pf
932     lsass.exe       0x18    0xd6483640      Section \BaseNamedObjects\LSASS_CACHE_READ
2154    rundll32.exe    0x1c    0xd6511a30      Process (Handle to lsass.exe) [ACCESS: PROCESS_ALL_ACCESS]
```

**Critical finding:**
- **Handle from unexpected process (2154) to lsass.exe** = Credential access attempt. Corroborate with Sysmon Event ID 10 (ProcessAccess) if available.

---

## Driver & Rootkit Detection

### driverscan — Driver Enumeration

**What it does:** Pool-scans for loaded kernel drivers (`_DRIVER_OBJECT` structures), independent of the driver list. Shows:
1. Driver name
2. Driver object address
3. Driver entry point
4. Service name

**Syntax:**
```bash
# All drivers
vol -f memory.dmp windows.driverscan

# Dump driver files
vol -f memory.dmp windows.driverscan --dump-dir ./drivers/
```

**Output example:**
```
Offset(V)       DriverName      DriverObject Address       EntryPoint      ServiceName
0xd6511a30      \Driver\PNP_TL D 0xd64a2720      0x835f0 PNPTlDriver
0xd6511a48      \Driver\Disk    0xd64a2738      0x836a0 Disk
0xd6511a60      \Driver\atapi   0xd64a2750      0x83700 atapi
0xd6511a78      \Driver\SUSPICIOUS_DRV       0xd64a2768      0x500000 UNKNOWN_SERVICE
```

**Interpretation:**
- **Unknown driver names** — Drivers with randomized or suspicious names
- **Unsigned drivers** — Cross-reference against the system's known-good driver list
- **Drivers pointing to unusual entry points** — Entry point outside expected kernel memory ranges

**Follow-up:**
```bash
# Check driver signing status (on live system or via cross-reference)
vol -f memory.dmp windows.driverirp
```

---

### ssdt — System Service Descriptor Table

**What it does:** Dumps the SSDT (the kernel's system-call dispatch table) and checks for hooks. A rootkit might patch SSDT entries to intercept system calls (e.g., `NtOpen File` redirected to rootkit code).

**Syntax:**
```bash
vol -f memory.dmp windows.ssdt
```

**Output example:**
```
Index   Address(V)      Address(P)      Name    Hooked?
0       0x835a2f00      0x5a2f00        NtCreateFile    False
1       0x835a2f04      0x5a2f04        NtOpenFile      True (Rootkit: 0xaaaabbbb)
2       0x835a2f08      0x5a2f08        NtReadFile      False
```

**Interpretation:**
- **Hooked entries** — System calls intercepted by rootkit code; this is the kernel-level equivalent of DLL injection
- **Verify against known-good baseline** — SSDT should be consistent across Windows versions

**Note:** SSDT hooking is less common on modern 64-bit Windows due to PatchGuard protections, but still possible through vulnerable-driver abuse.

---

## Registry Analysis

### hivelist — Registry Hive Enumeration

**What it does:** Lists all loaded registry hives (HKEY_LOCAL_MACHINE, HKEY_USERS, etc.) in memory, showing their virtual and physical addresses.

**Syntax:**
```bash
vol -f memory.dmp windows.registry.hivelist
```

**Output example:**
```
Offset(V)       Offset(P)       Name    Root Cell Address
0xd64a2720      0xa2720 \Registry\Machine\System      0xc0
0xd64a2738      0xa2738 \Registry\Machine\Software    0xc0
0xd64a2750      0xa2750 \Registry\User\S-1-5-21-XXXX\Software\Microsoft\Windows\Run       0xc0
```

---

### printkey — Registry Key Reading

**What it does:** Reads registry keys directly from the memory image. Useful for finding persistence mechanisms, recent documents, and other malware indicators.

**Syntax:**
```bash
# Read a specific key
vol -f memory.dmp windows.registry.printkey -r "Microsoft\Windows\Run"

# Read from a specific hive offset (get offset from hivelist)
vol -f memory.dmp windows.registry.printkey -o 0xd64a2750

# Recursive dump of all subkeys
vol -f memory.dmp windows.registry.printkey -r "Microsoft\Windows" -R
```

**Output example:**
```
Registry\User\S-1-5-21-XXXX\Software\Microsoft\Windows\Run
  Timestamp       Value   Data
  2024-01-15 10:30:00     MalwareRunner    C:\Users\admin\malware.exe
  2024-01-15 10:31:00     WindowsUpdate    C:\Temp\wupdate.exe
```

**Interpretation:**
- **Unexpected entries in Run/RunOnce keys** — Classic persistence mechanism (see note 09)
- **Recent timestamps** — Persistence added during the intrusion window

---

## String Searching & Signatures

### strings — String Extraction

**What it does:** Extracts readable ASCII/Unicode strings from the memory image, useful for:
1. Finding C2 URLs, IP addresses, or domain names
2. Locating configuration strings in malware
3. Searching for specific keywords across all memory

**Syntax:**
```bash
# Extract all strings
vol -f memory.dmp windows.strings

# Search for specific string
vol -f memory.dmp windows.strings | grep "http"

# Search strings in specific process memory
vol -f memory.dmp windows.strings --pid 2154 | grep -i "password"

# Dump to file
vol -f memory.dmp windows.strings > all_strings.txt
```

**Output example:**
```
0x390050 "GET /c2/check HTTP/1.1\r\n"
0x390100 "User-Agent: Mozilla/5.0\r\n"
0x5a2f00 "192.0.2.100:8888"
0x6b1a50 "shell_execute"
```

---

### yarascan — YARA Rule Scanning

**What it does:** Scans the entire memory image (or a specific process) against YARA rules. Can detect:
1. Known malware signatures
2. Packer signatures
3. C2 framework markers
4. Custom IOC patterns

**Syntax:**
```bash
# Scan with a single rule file
vol -f memory.dmp windows.yarascan -y /path/to/rule.yar

# Scan with multiple rules
vol -f memory.dmp windows.yarascan -y /path/to/rules/

# Scan specific process
vol -f memory.dmp windows.yarascan --pid 2154 -y /path/to/rule.yar

# Dump matching regions
vol -f memory.dmp windows.yarascan -y /path/to/rule.yar --dump-dir ./yara_matches/
```

**Example YARA rule for Cobalt Strike (community rule):**
```yara
rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike beacon signature"
        author = "DFIR Community"
    strings:
        $csobf1 = { 01 00 AE 42 }
        $csobf2 = "This program cannot be run in DOS mode"
        $config = /\x00\x01\x00\x02\x00[^\x00]{4,8}[^\x00]{1,4}\x00/
    condition:
        all of them
}
```

**Output example:**
```
Rule: CobaltStrike_Beacon
PID: 2154
Process: rundll32.exe
Match Address: 0x3a0f20
Match Data: 01 00 AE 42 00 01 02 01 (...)
```

**Sources for YARA rules:**
- Volatility official repository: https://github.com/volatilityfoundation/community3
- YARA Exchange: https://github.com/Yara-Rules/rules
- Custom rules from threat intelligence feeds

---

## Memory Dump & Extraction

### memdump — Process Memory Extraction

**What it does:** Dumps a single process's entire address space to a file for offline analysis with a disassembler (IDA, Ghidra) or carver.

**Syntax:**
```bash
# Dump by PID
vol -f memory.dmp windows.memdump --pid 2154 --dump-dir ./dumps/

# Dump by name
vol -f memory.dmp windows.memdump -n rundll32.exe --dump-dir ./dumps/
```

**Output:**
```
Dumped process 2154 (rundll32.exe) to ./dumps/rundll32.exe.2154.dmp
```

**Follow-up analysis:**
```bash
# Disassemble the dump
objdump -M intel -d ./dumps/rundll32.exe.2154.dmp

# Search for specific patterns in the dump
strings ./dumps/rundll32.exe.2154.dmp | grep -i "password\|password\|config"

# Analyze with IDA/Ghidra
# Import as a raw binary with detected architecture
```

---

### dlllist — DLL Enumeration (Per-Process)

**What it does:** Lists all DLLs loaded into a specific process's address space, following the process's module-list walk (same as `modscan` but per-process and following the linked list).

**Syntax:**
```bash
# DLLs in specific process
vol -f memory.dmp windows.dlllist --pid 2154

# DLLs in process by name
vol -f memory.dmp windows.dlllist -n explorer.exe
```

**Output example:**
```
PID     ImageFileName   Base    Size    DllName LoadedDllName
2154    rundll32.exe    0x400000        0x10000 RUNDLL32.EXE    C:\Windows\System32\rundll32.exe
2154    rundll32.exe    0x77dc0000      0x1a0000 ntdll.dll       C:\Windows\System32\ntdll.dll
2154    rundll32.exe    0x75b00000      0x190000 kernel32.dll    C:\Windows\System32\kernel32.dll
2154    rundll32.exe    0x10000000      0x50000 malicious.dll    C:\Users\admin\AppData\Local\malicious.dll
```

---

## Common Workflows

### Initial Triage of a Memory Image

```bash
# 1. Get process overview
vol -f memory.dmp windows.pstree

# 2. Check for hidden processes
vol -f memory.dmp windows.psxview

# 3. Scan for injection/hollowing
vol -f memory.dmp windows.malfind

# 4. Check network connections
vol -f memory.dmp windows.netscan

# 5. Summary output
vol -f memory.dmp windows.driverscan
vol -f memory.dmp windows.sockets
```

### Investigating a Suspected Compromised Process (PID 2154)

```bash
# 1. Get basic process info
vol -f memory.dmp windows.pslist --pid 2154

# 2. Show parent/child
vol -f memory.dmp windows.pstree | grep -A5 -B5 2154

# 3. Get command line
vol -f memory.dmp windows.cmdline --pid 2154

# 4. List DLLs
vol -f memory.dmp windows.dlllist --pid 2154

# 5. Check for injection
vol -f memory.dmp windows.malfind --pid 2154

# 6. Dump process memory
vol -f memory.dmp windows.memdump --pid 2154 --dump-dir ./dumps/

# 7. Check network connections
vol -f memory.dmp windows.netscan | grep 2154

# 8. Scan for injected code with YARA
vol -f memory.dmp windows.yarascan --pid 2154 -y ./rules/malware.yar
```

### Hunting for Credential Access (LSASS Dumping)

```bash
# 1. Find all handles to lsass.exe
vol -f memory.dmp windows.handles | grep lsass

# 2. Get LSASS process info
vol -f memory.dmp windows.pslist -n lsass.exe

# 3. Check for children of lsass (should be none/very few)
vol -f memory.dmp windows.pstree | grep -A10 "lsass.exe"

# 4. Extract LSASS memory if needed (offline credential extraction)
vol -f memory.dmp windows.memdump -n lsass.exe --dump-dir ./dumps/
```

### Detecting DKOM or Hidden Processes

```bash
# 1. Compare pslist vs psscan
vol -f memory.dmp windows.pslist > pslist.txt
vol -f memory.dmp windows.psscan > psscan.txt

# 2. Use psxview for automated detection
vol -f memory.dmp windows.psxview

# 3. Investigate any "False" entries in psxview
# Those are processes visible to some methods but not others

# 4. Dump and analyze hidden processes
# (get PID from psscan that's missing from pslist)
vol -f memory.dmp windows.memdump --pid <hidden_PID> --dump-dir ./dumps/
```

---

## Output Interpretation

### Process State Anomalies

| Finding | Interpretation | Action |
|---|---|---|
| Process in `psscan` but not `pslist` | DKOM or rootkit hiding | Immediate escalation; dump and analyze |
| Child process of `lsass.exe` | Credential access indicator | Check for dumping tools; correlate with Sysmon Event 10 |
| Process with unusual parent (e.g., System → notepad.exe) | PPID spoofing or process tree manipulation | Investigate parent/child relationship validity |
| RWX memory region in non-JIT process | Classic injection/shellcode | Dump region; analyze with disassembler |

### Memory Protection Flags

| Flag | Normal? | Concern |
|---|---|---|
| `PAGE_READONLY` | Executable code sections | No |
| `PAGE_READWRITE` | Data/heap sections | No |
| `PAGE_EXECUTE_READ` | Code sections (some compilers) | No |
| `PAGE_EXECUTE_READWRITE` (RWX) | Almost never legitimate | High — injection/shellcode indicator |

---

## Troubleshooting

### "Unknown address space" error

**Cause:** Volatility doesn't recognize the memory image format or OS version.

**Solution:**
```bash
# Specify the image format
vol -f memory.dmp --format raw -p windows.pslist

# Check image profile (Volatility 2 term; less relevant in Volatility 3)
vol -f memory.dmp windows.info
```

### Plugin not found

**Cause:** Plugin name is incorrect or not installed.

**Solution:**
```bash
# List all available plugins
vol plugins list

# Use correct Windows plugin namespace
# Correct: windows.pslist
# Incorrect: pslist or vol.pslist
```

### JSON output garbled or missing data

**Cause:** Plugin doesn't support JSON renderer or output is too large.

**Solution:**
```bash
# Use text renderer
vol -f memory.dmp -p windows.pslist -r text

# Pipe to file
vol -f memory.dmp windows.pslist > output.txt

# Use CSV for structured data
vol -f memory.dmp windows.netscan -r csv > connections.csv
```

### Out of memory error

**Cause:** Memory image is very large and Volatility is consuming too much RAM.

**Solution:**
```bash
# Run on a system with more RAM
# Or use a 64-bit version of Volatility
# Or process in chunks (less efficient)

# Check image size
ls -lh memory.dmp
```

### Dump directory doesn't exist

**Cause:** `--dump-dir` points to a nonexistent path.

**Solution:**
```bash
# Create directory first
mkdir -p ./extracted/
vol -f memory.dmp windows.malfind --dump-dir ./extracted/
```

---

## Additional Resources

- **Volatility Foundation:** https://volatilityfoundation.org/
- **Volatility 3 GitHub:** https://github.com/volatilityfoundation/volatility3
- **Volatility Community Plugins:** https://github.com/volatilityfoundation/community3
- **SANS FOR508 Course Material:** Memory Forensics in-depth reference
- **Rekall Project:** https://github.com/google/rekall (alternative framework)

