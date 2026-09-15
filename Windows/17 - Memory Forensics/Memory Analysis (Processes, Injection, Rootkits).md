# Memory Analysis (Processes, Injection, Rootkits) — Enterprise DFIR Edition

A systematic, Volatility 3-focused guide for analyzing Windows memory images to detect hidden processes, code injection, rootkits, and credential theft. Built on operational casework patterns and organized for enterprise DFIR teams.

This note assumes you have a clean memory image (raw dump, `.vmem`, hibernation-derived) and Volatility 3 installed. It covers **structural analysis** (process lists, memory regions, kernel objects) and **behavioral detection** (injection patterns, network anomalies, credential access indicators). See the sibling **Volatility 3 - Complete Reference Guide** for exact command syntax, output interpretation, and plugin options.

## Core Principle

A rootkit that hides a process from `tasklist` does so by unlinking that process from the Windows kernel's EPROCESS linked list — the exact structure `tasklist` walks to build output. A memory-analysis tool that scans raw memory for EPROCESS signatures, independent of list membership, still finds the hidden process. **Everything below is a variation on this single idea: live tools trust kernel structures an attacker can manipulate; memory analysis verifies those structures against raw bytes and internal consistency.**

## Contents

- [Enterprise Analysis Workflow](#enterprise-analysis-workflow)
- [Process Analysis & Hidden Process Detection](#process-analysis--hidden-process-detection)
  - [Initial Triage: pstree & psxview](#initial-triage-pstree--psxview)
  - [DKOM Detection: pslist vs. psscan](#dkom-detection-pslist-vs-psscan)
  - [Process Context Analysis](#process-context-analysis)
- [Code Injection Detection](#code-injection-detection)
  - [RWX Scanning (malfind)](#rwx-scanning-malfind)
  - [Injection Technique Reference](#injection-technique-reference)
  - [Process Hollowing Detection (hollowfind)](#process-hollowing-detection-hollowfind)
  - [DLL Injection & Module Anomalies](#dll-injection--module-anomalies)
- [Rootkit & Kernel-Level Threats](#rootkit--kernel-level-threats)
  - [Driver Enumeration & Validation](#driver-enumeration--validation)
  - [SSDT Hook Detection](#ssdt-hook-detection)
- [Credential Theft & LSASS Analysis](#credential-theft--lsass-analysis)
  - [LSASS Dumping Indicators](#lsass-dumping-indicators)
  - [Handle-Based Credential Access Detection](#handle-based-credential-access-detection)
- [Network Analysis & Anomalies](#network-analysis--anomalies)
- [Signature-Based Detection (YARA)](#signature-based-detection-yara)
- [Enterprise Remediation Framework](#enterprise-remediation-framework)
- [Red Flags (Priority Matrix)](#red-flags-priority-matrix)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Enterprise Analysis Workflow

**The structured approach:** for any memory image, this workflow ensures you catch the highest-value findings first and minimize false negatives.

### Phase 1: Initial Triage (30 minutes)

Run these to get a complete picture before drilling into specific processes:

```bash
# 1. Process tree overview
vol -f memory.dmp windows.pstree > process_tree.txt

# 2. Check for hidden/DKOM processes
vol -f memory.dmp windows.psxview > psxview.txt

# 3. Scan for injection/shellcode
vol -f memory.dmp windows.malfind > malfind.txt

# 4. Enumerate drivers
vol -f memory.dmp windows.driverscan > drivers.txt

# 5. Network connections
vol -f memory.dmp windows.netscan > connections.txt
```

**At this stage, you're looking for:**
- Any "False" entries in `psxview` output (hidden processes)
- RWX memory regions in `malfind` (injection indicators)
- Unsigned/unrecognized drivers
- Unexpected network connections from system processes

### Phase 2: Deep Dive on Findings (as needed)

For each finding from Phase 1, use targeted commands:

```bash
# If psxview shows hidden process with PID 8456:
vol -f memory.dmp windows.pslist --pid 8456
vol -f memory.dmp windows.pslist --pid 8456 -v  # verbose
vol -f memory.dmp windows.memdump --pid 8456 --dump-dir ./dumps/

# If malfind shows RWX in process 2154:
vol -f memory.dmp windows.dlllist --pid 2154
vol -f memory.dmp windows.handles --pid 2154
vol -f memory.dmp windows.memdump --pid 2154 --dump-dir ./dumps/

# If handles show access to lsass.exe:
vol -f memory.dmp windows.pslist -n lsass.exe
vol -f memory.dmp windows.handles | grep -i lsass
```

### Phase 3: Signature Validation (if time permits)

```bash
# YARA scan with malware signatures
vol -f memory.dmp windows.yarascan -y ./rules/malware.yar --dump-dir ./yara_matches/

# String search for IOCs
vol -f memory.dmp windows.strings | grep -E "http|https|192\."
```

---

## Process Analysis & Hidden Process Detection

### Initial Triage: pstree & psxview

**Start here for every engagement.**

**pstree** renders parent/child relationships immediately visually:

```bash
vol -f memory.dmp windows.pstree
```

**What to look for:**
- Any process spawned from `lsass.exe` (credential access)
- `System` spawning user-mode processes (unusual)
- Processes with unexpected parents (e.g., `notepad.exe` parented by `svchost.exe`)
- Duplicate singletons (`lsass.exe`, `csrss.exe`, `services.exe` should appear once)

**psxview** is your automated DKOM detector:

```bash
vol -f memory.dmp windows.psxview
```

Look for rows with **False** in the `pslist` column but **True** in the `psscan` column — that's a hidden process.

**Example interpretation:**
```
PID     PPID    ImageFileName   pslist  psscan  thrdproc    pspcid  csrss   session 
8456    892     hidden_malware  False   True    False       False   False   False
```

This process is visible only to pool scanning (`psscan`), meaning it has been **unlinked from the kernel's process list** — a DKOM/rootkit indicator. **Escalate immediately.**

### DKOM Detection: pslist vs. psscan

If `psxview` isn't available or you need more granular comparison:

```bash
# Get process list walk
vol -f memory.dmp windows.pslist > pslist.txt

# Get pool scan results
vol -f memory.dmp windows.psscan > psscan.txt

# Extract PIDs from each
grep -oP "^(\d+)" pslist.txt | sort | uniq > pslist_pids.txt
grep -oP "^(\d+)" psscan.txt | sort | uniq > psscan_pids.txt

# PIDs visible only to psscan (hidden processes)
comm -23 psscan_pids.txt pslist_pids.txt
```

**A process appearing in `psscan` but not `pslist`** is near-definitive evidence of DKOM or rootkit-based process hiding. Possible exceptions:
- Recently terminated process still in memory pools (check `ExitTime` column; if non-zero, likely not active)
- Corrupted EPROCESS structure (rare; verify with `psxview`)

### Process Context Analysis

For any suspicious process, establish context:

```bash
# Basic info
vol -f memory.dmp windows.pslist --pid <PID> -v

# Parent/child tree
vol -f memory.dmp windows.pstree | grep -A5 -B5 <PID>

# Command line used to launch
vol -f memory.dmp windows.cmdline --pid <PID>

# Network connections from this PID
vol -f memory.dmp windows.netscan | grep <PID>

# Handles it holds (especially to lsass.exe)
vol -f memory.dmp windows.handles --pid <PID>

# DLLs loaded
vol -f memory.dmp windows.dlllist --pid <PID>

# Threads (if terminated, shows exit time)
vol -f memory.dmp windows.threads --pid <PID>
```

Cross-reference against note 01's process-tree baseline:
- Normal svchost.exe should be a child of services.exe and have a specific command line (e.g., `-k netsvcs`)
- explorer.exe should be parented by userinit.exe or winlogon.exe
- powershell.exe running as a child of unexpected parents (cmd.exe, firefox.exe, etc.) is suspicious

---

## Code Injection Detection

### RWX Scanning (malfind)

**The highest-value technique for catching all injection types at once.**

```bash
# Scan all processes
vol -f memory.dmp windows.malfind

# Scan specific process
vol -f memory.dmp windows.malfind --pid 2154

# Dump suspicious regions
vol -f memory.dmp windows.malfind --dump-dir ./extracted/
```

**Interpretation:**

```
PID     ImageFileName   Start VAddr       End VAddr       VSize   Protect
2154    rundll32.exe    0x390000          0x3a0000        0x10000 PAGE_EXECUTE_READWRITE
        50 4d 5a 90 00 03 00 00 04 00 00 00...  (PE header "MZ..")
```

**This is the smoking gun:** `PAGE_EXECUTE_READWRITE` means memory is simultaneously writable and executable — exactly what injected shellcode or malicious payloads need to be. **Legitimate code is essentially never both writable and executable at the same time.** Read-only code sections and read-write data sections are the normal pattern; RWX is the exception.

**Exceptions (legitimate RWX):**
- JavaScript engines (chrome.exe, edge.exe) — JIT compilers naturally create RWX regions
- .NET runtime (dotnet.exe, powershell.exe) — CLR JIT compilation
- Virtual machines/hypervisors
- Wine/emulators

**Action:** Dump the region and disassemble it.

```bash
# Dump was created in ./extracted/ by malfind command above
objdump -M intel -d ./extracted/rundll32.exe.0x390000.mem | head -50

# Or use a full disassembler
# Import into IDA/Ghidra as raw binary, x86-64, set origin to 0x390000
```

### Injection Technique Reference

| Technique | Detection Method | Volatility Plugin | Signature |
|---|---|---|---|
| **Classic DLL Injection** | DLL from non-system path in `dlllist` | `dlllist`, `modscan` | Non-standard DLL path (not System32/SysWOW64) |
| **Process Hollowing** | In-memory code ≠ on-disk file | `hollowfind`, manual hash compare | PE header in unexpected location; mismatched sections |
| **Reflective DLL Injection** | RWX region with no loaded module | `malfind` | RWX + no corresponding `dlllist` entry |
| **Process Doppelgänging** | Transactional rollback evasion | `malfind` | RWX in process spawned from unusual parent |
| **PPID Spoofing** | Parent PID doesn't exist in current processes | `pslist`, `pstree` | Child of non-existent or unrelated parent |

### Process Hollowing Detection (hollowfind)

For cases where `malfind` alone doesn't surface the full picture:

```bash
vol -f memory.dmp windows.hollowfind
```

This explicitly checks: does the process's in-memory code match the on-disk file at the path it claims?

```
PID     ImageFileName   Address         Protection              Reason
2154    rundll32.exe    0x400000        PAGE_READWRITE          Unmapped section (expected PAGE_READONLY)
        Expected disk image at C:\Windows\System32\rundll32.exe does not match
```

**Unmapped or mismatched sections = process hollowing confirmed.**

### DLL Injection & Module Anomalies

```bash
# Enumerate all loaded DLLs for a process
vol -f memory.dmp windows.dlllist --pid 2154

# Pool-scan for DLLs (catches unlinked/reflective injections)
vol -f memory.dmp windows.modscan
```

**Red flags:**
- DLL from `C:\Users\<user>\AppData\Local\` or other user-writable paths
- DLL from `C:\Temp\`, `C:\Windows\Temp\`, or similar
- DLL with randomized or suspicious name
- DLL present in `modscan` but not in process's `dlllist` (module-list unlinking)

**Example suspect pattern:**
```
PID     DllName        Path
2154    kernel32.dll   C:\Windows\System32\kernel32.dll   ← Normal
2154    malicious.dll  C:\Users\admin\AppData\Local\malicious.dll  ← Injected, non-standard path
```

---

## Rootkit & Kernel-Level Threats

### Driver Enumeration & Validation

Kernel-level rootkits operate through malicious drivers. Always enumerate:

```bash
vol -f memory.dmp windows.driverscan
```

**What to look for:**
- Unsigned or unrecognized driver names
- Drivers with randomized/suspicious names
- Drivers not matching known-good baselines

**Cross-reference against legitimate drivers:**
- Windows default drivers (ntfs, disk, atapi, etc.)
- Known third-party drivers (antivirus, storage, virtualization)

**If you find a suspect driver:**
```bash
# Dump it
vol -f memory.dmp windows.driverscan --dump-dir ./drivers/

# Analyze with file hash against VirusTotal/known-good
sha256sum ./drivers/<suspicious_driver>.sys

# Check against NIST or custom baselines
```

### SSDT Hook Detection

System Service Descriptor Table (SSDT) hooks allow rootkits to intercept system calls:

```bash
vol -f memory.dmp windows.ssdt
```

**Look for:**
```
Index   Name            Address(V)      Hooked?
0       NtCreateFile    0x835a2f00      False
1       NtOpenFile      0x835a2f04      True (Expected: 0x835a2f00, Got: 0xaaaabbbb)
```

**Hooked entries = system call interception by rootkit code.** This is kernel-level equivalent of DLL injection.

**Note:** Modern 64-bit Windows with PatchGuard makes classic SSDT hooking harder (though still possible via vulnerable-driver abuse), but it's worth checking regardless.

---

## Credential Theft & LSASS Analysis

### LSASS Dumping Indicators

LSASS holds plaintext passwords, NTLM hashes, and Kerberos tickets. **Access to `lsass.exe` memory is a red flag.**

**Memory-side indicators (from this image):**

```bash
# Find all processes with handles to lsass.exe
vol -f memory.dmp windows.handles | grep -i lsass
```

**Expected legitimate accessors:**
- System, services.exe, csrss.exe, svchost.exe (specific instances)

**Unexpected accessors:**
- User-mode executables (powershell.exe, cmd.exe, rundll32.exe, notepad.exe)
- Browser processes (chrome.exe, firefox.exe)
- Office apps
- Unsigned binaries

**Critical finding:** If `rundll32.exe` or `powershell.exe` has a handle to `lsass.exe`, cross-reference with Sysmon Event ID 10 (ProcessAccess) if available.

### Handle-Based Credential Access Detection

A process opening a handle to `lsass.exe` with `PROCESS_ALL_ACCESS` or credential-read access rights is a strong indicator of credential extraction attempt:

```bash
# Enumerate handles to lsass
vol -f memory.dmp windows.handles --pid 932  # (assuming 932 is lsass.exe)
```

**Look for entries like:**
```
PID     Handle  Type    Object Name         Access Rights
2154    0x1c    Process (lsass.exe handle)  PROCESS_ALL_ACCESS
```

**Process 2154 (e.g., rundll32.exe) opening `PROCESS_ALL_ACCESS` to lsass.exe is a strong credential-access indicator.**

**Respond:**
- Check process 2154's command line and parent
- Check for children of lsass.exe (they shouldn't exist)
- Look for `.dmp` files on disk (lsass dump staging)
- Correlate with Sysmon Event ID 10 if available
- Cross-reference with note 06 (Prefetch/ShimCache) for evidence of dumping tools like `procdump.exe` or `rundll32.exe comsvcs.dll`

---

## Network Analysis & Anomalies

```bash
vol -f memory.dmp windows.netscan
```

**What to look for:**

| Finding | Interpretation |
|---|---|
| Established connection from unexpected process | Direct C2 communication or data exfil |
| Listening port on non-standard port (8888, 4444, etc.) | Backdoor or reverse-shell listener |
| Connection in `netscan` not visible in live `netstat` | Hidden connection (rootkit) or process has exited but connection still in memory |
| Multiple connections from same process to different IPs | Potential command-and-control beacon behavior |

**Example investigation:**

```bash
# Process 5892 (powershell.exe) connected to 45.33.32.156:443
vol -f memory.dmp windows.pslist --pid 5892
vol -f memory.dmp windows.cmdline --pid 5892
vol -f memory.dmp windows.dlllist --pid 5892
vol -f memory.dmp windows.netscan | grep 5892
```

Cross-reference against note 19 (Network Artifacts) for firewall logs, DNS queries, and network timeline to correlate the memory finding with network history.

---

## Signature-Based Detection (YARA)

For known malware families, frameworks, or custom IOCs:

```bash
# Scan entire image with community rules
vol -f memory.dmp windows.yarascan -y ./rules/malware.yar

# Scan specific process
vol -f memory.dmp windows.yarascan --pid 2154 -y ./rules/cobalt_strike.yar

# Dump matches
vol -f memory.dmp windows.yarascan -y ./rules/ --dump-dir ./yara_matches/
```

**Where to get rules:**
- Volatility Community Rules: https://github.com/volatilityfoundation/community3
- YARA-Rules repository: https://github.com/Yara-Rules/rules
- Threat-specific rules: Cobalt Strike, Mimikatz, PSTools, etc.

**Example Cobalt Strike beacon detection:**
```yara
rule CobaltStrike_Beacon {
    strings:
        $cs1 = { 01 00 AE 42 }
        $cs2 = "This program cannot be run in DOS mode"
    condition:
        all of them
}
```

---

## Enterprise Remediation Framework

For each finding, follow this framework:

### Finding: DKOM/Hidden Process (psxview shows False in pslist, True in psscan)

**Severity:** 🔴 **CRITICAL**

**Scope:** Single PID

**Action Plan:**
1. **Immediate**: Extract process memory for analysis
   ```bash
   vol -f memory.dmp windows.memdump --pid <hidden_PID> --dump-dir ./dumps/
   ```
2. **Analysis**: Disassemble and analyze with IDA/Ghidra
3. **Correlation**: Check timeline (note 18) for when process was created
4. **Hunting**: Search all systems for similar process names, DLLs, or network signatures
5. **Containment**: Block any C2 IPs/domains at perimeter
6. **Remediation**: Rebuild host; rootkit-level compromise requires full rebuild

### Finding: RWX Region (malfind)

**Severity:** 🔴 **CRITICAL**

**Scope:** Single process, single memory region

**Action Plan:**
1. **Triage**: Confirm not a JIT engine (check process name)
2. **Extract**: Dump the region
   ```bash
   # Region was already dumped by malfind --dump-dir
   objdump -M intel -d ./extracted/rundll32.exe.0x390000.mem | head -100
   ```
3. **Analyze**: Identify shellcode vs. legitimate JIT
4. **Escalate**: If confirmed malicious, treat as active intrusion; escalate to IR
5. **Remediation**: Terminate process, preserve logs, rebuild if needed

### Finding: LSASS Handle Access (handles show unexpected process touching lsass.exe)

**Severity:** 🟠 **HIGH**

**Scope:** Credential theft attempt (likely active)

**Action Plan:**
1. **Verify**: Confirm process is not in known legitimate accessor list
2. **Extract**: Dump the lsass.exe process memory (offline credential extraction possible)
   ```bash
   vol -f memory.dmp windows.memdump -n lsass.exe --dump-dir ./dumps/
   ```
3. **Correlate**: Check Sysmon Event ID 10 for corroborating ProcessAccess event
4. **Timeline**: Was this access during the intrusion window?
5. **Remediation**: Reset credentials (assume compromise); review access logs for lateral movement using stolen credentials

### Finding: Unsigned/Unknown Driver (driverscan)

**Severity:** 🟠 **HIGH**

**Scope:** System-level

**Action Plan:**
1. **Identify**: Hash the driver, check VirusTotal/internal baselines
2. **Extract**: Dump driver file
   ```bash
   vol -f memory.dmp windows.driverscan --dump-dir ./drivers/
   ```
3. **Analyze**: Reverse engineer with IDA; check import tables for rootkit-like behaviors
4. **Scope**: Check if driver present on other systems (internal compromise scope)
5. **Remediation**: Unload driver, remove from disk, review system for rootkit indicators

---

## Red Flags (Priority Matrix)

| Priority | Finding | Why | Command | Response |
|---|---|---|---|---|
| 🔴 **CRITICAL** | Process in `psscan` but not `pslist` (DKOM/hidden) | Active rootkit; process deliberately hidden | `psxview` | Extract & analyze; assume rootkit; rebuild host |
| 🔴 **CRITICAL** | RWX memory region in non-JIT process | Injected shellcode or malicious payload | `malfind` | Dump & disassemble; terminate process; escalate |
| 🔴 **CRITICAL** | In-memory PE doesn't match on-disk file (hollowing) | Process masquerading; legitimate binary replaced | `hollowfind` | Extract memory image; analyze with disassembler |
| 🟠 **HIGH** | Unexpected process with handle to lsass.exe | Credential extraction attempt | `handles` | Correlate with Sysmon Event 10; reset credentials |
| 🟠 **HIGH** | Child process of lsass.exe | Credential access (likely credential stealer) | `pstree` | Escalate to IR; analyze parent/child chain |
| 🟠 **HIGH** | Unsigned or unknown kernel driver | Possible kernel rootkit | `driverscan` | Hash/VirusTotal; extract & reverse; scope to other hosts |
| 🟡 **MEDIUM** | Established connection from unexpected process | Possible C2 communication or data exfil | `netscan` | Correlate with network logs; block IP/domain |
| 🟡 **MEDIUM** | Listening port from non-standard process | Possible backdoor or reverse shell | `netscan` | Kill process; block port; rebuild if persistent |
| 🟡 **MEDIUM** | DLL from user-writable path in `dlllist` | DLL injection (loaded via standard `LoadLibrary`) | `dlllist` | Check parent process for injection; escalate if from suspicious parent |
| 🟡 **MEDIUM** | PPID doesn't exist or mismatches baseline | Process tree manipulation or spoofing | `pstree` | Verify against note 01 baseline; check for parent spoofing |

---

## Correlate With

| Artifact Family | Why Correlate | Findings |
|---|---|---|
| **Execution Evidence (note 06)** — Prefetch, ShimCache, Amcache | Corroborate processes found in memory image; find disk-side evidence of dumping tools (`procdump.exe`, `rundll32.exe`) | Process names, timestamps, command lines |
| **Sysmon Event ID 10 (ProcessAccess)** — Handle opens to lsass.exe | Correlate LSASS credential-access findings with logged Sysmon events | Exact timestamp of handle open; source process; access rights |
| **Process Tree Baseline (note 01)** — Parent/child relationships | Verify `pstree` output against known-normal process trees | Detect PPID spoofing, unusual parents, unexpected children |
| **DLL Hijacking (note 10)** | Cross-reference injected DLLs with load-time DLL hijacking patterns | Non-standard DLL paths; hijacked system DLLs |
| **Network Artifacts (note 19)** — Firewall, DNS, connection logs | Correlate `netscan` findings with network timeline | Exact timing of connections; internal/external C2 communications |
| **Registry Analysis (note 09)** — Persistence mechanisms | Find malware startup paths; correlate with processes found in memory | Run keys, services, scheduled tasks that spawned suspicious processes |
| **Timeline Analysis (note 18)** — Master timeline | Place memory findings on intrusion timeline | When processes were created/exited; correlation with other events |



## Resources

- **Volatility 3 Complete Reference Guide** (sibling note in this directory) — Comprehensive command reference with plugin syntax, output examples, and workflows
- **Volatility Foundation:** https://volatilityfoundation.org/
- **Volatility 3 GitHub:** https://github.com/volatilityfoundation/volatility3
- **Volatility 3 Documentation:** https://volatility3.readthedocs.io/
- **Volatility Community Plugins:** https://github.com/volatilityfoundation/community3
- **YARA Project:** https://virustotal.github.io/yara/
- **YARA Rules Repository:** https://github.com/Yara-Rules/rules
- **SANS FOR508:** Memory Forensics and Incident Handling (reference for memory analysis concepts)
- **MITRE ATT&CK T1055:** Process Injection — https://attack.mitre.org/techniques/T1055/
- **MITRE ATT&CK T1003.001:** OS Credential Dumping: LSASS Memory — https://attack.mitre.org/techniques/T1003/001/
- **MITRE ATT&CK T1014:** Rootkit — https://attack.mitre.org/techniques/T1014/
- **Microsoft Credential Guard:** https://learn.microsoft.com/windows/security/identity-protection/credential-guard/
- **Sysmon (Sysinternals):** https://learn.microsoft.com/sysinternals/downloads/sysmon

## Correlate With

| To go deeper on… | Open |
|---|---|
| How the memory image analyzed in this note was actually captured | **Memory Acquisition Fundamentals** (sibling note, 17) |
| Normal vs. abnormal process-tree/parent-child relationships needed to interpret `pstree` output, and the process-name masquerade patterns this note's DKOM/injection findings often ride on top of | **Windows OS Fundamentals & Versions** (01) |
| Disk-side execution evidence for whatever a process's on-disk path claims to be, and why reflective injection leaves none of it | **Prefetch**, **ShimCache (AppCompatCache)**, **Amcache** (note 06) |
| The load-time/search-order DLL abuse this note's DLL-injection section is explicitly distinguished from | **DLL Hijacking** (note 10) |
| The Pass-the-Hash/Pass-the-Ticket credential-*use* this note's LSASS/Mimikatz section supplies the credential-*theft* half for | **Lateral Movement** (note 12) |
| Placing a rogue in-memory process's or injection event's timing against the rest of the intrusion timeline | **Timeline Analysis** (future note 18) |
| Building this note's findings into a repeatable, proactive hunt rather than a one-off incident response pass | **Threat Hunting Methodology and Intelligence** (future note 20) |

## Resources

- SANS FOR508 course syllabus, memory-forensics/rootkit-hunting section — used here purely as a coverage checklist; no text reproduced from the bundled poster/course material
- Volatility Foundation documentation and GitHub — https://volatilityfoundation.org/ and https://github.com/volatilityfoundation/volatility3
- Rekall project (historical/alternative framework, verify current maintenance status before relying on it) — https://github.com/google/rekall
- YARA — https://virustotal.github.io/yara/
- MITRE ATT&CK T1055 (Process Injection) — https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1055.012 (Process Injection: Process Hollowing) — https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK T1055.002 (Process Injection: Portable Executable Injection) — https://attack.mitre.org/techniques/T1055/002/
- MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory) — https://attack.mitre.org/techniques/T1003/001/
- MITRE ATT&CK T1014 (Rootkit) — https://attack.mitre.org/techniques/T1014/
- Microsoft Learn — Credential Guard — https://learn.microsoft.com/windows/security/identity-protection/credential-guard/
- Sysmon (Sysinternals) — https://learn.microsoft.com/sysinternals/downloads/sysmon
- Sysinternals Process Explorer / procdump — https://learn.microsoft.com/sysinternals/downloads/
