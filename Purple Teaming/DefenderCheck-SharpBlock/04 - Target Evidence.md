# DefenderCheck-SharpBlock: Target Evidence

## Overview

**DefenderCheck** and **SharpBlock** both operate **entirely within a single process** on the target machine with minimal persistent artifacts. DefenderCheck reads registry and WMI; SharpBlock patches AMSI in-memory. Neither creates new registry keys, new services, new scheduled tasks, or persistent files (unless explicitly captured by the operator). The primary evidence footprint is **process execution, brief temporary files (if redirected), and WMI event logs**.

---

## Process Execution Events

### Sysmon Event 1 / Security Event 4688 (Process Creation)

Both tools will appear in process-creation event logs when executed.

| Field | DefenderCheck | SharpBlock |
|-------|---|---|
| **Image (binary name)** | `C:\Temp\DefenderCheck.exe` (or operator-chosen path) | `C:\Temp\SharpBlock.exe` (or operator-chosen path) |
| **CommandLine** | `DefenderCheck.exe` (no switches in typical deployment) | `SharpBlock.exe` (no switches in typical deployment) |
| **ParentImage** | `cmd.exe`, `powershell.exe`, or C2 beacon (Cobalt Strike, Sliver, etc.) | Same; often injected into beacon or PowerShell process |
| **User** | Interactive user context OR SYSTEM (if executed via scheduled task / service) | Same |
| **TargetFilename / Image Details** | .NET executable signature; PE analysis shows DefenderCheck.cs compilation | .NET executable; PE shows SharpBlock.cs compilation |

**Example Sysmon 1 Event:**
```xml
<Event>
  <EventData>
    <Data Name="Image">C:\Temp\DefenderCheck.exe</Data>
    <Data Name="CommandLine">C:\Temp\DefenderCheck.exe</Data>
    <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
    <Data Name="User">DOMAIN\user</Data>
    <Data Name="ProcessId">5432</Data>
    <Data Name="CreationUtcTime">2026-08-29T14:16:00Z</Data>
  </EventData>
</Event>
```

### Behavior: Short Lifespan

Both tools typically execute and terminate quickly (< 1 second):
- **DefenderCheck**: runs WMI query, prints output, exits.
- **SharpBlock**: patches AMSI in-memory, exits (effect persists in current process).

A spike in short-lived .exe processes in the Temp folder is a **low-fidelity signal** (many legitimate cleanup scripts do this), but in combination with parent process (beacon, PowerShell) + timing = notable.

---

## WMI & Registry Access Events

### WMI-Activity Events (Event ID 5860–5861)

DefenderCheck queries WMI classes (Win32_Product, Win32_Service). Modern Windows versions may log this under **Microsoft-Windows-WMI-Activity/Operational** (Event ID 5860 or 5861), though detailed WMI auditing is typically **disabled by default**.

| Event | Triggered By | Content |
|-------|---|---|
| **5860** | WMI query execution | Namespace: `root\cimv2`, Query: `SELECT * FROM Win32_Product WHERE Name LIKE '%Defender%'` (or similar) |
| **5861** | WMI provider activity | Consumer/provider connection events (less direct) |

**Caveats:**
- WMI-Activity logging requires explicit Group Policy enable: `Computer Configuration > Policies > Administrative Templates > Windows Components > WMI-ADWMI-Activity`
- Most organizations **do not enable this** by default (creates high log volume).
- If enabled, queries can be reconstructed from event text.

**Example WMI-Activity Event (5860):**
```
Task Category: WMI Event
Description: Consumer with namespace id=1 with namespace id=1 with namespace id=1 is accessing WMI namespace `\\.\root\cimv2` 
Query: SELECT * FROM Win32_Product
Event: 5860
```

### Registry Access (Event ID 4663 – File/Object Access)

DefenderCheck reads from `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\`. If Object Access auditing is enabled for registry:

| Registry Key | Event ID | Logged |
|---|---|---|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\` (any subkey) | 4663 | YES, if SACL configured |
| `HKLM\Software\Microsoft\Windows Defender\` | 4663 | YES, if SACL configured |

**Caveat:** Registry Object Access auditing requires:
1. Group Policy enable: `Computer Configuration > Policies > Windows Settings > Security Settings > Audit Policy > Object Access`
2. Explicit SACL on the registry key (not inherited by default).

Most systems **do not have this configured**, so registry reads by DefenderCheck are **typically not logged**.

---

## Event Log Entries (Security / System Channel)

### No Direct Anti-Malware Service Events

DefenderCheck does **not** trigger Defender or antivirus alerts by design (it is reconnaissance, not malicious code execution). Defender's Event Log channels (e.g., `Microsoft-Windows-Windows Defender/Operational`) will **not show DefenderCheck** as a detected threat.

### SharpBlock: AMSI Bypass Detection (If Logged)

If AMSI bypass detection is enabled in Windows Defender or a third-party EDR, SharpBlock's in-memory patching of AMSI may trigger alerts:

| Product | Event Type | Event ID | Typical Behavior |
|---|---|---|---|
| **Windows Defender** | Threat Detected | 1116, 1117 | May log "Suspicious Behavior" or "PUA" if configured to detect AMSI evasion attempts |
| **EDR Agents (Crowdstrike, Sentinel One, etc.)** | Behavioral alert | Vendor-specific | May flag "AMSI function patching" or "in-process code injection" patterns |

**Note:** Detection depends on EDR sensitivity settings and whether AMSI patching is specifically monitored. Sophisticated operators may test SharpBlock beforehand to confirm no alerts before deployment.

---

## File System Artifacts

### Default Case: No Persistent Artifacts

Neither tool writes files to disk by default during normal execution:
- DefenderCheck: reads-only from WMI/registry; output is console text.
- SharpBlock: in-memory patching; no disk writes.

### If Redirected to File

If operator redirects output to a file:
```powershell
C:\Temp\DefenderCheck.exe > C:\Temp\av_results.txt
```

**File created:**
- **Path:** `C:\Temp\av_results.txt` (or operator-chosen)
- **Timestamps:** $CREATED = time of redirect; $MODIFIED/ACCESSED = time of write completion
- **Content:** Plaintext DefenderCheck output listing detected AV/EDR products and status
- **Persistence:** Remains on disk unless deleted; recoverable from unallocated clusters if deleted

### Prefetch Files

Both DefenderCheck.exe and SharpBlock.exe may create Windows Prefetch entries (if Prefetch is enabled, the default on most systems):

| Prefetch Entry | Location | Content |
|---|---|---|
| `DEFENDERCHECK.EXE-<hash>.pf` | `C:\Windows\Prefetch\` | Execution count, last-run timestamp, DLL dependencies (amsi.dll, wmi.dll, ntdll.dll, etc.) |
| `SHARPBLOCK.EXE-<hash>.pf` | `C:\Windows\Prefetch\` | Execution count, timestamp, amsi.dll + .NET CLR DLL dependencies |

**Forensic Value:**
- Confirms execution on the machine (Prefetch only created on first run).
- Last-run timestamp in Prefetch header (8 bytes, little-endian) = last execution time.
- `ExecCount` field shows how many times the tool ran on this machine.
- **Cannot be directly deleted by user without admin rights.**

**Example Prefetch Timeline:**
```
DefenderCheck.exe-A1B2C3D4.pf → Last Run: 2026-08-29 14:16:00 UTC, Exec Count: 1
SharpBlock.exe-E5F6G7H8.pf    → Last Run: 2026-08-29 14:16:30 UTC, Exec Count: 3
```

### Program Execution (PCA / Application Compatibility)

Windows may log application execution under `HKLM\System\CurrentControlSet\Services\ProgramDataUpdater`:
- DefenderCheck.exe and SharpBlock.exe are tracked if they're non-standard (not in System32, Program Files, etc.).
- Not user-readable without tools; requires registry parsing.

---

## Memory Forensics

### SharpBlock: In-Memory AMSI Patches

After SharpBlock runs, the affected process's memory contains:
- **Original AMSI stub locations (before patch):** `amsi!AmsiScanBuffer` (address varies per process)
- **Patched bytes:** Replaced with `ret` (0xC3) opcode or immediate-return JMP
- **Evidence:** Memory dump analysis (e.g., Volatility `psxview`, `vadinfo` plugins) shows non-standard bytes at amsi.dll export table

**Volatility Memory Analysis Example:**
```bash
volatility3 -f target_memory.dmp banners.Banner
# No AMSI.dll mentions in imports (tool disabled it)

volatility3 -f target_memory.dmp windows.dlllist --pid <pid>
# amsi.dll present but with modified memory pages (dirty pages in VAD)

volatility3 -f target_memory.dmp malfind
# May flag amsi.dll as modified if heuristics check for code caves / patched memory
```

### DefenderCheck: No In-Memory Artifacts

DefenderCheck does not persist in memory post-execution. If memory is captured during execution, only the output buffer and registry read-cache are visible (not distinctive).

---

## Behavioral Signatures

### DefenderCheck: WMI Query Patterns

Network-level or endpoint-behavioral detection may flag:
```
Process: cmd.exe / powershell.exe
  ├─ Child: DefenderCheck.exe
  └─ Parent activity: WMI queries to Win32_Product, Win32_Service classes
  └─ Registry reads: HKLM\Software\...\Uninstall\
```

**YARA / SigmaHQ detection rule pattern:**
```
process_name: DefenderCheck.exe
parent_process: cmd.exe OR powershell.exe
wmi_query: "Win32_Product" OR "Win32_Service"
action: detect_reconnaissance
```

### SharpBlock: Code Injection / AMSI Patching Signature

EDR behavioral signatures may flag:
```
process: powershell.exe
child_process: SharpBlock.exe (short-lived)
in_process_event: amsi.dll function patching detected
action: block
```

**Endpoint Detection & Response Heuristic:**
- Process memory write to `.text` section of amsi.dll
- AMSI function prologue rewritten (byte signature matching)
- Subsequent AMSI API calls return `AMSI_RESULT_CLEAN` (0x0) immediately

---

## Typical Event Timeline

**Scenario:** Attacker stages both tools, runs DefenderCheck for recon, then SharpBlock to disable AMSI before executing PowerShell payload.

| Time | Event | Log Channel | Event ID |
|------|-------|---|---|
| **14:16:00** | DefenderCheck.exe created via SMB | Sysmon File Create | 11 |
| **14:16:05** | DefenderCheck.exe executed | Sysmon Process Create | 1 |
| **14:16:06** | DefenderCheck.exe → WMI query (if logged) | WMI-Activity | 5860 |
| **14:16:08** | DefenderCheck.exe exits | Sysmon Process Terminate | 5 |
| **14:16:15** | SharpBlock.exe created | Sysmon File Create | 11 |
| **14:16:20** | SharpBlock.exe executed | Sysmon Process Create | 1 |
| **14:16:22** | amsi.dll patched in-memory | (No native log; memory forensics only) | — |
| **14:16:25** | SharpBlock.exe exits | Sysmon Process Terminate | 5 |
| **14:16:30** | PowerShell payload executed (bypasses AMSI) | PowerShell / Sysmon | (depends on payload) |

---

## Detection Avoidance Techniques Observed

### Living-Off-The-Land Alternatives

Sophisticated operators may avoid staging DefenderCheck.exe by using built-in tools instead:
```powershell
# Instead of DefenderCheck.exe:
Get-Service | Where-Object {$_.DisplayName -match "Defender|Sentinel|CrowdStrike"}
Get-WmiObject -Class Win32_Product | Select-Object Name, Version
# Same reconnaissance, no external tool artifact
```

### In-Process Injection

SharpBlock may be injected directly into a process (e.g., PowerShell) rather than executed as a child process:
```cpp
// No new process created; amsi.dll patched within existing powershell.exe
// Sysmon 1 event shows only powershell.exe, not SharpBlock.exe as child
```

This eliminates the Sysmon Process Create event for SharpBlock itself.

