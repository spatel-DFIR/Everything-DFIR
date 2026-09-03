# WinPEAS — Target Evidence

Target evidence refers to artifacts left on the **Windows host where WinPEAS executes**. WinPEAS is primarily a read-only enumeration tool — it queries registry, filesystem, and process APIs but does not modify system state for its own execution. Evidence is therefore minimal but highly actionable for timeline correlation.

## Process Execution & Artifact

### WinPEAS.exe Process Creation

| Artifact | Detail | Detection Strength |
|---|---|---|
| **Sysmon Event 1 (Process Creation)** | Parent: `cmd.exe`, `powershell.exe`, `rundll32.exe` (C2), or `explorer.exe` (direct launch); CommandLine: `C:\Temp\WinPEAS.exe` or `"C:\Windows\Temp\svchost.exe"` (renamed) | **High** if using original binary name; **lower** if renamed (but PE metadata survives). |
| **Event 4688 (Process Audit)** | Subject: logged-in user; New Process: `WinPEAS.exe`, `svchost.exe`, or other rename; Command Line includes full path and any flags | **High** but requires Process Audit policy enabled (default: off on Win10/11, on on server). |
| **Process object created** | Image name, PID, parent PID, command line, access rights requested | Visible in live process enumeration (Task Manager, Sysmon) while running. |

### PowerShell Script Execution (if .ps1 variant)

| Artifact | Detail | Detection Strength |
|---|---|---|
| **Event 4104 (Script Block Logging)** | Full PowerShell script content logged if enabled; requires non-default PS logging configuration (Group Policy or local PS execution policy) | **Very High** if enabled (5.0+, Server 2016+). Script content is captured unobfuscated. Unlikely to be on by default unless organization is security-conscious. |
| **Event 4105 (Engine Lifecycle)** | Script engine start/stop; less granular than 4104 | **Medium** — shows PowerShell invocation but not the script content. |
| **PowerShell process creation** | `powershell.exe` spawned as child of `cmd.exe` or C2 agent; CommandLine may show `-File`, `-Command`, or `-EncodedCommand` | **High** if command line is captured in full. |

## File System Artifacts

### Temporary Files

| Artifact | Location | Lifetime | Detail |
|---|---|---|---|
| **WinPEAS.exe binary** | `%TEMP%\WinPEAS.exe`, `%TEMP%\svchost.exe`, `C:\Users\<user>\AppData\Local\Temp\...` | Often deleted after execution (C2 cleanup) or left in place | Plaintext PE file; can be recovered from unallocated disk space even if deleted. PE metadata (FileDescription, InternalName) unambiguously identifies it. |
| **WinPEAS output file** | `%TEMP%\winpeas_output.txt`, `C:\Temp\winpeas_report.html` (if `-html` flag used) | Operator-defined; often exfiltrated or deleted | Contains enumeration findings; file size ~100–500 KB. Presence proves WinPEAS execution and enumeration success. |
| **Powershell script source** (if saved) | `%TEMP%\winpeas.ps1` | Temporary; usually deleted | Plaintext script; identifiable via content hash or string matching. |

**Timeline value:** File creation/modification timestamps indicate when WinPEAS was staged and executed.

## Registry Artifacts

### HKEY_LOCAL_MACHINE Registry Access

WinPEAS reads (but does not modify) the following registry hives — evidence comes from access auditing only, not artifact persistence:

| Registry Path | Why WinPEAS Reads It | Detection Signal |
|---|---|---|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` | Identifies persistence mechanisms (startup programs) | Registry access logs (if audited via FIM or Registry Access auditing) |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Svchost` | Enumerates service host processes | Registry read event (no persistent change) |
| `HKLM\System\CurrentControlSet\Services` | Enumerates all installed services, ImagePath, Start type, object account | Registry read event |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System` | Reads UAC settings (EnableUIAccess, ConsentPrompt, FilterAdministratorToken) | Registry read event |
| `HKLM\Security\SAM` | Attempts to read cached hashes (requires SYSTEM/admin) | Registry read event; denied if permissions prevent access |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths` | Identifies known application executables and their paths | Registry read event |
| `HKLM\Software\Classes\CLSID` | Enumerates COM objects; particularly LocalServer32 (executables registered as COM) | Registry read event |

**Detection evasion:** WinPEAS leaves **no registry modifications** — it only reads. If registry auditing is enabled, the reads are visible; if not, there's no persistent artifact. This is a strong defense: an analyst cannot detect WinPEAS by looking for modified registry state — only by observing the reads themselves (requires live monitoring, Sysmon, or full audit logging).

### HKEY_CURRENT_USER Registry Access (per-user data)

| Registry Path | Why WinPEAS Reads It |
|---|---|
| `HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store` | Identifies DLL/binary execution history |
| `HKCU\Software\Microsoft\Internet Explorer\TypedURLs`, `Chrome\User Data\*` | Looks for browser history (minimal — focused on browsed IPs/domains that might be targets) |

**No evasion impact:** These are per-user keys with minimal impact on escalation — WinPEAS reads them for context, not critical findings.

## Event Log Artifacts

### Windows Event Viewer

| Event Source | Event ID | When Fired | Captured Data |
|---|---|---|---|
| **Security** | 4688 | Process Audit enabled | Process creation: image, command line, user, parent process. Shows `WinPEAS.exe` execution, any flags. |
| **Security** | 4662 | Audit Directory Service Changes enabled | Uncommon for WinPEAS (no AD reads), but if the system is an AD member and WinPEAS queries group policy, might fire. |
| **Sysmon** | 1 | Process Creation | Full process tree, including parent-child relationships. WinPEAS → child processes (registry reader, file scanner). |
| **Sysmon** | 11 | File Created | Files dropped to disk (WinPEAS.exe, output files). Timestamp matches execution. |
| **Sysmon** | 13 | Registry Value Set | Not fired by WinPEAS (read-only); only if WinPEAS output triggers a follow-on exploitation. |

**Typical absence:** Many systems have event logging disabled (particularly security-light Windows 10 home editions). Organizations and servers have more logging. Default Windows 10/11 has **Process Audit disabled** — Event 4688 won't fire unless explicitly enabled via Group Policy.

## Network Activity

### Network Evidence (If Monitored)

| Activity | Detail | When Occurs |
|---|---|---|
| **DNS queries for C2** | WinPEAS itself makes no network calls; traffic is associated with C2 callback delivering the tool | When C2 agent calls home with execution output (Beacon→TeamServer, Sliver→Listener, Empire→RESTful API) |
| **SMB/RPC queries** (if WinPEAS queries remote hosts) | Uncommon (WinPEAS is local-only); only if a custom variant queries remote services | Rare in standard WinPEAS |
| **File exfiltration** | Output file egress via C2 or SMB share copy | When operator exfils WinPEAS output; high volume (100-500 KB) |

**Signature:** WinPEAS.exe itself has **zero outbound network capability** — all network activity is from the C2 agent or the delivery framework. This is a strong operational security feature: no domain query, no LDAP, no beacon home. Defenders cannot detect WinPEAS by network IOC.

## Memory Artifacts

### Volatile Memory (RAM)

| Artifact | Location | Significance |
|---|---|---|
| **WinPEAS.exe in process memory** | Virtual address space of `WinPEAS.exe` process (if still running or recently exited) | Full binary (if dump taken while running); deallocation clears it immediately after process exit |
| **Heap contents** | .NET/CLR heap inside WinPEAS.exe process | Registry query results, file enumeration results, cached in memory while WinPEAS runs |
| **Handles** | Open file handles, registry handles by WinPEAS | Visible via `Get-Process -Id <PID> | Select Handles` or `Handle.exe` (Sysinternals); shows HKEY_LOCAL_MACHINE path references |

**Operational impact:** If WinPEAS runs for 20–40 minutes, memory is visible to dumping tools (procdump.exe, `Out-MinidumpFiles.ps1`). After process exit, memory is freed (unless attacker has secured a memory dump beforehand).

## Detection / Hunting Priority Table

| Rank | Signal | Evasion Survivability | Confidence | Method |
|---|---|---|---|---|
| **1** | **PE Metadata** (FileDescription, ProductName, CompanyName in `.exe`) | ❌ Survives renaming only if not recompiled; recompilation required to change | **Very High** | `Get-Item C:\Temp\*.exe \| Select-Object VersionInfo`; look for "WinPEAS" or "Privilege Escalation" in Description |
| **2** | **Process Audit Event 4688** (if enabled) | ❌ Survives renaming; command line visible | **High** | Event Viewer → Security → Event 4688; filter for `powershell.exe` + `IEX` or `WinPEAS.exe` |
| **3** | **Sysmon Event 1** (Process Creation) | ❌ Survives renaming; full command line | **High** | Sysmon XML log → search for parent-child (C2 agent → PowerShell → WinPEAS or direct C2 → WinPEAS.exe) |
| **4** | **Output file** (Registry reads + file creation correlation) | ✅ Operator deletes file; careful cleanup removes artifact | **Medium** | File timeline analysis: file creation timestamp correlates with process execution event |
| **5** | **Sysmon Event 11** (File Created) | ✅ If file deleted, only recoverable from unallocated disk | **Medium** | Sysmon XML; file path + timestamp (e.g., `C:\Temp\WinPEAS.exe`, `%TEMP%\winpeas_output.txt`) |
| **6** | **PowerShell Event 4104** (Script Block Logging) | ❌ Full script content logged; obfuscation unwound | **Very High** (if enabled) | Event Viewer → Windows PowerShell → Event 4104; check for `IEX` + script content |
| **7** | **YARA / Fuzzy Hashing** (.exe binary pattern match) | ✅ Recompilation + obfuscation defeats static signatures | **Medium** | YARA rule: search for known WinPEAS function patterns (if not recompiled); PE-hash matching (if not rebuilt) |

### Recommended Hunt Commands

#### PowerShell (local hunt on suspect system):
```powershell
# Hunt 1: Find WinPEAS executables by name
Get-ChildItem -Path C:\Temp, $env:TEMP, C:\Windows\Temp -Filter "*WinPEAS*" -Recurse -File

# Hunt 2: Find process with PE metadata "WinPEAS"
Get-Process | Where-Object { $_.MainModule.FileVersionInfo.ProductName -like "*WinPEAS*" }

# Hunt 3: Look for recent PowerShell script executions (Event 4104)
Get-WinEvent -LogName "Windows PowerShell" -FilterXPath "*[System[(EventID=4104)]]" | Select-Object -First 10 | Format-Table TimeCreated, Message

# Hunt 4: Check for output files in temp
Get-ChildItem -Path $env:TEMP -Filter "*winpeas*" -File | Select-Object FullName, CreationTime, LastWriteTime

# Hunt 5: Search for Sysmon process events (WinPEAS execution)
Get-WinEvent -LogName "Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]] and *[EventData[Data[@Name='Image'] and contains(., 'WinPEAS')]]" | Format-Table TimeCreated, Message
```

#### SIEM / Splunk Query:
```splunk
index=windows EventID=4688 OR (index=sysmon EventID=1)
| search Image="*WinPEAS*" OR CommandLine="*WinPEAS*" OR ParentImage="*powershell*" AND CommandLine="*IEX*"
| stats count by Image, CommandLine, TimeCreated, User
```

#### YARA Rule (if binary is recovered):
```yara
rule Detect_WinPEAS {
    meta:
        description = "Detects WinPEAS privilege escalation tool"
        author = "DFIR"
    strings:
        $pe_desc = "Windows Privilege Escalation Awesome" nocase
        $pe_name = "WinPEAS" nocase
        $mz = "MZ"
    condition:
        $mz at 0 and ($pe_desc or $pe_name)
}
```

## Timeline Building Walkthrough

**Scenario:** Analyst is investigating a suspected privilege escalation on a workstation. Goals: determine if WinPEAS was used and correlate with other indicators.

```
Step 1: Check for recent suspicious process execution
  └─ Event 4688 (or Sysmon 1): Look for "WinPEAS.exe" or "powershell.exe -File winpeas.ps1"
     Timestamp: 2026-08-11 14:22:15

Step 2: Correlate with C2 callback or tool staging
  └─ If Cobalt Strike: TeamServer logs show "execute-assembly" command at same time
     Timestamp: 2026-08-11 14:22:10 (5 seconds before execution)
  └─ If direct shell: Reverse-shell connection logs, bash history, or SSH auth logs
     Timestamp: 2026-08-11 14:15:00 (initial access)

Step 3: Check for output file creation
  └─ Sysmon Event 11 (File Created): "C:\Temp\WinPEAS.exe" at 2026-08-11 14:22:05
     (3 seconds before execution; staging delay)
  └─ Sysmon Event 11: "C:\Temp\winpeas_output.txt" created at 2026-08-11 14:23:45
     (90 seconds after execution; enumeration completed)

Step 4: Check for exfiltration
  └─ Network log: File transfer to attacker's IP (192.0.2.1) at 2026-08-11 14:24:30
     File size: 287 KB (matches WinPEAS output size)

Step 5: Correlate with follow-on exploitation
  └─ Sysmon Event 1: "C:\Windows\Temp\Potato.exe" (or other escalation tool) at 2026-08-11 14:25:00
     (after WinPEAS output indicates SeImpersonate available)

Timeline Summary:
  14:15:00 ✓ Attacker gains initial access (Responder/phishing/web shell)
  14:22:05 ✓ WinPEAS.exe staged to temp
  14:22:15 ✓ WinPEAS.exe executed
  14:23:45 ✓ WinPEAS output file created (enumeration complete)
  14:24:30 ✓ Output exfiltrated
  14:25:00 ✓ Exploitation tool (Potato family) staged and executed
  14:26:00 ✗ Privilege escalation succeeds; SYSTEM shell gained
```

**Investigator conclusion:** WinPEAS was the recon tool, findings identified SeImpersonate as exploitable, and Potato family succeeded in escalation. The 2-minute delay between WinPEAS output and Potato execution suggests operator manual triage (read WinPEAS output, pick exploitation path) rather than fully automated orchestration.

