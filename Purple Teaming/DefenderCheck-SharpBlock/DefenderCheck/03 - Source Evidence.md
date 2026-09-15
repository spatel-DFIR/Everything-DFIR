# DefenderCheck — Source Evidence

**Where to look on the attacker/operator host for DefenderCheck usage.**

## File Presence

### DefenderCheck.exe itself
| Location | Likelihood | Persistence | Notes |
|---|---|---|---|
| `C:\Tools\`, `C:\Temp\`, `C:\Users\<user>\Downloads\` | High | None (may be deleted post-use) | Most common staging locations; easily deleted or moved. |
| Portable media (USB, SD card) | Medium | None on target host | Tool may be staged on removable media to avoid disk artifacts on the target. |
| AppData roaming/local | Low | If staged for repeated use | Unlikely; DefenderCheck is not typically installed, only run on-demand. |
| GitHub clone / source repo | Medium | None (source code only) | If operator cloned the repo from github.com/matterpreter/DefenderCheck, the source may exist locally for compilation. |

### Compiled DefenderCheck binaries (multiple versions)
If the operator compiled DefenderCheck from source multiple times with different flags or .NET Framework targets, multiple `.exe` files may exist (e.g., `DefenderCheck_x86.exe`, `DefenderCheck_x64.exe`, `DefenderCheck_release.exe`).

---

## Process Execution & Command-Line Evidence

### Process Tree
```
cmd.exe (or PowerShell.exe)
  └─ DefenderCheck.exe <binary_path> [debug]
```

**Expected command line examples:**
```
DefenderCheck.exe C:\Temp\beacon.exe
DefenderCheck.exe C:\Tools\payload.exe debug
DefenderCheck.exe \\<UNC_path>\malware.bin
```

### Event Log Artifacts
- **Windows Event Log: Security (Event ID 4688 - Process Creation)**
  - Process name: `DefenderCheck.exe`
  - Command line: contains the target binary path (e.g., `beacon.exe`, `payload.dll`)
  - Parent process: `cmd.exe` or `powershell.exe` (typically).
  - **Huntable pattern:** `CommandLine CONTAINS "DefenderCheck.exe"`

- **Windows Event Log: System (Event ID 1000 - Application Error)**
  - If DefenderCheck crashes or throws an exception, the error may be logged here.
  - May reveal the exact binary being scanned in the crash dump path.

- **Windows Event Log: Windows Defender/Security (Event ID 1116, 1117, 1118, etc.)**
  - DefenderCheck's own invocation of Defender's scanning engine may trigger Defender event logs.
  - Event ID 1001: Threat detected (`Type: VirTool:MSIL/BytzChk` if DefenderCheck itself is flagged).
  - Event IDs 1006–1009: Scan results (may show the target binary being scanned).

---

## Temporary Files (Short-Lived Artifacts)

### C:\Temp\ directory activity

DefenderCheck creates test files in `C:\Temp\` during binary splitting. Each iteration creates a file with the target binary's subset of bytes, tests it, then deletes it. **These files are cleaned up automatically** after the tool completes, but transient evidence may exist:

- **File system journal (`$Usn$J`)**: Forensic artifact tracking file creation and deletion in NTFS. Recovered files may show:
  - Rapid file creation/deletion cycles (e.g., 100+ test files created and deleted in seconds).
  - Filenames resembling the original target (e.g., `beacon.exe.tmp.001`, `beacon.exe.tmp.002`, etc.).
  - File size progression (smaller chunks created iteratively).

- **Unallocated file system clusters**: If the file system didn't immediately reclaim space, deleted `C:\Temp\` files may be recoverable via carving tools.

- **$MFT (Master File Table) records**: Even after deletion, `$MFT` may retain records of file entries that were removed, showing creation/modification timestamps.

**Example forensic artifact:**
```
$MFT Entry: 123456
Filename: C:\Temp\beacon_chunk_001.bin
Created: 2024-01-15 14:23:45.123
Modified: 2024-01-15 14:23:45.456
Deleted: 2024-01-15 14:23:46.789
Allocated: NO (file deleted)
```

### Prefetch files

Windows creates `.pf` (Prefetch) files for executed binaries to speed up future launches. The `C:\Windows\Prefetch\` directory may contain:
- `DEFENDERCHECK.EXE-<hash>.pf` — evidence that DefenderCheck was executed.
- Within the `.pf` file: referenced DLLs, execution timestamps, run count.

**Huntable:** Query `C:\Windows\Prefetch\` for `.pf` files with "DefenderCheck" in the filename.

---

## Registry Evidence

### Defender disablement registry keys
DefenderCheck's prerequisite (disable Defender real-time protection) leaves registry traces:

| Key | Value | Expected Data | Notes |
|---|---|---|---|
| `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender` | `DisableRealtimeMonitoring` | DWORD: 1 | Group Policy; set to 1 to disable real-time protection. |
| `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection` | `DisableBehaviorMonitoring` | DWORD: 1 | Local policy override; disables behavior-based detection. |
| `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection` | `DisableOnAccessProtection` | DWORD: 1 | Disables on-access (file open/read) scanning. |

**Forensic Hunt:**
- Timestamp these registry keys' last-modified times.
- Correlate with DefenderCheck execution (via Event Log 4688).
- If a timestamp shows DisableRealtimeMonitoring was set, then DefenderCheck ran, then it was re-enabled — that's a suspicious pattern.

### Run history / Most Recently Used (MRU)
The `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` key may contain:
```
a: DefenderCheck.exe
b: cmd.exe /c C:\Tools\DefenderCheck.exe C:\Temp\payload.exe
...
```
(Only if the operator typed commands into `Run` dialog box, which is rare for DefenderCheck; more likely via `cmd.exe` or PowerShell directly.)

### AppData / Local paths
If DefenderCheck was run from a user's AppData or profile directory, the `Recently Used` registry keys may reference it:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
```

---

## Compilation & Build Artifacts

If the operator compiled DefenderCheck from source on the target host:

### Visual Studio / Compiler artifacts
- **`.sln`, `.csproj` files**: Solution/project files (if source was cloned from GitHub).
- **`bin\` / `obj\` directories**: Temporary compilation artifacts (deleted on clean build).
- **`DefenderCheck.exe`, `.pdb` files**: Debug symbols (if compiled in Debug mode).

**Locations:**
```
C:\Users\<user>\Desktop\DefenderCheck\
C:\Users\<user>\Downloads\DefenderCheck\
C:\Dev\DefenderCheck\
```

### GitHub clone history
If the operator cloned `github.com/matterpreter/DefenderCheck` locally:
```
C:\Users\<user>\Downloads\DefenderCheck\
  .git\               (Git repository metadata, including clone history, commits accessed)
  README.md
  DefenderCheck.sln
  DefenderCheck\
    Program.cs
    App.config
    DefenderCheck.csproj
  ...
```

**Forensic value:** The `.git` directory contains metadata (reflog, packed-refs) showing when and from where the repo was cloned.

---

## Script & Automation Evidence

### Batch / PowerShell scripts invoking DefenderCheck

If the operator created a batch or PowerShell script to automate DefenderCheck scanning (e.g., Use Case 3: Batch scanning variants):

**Batch script example:**
```batch
@echo off
for %%F in (C:\Payloads\*.exe) do (
    DefenderCheck.exe %%F > results_%%~nF.txt
)
```

**Locations to search:**
- `C:\Tools\scan_payloads.bat`
- `C:\Temp\scan.ps1`
- `C:\Users\<user>\Desktop\run_tests.bat`
- `%TEMP%\build.bat`

**Forensic evidence:**
- File metadata (creation time, modification time).
- File contents (shows the operator's workflow, target binaries, etc.).
- File system journal (if script was deleted).

### Log files from script output

If the script redirected output to a log file:
```batch
DefenderCheck.exe payload.exe > scan_results.txt 2>&1
```

**Locations:**
- `C:\Tools\scan_results.txt`
- `C:\Temp\defendercheck_log.txt`
- `C:\Users\<user>\Desktop\results_*.txt`

**Contents reveal:**
- Which binaries were scanned.
- Detection status for each binary.
- Hex offsets of flagged bytes (actionable for analysts trying to understand what the operator was evading).

---

## Network Evidence (Unlikely)

DefenderCheck does **not** perform network communication — it is a local analysis tool. However, if the operator:
- Downloaded DefenderCheck from GitHub via a web browser or `curl`/`wget`.
- Executed it via a payload delivery mechanism (e.g., executed from a C2 session).

Then network logs may show:
- **HTTP GET** to `github.com/matterpreter/DefenderCheck/releases/` (if fetching a pre-compiled binary).
- **HTTPS** connection to a C2 server, followed by DefenderCheck execution.

---

## Summary: Most Reliable Source Evidence

| Artifact | Reliability | Persistence | Forensic Value |
|---|---|---|---|
| **Event Log 4688 (Process Creation)** | High | Until log rotation (default 30 days) | Exact command line, timestamp, parent process. |
| **Prefetch file** | High | Until Windows prefetch purge (~1 month age) | Execution timestamp, DLL dependencies. |
| **File system journal ($UsnJrnl)** | High | Until journal rotation (varies, typically days) | Rapid file creation/deletion in C:\Temp\ (binary splitting signature). |
| **Defender/Security event log** | Medium | Until log rotation | May show flagged binaries scanned; Defender disabled event. |
| **Registry (DisableRealtimeMonitoring)** | High | Persistent (until re-enabled) | Timestamp correlates with DefenderCheck usage window. |
| **Batch/PowerShell scripts** | Medium | Until deletion | Shows operator's workflow, target binaries, automation strategy. |
| **Temporary files (C:\Temp\)** | Low | Until cleanup (auto-deleted by DefenderCheck) | Only recoverable via forensics; shows binary splitting artifacts. |
| **Executable on disk** | Medium | Until deletion | File hash, timestamps, digital signature (if signed). |

---

## Key Indicators for Hunters

**If you suspect DefenderCheck usage, correlate:**
1. **Event Log 4688**: Process named `DefenderCheck.exe` or `DefenderCheck` in command line.
2. **Registry**: `DisableRealtimeMonitoring = 1` with timestamp overlapping suspected activity window.
3. **Prefetch**: `DEFENDERCHECK.EXE-*.pf` file exists, with execution timestamp.
4. **File system**: Rapid file creation/deletion in `C:\Temp\` visible in `$UsnJrnl` (binary splitting pattern).
5. **Custom artifacts**: Batch scripts or log files referencing DefenderCheck or payloads.

**Absence of evidence ≠ evidence of absence**: DefenderCheck's auto-cleanup and lack of persistent registry/disk artifacts make it forensically minimal — its presence is most reliably detected via process execution logs and Defender policy changes, not leftover files.
