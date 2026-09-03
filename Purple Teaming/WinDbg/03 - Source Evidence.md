# WinDbg — Source Evidence

## Process artifacts on the operator's host

### WinDbg process and window traces

**Evidence:** Process creation event (Sysmon event 1, Windows Security event 4688)

- **Parent process:** `explorer.exe`, `cmd.exe`, or automation script (if launched manually or via script)
- **Process name:** `windbg.exe` (or `WinDbgX.exe` on modern installations)
- **Command line:** Contains the target process name, PID, or dump file path (e.g., `windbg.exe -p 1234`, `windbg.exe -dump crash.dmp`, `windbg.exe -record malware.exe`)
- **Forensic weight:** **High** — WinDbg is not a Windows native utility, so its execution is clearly intentional for debugging/analysis work.

### TTD trace files (`.run`, `.idx`)

**Evidence:** Filesystem artifacts on the operator's host

- **Default location:** `C:\Users\<User>\Documents\`
- **File naming:** `<ProcessName>.run` and `<ProcessName>.idx` (e.g., `malware.run`, `malware.idx`)
- **File size:** `.run` file is typically 10-20x the size of a normal memory dump (e.g., 100 MB - 5 GB for a few minutes of recording). `.idx` is typically 2x the `.run` file size.
- **Format:** Proprietary Microsoft format; no public specification. Files are not encrypted.
- **Forensic weight:** **Critical** — TTD traces are deterministic, byte-exact recordings of process execution. Their presence indicates:
  - Exploit development or testing (payload validation)
  - Crash analysis (vulnerability research)
  - Behavior introspection (malware reverse engineering)
  - The attacker was actively debugging/analyzing something on their own system

**Timeline consideration:** If TTD traces exist alongside crash dumps or payload binaries, they can be temporally correlated — e.g., if a trace file's modification time aligns with a crash dump, the attacker was likely analyzing that specific crash.

### Crash dump files (`.dmp`)

**Evidence:** Filesystem artifacts on the operator's host

- **Generation method:** Manually generated (via ProcDump, Windows crash dump service, or debugger UI), not a system-automatic artifact.
- **File location:** Operator-chosen (common: `C:\Temp\`, `%TEMP%`, Downloads, Documents)
- **File naming:** Variable; ProcDump uses format `<ProcessName>.<PID>.dmp` or operator-custom names.
- **File size:** Minidump (compressed): 1-50 MB; full dump (uncompressed): 1-10 GB+ (depends on process VM size)
- **Forensic weight:** **High** — presence of a crash dump indicates the attacker was analyzing a crash or collecting process state for offline analysis.

**Artifact recovery:** Deleted dump files may be recoverable via file-carving tools (looks for MZ header or MINIDUMP_HEADER structures `MDMP`).

### WinDbg command history / .dbgrc scripts

**Evidence:** Configuration files and command history

- **Location:** `%USERPROFILE%\.dbgrc` (if configured) or stored per-session.
- **Contents:** Previous commands, breakpoint definitions, script paths.
- **Forensic weight:** **Medium** — reveals what the operator was debugging (function names, memory addresses, symbol tables) and what analysis they were performing.

### PDB symbol files (`.pdb`)

**Evidence:** Downloaded or cached symbol files

- **Location:** Typically in `C:\Symbols\` or a custom symbol cache directory configured via `.symfix` or `-symbols`.
- **Presence:** If the operator downloaded symbols for a target binary, the `.pdb` files are evidence they were analyzing that binary (rather than just running it).
- **Forensic weight:** **Medium** — indicates deliberate reverse-engineering of a specific binary, not accidental execution.

### Shell history / command line history (`.history`)

**Evidence:** Command-line execution history

- **Windows 10+ PowerShell:** `Get-PSReadlineOption | Select -ExpandProperty HistorySavePath`
- **Typical path:** `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
- **Contents:** If the operator used PowerShell or cmd to invoke `windbg.exe`, the full command line is logged.
- **Example:** `windbg.exe -p 1234` or `windbg -record exploit.exe` appears in history.
- **Forensic weight:** **High** — shell history is persistent across reboots and captures the exact command-line syntax used to launch WinDbg.

## Network artifacts (local machine)

**Note:** Live debugging with remote connectivity can generate network artifacts, but TTD recording (the most common operator workflow) is **offline** — no network calls occur during TTD recording itself. Exfiltration of traces, however, would generate network traffic.

### Remote debugging connections

**Evidence:** Network connection logs (Sysmon event 3, Windows NetFlow, firewall logs)

- **If the operator used remote debugging (`-remote tcp:Port=...`):**
  - Source: `<AttackerIP>:<EphemeralPort>` (client)
  - Destination: `<TargetIP>:5005` (or operator-chosen port, default port 5005)
  - Protocol: TCP
  - Process: `windbg.exe` or `WinDbgX.exe`

- **If the operator connected to a remote kernel debugger (`-k ...`):**
  - Traffic pattern depends on the kernel debugging transport (serial is physical-only, USB is physical, network requires specialized setup).
  - Network kernel debugging (if enabled) uses `kdnet.dll` and a custom RPC protocol (not HTTP/HTTPS).

- **Forensic weight:** **Critical** if remote debugging is used — the connection is a direct link from the operator's host to the target, timestamped in network logs. **Zero weight if TTD is used locally** (most common case), since TTD is offline recording.

### Exfiltration of TTD traces

**Evidence:** Network traffic during file transfer

- If the operator exfiltrates a TTD trace file (`.run` + `.idx`) off the network via SMB, HTTP, FTP, etc.:
  - **Protocol:** Variable (SMB, HTTP POST, scp, etc.)
  - **Source:** `<AttackerIP>:<EphemeralPort>`
  - **Destination:** `<ExfilIP>:<Port>` (cloud storage, attacker-controlled server, etc.)
  - **Payload size:** Large (100 MB - 5 GB+), making file-size-based anomaly detection possible.
  - **Process initiating transfer:** `explorer.exe` (UI drag-drop), `powershell.exe` (script), `curl.exe`, `wget.exe`, etc.

- **Forensic weight:** **Critical** — evidence of deliberate data exfiltration for offline analysis.

## Memory artifacts

### WinDbg process memory

**Evidence:** Live memory inspection of the debugger process itself

- **If an incident responder captures memory while WinDbg is running:**
  - The WinDbg process memory may contain fragments of the debugging session state (breakpoints, symbols, command history, references to the target process).
  - Less useful than TTD traces (which are the data the operator intentionally captured), but confirmatory.

## Correlation with target evidence

**Timeline correlation:**

1. If a **TTD trace** exists on the operator's host with a modification time of `2026-08-11 14:30:00`, and a **Windows event log** on the target host shows process launch at `2026-08-11 14:25:00` → the operator was likely recording that exact process execution.

2. If a **crash dump** exists alongside a **TTD trace**, both timestamped within minutes of each other, the operator was likely analyzing the crash interactively (live debugging → crash → dump generation → TTD replay).

3. If **shell history** shows `windbg.exe -p <PID>` and **Sysmon event logs** on the target show that process launching at approximately the same time, the operator's attack can be temporally aligned with the target's activity.

---

## Search queries (PowerShell, on attacker host)

### Find WinDbg process history

```powershell
# Search for WinDbg in Process Creation events (if Sysmon logging is enabled)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=1
} | Where-Object { $_.Message -match 'windbg' }

# Alternative: search recent file access
Get-ChildItem -Path "C:\Users\*\Documents" -Filter "*.run" -Recurse
Get-ChildItem -Path "C:\Users\*\Documents" -Filter "*.idx" -Recurse

# Search command line history
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | Select-String "windbg"
```

### Find TTD traces

```powershell
# Search for TTD trace files (.run, .idx)
Get-ChildItem -Path "C:\Users" -Filter "*.run" -Recurse -Force
Get-ChildItem -Path "C:\Users" -Filter "*.idx" -Recurse -Force

# Check temp directories
Get-ChildItem -Path "$env:TEMP" -Filter "*.run" -Recurse -Force

# Find large files (TTD traces are typically large)
Get-ChildItem -Path "C:\Users\*\Documents" -Recurse | Where-Object { $_.Length -gt 100MB }
```

### Find crash dumps

```powershell
# Search for .dmp files
Get-ChildItem -Path "C:\Users" -Filter "*.dmp" -Recurse
Get-ChildItem -Path "C:\Windows\Minidump" -Filter "*.dmp" -Recurse

# Check by modification time (within a specific range)
Get-ChildItem -Filter "*.dmp" -Recurse | Where-Object { $_.LastWriteTime -gt '2026-08-10' -and $_.LastWriteTime -lt '2026-08-12' }
```

