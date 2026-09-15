# WinDbg — Target Evidence

## Process artifacts (target host)

### WinDbg attachment (live debugging)

**Evidence:** Process creation and relationship logs

When an attacker attaches WinDbg to a running process for live debugging:

| Artifact | Details |
|---|---|
| **Sysmon Event 1 (Process Create)** | Parent: user login process, explorer.exe, or cmd.exe; Image: `windbg.exe` or `WinDbgX.exe`; Command line contains `-p <PID>` or target process name |
| **Sysmon Event 10 (Process Access)** | Source: `windbg.exe`; Target: the target process being debugged; Granted Access: `0x1fffff` (debug access) or `0x0410` (query + read). **Note:** Debugger attachment requires `PROCESS_VM_READ` + `PROCESS_VM_WRITE` access (0x0410 and 0x0020) |
| **Sysmon Event 3 (Network Connection)** | Only if remote debugging is used (`-remote tcp:Port=...`). Source: windbg.exe; Destination: debug server IP:port. For local debugging (most common), no network connection. |
| **Debugger object handle** | The target process remains under debugger control (`DEBUG_PROCESS` flag), which manifests as an unusual parent-child relationship in process monitoring tools (child shows parent as `windbg.exe` even if launched elsewhere) |

### Process tree anomaly (debugger as unexpected parent)

**Evidence:** Process hierarchy

- Normal: `explorer.exe` → `cmd.exe` → `notepad.exe`
- Under debugger: `windbg.exe` → `notepad.exe` (if WinDbg launched the process directly)
- Or: `explorer.exe` → `cmd.exe` → `notepad.exe` (with `notepad.exe` showing debugger handle to `windbg.exe` in handle table)

**Forensic weight:** **Medium** — an unexpected debugger parent is suspicious, but task automation or legitimate debugging could explain it.

---

## Memory and crash dump artifacts (target host)

### Crash dump generation

**Evidence:** Filesystem evidence on the target

- **Minidump directory:** `C:\Windows\Minidump\` (if crash dumps are enabled)
- **Filename:** `<ProcessName>.<ProcessID>.dmp` or Windows-generated timestamp naming
- **Trigger:** Manual creation via operator (e.g., ProcDump, debugger UI), **not** a system-automatic artifact unless the target is a service crash.

**Forensic weight:** **High** — deliberate dump generation indicates targeted analysis.

### Memory contents (if dump is captured by blue team)

**Evidence:** Artifacts visible in a memory dump captured by defensive tools

- **WinDbg breakpoint state:** If the target was paused at a breakpoint, the instruction pointer will point to the breakpoint address (the breakpoint instruction itself, `0xcc` in x86, `int3`).
- **Debug registers:** x86/x64 debug registers (`DR0`-`DR3`) may contain addresses of data breakpoints set by the debugger.
- **Loaded modules:** Symbols and debugging information, if debugged with symbols, leave evidence in the module list and memory layout.

**Forensic weight:** **Medium** — memory evidence is useful to blue teams but not to the attacker (they control the debugging session).

---

## Event logs (target host)

### Sysmon events related to debugger attachment

| Event ID | Details | Forensic Weight |
|---|---|---|
| **Sysmon 1 (Process Create)** | `windbg.exe -p <PID>` or direct process launch by debugger. Correlate with the target process's own creation time. | **High** |
| **Sysmon 10 (Process Access)** | Source process opens a handle to the target with debug access (`0x1fffff`). **Caveat:** Legitimate tools (profilers, .NET runtime) also request debug access. | **Medium** (could be legitimate) |
| **Sysmon 3 (Network Connection)** | Only if remote debugging is used. `windbg.exe` connecting to a debug server port (e.g., `localhost:5005` for local, or remote IP for network debugging). | **High** if remote; **zero** if local |

### Windows Security Event Log

| Event ID | Details |
|---|---|
| **4688 (Process Create)** | Standard Windows process-creation audit. Contains command line (e.g., `windbg.exe -p 1234`) if command-line auditing is enabled. | 
| **4689 (Process Terminate)** | Records when `windbg.exe` exits. |

**Forensic weight:** **Medium** — Windows Security logs confirm WinDbg execution but are not sensitive to debugger-specific behavior.

---

## Comparison with TTD vs. live debugging

### Live debugging (attaching to a running process)

**Target-side evidence:**
- ✅ Debugger attachment visible in process handles
- ✅ Process paused/halted (if breakpoint hit or Ctrl+Break pressed)
- ✅ Unusual parent-child relationship (windbg.exe → target process)
- ⚠️ Memory contents modified if operator edits registers/memory
- ⚠️ Network connection if remote debugging used

### TTD recording (recording from process launch)

**Target-side evidence:**
- ⚠️ **Minimal to none** — TTD recording occurs on the **source/attacker host**, not the target
- If the target process is launched with TTD recording, the recording files (`.run`, `.idx`) are stored on the **attacker's machine**, not the target
- **Exception:** If the process crashes and generates a crash dump on the target, that dump may correlate with a TTD trace on the attacker's host via timestamps

**Key distinction:** TTD is an offline technique. The target host sees only normal process execution; all analysis occurs on the attacker's host.

---

## Network artifacts (if remote debugging used)

### Remote debugging connection (target as a debug server)

**Evidence:** Network logs from the target's perspective

| Artifact | Details |
|---|---|
| **Inbound TCP connection** | Attacker's IP connects to target on a debug port (default 5005, or operator-chosen). Protocol: raw TCP (not HTTP/HTTPS). |
| **Firewall rules** | Remote debugging requires the target to allow inbound traffic on the debug port. This would need to be explicitly configured (not default). |
| **Network intrusion detection** | A persistent TCP connection from an external IP to a debug port is a strong indicator of remote debugging. |

**Forensic weight:** **Critical** if remote debugging is active. **Zero if TTD is used** (most common red-team scenario).

---

## Service / driver-specific artifacts (if debugging kernel or service)

### Kernel-mode debugging (serial/USB/network)

**Evidence:** Hardware/network setup and event logs

- **Serial/USB connection:** Physical connection between two machines. Evidence is the hardware setup itself (if recovered).
- **Kernel debugger boot flag:** `bcdedit /debug on` sets a registry flag. Blue team can check: `reg query HKLM\BCD00000000 | findstr debug`
- **KD (Kernel Debugger) protocol traffic:** If network kernel debugging is used, the network connection uses Microsoft's KD protocol (not standard HTTP/RPC).

**Forensic weight:** **High** for kernel debugging setup (it's not default and requires intentional configuration).

### Windows service debugging

**Evidence:** If debugging a Windows service (e.g., `svchost.exe`)

- **Service Manager reflection:** The Services.exe component may reflect that the service is under debugger control (unusual state, not running normally).
- **Service hang/pause:** If the debugger breaks at a breakpoint inside a service, the service will appear hung to clients trying to communicate with it.
- **Event log:** Service-specific event logs (e.g., for IIS, MSSQL) may show unexpected pauses or missing heartbeats.

**Forensic weight:** **High** if service appears hung during the timeframe of the attack.

---

## Timeline analysis: correlating source and target evidence

### Scenario 1: Live debugging → crash

```
Timeline:
2026-08-11 14:30:00 — Attacker launches: windbg.exe -p <victim-process-PID>
2026-08-11 14:30:05 — Target: Victim process paused at first breakpoint
2026-08-11 14:30:15 — Target: Exception occurs (attacker steps into bad code)
2026-08-11 14:30:20 — Target: Process crashes (EXCEPTION_ACCESS_VIOLATION)
                      Crash dump generated: C:\Windows\Minidump\<process>.dmp

Later analysis:
2026-08-11 14:31:00 — Attacker: Opens crash dump in WinDbg (!analyze -v)
2026-08-11 14:32:00 — Attacker's host: TTD trace file created (if TTD was enabled)
                      Files: <process>.run, <process>.idx in C:\Users\...\Documents\
```

**Correlation signals:**
- Timestamps of crash dump and TTD trace files on attacker's host
- WinDbg process creation in Sysmon on both attacker and target hosts
- Process handle opening from windbg.exe to victim process on target
- Exception event in target's event logs at crash time

### Scenario 2: TTD recording of exploit development (no target interaction)

```
Timeline:
2026-08-11 10:00:00 — Attacker: windbg -record exploit_payload.exe
2026-08-11 10:00:30 — Attacker: Exploit runs, injects shellcode, privilege-escalation attempt
2026-08-11 10:00:40 — Attacker: Process crashes; TTD recording stops (Ctrl+Break)
                      Files: exploit_payload.run, .idx saved locally

Target host: **Zero suspicious artifacts** (no network traffic, no process attachment)

Later:
2026-08-11 10:30:00 — Attacker: windbg -replay exploit_payload.run
2026-08-11 10:45:00 — Attacker: Exfiltrates exploit_payload.run via SMB to cloud storage
                      Network: SMB traffic to (attacker IP):(ephemeral port)
                               → (cloud storage IP):(445)
```

**Correlation signals:**
- Target: No direct evidence of the TTD recording
- Attacker: TTD trace files exist on disk
- Attacker: Network traffic exfiltrating large files (if traces are copied off-network)

---

## Hunting queries (on target host)

### Detect WinDbg attachment

```powershell
# Find process handles opened by windbg.exe
Get-Process -Name windbg -ErrorAction SilentlyContinue | ForEach-Object {
    # List all open handles for windbg.exe
    # (Requires NirSoft Handle.exe or similar tool)
    # or via WMI:
}

# Alternative: detect via Sysmon Event 10 (Process Access)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=10
} | Where-Object { 
    $_.Message -match 'windbg' -and 
    $_.Message -match '0x1fffff|0x0410|PROCESS_VM_READ'
} | Select-Object TimeCreated, Message
```

### Detect remote debugging server listening

```powershell
# Check if any process is listening on a debug port (e.g., 5005)
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq 5005 }

# Or check process handles (debug server would have a listening socket)
netstat -ano | findstr :5005
```

### Detect kernel debugging setup

```cmd
# Check if kernel debugging is enabled
reg query HKLM\BCD00000000 | findstr /i debug

# or
bcdedit | findstr /i debug
```

