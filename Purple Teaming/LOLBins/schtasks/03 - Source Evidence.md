# LOLBins — schtasks.exe — Source Evidence

`schtasks.exe` is a native Windows binary, so — as with this module's `bitsadmin/` and `certutil/` entries — most of its **local** use cases have no separate "operator machine" distinct from the box the command ran on; that evidence is target-side and covered in `04 - Target Evidence.md`. `schtasks.exe` differs from those two siblings in one important respect: its `/s <computer>` switch makes **remote task creation a genuine two-host operation**, closer in shape to this module's Impacket `psexec`/`wmiexec`/`smbexec` entries than to a local-only download primitive. This file covers what the **issuing/attacker host** leaves behind for that remote-creation use case, plus the thinner local-use and C2-tasking-layer evidence classes that apply either way.

## Contents
- [Command History on the Issuing Host](#command-history-on-the-issuing-host)
- [Process and Command-Line Evidence on the Issuing Host](#process-and-command-line-evidence-on-the-issuing-host)
- [Network Connection State on the Issuing Host](#network-connection-state-on-the-issuing-host)
- [Credential Material Exposure](#credential-material-exposure)
- [C2 Tasking Layer](#c2-tasking-layer)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Command History on the Issuing Host

| Artifact | Location | Notes |
|---|---|---|
| `cmd.exe` history | Not persisted to disk by `cmd.exe` itself — only in-session via `doskey /history`, lost on process exit | Unlike PowerShell, a plain `cmd.exe`-issued `schtasks` command line leaves no native on-disk history of its own; rely on process-creation logging (below) instead |
| PowerShell console history | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | If the operator ran `schtasks.exe` from a PowerShell prompt (directly or via `Start-Process`/`&`), the full command line — including any inline `/p`/`/rp` password argument — persists here across sessions, unlike `cmd.exe`'s history |
| Batch/script files on disk | Wherever the operator staged a `.bat`/`.ps1` wrapper around the `schtasks` invocation | If the remote-creation command was scripted rather than typed interactively, the script file's own filesystem timestamps and content are recoverable exactly like any other dropped file on that host |

## Process and Command-Line Evidence on the Issuing Host

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)schtasks(\.exe)?\s.*(/create|/s\s)' }
```

If Sysmon or Security 4688 (with command-line auditing enabled) is present on the **issuing** host, this is the most direct evidence: the full `schtasks.exe /create /s <target> ...` command line, including the target host/IP, task name, `/tr` payload path, and (if used inline rather than prompted) the `/u`/`/p`/`/rp` credential arguments. This is the mirror image of the target-side Sysmon 1 event this module's `psexec/`-style entries already document for the calling process — see `Windows/06 - Evidence of Program Execution/Prefetch.md` and the Amcache/ShimCache notes for the corroborating execution-evidence artifacts (first/last-run timestamps, hash identity of the `schtasks.exe` binary itself if it was copied/renamed per `02 - Hands-On Use Cases.md`'s masquerading variant).

## Network Connection State on the Issuing Host

| Artifact | Command | Notes |
|---|---|---|
| Live RPC connection | `Get-NetTCPConnection -RemotePort 135 -State Established` (endpoint-mapper query), then a corresponding dynamic-high-port connection to the same remote IP | Per `01 - Overview.md`, modern `schtasks.exe /s` remote creation drives the `ITaskSchedulerService` RPC interface (`ncacn_ip_tcp`) — a TCP 135 query immediately followed by a connection on a dynamic high port, visible while the command is running or briefly after via connection-tracking |
| SMB session state (legacy-interface tooling only) | `Get-SmbConnection` / `net use` | Only relevant if the operator's tooling specifically targets the older `ATSvc`/`SASec` named-pipe interface (`\PIPE\atsvc`, over SMB/445) rather than `schtasks.exe`'s own default — see `01 - Overview.md`'s caveat on this distinction |
| DNS/name-resolution cache | `Get-DnsClientCache` | The target hostname (if `/s <hostname>` rather than a literal IP was used) resolved shortly before the RPC connection |

## Credential Material Exposure

`/p` and `/rp` accept a password directly on the command line. If the operator supplied it inline rather than letting `schtasks.exe` prompt interactively, that plaintext password is exposed to:
- Any process-creation logging on the **issuing** host (Sysmon 1, Security 4688) — captured verbatim in the command-line field
- PowerShell's `ConsoleHost_history.txt`, if run from a PowerShell prompt (see above)
- Any other local user/process able to read the process's command line while it's still running (`Get-Process | Select CommandLine` via WMI, or `/proc`-equivalent tooling for a non-Windows operator platform driving the same RPC calls)

This is the same class of exposure this module's Impacket entries document for inline `user:password@target`-style invocations — the safer operator practice (omitting `/p`/`/rp` and answering the interactive prompt) leaves no command-line trace of the password at all, which is itself worth noting as a sign of relative operational discipline if the rest of a command's argument shape otherwise looks unsophisticated.

## C2 Tasking Layer

Where `schtasks.exe` was invoked via a C2 framework's command-execution feature rather than typed by a human operator directly:

- **Sliver / Empire / Cobalt Strike / Metasploit-style frameworks:** task history logs the exact command string tasked to the implant — including the full `/create /s <target> /tn ... /tr ... /ru SYSTEM` sequence and its timestamp — see this module's own `Sliver/03 - Source Evidence.md` and `PowerShell Empire/03 - Source Evidence.md` for what that logging looks like per framework.
- If the operator has access to the C2 server itself, this task history is a complete, timestamped record of every `schtasks` command issued across every compromised host — the most reliable single source for recovering original creation intent, especially for the persistence use cases in `02 - Hands-On Use Cases.md` where the gap between creation and trigger fire can span weeks.

## OS-Level Audit Trail

If `auditd`-equivalent or PowerShell Script Block Logging (Event ID 4104, if enabled — see `LOLBins/powershell/04 - Target Evidence.md` for its non-default-on caveats) is active on the issuing host, either captures the full command text independent of process-creation logging, and can survive a `ConsoleHost_history.txt` deletion or a `cmd.exe` session closing without ever writing history to disk in the first place.

## Memory Forensics

A still-running `schtasks.exe /s ... /p <password>` process's command-line arguments are already fully recoverable from Sysmon 1/Security 4688 if either is enabled — the more useful memory-forensics angle on the issuing host is a **scripting-language wrapper** (a PowerShell or Python driver calling `schtasks.exe` or the raw `ITaskSchedulerService`/`ATSvc` RPC calls directly): its process memory can retain a plaintext credential string well past the point it was used, the same reference-counting/garbage-collection timing lag this module's Impacket entries document for their own Python-based tooling.

## Timeline Correlation Value

For the local-only use cases, there is no genuine issuing-host artifact distinct from target-side evidence — see `04 - Target Evidence.md`'s own timeline walkthrough for those. For the **remote-creation** use case specifically, the issuing host's evidence (Sysmon 1 command line, the TCP 135/dynamic-port connection window) is what ties a specific operator, a specific box, and a specific timestamp to the corresponding target-side chain — Security 4624 (Type 3 network logon) on the target, followed by TaskScheduler/Operational 106 (task registered), followed eventually by 200/201 (action started/completed) once the trigger fires or `/run` forces it. Matching the issuing host's brief RPC connection window against the target's 4624 logon timestamp is the strongest single correlation available, since (unlike psexec's ADMIN$ file-copy or a service-installation event) the remote-creation RPC call itself leaves no separate file-transfer artifact to anchor against.
