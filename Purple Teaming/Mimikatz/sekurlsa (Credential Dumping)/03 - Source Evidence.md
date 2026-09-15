# Mimikatz — sekurlsa — Source Evidence

Evidence left on the **attacking/operator** host. Unlike a network-protocol tool, sekurlsa's evidence trail on the source side depends heavily on *which* loading method (see `00 - Mimikatz Overview.md`) the operator used — a dropped-binary run leaves far more than a reflectively-loaded one. Mimikatz itself writes **no persistent session log** of its own; anything recoverable here is generic shell/process/OS-audit trail, or artifacts of however the tool/loader was staged.

## Contents
- [Shell History](#shell-history)
- [Dropped Binary / Loader Script Artifacts](#dropped-binary--loader-script-artifacts)
- [Live Process State](#live-process-state)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| `cmd.exe` on the operator/pivot host | No native history file | Only recoverable via a separate console-logging mechanism (PowerShell transcription, a C2 framework's own operator log) — `cmd.exe` itself keeps no persistent record |
| PowerShell | `PSReadLine` history — `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | If the operator ran `Invoke-Mimikatz` or typed mimikatz commands interactively from a PowerShell console on their own attack/pivot box, the full command text — including any `/ntlm:`/`/aes256:` hash or key material typed inline — lands here in plaintext |
| bash/zsh (Linux operator box, e.g. running a Meterpreter/Beacon handler) | `~/.bash_history` / `~/.zsh_history` | Captures the handler/framework invocation (`msfconsole`, C2 teamserver startup) rather than the mimikatz commands themselves, since those are typed inside the C2 session's own interface, not the local shell |

## Dropped Binary / Loader Script Artifacts

| Loading method | What's left on the operator's own staging infrastructure |
|---|---|
| Dropped `mimikatz.exe`/`.dll` | The binary itself, wherever it was staged before delivery — file hash matches the well-known public releases unless custom-compiled |
| `Invoke-Mimikatz.ps1` (or similar reflective loader) | The `.ps1` file, typically hosted on operator infrastructure (a web server, an SMB share) for the target to pull via `IEX (New-Object Net.WebClient).DownloadString(...)` — web server access logs on that infrastructure record every target IP that fetched it, which is a valuable **operator-side** record of every host mimikatz was run against |
| Beacon/Meterpreter extension load | No separate mimikatz file at all — the credential-extraction logic lives inside the C2 framework's own extension binary (`kiwi` extension DLL, Beacon's `mimikatz.dll` referenced via `execute-assembly`/`inline-execute`), which is a permanent part of the framework's own installed files, not something staged per-engagement |
| Custom-compiled mimikatz from source | A local git checkout (`.git/logs/HEAD`, commit history) if built from the official repo rather than using a release binary — shows exactly which source revision (and therefore which build-specific memory-parsing signatures) was compiled |

## Live Process State

```powershell
Get-Process | Where-Object { $_.ProcessName -match 'mimikatz' }
```
If a dropped binary is still running on a Windows-based operator/pivot box (uncommon for a proper engagement, but realistic for a compromised infrastructure investigation, or an insider-threat scenario), process listing shows it directly. Reflectively-loaded instances show up only as the **host process** (`powershell.exe`, `beacon.exe`/the C2 agent binary) — mimikatz never appears as its own process name when loaded this way, which is precisely the point.

## Network Evidence

| Artifact | Notes |
|---|---|
| Operator infrastructure's own web/file-server logs | If a reflective loader (`Invoke-Mimikatz.ps1`) or a `.dmp` retrieval path was hosted on operator-controlled infrastructure, that infrastructure's own access logs are a durable, target-independent record of every host that fetched the loader or exfiltrated a minidump — valuable in a seized-infrastructure investigation even when the target side shows nothing |
| Live outbound connection state | `netstat`/`Get-NetTCPConnection` on the operator box, while a C2 session carrying mimikatz/kiwi traffic is active — shows the established connection to the target, but nothing mimikatz-specific (the C2 channel's own protocol carries the credential data, not a separate mimikatz protocol) |

## OS-Level Audit Trail

If the operator's own pivot/staging box is Windows and has command-line process-creation auditing enabled (Security 4688 with command-line logging, or Sysmon Event 1):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'mimikatz|Invoke-Mimikatz|sekurlsa' }
```
This is the most durable operator-side record for a dropped-binary or locally-executed-script run — generated at process-creation time, independent of shell history, and survives a `history -c`/PSReadLine-file deletion on that box.

## Memory Forensics

If the operator or pivot box itself is seized/imaged (compromised-infrastructure investigation, insider-threat case):
- A still-resident, reflectively-loaded mimikatz DLL exists **only in the memory** of whatever process loaded it (`powershell.exe`, the C2 agent) — there is no file to recover, making a live memory capture of that process the *only* way to recover the loaded module and any credential material it extracted but never wrote to disk.
- Recovered credential material (hashes, plaintext passwords, ticket bytes) frequently persists in the loading process's memory well past its last on-screen use, due to string/object retention in both PowerShell's runtime and unmanaged C buffers — a full memory capture or targeted string/YARA search (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md` for general technique) can recover it even if console output was never logged.

## Timeline Correlation Value

Source-side evidence here is rarely conclusive alone — its value is **correlating an operator-side timestamp against the target-side Sysmon Event ID 10 handle-open** documented in `04 - Target Evidence.md`. A `.ps1`-download-server log entry, a PSReadLine history line, or a Security 4688 process-creation event on the operator's own box, matched in time against a target-side LSASS-access event with the operator's known source IP, is what turns "an LSASS memory read happened somewhere" into a provable chain tying a specific operator box to a specific victim host.
