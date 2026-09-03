# DefenderCheck-SharpBlock: Source Evidence

## Overview

**DefenderCheck** and **SharpBlock** are execution-only tools with minimal artifact footprint on the operator's attacking machine (or staging server). Neither performs outbound callbacks, writes configuration files, nor maintains state between runs. The primary forensic angle is **detecting pre-staging and tool delivery**, not the tools' own operation.

---

## Shell History & Command Line

### DefenderCheck

If DefenderCheck.exe is executed from an operator's command shell (CMD, PowerShell, bash-via-WSL, etc.):

| Artifact | Location | Forensic Value |
|----------|----------|---|
| **PowerShell history** | `$PROFILE` (typically `C:\Users\<operator>\Documents\PowerShell\profile.ps1`) OR `(Get-PSReadlineOption).HistorySavePath` (PSReadline auto-log) | If operator ran `.\DefenderCheck.exe` or invoked via `Invoke-Expression`, command history captures execution. PSReadline typically stores in `%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`. |
| **CMD shell history** | Not logged by default (CMD does not maintain persistent history like PowerShell). | Only visible if `doskey /history` is manually run during that session, not persisted. |
| **Bash history** (WSL) | `~/.bash_history` | If DefenderCheck staged in WSL/Linux environment (uncommon; tool is .NET-only). |

### SharpBlock

SharpBlock is typically executed within a C2 beacon context (Cobalt Strike, Sliver, etc.) or injected into a process:

| Artifact | Location | Context |
|----------|----------|---------|
| **Beacon command history** | Stored in Cobalt Strike teamserver database (`~/.cobaltstrike/logs/`, `teamserver.log`, or beacon metadata) | Operator runs `shell C:\Temp\SharpBlock.exe` → logged in beacon session transcript. |
| **PowerShell history** (if invoked via PS) | `PSReadline ConsoleHost_history.txt` | Less common; most operators inject SharpBlock into process memory rather than invoke as shell command. |
| **C2 staging server logs** | Web server logs (Apache, IIS, nginx) if SharpBlock.exe was downloaded from HTTP staging server | Access logs show `GET /SharpBlock.exe` with timestamp, source IP, user-agent. |

---

## Tool Delivery Artifacts

### File System (Staging Location)

Both tools are typically staged on a compromised machine before execution, leaving temporal filesystem artifacts:

| Artifact | Scenario | Timeline Value |
|----------|----------|---|
| **DefenderCheck.exe** on disk | Staged in `C:\Temp\`, `C:\Windows\Temp\`, attacker-writable share | File timestamps (creation, modification, access) indicate when tool was deployed. Deletion does not erase MFT entry; recovered via forensic imaging. |
| **SharpBlock.exe** on disk | Same staging locations, or embedded in beacon payload | Typically removed post-execution by C2 cleanup, but MFT $STANDARD_INFORMATION resident timestamps survive; `$FILENAME` attribute gives true creation time. |

**Recovery Timeline:**
- `$CREATED` timestamp = actual upload time
- `$MODIFIED` timestamp = often same as created (tool not modified after staging)
- `$ACCESSED` timestamp = execution time (last read from disk)

### Web Server Logs (If Staged via HTTP)

If operator staged tools via web server (attacker-controlled or compromised web host):

```
# Staging server access log (e.g., Apache access.log or IIS logs)
203.0.113.45 - - [29/08/2026:14:23:15 +0000] "GET /tools/DefenderCheck.exe HTTP/1.1" 200 15360
203.0.113.45 - - [29/08/2026:14:24:02 +0000] "GET /tools/SharpBlock.exe HTTP/1.1" 200 18432
```

**Forensic Value:** IP address, timestamp, and referer/user-agent reveal operator's network footprint and tool delivery method. Cross-reference with victim machine's outbound network connections (`netstat`, Sysmon 3) to correlate timing.

---

## C2 Infrastructure Logs

### Cobalt Strike Teamserver Logs

If operator deployed DefenderCheck/SharpBlock via Cobalt Strike:

| Log | Content | Path |
|-----|---------|------|
| **Beacon session transcript** | Command execution history with timestamps | Teamserver: `~/.cobaltstrike/logs/<timestamp>_<beacon_id>.log` |
| **Teamserver console log** | High-level beacon callback/death events | `teamserver.log` |
| **Beacon metadata (SQLite)** | Beacon sessions, process IDs, user context, hostnames | Teamserver database (proprietary format; extracted via Dissect.cstrike) |

**Example Teamserver Log Entry:**
```
[16:45:23] beacon_cmd: 29e5 >> shell C:\Temp\DefenderCheck.exe
[16:45:24] Output: [*] Found Windows Defender engine...
```

---

## Process Memory (Post-Execution)

### Operators Running Tools Locally

If an operator runs DefenderCheck.exe on their own attacking machine (for pre-operations planning):

| Artifact | Forensic Value |
|----------|---|
| **Process memory dump** (if acquired during/shortly after execution) | DefenderCheck output buffer in memory; registry keys queried in recent-access cache |
| **.NET CLR metadata** | Compiled assembly manifest shows DefenderCheck version, compilation timestamp, target .NET Framework |

---

## Credential/Authentication Logs

### WMI Queries (DefenderCheck Only)

DefenderCheck queries WMI via COM interfaces on the target system. These queries may be logged on the **source** machine if WMI auditing is enabled:

| Platform | Artifact | Rarity |
|----------|----------|--------|
| **Windows (source machine)** | WMI Event logs (WMI-Activity channel, Event ID 5860-5861) | **Very rare.** WMI auditing is disabled by default and requires explicit configuration. Operator-controlled attacking machine almost never has WMI auditing enabled. |
| **Linux (if operator uses Impacket wmiexec from Linux)** | Command history (`.bash_history`), process tree (if logged) | Standard history captures `python3 wmiexec.py DOMAIN/user:pass@TARGET` command line. |

---

## Network Evidence (Source → Target)

### Outbound Network Connections

An operator executing DefenderCheck.exe or SharpBlock.exe on their own machine produces **no outbound network traffic** — both tools are purely local reconnaissance/patching and do not call back to C2 or external servers during execution.

**Exception:** If the operator stages the tools via a web request:
```
Source IP: 203.0.113.45 (operator/staging server)
Destination IP: 10.0.1.100 (victim endpoint)
Destination Port: 445 (SMB)
Protocol: SMB (file staging via \\\target\c$\temp\)
OR
Destination Port: 5985 (WinRM, if using PS remoting)
```

---

## Timeline Reconstruction Example

**Scenario:** Operator stages DefenderCheck.exe and SharpBlock.exe on compromised workstation, executes DefenderCheck to enumerate security products, then uses SharpBlock to disable AMSI before deploying PowerShell payload.

| Time | Artifact | Evidence |
|------|----------|----------|
| **14:15:00 UTC** | Outbound SMB 445 | Operator's machine → victim (staging binaries via `\c$\temp\`) |
| **14:15:30 UTC** | File created: `C:\Temp\DefenderCheck.exe` | MFT entry; $CREATED/$MODIFIED timestamps |
| **14:15:45 UTC** | File created: `C:\Temp\SharpBlock.exe` | Same |
| **14:16:00 UTC** | Process execution: DefenderCheck.exe | Sysmon 1, WMI Provider Host callback (target side, not source) |
| **14:16:05 UTC** | PowerShell history (Beacon logs) | `shell C:\Temp\DefenderCheck.exe` in teamserver transcript |
| **14:16:30 UTC** | Process execution: SharpBlock.exe | Sysmon 1 (short-lived process) |
| **14:16:35 UTC** | In-memory AMSI patch | No disk artifact; memory forensics only |
| **14:16:40 UTC** | PowerShell malware load | Bypasses AMSI; no EDR event logged |

---

## Data Exfiltration / Credential Exposure

Neither DefenderCheck nor SharpBlock reads, writes, or exfiltrates user credentials. DefenderCheck reads only from WMI/registry for security product inventory. SharpBlock modifies only AMSI function pointers in memory.

**Caveat:** If DefenderCheck output is piped to a file or uploaded to a C2 server for reporting, that output file (and its timestamp) becomes an artifact:
```powershell
C:\Temp\DefenderCheck.exe > C:\Temp\av_inventory.txt
# File av_inventory.txt is now a source-side artifact
```

---

## Compilation & Build Metadata

### .NET Assembly Metadata

Both DefenderCheck and SharpBlock are C# assemblies. Pre-compiled .exe binaries contain embedded metadata:

| Field | Recoverable Via | Forensic Use |
|-------|---|---|
| **Compilation timestamp** | COFF header (PE format), `TimeDateStamp` | Indicates when binary was built (not when executed) |
| **CLR metadata (.NET version)** | `ildasm` or hex dump of .reloc section | Target .NET Framework version; presence of NGEN/ready-to-run compilation indicators |
| **.NET assembly name & version** | ILDASM, hex dump | Semantic versioning if embedded by developer |
| **Embedded strings** | Hex dump, YARA string scan | Hardcoded AV/EDR product names (DefenderCheck), AMSI function names (SharpBlock) |

**Caveat:** Custom-compiled variants (operator compiles from source) have no official version; the $CREATED timestamp on the resulting .exe is the compile time on the operator's machine.

