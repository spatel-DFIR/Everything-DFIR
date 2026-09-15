# WinPEAS — Source Evidence

Source evidence here refers to artifacts left on the **operator's/attacker's own machine** when staging, running, or managing WinPEAS payloads. Since WinPEAS is primarily a C2-delivered or reverse-shell-executed tool, the source-side artifacts depend heavily on delivery method.

## Binary / Payload Staging Artifacts

### Downloaded WinPEAS.exe Artifact

If the operator downloads WinPEAS.exe via browser or `certutil` on their own machine:

| Artifact | Location | Significance |
|---|---|---|
| **Cached binary** | `%TEMP%\WinPEAS.exe` or `Downloads\WinPEAS.exe` | Direct evidence of tool staging; PE metadata (`FileDescription: "WinPEAS Windows Privilege Escalation Awesome Script"`, `ProductName: "WinPEAS"`) identifies it unambiguously. |
| **Browser history** | Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` (SQLite DB) | `http://github.com/carlospolop/PEASS-ng/releases/` or attacker's hosting domain in browsing history. |
| **Browser download metadata** | Chrome: `History` table with `url`, `last_visit_time`; Firefox: `places.sqlite` | Timestamp of when WinPEAS.exe was acquired. |
| **PowerShell history (if DownloadString used)** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` (PS 5.0+) | Command line: `IEX (New-Object Net.WebClient).DownloadString('...')` shows attacker's staging server. |
| **Network connection logs (if using ETW/Packet Capture)** | Windows Event Viewer → Event Tracing for Windows (ETW) or Wireshark PCAP | HTTP/HTTPS outbound to attacker's hosting infrastructure or GitHub (github.com/releases). |

### PowerShell Script Staging

If delivering `winpeas.ps1` in-memory via IEX:

| Artifact | Location | Significance |
|---|---|---|
| **PowerShell command history** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Full `IEX` command line; if the script URL or inline script is visible, it's a direct fingerprint. |
| **Event Viewer → Windows PowerShell** | Event 4104 (Script Block Logging) on PS 5.0+ systems with Script Block Logging enabled | Full deobfuscated PowerShell script contents logged if SIEM/EDR collects it. |
| **Temp directory** | `%TEMP%\*.ps1` (only if saved to disk instead of IEX'd) | Script source code if not executed via in-memory IEX. |

**Evasion impact:** If the operator uses IEX (in-memory execution), **no source-side file artifact exists** — only PowerShell's own process memory and event logs capture the activity. If saved to disk, the `.ps1` file is plaintext and trivially identifiable.

## C2 Command & Control Artifacts

### Cobalt Strike Beacon (if operator is orchestrating via Cobalt Strike)

| Artifact | Location | Significance |
|---|---|---|
| **C2 server logs** | Attacker's TeamServer logs (`/var/log/cobalt-strike.log` or Malleable C2 profile output) | Command execution timestamp, beacon ID, output capture. Timestamp of `execute-assembly WinPEAS.exe`. |
| **C2 listener history** | Cobalt Strike GUI → Event Log tab | Logged execution, beacon callback, output streaming. |
| **Network artifacts (if PCAP'd)** | Operator's ISP/network log → DNS/HTTP/HTTPS to Cobalt Strike C2 domain | C2 callback traffic when WinPEAS execution is staged and results are retrieved. |

### Sliver / Empire (if operator is using open-source C2)

| Artifact | Location | Significance |
|---|---|---|
| **Sliver server logs** | `~/.sliver/server.log` (or configured log path) | Full history of `execute` commands, output, timing. |
| **Empire database** | `./data/empire.db` (SQLite) | Agent history, module execution, callbacks. |

**Shared pattern:** All C2 frameworks log when WinPEAS is executed. If the operator's C2 infrastructure is later seized, this log is direct evidence of tool usage, timing, and which systems were targeted.

## Command-Line History

### Cmd.exe / PowerShell Command History

| Artifact | Location | Significance |
|---|---|---|
| **cmd.exe history (if enabled)** | Requires third-party shell (ConEmu, Windows Terminal) to save history; native cmd.exe has no history file | Not typically present in vanilla cmd.exe; if visible, shows exact commands typed. |
| **PowerShell 5.0+ history** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Commands executed in PowerShell sessions, including WinPEAS invocation: `.\WinPEAS.exe`, `IEX ...`, etc. |
| **ConEmu history** | `%APPDATA%\ConEmu\ConEmu.xml` or `%APPDATA%\ConEmu\ConEmu.sqlite` | If using ConEmu for shells, full history stored. |

**Timeline value:** Timestamp of WinPEAS execution correlates with when operator decided to begin escalation reconnaissance, useful for incident timelines.

## Process Artifacts (Memory / ETW)

### Memory Forensics (if operator's machine is captured via malware, EDR, or memory dump)

| Artifact | Location | Significance |
|---|---|---|
| **Loaded DLL modules in PowerShell process** | Memory dump of `powershell.exe` → module list | If WinPEAS was loaded via IEX, .NET reflection objects are visible in memory. |
| **Heap contents (PowerShell process)** | Memory dump of `powershell.exe` → heap analysis | Deobfuscated PowerShell script code, variable contents, attacker's hosting URL. |

### Event Tracing for Windows (ETW)

| Artifact | Location | Significance |
|---|---|---|
| **Process creation (Event 1, Sysmon)** | Sysmon XML log (if running on operator's machine for self-monitoring) | `powershell.exe` child process creation, `WinPEAS.exe` execution, file access patterns. |
| **Network connection (Event 3, Sysmon)** | Sysmon XML log | Outbound HTTPS to GitHub or attacker's staging server. |
| **File created (Event 11, Sysmon)** | Sysmon XML log | WinPEAS.exe saved to `%TEMP%`, output file created. |

**Operational security note:** Most operators do not run Sysmon or ETW logging on their own attack machines — these artifacts are only visible if the operator's workstation is compromised or if the operator is using a monitored lab environment.

## Network Communication Artifacts

### Attacker's Infrastructure Logs

If WinPEAS.exe is hosted on attacker's web server:

| Artifact | Location | Significance |
|---|---|---|
| **Web server access logs** | `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, etc. | Source IP (operator's IP or jump box), User-Agent, timestamp of download. Example: `192.168.1.100 - - [11/Aug/2026:09:15:23] "GET /WinPEAS.exe HTTP/1.1" 200 1234567` |
| **Malware sandbox detections** | If attacker's hosting IP is blacklisted and checked via VirusTotal/URLhaus | Incoming traffic to attacker's C2 domain noted as "hosting WinPEAS.exe" (public IOC). |

### Firewall / Proxy Logs (if operator's network is monitored)

| Artifact | Location | Significance |
|---|---|---|
| **HTTP/HTTPS egress log** | Corporate proxy, firewall log | Destination `github.com/carlospolop/PEASS-ng/releases`, timestamp, data volume downloaded. |
| **DNS query log** | Firewall DNS log, Pi-hole, etc. | Operator queried `github.com`, `attacker.com`, or staged domain. |

## Credential Material & API Keys

### GitHub API Access (if downloading via GitHub API)

| Artifact | Location | Significance |
|---|---|---|
| **GitHub API token usage** | GitHub account logs (if via API token vs. web browser) | User's GitHub account activity log shows download of `carlospolop/PEASS-ng/releases` asset. |

**Evasion note:** Downloading via web browser (no API token) is less traceable to a specific GitHub account; downloading via API token directly associates the download to a GitHub user account.

## Exfiltration Artifacts (if operator is exfilling WinPEAS output)

### Output File Transmission

If operator exfiltrates WinPEAS output from target back to attacker's infrastructure:

| Artifact | Location | Significance |
|---|---|---|
| **Outbound file transfer (DNS/HTTPS/SMB)** | Operator's network log, firewall | Large data blob (WinPEAS output, typically 50-500 KB) transmitted to attacker's IP. Timing correlates with "WinPEAS run completed." |
| **DNS TXT record queries** | DNS query log | If using DNS tunneling (dnscat2, iodine), DNS TXT queries with base64-encoded output visible. |
| **C2 callback with output** | C2 server log | Beacon callback including WinPEAS output; if C2 is later compromised, this is direct evidence of reconnaissance activity. |

## Artifact Timeline for Investigation

A typical operator's source-side timeline:

```
T+0:00      Operator downloads WinPEAS.exe from GitHub
            └─ Browser history: github.com/carlospolop/PEASS-ng
            └─ Downloads folder: WinPEAS.exe
            └─ Network log: HTTPS to github.com

T+0:05      Operator stages WinPEAS.exe via C2 (Cobalt Strike, Sliver)
            └─ C2 server log: execute-assembly command
            └─ Network log: C2 callback with binary data
            └─ Operator's temp directory: WinPEAS.exe artifact (staging)

T+0:10      Target executes WinPEAS (via C2 callback)
            └─ C2 output captured: WinPEAS result stream
            └─ Target-side artifacts: Registry reads, file enumeration
            └─ → (See 04 - Target Evidence.md for target-side timeline)

T+0:20      Operator analyzes WinPEAS output (local analysis)
            └─ C2 GUI: result parsing, red-flag extraction
            └─ Operator's machine: PowerShell parsing scripts (if used)

T+0:30      Operator exfiltrates WinPEAS output (optional)
            └─ Network log: Large data blob egress to attacker infrastructure
            └─ C2 log: Output file transfer
```

**For blue-team investigation:** Focus on the operator's C2 logs (if infrastructure is seized), network egress to GitHub (initial staging), and timestamps in C2 callback logs (when reconnaissance began).

