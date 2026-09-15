# Lateral Movement

Every technique in this note answers the same underlying question from two different vantage points: from the **source** host, "what did the attacker do with credentials they already had to reach another machine?" and from the **destination** host, "what evidence did that connection, that authentication, and whatever ran as a result, leave behind?" RDP, PsExec/SMB admin shares, WMI, PowerShell Remoting, remote scheduled tasks, remote services, and `net use` share mapping are seven different *mechanisms* for the same handful of underlying actions — authenticate remotely, optionally place a payload, cause code to execute on the target — and they leave evidence in the same handful of *places*: a network connection, a logon event, a technique-specific footprint (service/task/WMI object/session), and execution evidence for whatever ran.

This note is the **hub** for that pattern. Three sibling notes in Persistence Mechanisms (10) — **Services**, **Scheduled Tasks**, and **WMI Event Consumers** — each already carry a full destination-host evidence table for their own remote-execution primitive (`sc \\host create`, `schtasks /create /s`, `wmic /node:`) and explicitly defer "source/destination pairing, session/credential flow, and the rest of the remote-execution toolkit" here. This note does not re-derive those tables — it cross-links to them and adds the pieces they don't cover: RDP, PowerShell Remoting, `net use`/share reconnaissance, the credential-theft angle, and — critically — the **unified framework and comparative table** that lets an analyst see all seven techniques side by side and recognize when an attacker is technique-hopping across the same destination host.

> 🔴 **Lateral movement is rarely a single technique.** An intruder who fails with PsExec because AV flags it often falls back to WMI, then WinRM, then a scheduled task — probing for whatever isn't monitored on that specific host. Seeing two or more of these techniques used against the *same destination* in a short window is itself one of the strongest lateral-movement indicators available, independent of whether any single technique looks alarming in isolation.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [The Source → Network → Destination Framework](#the-source--network--destination-framework)
- [RDP](#rdp)
- [PsExec / SMB Admin Shares](#psexec--smb-admin-shares)
- [WMI / WMIC Remote Execution](#wmi--wmic-remote-execution)
- [PowerShell Remoting (WinRM)](#powershell-remoting-winrm)
- [Remote Scheduled Tasks](#remote-scheduled-tasks)
- [Remote Services](#remote-services)
- [`net use` / Share Mapping / SMB Session Enumeration](#net-use--share-mapping--smb-session-enumeration)
- [Pass-the-Hash / Pass-the-Ticket — The Credential-Theft Angle](#pass-the-hash--pass-the-ticket--the-credential-theft-angle)
- [Comparative Summary Table](#comparative-summary-table)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across all seven techniques in this note — no third-party modules required. Each pulls a single technique's fastest destination- or source-host tell; go to the technique's own section below for the full evidence chain once one of these turns up something.

```powershell
# Inbound PSRemoting/WinRM session activity on this host - WSMan session-lifecycle events, destination side
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 100 |
    Where-Object { $_.Id -in 91,168 } | Select-Object TimeCreated, Id, Message

# Type 3 (network) logons in the last 24h - the shared authentication baseline every technique in this note rides on
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} |
    Where-Object { $_.Properties[8].Value -eq 3 } |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}

# PsExec-style service installs - 7045 whose service name or ImagePath matches the classic ADMIN$/temp drop pattern
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 100 |
    Where-Object { $_.Message -match 'PSEXESVC' -or $_.Message -match '\\ADMIN\$|\\Temp\\' }

# WMI remote process creation - any live process whose parent is wmiprvse.exe right now
Get-CimInstance Win32_Process | ForEach-Object {
    $p = $_
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue
    if ($parent.Name -eq 'WmiPrvSE.exe') { [PSCustomObject]@{ Process = $p.Name; PID = $p.ProcessId; ParentPID = $p.ParentProcessId } }
}

# Active SMB sessions and outbound share mappings on this host, right now
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens
Get-SmbMapping | Select-Object LocalPath, RemotePath, Status

# Outbound RDP connections this host's client has made - source-host confirmation of where a user's mstsc session went
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -MaxEvents 50 |
    Where-Object { $_.Id -eq 1024 } | Select-Object TimeCreated, Message

# Cross-host sweep - check an entire estate for one technique's footprint (example here: PsExec-style service installs)
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'PSEXESVC' }
} | Select-Object PSComputerName, TimeCreated, Message | Export-Csv C:\hunt\psexec_sweep.csv -NoTypeInformation
```

## The Source → Network → Destination Framework

Before the technique-specific detail, it's worth internalizing the shape every one of these techniques shares — this is the mental model the rest of the note hangs off, and it mirrors the layout of the FOR508 poster's lateral-movement panel (rewritten here, not reproduced).

| Stage | What to look for | Where |
|---|---|---|
| **Source host — pre-movement** | Reconnaissance: share enumeration (`net view`, `net use`), port scanning, credential harvesting. Command-line/PowerShell history of the tool being staged | Prefetch/ShimCache/Amcache for attacker tooling (note 06), 4104/4103 PowerShell Operational log (note 11), console/command history |
| **Source host — credential use** | Cached credentials, prompted credentials, explicit alternate credentials (`runas`, `-u` flags), pass-the-hash | Security log 4648 (explicit credentials — see note 05's dedicated section), Logon Type 9 (NewCredentials) |
| **Network** | The protocol/port the technique rides on — this is often the fastest way to fingerprint *which* technique was used from network evidence alone before host evidence is even pulled | See the port column in the Comparative Summary Table below |
| **Destination host — inbound authentication** | The logon that lets the technique execute at all | Security log 4624 (logon type varies by technique — see each subsection) and 4672 (privilege assignment) — full logon-type mechanics in note 05 |
| **Destination host — technique footprint** | The mechanism-specific artifact the technique itself creates: a service, a task, a WMI triad, a PSSession, a mapped share handle | Covered per-technique below, with cross-links to the owning note where full depth already exists |
| **Destination host — execution evidence** | Confirmation that whatever payload/command was pushed actually ran | Prefetch, ShimCache, Amcache (note 06) for the dropped/launched executable |

The value of laying it out this way: once you've found *any one* row for a suspected lateral-movement event, the framework tells you exactly what to go pull next. A 4624 Type 3 logon on a workstation with no legitimate admin function, for instance, should immediately send you looking for the technique footprint (which service/task/WMI object/session was created) and the execution evidence (what actually ran as a result) — not just the logon event in isolation.

## RDP

**What it is:** Full interactive remote desktop session — the attacker gets a graphical session on the destination exactly as if sitting at the console, as opposed to the command-execution-only primitives covered later in this note.

**Port/protocol:** TCP 3389 by default (RDP protocol, can be reconfigured to a non-standard port — always confirm the actual listening port rather than assuming 3389).

**Logon type:** Type 10 (RemoteInteractive) for a fresh session; Type 7 (Unlock) for a reconnect to an existing disconnected session. Full logon-type interpretation lives in **Users, Groups & Authentication (05)** — this note only needs the RDP-specific reading of those types.

**Destination-host event evidence** (full mechanics owned by **Event Log Analysis (11)** — this is the RDP-specific interpretation):

| Source | Event ID | What it shows |
|---|---|---|
| `TerminalServices-LocalSessionManager/Operational` | 21 / 22 / 23 / 24 / 25 | Session logon succeeded / shell started / logoff / disconnect / reconnect — the fullest picture of session lifecycle on the destination |
| `TerminalServices-RemoteConnectionManager/Operational` | 1149 | Network-level RDP connection reached the host, including source IP — 🔴 fires even on connections that never complete authentication; don't read this alone as a successful logon (see note 11 for the full caveat) |
| `Security.evtx` | 4624 (Type 10) / 4624 (Type 7) | Authentication half of a fresh session / reconnect |
| `Security.evtx` | 4778 / 4779 | Session reconnected / disconnected — bounds how long a session sat idle before reconnect |

**Source-host evidence — RDP-specific, not covered elsewhere:**

- **RDP bitmap cache** (`%LocalAppData%\Microsoft\Terminal Server Client\Cache\` — files named `Cache####.bin` plus an index) — an under-known but genuinely valuable artifact: the RDP client caches small tiles of what was *rendered* on screen during a remote session to speed up redraws. Because this lives on the **source** machine, it can let an analyst reconstruct fragments of what was visually displayed during an RDP session an attacker used to pivot — useful when the destination's own logs are gone (cleared, rolled past, or the destination is a machine outside the current collection scope). Tools such as `bmc-tools` (bitmap cache carving/reconstruction) can rebuild viewable images from the cache tiles.
- **`mstsc.exe` connection history** — `HKCU\Software\Microsoft\Terminal Server Client\Servers` (one subkey per hostname/IP the user's RDP client has connected to, via the standard client) records **where a user RDP'd to** from this machine — source-host evidence of outbound RDP activity, complementary to the destination-host session evidence above. A `Default` value under `Servers\<UsernameHint>` may also carry the username last used against that server, depending on OS version.

**Evasion/variants:** Non-default listening port (defeats simple 3389 network filtering, does not defeat 1149/21 host-side evidence); Restricted Admin Mode / pass-the-hash-compatible RDP (avoids needing the plaintext password — see the Pass-the-Hash subsection below); RDP over an already-established tunnel (SSH/SOCKS/VPN) makes the network hop invisible to simple port-based detection even though the host-side event chain is unchanged.

Full RDP mechanics beyond the lateral-movement-specific interpretation above — log retention, EvtxECmd parsing — are owned by **Event Log Analysis (11)**; logon-type semantics are owned by **Users, Groups & Authentication (05)**.

### PowerShell

To pull this host's own outbound RDP connection history (source-host artifact) and the destination-side session-lifecycle events, natively:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Terminal Server Client\Servers\*' -ErrorAction SilentlyContinue |
    Select-Object PSChildName, UsernameHint

Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 50 |
    Where-Object { $_.Id -in 21,22,23,24,25 } | Select-Object TimeCreated, Id, Message
```

To pair Security 4624 (Type 10 fresh session / Type 7 reconnect) with account and source IP, so a bare logon event reads as a session, not just an authentication:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 |
    Where-Object { $_.Properties[8].Value -in 10,7 } |
    Select-Object TimeCreated, @{N='LogonType';E={$_.Properties[8].Value}}, @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
```

To sweep an estate for every RDP Type-10 logon from one suspect source IP, across every host that answers:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[8].Value -eq 10 -and $_.Properties[18].Value -eq '10.0.0.5' } |
        Select-Object @{N='Account';E={$_.Properties[5].Value}}, TimeCreated
} | Select-Object PSComputerName, TimeCreated, Account | Export-Csv C:\hunt\rdp_sweep.csv -NoTypeInformation
```

## PsExec / SMB Admin Shares

**What it is:** Sysinternals PsExec (and tools built on the same primitive — Impacket's `psexec.py`/`smbexec.py`, CrackMapExec's `--exec-method`) copies a service binary to the target over an administrative share (`ADMIN$`, mapping to `C:\Windows\`, or `C$`), installs it as a temporary service, executes the requested command, relays output over a named pipe, and removes the service afterward.

**Port/protocol:** SMB, TCP 445 (legacy NetBIOS-over-TCP on 139 is possible but rare on modern networks).

**Essentials** (full depth — the complete evidence table, `EulaAccepted` registry key detail, service-name renaming caveat — lives in **Services.md → PsExec Special Case (note 10)**; summarized here so this note stands alone):

| Evidence | What it shows |
|---|---|
| `ADMIN$`/`C$` share access — Security 5140 (share accessed) / 5145 (detailed share access check) | Confirms the administrative share was mounted from the source host — the first observable step of the technique |
| `EulaAccepted` registry value under the executing user's `NTUSER.DAT\Software\SysInternals\PsExec` | Proves PsExec ran interactively on this specific host under this specific profile at least once |
| `PSEXESVC` service creation (or a renamed equivalent via `-r`) | The technique's own footprint — see Services.md for the full System 7045 / Security 4697 chain |
| Security 4624 (Type 3, or Type 2/9-adjacent if `-u` alternate credentials used) + 4672 | Session and privilege evidence for the connection itself; `-u` alternate credentials also produce a source-host 4648 |
| Prefetch/ShimCache/Amcache for `psexesvc.exe` and any pushed executable | Execution confirmation on the destination (note 06) |

**Known tooling fingerprints:** `PSEXESVC` is the default service name (renamable with `-r`); Impacket's `psexec.py`/`smbexec.py`/`atexec.py` and CrackMapExec each have their own default share-naming and cleanup conventions — recognizing the specific tool's default naming pattern, when it hasn't been changed, is a fast triage shortcut.

### PowerShell

To check for the `EulaAccepted` key (proves PsExec ran interactively on this host under this profile at least once) and pull recent `ADMIN$`/`C$` share-access events natively (full 7045 service-creation querying is owned by **Services.md**, cross-linked below):

```powershell
Get-ItemProperty 'HKCU:\Software\Sysinternals\PsExec' -Name EulaAccepted -ErrorAction SilentlyContinue

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140} -MaxEvents 100 |
    Where-Object { $_.Message -match 'ADMIN\$|C\$' }
```

To pair a 7045 service install with any `ADMIN$`/`C$` share access from the same source in a tight window; the *timing pairing* is the tell, not the (renamable) service name alone per this section's red flag above:

```powershell
$shareAccess = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140} -MaxEvents 200 |
    Where-Object { $_.Message -match 'ADMIN\$' }
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 200 | ForEach-Object {
    $svc = $_
    $nearby = $shareAccess | Where-Object { [math]::Abs(($_.TimeCreated - $svc.TimeCreated).TotalMinutes) -lt 5 }
    if ($nearby) { [PSCustomObject]@{ ServiceInstall = $svc.TimeCreated; ShareAccess = $nearby[0].TimeCreated } }
}
```

To sweep an estate for the `EulaAccepted` key, which confirms PsExec (not just a same-named renamed service) actually executed on a given host:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ItemProperty 'HKCU:\Software\Sysinternals\PsExec' -Name EulaAccepted -ErrorAction SilentlyContinue
} | Select-Object PSComputerName, EulaAccepted | Export-Csv C:\hunt\psexec_eula_sweep.csv -NoTypeInformation
```

## WMI / WMIC Remote Execution

**What it is:** Uses WMI's built-in remote-connection support to instantiate a process on the destination directly — no service installed, no task registered, no file necessarily dropped beyond whatever the launched command line itself does.

```
wmic /node:<host> process call create "cmd.exe /c <command>"
Invoke-CimMethod -ComputerName <host> -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c <command>"}
```

**Port/protocol:** Two distinct transports depending on invocation method — this distinction is itself diagnostic:

| Transport | Ports | Triggered by |
|---|---|---|
| DCOM/RPC | TCP 135 (endpoint mapper) + a dynamic high RPC port | `wmic /node:`, `Invoke-WmiMethod`, legacy `Invoke-CimMethod` without an explicit WSMan session |
| WinRM / CIM-over-WSMan | TCP 5985 (HTTP) / 5986 (HTTPS) | `Invoke-CimMethod`/`New-CimSession` built explicitly over WSMan — the same ports PowerShell Remoting uses, see below |

**Essentials** (full depth — the complete evidence table including WMI-Activity/Operational reliability caveats — lives in **WMI Event Consumers.md → Remote WMI as a Lateral-Movement Primitive (note 10)**):

- **`WmiPrvSE.exe`** as the parent process of whatever the remote call launched — the destination-host tell that a process was spawned via WMI rather than directly by a user or another parent. Any unexpected `WmiPrvSE.exe` parent in a process-tree review is worth chasing, whether the trigger was remote lateral movement or a local permanent-subscription firing.
- Security 4624 (Type 3) + 4672 on the destination — WMI process creation requires local admin rights on the target by default.
- `Microsoft-Windows-WMI-Activity/Operational` 5857/5858 (provider start/error) around the call, plus 5859-5861 if the attacker also registered a permanent subscription in the same session — see WMI Event Consumers.md for the Windows-10-centric reliability caveat on this log.
- Prefetch/ShimCache/Amcache for whatever the command line launched.

**Known tooling fingerprints:** Impacket's `wmiexec.py` (semi-interactive shell over WMI, notably does **not** drop a file to disk the way PsExec does — output is retrieved via a written-then-read file share or, in some variants, purely in-memory command results); CrackMapExec's `--exec-method wmiexec`.

### PowerShell

🔴 This subsection is specifically about WMI used as a **remote-execution** primitive — `Win32_Process.Create` launching code on another host. WMI used as a **persistence** mechanism (permanent event-filter/consumer subscriptions) is a genuinely different use case, covered with its own full PowerShell treatment in **WMI Event Consumers (10)**; don't conflate the two here.

To invoke a remote process via WMI/CIM the same way an attacker's tooling would, so you know exactly what the resulting artifact looks like on the wire and on the destination:

```powershell
Invoke-CimMethod -ComputerName <host> -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"}
```

To find every process on the destination whose parent is `WmiPrvSE.exe` right now and walk each one up to its actual command line:

```powershell
Get-CimInstance Win32_Process | Where-Object {
    (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue).Name -eq 'WmiPrvSE.exe'
} | Select-Object Name, ProcessId, ParentProcessId, CommandLine
```

To perform a cross-host sweep for `WmiPrvSE.exe`-parented processes across an estate, exported for timeline correlation with the WMI-Activity 5857/5858 events covered above:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-CimInstance Win32_Process | Where-Object {
        (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue).Name -eq 'WmiPrvSE.exe'
    } | Select-Object Name, ProcessId, CommandLine
} | Select-Object PSComputerName, Name, ProcessId, CommandLine | Export-Csv C:\hunt\wmi_exec_sweep.csv -NoTypeInformation
```

## PowerShell Remoting (WinRM)

**What it is:** `Enter-PSSession`/`Invoke-Command` establish a remote PowerShell session over WS-Management (WinRM) — the native, fully-featured Windows remote-shell mechanism.

**Port/protocol:** TCP 5985 (HTTP) / 5986 (HTTPS).

**Prerequisite the attacker must satisfy first:** unlike RDP (which is commonly already enabled) or the service/task/WMI primitives (which use components present on every host by default), the WinRM **service** must actually be running and configured to accept connections on the destination — `Enable-PSRemoting` if it isn't already. On a host where WinRM was off, an attacker turning it on to enable this technique is itself sometimes a detectable configuration-change event, and is a signal worth checking for on hosts where WinRM activity appears unexpectedly.

**Event evidence:**

| Source | Event | What it shows |
|---|---|---|
| `Microsoft-Windows-WinRM/Operational` | (channel-level activity) | Native log for WS-Management activity — full channel mechanics owned by **Event Log Analysis (11)**; both a client-side (source) and server-side (destination) log exist, with the destination's generally the more useful for confirming an inbound session actually occurred |
| `Microsoft-Windows-PowerShell/Operational` | 4104 (Script Block Logging) | 🔴 Fires on **both** the source host (the command as sent) and the destination host (the command as executed) — comparing the two is a strong corroboration technique when both are available. Off by default; see note 11 for the enabling GPO |
| `Microsoft-Windows-PowerShell/Operational` | 4103 | Module/pipeline execution detail, on by default at the channel level (module logging configuration affects richness) |
| `Security.evtx` | 4624 (Type 3) | PowerShell Remoting authenticates as a network logon on the destination |

Full PowerShell logging mechanics (the three-tier 400/800/4103/4104/4105-4106 logging surface, the Script Block Logging enabling GPO, obfuscation markers to grep for) are owned by **Event Log Analysis (11)** — this note only needs the fact that 4104 shows up on both ends of a remoting session.

**Known tooling fingerprints:** **Evil-WinRM** is the standard offensive tool built specifically around WinRM abuse — its interactive shell and built-in file-transfer/`Invoke-Binary` functions leave a fairly recognizable PowerShell command-line pattern in 4104 content once captured.

### PowerShell

🔴 **This is the one technique in this note where the investigator's tool and the attacker's technique are the same commands.** `Invoke-Command`/`Enter-PSSession` are exactly what a hunter runs to sweep an estate (throughout this note's other Advanced subsections) *and* exactly what an attacker uses to move laterally over WinRM. There is no syntactic difference between the two — only context (source host, account, time, destination, and what the session then did) tells them apart. Read every command below as "what a legitimate hunt session looks like on the wire" and cross-check it against the same artifacts before assuming a PSSession you find in the logs was yours.

To list active PSSessions on this host and the destination-side WSMan session-lifecycle events natively (PSSession transcripts, if the `EnableTranscripting` GPO is on, live under `Documents\PowerShell_transcript.*` by default and are the richest record of what actually ran inside a session):

```powershell
Get-PSSession

Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 100 |
    Where-Object { $_.Id -in 91,168 } | Select-Object TimeCreated, Id, Message
```

To pull 4104 (Script Block Logging) content on both ends of a session and compare source vs. destination copies — this note's own guidance is that seeing the same script block on both hosts is strong corroboration, not a coincidence to explain away:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 200 |
    Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

To perform a cross-host sweep for inbound WinRM session-creation events across an estate, to find every destination a given account has PSRemoted into (distinguish a legitimate admin's known sweep pattern from an attacker's by checking whether the account/hosts/timing match an expected change window):

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 91 }
} | Select-Object PSComputerName, TimeCreated, Message | Export-Csv C:\hunt\winrm_session_sweep.csv -NoTypeInformation
```

## Remote Scheduled Tasks

**What it is:** Push a task to a remote host and trigger it, using the Task Scheduler service's own remote-connection support.

```
schtasks /create /s <host> /tn <taskname> /tr "c:\temp\evil.exe" /sc onstart /ru SYSTEM
schtasks /run /s <host> /tn <taskname>
```

**Port/protocol:** RPC (same transport family as `sc.exe`'s remote service control).

**Essentials** (full depth — the complete registration/execution evidence table — lives in **Scheduled Tasks.md → Remote Task Creation for Lateral Movement (note 10)**):

- `TaskScheduler/Operational` 106 (registered) / 200-201 (executed) on the destination — the reliable, default-on baseline; lead with these over the audited-only Security 4698.
- Security 4624 (Type 3) + 4672 for the connecting session.
- The task's own filesystem (`C:\Windows\System32\Tasks\<TaskName>`) and `TaskCache` registry footprint, same structure as any locally-created task.
- Prefetch/ShimCache/Amcache for the pushed executable.

### PowerShell

To list scheduled tasks on this host natively, since a remotely-pushed task looks identical to a local one once registered (full registration/execution event depth is owned by **Scheduled Tasks (10)**):

```powershell
Get-ScheduledTask | Select-Object TaskName, State, @{N='Author';E={$_.Principal.UserId}}
```

To pull the destination-side registration/execution events and flag any task whose action path points at a temp/staging location rather than a normal application install path:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 200 |
    Where-Object { $_.Id -in 106,200,201 } | Select-Object TimeCreated, Id, Message |
    Where-Object { $_.Message -match '\\Temp\\|\\Users\\Public\\' }
```

To sweep an estate for a specific suspect task name pushed remotely, exported for pivoting into a timeline:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ScheduledTask -TaskName '<suspect-task-name>' -ErrorAction SilentlyContinue |
        Select-Object TaskName, State, @{N='Author';E={$_.Principal.UserId}}
} | Select-Object PSComputerName, TaskName, State, Author | Export-Csv C:\hunt\schtask_sweep.csv -NoTypeInformation
```

## Remote Services

**What it is:** Create and start a service on a remote host directly via the Service Control Manager's remote-connection support — the primitive PsExec itself is built on top of.

```
sc \\host create servicename binpath= "c:\temp\evil.exe"
sc \\host start servicename
```

**Port/protocol:** RPC (same transport family as remote scheduled tasks).

**Essentials** (full depth — the complete evidence table — lives in **Services.md → Remote Service Creation for Lateral Movement (note 10)**):

- System 7045 (service installed) on the destination — the reliable, default-on baseline; lead with this over the audited-only Security 4697.
- Security 4624 (Type 3) + 4672 for the connecting session.
- `SYSTEM\CurrentControlSet\Services\<Name>` key creation on the destination, same structure as any local service.
- Prefetch/ShimCache/Amcache for the dropped executable — ShimCache is bypassed if the service is implemented as a service DLL rather than a standalone executable.

### PowerShell

To list services on this host and their binary paths natively; a remotely-created service is indistinguishable at this level from a locally-created one (full 7045/registry evidence chain owned by **Services (10)**):

```powershell
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, PathName
```

To flag any service whose `PathName` points outside the normal `Program Files`/`Windows\System32` install locations — the same "does this belong here" question the destination-host evidence table above is built around:

```powershell
Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch '^"?[A-Z]:\\(Program Files|Windows)\\'
} | Select-Object Name, PathName, StartMode
```

To sweep an estate for services with suspicious binary paths, correlating a hit against 7045 on the same host for a full install timeline:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch '^"?[A-Z]:\\(Program Files|Windows)\\' } |
        Select-Object Name, PathName
} | Select-Object PSComputerName, Name, PathName | Export-Csv C:\hunt\remote_service_sweep.csv -NoTypeInformation
```

## `net use` / Share Mapping / SMB Session Enumeration

`net use \\host\share` (and its scripted/enumeration variants, e.g. `net view \\host`, PowerShell's `Get-SmbShare`/`Get-SmbConnection`) maps a remote SMB share and authenticates a session against it. On its own this is thin — a mapped drive is not code execution — but it plays a specific, recurring role in the broader intrusion narrative: **share mapping is frequently the reconnaissance-and-staging step that precedes one of the execution techniques above.** An attacker maps `\\host\C$` or `\\host\ADMIN$` to confirm write access and find a usable drop location *before* pushing a PsExec service or a remotely-scheduled task — the share-mapping event is often the earliest observable step in a chain that only becomes clearly malicious once a technique-specific footprint (service, task, WMI object) shows up afterward.

**Evidence:**

| Source | Event ID | Notes |
|---|---|---|
| Security 5140 | Network share accessed | The share-level equivalent of a logon event — records the share name and source |
| Security 5145 | Detailed share access check | Finer-grained, records the specific access requested against a file/folder within the share — off by default, same Object Access auditing-gap pattern covered in note 11 |
| Security 4624 (Type 3) | Network logon underlying the share connection | Same logon-type pattern as every other Type 3 technique in this note |

🔴 **Read `net use`/share-mapping activity in context, not isolation.** A single 5140 against `ADMIN$`/`C$` from a host with no legitimate administrative function is worth flagging on its own, but its real diagnostic value comes from what follows it in the timeline — check for a service/task/WMI footprint or a dropped executable appearing on the destination in the minutes after.

### PowerShell

Beyond the active-session/mapping check in Hunt Evil above, to list this host's own shared folders and who currently has files open on them:

```powershell
Get-SmbShare | Select-Object Name, Path, Description
Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path
```

To pull 5140 share-access events and flag `ADMIN$`/`C$` access from source hosts with no expected administrative role, per this section's red flag above:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140} -MaxEvents 200 |
    Where-Object { $_.Message -match 'ADMIN\$|C\$' } | Select-Object TimeCreated, Message
```

To perform a cross-host sweep for every host currently holding an open SMB session against a suspect destination, to build the "who's connected right now" picture across an estate before it changes:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens
} | Select-Object PSComputerName, ClientComputerName, ClientUserName, NumOpens |
    Export-Csv C:\hunt\smb_session_sweep.csv -NoTypeInformation
```

## Pass-the-Hash / Pass-the-Ticket — The Credential-Theft Angle

This is a brief, focused mention — the movement *mechanism* is this note's job, not credential-theft internals. NTLM relay and Pass-the-Hash (PtH) let an attacker authenticate to a remote host using a captured NTLM hash directly, without ever knowing or cracking the plaintext password; Pass-the-Ticket (PtT) does the equivalent with a captured/forged Kerberos ticket. Either credential-theft technique can be the authentication method *underneath* any of the Type-3 techniques covered above (PsExec, WMI, remote services/tasks) — PtH/PtT change *how* the attacker authenticated, not *which* remote-execution primitive they then used.

**What to look for on the destination:**

- Logon Type 9 (NewCredentials) — the `runas /netonly`-style pattern, common when an attacker's tooling explicitly supplies a stolen hash/ticket for outbound authentication while keeping their own session's original logon context.
- Logon Type 3 with NTLM-only authentication where Kerberos would normally be expected on that network — an anomalous auth-package choice is itself a mild PtH signal, distinct from a hash actually being cracked.
- A nearby Security 4648 (explicit credentials) pairing with the Type 9 logon — see note 05's dedicated 4648 section for the full "lateral movement tell" analysis.

Full logon-type mechanics and the 4648 deep dive live in **Users, Groups & Authentication (05)**. Deep credential-theft internals — LSASS memory extraction, Mimikatz artifact analysis, ticket-forging mechanics (Golden/Silver Ticket) — are explicitly out of scope here and belong to the forthcoming **Memory Analysis** note; this note's job stops at recognizing that a Type 9/anomalous-NTLM pattern likely means the attacker didn't need the plaintext password to get here.

## Comparative Summary Table

The single highest-value quick-reference in this note — one row per technique, dense on purpose.

| Technique | Port/Protocol | Primary Destination Event IDs | Primary Destination Artifact | Admin Rights Required? | Common Tooling |
|---|---|---|---|---|---|
| RDP | TCP 3389 | Security 4624 (Type 10/7), LocalSessionManager 21-25, RemoteConnectionManager 1149 | Full interactive session; source-host bitmap cache | Not necessarily (Remote Desktop Users group suffices) | `mstsc.exe`, `xfreerdp` |
| PsExec / SMB admin share | TCP 445 (SMB) | Security 5140/5145, System 7045 (`PSEXESVC`), Security 4624 (Type 3) | `PSEXESVC` service, `EulaAccepted` reg key, `ADMIN$` drop | Yes — local admin on target | PsExec, Impacket `psexec.py`/`smbexec.py`, CrackMapExec |
| WMI/WMIC | TCP 135+dynamic RPC (DCOM) or 5985/5986 (WSMan) | Security 4624 (Type 3), WMI-Activity 5857-5861 | `WmiPrvSE.exe` parent process | Yes — local admin on target | `wmic`, `Invoke-CimMethod`, Impacket `wmiexec.py`, CrackMapExec |
| PowerShell Remoting (WinRM) | TCP 5985 (HTTP) / 5986 (HTTPS) | Security 4624 (Type 3), PowerShell/Operational 4104 (both ends), WinRM/Operational | Active PSSession; 4104 script-block content on source AND destination | Yes — local admin (or explicit WinRM permission) on target; WinRM must be enabled first | `Enter-PSSession`, `Invoke-Command`, Evil-WinRM |
| Remote scheduled task | RPC | Security 4624 (Type 3), TaskScheduler/Operational 106/200/201 | Task XML + `TaskCache` GUID entry | Yes — local admin on target | `schtasks /s`, Impacket `atexec.py` |
| Remote service (`sc create`) | RPC | Security 4624 (Type 3), System 7045 | `SYSTEM\...\Services\<Name>` key | Yes — local admin on target | `sc.exe`, PsExec (built on this primitive) |
| `net use`/share mapping | TCP 445 (SMB) | Security 5140/5145, 4624 (Type 3) | Mapped share handle — reconnaissance/staging, not execution | Depends on share ACL, not necessarily admin | `net use`, `net view`, `Get-SmbShare`, CrackMapExec share enumeration |
| Pass-the-Hash / Pass-the-Ticket | Rides underneath whichever technique above is used | Security 4624 (Type 9), 4648, anomalous NTLM on a Kerberos-preferring network | N/A — an authentication method, not a standalone technique | N/A | Mimikatz, Impacket (`-hashes` flag across its tools), Rubeus (PtT) |

## Tooling

| Tool | Use |
|---|---|
| **EvtxECmd** (Eric Zimmerman) | Pull the relevant event IDs across both source and destination hosts into a normalized CSV/JSON dataset — the standard way to correlate a multi-host lateral-movement timeline; see note 11 for full mechanics |
| **`netstat` / `Get-NetTCPConnection`** | Live enumeration of current connections on a host — useful during an active response window to catch a session still open, though it only shows the *current* state, not history |
| **Sysmon Event ID 3 (Network Connection)** | If deployed, a materially stronger network-evidence source than native Windows logging for reconstructing which process made which outbound connection, to which host/port — native Windows logging has no equivalent per-process network-connection event by default |
| **KAPE** | Multi-host collection targeting — pull the relevant `.evtx` channels, `TaskCache`, `Services` hive keys, and WMI repository files from source and destination hosts in one pass; see Evidence Acquisition & Imaging (note 02) |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `ADMIN$`/`C$` access from a workstation with no legitimate administrative function | Workstations rarely have a real business reason to reach another host's admin share |
| Logon Type 3 immediately followed by 4672 (admin rights) for an account that doesn't normally administer that host | Privilege assignment on a network logon that doesn't match the account's expected role |
| WMI/WinRM/RDP activity outside business hours or from an unusual source IP | Timing/origin anomaly independent of the technique itself |
| `PSEXESVC` (or a similarly-named, short-lived service) appearing and disappearing in System 7045/7036 in rapid succession | Classic transient-service lateral-movement pattern, even if renamed via `-r` |
| Multiple distinct lateral-movement techniques (e.g. WMI, then a scheduled task, then PsExec) used against the same destination host in a short window | Technique-hopping — a strong signal the attacker is probing for whatever isn't monitored or blocked on that host |
| Logon Type 9 (NewCredentials) with no plausible legitimate `runas /netonly` explanation | Possible pass-the-hash/credential-theft-driven movement — pull the nearby 4648 |
| WinRM activity on a host where the service was previously disabled, with a recent enabling configuration change | Attacker turning on the prerequisite service themselves to enable this technique |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full `sc create`/PsExec registry and filesystem evidence chain | **Services (10)** |
| Full remote-task XML/`TaskCache`/event evidence chain | **Scheduled Tasks (10)** |
| Full WMI permanent-subscription and remote-WMI evidence chain, `WmiPrvSE.exe` process-tree context | **WMI Event Consumers (10)** |
| Full logon-type interpretation, 4648 explicit-credentials deep dive, RDP client-side connection-history summary | **Users, Groups & Authentication (05)** |
| EVTX mechanics, retention, audit-policy prerequisites, EvtxECmd usage, full PowerShell/WinRM/RDP log-channel mechanics | **Event Log Analysis (11)** |
| Execution evidence for whatever a lateral-movement technique launched on the destination | **Prefetch**, **ShimCache (AppCompatCache)**, **Amcache** (note 06) |
| LSASS/credential-theft internals, Mimikatz artifact analysis, ticket-forging mechanics | **Memory Analysis** (forthcoming) |
| Kill-chain placement of lateral movement within a broader intrusion timeline | **Threat Hunting Methodology and Intelligence** (forthcoming) |
| Correlating multi-host timelines built from the evidence chains in this note | **Timeline Analysis** (forthcoming) |

## Resources

- SANS FOR508 poster, "Hunt Evil: Lateral Movement" panel — coverage checklist for the source/destination technique layout this note's framework and comparative table are structured around; rewritten here in original prose, no verbatim reproduction
- MITRE ATT&CK Lateral Movement (TA0008) — https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK T1021.001 (Remote Services: Remote Desktop Protocol) — https://attack.mitre.org/techniques/T1021/001/
- MITRE ATT&CK T1021.002 (Remote Services: SMB/Windows Admin Shares) — https://attack.mitre.org/techniques/T1021/002/
- MITRE ATT&CK T1021.003 (Remote Services: Distributed Component Object Model) — https://attack.mitre.org/techniques/T1021/003/
- MITRE ATT&CK T1021.006 (Remote Services: Windows Remote Management) — https://attack.mitre.org/techniques/T1021/006/
- MITRE ATT&CK T1570 (Lateral Tool Transfer) — https://attack.mitre.org/techniques/T1570/
- MITRE ATT&CK T1550.002 (Use Alternate Authentication Material: Pass the Hash) — https://attack.mitre.org/techniques/T1550/002/
- MITRE ATT&CK T1550.003 (Use Alternate Authentication Material: Pass the Ticket) — https://attack.mitre.org/techniques/T1550/003/
- Eric Zimmerman's tools (EvtxECmd) — https://ericzimmerman.github.io/
- Sysinternals PsExec — https://learn.microsoft.com/sysinternals/downloads/psexec
- Impacket — https://github.com/fortra/impacket
- CrackMapExec — https://github.com/Porchetta-Industries/CrackMapExec
- Evil-WinRM — https://github.com/Hackplayers/evil-winrm
- bmc-tools (RDP bitmap cache reconstruction) — https://github.com/ANSSI-FR/bmc-tools
