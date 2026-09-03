# Live Response and Volatile Data

Everything in this note happens on a system that is still running. That single fact is both the opportunity and the hazard: a live Windows host holds evidence that a disk image can never contain — the process table, live network connections, decrypted memory contents, open handles, what's actually in the DNS cache right now — but every command an analyst runs to collect it also changes the host, including generating fresh Prefetch/ShimCache/Amcache entries for the analyst's *own* tooling (note 06). This note is the collection methodology and sequencing for that window: what to capture, in what order, and with what tool, before the volatile tier is gone. It mirrors the Linux module's Live Response and Volatile Data note in structure, but every command and artifact below is Windows-specific.

Full acquisition-strategy tradeoffs — whether to go live at all versus power off and image dead-box, encryption-detection sequencing, chain of custody — are owned by **Evidence Acquisition & Imaging (note 02)**. This note assumes live response has already been chosen and focuses on *how to execute it well*.

> 🔴 **Capture memory before extensive live-command interaction, and follow the order of volatility.** Every keystroke on a live host risks displacing the very RAM pages under investigation and adds your own tooling to Prefetch/ShimCache/Amcache/PowerShell history — document every command run so it can later be distinguished from attacker activity.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Order of Volatility](#order-of-volatility)
- [Live Response Principles and Cautions](#live-response-principles-and-cautions)
- [Memory Acquisition — Priority and Forward Reference](#memory-acquisition--priority-and-forward-reference)
- [Live Collection by Category](#live-collection-by-category)
  - [Running Processes](#running-processes)
  - [Network Connections](#network-connections)
  - [Logged-On Users and Sessions](#logged-on-users-and-sessions)
  - [Open Files and Handles](#open-files-and-handles)
  - [Loaded DLLs and Modules Per Process](#loaded-dlls-and-modules-per-process)
  - [Autoruns Snapshot](#autoruns-snapshot)
  - [Command History](#command-history)
  - [Scheduled Tasks and Services Snapshot](#scheduled-tasks-and-services-snapshot)
  - [Clipboard](#clipboard)
- [Triage Collection Scripting and Automation](#triage-collection-scripting-and-automation)
- [Recommended Response Sequence](#recommended-response-sequence)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native PowerShell triage against a live host — no Sysinternals, no third-party module, roughly in order-of-volatility priority. This is the fast pass; the category-by-category sections below go deeper on each.

```powershell
# System time, boot time, and uptime - normalizes every timestamp collected afterward against clock skew (Recommended Response Sequence, step 1)
Get-Date; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# Running processes with path, start time, and owning account - the live process table, order-of-volatility position 4
Get-Process -IncludeUserName | Select-Object Id, ProcessName, Path, StartTime, UserName

# TCP connections joined to owning process name - native equivalent of `netstat -anob` without its admin-rights/slowness tradeoff
Get-NetTCPConnection | ForEach-Object {
    [PSCustomObject]@{
        Local   = "$($_.LocalAddress):$($_.LocalPort)"
        Remote  = "$($_.RemoteAddress):$($_.RemotePort)"
        State   = $_.State
        Process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    }
}

# Logged-on sessions and their logon type - live session state; see note 05 for logon-type interpretation
Get-CimInstance Win32_LogonSession | Select-Object LogonId, LogonType, StartTime

# ARP cache and DNS resolver cache - zero-cost, fast-changing network state that doesn't survive a flush or reboot
Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress, LinkLayerAddress, State
Get-DnsClientCache | Select-Object Entry, Data, TimeToLive

# Auto-start services and enabled scheduled tasks in one pass - the live persistence snapshot to grab before shutdown
Get-CimInstance Win32_Service | Where-Object StartMode -eq 'Auto' | Select-Object Name, PathName, StartName
Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName, TaskPath, State

# Clipboard contents - low-cost but easy to disturb by viewing it yourself, so grab it early rather than returning to it later
Get-Clipboard
```

## Order of Volatility

The classic RFC 3227 order of volatility, adapted for a Windows host — most volatile (capture first, gone soonest) to least volatile (capture last, survives longest):

| Order | Layer | Capturable in live response? | Notes |
|---|---|---|---|
| 1 | CPU registers / cache | Essentially no | Mentioned for completeness — no practical live-response tool captures register/cache state in a form useful to a triage analyst; by the time any tool runs, this layer has already changed |
| 2 | **RAM / physical memory** | **Yes — highest-priority capturable evidence** | Running processes, network state, kernel statistics, encryption keys, injected/fileless code — all live only here; see Memory Acquisition below |
| 3 | Network state | Yes | Active connections, listening ports, ARP cache, DNS cache, routing table |
| 4 | Running processes | Yes | Process table, command lines, loaded modules, open handles |
| 5 | Disk (temp files, page/swap file) | Yes, but not truly volatile | `pagefile.sys`/`swapfile.sys` hold memory-adjacent fragments — see note 02's Static Memory-Adjacent Sources for the dead-box angle |
| 6 | Remote logging / monitoring data | Yes, off-host | SIEM/EDR telemetry already shipped off the host before the analyst arrived — outside this note's live-collection scope but worth pulling in parallel |
| 7 | Physical configuration / network topology | Yes, but changes slowly | Network diagrams, switch/firewall configs — rarely relevant to a single-host triage |
| 8 | Archival media | Yes, essentially permanent | Backups, offline media — least volatile, can wait indefinitely |

**Why the order matters:** every live-response action has a cost. Running a command touches the system — it allocates memory (potentially displacing pages you'd otherwise have captured), writes execution artifacts (Prefetch/ShimCache/Amcache, command history), and can overwrite volatile state that only existed for a moment. Collection should proceed from most-volatile-and-highest-priority to least, and any action with a larger footprint (imaging, extensive filesystem walks, rebooting) should be deferred until after the fragile volatile tier is captured — see Recommended Response Sequence below for how this translates into an actual walk-up-to-the-host order.

## Live Response Principles and Cautions

- **Your own toolkit becomes part of the evidence.** Running `tasklist`, `handle.exe`, or any other live-response tool generates the same execution artifacts — Prefetch, ShimCache, Amcache, command-line history — that the module uses to prove *attacker* execution (note 06). An analyst who doesn't track what they ran will later struggle to distinguish their own triage activity from the intrusion under investigation.
- **Run from read-only, trusted external media where possible** — a USB drive carrying a known-clean, ideally statically-linked toolkit — rather than installing tools onto the target. Installing a tool writes it to disk, registers it in Prefetch/Amcache under a name the analyst chose, and risks picking up a compromised system DLL if the host's own loader path has been tampered with.
- **Document every command run** — timestamp, exact command line, and result location. This isn't just good practice; it's what later lets the analyst explain to opposing counsel, a client, or a peer reviewer exactly why a given Prefetch/ShimCache/Amcache/PowerShell-history entry exists and that it was the analyst's own activity, not the intruder's.
- **The live-vs-dead-box decision itself is out of scope here** — see note 02's Live vs Dead-Box Acquisition and Decision Flow sections for that tradeoff. This note assumes the decision has already landed on "work the system live" and picks up from there.

## Memory Acquisition — Priority and Forward Reference

Capture a full memory image **before** extensive live-command-line interaction. RAM is the most volatile *capturable* evidence (order-of-volatility position 2), and every subsequent live command — including the collection steps later in this note — risks allocating pages that overwrite or displace the very memory contents under investigation.

**WinPMEM** and **Magnet RAM Capture** are the standard tools for this step (both already named in note 02's Memory Acquisition section). Full acquisition mechanics (physical vs logical capture, kernel-driver detection risk) and full memory *analysis* depth (process trees, injected code, hidden processes, rootkit detection) belong to the forthcoming **Memory Forensics** notes (17) — this note's job is only to place memory capture correctly in the sequence: early, before the category-by-category collection below.

## Live Collection by Category

The commands below are the core of live triage — one category at a time, roughly in order-of-volatility priority. Each surfaces raw data; interpreting whether a given finding is normal or anomalous leans on the baseline/artifact-family knowledge already built out elsewhere in this module, cross-referenced per category.

### Running Processes

```
tasklist /v
```

```powershell
Get-Process | Select-Object Id, ProcessName, Path, StartTime
```

A live process listing alone doesn't tell you what's *anomalous* — that judgment needs a baseline of what a normal Windows process tree looks like (parent/child expectations, which processes should and shouldn't spawn which children). See **Windows OS Fundamentals & Versions (note 01)**, "Know Normal: The Core Process Tree," before treating any single live-listed process as suspicious on its own.

### PowerShell

Since `Get-Process` above doesn't expose the command line or parent PID, `Win32_Process` does, and parent/child pairing is exactly what note 01's process-tree baseline is for:

```powershell
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Sort-Object ParentProcessId
```

To identify processes running from a user-writable path, the process-list equivalent of the service/task drop-and-persist pattern covered in note 10:

```powershell
Get-Process | Where-Object { $_.Path -match '\\(Temp|AppData|ProgramData)\\' } | Select-Object Id, ProcessName, Path
```

### Network Connections

```
netstat -anob
```

The `-b` flag names the owning executable for each connection — genuinely high-value, since it maps a socket straight to a process without a separate lookup. Two operational tradeoffs worth flagging: it requires administrative rights, and it can be noticeably slow (and, on some systems, is documented as potentially disruptive) against a production host — weigh that cost against the value before running it broadly.

```powershell
Get-NetTCPConnection
```

```
arp -a
ipconfig /displaydns
```

`arp -a` dumps the local ARP cache — cross-reference **Lateral Movement (note 12)** where relevant for network-side lateral-movement evidence. `ipconfig /displaydns` dumps the DNS resolver cache — a fast, zero-cost first check that can retain recently resolved hostnames regardless of which application triggered the resolution; see **Private Browsing & Anti-Forensic Recovery (14)**, DNS Cache section, which already covers this artifact and explicitly points back here.

### PowerShell

For native cmdlet equivalents of `arp -a` and `ipconfig /displaydns`:

```powershell
Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress, LinkLayerAddress, State
Get-DnsClientCache | Select-Object Entry, Name, Data, TimeToLive
```

Since `Get-NetTCPConnection` alone doesn't name the owning process the way `netstat -anob` does, join it to `Get-Process` for the same answer without the admin-rights/performance tradeoff called out above, plus the UDP endpoints TCP-only tooling misses:

```powershell
Get-NetTCPConnection | ForEach-Object {
    [PSCustomObject]@{
        Local   = "$($_.LocalAddress):$($_.LocalPort)"
        Remote  = "$($_.RemoteAddress):$($_.RemotePort)"
        State   = $_.State
        Process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    }
}

Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess
```

### Logged-On Users and Sessions

```
query user
quser
net session
```

A live session listing shows *who's connected right now*, but interpreting what kind of session it is (interactive, RDP/RemoteInteractive, network, service) needs the logon-type reference in **Users, Groups & Authentication (note 05)**, "Logon Types (Event ID 4624/4625)."

### PowerShell

Since `query user`/`quser`/`net session` have no single cmdlet equivalent, `Win32_LogonSession` is the closest native source, and its `LogonType` maps directly onto note 05's reference table:

```powershell
Get-CimInstance Win32_LogonSession | Select-Object LogonId, LogonType, StartTime, AuthenticationPackage
```

To pair each session with the account that owns it, via the `Win32_LoggedOnUser` association class:

```powershell
Get-CimInstance Win32_LoggedOnUser | ForEach-Object {
    [PSCustomObject]@{
        Session = ($_.Antecedent -replace '.*Domain="([^"]+)",Name="([^"]+)".*', '$1\$2')
        LogonId = ($_.Dependent  -replace '.*LogonId="(\d+)".*', '$1')
    }
} | Sort-Object LogonId -Unique
```

### Open Files and Handles

Sysinternals **`handle.exe`** enumerates what files, named pipes, and registry keys a given process (or the whole system) currently has open — live-response relevance is answering "what does this suspicious process have its hands on right now" before it exits and those handles close.

### Loaded DLLs and Modules Per Process

Sysinternals **`listdlls.exe`** dumps every loaded module for a running process, including full path and, notably, whether a module was relocated (a rough proxy for whether it loaded at its preferred base address, occasionally worth a second look). For live observation of the DLL *search-order walk itself* as it happens (as opposed to a static snapshot of what's currently loaded), see **DLL Hijacking (10)**'s Process Monitor technique — that note already covers using Procmon to catch a hijack in progress; this note's `listdlls.exe` step is the fast snapshot, not the real-time walk.

### PowerShell

Since `Get-Process` exposes loaded modules natively per process, but lacks `listdlls.exe`'s relocation flag, treat this as the quick single-process check, not a full replacement:

```powershell
(Get-Process -Id <PID>).Modules | Select-Object ModuleName, FileName, Company
```

To find modules loaded from outside the expected `System32`/`Program Files` locations, across every running process at once:

```powershell
Get-Process | ForEach-Object {
    $proc = $_
    try {
        $_.Modules | Where-Object { $_.FileName -notmatch '^C:\\Windows\\(System32|SysWOW64)\\' -and $_.FileName -notmatch '^C:\\Program Files' } |
            Select-Object @{N='Process'; E={$proc.ProcessName}}, ModuleName, FileName
    } catch {}
}
```

### Autoruns Snapshot

Sysinternals **`autorunsc.exe`** (command-line Autoruns) is the single fastest way to snapshot the entire persistence landscape of a live host in one pass — Run/RunOnce keys, services, scheduled tasks, WMI subscriptions, and more, all in one output. Rather than re-deriving any of that content here, cross-reference the full **Persistence Mechanisms** family (10): **Autostart (Run/RunOnce) Keys**, **Services**, **Scheduled Tasks**, **WMI Event Consumers**, and **DLL Hijacking**. This note's contribution is simply: run `autorunsc.exe` early in a live-triage pass, because it surfaces all five mechanisms at once instead of requiring five separate manual checks.

### Command History

PowerShell keeps its own persistent command history independent of the console session — the file path is typically under `%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` (confirm the exact path on the host with `(Get-PSReadlineOption).HistorySavePath`, since it can vary by PSReadLine version/profile). This is a genuinely valuable live-response artifact: it shows exactly what commands were typed into a PowerShell session — whether by an attacker operating interactively on the box, or by the responding analyst, which matters for the same chain-of-custody/self-attribution point raised above.

### PowerShell

To resolve the actual history file path on this host, then read it (running this itself appends a new line — expected, and part of what "document every command run" means):

```powershell
(Get-PSReadlineOption).HistorySavePath
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
```

Since the in-session history object carries start/end times per command, which the flat text file doesn't, this is useful for placing a suspicious command precisely on the timeline:

```powershell
Get-History | Select-Object Id, CommandLine, StartExecutionTime, EndExecutionTime
```

### Scheduled Tasks and Services Snapshot

```
schtasks /query
sc query
```

Fast live enumeration of what's currently registered — full evidence-chain depth (registration events, `TaskCache`, `ImagePath`/`ObjectName` interpretation) belongs to **Scheduled Tasks** and **Services** (10); these commands are the live-triage snapshot, not a substitute for that depth.

### PowerShell

For native cmdlet equivalents of `schtasks /query` and `sc query`, the fast live-triage snapshot:

```powershell
Get-ScheduledTask | Select-Object TaskName, TaskPath, State
Get-CimInstance Win32_Service | Select-Object Name, StartMode, State, PathName
```

For the full `ImagePath`/`ObjectName`/registration-event evidence chain and the Hunt-Evil-depth hunting queries against these same cmdlets (drop-and-persist paths, unsigned binaries, `ServiceDll` abuse, 7045 correlation), see **Services (10)** and **Scheduled Tasks (10)** directly rather than re-deriving that depth here.

### Clipboard

Clipboard contents are a real, if often overlooked, live-response artifact — a pasted password, a C2 command, or exfiltrated text can sit in the clipboard at the moment of response. Collection is host-state-dependent and easy to disturb (viewing or using the clipboard yourself can overwrite it), so treat it as a low-cost, early check rather than something to return to later.

### PowerShell

For a native clipboard read, no third-party tool required:

```powershell
Get-Clipboard
```

## Triage Collection Scripting and Automation

Running each category above by hand doesn't scale across an active incident, so triage collection is normally automated:

| Tool | Scope | Role |
|---|---|---|
| **KAPE** | Single-host (or scripted across many via remoting/EDR console) | Already established for imaging/triage-collection in **Evidence Acquisition & Imaging (note 02)** — the `!SANS_Triage` target and similar bundle much of the filesystem/registry/log side of a live-triage pull into one repeatable collection, run here for the live-triage use case specifically rather than post-mortem imaging |
| **CyLR** | Single-host, fast targeted collection | Lightweight open-source live-collection tool focused on grabbing a defined artifact set quickly and packaging it for offline analysis — a narrower, faster alternative to a full KAPE pass when speed matters most |
| **Kansa** | Enterprise-scale, many hosts at once | PowerShell-based framework for pushing collection modules out across an entire domain/fleet and pulling results back centrally — distinct from KAPE's single-host-triage focus; Kansa is built for "run this collection against every endpoint," not "collect deeply from one host." (Hedge: exact current module set/maintenance status not independently verified here — treat the framework's role as described, confirm specifics against current documentation before relying on it operationally.) |

None of these automated tools replace understanding *what* they're collecting and *why* — the category-by-category commands above are what these tools are ultimately running under the hood.

## Recommended Response Sequence

The practical order an analyst should follow sitting down at a live, potentially-compromised host, built directly from the order-of-volatility reasoning above:

```
1. Document system time, timezone, and uptime
   (date/time skew normalization for every timestamp collected afterward)
        │
        ▼
2. Capture memory
   (WinPMEM / Magnet RAM Capture — before anything else touches RAM)
        │
        ▼
3. Capture network state
   (netstat -anob, Get-NetTCPConnection, arp -a, ipconfig /displaydns)
        │
        ▼
4. Capture process / handle / DLL state
   (tasklist /v, Get-Process, handle.exe, listdlls.exe)
        │
        ▼
5. Capture autoruns / persistence snapshot
   (autorunsc.exe — covers all five Persistence Mechanisms notes at once)
        │
        ▼
6. Capture command history
   (PowerShell ConsoleHost_history.txt, plus logged-on-session state — query user, net session)
        │
        ▼
7. THEN proceed to imaging / dead-box acquisition (note 02) if warranted
   — by this point the fragile, capture-once volatile tier is already preserved
```

This is a floor, not a rigid script — a specific incident may reorder steps within the volatile tier (e.g., pulling the DNS cache alongside network state rather than as a separate pass), but memory capture staying at step 2, and full disk imaging staying last, are the two anchors that should not move.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Analyst's own live-response tool execution appearing in Prefetch/ShimCache/Amcache | A genuine, common source of confusion — must be distinguished from attacker activity by cross-referencing the documented command log, not assumed to be malicious |
| Memory not captured before extensive live-command interaction | An investigation-methodology red flag, not a target-host one — every command run before memory capture risks displacing the volatile evidence the response was meant to preserve |
| Unexplained gaps in PowerShell command history | Suggests selective clearing — an attacker (or, less often, a well-meaning but undisciplined analyst) removing evidence of specific commands from `ConsoleHost_history.txt` |
| `netstat`/process findings inconsistent with what Autoruns/persistence-mechanism notes would predict | A mismatch between "what's running now" and "what's configured to persist" is worth investigating directly — it can mean a process was launched outside its normal persistence path, or that a persistence mechanism hasn't fired yet |
| No documentation of commands run during live response | Undermines the analyst's own ability to later distinguish their triage activity from the intrusion under investigation |

## Tooling

| Tool | Use |
|---|---|
| **Sysinternals `handle.exe`** | Live enumeration of open files/pipes/registry keys per process |
| **Sysinternals `listdlls.exe`** | Live snapshot of loaded modules per process |
| **Sysinternals `autorunsc.exe`** | Command-line Autoruns — fast full-persistence-landscape snapshot |
| **`tasklist` / `netstat` / `query user` / `schtasks` / `sc` / `ipconfig` / `arp`** | Native Windows commands for process, network, session, task, service, and DNS/ARP-cache live enumeration |
| **PowerShell (`Get-Process`, `Get-NetTCPConnection`)** | Cmdlet equivalents of several native commands above, with richer object output |
| **KAPE** | Automated triage collection, single-host or scripted across a fleet — already covered for imaging in note 02, used here for the live-triage use case |
| **CyLR** | Lightweight, fast targeted single-host live collection |
| **Kansa** | PowerShell-based enterprise-scale live-response/collection framework across many hosts at once |
| **WinPMEM / Magnet RAM Capture** | Memory acquisition — full depth in the forthcoming Memory Forensics notes (17) |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Live-vs-dead-box acquisition tradeoffs, encryption-detection sequencing, chain of custody | **Evidence Acquisition & Imaging (02)** |
| Baseline process-tree knowledge for judging what a live process/network finding actually means | **Windows OS Fundamentals & Versions (01)** |
| Full evidence chains for whatever Autoruns/`schtasks`/`sc` surface in the live snapshot | All five **Persistence Mechanisms** notes (10) |
| Interpreting logon types found in `query user`/`net session` | **Users, Groups & Authentication (05)** |
| The "your own tools leave traces too" problem in full — Prefetch/ShimCache/Amcache mechanics | **Evidence of Program Execution** notes (06) |
| DLL search-order hijacking caught live via Procmon | **DLL Hijacking (10)** |
| DNS-cache artifact as it relates to private-browsing recovery | **Private Browsing & Anti-Forensic Recovery (14)** |
| Network/lateral-movement live evidence (`netstat`/`Get-NetTCPConnection` already referenced there) | **Lateral Movement (12)** |
| Full memory acquisition mechanics and deep analysis (processes, injection, rootkits) | **Memory Forensics** (forthcoming, 17) |
| Building a unified timeline from everything captured here | **Timeline Analysis** (forthcoming, 18) |

## Resources

- SANS FOR500/FOR508 posters and indices — coverage checklist for triage-collection scope, rewritten here in original prose, no verbatim reproduction
- Sysinternals Suite documentation — https://learn.microsoft.com/sysinternals/
- KAPE (Kroll Artifact Parser and Extractor) documentation — https://www.kroll.com/kape
- RFC 3227, "Guidelines for Evidence Collection and Archiving" — https://www.rfc-editor.org/rfc/rfc3227 (the original order-of-volatility reference this note's opening table adapts for Windows)
