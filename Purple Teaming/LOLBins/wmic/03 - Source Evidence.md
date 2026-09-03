# LOLBins — wmic.exe — Source Evidence

**Framing note.** `wmic.exe` doesn't fit either extreme this module has already covered. It isn't `bitsadmin.exe`/`certutil.exe`-shaped (a binary that only ever runs *on* the victim host, with no separate "operator box" concept at all) — for `/node:` remote use there's a genuine, separate attacker/operator machine. But it also isn't quite [`wmiexec.py`](<../../Impacket/wmiexec/01 - Overview.md>)-shaped either: `wmiexec.py`'s operator box is almost always a Linux/Kali machine, so that note's Source Evidence leans on shell history and `auditd`. `wmic.exe` **only runs on Windows**, so its own operator box — whether that's a separate `/node:`-launching machine or the single host a purely local command runs on — is itself a Windows endpoint generating native Windows telemetry (Sysmon, Security 4688, Prefetch) for the `wmic.exe` process itself. That telemetry is what this file covers.

**Local vs. `/node:` remote matters here more than for any other file in this folder.** For a purely local command (no `/node:`), the "source" host and the "target" host are the literal same machine — everything in this file and everything in `04 - Target Evidence.md` describe one box, and `04`'s `WmiPrvSE.exe`-child material is the stronger signal of the two. This file earns its keep specifically for genuine `/node:` remote use, where the operator's box really is a separate machine from whatever `/node:` named — and for one XSL-specific case (see below) that fires regardless of `/node:`.

## Contents
- [Command-Line and Shell History](#command-line-and-shell-history)
- [Live Process State](#live-process-state)
- [Local Network-Connection State](#local-network-connection-state)
- [Cached Credential Material](#cached-credential-material)
- [Process Artifacts and OS-Level Audit Trail](#process-artifacts-and-os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Command-Line and Shell History

| Shell | Artifact | Notes |
|---|---|---|
| `cmd.exe` | None persistent by default | The in-session `doskey` command buffer is memory-only and gone the moment the `cmd.exe` process exits — there is no `cmd.exe` equivalent of `.bash_history` unless the operator explicitly piped a transcript or ran under `doskey /history` logging they arranged themselves |
| PowerShell | `%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | If `wmic.exe` was invoked from a PowerShell session, PSReadLine's persistent history file captures the full line verbatim, including any inline `/user:`/`/password:` credentials. See `Windows/16 - Live Response and Volatile Data.md` for general PSReadLine mechanics this note doesn't re-derive |

Per `01 - Overview.md`'s Prerequisites table, `wmic.exe` has **no credential-file input mode** the way `wmiexec.py` has `-A authfile` — an operator who needs explicit alternate credentials for `/node:` has no way to keep them off the command line entirely. Whatever captures the command line (PSReadLine history, or the audit trail below) captures the password in cleartext alongside it.

## Live Process State

```powershell
Get-Process -Name wmic -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='wmic.exe'" | Select-Object ProcessId, ParentProcessId, CommandLine
```

While `wmic.exe` is running, its full command line — including any inline `/password:`— is visible to any other local process or user querying `Win32_Process`/`Get-Process`, the same local exposure risk `wmiexec.py`'s `/proc/<pid>/cmdline` carries on Linux. **The parent-process chain is worth reviewing on its own**: an interactive analyst or red-team operator typing at a console shows `wmic.exe` parented by `cmd.exe`/`powershell.exe`/`conhost.exe`; a C2 implant tasking the same command instead shows `wmic.exe` parented by whatever process hosts the implant's command-execution primitive — a useful discriminator when triaging *how* the operator got to the point of running `wmic.exe` at all, distinct from what `wmic.exe` itself then did (covered in `04 - Target Evidence.md`).

## Local Network-Connection State

```powershell
Get-NetTCPConnection -RemotePort 135 -ErrorAction SilentlyContinue
Get-NetTCPConnection | Where-Object { $_.RemotePort -ge 49152 -and $_.RemotePort -le 65535 }
```

Two structurally different outbound connections can originate from the source host, and they map to different techniques:

| Connection | When It Appears | What It's For |
|---|---|---|
| TCP 135 (RPC endpoint mapper) → dynamically negotiated high port | **Only** for `/node:` remote use — never for a purely local command | The DCOM/RPC channel `wmic.exe` uses to reach the remote WMI service, per `01 - Overview.md`'s How It Works §3. **Absent entirely** for local-only execution, since local COM activation never leaves the box |
| Outbound HTTP(S) or an SMB tree-connect | For the XSL-transform ("SquiblyTwo") technique, **regardless of whether `/node:` is also in use** | `wmic.exe` itself fetching the malicious `.xsl` stylesheet from the URL or SMB path given to `/format:` — this connection originates from whichever host is actually running `wmic.exe`, independent of the DCOM channel above |

A local-only, non-XSL command (e.g. plain `wmic.exe process call create "calc.exe"` with no `/node:`) produces **zero** outbound network connections from `wmic.exe` at all — a useful negative check when triaging whether a given invocation was local or remote.

## Cached Credential Material

If the operator supplied explicit `/user:`/`/password:` for `/node:` use rather than relying on the current user's token, Windows creates a logon session for that identity on the source host at the point of DCOM authentication, and LSASS caches the corresponding credential material for the life of that session — recoverable via the same `sekurlsa::logonpasswords`-class technique covered in [`Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md`](<../../Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md>) if the source host itself is later seized or compromised. `wmic.exe` has no saved-credential/credential-manager integration of its own — every credential artifact here traces back to the OS-level logon session the explicit `/user:`/`/password:` triggered, not to anything `wmic.exe` persists itself.

## Process Artifacts and OS-Level Audit Trail

> 🔴 **This is the only place the operator's literal command line is recoverable.** Target-side evidence (`04 - Target Evidence.md`) never sees the actual `wmic.exe` invocation — WMI-Activity and Sysmon on the *target* only ever see the resulting `Win32_Process.Create()` method call or WQL query, not the `/user:`/`/password:`/`/node:`/`/format:` arguments `wmic.exe` was actually typed with. If command-line auditing matters for attribution or credential recovery, the **source** host's own 4688/Sysmon 1 is the only place to find it.

| Artifact | Detail |
|---|---|
| Security 4688 (Process Creation) | If command-line auditing is enabled, captures `wmic.exe`'s full invocation verbatim — including `/password:` in cleartext, the complete `/node:` target list, and the `/format:` stylesheet path/URL for the XSL variant |
| Sysmon 1 (Process Create) | Same full-command-line capture as 4688, plus `ParentImage` — the discriminator between an interactive console launch and a scripted/C2-tasked one described above |
| Sysmon 3 (Network Connect) | The DCOM/RPC outbound connection (`/node:` use) and/or the HTTP(S)/SMB stylesheet fetch (XSL use), both originating from `wmic.exe`'s own PID |
| Prefetch | `WMIC.EXE-<HASH>.pf` on the source host, updated on every run. See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record `wmic.exe` execution on the source host — corroborating, low-uniqueness signals. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |

## Memory Forensics

`wmic.exe` runs as an ordinary, typically short-lived process — standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) shows nothing structurally unusual about it. Its forensic value in memory is the same as for `wmiexec.py`: a `/password:` value is recoverable from process memory even in scenarios where 4688/Sysmon logging was disabled or suppressed. For the XSL variant specifically, the plaintext JScript/VBScript payload passes through `wmic.exe`'s own process space (via the CLR-hosted script engine, per `01 - Overview.md`'s How It Works §5) before execution — a live memory capture of `wmic.exe` mid-run is the only source-side artifact that can recover the **actual script content**, since neither the source-host artifacts above nor the target-side `wmic.exe.log` CLR usage entry (see `04 - Target Evidence.md`) record the script text itself.

## Timeline Correlation Value

For genuine `/node:` remote use, the tightest cross-host anchor is: source-host Sysmon 1/Security 4688 for the `wmic.exe` launch → source-host Sysmon 3 (DCOM outbound) → target-host Security 4624 (Type 3, DCOM auth) → target-host WMI-Activity 5857 → target-host Sysmon 1 (`WmiPrvSE.exe` → child process, execution family only). For purely local execution, this entire chain collapses onto a single host's timeline, and the source-side artifacts in this file become the *only* record of the operator's literal command-line intent — `04 - Target Evidence.md`'s artifacts still show that something happened, but not the exact flags used to cause it.
