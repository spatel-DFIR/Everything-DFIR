# PowerUp — Source Evidence

**Framing note before anything else:** unlike every other tool page in this module so far, PowerUp has **no remote-targeting capability at all** — verified directly in source: none of its functions accept a `-ComputerName`/`-Server`/remote-target parameter (the only `$Env:ComputerName` reference in the whole script is cosmetic, used to name the optional HTML report file). PowerUp only ever acts on the host it is currently running on. That means **"source" and "target" are the same host** for every realistic PowerUp use case — this page and `04 - Target Evidence.md` describe two views of the identical host, not two different machines the way PowerView's (source enumerator, target DC) or a lateral-movement tool's (source operator box, target victim host) pages do. This page covers what's recoverable from **live/volatile analysis and the operator's own session** on that host; `04` covers what's recoverable **after the fact** from disk/registry/event logs.

## Contents
- [Loading Method](#loading-method)
- [ConsoleHost_history.txt and Interactive-Session Artifacts](#consolehost_historytxt-and-interactive-session-artifacts)
- [Process Artifacts](#process-artifacts)
- [The Pre-Compiled Payload Blob as a Recoverable Artifact](#the-pre-compiled-payload-blob-as-a-recoverable-artifact)
- [Cached Credential Material](#cached-credential-material)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Loading Method

Identical to PowerView's loading-method matrix (see `PowerView/03 - Source Evidence.md`) — dot-source/`Import-Module` from a staged file, or `IEX (New-Object Net.WebClient).DownloadString(...)`-style in-memory load, with the same consequence: the in-memory path leaves no `PowerUp.ps1` file on disk at all, and recovery of *that the script ran* depends on PowerShell's own logging subsystem (see `04 - Target Evidence.md`, cross-linked to `LOLBins/powershell/04 - Target Evidence.md`).

## ConsoleHost_history.txt and Interactive-Session Artifacts

Same mechanism as documented in full in `LOLBins/powershell/04 - Target Evidence.md` and applied to PowerView in `PowerView/03 - Source Evidence.md` — `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` captures interactive-console input only. For PowerUp specifically, this is often the **richest single artifact available**, because PowerUp is disproportionately likely (relative to PowerView) to be run interactively, one check/abuse function at a time, by an operator working through a manual escalation chain on a single compromised host — `Get-ModifiableService`, then `Set-ServiceBinaryPath`, then `Install-ServiceBinary`, then a service restart, typed in sequence at a live prompt, all land here verbatim if the session was interactive.

## Process Artifacts

- **Command line**: same Sysmon 1/Security 4688 capture as any PowerShell invocation on this host — see `LOLBins/powershell/04 - Target Evidence.md`.
- **Loaded assemblies**: the reflective `Add-Win32Type` pattern (see `01 - Overview.md`) causes the hosting `powershell.exe`/`pwsh.exe` process to hold dynamically-generated, unbacked assemblies wrapping `advapi32.dll` P/Invoke calls — a real memory-forensics signature (see below), and one that never shows up as a normal DLL-load event since no `advapi32.dll`-wrapping helper DLL is ever loaded from disk.
- **No `sc.exe` child process** for the service-abuse path — directly consequential for process-tree-based hunting: an analyst looking for `powershell.exe → sc.exe` as evidence of scripted service abuse will find nothing for PowerUp's own service functions, since `ChangeServiceConfig`/`QueryServiceObjectSecurity` are called via P/Invoke, not by spawning the `sc.exe` binary (see `01 - Overview.md`'s How It Works section, cross-linked to `LOLBins/sc/`).

## The Pre-Compiled Payload Blob as a Recoverable Artifact

Because `Write-ServiceBinary`/`Install-ServiceBinary`/`Write-UserAddMSI` all decode a **hardcoded Base64 PE/MSI blob already embedded in the PowerUp script itself** (see `01 - Overview.md`'s red-flag callout), that blob is recoverable from **any surviving copy of the PowerUp.ps1 source** — a staged file on disk, a cached web-proxy log entry for the download-cradle fetch, or a memory-resident copy of the script text — independent of whether the dropped binary itself is still present on the filesystem. This is a distinctive property worth flagging: most tools' "what got dropped" and "what delivered it" are separate artifact classes; here, the delivery mechanism (the script) and the payload template are the same object, so recovering one recovers the other.

## Cached Credential Material

- Where `Install-ServiceBinary`'s default user-creation behavior was used, the created account's password (`Password123!` unless overridden — see `04 - Target Evidence.md`'s Default-Credential Signature section) exists briefly in the PowerShell session's memory as a plaintext string argument, recoverable via live memory analysis while the process is still running.
- Credentials recovered by the harvesting functions (`Get-CachedGPPPassword`, `Get-RegistryAutoLogon`, `Get-SiteListPassword`, `Get-WebConfig`) are held as PowerShell string/object output for the remainder of the session — if the operator piped output to a file (`Out-File`, `| Export-Csv`) that becomes a straightforward filesystem artifact on this same host; if only displayed to console, it's a memory-only artifact until the session ends.

## OS-Level Audit Trail

No distinct signal beyond what `LOLBins/powershell/04 - Target Evidence.md` already documents for PowerShell generally — Module/Script Block Logging off by default, the narrow always-on Warning-level 4104 heuristic for a hardcoded suspicious-strings list (PowerUp's own reflective `Add-Win32Type`/`DllImport`-pattern code is very likely to trip this heuristic, since those exact strings are on the documented list — a genuinely useful, source-verified detail: **PowerUp's own reflective-API mechanism is more likely than PowerView's LDAP-only code to trigger the always-on Warning-level exception**, since PowerView uses far less `Add-Win32Type`/`DllImport`-pattern code overall).

## Memory-Forensics Angle

- Same unbacked-executable-memory signature discussed for PowerView applies here, with the specific addition that PowerUp's dynamically-generated P/Invoke wrapper types (`advapi32`, `netapi32` function tables) are a recognizable, source-verifiable structure to look for if reversing a suspected PowerUp session from a memory image.
- The decoded pre-compiled service-binary/MSI blob, if the script executed far enough to decode it, exists as a contiguous byte sequence in process memory matching the known `$B64Binary` template (minus the patched command) — a strong, source-verified static signature for memory scanning, independent of whether the binary ever reached disk.

## Timeline Correlation Value

Because source and target coincide for PowerUp, the timeline-building exercise is simpler than PowerView's cross-host correlation problem — everything lives on one host's own artifact set: `[process creation/Sysmon 1, if the engine launched directly]` → `[ConsoleHost_history.txt, interactive sessions]` → `[registry ImagePath change / Event log gap, see 04]` → `[service restart / new process spawned as SYSTEM]`. See `04 - Target Evidence.md` and `05 - Detection and Hunting.md` for the registry/event-log half of that same single-host chain.
