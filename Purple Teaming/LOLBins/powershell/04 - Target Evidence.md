# LOLBins — powershell.exe / pwsh.exe — Target Evidence

This is the module's own distinctive content for this tool: unlike every other sub-tool in `Purple Teaming/`, the strongest evidence classes here come from the **executing engine's own instrumentation**, not from OS-level process/file/network telemetry layered on top. That instrumentation is also, per `01 - Overview.md`, mostly **off by default** — so this file is organized around what each source actually requires to be turned on, not just what it captures.

## Contents
- [Two Separate Event Logs — Don't Confuse Them](#two-separate-event-logs--dont-confuse-them)
- [Windows Event Logs — Classic "Windows PowerShell" Channel](#windows-event-logs--classic-windows-powershell-channel)
- [Windows Event Logs — Microsoft-Windows-PowerShell/Operational Channel](#windows-event-logs--microsoft-windows-powershelloperational-channel)
- [Transcription](#transcription)
- [PSReadLine History](#psreadline-history)
- [Security Log and Sysmon](#security-log-and-sysmon)
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Behavior](#endpoint-security-product-behavior)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)

---

## Two Separate Event Logs — Don't Confuse Them

Windows PowerShell writes to **two architecturally distinct logs**, each with its own history and default state — conflating them is a common analyst mistake:

| Log | Location | Introduced | Holds |
|---|---|---|---|
| **"Windows PowerShell"** (classic) | `Applications and Services Logs\Windows PowerShell` | PowerShell 2.0 era — the original engine-lifecycle logging | Engine start/stop, provider start/stop, and (if module logging was separately enabled) pipeline execution detail — Event IDs 400/403/600/800, detailed below |
| **"Microsoft-Windows-PowerShell/Operational"** (modern) | `Applications and Services Logs\Microsoft\Windows\PowerShell\Operational` | PowerShell 4.0/5.0-era — the modern Script Block/Module Logging subsystem this note's red-flag principle centers on | Module Logging (4103) and Script Block Logging (4104) — Event IDs 4100-4106, detailed below |

For **`pwsh.exe` (PowerShell 7.x)**, Microsoft's own [`about_Logging_Windows`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) documents a **separate, differently-named log**: `PowerShellCore/Operational`, associated with a distinct ETW provider GUID (`{f90714a8-5509-434a-bf6d-b1624c8a19a2}`, vs. Windows PowerShell 5.1's `{a0c1853b-5c40-4b15-8766-3cf1c58f985a}` per `about_Logging`). **This means a hunt built only against `Microsoft-Windows-PowerShell/Operational` misses every `pwsh.exe`-generated Script Block Logging event entirely** — a real, source-verified gap in single-log detection coverage that's easy to overlook on an estate where both binaries are present. Microsoft's own docs also note that on Windows, `pwsh`'s event provider must be explicitly registered (`$PSHOME\RegisterManifest.ps1`, run elevated) before any events land in `PowerShellCore/Operational` at all — unlike Windows PowerShell 5.1, which registers its provider automatically as part of the OS.

## Windows Event Logs — Classic "Windows PowerShell" Channel

**Verification note:** Microsoft's current `about_Logging`/`about_Logging_Windows` reference pages document the modern Operational-log schema in detail but do not itemize these specific legacy event IDs in their current prose. The table below is corroborated across multiple independent DFIR references (LogRhythm/Exabeam's EVID documentation, the community-maintained OTRF/OSSEM data dictionary) rather than a single primary Microsoft source — treat it as well-established community consensus, not a Microsoft Learn citation.

| Event ID | Name | Signal |
|---|---|---|
| **400** | Engine Lifecycle (state: None → Available) | **The single highest-value event in this log** — fires at the start of every PowerShell session, local or remote. The `HostApplication` field records the **full command line**, including every switch documented in `01`'s reference table — this fires regardless of whether Script Block/Module Logging were ever configured, making it the detection floor on an estate with zero PowerShell-specific GPO configuration |
| **403** | Engine Lifecycle (state: Available → Stopped) | Session termination — corroborates 400 for session duration, of limited independent value on its own |
| **600** | Provider Lifecycle | Fires when a PowerShell provider (e.g. `WSMan`, for remoting sessions) starts — useful primarily for identifying remoting-based PowerShell activity distinct from a local console invocation |
| **800** | Pipeline Execution Details | Only populated if **module logging is separately enabled** — records the command line for each pipeline execution once that policy is on; functionally a legacy sibling of the modern 4103 |

## Windows Event Logs — Microsoft-Windows-PowerShell/Operational Channel

Verified directly against Microsoft's [`about_Logging`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) (Windows PowerShell 5.1) and [`about_Logging_Windows`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) (PowerShell 7.x) references.

| Event ID | Name | Signal | On by default? |
|---|---|---|---|
| **4103** | Module Logging | Pipeline execution details (parameter names/values, cmdlet invoked) for members of specified modules — requires **both** the session-level policy enabled **and** the specific module's `LogPipelineExecutionDetails` set `$true` | **No.** Per `about_Group_Policy_Settings`: *"By default, the **LogPipelineExecutionDetails** property of all modules is set to `$false`"* |
| **4104** | Script Block Logging | The **full text** of every script block the engine processes, captured **after** parsing/decoding — this is what defeats `-EncodedCommand`/most string-concatenation obfuscation. Microsoft's own schema for this event, confirmed live against both the 5.1 and 7.x docs: `Level=Verbose`, `Opcode=Create`, `Task=CommandStart`, `Keyword=Runspace` | **No**, with one narrow exception — see the Warning-level heuristic note below |
| 4100 | Module output/error/warning entries during logged pipeline execution | Secondary detail records accompanying 4103, of limited standalone hunting value | Same as 4103 |
| 4105 / 4106 | Command Invocation Started / Stopped | Records the *start* and *stop* of each script block **invocation**, as distinct from 4104's one-time *creation*/content-logging event — community-documented as the "Script Block Invocation Logging" sub-option Microsoft's own `about_Group_Policy_Settings` references (*"If you enable the Script Block Invocation Logging, PowerShell also logs events when invocation of a command, scriptblock, function, or script starts or stops. Enabling Invocation Logging generates a high volume of event logs"*) — a real, documented volume tradeoff worth flagging to anyone about to enable it estate-wide | Off unless the Invocation Logging sub-option is separately enabled on top of base Script Block Logging |

**The Warning-level heuristic exception, source-verified against security researcher cobbr's published research** (`cobbr.io`, 2017, referencing PowerShell's own open-source `CompiledScriptBlock.cs`): PowerShell 5.0+ automatically emits a **Warning-level 4104 event** for any script block matching a hardcoded "suspicious strings" list (`Add-Type`, `DllImport`, `DefineDynamicAssembly`, `GetField`, `NonPublic`, and others) — **even when Script Block Logging has never been explicitly enabled**. This is a genuine, if narrow, detection floor below the "logging must be turned on first" rule this note otherwise emphasizes; see the reflection-based bypass documented in `02 - Hands-On Use Cases.md` and the ranking discussion in `05 - Detection and Hunting.md`.

## Transcription

`Start-Transcript` (manual) or the "Turn on PowerShell Transcription" GPO (automatic, every session) writes a **plaintext, human-readable** file containing every command typed and its output — not an event-log artifact, a real file on disk.

| Detail | Value | Source |
|---|---|---|
| Default output location | Each user's `My Documents`/`Documents` folder | `about_Group_Policy_Settings`: *"By default, PowerShell records transcript output to each users' My Documents directory, with a filename that includes PowerShell_transcript, along with the computer name and time started"* |
| Filename pattern | `PowerShell_transcript.<computername>.<random>.<timestamp>.txt` | Same source |
| Registry policy path | `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription`, values `EnableTranscripting` and `OutputDirectory` | Corroborated across multiple community DFIR/GPO references (admx.help, TrustedSec) — Microsoft's own `about_*` prose describes the GPO's behavior but does not itemize the exact registry value names in the fetched documentation, so treat the exact value names as well-corroborated rather than a direct Microsoft Learn quote |
| Off by default? | **Yes** — `about_Group_Policy_Settings`: *"If you disable this policy setting, PowerShell-based applications don't write transcript logs by default. The Start-Transcript cmdlet can still enable transcription logging"* |

## PSReadLine History

| Detail | Value |
|---|---|
| Default path | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` (i.e. `%USERPROFILE%\AppData\Roaming\...`) — confirm the exact path per-host via `(Get-PSReadLineOption).HistorySavePath`, since it's configurable |
| Content | Every line submitted at an **interactive** console prompt, one per line, in plaintext — includes credentials typed inline, full `-EncodedCommand` blobs if constructed interactively, and any other sensitive argument an operator typed directly rather than scripted |
| On by default? | **Yes** — the one genuinely default-on PowerShell-specific evidence source, present since PowerShell 5.0 for any interactive console session. Not itemized as a specific default-on guarantee in Microsoft's own logging-focused `about_*` prose (those pages cover PSReadLine's module documentation separately, not this specific forensic property) — treat this as well-established, widely-corroborated community knowledge rather than a single Microsoft Learn citation |
| Scope limitation | **Only interactive sessions populate this file.** Every scripted/automated invocation in `02 - Hands-On Use Cases.md` (a `-Command`/`-File`/`-EncodedCommand` argument passed directly on the command line rather than typed at a prompt) leaves **nothing** here — this is the single most important caveat to this artifact, and the reason it should never be treated as a complete PowerShell activity record on its own |

## Security Log and Sysmon

| Log | Event ID | Signal |
|---|---|---|
| **Security** | **4688** (Process Creation) | Captures `powershell.exe`/`pwsh.exe` launching with its full command line **if** command-line auditing is enabled — including the raw `-EncodedCommand` Base64 blob (still opaque without decoding it yourself, unlike 4104's already-decoded content) |
| **Security** | 4689 | Process termination — limited independent value |
| **Sysmon** | **1** (Process Create) | Same command-line capture as 4688, independent of native auditing configuration — `ParentImage` here is often the single fastest tell for the chained-use scenarios in `02` (Office app, script host, another LOLBin, or a C2 implant as parent, rather than `explorer.exe`/a normal console host) |
| **Sysmon** | 3 (Network Connect) | Outbound HTTP/HTTPS connection for download-cradle scenarios, absent for purely local/in-memory techniques |
| **Sysmon** | 7 (Image/DLL Load) | Can reveal reflectively-loaded .NET assemblies in some configurations, though in-memory `Assembly.Load()` loading (see `02`'s reflective-loading scenario) is specifically designed to avoid a conventional on-disk DLL load event |
| **Sysmon** | 11 (File Create) | Fires for the stage-to-disk download variant's `-OutFile`; absent for the pure in-memory cradle variants |

## Filesystem

| Artifact | Detail |
|---|---|
| `powershell.exe` install paths | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` — verified against the LOLBAS Project's own `Full_Path` listing for the tool |
| `pwsh.exe` install path | No single fixed path — depends entirely on install method (MSI default is typically `C:\Program Files\PowerShell\<version>\pwsh.exe`); its presence at all is itself evidentiary, per `01`'s Prerequisites table |
| Stage-to-disk download output | Whatever path the operator's `-OutFile`/`.DownloadFile()` call specified — no fixed naming convention, unlike `certutil`'s CryptnetUrlCache side-effect write. **PowerShell's download cradles have no equivalent forced-cache side effect** — this is a real, meaningful contrast with `certutil.exe`'s strongest hunting signal documented in `Purple Teaming/LOLBins/certutil/04 - Target Evidence.md` |
| Prefetch | `POWERSHELL.EXE-<HASH>.pf` / `PWSH.EXE-<HASH>.pf` — low-uniqueness on its own given how common legitimate PowerShell execution is; useful for corroborating a specific execution timestamp once one is already suspected |
| Amcache / ShimCache | Record executions of both binaries — same low-uniqueness caveat as Prefetch |
| Zone.Identifier / MOTW | Applies normally to any `.ps1` **file** downloaded via a browser or an application that sets it — but per `about_Execution_Policies`' own explicit note, `curl.exe`, `Invoke-RestMethod`, and `Invoke-WebRequest` **do not** reliably mark downloaded files with this zone identifier the way a browser does, meaning a PowerShell-fetched script staged to disk by PowerShell itself may show no MOTW at all, regardless of the target's execution policy |

## Registry

| Key | Purpose | Default state |
|---|---|---|
| `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, value `EnableScriptBlockLogging` | Enables 4104 | Verified against `about_Logging`'s own `Enable-PSScriptBlockLogging` example function. **Not present/not `1`** unless explicitly configured |
| `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging`, value `EnableModuleLogging` + `ModuleNames` subkey | Enables 4103 for named modules (or `*` for all) | Corroborated via community ADMX-policy documentation (admx.help) rather than itemized in Microsoft's own `about_*` prose beyond the GPO description — **off by default** |
| `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription`, values `EnableTranscripting` + `OutputDirectory` | Enables automatic, every-session transcription | Same corroboration caveat as above — **off by default** |
| `HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`, value `ExecutionPolicy` | Persisted `LocalMachine`-scope execution policy | Absent/`Undefined` unless `Set-ExecutionPolicy -Scope LocalMachine` was run — see the precedence discussion in `01`/`05` |
| `PowerShellCore`-equivalent policy keys for `pwsh.exe` | Same structure, under `HKLM:\Software\Policies\Microsoft\PowerShellCore\...` per `about_Logging_Windows`'s example function | Independently configured from the Windows PowerShell 5.1 keys above — an estate can have one enabled and not the other |

## Network-Layer Evidence

| Source | What it shows |
|---|---|
| Proxy/firewall access logs | The download-cradle request itself — destination host, URI path, response size |
| Zeek `http.log` | Full request URI and (if not deliberately overridden by the operator's script) a `.NET`/`WindowsPowerShell`-pattern User-Agent string — a much weaker, more easily-defeated signal than `certutil`'s characteristic UA, since overriding it is a single extra line in the cradle script |
| NetFlow | A short-lived outbound TCP 80/443 connection per cradle invocation — no persistent session unless the fetched payload itself establishes ongoing C2 |

## Endpoint Security Product Behavior

**AMSI is the primary EDR/AV integration point for this tool** — since PowerShell 5.0, the engine submits script content to the Antimalware Scan Interface before execution, giving any AMSI-aware AV/EDR product visibility into script content even without Script Block Logging enabled. This is precisely why the AMSI-bypass technique in `02 - Hands-On Use Cases.md` is operationally significant: a successful bypass removes AV/EDR's AMSI-based visibility, but — as documented above — has no verified effect on 4103/4104, meaning an analyst with access to those event logs retains visibility an AMSI-blind product has lost. Most mainstream EDR products also carry built-in behavioral detections for the switch combinations and download-cradle patterns in `02`, independent of AMSI.

## Memory Forensics

In-memory/reflective execution (`02`'s reflective-assembly-loading and download-cradle scenarios) is specifically designed to minimize disk artifacts, which makes memory analysis disproportionately valuable for this tool compared to most others in this module:

- A `powershell.exe`/`pwsh.exe` process holding loaded, unbacked (no corresponding on-disk file) executable memory regions is a strong indicator of reflective assembly loading — standard memory-forensics tooling for unbacked/injected regions applies (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`).
- Script content submitted to AMSI passes through a recoverable buffer at scan time — AMSI-focused memory-forensics tooling and some EDR products can recover script content from this buffer even when the on-disk/event-log trail is otherwise thin, though this note did not independently verify a specific, named forensic tool/technique for this beyond noting it as a documented analytical avenue.
- If Script Block Logging is enabled, 4104's already-decoded plaintext content typically makes a live memory-forensics pass against the process itself unnecessary for recovering *what ran* — memory analysis becomes most valuable specifically on estates where logging was off, which is the more common real-world case per `01`'s correction.

## Building a Timeline

The tightest anchor sequence, per invocation, **assuming full logging is enabled** (the exception, not the rule, per `01`): **Event 400 (session start, full command line) → 4103 (module/pipeline detail, if module logging is on) → 4104 (full decoded script-block content) → Sysmon 1 / Security 4688 (process create, corroborating command line) → Sysmon 3/22 (network activity, download-cradle scenarios only) → Sysmon 11 (file create, stage-to-disk scenarios only) → Event 403 (session stop).**

**On the far more common estate where none of the PowerShell-specific logging was ever configured**, the sequence collapses to just: **Sysmon 1 / Security 4688 (process create, full command line if command-line auditing is on) → Sysmon 3/11 (network/file activity, where relevant).** In that reduced state, an `-EncodedCommand` Base64 blob is visible but **not decoded** by anything in the standard telemetry stack — the analyst has to manually Base64-decode the captured command line themselves to recover the actual script content, a manual step this note's hunting commands in `05` automate.
