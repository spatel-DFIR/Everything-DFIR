# LOLBins — msbuild.exe — Overview

> 🔴 **Red Flag Principle:** `msbuild.exe` can compile and execute arbitrary C#/VB code **entirely in-process**, via a `UsingTask`/`CodeTaskFactory` (or `RoslynCodeTaskFactory`) declaration inside an XML project file — no `csc.exe`/`vbc.exe` compiler child process is ever spawned, and no compiled PE binary is ever written to disk. The only thing that touches disk is the project file itself, and by default that file is **the entire payload written in plaintext XML** — there is no packing, no encoding, nothing "malware-shaped" about it. `msbuild.exe` is a Microsoft-signed binary present on essentially every developer workstation and CI/build server, which is exactly why AppLocker/WDAC rule sets built around signed-binary trust routinely allowlist it. The single most important detection consequence of all this: **the malicious code lives inside the project file's content, not in the process command line MSBuild was launched with** — a Sysmon/4688 command-line hunt keyed on `msbuild.exe evil.csproj` sees nothing more than a filename. Content-level inspection of the project file, not command-line pattern matching, is where this technique is actually caught. Detailed below and ranked in `05 - Detection and Hunting.md`.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Legitimate vs. Abused Usage](#legitimate-vs-abused-usage)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`msbuild.exe` (Microsoft Build Engine) is **not** an offensive-security-authored tool — it's Microsoft's native build engine for compiling Visual Studio project/solution files (`.csproj`, `.vbproj`, `.sln`), shipped as part of the .NET Framework since **.NET Framework 2.0 (2005)**, replacing the older NMAKE-style build-script approach. It ships in-box with every Windows installation that has the .NET Framework (which is nearly all of them, since .NET Framework has been a default Windows component since Vista/Server 2008), independent of whether Visual Studio itself is installed, and additional copies are bundled with each Visual Studio release and the modern cross-platform .NET SDK (`dotnet build`/`dotnet msbuild` invoke the same engine, though — per Microsoft's own command-line reference — `dotnet run` does not pass MSBuild's command-line switches through). The modern engine is open-source at [`dotnet/msbuild`](https://github.com/dotnet/msbuild) (MIT-licensed), but the classic `Microsoft.NET\Framework\...\MSBuild.exe` binary this note focuses on is a first-party OS/.NET Framework component, not a separately maintained project with its own release cadence to track the way a GitHub tool in this repo's other folders would have.

The abuse technique — using MSBuild's legitimate **inline task** feature (a project file embeds C#/VB source that MSBuild itself compiles and runs as part of the build) to execute arbitrary code under a trusted, frequently-allowlisted signed binary — is catalogued by the **LOLBAS Project** ([lolbas-project.github.io/lolbas/Binaries/Msbuild](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)), which credits **Casey Smith (@subTee)** for the technique family, with additional contributions from **Cn33liz (@Cneelis)** and **Jimmy (@bohops)**. Casey Smith's original public write-up popularizing MSBuild as an application-allowlisting bypass is widely cited in the security community as the origin of this technique class; this note did not fetch that original blog post directly (kept the research footprint narrow per this build's sourcing constraints) and instead verified the current abuse syntax directly against LOLBAS's own live catalog, which lists **5 distinct documented commands**, not just the single inline-task technique most write-ups focus on — see `02 - Hands-On Use Cases.md` for all five.

The specific `RoslynCodeTaskFactory` mechanism most current inline-task PoCs use was introduced later than the original technique: per [Microsoft's own documentation](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-roslyncodetaskfactory), it first became available in **MSBuild 15.8** (Visual Studio 2017 version 15.8, 2018). The original, older `CodeTaskFactory` predates it and is still present for backward compatibility — Microsoft's current docs explicitly steer developers away from it: *"For current development, be sure to use RoslynCodeTaskFactory, not CodeTaskFactory. CodeTaskFactory only supports C# versions up to 4.0."* Both factories remain functional on current Windows/.NET Framework installs, which matters for this note because older, more widely-circulated PoC project files (including variants attributed to the original 2016-era technique) tend to use `CodeTaskFactory`, while newer ones use `RoslynCodeTaskFactory` — an analyst should expect to see either in the wild, not just one.

MITRE ATT&CK tracks this as its own named sub-technique — **T1127.001 "Trusted Developer Utilities Proxy Execution: MSBuild"** (verified directly against [attack.mitre.org/techniques/T1127/001](https://attack.mitre.org/techniques/T1127/001/)), a child of **T1127**. ATT&CK's own procedure examples confirm this is not just a theoretical PoC technique — it lists **Empire** (built-in modules for MSBuild abuse), the **Frankenstein campaign** (used MSBuild to execute actor-created files), **NOOPLDR** (executable via MSBuild), **MirrorFace/Operation AkaiRyū** (used MSBuild to compile and execute the FaceXInjector malware), and a **PlugX** variant that loads as shellcode within a .NET Framework project via `msbuild.exe` specifically to bypass application control.

## How It Works

**The mechanism is legitimate MSBuild functionality, not a bug.** MSBuild project files are XML, and the `UsingTask` element is a documented, first-class way to define a build task — normally by pointing at a precompiled task assembly (`AssemblyFile`/`AssemblyName`), but optionally by pointing `TaskFactory` at a **code task factory** (`CodeTaskFactory` or `RoslynCodeTaskFactory`) and supplying the task's actual source code inline, inside a `<Code>` child element. When MSBuild evaluates the project and reaches a `<Target>` that invokes that task, the task factory compiles the inline source **in-process** — via the legacy CodeDom compiler for `CodeTaskFactory`, or via the Roslyn C#/VB compilers for `RoslynCodeTaskFactory` — into an in-memory assembly, loads it, and calls its `Execute()` method. This is precisely the mechanism Microsoft's own docs describe as letting a developer "avoid the overhead of creating a compiled task" for small build-time utility code — an attacker is not exploiting a flaw, just repurposing a legitimate convenience feature.

```
Malicious project file (evil.csproj / evil.xml / evil.proj)
  <Project>
    <UsingTask TaskName="Pwn"
               TaskFactory="RoslynCodeTaskFactory"
               AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
      <Task>
        <Code Type="Fragment" Language="cs">
          <![CDATA[ ... attacker C# source, plaintext ... ]]>
        </Code>
      </Task>
    </UsingTask>
    <Target Name="Hello" BeforeTargets="Build"><Pwn/></Target>
  </Project>
                        │
                        ▼
        cmd.exe/PowerShell ──▶ msbuild.exe evil.csproj
                                    │
                                    ├─ 1. Parses/evaluates the XML project file
                                    ├─ 2. Reaches the UsingTask declaration, invokes the
                                    │      named TaskFactory (Roslyn or CodeDom)
                                    ├─ 3. Task factory compiles the inline <Code> block
                                    │      IN-MEMORY — writes a source+output temp file to
                                    │      %LOCALAPPDATA%\Temp\MSBuildTemp\<GUID> during
                                    │      compilation, THEN DELETES IT — unless the
                                    │      operator/environment set
                                    │      MSBUILDLOGCODETASKFACTORYOUTPUT=1, in which case
                                    │      it survives (Microsoft's own documented debug
                                    │      switch — verified against MS Learn's
                                    │      "Create MSBuild inline tasks" article)
                                    ├─ 4. The resulting assembly is loaded via
                                    │      Assembly.Load()/Roslyn in-memory emit — NO .exe/
                                    │      .dll is ever written to disk as the payload
                                    └─ 5. The Target invokes the task, running attacker code
                                           INSIDE msbuild.exe's own process — same user
                                           token/integrity level MSBuild itself is running as
```

No separate compiler process is ever visible in a process tree, and — critically — **no dropped PE binary exists at any point** unless the attacker's own code chooses to write one out as a follow-on action. This combination (signed binary, in-memory compile, no compiler child process, plaintext-not-packed source) is what makes MSBuild attractive specifically as an **application-control bypass**, not just a generic "LOLBIN downloader" the way `certutil.exe` (`../certutil/`) is.

**One item this note could not verify against a clean, current source**: whether MSBuild's inline-task compilation path is itself AMSI-instrumented on current Windows/.NET Framework builds. AMSI is well-documented for PowerShell, JScript/VBScript hosts, and .NET Framework 4.8+'s dynamic-assembly-load path — whether the specific `RoslynCodeTaskFactory`/`CodeTaskFactory` in-memory compile-and-load sequence is covered was not something this build's narrowed research footprint could confirm one way or the other. Treat AMSI coverage of this specific path as an open question rather than assuming it is or isn't scanned.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Execution | Local process, no network client of its own — reaching the point of running `msbuild.exe <project>` requires a separate access vector (interactive shell, a macro, a chained LOLBIN, a C2 implant), same prerequisite structure as `../ntdsutil/` |
| Underlying mechanism | `UsingTask` element + a code task factory (`CodeTaskFactory` — legacy, CodeDom-based, C# ≤4.0 only; `RoslynCodeTaskFactory` — current, Roslyn-based, MSBuild 15.8+) — both documented first-class MSBuild features, verified against [Microsoft's `UsingTask` reference](https://learn.microsoft.com/en-us/visualstudio/msbuild/usingtask-element-msbuild) and its [RoslynCodeTaskFactory how-to](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-roslyncodetaskfactory) |
| Payload location | Inline, plaintext, inside the project file's own `<Code>` element — not encoded, not a separate dropped file, not present anywhere in the command line MSBuild was launched with |
| Compilation | In-process, in-memory — Roslyn (Microsoft.CodeAnalysis.CSharp) or the legacy CodeDom compiler, depending on the factory used; a transient debug artifact exists only if `MSBUILDLOGCODETASKFACTORYOUTPUT=1` is explicitly set |
| Execution context | Runs as whatever user/token invoked `msbuild.exe` — no elevation required beyond whatever the attacker's own inline code subsequently attempts |
| Process model | Single process by default — the compiled task executes inside `msbuild.exe` itself, not a child process. A child process only appears if the attacker's own inline code deliberately spawns one |
| Non-inline-task variants | Two additional LOLBAS-documented techniques don't involve inline compilation at all: loading and executing an arbitrary **Logger DLL** via `/logger:`, and executing **JScript/VBScript via XSL Transformation** through a `.proj` file — see `02` |
| Binary location | See the Full-Path table below — the only 7 install paths **LOLBAS's own catalog** currently documents |

## Command-Line Switches — Quick Reference

Verified against [Microsoft Learn's MSBuild command-line reference](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference) (all switches accept either a `-switch` or `/switch` form; Microsoft's docs show only the `-switch` form, but `/switch` — e.g. `/target`, `/property` — is what nearly every published LOLBAS/PoC one-liner uses, so both are shown here). `msbuild.exe` exposes dozens of switches for legitimate build control — this table covers only the ones with direct abuse relevance.

| Switch | Plain-English meaning |
|---|---|
| `ProjectFile` (positional, no switch) | The project/solution file to build. If omitted, MSBuild searches the current directory for any file ending in `proj` — meaning a malicious project file dropped as e.g. `notes.csproj` in a directory MSBuild is later run from can be picked up **without being named on the command line at all** |
| `-target:{targets}` / `-t:{targets}` | Build the specified target(s) instead of whatever the project's `DefaultTargets` attribute names. Attack-relevant because a malicious project file's inline task can be wired to run from any target — including one that fires automatically via `BeforeTargets`/`AfterTargets`, needing no `-target` at all |
| `-property:{name}={value}` / `-p:{name}={value}` | Set/override a project-level property (`MSBuild.rsp` example: `-p:Configuration=Release`). Legitimate CI pipelines pass dozens of these; an attacker's project file rarely needs any, since the payload doesn't depend on external property values |
| `-nologo` | Suppresses the startup banner/copyright text — cosmetic only, but appears in nearly every published one-liner since it keeps console output minimal |
| `-verbosity:{level}` / `-v:{level}` | Controls build-log detail: `q[uiet]`, `m[inimal]`, `n[ormal]` (default), `d[etailed]`, `diag[nostic]`. An operator commonly sets `-verbosity:quiet` (or `-nologo` alone) to suppress the build-progress output a normal `msbuild.exe` run produces, since that noisy output is itself a visual tell that something unusual is running |
| `-noAutoResponse` / `-noautorsp` | Prevents MSBuild from automatically including `MSBuild.rsp`/`Directory.Build.rsp` response files it would otherwise pick up from the project directory or MSBuild's own install directory — relevant because a defender relying on a pre-planted "safe defaults" `.rsp` file to constrain builds can have that constraint bypassed outright |
| `-noConsoleLogger` / `-noconlog` | Disables the default console logger entirely — build output produces no visible console text at all, useful for an operator wanting a fully silent invocation |
| `@{file}` | **Insert command-line switches from a response file (`.rsp`).** This is itself one of LOLBAS's 5 documented abuse techniques (`msbuild.exe @evil.rsp`) — any switches, including the project file path itself, can be relocated out of the visible command line and into the `.rsp` file's contents, which most command-line-only detection rules never inspect |
| `-logger:{logger}` / `-l:{logger}` | Loads a specified logger DLL and class to receive build events. **LOLBAS's "Logger DLL" technique abuses this directly** (`/logger:TargetLogger,{dll};params`) to load and execute an arbitrary compiled DLL — a fundamentally different abuse path from inline-task compilation, since here the payload is a real, precompiled DLL rather than plaintext source |
| `-validate:[{schema}]` / `-val` | Validates the project file against a schema before building — legitimate use is CI-pipeline hygiene; irrelevant to the abuse techniques in this note but appears in some published one-liners as harmless noise |
| `-restore` / `-r` | Runs the `Restore` target before building — the one switch that generates **legitimate** outbound network activity (NuGet package restore against a known package feed), useful as a contrast point since the abuse techniques in this note generate no network traffic of their own unless the attacker's inline code deliberately adds it |

## Legitimate vs. Abused Usage

For contrast: legitimate `msbuild.exe` invocations come from a developer's own build (`devenv.exe`/Visual Studio spawning it), a CI/build-server agent (Azure DevOps, Jenkins, TeamCity, GitHub Actions runners), or `dotnet build`/`dotnet msbuild` wrapping the same engine — targeting a real, version-controlled `.csproj`/`.sln` that lives inside a source-tree directory structure, invoked with property/target switches that make sense for an actual application build (`-p:Configuration=Release`, `-t:Rebuild`), and typically producing visible build-progress output and a real compiled output assembly in `bin\`/`obj\`. An abused invocation targets a single, isolated project file with **no accompanying source tree**, often staged in `%TEMP%`, `%APPDATA%`, `C:\Users\Public`, or a similarly non-project location, frequently paired with `-nologo`/quiet verbosity to suppress the normal build-progress noise, and produces **no compiled output on disk** at all — the entire point is that the "build" never touches the filesystem with a deliverable.

## Quick Use-Case List

- Baseline inline-task payload execution via a malicious `.csproj`/`.xml` using `RoslynCodeTaskFactory` — the modern, currently-recommended factory
- Same technique using the legacy `CodeTaskFactory` — still functional, more likely to appear in older/recirculated PoC project files
- Explicit AppLocker/WDAC application-control bypass framing — LOLBAS categorizes the `.xml`-file variant specifically as "AWL Bypass"
- PowerShell Constrained Language Mode bypass — the attacker's code runs as compiled .NET inside `msbuild.exe`, never touching the PowerShell engine CLM restricts at all
- Logger DLL execution (`/logger:TargetLogger,{dll};params`) — loading and running an arbitrary precompiled DLL's exported logger class, a LOLBAS-documented technique distinct from inline-task compilation
- XSL Transformation execution of JScript/VBScript via a `.proj` file (requires MSBuild v14.0+) — a third, separately LOLBAS-documented execution path
- Response-file invocation (`msbuild.exe @evil.rsp`) to relocate the project-file path and switches out of the visible process command line
- Staged delivery of the project file via another LOLBIN — e.g. dropped with `certutil.exe -urlcache` (cross-link `../certutil/`) ahead of the `msbuild.exe` invocation
- Payload/shellcode generated with `msfvenom` (cross-link `../../Metasploit/msfvenom/`) embedded as a byte array inside the inline `<Code>` block for in-memory execution
- Renamed or relocated copy of `msbuild.exe` to dodge simple `Image`-name detections — Authenticode/`OriginalFileName` still resolves it to the genuine Microsoft binary
- Fleet-wide/mass execution via C2 tasking — MITRE ATT&CK records **Empire** shipping built-in modules specifically for this
- Chained execution from an initial-access vector — a phishing macro or another LOLBIN drops the project file and calls `msbuild.exe` against it
- Real-world documented malicious use for threat-intel context — MITRE ATT&CK cites the **Frankenstein campaign**, **NOOPLDR**, **MirrorFace/Operation AkaiRyū** (FaceXInjector), and a **PlugX** shellcode-loading variant, all using MSBuild specifically to bypass application control
- Legitimate-baseline contrast use: routine developer/CI-pipeline build activity an analyst should expect to see as background noise on any dev workstation or build server

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target | Any existing foothold that can run a command line — `msbuild.exe` is not itself an initial-access vector, same prerequisite as every other tool in this folder |
| Privilege level | **None beyond a standard user token** for the execution techniques themselves — MSBuild runs as whatever identity launched it; no elevation is inherent to any technique in this note (what the attacker's own inline code subsequently does may of course require more) |
| `msbuild.exe` present on the host | Present on essentially any host with the .NET Framework installed (near-universal on Windows) — verified install paths in the table below — plus any host with Visual Studio or the .NET SDK installed |
| A crafted project file | The `.csproj`/`.xml`/`.proj`/`.rsp` payload itself must already be staged on the target — MSBuild has **no documented remote/URL-hosted project-file capability**; every LOLBAS-listed command takes a local file path. (A UNC/SMB-share-hosted path is technically possible since any Windows path-accepting argument can point at `\\server\share\file`, but this is generic Windows filesystem behavior, not an MSBuild-specific feature, and is not a technique LOLBAS documents for this binary — treat it as theoretically available, not confirmed-in-the-wild) |
| Compatible MSBuild version | `RoslynCodeTaskFactory` requires MSBuild 15.8+ (VS2017 15.8+, 2018 onward); `CodeTaskFactory` works on materially older installs but caps at C# 4.0 language features; the XSL-transformation technique requires MSBuild v14.0+ per LOLBAS |
| Full-Path reference (verified against LOLBAS's own catalog) | `C:\Windows\Microsoft.NET\Framework\v2.0.50727\Msbuild.exe`, `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Msbuild.exe`, `C:\Windows\Microsoft.NET\Framework\v3.5\Msbuild.exe`, `C:\Windows\Microsoft.NET\Framework64\v3.5\Msbuild.exe`, `C:\Windows\Microsoft.NET\Framework\v4.0.30319\Msbuild.exe`, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Msbuild.exe`, `C:\Program Files (x86)\MSBuild\14.0\bin\MSBuild.exe` — **these are the only 7 paths LOLBAS's own Full_Path listing documents.** Modern Visual Studio 2017/2019/2022 installs also bundle their own `MSBuild.exe` under `C:\Program Files\Microsoft Visual Studio\<year>\<edition>\MSBuild\Current\Bin\` (and a `\Bin\amd64\` 64-bit sibling), and the .NET SDK bundles `MSBuild.dll` under `C:\Program Files\dotnet\sdk\<version>\` (invoked via `dotnet msbuild`, not a standalone `.exe`) — these are real, well-known installation locations from general Visual Studio/.NET SDK layout knowledge, **but they are not part of LOLBAS's own verified path list**, a real gap worth flagging: a hunt scoped only to LOLBAS's 7 documented paths misses every VS2017+-bundled instance |
