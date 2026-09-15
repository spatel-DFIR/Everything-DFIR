# LOLBins — msbuild.exe — Target Evidence

Evidence left on the **target/victim** host — where every technique in this note actually executes. The defining evidentiary fact for this tool, different from every other LOLBIN in this module so far: **the malicious content lives inside the project file itself, not in the process command line MSBuild was launched with.** A command-line-only evidence source (raw Security 4688 without full context, a naive Sysmon 1 CommandLine regex) sees only a filename and some generic switches — the actual `UsingTask`/`CodeTaskFactory`/inline-`<Code>` content is invisible to it. The project file, where it still exists on disk, is this technique's single richest artifact.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon-if-deployed)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing Abuse from Legitimate Build Activity](#distinguishing-abuse-from-legitimate-build-activity)

---

## Filesystem

| Artifact | Detail |
|---|---|
| **The project file itself** (`.csproj`/`.xml`/`.proj`/`.rsp`) | **The single richest artifact for this entire technique.** Unlike a compiled/packed malware sample, this is a plaintext XML file containing the attacker's actual C#/VB source code (or JScript/VBScript, for the XSL-transformation variant) in full, human-readable form — no disassembly needed. If the operator didn't delete it post-execution, it is a complete record of exactly what ran. Path is entirely operator-controlled; commonly staged in `%TEMP%`, `%APPDATA%`, or `C:\Users\Public` |
| `%LOCALAPPDATA%\Temp\MSBuildTemp\<GUID>` | The transient source+compile-output temp file MSBuild's code task factories generate during in-memory compilation — verified directly against [Microsoft's own "Debug an inline task" documentation](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks): *"MSBuild generates a source file [for] the inline task and writes the output to [a] text file with a GUID filename in the temporary files folder... The output is normally deleted."* **By default this file does NOT persist** — it is deleted immediately after compilation completes. It is only preserved if the environment variable `MSBUILDLOGCODETASKFACTORYOUTPUT=1` was explicitly set at execution time, which almost no real-world attacker invocation does deliberately. Treat the absence of this artifact as the expected, default case, not evidence of anything — but its *presence* (if found) is a high-value, near-unambiguous confirmation |
| Compiled output (`bin\`/`obj\`) | **Absent** for the inline-task and Logger-DLL techniques — no PE binary is written as the payload itself. A legitimate build produces real output here; its absence alongside a `msbuild.exe` execution event is itself a distinguishing signal (see the contrast table below) |
| The Logger DLL (`/logger:` technique only) | A real, precompiled `.dll` at whatever path the operator specified — unlike the inline-task techniques, this variant DOES leave a compiled binary on disk, and that binary is itself a conventional malware sample subject to normal static/AV analysis |
| Prefetch | `MSBUILD.EXE-<HASH>.pf` updates on every run — **low-uniqueness on its own**, since `msbuild.exe` also runs constantly and legitimately on any developer workstation or CI/build server. See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record `msbuild.exe` executions — same low-uniqueness caveat as Prefetch, useful only as corroboration once a specific timestamp is already suspected from stronger evidence below |
| Zone.Identifier / MOTW | Applies normally to however the project file itself was delivered (email attachment, browser download) — this note found no evidence that MSBuild's own execution of the file strips or adds a MOTW marker; the project file's MOTW status reflects its delivery mechanism, not anything MSBuild-specific |

## Registry

No MSBuild-specific registry key was found or verified for these techniques across the sources reviewed for this note (Microsoft's own MSBuild/UsingTask/inline-task documentation, LOLBAS). Treat "no distinctive registry artifact" as the accurate, verified position here, matching the same finding already documented for `../certutil/`.

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **Security** | **4688** (Process Creation) | Captures the `msbuild.exe` command line verbatim if command-line auditing is enabled — but per this note's central finding, that command line typically shows only the project-file path and any switches (`-nologo`, `-verbosity:quiet`), **not** the malicious code itself, which lives inside the file's content. For the response-file variant (`msbuild.exe @evil.rsp`), even the project-file path is hidden from 4688 entirely |
| Security | 4689 | Process termination — limited independent value; MSBuild abuse invocations are typically short-lived |
| System | 7036 | **Not applicable** — no service is created or started by any technique in this note |

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| **1 (Process Create)** | Captures `Image`, `CommandLine`, parent process. Same command-line-content limitation as Security 4688 above — the payload isn't in the command line. **`ParentImage` is a stronger signal here than the command line itself**: `msbuild.exe` spawned by `winword.exe`, `powershell.exe`, `wscript.exe`, or a C2 implant's process is anomalous; spawned by `devenv.exe`, a CI agent process, or another `msbuild.exe`/`dotnet.exe` is expected baseline |
| **7 (Image/DLL Load)** | **The strongest single behavioral signal for the inline-task techniques.** `msbuild.exe` loading `Microsoft.CodeAnalysis.CSharp.dll` (Roslyn) or the legacy CodeDom compiler assemblies is exactly what happens when `RoslynCodeTaskFactory`/`CodeTaskFactory` compiles inline code — legitimate developer builds load these too, so this alone isn't a finding, but combined with an anomalous `ParentImage`, a non-source-tree project-file path, or the absence of any real `bin\`/`obj\` output afterward, it corroborates that in-memory compilation actually occurred |
| 3 (Network Connect) | **Not expected** for the techniques in this note by default — MSBuild itself makes no network calls to execute an inline task. An outbound connection from `msbuild.exe` is either legitimate NuGet restore activity (`-restore`/`-r`, targeting a known package-feed endpoint) or the attacker's own inline code making its own network call post-compilation — the latter reaching an arbitrary, non-package-feed destination is a strong tell |
| 11 (File Create) | Fires for the project file itself if written to disk as part of delivery, and — if `MSBUILDLOGCODETASKFACTORYOUTPUT=1` was set — the `MSBuildTemp\<GUID>` debug artifact. For the Logger-DLL technique, fires for the DLL file itself if it was written to disk rather than already present |
| 13 (Registry Value Set) | **Not expected**, consistent with the "no verified registry artifact" finding above |
| 22 (DNS Query) | Only expected alongside Sysmon 3, for the same NuGet-restore-vs-attacker-code distinction noted above |

## Network-Layer Evidence

`msbuild.exe` generates no network traffic of its own to execute any technique in this note. The one legitimate exception is `-restore`/`-r` triggering NuGet package restore against a known feed (typically `nuget.org` or an organization's internal feed) — an `msbuild.exe` process connecting to an arbitrary, non-package-feed IP or domain is not explained by any documented legitimate MSBuild behavior and should be treated as originating from the attacker's own inline code, not MSBuild itself. Proxy/firewall/Zeek logs showing this pattern are a strong corroborating signal once a suspicious `msbuild.exe` process-creation event is already identified.

## Endpoint Security Product Signatures

Because `msbuild.exe` is a legitimate, Microsoft-signed binary and the payload (for the inline-task techniques) is plaintext XML rather than a recognizable executable format, static file-signature detection is a non-starter — detection depends on behavioral heuristics and, where available, **project-file content inspection**. MITRE ATT&CK's own detection guidance for T1127.001 (verified against [attack.mitre.org/techniques/T1127/001](https://attack.mitre.org/techniques/T1127/001/)) describes a behavior-chain approach — monitoring for `msbuild.exe` invoked outside development contexts with anomalous arguments, followed by spawning high-risk tools, writing artifacts to user-writable paths, loading unsigned modules, memory injection, or initiating outbound connections — rather than any single static indicator. This is a materially different detection posture from `../certutil/`'s, where a specific, unavoidable disk artifact (`CryptnetUrlCache`) exists — no equivalent unavoidable artifact exists here by default, which is exactly why behavioral/content-based detection carries proportionally more weight for this tool.

## Memory Forensics

**This is where the inline-task techniques' actual payload lives, and it is the single best recovery point when the project file itself has already been deleted.** Since the compiled task assembly is emitted and loaded entirely in-memory (`Assembly.Load()`/Roslyn in-memory emit — see `01`'s How It Works diagram), it never exists as a PE file on disk at any point. A memory capture of the `msbuild.exe` process while the task is loaded (or, forensically, of a memory image taken before the process exits) can recover the compiled assembly bytes via standard .NET-assembly-in-memory carving techniques — conceptually similar to recovering a reflectively-loaded DLL from a process-injection case, except here it's the build engine's own legitimate JIT/Roslyn machinery doing the loading rather than a custom loader. See `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md` for the general .NET-assembly-in-memory recovery approach this note doesn't re-derive. For the Logger-DLL technique, by contrast, the payload is already a normal on-disk DLL and doesn't depend on memory forensics to recover.

## Building a Timeline

The tightest anchor sequence, per invocation: **Sysmon 11 (project-file create, if delivered rather than already present) → Sysmon 1 (msbuild.exe process create, `ParentImage` is the key field) → Sysmon 7 ×N (Roslyn/CodeDom compiler assembly loads, inline-task techniques only) → [attacker code's own effects — process creates, file writes, network connects, all attributable to `msbuild.exe` as the parent/source process] → Security 4688 (if command-line auditing is separately enabled, corroborating Sysmon 1 but not revealing the payload itself).** Because the project file is frequently deleted post-execution and the `MSBuildTemp` debug artifact is absent by default, this technique is more evidence-perishable than `../certutil/`'s — if the project file isn't recovered from disk (deleted-file forensics) or memory (the compiled assembly, per above) close to the time of execution, the actual malicious logic may not be recoverable at all, leaving only the behavioral shell (process creation, image loads, downstream effects) to work from.

## Distinguishing Abuse from Legitimate Build Activity

> 🔴 A bare `msbuild.exe` process-creation event is not a finding — this binary runs constantly and legitimately on any developer workstation or CI/build server. **Project-file location, parent process, and the presence/absence of real compiled output are the signal.**

| Dimension | Legitimate build activity | Abuse (this note) |
|---|---|---|
| Project-file location | Inside a version-controlled source-tree directory | Isolated file in `%TEMP%`, `%APPDATA%`, `C:\Users\Public`, or similar non-project location |
| Parent process | `devenv.exe`, a CI/build-agent process, `cmd.exe`/`powershell.exe` from a developer's own interactive session, or another `msbuild.exe`/`dotnet.exe` | `winword.exe`, `wscript.exe`, `powershell.exe` in an otherwise CLM-constrained context, or a C2 implant's process |
| Compiled output | Real `bin\`/`obj\` output matching the project's configuration | None — the "build" produces no deliverable at all (inline-task/Logger-DLL techniques) |
| Command-line switches | `-p:Configuration=...`, `-t:Rebuild`/`-t:Build`, often `-restore` | Frequently `-nologo`/`-verbosity:quiet` only, or `@rsp`-file invocation hiding everything else |
| Sysmon 7 compiler-assembly loads | Expected, routine | Same DLLs load, but combined with the anomalous location/parent-process/no-output pattern above |
| Network activity | NuGet restore against a known package feed (`-restore`) | None from MSBuild itself, or an arbitrary non-package-feed destination reached by the attacker's own inline code |
