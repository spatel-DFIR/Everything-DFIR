# LOLBins — msbuild.exe — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`msbuild.exe`'s abuse surface has more evasion knobs than `../certutil/`'s, and — the defining structural fact for this whole note — its most incriminating content (`UsingTask`, `CodeTaskFactory`/`RoslynCodeTaskFactory`, the inline `<Code>` block) lives **inside the project file, not in the process command line**. That single fact reshapes the entire priority ranking: command-line-only hunting, which was rank-2 for `certutil`, is materially weaker here.

| Rank | Signal | Survives binary rename/relocation? | Survives `@rsp`-file invocation (hides command line)? | Survives project-file deletion post-execution? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | **Project-file content inspection** — scanning `.csproj`/`.xml`/`.proj`/`.rsp` files for `UsingTask`, `CodeTaskFactory`, `RoslynCodeTaskFactory`, `<Code Type=` strings | ✅ Yes — content-based, independent of how MSBuild itself was invoked | ✅ Yes — the file still exists and can be scanned regardless of how it was referenced on the command line | ❌ No — this is the technique's single most perishable artifact | Requires either an EDR with file-content/YARA-style scanning, endpoint file-integrity tooling, or catching the file before deletion. The single highest-value signal when available, but also the one most dependent on timing |
| 2 | Sysmon 7 (Image/DLL Load) — `msbuild.exe` loading Roslyn/CodeDom compiler assemblies, combined with anomalous `ParentImage` or project-file path | ✅ Yes | ✅ Yes | ✅ Yes — this is process-execution telemetry, independent of the file's later fate | Behavioral, not content-based — doesn't reveal *what* the code did, only that in-memory compilation plausibly occurred in a suspicious context |
| 3 | Sysmon 1 `ParentImage` anomaly (`msbuild.exe` spawned by `winword.exe`/`wscript.exe`/`powershell.exe`/a C2 implant rather than `devenv.exe`/a CI agent) | ✅ Yes | ✅ Yes | ✅ Yes | Requires Sysmon or equivalent process-ancestry telemetry; a common baseline-vs-anomaly hunt applicable across most LOLBIN abuse, not unique to MSBuild |
| 4 | Command-line argument shape (project-file path outside a source-tree directory, `-nologo`/`-verbosity:quiet` pairing, bare `@rsp` invocation) | ✅ Yes | ❌ **No** — the whole point of the `@rsp` technique is to defeat exactly this | ✅ Yes (the event itself persists even if the file is later deleted) | Weaker here than the equivalent rank for `certutil`, precisely because the payload was never in the command line to begin with — this only ever shows *that* something ran against *some* file, not what that file contained |
| 5 | `MSBuildTemp\<GUID>` debug artifact | ✅ Yes | ✅ Yes | N/A — only exists if `MSBUILDLOGCODETASKFACTORYOUTPUT=1` was explicitly set | High-confidence when found, but **absent by default** in nearly every real-world invocation — don't build a primary hunt around expecting this |
| 6 (weakest) | Bare `msbuild.exe` process-creation frequency/presence, or `Image`/file-path checks alone | ❌ No | N/A | N/A | High false-positive rate on any estate with developers or CI/build servers. Never hunt on this alone |

**Build hunts on ranks 1-3 as primary detections — rank 1 is the only one that recovers the actual malicious logic, but is timing-dependent; ranks 2-3 are durable behavioral fallbacks when the file is already gone. Treat ranks 4-5 as corroboration only, and rank 6 as enrichment only.**

## Hunting on Source

Source-side hunting for this tool means pivoting through the tasking/authoring layer described in `03 - Source Evidence.md`, not an "operator machine" in the usual sense of this module:

```
# If C2 server task history is available (red-team retrospective, or recovered
# attacker infrastructure): search issued-command history for msbuild invocations
grep -iE "msbuild\.exe" c2_task_history.log

# If attacker web-hosting infrastructure was used to stage the project file
# (chained via certutil or similar): see ../certutil/05 - Detection and Hunting.md's
# "Hunting on Source" block for the matching access-log pivot
```

See `../../PowerShell Empire/03 - Source Evidence.md` and this module's other C2-framework folders for how each framework's own task-history logging is structured, rather than re-deriving it here.

## Hunting on Target

```powershell
# 1. HIGHEST-VALUE, MOST PERISHABLE: scan for project/response files containing
#    inline-task or logger-abuse indicators, wherever readable project files exist
#    on disk. Run this BEFORE assuming a file has already been deleted.
Get-ChildItem -Path C:\ -Include *.csproj,*.xml,*.proj,*.rsp -Recurse -ErrorAction SilentlyContinue |
  Select-String -Pattern 'CodeTaskFactory|RoslynCodeTaskFactory|UsingTask' -List |
  Select-Object Path

# 2. Sysmon Image/DLL-load hunt: msbuild.exe loading Roslyn/CodeDom compiler
#    assemblies — survives file deletion and @rsp obfuscation
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { $_.Message -match 'msbuild\.exe' -and $_.Message -match 'Microsoft\.CodeAnalysis|Microsoft\.Build\.Tasks' } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='ImageLoaded';e={($_.Message -split "`n" | Select-String '^ImageLoaded:').ToString()}}

# 3. Parent-process anomaly hunt: msbuild.exe spawned by an unexpected parent
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match 'Image:.*\\msbuild\.exe' -and
    $_.Message -notmatch 'ParentImage:.*\\(devenv|MSBuild|dotnet|Build\.Runtime)\.exe'
  } |
  Select-Object TimeCreated,
    @{n='ParentImage';e={($_.Message -split "`n" | Select-String '^ParentImage:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String '^CommandLine:').ToString()}}

# 4. Command-line argument-shape hunt (weaker — defeated by @rsp invocation, see
#    priority table rank 4) against native Security 4688, if Sysmon isn't deployed
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'msbuild\.exe' -and $_.Message -match '@\S+\.rsp|-nologo|-verbosity:quiet' }

# 5. Rare but high-confidence if present: the debug temp-file artifact
Get-ChildItem "$env:LOCALAPPDATA\Temp\MSBuildTemp" -ErrorAction SilentlyContinue

# 6. Corroboration only — do NOT hunt on this alone (rank 6, weakest)
Get-Process -Name msbuild -ErrorAction SilentlyContinue
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — the fleet-level
# signal is many hosts each independently showing msbuild.exe with an anomalous
# parent process and/or Roslyn/CodeDom compiler-assembly loads within a tight window
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  $parentAnomalies = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Message -match 'Image:.*\\msbuild\.exe' -and
      $_.Message -notmatch 'ParentImage:.*\\(devenv|MSBuild|dotnet|Build\.Runtime)\.exe'
    }

  $suspiciousFiles = Get-ChildItem -Path C:\Users, C:\Windows\Temp -Include *.csproj,*.xml,*.proj,*.rsp -Recurse -ErrorAction SilentlyContinue |
    Select-String -Pattern 'CodeTaskFactory|RoslynCodeTaskFactory' -List

  [PSCustomObject]@{
    Host                  = $env:COMPUTERNAME
    ParentAnomalyCount    = ($parentAnomalies | Measure-Object).Count
    LatestParentAnomaly   = ($parentAnomalies | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    SuspiciousFileHits    = ($suspiciousFiles | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.ParentAnomalyCount -gt 0 -or $_.SuspiciousFileHits -gt 0 } |
  Sort-Object LatestParentAnomaly -Descending

$results | Export-Csv -Path .\msbuild_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

Of limited standalone value for this tool — see `04 - Target Evidence.md`'s Network-Layer Evidence section: `msbuild.exe` generates no network traffic of its own beyond legitimate `-restore`/NuGet activity. Where a network sensor is available, the useful hunt is the inverse of `../certutil/`'s UA-string approach:

```
# Zeek: msbuild.exe-attributed connections (via endpoint-correlated process metadata,
# e.g. through an EDR-to-Zeek pivot) to destinations that are NOT a known package
# feed (nuget.org, an internal artifact repository) are not explained by any
# documented legitimate MSBuild behavior
```

This requires endpoint-process correlation to be useful at all — raw Zeek/NetFlow alone can't attribute a connection to `msbuild.exe` specifically the way it could read a certutil-characteristic User-Agent string directly off the wire.

## Remediation

**Capture evidence first** — the project file itself (if it still exists), a Sysmon 7 image-load record showing the compiler assemblies that loaded, and, if present, the `MSBuildTemp` debug artifact, before removing anything. Given how perishable the project file is (routinely deleted post-execution, and never recreated by any subsequent forensic action), prioritize recovering it — from disk, from deleted-file forensics, or from a memory capture per `04 - Target Evidence.md`'s Memory Forensics section — above all other remediation steps.

```powershell
# Kill the process if caught live
Get-Process -Name msbuild -ErrorAction SilentlyContinue | Stop-Process -Force

# Quarantine the project file and any Logger DLL — paths recovered from the
# Sysmon 1 CommandLine field, the @rsp file's contents, or file-content scanning
Move-Item "<RecoveredProjectFilePath>" "C:\Quarantine\" -Force -ErrorAction SilentlyContinue

# Check for the rare debug artifact before it's overwritten by a subsequent build
Get-ChildItem "$env:LOCALAPPDATA\Temp\MSBuildTemp" -ErrorAction SilentlyContinue |
  Move-Item -Destination "C:\Quarantine\" -Force -ErrorAction SilentlyContinue
```

Address whatever the executed inline task actually did — a C2 agent, shellcode staged via `msfvenom` (cross-link `../../Metasploit/msfvenom/`), a downstream download — using that payload's own dedicated tool folder in this module; this section covers only the MSBuild execution step itself.

Real hardening — beyond evidence capture:

- **Constrain `msbuild.exe` via AppLocker/WDAC on non-developer, non-build-server hosts** — most endpoints in most estates have no legitimate need for it at all. Note that a signed-binary-allowlist policy that trusts `msbuild.exe` purely because it's Microsoft-signed is precisely the gap this technique was built to exploit — a workstation-tier policy should deny it by default rather than allow it by signature alone.
- **Deploy file-content/YARA-style scanning for `.csproj`/`.xml`/`.proj`/`.rsp` files** where feasible — per the priority table, this is the only signal class that recovers the actual malicious logic, and it's the one most existing detection-rule sets (built around command-line pattern matching) don't cover.
- **Alert on Sysmon 7 Roslyn/CodeDom compiler-assembly loads by `msbuild.exe` combined with an anomalous parent process** — this survives every command-line-hiding evasion documented in this note (`@rsp` invocation, quiet verbosity) and doesn't depend on the project file still existing.
- **Enable command-line process auditing and Sysmon** — without either, only file-content scanning (rank 1, if deployed) remains usable; ranks 2-4 all depend on process-execution telemetry existing in the first place.
- **Treat "developer/CI-context only" as the actual policy target, not "signed binary = trusted"** — per `04 - Target Evidence.md`'s legitimate-vs-abuse contrast table, project-file location and parent process are what separate real build activity from abuse; a policy or detection rule built around those two dimensions is more durable than one built around the binary's signature alone.
