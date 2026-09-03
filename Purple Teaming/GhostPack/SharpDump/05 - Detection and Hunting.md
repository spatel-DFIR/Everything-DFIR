# SharpDump — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

SharpDump has essentially **one** real evasion lever, not a flag surface to weigh against several — per `01`/`02`, there is no argument beyond an optional numeric PID, no output-path/dump-type/rename switch of any kind. The only way to change any of the tool's fixed behavior is to **edit `Program.cs` directly and recompile** (`02`'s "Recompiling From Source" use case); everything else (a plain rename, reflective/in-memory loading) leaves the hardcoded internals untouched. Ranked by what a typical operator actually bothers to change versus what's structurally fixed regardless:

| Rank | Signal | Survives binary rename? | Survives full source recompile? | Survives reflective/in-memory loading? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | Fixed `debug<PID>.out`/`debug<PID>.bin` filenames under `%SystemRoot%\Temp\` (Sysmon 11) | ✅ Yes | ❌ **No** — this is the one thing a recompile is specifically capable of changing (a single `String.Format` literal edit) | ✅ Yes — the output still lands here regardless of how the assembly was loaded | The single most SharpDump-specific artifact this tool produces — **no CLI flag anywhere can change it**, only editing and rebuilding the source can; a hit against this exact pattern is close to a direct tool fingerprint, not just "LSASS dumping happened" (per `04`) |
| 2 | `PROCESS_ALL_ACCESS` (`0x1F0FFF`) requested against the target process (Sysmon 10 `GrantedAccess`) | ✅ Yes | ⚠️ Partial — defeated only if the operator deliberately swaps `Process.Handle` for a narrow, purpose-built `OpenProcess()` call, a real code change beyond a string edit | ✅ Yes | Broader than Mimikatz's `0x1010`/ProcDump's DbgHelp-driven mask (`03`/`04`) — a mask-based rule tuned only to those narrower values will **miss** SharpDump entirely; this rule catches it even against a renamed or PE-metadata-scrubbed build |
| 3 (weakest) | `dbghelp.dll` image load (Sysmon 7) into the calling process | ✅ Yes | ✅ Yes — inherent to calling `MiniDumpWriteDump()` at all; cannot be avoided without abandoning the DbgHelp API entirely | ✅ Yes | The most invariant signal of the three (survives even a full recompile) but the **least distinctive** — it's identical to what ProcDump `-ma` and `comsvcs.dll`'s `MiniDump` export also produce (`../../ProcDump/05 - Detection and Hunting.md`'s own rank-1 signal). Alone it only proves "*some* DbgHelp-based dumper ran here," not specifically SharpDump — combine with rank 1/2 to attribute it |

**Build hunts on rank 1 first, specifically for this tool.** Unlike `../../ProcDump/05 - Detection and Hunting.md`, where the `dbghelp.dll` load is the top-ranked signal because ProcDump/`comsvcs.dll` expose several genuine command-line evasion options that defeat everything else, SharpDump has no such options — its fixed filename pattern is both unusually strong *and* unusually cheap to hunt on (a simple path/filename match, no Sysmon-mask parsing required), which is why it outranks the shared `dbghelp.dll` signal here even though the DLL-load signal is technically the more evasion-proof of the two in absolute terms. Rank 3 is still worth deploying — it's the fallback that catches a fully recompiled SharpDump variant that ranks 1-2 miss — but treat it as attribution-weak on its own, per `../../ProcDump/04 - Target Evidence.md`'s shared-mechanic framing.

## Hunting on Source

Per `03 - Source Evidence.md`, SharpDump is normally run directly on the host it's dumping — "source" evidence here is mostly about where the binary came from and what identity ran it, since the mechanical dump artifacts are `04`'s territory. When fired remotely (`02`'s fleet-wide use case), the actual source-side command history/session state belongs to the delivery vector's own `03` file (`../../PsExec/03 - Source Evidence.md`, `../../Impacket/wmiexec/03 - Source Evidence.md`) — not re-derived here.

```powershell
# 1. PowerShell command history — captures the exact PID argument if run interactively
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'SharpDump'

# 2. PE metadata + Authenticode check on any *.exe found on disk, regardless of current filename
Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    $vi = $_.VersionInfo
    if ($vi.OriginalFilename -match 'SharpDump' -or $vi.ProductName -match 'SharpDump') {
      [PSCustomObject]@{ Path=$_.FullName; Signer=$sig.SignerCertificate.Subject; Status=$sig.Status; OriginalFileName=$vi.OriginalFilename }
    }
  }

# 3. RANK-1 — the fixed debug<PID>.out/.bin pattern, checked directly on this host
Get-ChildItem "$env:SystemRoot\Temp\debug*.out","$env:SystemRoot\Temp\debug*.bin" -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, CreationTime, LastWriteTime

# 4. RANK-2 — local Sysmon 10, if this host also has Sysmon deployed, for the PROCESS_ALL_ACCESS
#    request against whatever PID was targeted
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'GrantedAccess:\s*0x1F0FFF\b' }

# 5. Local Sysmon 7 — dbghelp.dll load into the invoking process (rank 3, weakest alone)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'dbghelp\.dll' }
```

## Hunting on Target

```powershell
# 1. RANK-1 — STRONGEST: the fixed debug<PID>.out/.bin filename pattern under %SystemRoot%\Temp\.
#    No CLI flag anywhere in SharpDump can move or rename this -- only a source recompile can.
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '(?i)\\Windows\\Temp\\debug\d+\.(out|bin)$' }

# Direct filesystem sweep for the same pattern (catches files even if Sysmon wasn't
# deployed at write-time but the artifact is still present)
Get-ChildItem "$env:SystemRoot\Temp\debug*.out","$env:SystemRoot\Temp\debug*.bin" -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, CreationTime

# Content-over-extension check -- confirm a .bin hit is genuinely gzip (1F 8B magic bytes),
# not an unrelated file that happens to match the naming pattern coincidentally
Get-ChildItem "$env:SystemRoot\Temp\debug*.bin" -ErrorAction SilentlyContinue | ForEach-Object {
  $bytes = [System.IO.File]::ReadAllBytes($_.FullName) | Select-Object -First 2
  if ($bytes[0] -eq 0x1F -and $bytes[1] -eq 0x8B) { $_.FullName }
}

# 2. RANK-2 -- PROCESS_ALL_ACCESS (0x1F0FFF) GrantedAccess against a sensitive process --
#    broader than the narrower masks Mimikatz/ProcDump typically request
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'GrantedAccess:\s*0x1F0FFF\b' -and $_.Message -match 'TargetImage:.*lsass\.exe' }

# 3. RANK-3 (weakest alone) -- dbghelp.dll image load into an unexpected process --
#    shared with ProcDump/comsvcs.dll, see ../../ProcDump/05 for the full ranking there
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'dbghelp\.dll' }

# 4. Sysmon 1 -- process creation for SharpDump.exe (or its renamed equivalent) with its
#    one positional PID argument, if any -- corroborating, not primary (defeated by rename)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '(?i)OriginalFileName:\s*SharpDump' }

# 5. USN Journal / $MFT check for the raw .out file's creation-then-deletion pair --
#    confirms a completed run even after the .out is gone (per 04's timeline)
fsutil usn readjournal C: csv | Select-String 'debug\d+\.out'
```

## Fleet-Wide Sweep

```powershell
# The realistic scale scenario per 02's fleet-wide deployment use case -- sweep for the
# rank-1 fixed-filename pattern across the estate first, since it's both the strongest
# and cheapest signal to check (a plain path/filename match, no mask parsing required).
$targets = Get-Content .\hosts.txt

$filenameHits = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-ChildItem "$env:SystemRoot\Temp\debug*.out","$env:SystemRoot\Temp\debug*.bin" -ErrorAction SilentlyContinue |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, FullName, Length, CreationTime
} -ErrorAction SilentlyContinue

$filenameHits | Export-Csv -Path .\sharpdump_filename_sweep.csv -NoTypeInformation

# Second pass -- PROCESS_ALL_ACCESS against lsass.exe across the estate, cross-referenced
# against Mimikatz/ProcDump's own narrower mask families (see 03/04) to separate this
# tool's broader request from the others
Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'GrantedAccess:\s*0x1F0FFF\b' -and $_.Message -match 'TargetImage:.*lsass\.exe' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated, Message
} -ErrorAction SilentlyContinue | Export-Csv -Path .\sharpdump_mask_sweep.csv -NoTypeInformation

# Third pass -- the shared dbghelp.dll signal, fleet-wide, catches a fully recompiled
# variant that defeats ranks 1-2 -- same query ../../ProcDump/05 already runs for its own tools
Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'dbghelp\.dll' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated, Message
} -ErrorAction SilentlyContinue | Export-Csv -Path .\dbghelp_load_sweep.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — pull the `.bin` file if it still exists (it's the direct memory-forensics artifact per `04`, parseable identically to a ProcDump/`comsvcs.dll` capture via `sekurlsa::minidump`), the Sysmon 1/7/10/11 event sequence, and — if LSASS was the target and PPL blocked the attempt — the WinInit Event 12/`RunAsPPL` state, before killing the responsible process or isolating the host. If the `.bin` already left the environment (per `02`'s exfil use case), the target-side event sequence and the USN Journal's record of the deleted `.out` may be the only remaining evidence of what was actually captured.

SharpDump itself is not the thing to fix — like ProcDump and `comsvcs.dll`, it's exercising a legitimate, documented Windows API (`DbgHelp!MiniDumpWriteDump()`). The durable controls target the access path to the process being dumped, not this specific tool:

```powershell
# Enable LSA protection (RunAsPPL) -- blocks SharpDump identically to ProcDump/comsvcs.dll,
# since all three fail at OpenProcess() against a Protected Process Light lsass.exe
# regardless of the access mask requested. Full mechanics and syntax: ../../ProcDump/05.
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -PropertyType DWord -Value 1 -Force
# Restart-Computer required for this to take effect.

# Enable the ASR rule "Block credential stealing from the Windows local security authority
# subsystem (lsass.exe)" (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2) in Block mode -- catches
# SharpDump's OpenProcess()-then-MiniDumpWriteDump() sequence the same way it catches
# ProcDump/comsvcs.dll, cross-linked from ../../Mimikatz/sekurlsa (Credential Dumping)/05
# and ../../ProcDump/05 rather than re-derived here.

# Deploy Sysmon with File Create (11) coverage specifically scoped to include
# %SystemRoot%\Temp\ -- per the Hunting Priority table, rank 1 (the strongest, cheapest
# signal on this page) depends entirely on this being logged; many default Sysmon configs
# exclude high-churn temp directories from File Create coverage, which would blind this
# specific hunt while leaving ranks 2-3 (Process Access / Image Load) unaffected.
```

Enabling `RunAsPPL` remains the single highest-leverage move when LSASS is the target — it removes the technique's actual prerequisite rather than just detecting a specific invocation pattern, and (per `01`'s convergence table) blocks SharpDump, ProcDump `-ma`, and `comsvcs.dll` MiniDump identically, since all three bottom out in the same `OpenProcess()`-then-`MiniDumpWriteDump()` sequence against a now-protected process. For non-LSASS targets (`02`'s arbitrary-PID use case), PPL offers no protection at all — that scenario's real mitigation is reducing which processes hold credential-bearing memory in the first place and restricting `SeDebugPrivilege`/local-admin-equivalent access, the same broader control `../../ProcDump/05 - Detection and Hunting.md` already documents.
