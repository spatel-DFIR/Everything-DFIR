# SafetyKatz — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion](#hunting-priority--which-signal-survives-which-evasion)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion

SafetyKatz's real evasion levers are narrower than most tools in this repo, precisely because `Main()` ignores `args` entirely (per `01`): **renaming the outer binary** (defeats image-name matching only), **in-memory/reflective loading** (`execute-assembly`, `[Assembly]::Load()` — defeats every file-based detection layer for the outer assembly), and **recompiling from modified source** (the only way to change the fixed `debug.bin` path, add PID targeting, or swap the embedded Mimikatz build — a materially higher-effort evasion step than any single command-line flag). No operator-facing option changes the `MiniDumpWriteDump()` call, the `PROCESS_ALL_ACCESS` request, or the fact that a second `PAGE_EXECUTE_READWRITE` region gets manually mapped inside the process for the embedded Mimikatz — all three are baked into the tool's unconditional code path.

| Rank | Signal | Survives binary rename? | Survives in-memory/reflective load? | Survives recompiling from modified source? |
|---|---|---|---|---|
| 1 (strongest) | Sysmon 10 `GrantedAccess` mask against `lsass.exe` (`0x1F0FFF`, the `PROCESS_ALL_ACCESS` family shared with `../SharpDump/`) | ✅ Yes — kernel-generated at `OpenProcess()` time, independent of file identity | ✅ Yes — identical system call whether the code came from a file or a reflectively-mapped region | ✅ Yes, **unless** the operator also rewrites the handle-acquisition code to use a narrower `OpenProcess()` call directly instead of `Process.Handle` — a real but nontrivial source change beyond adding PID targeting |
| 2 | Sysmon 7 — `dbghelp.dll` image load into the SafetyKatz process (or its reflective-load host) | ✅ Yes | ✅ Yes | ✅ Yes — the API call is the entire mechanism, not something a simple recompile would remove |
| 3 | Sysmon 11 → 23 pairing — `debug.bin` create-then-delete in a tight window at `%SystemRoot%\Temp\` | ✅ Yes | ✅ Yes | ❌ **No** — this is exactly the fixed behavior a source-level recompile can change (different path, different filename, PID-qualified naming) |
| 4 | Internal `VirtualAlloc(PAGE_EXECUTE_READWRITE)` region inside the SafetyKatz process, distinct from its own loaded-module list (the manually-mapped inner Mimikatz PE) | ✅ Yes | ✅ Yes — present on every run regardless of how the outer assembly itself was loaded | ⚠️ Partial — surviving only if the operator keeps the hand-rolled PE-loader approach; swapping to a different in-memory-execution technique (e.g., process hollowing, a different loader) changes this signal's shape without eliminating in-process anomaly entirely |
| 5 | ASR rule 1121 (block) / 1122 (audit) — "Block credential stealing from lsass.exe" | ✅ Yes | ✅ Yes — but **only if the rule is actually deployed**; absence proves nothing, same caveat as `../../Mimikatz/sekurlsa (Credential Dumping)/05 - Detection and Hunting.md` | ✅ Yes |
| 6 (weakest) | PE metadata / static hash on the outer `SafetyKatz.exe`, or a static signature on the embedded Mimikatz blob specifically | ❌ **No** for the outer assembly — trivially defeated by editing `AssemblyInfo.cs` before compiling | ❌ **No** — no outer file exists to hash at all if reflectively loaded | ❌ No for the outer assembly; the **embedded Mimikatz blob** signature is comparatively more durable (per `04`'s finding that it's a fixed 2018 build across unmodified compiles) but is defeated the moment an operator regenerates `Constants.cs` with a different build |

**Build detections on ranks 1-2.** Both are direct, kernel/API-level consequences of calling `MiniDumpWriteDump()` at all — identical reasoning to `../../ProcDump/05 - Detection and Hunting.md` and `../SharpDump/01 - Overview.md`'s shared-mechanic framing. **Rank 4 is SafetyKatz's own distinguishing high-value signal** — no other tool in this GhostPack family manually maps a second executable image inside its own process on every single run. **Rank 6 catches only the least-careful operators and should never be a sole control**, same conclusion as every other credential-dumping tool documented in this repo.

## Hunting on Source

Applies when the operator's own pivot/staging box is itself in scope. Finds the artifacts documented in `03 - Source Evidence.md`.

```powershell
# PSReadLine history — SafetyKatz's command line carries no arguments, so this
# only confirms the bare invocation was typed, not any targeting detail
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
  -Pattern 'SafetyKatz' -ErrorAction SilentlyContinue

# Security 4688 (command-line process creation, if enabled) — the most durable
# operator-side record, generated at process-creation time
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'SafetyKatz' }

# Live process check for a still-running dropped binary
Get-Process | Where-Object { $_.ProcessName -match 'SafetyKatz' }

# PE metadata check on any *.exe found on disk, regardless of current filename —
# catches a renamed SafetyKatz.exe via its AssemblyTitle/AssemblyProduct strings
Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $vi = $_.VersionInfo
    if ($vi.ProductName -match 'SafetyKatz' -or $vi.FileDescription -match 'SafetyKatz') {
      [PSCustomObject]@{ Path=$_.FullName; ProductName=$vi.ProductName }
    }
  }

# A leftover debug.bin from an interrupted run staged locally for later analysis
Get-ChildItem -Path C:\ -Recurse -Filter 'debug.bin' -ErrorAction SilentlyContinue -Force
```

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE: Sysmon Event 10 against lsass.exe with the PROCESS_ALL_ACCESS-
#    family GrantedAccess mask, excluding known-legitimate SourceImages
$knownMaskPattern = '0x1F0FFF|0x1FFFFF|0x1F1FFF'
$legitSourcePattern = 'MsMpEng\.exe|SenseIR\.exe|svchost\.exe'
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object {
    $_.Message -match 'TargetImage:.*lsass\.exe' -and
    $_.Message -match $knownMaskPattern -and
    $_.Message -notmatch $legitSourcePattern
  } |
  Select-Object TimeCreated, @{n='SourceImage';e={($_.Message -split "`r`n" | Where-Object { $_ -match 'SourceImage:' })}},
    @{n='GrantedAccess';e={($_.Message -split "`r`n" | Where-Object { $_ -match 'GrantedAccess:' })}}

# 2. dbghelp.dll image load — shared signal, catches SafetyKatz alongside
#    SharpDump/ProcDump/comsvcs.dll
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { $_.Message -match 'dbghelp\.dll' }

# 3. debug.bin file creation — the narrowest filename signal in this tool
#    family (no PID suffix at all); best caught LIVE, since the file is
#    normally deleted again within seconds
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} |
  Where-Object { $_.Message -match '\\Temp\\debug\.bin$' }

# 4. debug.bin deletion, if File Delete auditing (Sysmon 23) is configured —
#    pairing with #3 above confirms a complete run rather than an interrupted one
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=23} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\Temp\\debug\.bin$' }

# 5. Correlate #3 and #4 into create-then-delete pairs within a tight window —
#    a strong behavioral signature for this specific tool's transient-file design
$creates = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\Temp\\debug\.bin$' }
$deletes = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=23} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\Temp\\debug\.bin$' }
foreach ($c in $creates) {
  $match = $deletes | Where-Object { ($_.TimeCreated - $c.TimeCreated).TotalSeconds -ge 0 -and ($_.TimeCreated - $c.TimeCreated).TotalSeconds -lt 30 }
  if ($match) { [PSCustomObject]@{ Created = $c.TimeCreated; Deleted = $match.TimeCreated } }
}

# 6. ASR rule hits — Block (1121) and Audit (1122) for the LSASS credential-theft rule
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1121,1122} |
  Where-Object { $_.Message -match '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' }

# 7. WinInit Event 12 — LSA-protection (PPL) state at boot, same mechanic as
#    ../../ProcDump/04 - Target Evidence.md
Get-WinEvent -FilterHashtable @{LogName='System'; Id=12} |
  Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Wininit' }

# 8. Filesystem-remnant hunt for an orphaned/uncleaned debug.bin from an
#    interrupted run (crash, kill, PPL block after partial write)
Get-ChildItem -Path "$env:SystemRoot\Temp\debug.bin" -ErrorAction SilentlyContinue
```

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

# Incident sweep — PROCESS_ALL_ACCESS hits against lsass.exe across the estate,
# the same shared mask family SharpDump and SafetyKatz both trigger
$incidentResults = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'lsass\.exe' -and $_.Message -match '0x1F0FFF|0x1FFFFF' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated
} -ErrorAction SilentlyContinue

# debug.bin create-event sweep — narrow filename, catches live/near-live runs;
# will miss any run whose full lifecycle (create + delete) happened between polls
$debugBinHits = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '\\Temp\\debug\.bin$' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated
} -ErrorAction SilentlyContinue

# Orphaned-file sweep — hosts where an interrupted run left debug.bin behind
$orphanResults = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-ChildItem -Path "$env:SystemRoot\Temp\debug.bin" -ErrorAction SilentlyContinue |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, FullName, CreationTime, LastWriteTime
} -ErrorAction SilentlyContinue

# Posture sweep — which hosts still allow the technique at all (identical
# control surface to SharpDump/ProcDump/comsvcs.dll, since all four are
# blocked identically by RunAsPPL)
$postureResults = Invoke-Command -ComputerName $targets -ScriptBlock {
  [PSCustomObject]@{
    Host     = $env:COMPUTERNAME
    RunAsPPL = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
  }
} -ErrorAction SilentlyContinue

$incidentResults + $debugBinHits + $orphanResults | Export-Csv -Path .\safetykatz_incident_sweep.csv -NoTypeInformation
$postureResults | Where-Object { $_.RunAsPPL -ne 1 } | Export-Csv -Path .\safetykatz_exposed_hosts.csv -NoTypeInformation
```

## Remediation

**Capture evidence before acting.** SafetyKatz's real damage is whatever credential material was already parsed and displayed/exfiltrated by the time it's detected — killing the process after the fact doesn't undo that. Because the `debug.bin` dump file is normally already deleted by the time a hunt catches this activity, **the SafetyKatz process's own live memory** (if it's still running) is a materially higher-value capture target than for `../SharpDump/`, since the decrypted credential material genuinely exists inside that process's address space during execution (per `03`/`04`). Export the relevant Sysmon 7/10/11/23 events and, where forensically warranted and the process is still live, capture a memory image of the SafetyKatz process (or the full host) before proceeding.

```powershell
# 1. Isolate the host — any credential material SafetyKatz already displayed/
#    exfiltrated can be used for lateral movement independent of anything
#    happening on this box going forward
# (isolation mechanism is environment-specific — EDR network-containment, VLAN change, etc.)

# 2. Kill the offending process/session, if still running
Get-Process | Where-Object { $_.ProcessName -match 'SafetyKatz' } | Stop-Process -Force -ErrorAction SilentlyContinue

# 3. Force credential rotation for every account whose material could plausibly
#    have appeared in the dump — assume anything a full-memory LSASS dump could
#    expose (NTLM hash, WDigest plaintext if enabled, Kerberos keys/tickets) is
#    compromised, not just the account used to gain initial access. See
#    ../../Mimikatz/sekurlsa (Credential Dumping)/05 - Detection and Hunting.md
#    for the full credential-scope reasoning.

# 4. Remove any surviving debug.bin (interrupted-run scenario) only AFTER
#    forensic capture is complete — it's the direct evidence of exactly which
#    LSASS memory state was exposed
```

**Close the underlying exposure, not just this incident:**
- Enable LSA Protection (`RunAsPPL`) fleet-wide where compatible — this is the single highest-leverage control here, exactly as `../../ProcDump/05 - Detection and Hunting.md` concludes: it removes SafetyKatz's actual prerequisite (a successful `OpenProcess()`/`MiniDumpWriteDump()` against `lsass.exe`) rather than reacting to any one binary or filename, and blocks SafetyKatz, `../SharpDump/`, ProcDump, and `comsvcs.dll` identically, since all four share the same `MiniDumpWriteDump()` mechanic.
- Enable the ASR rule "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) in **Block** mode — cross-linked from `../../Mimikatz/sekurlsa (Credential Dumping)/05 - Detection and Hunting.md` and `../../ProcDump/05 - Detection and Hunting.md`, the same rule already documented to catch non-Mimikatz LSASS-access tools generally.
- Enable Credential Guard where hardware/edition support allows — isolates NTLM/Kerberos secrets in a VBS-protected LSA process (`LsaIso.exe`) separate from `lsass.exe`, a deeper mitigation than PPL alone.
- Deploy Sysmon with Image Load (7), Process Access (10), File Create (11), and — specifically valuable for this tool's transient-file design — File Delete (23) coverage, since SafetyKatz's `debug.bin` create-then-delete pairing (per this page's Hunting Priority rank 3) depends on both event types existing to be useful at all.
- Restrict `SeDebugPrivilege`/local-administrator assignment to only the accounts/groups that genuinely need it — SafetyKatz's own unconditional `IsHighIntegrity()` gate (per `01`) means this control alone stops the tool from ever reaching its dump step in the first place for a non-elevated caller.
