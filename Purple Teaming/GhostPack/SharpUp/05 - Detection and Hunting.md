# SharpUp — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

SharpUp has an unusually narrow evasion surface compared to most tools in this repo — there is no flag namespace at all beyond check names and the literal `audit` keyword (per `01`), so the realistic evasion levers are: **binary rename** (trivial, no PE-metadata effect unless deliberate), **recompiling from modified source** (per `03`, the *only* way to change check-name strings, PE metadata, or the tool's own dispatch/threading model), and **reflective/in-memory loading** (`execute-assembly`, `[Assembly]::Load()` — avoids a standalone-EXE process-creation event entirely). Ranked by which signals survive the most of these:

| Rank | Signal | Survives binary rename? | Survives full source recompile? | Survives reflective/in-memory loading? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | The concurrent-thread query burst — a dense, sub-second cluster of registry/WMI/file-ACL reads and (if `ProcessDLLHijack` runs) dozens of Process Access events, all from one process | ✅ Yes | ⚠️ **Only defeated by rewriting `Program.cs`'s dispatch loop itself** — a structural change, not a string edit, meaningfully harder than editing a check's own file | ✅ Yes — the burst happens inside whatever process hosts the CLR, standalone or reflective | The most invariant signal on this page precisely because it's a property of the tool's *architecture*, not any editable string or flag; the same operator who recompiles to rename `ModifiableServices` rarely also reworks the threading model |
| 2 | `ProcessDLLHijack`'s mass `OpenProcess(0x0410)` burst against every running process (Sysmon 10) | ✅ Yes | ⚠️ Partial — only defeated by dropping/rewriting that specific check | ✅ Yes | Distinctive for *volume* (dozens-to-hundreds of target PIDs from one source in one window), not mask novelty — see `03`/`04` |
| 3 | Registry/WMI query telemetry (WMI-Activity 5857 for the `Win32_Service` query; Sysmon RegistryEvent 12/13 if deployed, non-default) | ✅ Yes | ✅ Yes — the underlying API call is inherent to what the check has to do to get its answer, unrelated to naming | ✅ Yes | Individually low-signal (registry/WMI reads are common background noise) — value comes from correlating against rank 1's timing burst, not from any single hit alone |
| 4 | `DomainGPPPassword`'s SYSVOL SMB read — source-host outbound SMB session + (non-default) target-DC Event 5140/5145 | ✅ Yes | ✅ Yes — a UNC-path walk to `\\<domain>\SYSVOL` is unavoidable if this specific check runs at all | ✅ Yes | Only fires when this one check is requested — not a general-purpose signal, but the strongest *network-layer* evidence this tool ever produces, and the only one this repo can point a Zeek/NetFlow hunt at |
| 5 | Specific check names as literal strings in the process command line (`ModifiableServices`, `UnquotedServicePath`, `audit`, etc.) | ❌ **No** — an operator who renames the `Checks/*.cs` classes before compiling changes what argument they must type, defeating a string match entirely | ❌ **No** | ❌ **No** — reflectively loaded via `[SharpUp.Program]::Main(@("audit","ModifiableServices"))`, the argument array never appears in an on-disk command line or native Sysmon 1 event at all, only (if anywhere) in the hosting C2 framework's own task/beacon log | Highest plain-English value when it *is* captured (states attacker intent directly, per `03`) but the single most easily defeated signal in this table |
| 6 (weakest) | Process/binary identity — image name, file hash, PE metadata (`AssemblyTitle`/`AssemblyProduct`) | ❌ **No** — rename defeats image-name matching outright | ❌ **No** — recompiling with edited `AssemblyInfo.cs` takes seconds | ✅ N/A once reflective (no on-disk binary at all) | No official binary is ever released (per `01`) — there is no canonical hash or signature to match against in the first place, the same structural weakness this repo already documents for Rubeus/Seatbelt/SharpDump |

**Build hunts on ranks 1-2 first.** They're the direct consequence of `Program.cs`'s own architecture (per `03`/`04`) — every realistic SharpUp invocation that runs more than one or two checks produces this burst regardless of which specific checks were named, how the binary was renamed, or whether PE metadata was scrubbed. Rank 5-6 are the naive approaches ("match the string `SharpUp`" / "match this file hash") that a minimally competent operator defeats with a five-minute recompile.

## Hunting on Source

```powershell
# 1. PowerShell command history — captures the exact check name(s)/audit argument if run interactively
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'SharpUp|audit\s+(AlwaysInstallElevated|CachedGPPPassword|DomainGPPPassword|HijackablePaths|McAfeeSitelistFiles|ModifiableScheduledTaskFile|ModifiableServiceBinaries|ModifiableServiceRegistryKeys|ModifiableServices|ProcessDLLHijack|RegistryAutoLogons|RegistryAutoruns|TokenPrivileges|UnattendedInstallFiles|UnquotedServicePath)'

# 2. Process creation with the tool's actual command-line shape (works even against a renamed
#    binary, since it matches on the check-name/audit argument structure, not the image name)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '(?i)\baudit\b' -and $_.Message -match '(?i)ModifiableServ|UnquotedServicePath|HijackablePaths|TokenPrivileges|GPPPassword' }

# 3. PE metadata + Authenticode check on any *.exe found on disk, regardless of current filename
Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    $vi = $_.VersionInfo
    if ($vi.OriginalFilename -match 'SharpUp' -or $vi.ProductName -match 'SharpUp') {
      [PSCustomObject]@{ Path=$_.FullName; Signer=$sig.SignerCertificate.Subject; Status=$sig.Status; OriginalFileName=$vi.OriginalFilename }
    }
  }

# 4. The concurrent-thread burst — rank-1 signal — a single SourceImage generating a dense
#    cluster of Sysmon 10 Process Access events against MANY distinct target PIDs within
#    a short window (the ProcessDLLHijack signature)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
  Group-Object { ($_.Message -split "`n" | Select-String 'SourceImage:').ToString() }, { $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm') } |
  Where-Object { $_.Count -gt 15 } |
  Select-Object Name, Count

# 5. Outbound SMB session to a domain's SYSVOL share (DomainGPPPassword only)
Get-SmbConnection -ErrorAction SilentlyContinue | Where-Object { $_.ShareName -eq 'SYSVOL' }
```

## Hunting on Target

Since SharpUp is normally local-only, "target" is the same host — the queries below are the target-side equivalents of the same events, reframed for a fleet-hunt/SOC-analyst perspective rather than a live-response-on-this-box perspective.

```powershell
# 1. RANK-1 — the concurrent-thread burst, fleet-scoped: any single process generating a
#    dense cluster of Process Access events against many distinct PIDs in one short window
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
  Group-Object { ($_.Message -split "`n" | Select-String 'SourceImage:').ToString() }, { $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss') } |
  Where-Object { $_.Count -gt 15 } |
  Select-Object @{n='Group';e={$_.Name}}, Count | Sort-Object Count -Descending

# 2. RANK-2 — GrantedAccess mask 0x410 (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
#    fired against an unusually large number of distinct TargetImage values from one SourceImage
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'GrantedAccess:\s*0x410\b' }

# 3. WMI-Activity 5857 for a local Win32_Service query, correlated against the process burst above
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5857} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Message

# 4. DomainGPPPassword's SYSVOL read, if Object Access auditing is enabled on the share
#    (non-default — see 04) -- recursive .xml enumeration from a single source in a short window
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140,5145} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'SYSVOL' }

# 5. Command-line argument-shape hunt — check-name strings, survives rename but not recompile
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '(?i)\baudit\b' -or $_.Message -match '(?i)ModifiableServ|UnquotedServicePath|GPPPassword|TokenPrivileges' }

# 6. PE metadata check on any *.exe found anywhere on the host, regardless of current filename
Get-ChildItem -Path C:\Windows,C:\ProgramData,C:\Users -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $vi = $_.VersionInfo
    if ($vi.OriginalFilename -match 'SharpUp' -or $vi.ProductName -match 'SharpUp') {
      [PSCustomObject]@{ Path=$_.FullName; OriginalFileName=$vi.OriginalFilename }
    }
  }
```

## Fleet-Wide Sweep

```powershell
# The realistic scale scenario: sweep for the concurrent-thread burst (rank 1) and the
# ProcessDLLHijack mass-OpenProcess signature (rank 2) across the estate at once, since
# both survive binary rename and are the hardest signals for an operator to engineer away
# without rewriting SharpUp's own dispatch loop.
$targets = Get-Content .\hosts.txt

$burstHits = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Group-Object { ($_.Message -split "`n" | Select-String 'SourceImage:').ToString() }, { $_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss') } |
    Where-Object { $_.Count -gt 15 } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, @{n='Group';e={$_.Name}}, Count
} -ErrorAction SilentlyContinue

$burstHits | Export-Csv -Path .\sharpup_burst_sweep.csv -NoTypeInformation

# Second pass — SYSVOL access-object auditing, if enabled anywhere in the estate's DCs
$DCs = (Get-ADDomainController -Filter *).HostName
Invoke-Command -ComputerName $DCs -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140,5145; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'SYSVOL' } |
    Select-Object @{n='DC';e={$env:COMPUTERNAME}}, TimeCreated, Message
} -ErrorAction SilentlyContinue | Export-Csv -Path .\sysvol_access_sweep.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — the process-creation event with its check-name argument, the Sysmon 10 burst pattern, and (if `DomainGPPPassword` ran) the target-DC Event 5140/5145 window, before killing the process or isolating the host. Because SharpUp writes no output file, once the process exits its own console output is normally the only record of *what it actually found* (as opposed to *that it ran*) unless that console session's own scrollback/logging was separately captured.

SharpUp itself is not the thing to fix — it's a read-only enumeration tool exercising legitimate Windows APIs; the durable controls close the underlying misconfigurations it finds, not the finder:

```powershell
# The single highest-leverage move: fix whatever SharpUp actually found, per finding class.
# SharpUp itself never weaponizes anything (per 01) -- remediate the underlying
# misconfiguration directly, the same targets PowerUp's own weaponization functions abuse:

# Unquoted service paths -- quote the ImagePath directly
Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match '\s' } |
  ForEach-Object { sc.exe config $_.Name binPath= "`"$($_.PathName)`"" }

# Overly permissive service DACLs / registry keys -- audit and tighten with sc.exe sdset
# or Set-Acl against HKLM:\SYSTEM\CurrentControlSet\Services\<name>, scoped to the
# specific over-broad ACE SharpUp's ModifiableServices/ModifiableServiceRegistryKeys
# check identified -- do not blanket-apply, verify per-service first.

# AlwaysInstallElevated -- disable in both hives (SharpUp's own check has a known false-
# positive gap here, per 02 -- verify both keys are literally 1 before treating as exploitable)
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

# Cached/domain GPP passwords -- per MS14-025, delete the offending Groups.xml/etc. files
# outright (the setting itself, not just the cpassword value, is deprecated) and rotate
# any credential ever stored this way -- see Windows/GPO/02 for the full remediation detail.
```

- **Deploy Sysmon with Process Access (10), Image Load (7), and — if the registry-read
  angle matters for a given environment — RegistryEvent (12/13) coverage.** Per the Hunting
  Priority table, ranks 1-2 depend entirely on Process Access coverage; without it, this
  tool leaves almost nothing native to hunt on at all, since Windows doesn't audit registry/
  file-ACL reads or local WMI queries by default.
- **Enable Object Access auditing on the SYSVOL share** if `DomainGPPPassword`-style hunting
  matters in a given environment — non-default, the same gap this repo's Kerberoasting/DCSync
  pages already flag for their own SYSVOL/DRSUAPI-adjacent signals.
- **Reduce the standing local-admin/write-access footprint** that makes SharpUp's findings
  exploitable in the first place — LAPS, tiered administration, and routine service-ACL/
  scheduled-task-ACL hygiene audits shrink the attack surface SharpUp is built to discover,
  independent of whether any given run is ever detected.
- **Treat a captured SharpUp finding as a live-exploitation warning, not just a detection
  event** — because the tool is pure enumeration, catching it *at all* (via the burst
  pattern) is genuinely time-sensitive: the operator now knows exactly which privesc path
  is open on this host and the next step is real exploitation, not further recon.
