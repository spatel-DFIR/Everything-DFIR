# ProcDump / comsvcs.dll MiniDump — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

Real evasion levers across both techniques: **renaming the ProcDump binary** (defeats image-name matching, not PE metadata), **calling `comsvcs.dll`'s export by ordinal instead of name** (defeats command-line string matching on `MiniDump`), **choosing a smaller dump type** (`-mp`/`-mt` instead of `-ma` — changes dump content, not the API call or access mask), and **disabling `RunAsPPL`** (removes the access-control gate entirely, an administrative action rather than a per-invocation flag). No option defeats the shared `dbghelp.dll` load or the underlying `OpenProcess()` access mask — both are consequences of calling `MiniDumpWriteDump()` at all, which is the one thing every variant of this technique on this page has in common.

| Rank | Signal | Survives binary renaming? | Survives ordinal-vs-name invocation? | Survives dump-type choice (`-ma`/`-mp`/`-mt`)? | Depends on Sysmon deployment? |
|---|---|---|---|---|---|
| 1 (strongest) | Sysmon 7 — `dbghelp.dll` image load into `rundll32.exe` (comsvcs.dll path) or any non-standard process | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Required |
| 2 | Sysmon 10 — `OpenProcess()` `GrantedAccess` mask against `lsass.exe` from an unexpected `SourceImage` (cross-linked mask family, `../Mimikatz/sekurlsa (Credential Dumping)/05`) | ✅ Yes | ✅ Yes | ✅ Yes — the mask requested doesn't meaningfully change across dump types | ✅ Required |
| 3 | `WinInit` Event 12 + `RunAsPPL` registry-value-change timestamp pairing (catches the PPL-disable prerequisite step) | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No — native Windows event |
| 4 | PE metadata check (`OriginalFileName`/`InternalName`) on any `procdump*.exe` found on disk | ✅ Yes — survives the rename it's specifically designed to catch | N/A (comsvcs.dll path has no equivalent binary) | ✅ Yes | ❌ No |
| 5 | Sysmon 11 — `.dmp`/`.bin` file creation, filtered on size/path heuristics rather than filename | ✅ Yes | ✅ Yes | ⚠️ Partial — a `-mt` Triage dump's smaller size may fall below a naive size-threshold filter tuned for `-ma` Full dumps | ✅ Required |
| 6 (weakest) | Command-line string match on literal `-ma lsass.exe` / `MiniDump` | ❌ **No** — defeated by dump-type choice, PID-only targeting (no literal `lsass.exe` string), or the ordinal-invocation variant | ❌ **No** | ❌ **No** — a `-mm`/`-mt` invocation doesn't contain `-ma` at all | ❌ No, but weak regardless |

**Build hunts on ranks 1–2 first.** They're the direct consequence of the mechanical convergence documented in `01`/`04` — every variant of either technique on this page, however the operator dresses it up at the command-line level, still has to load `dbghelp.dll` and request the same `OpenProcess()` access rights against `lsass.exe`. Rank 6 is the naive approach most generic "detect LSASS dumping" write-ups lead with, and it's the first thing a competent operator defeats.

## Hunting on Source

```powershell
# 1. EulaAccepted registry value — ProcDump-specific, proves it ran under this profile
Get-ItemProperty 'HKCU:\Software\Sysinternals\ProcDump' -Name EulaAccepted -ErrorAction SilentlyContinue
Get-ItemProperty 'HKCU:\Software\Sysinternals' -Name EulaAccepted -ErrorAction SilentlyContinue

# 2. PE metadata + Authenticode check on any procdump*.exe found on disk, regardless
#    of its current filename
Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    $vi = $_.VersionInfo
    if ($vi.OriginalFilename -match 'procdump' -or $vi.ProductName -match 'ProcDump') {
      [PSCustomObject]@{ Path=$_.FullName; Signer=$sig.SignerCertificate.Subject; Status=$sig.Status; OriginalFileName=$vi.OriginalFilename }
    }
  }

# 3. Command-line history for either technique's invocation syntax
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'procdump|comsvcs|MiniDump|-ma\s+lsass|,#24'

# 4. Local Sysmon 7/10 (if this host is itself the origin of a locally-run dump
#    rather than a lateral target) — dbghelp.dll load + lsass.exe process access
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'dbghelp\.dll' }
```

## Hunting on Target

```powershell
# 1. STRONGEST — dbghelp.dll loaded into rundll32.exe (highly anomalous) or into
#    any process whose image name doesn't already suggest a debugging tool
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { $_.Message -match 'dbghelp\.dll' -and $_.Message -match 'rundll32\.exe|Image:.*(?!procdump)' }

# 2. Sysmon 10 — OpenProcess() against lsass.exe, any SourceImage that isn't a
#    known-legitimate AV/EDR/debugging process
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object { $_.Message -match 'TargetImage:.*lsass\.exe' }

# 3. WinInit Event 12 — confirm PPL protection state at each boot, and pair
#    against any RunAsPPL registry-write timestamp to catch the disable-then-
#    reboot-then-dump sequence from 02
Get-WinEvent -FilterHashtable @{LogName='System'; Id=12} |
  Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Wininit' }

# 4. PE metadata check on any procdump*.exe found on the target, wherever it landed
Get-ChildItem -Path C:\Windows,C:\ProgramData,C:\Users -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $vi = $_.VersionInfo
    if ($vi.OriginalFilename -match 'procdump') {
      [PSCustomObject]@{ Path=$_.FullName; OriginalFileName=$vi.OriginalFilename }
    }
  }

# 5. Sysmon 11 — .dmp/.bin file creation, filtered on size + non-standard path
#    rather than filename (catches a renamed output file)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} |
  Where-Object { $_.Message -match '\.dmp$|\.bin$' -and $_.Message -notmatch '\\WINDOWS\\Minidump\\|\\CrashDumps\\' }

# 6. Sysmon 1 — command-line syntax for either invocation form, including the
#    ordinal-bypass variant
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'comsvcs\.dll' -or $_.Message -match '-ma\s' }
```

## Fleet-Wide Sweep

```powershell
# The realistic scale scenario per 02's chained-deployment use case — sweep
# for the shared dbghelp.dll-into-unexpected-process signal across the estate,
# since it's the one thing that survives every evasion option in this note
$targets = Get-Content .\hosts.txt

$dbghelpHits = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'dbghelp\.dll' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated, Message
} -ErrorAction SilentlyContinue

$dbghelpHits | Export-Csv -Path .\dbghelp_load_sweep.csv -NoTypeInformation

# Second pass — lsass.exe ProcessAccess across the estate, cross-referenced
# against the mask family documented in Mimikatz/sekurlsa's own hunting note
Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'lsass\.exe' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated, Message
} -ErrorAction SilentlyContinue | Export-Csv -Path .\lsass_access_sweep.csv -NoTypeInformation

# Third pass — any orphaned .dmp/.bin files sitting outside the two legitimate
# crash-dump directories, across the estate
Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-ChildItem -Path C:\Windows\Temp,C:\ProgramData,C:\Users -Recurse -Include *.dmp,*.bin -ErrorAction SilentlyContinue |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, FullName, Length, CreationTime
} -ErrorAction SilentlyContinue | Export-Csv -Path .\orphaned_dump_sweep.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — pull the `.dmp`/`.bin` file if it still exists, the Sysmon 1/7/10/11 event sequence, and any `RunAsPPL` registry-change/WinInit Event 12 pairing, before killing the responsible process or isolating the host. If the dump file already left the environment (per `02`'s exfil use case), the target-side event sequence may be the only remaining evidence of what was actually captured.

Neither ProcDump nor `comsvcs.dll` is the thing to fix — one is a legitimate signed Microsoft diagnostic tool, the other is a core OS component. The durable controls target the access path to `lsass.exe` itself, not either binary:

```powershell
# Enable LSA protection (RunAsPPL) — the single control that blocks BOTH
# techniques on this page outright, since both fail at OpenProcess() against
# a Protected Process Light lsass.exe regardless of privilege level. Verified
# against Microsoft Learn's own "Configure added LSA protection" guidance.
# HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (with UEFI lock) or
# 2 (without), followed by a required restart.
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -PropertyType DWord -Value 1 -Force
# Restart-Computer required for this to take effect.

# Enable Credential Guard where hardware/edition support it — isolates NTLM/
# Kerberos/Credential-Manager secrets in a VBS-protected LSA process (LSAIso.exe)
# separate from lsass.exe itself, a deeper mitigation than PPL alone.

# Enable the ASR rule "Block credential stealing from the Windows local
# security authority subsystem (lsass.exe)" (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)
# in Block mode — cross-linked from ../Mimikatz/sekurlsa (Credential Dumping)/05,
# this rule is specifically documented to catch non-Mimikatz LSASS-access tools
# including ProcDump-style dumping.

# Restrict SeDebugPrivilege assignment to only the accounts/groups that
# genuinely need it — both techniques rely on this privilege (or local-admin-
# equivalent access) being available to the operator's session at all.

# Deploy Sysmon with Image Load (7), Process Access (10), and File Create (11)
# coverage if not already present — per the Hunting Priority table, ranks 1-2
# (the strongest, evasion-resistant signals on this page) depend on it existing.
```

Enabling `RunAsPPL` is the highest-leverage single move here — unlike a detection rule tuned to a specific binary name or command-line pattern, it removes the technique's actual prerequisite (per `01`'s How It Works section) for both ProcDump and `comsvcs.dll` at once, and for any future third launcher that reaches the same `MiniDumpWriteDump()` API.
