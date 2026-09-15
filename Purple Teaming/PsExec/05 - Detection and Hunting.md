# PsExec (Sysinternals) — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

Genuine PsExec exposes three real evasion levers: **`-r`** (renames the service, the dropped binary, and the resulting named pipes all together — per `01`/`04`'s finding, they're not independent), **a custom-built/patched service binary** (defeats hash-based matching on the default `PSEXESVC.exe`, the direct analog of Impacket's own `-file` caveat), and **an outdated pre-v2.30 PsExec build** (never generates the `.key` file at all — an evasion the operator gets "for free" simply by not updating, not a flag they have to choose). No single option defeats every signal below — build hunts on the top of this table first.

| Rank | Signal | Survives `-r`? | Survives a custom/patched service binary? | Depends on PsExec ≥ v2.30? |
|---|---|---|---|---|
| 1 (strongest) | `PSEXEC-<source-hostname>-<8-hex>.key` file creation in `C:\Windows\` (Sysmon 11 / USN Journal) | ✅ Yes — the `.key` mechanism is entirely separate from the service/pipe-naming logic `-r` touches | ✅ Yes — created by the *client's* logic, independent of which service binary got dropped | ❌ **No** — absent entirely on pre-v2.30 operator tooling. Absence is not proof of no PsExec use |
| 2 | PE metadata match — `OriginalFileName == psexesvc.exe` / `InternalName == "PsExec Service Host"` on the target-side dropped binary (or `OriginalFileName == psexec.c` on the source-side client) | ✅ Yes — renaming the file on disk doesn't touch compiled-in VERSIONINFO | ❌ **No** — a genuinely custom-built service binary has no reason to carry PsExec's PE metadata at all | ✅ Yes — unrelated to version |
| 3 | Authenticode signature validity + publisher check on `psexec.exe` itself (source host) | ✅ Yes | N/A — this check is about the client binary, not the dropped service payload | ✅ Yes |
| 4 | System 7045 (service install) event, filtered on `ImagePath` pattern (`...\System32\*.exe`, installed then removed within minutes) rather than a literal `ServiceName == PSEXESVC` string match | ✅ Yes, if matched on behavior/path rather than the literal name | ✅ Yes — 7045 fires regardless of which binary got installed | ✅ Yes |
| 5 | Named pipe `psexecsvc` / `PSEXESVC-<host>-<pid>-std*` (Sysmon 17/18) | ❌ **No** — per `04`'s finding, the pipe prefix is read from the (renamed) binary's own filename at runtime | ✅ Yes — pipe creation itself isn't affected by which binary is running, only its name is | ✅ Yes |
| 6 (weakest) | Literal `ServiceName == "PSEXESVC"` or image name `PSEXESVC.exe` match | ❌ **No** — trivially defeated by `-r`, and real incidents (the documented `FRAMEPKG.EXE` case) confirm operators actually do this | ✅ Yes (irrelevant to a custom binary anyway) | ✅ Yes |

**Build hunts on ranks 1–3 first.** The `.key` file is the standout finding of this note: it's the only signal in this table that survives every flag-based evasion PsExec exposes, precisely because it isn't tied to the service/pipe-naming subsystem `-r` controls at all — its one real weakness is a version dependency, not an operator choice. Rank 6 (raw name-string matching) is trivially defeated and documented as defeated in real intrusions — never build a detection around it alone.

## Hunting on Source

```powershell
# 1. EulaAccepted registry value — proves PsExec ran interactively (or via
#    -accepteula) on THIS host, under THIS profile, at least once
Get-ItemProperty 'HKCU:\Software\Sysinternals\PsExec' -Name EulaAccepted -ErrorAction SilentlyContinue
Get-ItemProperty 'HKCU:\Software\Sysinternals' -Name EulaAccepted -ErrorAction SilentlyContinue

# 2. Authenticode signature + PE metadata check on any psexec.exe found on disk —
#    confirms it's the genuine Microsoft binary and surfaces the OriginalFileName
#    field even if the file itself has been renamed locally
Get-ChildItem -Path C:\ -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    $vi = $_.VersionInfo
    if ($vi.OriginalFilename -match 'psexec' -or $vi.ProductName -match 'PsExec') {
      [PSCustomObject]@{ Path=$_.FullName; Signer=$sig.SignerCertificate.Subject; Status=$sig.Status; OriginalFileName=$vi.OriginalFilename }
    }
  }

# 3. Sysmon Process Create for psexec.exe (any name), matching on command-line
#    syntax rather than image name alone
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'OriginalFileName:\s*psexec\.c' -or $_.Message -match '\\\\\*|-accepteula|-nobanner|-s -i|-r \S+' }

# 4. PowerShell console history for the invocation, including any inline -p password
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'psexec'

# 5. Recent outbound SMB sessions consistent with an active or recent PsExec run
Get-NetTCPConnection -RemotePort 445 -State Established -ErrorAction SilentlyContinue
```

## Hunting on Target

```powershell
# 1. STRONGEST — the .key file, present regardless of -r or which service/
#    binary name was used. Directly names the source host in the filename.
Get-ChildItem -Path C:\Windows -Filter "PSEXEC-*.key" -ErrorAction SilentlyContinue |
  Select-Object Name, CreationTime, LastWriteTime

# 2. PE metadata check on the dropped service binary, wherever it landed —
#    catches -r renaming outright
Get-ChildItem -Path 'C:\Windows\System32','C:\Windows' -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $vi = $_.VersionInfo
    if ($vi.OriginalFilename -match 'psexesvc' -or $vi.InternalName -match 'PsExec Service Host') {
      [PSCustomObject]@{ Path=$_.FullName; OriginalFileName=$vi.OriginalFilename; InternalName=$vi.InternalName }
    }
  }

# 3. System 7045 — filter on ImagePath/behavior pattern, not a literal service-name string,
#    so a -r-renamed install still surfaces
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Where-Object { $_.Message -match '\\System32\\\S+\.exe' -or $_.Message -match 'PSEXESVC' }

# 4. Sysmon 11 (File Create) for the .key file AND the dropped binary together —
#    the pairing (two File Create events, milliseconds apart) is itself distinctive
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} |
  Where-Object { $_.Message -match 'PSEXEC-.*\.key' -or $_.Message -match 'PSEXESVC\.exe' }

# 5. Sysmon 17/18 pipe creation — catches a -r-renamed pipe too, since the query
#    matches on the shape (a *-stdin/-stdout/-stderr triple), not the literal PSEXESVC name
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} |
  Where-Object { $_.Message -match '-\w+-\d+-std(in|out|err)$' }

# 6. Security 4624/5140 for the ADMIN$ session and share access itself
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,5140} |
  Where-Object { $_.Message -match 'ADMIN\$' -or $_.Message -match 'Logon Type:\s+3' }
```

## Fleet-Wide Sweep

```powershell
# The realistic scenario this actually matters for: \\* or @file mass execution
# (per 02's fleet-wide use cases). Sweep for the .key file specifically — it's
# the one signal every evasion option in this note's priority table fails to defeat.
$targets = Get-Content .\hosts.txt

$keyFiles = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-ChildItem -Path C:\Windows -Filter "PSEXEC-*.key" -ErrorAction SilentlyContinue |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, Name, CreationTime
} -ErrorAction SilentlyContinue

$keyFiles | Sort-Object CreationTime | Export-Csv -Path .\psexec_key_sweep.csv -NoTypeInformation

# A cluster of .key files across many hosts, all naming the SAME source hostname,
# within a tight time window, is the direct fingerprint of a fleet-wide \\* or
# @file run — group by the embedded source hostname to confirm
$keyFiles | Group-Object { ($_.Name -split '-')[1] } | Sort-Object Count -Descending

# Second pass — 7045 across the estate, filtered on the behavioral ImagePath
# pattern rather than a literal PSEXESVC string, to also catch -r-renamed installs
Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '\\System32\\\S+\.exe' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated, Message
} -ErrorAction SilentlyContinue | Export-Csv -Path .\psexec_7045_sweep.csv -NoTypeInformation
```

**Published detections worth knowing directly (verified live against each source):**

| Source | What it checks |
|---|---|
| Splunk `Detect Renamed PSExec` | `Processes.process_name != psexec.exe AND Processes.process_name != psexec64.exe AND Processes.original_file_name = psexec.c` — a direct PE-metadata-vs-image-name mismatch hunt for the **source-side client**, the exact PsExec analog of the equivalent rclone/renamed-binary detections elsewhere in this module |
| Elastic `Suspicious Process Execution via Renamed PsExec Executable` | `process.pe.original_file_name : "psexesvc.exe" and not process.name : "PSEXESVC.exe"` — the same PE-metadata-mismatch logic applied to the **target-side dropped service binary**; mapped to T1569.002, T1036.003, and T1021.002 |

## Remediation

**Capture evidence first** — pull the `.key` file(s) and their creation timestamps, the Sysmon 1/11/17/18 events, any recoverable dropped binary, and the `EulaAccepted` timestamp on any suspected source host, before killing the service or isolating either machine. Per `04`, the `.key` file is uniquely valuable here because it directly names the source host — capturing it before it's cleaned up (manually or by an interrupted `psexec.exe` retry) may be the only first-party attribution evidence available.

PsExec itself isn't the thing to fix — it's a legitimate, signed Microsoft tool being run with access the operator already obtained. The durable controls target the execution path and the credentials behind it, not the binary:

```powershell
# Disable or restrict ADMIN$ / default administrative shares where genuinely
# not needed for legitimate remote administration — this single control defeats
# PsExec, Impacket's psexec.py/smbexec.py, and every other ADMIN$-dependent
# lateral-movement tool in this module at once, since none of them work without it
# Computer Configuration > Administrative Templates > Network > ... (AutoShareServer/
# AutoShareWks registry values under HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters)

# Restrict local-admin group membership / apply LAPS so a single compromised
# credential can't reach every host PsExec would otherwise touch fleet-wide
# (per 02's \\* and @file use cases) — the actual control that limits blast radius,
# since PsExec's own auth model has no MFA/step-up challenge of any kind

# Enable command-line process-creation auditing if not already present, and
# deploy Sysmon with File Create (11) and Pipe Created/Connected (17/18)
# coverage — per the Hunting Priority table, the .key file and PE-metadata
# checks above depend on this level of visibility existing at all:
# Computer Configuration > Administrative Templates > System > Audit Process
# Creation > "Include command line in process creation events" = Enabled

# Enable "Audit Security System Extension" to get Security 4697 as a second,
# independently-configured signal alongside System 7045 for service installs
```

Restricting `ADMIN$` availability and tightening local-admin group sprawl are the highest-leverage moves here — unlike a detection rule tuned to one specific evasion flag, both controls remove the tool's actual prerequisite (per `01`'s Prerequisites table) rather than reacting to whichever naming convention the operator happened to choose.
