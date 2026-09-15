# Impacket — secretsdump.py — Detection and Hunting

## Contents
- [Hunting Priority — Split by Extraction Path](#hunting-priority--split-by-extraction-path)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target — Path 1 (Remote Registry)](#hunting-on-target--path-1-remote-registry)
- [Hunting on Target — Path 2 (DRSUAPI / DCSync)](#hunting-on-target--path-2-drsuapi--dcsync)
- [Hunting on Target — Path 2 (VSS / WMI-Shadow Fallback)](#hunting-on-target--path-2-vss--wmi-shadow-fallback)
- [Path 3 (Offline/Local) — Not Huntable at the secretsdump.py Layer](#path-3-offlinelocal--not-huntable-at-the-secretsdumppy-layer)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Split by Extraction Path

Unlike a single-technique tool where one priority table covers everything, `secretsdump.py`'s three paths need **three separate rankings** — a hunt tuned for Path 2/DRSUAPI tells you nothing about a Path 1/Remote-Registry run against the same domain.

**Path 1 — Remote Registry (SAM/LSA/cache):**

| Rank | Signal | Notes |
|---|---|---|
| 1 (strongest) | Sysmon 11 — File Create matching `%SystemRoot%\Temp\[A-Za-z]{8}\.tmp` immediately after `svcctl`/`winreg` pipe activity | Kernel-level, generated unconditionally if Sysmon is deployed with default file-create tuning covering `%SystemRoot%\Temp\` |
| 2 | Zeek `dce_rpc.log` — `winreg`/`svcctl` operation sequence (service status check/start, `BaseRegSaveKey`) from a non-administrative-tooling source | Audit-policy-independent, network-layer |
| 3 | System 7036 for `RemoteRegistry` from a host that doesn't normally run remote-registry-dependent management tooling | Generated on **legitimate** Remote Registry usage too (GPO tools, some backup/inventory software) — enrichment, not a standalone alert |
| 4 (weakest) | Security 5145 for the specific `.tmp` filename in `ADMIN$` | Requires object-access auditing enabled; the filename itself is random and uninformative without the surrounding sequence |

**Path 2 — DRSUAPI (DCSync-equivalent):** identical to `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md`'s priority table — network-layer `drsuapi`/`IDL_DRSGetNCChanges` traffic first, MDI alert 2006 second, Event 4662 (with its non-default audit-policy/SACL prerequisites) third. **Not re-ranked here** — see that file directly.

**Path 2 — VSS/WMI-shadow fallback:**

| Rank | Signal | Notes |
|---|---|---|
| 1 (strongest) | Sysmon 1 — `vssadmin.exe` process creation with `list shadows`/`create shadow` arguments, on a Domain Controller | A DC almost never legitimately runs interactive `vssadmin` commands outside a scheduled backup job — correlate against known backup-job schedules to suppress that one legitimate case |
| 2 | `ntds.dit` appearing anywhere outside `%SystemRoot%\NTDS\` (Sysmon 11 / filesystem sweep) | Strong positional anomaly regardless of how it got there |
| 3 | WMI-Activity operational log — `Win32_ShadowCopy` method invocation | **Only** signal that survives `-use-remoteSSWMI`'s evasion of the `vssadmin.exe` process-creation signal above |
| 4 (weakest) | Security Event 8222 | Fires for legitimate VSS activity across the environment broadly; low signal-to-noise alone |

**Path 3 — Offline/Local:** no ranking possible — see the dedicated section below.

## Hunting on Source

```bash
# Shell history — the target and mode flags reveal operator intent
grep -iE "secretsdump|just-dc|use-vss|use-remoteSSWMI|use-keylist" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process check
ps aux | grep -i secretsdump

# Confirm impacket install + version (flag surface varies by release — see 03)
pip3 show impacket 2>/dev/null

# Local loot files — the single most direct evidence this tool ran and what it recovered
find / -iname "*.sam" -o -iname "*.secrets" -o -iname "*.cached" -o -iname "*.ntds*" 2>/dev/null

# Live network state — TCP 445 (Path 1/VSS fallback) or 135+dynamic (Path 2 DRSUAPI default)
ss -tnp | grep -E ':445|:135|:4[0-9]{4}|:5[0-9]{4}|:6[0-4][0-9]{3}'

# auditd execve record — survives a shell-history wipe
ausearch -x secretsdump.py 2>/dev/null
```

## Hunting on Target — Path 1 (Remote Registry)

```powershell
# 1. HIGHEST-CONFIDENCE: temp hive-copy file creation in %SystemRoot%\Temp\
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} |
  Where-Object { $_.Message -match 'TargetFilename.*\\Windows\\Temp\\[A-Za-z]{8}\.tmp' }

# 2. RemoteRegistry service start events, correlated against Security 4624 (Type 3) in the
#    same short window from the same source — a start immediately following a network logon
#    is the pattern to chase, not RemoteRegistry starts in isolation
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} |
  Where-Object { $_.Message -match 'Remote Registry' }

# 3. ADMIN$ file-read events matching the same random 8-letter .tmp naming (requires 5145 auditing)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} |
  Where-Object { $_.Message -match '\\Temp\\[A-Za-z]{8}\.tmp' }

# 4. Orphaned temp hive-copy files that survived a failed cleanup (interrupted transfer, EDR block)
Get-ChildItem "$env:SystemRoot\Temp\*.tmp" -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^[A-Za-z]{8}\.tmp$' }
```

## Hunting on Target — Path 2 (DRSUAPI / DCSync)

**Cross-link, don't duplicate:** the full hunt set for this path — network-layer `dce_rpc.log` review, the Event 4662 query (with its exclusion list for DC computer accounts/SYSTEM/Azure AD Connect sync accounts), the MDI alert 2006 check, and the volumetric single-object-vs-full-domain enrichment — is documented in `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md`'s "Hunting on Target" section. Run those exact queries; they detect a `secretsdump.py -just-dc` run identically to a Mimikatz `lsadump::dcsync` run, since both are the same RPC call.

**secretsdump.py-specific delta:**

```powershell
# Multi-session resume pattern — a -resumefile-driven pull shows 4662 hits from the SAME
# SubjectUserSid across MULTIPLE, possibly widely time-separated sessions rather than one
# contiguous burst. Group by day/hour to spot this shape distinctly from a single-sitting pull.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} |
  Where-Object { $_.Message -match '1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2' } |
  Group-Object { ($_.Message -split "`r`n" | Where-Object {$_ -match 'Account Name:'})[0] },
               { $_.TimeCreated.ToString('yyyy-MM-dd') } |
  Sort-Object Count -Descending
```

## Hunting on Target — Path 2 (VSS / WMI-Shadow Fallback)

```powershell
# 1. vssadmin.exe process creation on a Domain Controller — should be rare outside
#    scheduled backup jobs; correlate against your backup schedule to suppress that case
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'vssadmin\.exe' -and $_.Message -match 'list shadows|create shadow' }

# 2. ntds.dit appearing outside its normal location — strong positional anomaly
Get-ChildItem "$env:SystemRoot\Temp\*.tmp" -ErrorAction SilentlyContinue

# 3. WMI-Activity log — catches -use-remoteSSWMI, which evades hunt #1 entirely
Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' |
  Where-Object { $_.Message -match 'Win32_ShadowCopy' }

# 4. Stale/orphaned shadow copies — if secretsdump.py reused an existing shadow rather than
#    creating (and later deleting) its own, nothing gets torn down
vssadmin list shadows
```

## Path 3 (Offline/Local) — Not Huntable at the secretsdump.py Layer

> 🔴 **Say this plainly rather than padding it:** there is no hunt query, event ID, or network signature that detects `secretsdump.py LOCAL`/`-sam`/`-security`/`-system`/`-ntds` execution on the original target host, because the tool never touches that host at all (`04 - Target Evidence.md`). **Any detection effort for this scenario has to target the exfiltration step that produced the hive/`ntds.dit` copies in the first place** — `vssadmin`/Sysmon 1 hunts for a local shadow-copy-and-copy sequence, `ntdsutil.exe ifm` process-creation monitoring, file-integrity monitoring on `%SystemRoot%\NTDS\ntds.dit` and the `SYSTEM`/`SAM`/`SECURITY` hive files themselves, or DLP/egress monitoring on however those files subsequently left the environment. Treat "we can't detect secretsdump.py here" as the correct, accurate conclusion for this path — not a gap to explain away.

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

# Path 1 sweep — orphaned temp hive-copy files and recent RemoteRegistry starts, fleet-wide
$path1Results = Invoke-Command -ComputerName $targets -ScriptBlock {
  $tmpFiles = Get-ChildItem "$env:SystemRoot\Temp\*.tmp" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^[A-Za-z]{8}\.tmp$' }
  $svcStarts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Remote Registry' }
  [PSCustomObject]@{
    Host = $env:COMPUTERNAME
    OrphanedTmpFiles = ($tmpFiles | Measure-Object).Count
    RecentRemoteRegistryStarts = ($svcStarts | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

# Path 2 (DRSUAPI) sweep — run against every DC using the query from
# Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md's Fleet-Wide Sweep, unmodified

# Path 2 (VSS fallback) sweep — vssadmin process creation across every DC specifically
$domainControllers = (Get-ADDomainController -Filter *).HostName
$vssResults = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'vssadmin\.exe' }
} -ErrorAction SilentlyContinue

$path1Results | Where-Object { $_.OrphanedTmpFiles -gt 0 -or $_.RecentRemoteRegistryStarts -gt 0 } |
  Export-Csv -Path .\secretsdump_path1_sweep.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — for Path 1/VSS-fallback, export any surviving temp files and the surrounding event sequence before cleanup; for Path 2/DRSUAPI, the guidance in `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md`'s Remediation section applies without modification, since the compromise (every credential replicated) is already complete the moment the RPC call finishes.

```powershell
# Path 1 — remove any orphaned temp hive-copy files, restore RemoteRegistry to its prior
# start-type if it was found disabled and left enabled
Get-ChildItem "$env:SystemRoot\Temp\*.tmp" -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^[A-Za-z]{8}\.tmp$' } | Remove-Item -Force

# Path 2/VSS fallback — remove any orphaned shadow copies
vssadmin list shadows
# vssadmin delete shadows /shadow="{<id>}" /Quiet   -- after confirming it's not a legitimate backup snapshot
```

**Close the underlying exposure, not just this incident:**
- For **Path 1**: local-admin credential compromise is the root enabler — the fix is credential hygiene (unique local admin passwords via LAPS, not credential-dumping-specific hardening), since Remote Registry itself is a legitimate, often-needed management feature.
- For **Path 2/DRSUAPI**: identical to `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md`'s remediation — audit and minimize the population holding `DS-Replication-Get-Changes-All`, enable the Directory Service Access audit policy + SACL, deploy Microsoft Defender for Identity, network-segment DCs, and rotate `krbtgt` twice if a full-domain pull cannot be ruled out.
- For **Path 2/VSS fallback**: this path only works with code-exec-equivalent access on the DC already established — the real root cause is whatever got the operator that access in the first place, not the VSS mechanism itself.
- For **Path 3**: prevention lives entirely upstream, at whatever control should have stopped the hive/`ntds.dit` exfiltration in the first place (backup-access controls, VSC-creation monitoring, disk-image/media handling policy) — there is no secretsdump.py-specific control to add here.
