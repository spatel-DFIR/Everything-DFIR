# LOLBins — WinRAR — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

Unlike `../certutil/` or `../msbuild/`, WinRAR has **no side-effect artifact that survives independent of process-creation logging** — there's no `CryptnetUrlCache`-style disk write, and no unique download-URL cache. Every meaningful signal here depends on either command-line visibility or behavioral correlation with a separate network transfer. Rank hunts by what survives which operator choice:

| Rank | Signal | Survives `-hp` (header encryption)? | Survives binary rename/relocation? | Survives no command-line auditing/Sysmon at all? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | Command-line **argument shape** (`a`/`m` + `-p`/`-hp` + `-r`/`-v` against a non-standard source path) in Sysmon 1 or 4688 | ✅ Yes — capturing the command line doesn't require decrypting anything | ✅ Yes — argument parsing is unaffected by the binary's name/path | ❌ No — this is the one signal that's entirely dependent on that logging existing | The **only** chance to ever recover the password itself; if this isn't captured live, it's very likely gone for good (see `01`'s red-flag callout) |
| 2 | Behavioral correlation: a WinRAR process-create followed within minutes by a large outbound network transfer from the same host | ✅ Yes — doesn't depend on the archive's own encryption state | ✅ Yes | ⚠️ Partial — still visible via NetFlow/proxy volume spikes even with zero endpoint telemetry, but loses the "what was archived" half of the picture | The best fallback when command-line logging isn't available |
| 3 | Source-path anomaly — the archived path is a freshly-populated, non-standard staging directory (`C:\Windows\Temp`, `C:\Users\Public`, `C:\ProgramData`) rather than a normal user/project folder | ✅ Yes | ✅ Yes | ❌ No — requires the command line to see the source path at all | Strong context, but only visible alongside rank-1 |
| 4 | Registry MRU (`ArcHistory`/`DialogEditHistory`) | ✅ Yes (the MRU key itself isn't encrypted, only the archive contents are) | ✅ Yes | N/A — registry-based, independent of process logging | **Only populated by GUI-dialog-driven use** — largely absent for the `Rar.exe`-console pattern this note's use cases favor; treat its *absence* as expected, not suspicious, and its *presence* as evidence of interactive rather than scripted/C2-driven use |
| 5 (weakest) | Bare `Rar.exe`/`WinRAR.exe` process-creation frequency/presence | N/A | ❌ No | ❌ No | High false-positive rate on any estate where WinRAR is legitimately installed. Never hunt on this alone |

**Build hunts on ranks 1-2 as primary detections. Rank 1 is the only place the password itself is ever recoverable — prioritize deploying the logging that makes it visible (see Remediation) over any post-hoc analysis technique.**

## Hunting on Source

Source-side hunting for this tool means pivoting through the infrastructure/tasking layer described in `03 - Source Evidence.md`, not an "operator machine" in the usual sense of this module:

```
# If attacker-controlled destination infrastructure is ever recovered: check upload
# logs/timestamps for archive volumes matching the naming pattern seen target-side
# (out.part1.rar, out.part2.rar, ...)
grep -E "\.part[0-9]+\.rar|\.rar$" access.log

# If C2 server task history is available (red-team retrospective, or recovered
# attacker infrastructure): search issued-command history for the archive verbs,
# which may still carry the plaintext password used
grep -iE "(rar|winrar)\.exe.*(a|m)\s.*-(h?p|v[0-9])" c2_task_history.log
```

See this module's `Sliver/`, `PowerShell Empire/`, and other C2-framework folders for how each framework's own task-history logging is structured, rather than re-deriving it here.

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE, MAY CAPTURE THE PASSWORD ITSELF: command-line argument
#    shape in Sysmon — the "a"/"m" command plus -p/-hp and a non-standard source path
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match '(?i)\b(Rar|WinRAR)\.exe\b' -and
    $_.Message -match '(?i)\s(a|m)\s.*-(h?p\S*|v\d+)'
  } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='OriginalFileName';e={($_.Message -split "`n" | Select-String 'OriginalFileName:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 2. Same argument-shape hunt against native Security 4688, if Sysmon isn't deployed
#    but command-line auditing IS enabled
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match '(?i)\b(Rar|WinRAR)\.exe\b.*\s(a|m)\s.*-(h?p\S*|v\d+)' }

# 3. Source-path anomaly: WinRAR command lines whose target argument sits under a
#    non-standard staging path
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match '(?i)\b(Rar|WinRAR)\.exe\b' -and
    $_.Message -match '(?i)(Windows\\Temp|Users\\Public|ProgramData)'
  }

# 4. Registry MRU check — evidence of interactive GUI use specifically (see the
#    caveat in 04 - Target Evidence.md: this will be empty for CLI-driven use)
Get-ItemProperty -Path 'HKCU:\Software\WinRAR\ArcHistory' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKCU:\Software\WinRAR\DialogEditHistory\ArcName' -ErrorAction SilentlyContinue

# 5. Path/location check: a WinRAR-signed binary (by OriginalFileName/Authenticode)
#    running from anywhere other than the default vendor install path
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match 'OriginalFileName:\s*(Rar\.exe|WinRAR\.exe)' -and
    $_.Message -notmatch 'Image:.*\\Program Files( \(x86\))?\\WinRAR\\'
  }

# 6. Corroboration only — do NOT hunt on this alone (rank 5, weakest)
Get-Process -Name Rar,WinRAR -ErrorAction SilentlyContinue
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — the fleet-level
# signal is many hosts each independently generating the same WinRAR argument
# shape (and often the same password) within a tight overall window
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  $sysmonHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Message -match '(?i)\b(Rar|WinRAR)\.exe\b' -and
      $_.Message -match '(?i)\s(a|m)\s.*-(h?p\S*|v\d+)'
    }

  [PSCustomObject]@{
    Host           = $env:COMPUTERNAME
    HitCount       = ($sysmonHits | Measure-Object).Count
    LatestHit      = ($sysmonHits | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    ArcHistoryRows = (Get-ItemProperty -Path 'HKCU:\Software\WinRAR\ArcHistory' -ErrorAction SilentlyContinue).PSObject.Properties.Count
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.HitCount -gt 0 } | Sort-Object LatestHit -Descending

$results | Export-Csv -Path .\winrar_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

Since WinRAR itself produces no network traffic, this is really a hunt for the **follow-on exfil channel**, time-correlated against the WinRAR process-create timestamp already found above:

```
# Zeek/NetFlow: outbound transfer volume spikes shortly after a known WinRAR
# process-create timestamp on the same host — cross-reference rather than
# search on network data alone
zeek-cut ts id.orig_h id.resp_h duration orig_bytes resp_bytes < conn.log |
  awk '$5 > 50000000'   # adjust threshold to the archive size(s) already observed target-side

# Proxy logs: filenames matching the .part1.rar / .part2.rar naming convention,
# or any .rar/.exe (if -sfx was used) upload shortly after the archive-creation event
grep -E "\.part[0-9]+\.rar|\.rar($|\?)" proxy_access.log
```

## Remediation

**Capture evidence first** — export the Sysmon 1/Security 4688 command-line record (it may be the only surviving copy of the archive password), a copy of the archive itself if still present, and any correlated network-transfer logs before removing anything.

```powershell
# Kill the process if caught live
Get-Process -Name Rar,WinRAR -ErrorAction SilentlyContinue | Stop-Process -Force

# Quarantine the archive itself — path recovered from the Sysmon 1 CommandLine field
Move-Item "<RecoveredArchivePath>" "C:\Quarantine\" -Force -ErrorAction SilentlyContinue

# If the password was captured (Sysmon/4688/C2 task history), attempt extraction
# under controlled conditions to confirm exactly what was staged/exfiltrated —
# do this on an isolated analysis system, never on the live host
```

Address the underlying intrusion — whatever gained the code execution that ran WinRAR in the first place, and whatever exfil channel picked the archive up next — using that access vector's own dedicated tool folder in this module or the relevant `Windows/Threat Landscape and Playbooks/` playbook; this section covers only the archiving/staging step itself.

Real hardening — beyond evidence capture:

- **Enable command-line process auditing** (Security 4688 with command-line logging, or deploy Sysmon) — without it, rank-1 in the priority table above is entirely invisible, and the archive password is very likely unrecoverable by any other means.
- **Alert on source-path anomalies, not the binary name** — per the priority table, a `Rar.exe`/`WinRAR.exe` invocation against `C:\Windows\Temp`, `C:\Users\Public`, or `C:\ProgramData` as the source path is a materially stronger signal than the process name alone, since the binary itself is legitimate on most estates.
- **Correlate archive-creation events with outbound network-transfer volume** — this is the one hunt that survives every operator-side evasion documented in this note (`-hp`, renamed binary, no command-line logging at all), since it depends only on NetFlow/proxy-level visibility.
- **Constrain WinRAR via AppLocker/WDAC on hosts with no legitimate need for it** — many server/DC-tier and non-power-user endpoints have no genuine business reason to run an archiver at all; a default-deny or alert-on-execution policy meaningfully shrinks this technique's usable footprint on those hosts specifically.
- **Egress data-loss-prevention/size-threshold monitoring** — since `-v` splitting exists specifically to dodge size-threshold alerting (T1030), a DLP/egress control that aggregates multiple same-destination transfers within a short window (rather than evaluating each part in isolation) closes that particular evasion.
