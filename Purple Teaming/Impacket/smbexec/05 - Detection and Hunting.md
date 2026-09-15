# Impacket — smbexec.py — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`smbexec.py`'s evasion surface is narrower than `psexec.py`'s (no binary to swap, no output-suppression flags like `wmiexec.py`'s `-silentcommand`) — its only meaningful blend-in knobs are `-service-name`, `-share`, `-mode`, and `-shell-type`. None of them change the underlying **structure** of the technique: a batch-file/`echo`/redirect command line, embedded as a service `ImagePath`, repeated once per typed command. Rank hunts by **invariant strength**, strongest first:

| Rank | Signal | Survives `-service-name`? | Survives `-share`? | Survives `-mode SERVER`? | Survives `-shell-type powershell`? |
|---|---|---|---|---|---|
| 1 (strongest) | The `echo ... ^> ... 2^>^&1 > ...\.bat & ... & del ...\.bat` command-line **template** in Sysmon 1 / Security 4688 | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes — same template, only the echoed payload changes |
| 2 | System 7045 **burst**: many events, one identical `ServiceName`, tight time window | ✅ Yes — burst pattern holds even with a custom name | ✅ Yes | ✅ Yes | ✅ Yes |
| 3 | `services.exe → cmd.exe → cmd.exe` three-hop process lineage before the operator's real command | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| 4 | Session-level ratio anomaly: **one** Security 4624 correlated against **many** System 7045 from the same source | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| 5 | Output-relay file naming pattern (`__output_<8-random-letters>`) | ✅ Yes (name itself isn't configurable) | Location only changes | ✅ Yes — and in `SERVER` mode it's **abandoned**, not transient, making it *more* durable there, not less |
| 6 (weakest) | `\PIPE\svcctl` pipe observation alone | N/A | N/A | N/A | N/A — **not distinctive on its own**, since legitimate remote service management uses the same pipe; only useful correlated with rank 1-4 signals |

**Build hunts on ranks 1-3 as your primary detections; treat ranks 4-5 as high-confidence enrichment; never hunt on rank 6 alone.**

## Hunting on Source

```bash
# Shell history for any smbexec/impacket invocation (credentials may be exposed in the match)
grep -iE "smbexec|impacket" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process check — argv is visible to any local user via /proc, not just root
ps aux | grep -i smbexec

# Confirm impacket install + locate the script and its version on disk
pip3 show impacket 2>/dev/null
find / -iname "smbexec.py" 2>/dev/null

# Live SMB connection to a target on 445 (or 139 if -port was used) —
# the ONE persistent connection carrying both SVCCTL and share I/O
ss -tnp | grep -E ':445|:139'

# -mode SERVER specific: a locally bound listening socket requires root/sudo
ss -tlnp | grep :445
grep -i smbexec /var/log/auth.log 2>/dev/null
journalctl _COMM=sudo 2>/dev/null | grep -i smbexec

# If auditd is enabled, pull the execve record even after the process has exited
ausearch -x smbexec.py 2>/dev/null

# .pyc bytecode-cache mtimes can bound "first run on this box" even after history -c
find / -path "*/impacket/*" -name "*.pyc" -newer /etc/hostname 2>/dev/null
```

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE: the batch/echo/redirect command-line template in Sysmon 1,
#    surviving every evasion flag this tool exposes. Also recovers the operator's
#    literal typed command directly from the echo clause.
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)echo .* \^> .*\.bat\b.*&.*del .*\.bat' } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='ParentImage';e={($_.Message -split "`n" | Select-String 'ParentImage:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 2. Service-installation BURST detector — group 7045 events by ServiceName and flag
#    any name appearing 2+ times within a short window, since a legitimate installer
#    never creates/destroys the same service key in a loop like this
$svc7045 = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045}
$svc7045 | Group-Object { $_.Properties[0].Value } |
  Where-Object { $_.Count -ge 2 } |
  ForEach-Object {
    $times = $_.Group.TimeCreated | Sort-Object
    if ((($times[-1]) - ($times[0])).TotalMinutes -le 15) {
      [PSCustomObject]@{ ServiceName = $_.Name; Count = $_.Count; First = $times[0]; Last = $times[-1] }
    }
  }

# 3. Session-level ratio anomaly: correlate ONE Security 4624 (Type 3) against
#    MANY System 7045 events from the same time window/source — a normal admin
#    session doesn't look like this
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -eq 3 } |
  Select-Object TimeCreated, @{n='Account';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}

# 4. Process lineage: services.exe -> cmd.exe -> cmd.exe (the nested batch-file hop)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*\\services\.exe' -and $_.Message -match 'Image:.*\\cmd\.exe' }

# 5. Output-relay filename pattern — transient in SHARE mode, ABANDONED (worth
#    checking first) in SERVER mode
Get-ChildItem C:\, C:\Windows\* -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^__output_[A-Za-z]{8}$' }

# 6. Orphaned .bat files — a command that hit the SCM start-timeout can leave
#    the batch file behind since 'del' never gets reached
Get-ChildItem C:\Windows\*.bat -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^[A-Za-z]{8}\.bat$' }

# 7. -mode SERVER specific: outbound SMB connection FROM this host TO an
#    external IP on port 445 — the copy-back clause, an unusual direction
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object { $_.Message -match 'DestinationPort: 445' -and $_.Message -notmatch 'Initiated: false' }

# 8. Enrichment only — do NOT hunt on this alone (see priority table, rank 6)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} |
  Where-Object { $_.Message -match '\\PIPE\\svcctl' }
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — the fleet-level
# signal for smbexec is many hosts EACH showing their own internal 7045 burst
# within a tight overall window, not any single event in isolation
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Group-Object { $_.Properties[0].Value } |
    Where-Object { $_.Count -ge 2 } |
    ForEach-Object {
      [PSCustomObject]@{
        Host = $env:COMPUTERNAME
        ServiceName = $_.Name
        Count = $_.Count
        First = ($_.Group.TimeCreated | Sort-Object | Select-Object -First 1)
        Last  = ($_.Group.TimeCreated | Sort-Object | Select-Object -Last 1)
      }
    }
} -ErrorAction SilentlyContinue

# Group by time window to spot a burst (ransomware-style push) vs. isolated single-host use
$results | Group-Object { $_.First.ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10 Count, Name

$results | Export-Csv -Path .\smbexec_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

For environments with a network sensor (Zeek, Suricata, etc.) — valuable in segments without endpoint logging, or as an independent corroborating source:

```
# Zeek: repeated CreateServiceW/StartServiceW/DeleteService triplets against
# svcctl in a tight window — the REPETITION COUNT is the tell, not any single
# occurrence (a legitimate remote-service operation is a one-off)
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -i svcctl

# Zeek: repeated write/read/delete (SHARE) or write-only (SERVER) cycles
# against the SAME output filename
zeek-cut ts id.orig_h id.resp_h path < smb_mapping.log | grep -iE '__output_'
```

## Remediation

**Capture evidence first** — export the full 7045 burst and the Sysmon 1 command-line records before touching anything; because the operator's literal commands are embedded in those command lines, this export **is** the command-history evidence for the whole session, not just a supporting artifact.

```powershell
# Stop/remove the service if caught live (name recovered from the 7045 burst)
$svc = "<ServiceNameFrom7045Burst>"
Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
sc.exe delete $svc

# Remove any orphaned .bat file
Remove-Item "C:\Windows\<RANDOM8>.bat" -Force -ErrorAction SilentlyContinue

# Remove the output-relay file — check this even on hosts where you don't expect
# an active session, since -mode SERVER leaves this behind indefinitely
Remove-Item "C:\__output_<RANDOM8>" -Force -ErrorAction SilentlyContinue
```

Real hardening — beyond evidence capture:

- **Enable Security 4697 auditing** ("Audit Security System Extension") and centrally collect it alongside System 7045 — by default only 7045 is enabled, and the burst pattern is far easier to alert on with both sources correlated.
- **Enable command-line process auditing** (Security 4688 with command-line logging) — this tool's single richest recovery path, since the operator's literal command sits in the `echo` clause of a fully-logged command line.
- **Restrict remote SCM access** where feasible — the same `SC_MANAGER_CREATE_SERVICE` right this tool depends on is also the lever to shrink its blast radius; consider tiered administration so routine helpdesk/monitoring accounts don't carry it broadly.
- **Reduce standing local-admin exposure** (LAPS, tiered administration) — `smbexec.py`, like `psexec.py`/`wmiexec.py`, is entirely gated on the authenticating account already being a local administrator on the target.
- **Alert on service-creation velocity, not just presence** — a single 7045 event is often legitimate (software installers, patch management); a burst of 2+ sharing one `ServiceName` within minutes is not a pattern legitimate tooling produces, and is the single highest-value custom detection rule this tool's mechanics justify.
