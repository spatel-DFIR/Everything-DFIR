# SharpWMI — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

SharpWMI's three families (per `01`/`04`) each have their own strongest signal, and — unlike `Impacket/wmiexec.py`, whose evasion surface is a handful of flags on one execution path — SharpWMI's evasion surface is really "which action the operator picked." A hunt built only around `WmiPrvSE.exe`-direct-child detection (the standard playbook for `wmiexec.py`/`wmic.exe`) fully covers the `exec` family, partially covers `executevbs` (only via its `scrcons.exe`-mediated grandchild), and says nothing at all about the query/enumeration family. Rank by invariant strength **within** each family:

| Rank | Signal | Applies to | Notes |
|---|---|---|---|
| 1 | `WmiPrvSE.exe` spawning **any** unexpected direct child process | `exec`/`terminate`/`setenv`/`delenv`/`install` (method-call family) | The same primitive that catches `wmiexec.py`/`wmic.exe` — a property of `Win32_Process.Create()` itself, survives binary rename/relocation of the SharpWMI binary since the signal lives entirely on the target side |
| 1 | `WmiPrvSE.exe` spawning **`scrcons.exe`**, with `scrcons.exe` itself then spawning an unexpected child | `executevbs` only | **Does not overlap with rank-1 above** — a hunt keyed strictly on `WmiPrvSE.exe`-direct-child misses this family entirely. This is the single most important addition this tool's coverage makes to the wmiexec/wmic playbook already in this repo |
| 1 | WMI-Activity **5859/5860/5861** (`__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` registration) | `executevbs` only | The strongest, most specific signal for this family — direct registration evidence, not an inferred process-tree pattern. Correlate the registered `Name`/`ScriptText`/`Query` fields against `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`'s baseline-vs-malicious triage guidance before concluding malicious intent, since legitimate management tooling also registers permanent subscriptions |
| 2 | WMI-Activity 5857 (`HostProcess=wmiprvse.exe`) correlated to an external-source Security 4624 | **All actions, all three families** | Broadest-coverage signal in this note — fires for query/enumeration reads, `Win32_Process.Create()` calls, and `executevbs`'s underlying provider load alike — but noisy/high-recall alone, since it fires for ordinary local/remote WMI use too |
| 3 | DCOM/RPC network connection (TCP 135 + dynamic high port, 49152-65535 by default) | Any **remote** action | Never optional for genuine remote use — absent entirely for local-only invocations (`computername` omitted). See `LOLBins/wmic/04 - Target Evidence.md`'s cited KB929851 for the port-range detail this note doesn't re-derive |
| 4 | Command-line/argument-shape hunt (`action=`, `executevbs`, `scriptb64=`, `amsi=disable`) in Sysmon 1 / Security 4688 | Source host only | SharpWMI's fully literal `key=value` syntax (per `03 - Source Evidence.md`) makes this an unusually high-fidelity signal **when captured**, but it only exists on the operator's own launching host — invisible entirely for the in-memory `execute-assembly` delivery model |
| 5 | `result=true` / `upload`'s absence of any output-relay filesystem artifact | `exec`/`upload` | **Not a positive signal** — its value is negative/enrichment only: a host showing WMI-Activity 5857 correlated to a suspicious source IP but **no** `__<timestamp>`-style file (the pattern `wmiexec.py` leaves) doesn't rule out WMI-based execution, it may indicate SharpWMI's `result=true`/`upload` specifically. Don't let the absence of a `wmiexec.py`-shaped file artifact be read as "no WMI execution occurred" |
| 6 (weakest) | Sysmon 13 (Registry Value Set) under `Session Manager\Environment`/`HKCU\Environment` | `setenv`/`delenv` only | Narrow — only fires for the two environment-variable actions, and the registry path itself is legitimately written by many non-malicious processes; only useful correlated tightly against a preceding WMI-Activity 5857/Security 4624 pair |

**Build hunts on rank-1 signals as primary detections for each family — note there are two independent rank-1 signals, not one, and both need coverage. Treat ranks 2-4 as strong corroborators, and ranks 5-6 as enrichment only.**

## Hunting on Source

The operator's own launching host — a standalone `SharpWMI.exe` invocation from a Windows jump box/pivot, since (per `03 - Source Evidence.md`) the in-memory `execute-assembly` delivery model leaves none of this evidence class at all.

```powershell
# PowerShell command history — the ONLY place SharpWMI's fully literal key=value
# command line (including any username=/password=) is recoverable verbatim
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue | Select-String -Pattern 'SharpWMI|action=|executevbs'

# Live process + full command line
Get-CimInstance Win32_Process -Filter "Name='SharpWMI.exe'" | Select-Object ProcessId, ParentProcessId, CommandLine

# Source-side command-line audit trail — captures action=/computername=/command=/
# username=/password= verbatim if command-line auditing or Sysmon is deployed here
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'SharpWMI\.exe' }

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '(?i)Image:.*\\SharpWMI\.exe' }

# Live outbound DCOM/RPC connection to a target — present for ANY remote action
Get-NetTCPConnection -RemotePort 135 -ErrorAction SilentlyContinue
Get-NetTCPConnection | Where-Object { $_.RemotePort -ge 49152 -and $_.RemotePort -le 65535 }

# Prefetch/Amcache/ShimCache corroboration that SharpWMI.exe actually ran on this host
Get-ChildItem "$env:SystemRoot\Prefetch\SHARPWMI.EXE-*.pf" -ErrorAction SilentlyContinue
```

## Hunting on Target

```powershell
# 1. RANK-1 (method-call family): WmiPrvSE.exe spawning an unexpected DIRECT child.
#    Covers exec/terminate/setenv/delenv/install. Does NOT cover executevbs — see #2.
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe' } |
  Select-Object TimeCreated,
    @{n='Parent';e={($_.Message -split "`n" | Select-String 'ParentImage:').ToString()}},
    @{n='Child';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 2. RANK-1 (executevbs family): WmiPrvSE.exe spawning scrcons.exe, then scrcons.exe's
#    OWN children — the extra hop most wmiexec/wmic-tuned hunts will not catch.
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe' -and $_.Message -match 'Image:.*scrcons\.exe' }

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*scrcons\.exe' } |
  Select-Object TimeCreated,
    @{n='Child';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 3. RANK-1 (executevbs family): direct WMI event-subscription registration evidence —
#    the strongest, most specific signal for this family. See Windows/10 - Persistence
#    Mechanisms/WMI Event Consumers.md for baseline-vs-malicious triad triage.
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5859,5860,5861} |
  Select-Object TimeCreated, Id, Message

# 4. RANK-2: WMI-Activity 5857 — fires for ALL SharpWMI actions, correlate against an
#    external-source 4624 to cut noise from routine local/legitimate WMI use
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5857} |
  Where-Object { $_.Message -match 'wmiprvse\.exe' } |
  Select-Object TimeCreated, Message

# 5. Network logons (Type 3) preceding WmiPrvSE.exe/scrcons.exe activity -> correlate source IP
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -eq 3 } |
  Select-Object TimeCreated, @{n='Account';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}

# 6. Live/recent WMI event-subscription triad enumeration — catches an executevbs
#    subscription that hasn't fired yet, or one whose cleanup didn't run (per 01's open question)
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
  Select-Object Name, Query
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer |
  Select-Object Name, ScriptingEngine, ScriptText
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Select-Object Filter, Consumer

# 7. setenv/delenv registry-write trail (rank 6 — narrow, correlate tightly)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} |
  Where-Object { $_.Message -match 'Session Manager\\Environment|HKCU.*\\Environment' }

# 8. Failed-attempt indicators: WMI-Activity client failures + DCOM permission denials
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5858} |
  Select-Object TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName='System'; Id=10016} -ErrorAction SilentlyContinue

# 9. Command-line audit trail (requires 4688 command-line auditing) — WmiPrvSE.exe/
#    scrcons.exe as parent, showing the actual command/payload as a child
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'wmiprvse\.exe|scrcons\.exe' }
```

## Fleet-Wide Sweep

```powershell
# Sweep for BOTH rank-1 signals across an estate at once — a hunt that only checks
# WmiPrvSE.exe-direct-child will silently miss any executevbs activity fleet-wide
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  $execFamily = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe' -and $_.Message -notmatch 'Image:.*scrcons\.exe' }

  $vbsFamily = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe.*scrcons\.exe|ParentImage:.*scrcons\.exe' }

  $triadRegistrations = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5859,5860,5861} -MaxEvents 100 -ErrorAction SilentlyContinue

  [PSCustomObject]@{
    Host                = $env:COMPUTERNAME
    ExecFamilyHits      = ($execFamily | Measure-Object).Count
    ExecVBSFamilyHits   = ($vbsFamily | Measure-Object).Count
    TriadRegistrations  = ($triadRegistrations | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.ExecFamilyHits -gt 0 -or $_.ExecVBSFamilyHits -gt 0 -or $_.TriadRegistrations -gt 0 } |
  Sort-Object TriadRegistrations, ExecFamilyHits -Descending

$results | Export-Csv -Path .\sharpwmi_sweep_results.csv -NoTypeInformation
```

Group by time window (`$results | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') }` against the raw per-host event objects, not the summarized table above) to spot a burst indicating mass lateral movement versus isolated single-host use — same framing as `Impacket/wmiexec/05 - Detection and Hunting.md`'s fleet-wide sweep.

## Network-Layer Hunting

```
# Zeek: DCE/RPC bind + WMI-interface operations, over the RPC endpoint-mapper-negotiated
# dynamic port (49152-65535 by default) — present for EVERY remote SharpWMI action,
# including plain query/loggedon/firewall/ps/getenv reads with no execution at all
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -iE 'IWbem|135'

# Zeek: HTTP(S) fetch for executevbs methods B/C/D's download step
zeek-cut ts id.orig_h id.resp_h host uri < http.log
```

## Remediation

**Capture evidence first** — export the WMI-Activity 5857 (and, for `executevbs`, 5859/5860/5861) records, the Sysmon 1 `WmiPrvSE.exe`/`scrcons.exe` process-tree chain, and (for `executevbs`) the live `__EventFilter`/`ActiveScriptEventConsumer`/`__FilterToConsumerBinding` triad content via `Get-CimInstance -Namespace root\subscription`, before touching anything — remediation destroys the artifacts this note is built around, and per `01`'s open question, deleting a suspected triad forecloses forever confirming whether SharpWMI's own cleanup would have removed it anyway.

```powershell
# Kill any live command process still hanging off WmiPrvSE.exe or scrcons.exe, if caught live
Get-CimInstance Win32_Process -Filter "ParentProcessId = $wmiprvsePid" |
  Where-Object { $_.Name -notin @('WmiPrvSE.exe') } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Remove a confirmed-malicious executevbs subscription triad — sever the binding FIRST,
# same discipline Windows/10 - Persistence Mechanisms/WMI Event Consumers.md documents in full
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
  Where-Object { $_.Filter -match '<confirmed-malicious-filter-name>' } | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='<FilterName>'" | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -Filter "Name='<ConsumerName>'" | Remove-CimInstance
```

Real hardening — beyond evidence capture:

- **Restrict WMI/DCOM remote access** to a management subnet via the built-in "Windows Management Instrumentation (WMI-In)" firewall rule group — identical guidance to `Impacket/wmiexec/05 - Detection and Hunting.md` and `LOLBins/wmic/05 - Detection and Hunting.md`, since all three tools ride the same DCOM/RPC channel.
- **Restrict DCOM launch/activation permissions** (`dcomcnfg.exe` → Component Services → *My Computer* → COM Security) to only the accounts/groups that legitimately need remote WMI access.
- **Enable and centrally collect the WMI-Activity Operational log**, including 5859/5860/5861 specifically — it's not enabled/forwarded by default in many environments, and for `executevbs` it's this tool's single richest signal.
- **Configure Sysmon's WMI-event tracing (Event IDs 19/20/21)** in addition to the default process-creation rules — per `04`, this coverage is not part of Sysmon's default ruleset and needs an explicit config addition to catch `executevbs` triad registration at the endpoint level.
- **Enable command-line process auditing** (Security 4688 with command-line logging) on both source and target hosts — per `03 - Source Evidence.md`, SharpWMI's fully literal `key=value` argument syntax makes a captured command line unusually information-dense once auditing is in place.
- **Baseline legitimate permanent WMI event subscriptions** in the environment (SCCM/MECM, endpoint agents, monitoring tooling) so a `CommandLineEventConsumer`/`ActiveScriptEventConsumer` triad with no matching legitimate product is a high-confidence finding rather than noise — see `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md` for the full baselining methodology.
- **Reduce standing local-admin exposure** (LAPS, tiered administration) — every SharpWMI remote action that writes or executes anything (the method-call and event-subscription families) is gated on the authenticating account already being a local administrator on the target, the same dependency `wmiexec.py`/`wmic.exe` share.
