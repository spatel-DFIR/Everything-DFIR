# LOLBins — wmic.exe — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`wmic.exe`'s abuse surface splits into two families with **different strongest signals each** — see `04 - Target Evidence.md`'s framing note before reading this table. Rank by invariant strength **within** each family, since a rank-1 signal for one family may not exist at all for the other:

| Rank | Signal | Applies to | Survives binary rename/relocation? | Survives local-only (no `/node:`)? | Notes |
|---|---|---|---|---|---|
| 1 | `WmiPrvSE.exe` spawning **any** unexpected child process | Local / ADS / `/node:` remote execution | ✅ Yes — the parent-child relationship is a property of `Win32_Process.Create()`, not of what invoked it | ✅ Yes — present for both local and remote | **Does not apply to the XSL family at all** — no `Create()` call, no child process, ever |
| 1 | `.NET CLR usage-log entry for `wmic.exe` (or a renamed variant) under `CLR_v4.0[_32]\UsageLogs\` | XSL / SquiblyTwo only | ⚠️ **Partially** — the log **filename** is keyed to the hosting process's own image name, so a renamed binary produces a differently-named log file, but the underlying signal ("a normally-non-.NET system utility just loaded the CLR") survives rename intact | ✅ Yes — fires regardless of `/node:` | The single most invariant signal in this note — `wmic.exe`/its renamed equivalent has **zero** legitimate reason to ever load the CLR outside this technique |
| 2 | WMI-Activity Operational 5857 (`HostProcess=wmiprvse.exe`) correlated to source IP/account | **All three** execution paths | ✅ Yes | ✅ Yes | Broadest-coverage signal in this note — fires for local `Create()`, remote `Create()`, and the XSL family's underlying query — but noisy/high-recall alone; always correlate |
| 3 | DCOM/RPC network connection (TCP 135 + dynamic high port, 49152-65535 by default) | `/node:` remote execution only | ✅ Yes | ❌ **No** — doesn't exist for local-only use | The one signal that's never optional for genuine remote lateral movement via this tool |
| 4 | Command-line argument shape (`process call create`, `/format:.*\.xsl`, `/node:`) in Sysmon 1 or Security 4688 | All | ✅ Yes — argument parsing is unaffected by binary rename | ✅ Yes | Requires Sysmon or 4688 command-line auditing deployed; invisible without either |
| 5 | HTTP(S) or SMB egress fetching the `.xsl` stylesheet | XSL only | ✅ Yes | ✅ Yes | **Defeated entirely** by the SMB-sourced variant against a network segment with no SMB-traffic visibility — generates zero web-proxy-visible traffic |
| 6 | Cleartext `/password:` on the source-host command line (4688/Sysmon 1/PSReadLine history) | `/node:` remote with **explicit** credentials only | ✅ Yes | N/A — only exists when explicit creds are used at all; token-based auth never produces this artifact | Source-host-only — see `03 - Source Evidence.md` |
| 7 (weakest) | Bare `wmic.exe` process presence / image path (`System32\wbem\` or `SysWOW64\wbem\`) | All | ❌ **No** — defeated by the renamed/relocated binary variant in `02`'s "Renamed or Relocated Binary" scenario | ✅ Yes | Combine with Authenticode/`OriginalFileName` verification to catch a renamed-but-genuine binary specifically |

**Build hunts on rank 1-2 signals as primary detections for each family; treat ranks 3-6 as strong corroborators, and rank 7 as enrichment only — a renamed binary defeats it on its own.**

## Hunting on Source

The operator's own launch of `wmic.exe` — whether that's a genuinely separate `/node:`-launching machine or the single host a local command ran on. See `03 - Source Evidence.md` for why this is the *only* place the literal command line (including any `/password:`) is recoverable.

```powershell
# PowerShell command history, if wmic.exe was launched from a PS session
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue | Select-String -Pattern 'wmic'

# Live process + full command line — argv is visible to any local process/user
Get-CimInstance Win32_Process -Filter "Name='wmic.exe'" | Select-Object ProcessId, ParentProcessId, CommandLine

# Source-side command-line audit trail — the ONLY place /user://password:/-format:xsl are recoverable verbatim
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'wmic\.exe' }

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)Image:.*\\wmic\.exe' }

# Live outbound DCOM/RPC connection — ONLY present for /node: remote use, absent for local-only
Get-NetTCPConnection -RemotePort 135 -ErrorAction SilentlyContinue
Get-NetTCPConnection | Where-Object { $_.RemotePort -ge 49152 -and $_.RemotePort -le 65535 }

# Live outbound HTTP(S)/SMB connection for the XSL stylesheet fetch — present regardless of /node:
Get-NetTCPConnection -RemotePort 443,80 -ErrorAction SilentlyContinue
Get-SmbConnection -ErrorAction SilentlyContinue

# Prefetch/Amcache/ShimCache corroboration that wmic.exe actually ran on this host
Get-ChildItem "$env:SystemRoot\Prefetch\WMIC.EXE-*.pf" -ErrorAction SilentlyContinue
```

## Hunting on Target

```powershell
# 1. RANK-1 (execution family): WmiPrvSE.exe spawning an unexpected child process.
#    Never fires for the XSL family — see rank-1 (XSL) below for that family's own top signal.
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe' } |
  Select-Object TimeCreated,
    @{n='Parent';e={($_.Message -split "`n" | Select-String 'ParentImage:').ToString()}},
    @{n='Child';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 2. RANK-1 (XSL family): CLR usage-log entry for wmic.exe (or a renamed variant) — a system
#    utility with zero legitimate reason to ever load the CLR just loaded it.
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\CLR_v4.0*\UsageLogs\" -Filter "*.log" -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'wmic' -or $_.Name -notmatch '(?i)\.net|dotnet|powershell|msbuild|visualstudio' }

# 3. WMI-Activity 5857 — fires for ALL three execution paths, correlate against an
#    external-source 4624 (or, for local-only, against source-side wmic.exe process evidence)
#    to cut noise from routine local WMI use
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5857} |
  Where-Object { $_.Message -match 'wmiprvse\.exe' } |
  Select-Object TimeCreated, Message

# 4. Network logons (Type 3) immediately preceding a WmiPrvSE.exe spawn -> correlate source IP.
#    /node: remote execution only — absent for local-only use.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -eq 3 } |
  Select-Object TimeCreated, @{n='Account';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}

# 5. Command-line argument-shape hunt — survives a renamed/relocated binary since it
#    matches on argument shape, not image name
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)process\s+call\s+create|/format:.*\.xsl|/node:' }

# 6. Sysmon 7 (Image Load) for the CLR loading into wmic.exe specifically — near-real-time
#    corroboration of #2, requires a targeted Sysmon config since ID 7 is normally noisy/filtered
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { $_.Message -match '(?i)Image:.*\\wmic\.exe' -and $_.Message -match '(?i)clr\.dll|mscoree\.dll|clrjit\.dll' }

# 7. Failed-attempt indicators: WMI-Activity client failures + DCOM permission denials
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5858} |
  Select-Object TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName='System'; Id=10016} -ErrorAction SilentlyContinue

# 8. Path/location + Authenticode check: a wmic-signed binary running from anywhere
#    other than the two legitimate install paths
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match 'OriginalFileName:\s*WMIC\.EXE' -and
    $_.Message -notmatch 'Image:.*\\(System32|SysWOW64)\\wbem\\wmic\.exe'
  }
```

## Fleet-Wide Sweep

> 🔴 **`wmic.exe` is itself a fleet-remote-execution tool** — the same `/node:` capability an operator abuses for lateral movement can be turned around and used defensively, natively, with no additional tooling required. This is a genuine point of difference from every other tool in this module: `bitsadmin.exe` and `certutil.exe` have no remote-query mode of their own, and `wmiexec.py` isn't installed on most Windows hunting workstations by default. `wmic.exe`'s `/node:` switch works as well for a defender pulling data from many hosts as it does for an attacker pushing commands to them.

**Modern approach — `Invoke-Command`/CIM over WinRM, matching this module's other fleet sweeps:**

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  $wmiprvseChildren = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe' }

  $clrLogHits = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\CLR_v4.0*\UsageLogs\" -Filter "*.log" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'wmic' }

  [PSCustomObject]@{
    Host              = $env:COMPUTERNAME
    WmiPrvSEChildren  = ($wmiprvseChildren | Measure-Object).Count
    CLRUsageLogHits   = ($clrLogHits | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.WmiPrvSEChildren -gt 0 -or $_.CLRUsageLogHits -gt 0 } |
  Sort-Object WmiPrvSEChildren -Descending

$results | Export-Csv -Path .\wmic_sweep_results.csv -NoTypeInformation
```

**Native `wmic.exe`-as-hunting-tool approach — the tool's own `/node:` fleet capability, turned defensively:**

```cmd
:: Query live WmiPrvSE.exe child processes across an entire target list at once —
:: the defender's use of the exact same mechanism the attacker abused
wmic /node:@hosts.txt /failfast:on process where "ParentProcessId=(select ProcessId from win32_process where name='WmiPrvSE.exe')" get ProcessId,Name,CommandLine

:: Pull the last N WMI-Activity Operational log entries across the same target list —
:: requires the querying account to have admin rights on every target, same
:: prerequisite the attacker's own /node: use depends on
wmic /node:@hosts.txt /failfast:on process where "name='wmic.exe'" get ProcessId,CommandLine,CreationDate
```

`/failfast:on` (per `01 - Overview.md`'s switches table) skips unreachable hosts rather than hanging the sweep — worth setting explicitly for any fleet-wide use against a target list that may include offline machines.

## Network-Layer Hunting

```
# Zeek: DCE/RPC bind + operations against the WMI interface, over the RPC
# endpoint-mapper-negotiated dynamic port (49152-65535 by default) — /node: remote use only
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -iE 'IWbem|135'

# Zeek: the .xsl stylesheet fetch over HTTP(S) — XSL/URL variant only, no wmic-specific
# User-Agent confirmed, correlate on requested filename/timing instead
zeek-cut ts id.orig_h id.resp_h host uri < http.log | grep -iE '\.xsl'

# Zeek: the .xsl stylesheet fetch over SMB — XSL/SMB variant, generates zero HTTP(S)
# traffic and is invisible to a web-proxy-only network hunt
zeek-cut ts id.orig_h id.resp_h name path < smb_files.log | grep -iE '\.xsl'
```

## Remediation

**Capture evidence first** — export the WMI-Activity 5857 records, the Sysmon 1 `WmiPrvSE.exe` parent-child chain (execution family) or the `wmic.exe.log` CLR usage-log entry (XSL family), and the source-host 4688/Sysmon 1 command line, before touching anything.

```powershell
# Kill any live command process still hanging off WmiPrvSE.exe, if caught live (execution family)
Get-CimInstance Win32_Process -Filter "ParentProcessId = $wmiprvsePid" |
  Where-Object { $_.Name -notin @('WmiPrvSE.exe') } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Kill a live wmic.exe process itself, if caught mid-XSL-execution
Get-Process -Name wmic -ErrorAction SilentlyContinue | Stop-Process -Force
```

Real hardening — beyond evidence capture:

- **Consider removing the WMIC Feature-on-Demand entirely** on hosts with no legitimate need for the interactive CLI — a hardening lever unique to this tool in the module, since `wmic.exe` is a genuinely removable, deprecated first-party component (per `01 - Overview.md`'s deprecation-timeline finding), unlike `wmiexec.py`, which isn't a Windows component at all. `Get-WindowsCapability -Online -Name "WMIC*"` (verified in `01`) followed by `Remove-WindowsCapability -Online -Name <name-returned-above>` removes it where policy allows — confirm no legitimate local dependency on the CLI first, since WMI itself (and PowerShell's WMI cmdlets) remain unaffected either way.
- **Restrict WMI/DCOM remote access** to a management subnet via the built-in "Windows Management Instrumentation (WMI-In)" firewall rule group, rather than leaving it open host-wide — identical guidance to [`Impacket/wmiexec/05 - Detection and Hunting.md`](<../../Impacket/wmiexec/05 - Detection and Hunting.md>), since both tools ride the same DCOM/RPC channel.
- **Restrict DCOM launch/activation permissions** (`dcomcnfg.exe` → Component Services → *My Computer* → COM Security) to only the accounts/groups that legitimately need remote WMI access.
- **Enable and centrally collect the WMI-Activity Operational log** — it's this note's broadest-coverage signal (rank 2) and isn't enabled/forwarded by default in many environments.
- **Enable command-line process auditing** (Security 4688 with command-line logging) on both source and target hosts — per `03 - Source Evidence.md`, the source host's own audit trail is the *only* place the literal command line (including credentials) is recoverable.
- **Constrain `.xsl`-formatted `wmic.exe` invocations via AppLocker/WDAC rules targeting the `/format:` argument shape**, since the XSL family is specifically designed to defeat binary-identity-based allowlisting — a rule keyed only on `wmic.exe`'s signed status does nothing against this technique.
- **Reduce standing local-admin exposure** (LAPS, tiered administration) — `Win32_Process.Create()` against a `/node:` target requires the authenticating account to already be a local administrator there, the same gating requirement `wmiexec.py`/`psexec.py` depend on; shrinking that population shrinks the set of hosts any one recovered credential can reach.
