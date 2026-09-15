# LOLBins — sc.exe — Detection and Hunting

`sc.exe` exposes several genuinely distinct evasion angles — the `create`-vs-`config` event-logging gap, service-DACL hiding via `sdset`, binary renaming, and the total absence of any credential material on the command line itself — so no single hunting signal covers every case. This file ranks signals by which of those evasion options they survive, **before** giving the hunt commands themselves, per this module's Writing Style Guide. Hunting on Source targets the artifacts in `03 - Source Evidence.md`; Hunting on Target targets `04 - Target Evidence.md`.

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked strongest (survives the most evasion variants) to weakest.

| Rank | Signal | Survives | Defeated by |
|---|---|---|---|
| 1 | **Direct registry enumeration of `HKLM\SYSTEM\CurrentControlSet\Services\*`** (raw key walk, not `sc query`/`Get-Service`) | The `sdset`-hiding technique — per SANS's own testing, the deny-ACE pattern blocks the **SCM enumeration API**, not the registry key's own (typically admin-permissive) ACL; a direct registry read sees the service regardless. Also survives the `create`-vs-`config` event gap entirely (it's reading current state, not an event), a renamed `sc.exe` binary, and no-Sysmon/no-audit-policy hosts | Outright deletion of the `Services\<Name>` key itself — a far more aggressive, far more detectable cleanup step than a DACL tweak |
| 2 | **Network-layer MS-SCMR RPC operation decode** (Zeek `dce_rpc.log` or equivalent) | Renamed/relocated `sc.exe` binary (the RPC call is what's logged, not the calling process's filename), the `sdset`-hiding technique (the security descriptor governs the SCM API, not whether the RPC call itself gets logged on the wire), and the `create`-vs-`config` gap (`ChangeServiceConfigW` is just as visible on the wire as `CreateServiceW`) | No full-packet-capture/Zeek coverage of the segment; SMB3 transport encryption blinding a passive decoder that lacks the session keys |
| 3 | **System 7045** (new service installed) | Renamed `sc.exe` binary (SCM logs regardless of what created the service), and works identically whether an operator scripted it, used PsExec, or used any other SCM client | The **`config`-path entirely** — per `01 - Overview.md`'s red-flag callout, this event is install-only and never fires for a `binPath` hijack of an existing service; also defeated by log clearing/rollover |
| 4 | **Sysmon 1 / Security 4688 command line for `sc.exe`'s own invocation** | Captures the full `binpath=`/`sdset` argument text when present — the only signal in this table that shows *what the operator actually typed*, including a hidden service's target SDDL | No Sysmon/no command-line-auditing deployment; a renamed binary defeats `Image`-keyed rules specifically (though `OriginalFileName`/hash-based rules still catch it); and for the **remote-target use case, this only ever appears on the source host** — `sc.exe` never runs on the target it points at |
| 5 | **System 7040** (start type changed) | The general `config`-path visibility gap for events that *do* fire | Only fires when `start=` itself changes — a pure `binpath=` swap with no start-type change produces **no signal here at all**, the specific gap this note's red-flag callout centers on |
| 6 | **Security 4697** (service installed, audited) | Ties the install directly to an authenticated account (`SubjectUserSid`), richer than 7045 alone | Requires the non-default **"Audit Security System Extension"** subcategory — absence proves nothing about whether it's enabled, only that this specific signal isn't available; and, like 7045, is `create`-path only |
| 7 | **Behavioral differential test** (`Set-Service -Status Stopped`/`sc query` on a *guessed* service name returns "Access is denied" instead of "service does not exist") | Confirms presence of a specific `sdset`-hidden service once its name is already suspected | Useless without a candidate name to test — doesn't help discover an unknown hidden service, only confirm or deny one already suspected |

## Hunting on Source

Targets `03 - Source Evidence.md`'s artifact set — most relevant to the remote-creation/lateral-movement use cases, and to recovering *how* an operator authenticated, since `sc.exe`'s own command line never will.

```powershell
# sc.exe command lines — Sysmon 1, if present. Captures binpath=/sdset/obj= arguments in full
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)\bsc(\.exe)?\b' -and $_.Message -match '(?i)(create|config|sdset|failure|\\\\)' } |
  Select-Object TimeCreated, @{N='CommandLine';E={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# Same via Security 4688 (requires command-line auditing enabled)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match '(?i)\\sc\.exe' }

# The session-establishment step that actually carries credential material —
# explicit-credential logons (4648) around the same time window as any sc.exe activity above
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648} |
  Select-Object TimeCreated, @{N='TargetServer';E={$_.Properties[5].Value}}, @{N='Account';E={$_.Properties[1].Value}}

# Live/recent SMB session state to a remote target — proves an IPC$/ADMIN$/C$ session
# sc.exe's own command line will never show
Get-SmbConnection | Where-Object { $_.ShareName -in @('IPC$','ADMIN$','C$') }

# PSReadLine console history — sc.exe's syntax is awkward enough that operators often
# script it, but interactive use still lands here
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Pattern 'sc\s+(\\\\|create|config|sdset|failure)' -SimpleMatch:$false

# Renamed-binary check — walk running/recent processes for sc.exe's Authenticode identity under a different name
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.ExecutablePath -ErrorAction SilentlyContinue
    if ($sig.SignerCertificate.Subject -match 'Microsoft Windows' -and $_.Name -ne 'sc.exe' -and $_.ExecutablePath -match '(?i)sc(\.exe)?$') {
        [PSCustomObject]@{ PID = $_.ProcessId; Path = $_.ExecutablePath; Name = $_.Name; Signer = $sig.SignerCertificate.Subject }
    }
}
```

## Hunting on Target

Targets `04 - Target Evidence.md`'s artifact set. Leads with the raw registry walk from Hunting Priority row 1, since it's the only signal that survives both the `sdset`-hiding technique and the `create`-vs-`config` logging gap simultaneously — **do not rely on `sc query`, `Get-Service`, or 7045/4697 alone.**

```powershell
# Row 1: raw registry enumeration — catches sdset-hidden services that Get-Service/sc query silently omit,
# and surfaces every service's current ImagePath regardless of whether its install/config ever generated an event
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
    $svc = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($svc.ImagePath -match '\\(Temp|AppData|ProgramData|Users|Public)\\' -or $svc.ImagePath -match ':\w+\.\w+') {
        [PSCustomObject]@{ Name = $_.PSChildName; ImagePath = $svc.ImagePath; Start = $svc.Start; ObjectName = $svc.ObjectName }
    }
}

# Cross-check: services visible in the raw registry walk but NOT enumerable via Get-Service —
# the concrete signature of an sdset-hidden service
$liveNames = (Get-Service).Name
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | Where-Object {
    (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ObjectName -and $_.PSChildName -notin $liveNames
} | Select-Object PSChildName

# Behavioral differential test (Hunting Priority row 7) — run only against a specific suspected name;
# "Access is denied" indicates a present-but-DACL-hidden service, "does not exist" indicates it's genuinely absent
try { Get-Service -Name 'SysHelperSvc' -ErrorAction Stop } catch { $_.Exception.Message }

# Row 3/6: 7045 and 4697 — the create-path signals, sorted newest-first
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 100 |
    Sort-Object TimeCreated -Descending |
    Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}}, @{N='Account';E={$_.Properties[4].Value}}
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} -ErrorAction SilentlyContinue -MaxEvents 100

# Row 5: 7040 — start-type changes only, the partial config-path signal
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7040} -MaxEvents 100 |
    Sort-Object TimeCreated -Descending

# Sysmon 13 registry-set for Services\<Name>\ImagePath or \Security — only useful if a custom
# include rule was deployed (not stock/default), but the single best config-path catch when present
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '(?i)CurrentControlSet\\Services\\.*\\(ImagePath|Security)' }

# Target-side Sysmon 1: the spawned payload, parented by services.exe or a svchost.exe -k <group> instance
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*(services\.exe|svchost\.exe)' -and $_.Message -notmatch 'ParentCommandLine:.*-k (DcomLaunch|netsvcs|LocalService|rpcss)\b' }

# Baseline diff against a known-good service inventory to catch a hijacked ImagePath on an
# otherwise long-standing, previously-trusted service — the config-path's own strongest hunting angle
Get-CimInstance Win32_Service | Select-Object Name, PathName, StartName |
    Export-Csv "C:\hunt\services_current_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
# Compare-Object against a prior export from the same host to surface any changed PathName/StartName
```

## Fleet-Wide Sweep

For the remote-creation/fleet-wide use case in `02 - Hands-On Use Cases.md`, the strongest signal is the **same service name or `binPath` pattern appearing across many hosts in a tight creation window** — a single unfamiliar service rarely stands out against the dozens of legitimate ones on any one host, but an identical service landing on 40 hosts inside a five-minute window does.

```powershell
$computers = Get-Content C:\hunt\hosts.txt

# Pull every non-standard service's ImagePath/StartName across the fleet in one pass, via the raw
# registry walk (Hunting Priority row 1) rather than Get-Service, to catch sdset-hidden instances too
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
        $svc = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($svc.ImagePath) {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME; ServiceName = $_.PSChildName
                ImagePath = $svc.ImagePath; Start = $svc.Start; ObjectName = $svc.ObjectName
            }
        }
    }
} | Export-Csv C:\hunt\sc_fleet_sweep.csv -NoTypeInformation

# Group by ImagePath across the fleet — an identical, non-Microsoft binPath appearing on many hosts
# at once is the fleet-wide tell
Import-Csv C:\hunt\sc_fleet_sweep.csv | Group-Object ImagePath | Where-Object Count -gt 3 | Sort-Object Count -Descending

# System 7045 across the fleet, tight recent window — faster at scale than the registry walk above,
# and pinpoints creation timing precisely (create-path only, per the Hunting Priority caveat)
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -LogName System -FilterXPath '*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= 3600000]]]' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, Message
} | Group-Object { ($_.Message -split "`n")[0] } | Where-Object Count -gt 3 | Sort-Object Count -Descending
```

## Remediation

🔴 **Capture evidence before disabling or deleting.** `sc delete` removes the registry subkey this entire evidence chain depends on, and — per `04 - Target Evidence.md` — leaves no dedicated "service deleted" event behind it. Export first.

```powershell
# Export full current config and the raw security descriptor before touching anything
Get-CimInstance Win32_Service -Filter "Name='SysHelperSvc'" | Export-Clixml 'C:\hunt\SysHelperSvc_config_before.xml'
reg export "HKLM\SYSTEM\CurrentControlSet\Services\SysHelperSvc" 'C:\hunt\SysHelperSvc_before.reg'
sc.exe sdshow SysHelperSvc | Out-File 'C:\hunt\SysHelperSvc_sddl_before.txt'

# Export the relevant event-log windows before any retention rollover
wevtutil epl System 'C:\hunt\system_relevant.evtx'
wevtutil epl Security 'C:\hunt\security_relevant.evtx'

# Disable rather than delete while the investigation is open — preserves the service and its history.
# For an sdset-hidden service, restore a normal SDDL first so standard tools can even see it to disable it
sc.exe sdset SysHelperSvc "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
Stop-Service -Name 'SysHelperSvc' -Force
Set-Service -Name 'SysHelperSvc' -StartupType Disabled

# For a config-path hijack of a legitimate, still-needed service (e.g. wuauserv), restore the
# original ImagePath/start type from the pre-incident baseline export rather than deleting the service outright
sc.exe config wuauserv binpath= "C:\Windows\System32\svchost.exe -k netsvcs -p" start= auto

# Full removal — only after every export above is complete, and only for services that were
# entirely attacker-created (never for a hijacked legitimate service, which should be restored instead)
sc.exe delete SysHelperSvc
```

For the remote-creation use case, also investigate and rotate the account behind whatever session backed the `\\target` call — per `01 - Overview.md`'s red-flag callout, a successful remote `sc create`/`config` demonstrates the operator already held local-admin-equivalent rights on that target, which is itself the higher-priority finding relative to any single service artifact. Cross-reference the 4648/4624 chain on both hosts (see `03`/`04`) to identify exactly which credential was used, since it is very unlikely to have been typed on the `sc.exe` command line itself.
