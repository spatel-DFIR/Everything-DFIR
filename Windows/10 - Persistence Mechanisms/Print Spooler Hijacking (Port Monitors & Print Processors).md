# Print Spooler Hijacking (Port Monitors & Print Processors)

The Windows Print Spooler (`spoolsv.exe`) is a SYSTEM-level service that has been running on essentially every Windows install since Windows 2000, and it loads several categories of vendor- and OS-supplied DLLs into its own process at startup and on-demand as part of normal printing functionality — port monitors (how a print job reaches its physical or logical destination) and print processors (how a print job's data is formatted before spooling). Both categories are registered in the registry, both are extensible by design so third-party printer drivers can plug into the spooler, and both get loaded automatically, with no user interaction, every time the Print Spooler service starts.

That extensibility is exactly what makes them attractive persistence primitives: registering a malicious DLL as either a port monitor or a print processor gets it loaded into a SYSTEM process, automatically, on every service (re)start — no scheduled task, no service entry of its own, no unusual process name. This note covers both mechanisms together because they are structurally the same technique (a DLL-hijack of the same host process, `spoolsv.exe`) reached via two different registry locations, and because an analyst hunting one should routinely check the other.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing spooler-based DLL hijacking against Run keys, Services, Scheduled Tasks, and WMI Event Consumers.

> 🔴 **A registered port monitor or print processor is only as suspicious as its `Driver` DLL's location and signature.** Every Windows install carries a small, well-known set of legitimate entries — `Local Port`, `Standard TCP/IP Port`, `WSD Port` for monitors; `winprint` and a handful of vendor processors for print processors. The finding is never "an entry exists," it's "this `Driver` value points at a DLL outside `System32`, or at one that is unsigned, or at a name that doesn't match anything a legitimate printer driver package would register."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Port Monitors — Registry Structure](#port-monitors--registry-structure)
- [Print Processors — Registry Structure](#print-processors--registry-structure)
- [Why the Print Spooler Is a High-Value Target](#why-the-print-spooler-is-a-high-value-target)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to Print Spooler Hijacking](#red-flags-specific-to-print-spooler-hijacking)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native registry-only triage against both spooler-extensibility points in one pass — neither has a dedicated PowerShell module, so these read `HKLM` directly and cross-check each `Driver` DLL's location and signature.

```powershell
# Every registered port monitor with its Driver DLL and whether that DLL lives under System32
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object {
    $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver
    [PSCustomObject]@{ Monitor = $_.PSChildName; Driver = $d; UnderSystem32 = $d -match '^[Ss]ystem32\\' -or $d -match '\\Windows\\System32\\' }
}

# Every registered print processor across all print Environments (usually just 'Windows x64') with the same System32 check
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments' | ForEach-Object {
    $envName = $_.PSChildName
    $ppPath = "$($_.PSPath)\Print Processors"
    if (Test-Path $ppPath) {
        Get-ChildItem $ppPath | ForEach-Object {
            $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver
            [PSCustomObject]@{ Environment = $envName; Processor = $_.PSChildName; Driver = $d }
        }
    }
}

# Port monitor or print processor Driver DLLs that fail Authenticode signature validation - the primary triage filter
$monitors = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object {
    $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver
    if ($d) { [PSCustomObject]@{ Type = 'Monitor'; Name = $_.PSChildName; DllPath = "C:\Windows\System32\$d" } }
}
$monitors | ForEach-Object {
    if (Test-Path $_.DllPath) {
        $sig = Get-AuthenticodeSignature $_.DllPath
        if ($sig.Status -ne 'Valid') { [PSCustomObject]@{ Name = $_.Name; DllPath = $_.DllPath; SignatureStatus = $sig.Status } }
    }
}

# Names outside the well-known legitimate baseline for port monitors - a small, stable list on any given host
$knownMonitors = @('Local Port', 'Standard TCP/IP Port', 'WSD Port', 'PDF Port Monitor', 'USB Monitor', 'Hpmon6', 'AppleTalk Printing Devices')
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' |
    Where-Object { $_.PSChildName -notin $knownMonitors } |
    Select-Object PSChildName

# spoolsv.exe currently running with any loaded module outside System32/WinSxS - live-process corroboration of a planted DLL
Get-Process spoolsv -ErrorAction SilentlyContinue | ForEach-Object {
    $_.Modules | Where-Object { $_.FileName -notmatch '\\(System32|WinSxS)\\' } | Select-Object ModuleName, FileName
}

# Registered monitor/processor entries with no corresponding printer driver package installed - orphaned or planted registrations
Get-WmiObject Win32_PrinterDriver -ErrorAction SilentlyContinue | Select-Object Name, DriverPath
```

## Port Monitors — Registry Structure

Port monitors define *how* a print job reaches its destination — a physical LPT/USB port, a network TCP/IP address, a PDF virtual printer, and so on. They register under:

```
HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName>
```

| Value | Meaning | Forensic relevance |
|---|---|---|
| `Driver` | The filename (resolved relative to `%SystemRoot%\System32`) of the DLL the Print Spooler service loads for this monitor | 🔴 The value that matters — legitimate monitor DLLs live directly in `System32`; anything with a path traversal, a fully-qualified path outside `System32`, or a name that doesn't match a known monitor is the tell |

A default Windows install carries a small, stable set of legitimate monitor names — `Local Port`, `Standard TCP/IP Port`, `WSD Port`, and occasionally a PDF or virtual-printer vendor's own monitor if that software is installed. This short, well-known baseline is precisely what makes outlier-hunting effective here: unlike Run keys or services, where dozens of legitimate third-party entries are routine, an unrecognized port monitor name is unusual enough on its own to warrant a look, before even checking the `Driver` DLL's signature.

Registering a new port monitor requires the `AddMonitor` Win32 API, which itself requires administrative privilege — this is a real barrier, not a bypassable check, so a newly planted monitor implies the attacker already had local admin or SYSTEM at the time of registration. What it buys them in return is durable, SYSTEM-context code execution that survives independent of any user session and re-loads automatically every time the spooler service restarts (which happens on every reboot, and can also be triggered on demand by restarting the `Spooler` service).

### PowerShell

Enumerate every registered port monitor and resolve its `Driver` value to a full path for signature checking, since the registry stores only the filename relative to `System32`:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object {
    $driver = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver
    [PSCustomObject]@{ Monitor = $_.PSChildName; Driver = $driver; FullPath = "C:\Windows\System32\$driver" }
}
```

Check the Authenticode status of each resolved DLL, since Microsoft- and hardware-vendor-supplied monitor DLLs are signed:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object {
    $driver = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver
    $path = "C:\Windows\System32\$driver"
    if (Test-Path $path) { Get-AuthenticodeSignature $path | Select-Object Path, Status }
}
```

## Print Processors — Registry Structure

Print processors define *how* a print job's data gets formatted once it reaches the spooler, and are registered per print environment (the architecture-specific grouping, typically just `Windows x64` on a modern 64-bit host, though `Windows x86` and legacy environments can also appear):

```
HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\<Environment>\Print Processors\<ProcessorName>
```

| Value | Meaning | Forensic relevance |
|---|---|---|
| `Driver` | The filename of the DLL the Print Spooler service loads for this processor, resolved relative to the print-processor directory under `System32\spool\prtprocs\<environment>` | Same logic as port monitors — a legitimate processor DLL lives in the expected `prtprocs` subdirectory; anything elsewhere is the tell |

The default, legitimate processor on virtually every Windows install is `winprint`. Vendor print-driver packages occasionally register their own processor alongside it. As with port monitors, the baseline population here is small and stable, which is what makes an unrecognized processor name — rather than requiring deep DLL analysis — a fast first-pass filter.

Registration mechanics mirror port monitors: adding a print processor requires the `AddPrintProcessor` API and, in practice, administrative privilege to write the relevant registry key, so this is again a post-privilege-escalation persistence technique rather than an initial-access one.

### PowerShell

Enumerate print processors across every registered environment, since a host can carry more than one environment key even though only one (matching the host's own architecture) is normally active:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments' | ForEach-Object {
    $envName = $_.PSChildName
    $ppKey = "$($_.PSPath)\Print Processors"
    if (Test-Path $ppKey) {
        Get-ChildItem $ppKey | ForEach-Object {
            Get-ItemProperty $_.PSPath | Select-Object @{N='Environment';E={$envName}}, PSChildName, Driver
        }
    }
}
```

Resolve each processor's `Driver` to its expected on-disk location and confirm the file actually exists there — a registry entry with no matching file on disk is itself worth investigating (remnant of a removed tool, or evidence the DLL was deleted post-execution):

```powershell
$env = 'Windows x64'
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments\$env\Print Processors" | ForEach-Object {
    $driver = (Get-ItemProperty $_.PSPath).Driver
    $path = "C:\Windows\System32\spool\prtprocs\$($env -replace ' ','')\$driver"
    [PSCustomObject]@{ Processor = $_.PSChildName; Driver = $driver; ExpectedPath = $path; Exists = Test-Path $path }
}
```

## Why the Print Spooler Is a High-Value Target

Both techniques in this note exist because the Print Spooler service has been a consistently attractive attack surface for reasons independent of persistence alone: it runs as SYSTEM by default, it has historically accepted remote RPC connections for driver installation and management (the interface abused in the PrintNightmare vulnerability chain — CVE-2021-1675 and the distinct CVE-2021-34527 — which allowed authenticated remote users to trigger SYSTEM-level remote code execution via `RpcAddPrinterDriverEx`), and it has a long history of additional privilege-escalation and RCE vulnerabilities beyond PrintNightmare specifically. That history is context, not the technique itself — port monitor and print processor registration are a *local*, registry-based persistence mechanism distinct from the network-facing RPC vulnerabilities, but both trace back to the same underlying fact: `spoolsv.exe` is a SYSTEM-privileged, broadly-present, historically under-scrutinized service, which is exactly the profile that makes any of its extensibility points worth an attacker's attention and an analyst's routine check.

## Event Log Evidence

Neither port monitors nor print processors have a dedicated, always-on event ID the way scheduled tasks (106) or services (7045) do. Evidence is split between generic registry auditing and the spooler's own operational log.

| Source | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4657 | Registry value modified | 🔴 Requires **non-default auditing** with a SACL set on the `Monitors`/`Print Processors` keys specifically — not enabled by default on any standard build |
| `Microsoft-Windows-PrintService/Operational` | 300-series (varies by build) | Print Spooler service and driver-related operational events | Enabled by default on modern Windows for general print-service activity, though it is not consistently populated for monitor/processor *registration* specifically — treat as corroborating context (spooler restarts, driver install activity) rather than a direct "monitor registered" signal |
| System log | 7036 | Print Spooler service started/stopped | Confirms *when* the spooler last (re)started — useful for bounding when a newly-registered monitor/processor DLL would first have been loaded |
| System log | 7045 (unrelated to this technique directly) | New service installed | Not triggered by monitor/processor registration itself, but worth checking in case an attacker also dropped a supporting service as part of the same operation |

Given the thin native logging coverage, this note leans on the registry-state hunt (unrecognized monitor/processor names, unsigned or out-of-place `Driver` DLLs) as the primary detection method, corroborated by Prefetch/Amcache/ShimCache for the DLL itself and by live-process module enumeration against `spoolsv.exe`.

### PowerShell

Correlate the spooler's last start time against each registered monitor/processor DLL's own file creation time — a DLL created significantly *before* the spooler's most recent start, with no plausible legitimate reason, is less likely to be a fresh plant, while one created just before an unexplained spooler restart is worth closer attention:

```powershell
$spoolerStart = (Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} -MaxEvents 20 |
    Where-Object { $_.Message -match 'Print Spooler' -and $_.Message -match 'running' } |
    Select-Object -First 1).TimeCreated

Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' | ForEach-Object {
    $driver = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver
    $path = "C:\Windows\System32\$driver"
    if (Test-Path $path) {
        $created = (Get-Item $path).CreationTime
        [PSCustomObject]@{ Monitor = $_.PSChildName; DllCreated = $created; SpoolerLastStart = $spoolerStart }
    }
}
```

## Red Flags Specific to Print Spooler Hijacking

- **Monitor or processor name outside the small, well-known legitimate baseline.** Because the legitimate population is genuinely tiny (`Local Port`, `Standard TCP/IP Port`, `WSD Port` for monitors; `winprint` and rare vendor processors for print processors), an unrecognized name is a stronger signal here, faster, than the equivalent check for services or Run keys where dozens of legitimate third-party entries are routine.
- **`Driver` value resolving outside `System32` (monitors) or the expected `prtprocs\<environment>` subdirectory (processors).** Legitimate registrations always resolve into these standard locations; a path traversal or a value that resolves elsewhere is the direct equivalent of an out-of-place service `ImagePath`.
- **`Driver` DLL that is unsigned or fails Authenticode validation.** Every legitimate Microsoft- or hardware-vendor-supplied monitor/processor DLL is signed — an unsigned DLL loaded into a SYSTEM process via this path has no legitimate excuse.
- **A registry entry for a monitor or processor with no matching printer driver package installed on the host (`Win32_PrinterDriver` enumeration comes up empty for that name).** Legitimate monitors and processors are almost always installed alongside a corresponding printer driver package — a registration with no accompanying driver package is a mismatch worth explaining.
- **`spoolsv.exe`'s live module list includes a DLL not resolvable to a registered monitor, processor, or driver at all.** If the loaded-module enumeration shows something the registry doesn't account for, that's either a different (unregistered/injected) loading mechanism entirely or evidence the registry has since been cleaned up post-execution.
- **A recent, otherwise-unexplained Print Spooler service restart (System 7036) shortly followed by new network or process activity from `spoolsv.exe`.** Since newly registered monitors/processors only take effect on the next spooler start, a deliberate restart shortly after a registry write is a natural pairing worth checking for.

## Tooling

| Tool | Use |
|---|---|
| **`reg query`** | Live enumeration of `Print\Monitors` and `Print\Environments\<Environment>\Print Processors` — neither mechanism has a dedicated PowerShell module, so direct registry access (interactively or via `Get-ItemProperty`) is the primary native tool |
| **Autoruns** (Sysinternals) | Its "Print Monitors" tab covers registered port monitors directly (with code-signing and VirusTotal cross-reference); print processors are not broken out as their own dedicated Autoruns category on all versions, so cross-check those manually against the registry path above |
| **Process Explorer** (Sysinternals) | Live inspection of `spoolsv.exe`'s loaded DLL list — useful for the live-process corroboration step in the Hunt Evil block above |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `SYSTEM\CurrentControlSet\Control\Print\Monitors` and `...\Environments\<Environment>\Print Processors` when working from an acquired `SYSTEM` hive — see Registry Forensics Fundamentals (note 04) |
| `sigcheck` (Sysinternals) | Bulk signature verification of every DLL under `System32\spool\prtprocs` and the resolved monitor DLL paths, faster than one-at-a-time `Get-AuthenticodeSignature` calls across a large driver population |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Monitor/processor name outside the small, well-known legitimate baseline | Unusual on its own given how tiny the legitimate population normally is |
| `Driver` value resolving outside `System32` (monitors) or `prtprocs\<environment>` (processors) | Equivalent of an out-of-place service `ImagePath` — legitimate registrations always resolve into these standard locations |
| `Driver` DLL unsigned or fails Authenticode validation | Legitimate spooler-loaded DLLs are signed by Microsoft or the hardware vendor |
| Registration with no matching installed printer driver package | Legitimate monitors/processors are normally installed alongside a corresponding driver package |
| `spoolsv.exe` live module list includes an unregistered DLL | Either a different loading mechanism entirely, or registry cleanup occurred after the DLL was already loaded |
| Unexplained Print Spooler service restart shortly after a registry write to `Monitors`/`Print Processors` | Newly registered entries only take effect on next spooler start — a deliberate restart is the natural next step for an attacker activating a freshly planted DLL |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline `SYSTEM` hive access mechanics | Registry Forensics Fundamentals (note 04) |
| Service-based persistence and how `svchost`-hosted service-DLL abuse compares structurally to this technique | Services |
| Other DLL-search-order and DLL-hijack persistence with no service/task footprint of its own | DLL Hijacking |
| First/last-seen evidence and hash identity of a planted monitor/processor DLL | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual loading/execution of a planted DLL via the spooler process | Prefetch.md (note 06) |

## Resources

- MITRE ATT&CK T1547.010 (Boot or Logon Autostart Execution: Port Monitors) — https://attack.mitre.org/techniques/T1547/010/
- MITRE ATT&CK T1547.012 (Boot or Logon Autostart Execution: Print Processors) — https://attack.mitre.org/techniques/T1547/012/
- Microsoft, Print Spooler API documentation (`AddMonitor`, `AddPrintProcessor`) — https://learn.microsoft.com/windows/win32/printdocs/print-spooler-api
- PrintNightmare, CVE-2021-1675 / CVE-2021-34527 — https://en.wikipedia.org/wiki/PrintNightmare
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Sysinternals Process Explorer, sigcheck — https://learn.microsoft.com/sysinternals/downloads/
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- Atomic Red Team, T1547.010 / T1547.012 — https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.010/T1547.010.md , https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.012/T1547.012.md
