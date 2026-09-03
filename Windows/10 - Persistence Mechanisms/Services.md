# Services

Windows services are programs the Service Control Manager (`services.exe`) starts on its own schedule — at boot, on demand, or in response to a trigger — completely independent of any user logging in. That independence from a logon session is precisely why services are such a durable persistence mechanism: unlike a Run key (fires only at logon) or a Scheduled Task (fires on whatever trigger was configured), a service configured to auto-start runs before any user ever touches the keyboard, as SYSTEM by default, and looks — at a glance — exactly like the hundreds of other legitimate services Windows and third-party software register on every machine.

Services also do double duty this note has to cover: they are simultaneously a **persistence** mechanism (survive reboot, blend into a large legitimate population) and the classic **remote-execution** mechanism attackers use to move laterally (`sc \\host create` + `sc \\host start`, and the tools built on top of that primitive, chiefly PsExec). This note covers both angles from the persistence/host-evidence side; full lateral-movement depth — source/destination pairing, session/credential flow, the rest of the remote-execution toolkit (WMI, PowerShell Remoting, scheduled tasks) — belongs in Lateral Movement (note 12) and is only summarized here.

This is the second note in the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing Services against Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **A service is only as suspicious as its `ImagePath`, `ObjectName`, and install context.** Hundreds of legitimate services exist on any given host. The finding is never "a service exists," it's "this service points at an unexpected binary, runs as an account it has no business running as, or was installed moments before other evidence of attacker activity."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Services as Persistence — Registry Structure](#services-as-persistence--registry-structure)
- [Service DLL Abuse (svchost-Hosted)](#service-dll-abuse-svchost-hosted)
- [Remote Service Creation for Lateral Movement](#remote-service-creation-for-lateral-movement)
- [PsExec Special Case](#psexec-special-case)
- [Red Flags Specific to Services](#red-flags-specific-to-services)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against the live service population — no third-party tool required. `Get-Service` alone doesn't expose `ImagePath`/`StartName`; `Get-CimInstance Win32_Service` and direct registry reads do, and are the workhorses below.

```powershell
# Every service with the three values this note keys on - ImagePath, StartMode, and the account it runs as
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, StartName, State | Sort-Object Name

# ImagePath pointing into Temp/AppData/ProgramData/a user profile - the drop-and-persist pattern
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '\\(Temp|AppData|ProgramData|Users)\\' } | Select-Object Name, PathName, StartName

# No Description string AND an unsigned binary - either alone is a mild signal, both together is worth a look
Get-CimInstance Win32_Service | Where-Object State -eq 'Running' | ForEach-Object {
    if ($_.PathName -match '^"?([^"]+\.exe)"?') {
        $sig = Get-AuthenticodeSignature $Matches[1] -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($_.Description) -and $sig.Status -ne 'Valid') {
            [PSCustomObject]@{ Name = $_.Name; PathName = $_.PathName; SignatureStatus = $sig.Status }
        }
    }
}

# svchost-hosted services whose ServiceDll doesn't live under the normal System32 path - the tell that never shows up in the process list
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
    $svc = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($svc.ImagePath -match 'svchost\.exe') {
        $dll = (Get-ItemProperty "$($_.PSPath)\Parameters" -ErrorAction SilentlyContinue).ServiceDll
        if ($dll -and $dll -notmatch '^C:\\Windows\\System32\\') { [PSCustomObject]@{ Service = $_.PSChildName; ServiceDll = $dll } }
    }
}

# 7045 (new service installed) sorted newest-first - the primary, default-enabled detection signal for this whole note
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 |
    Sort-Object TimeCreated -Descending |
    Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}}, @{N='Account';E={$_.Properties[4].Value}}

# SYSTEM/LocalService services whose ImagePath falls outside Windows/Program Files - privilege-escalation shape
Get-CimInstance Win32_Service | Where-Object { $_.StartName -in @('LocalSystem','NT AUTHORITY\LocalService') -and $_.PathName -notmatch '^"?[A-Za-z]:\\(Windows|Program Files)' } |
    Select-Object Name, StartName, PathName

# Cross-host baseline diff - service names present on one host but not the other, the classic outlier-hunting sweep
Compare-Object (Get-CimInstance Win32_Service -ComputerName HostA | Select-Object -ExpandProperty Name) `
                (Get-CimInstance Win32_Service -ComputerName HostB | Select-Object -ExpandProperty Name)
```

## Services as Persistence — Registry Structure

Every service on the host — legitimate and malicious — has a subkey under `SYSTEM\CurrentControlSet\Services\<ServiceName>`. See Registry Forensics Fundamentals (note 04) for how `CurrentControlSet` resolves to a literal `ControlSetNNN` on an offline hive — the same resolution gotcha applies here.

| Value | Meaning | Forensic relevance |
|---|---|---|
| `ImagePath` | Full path to the executable (own-process service) or the host executable (`svchost.exe -k <group>`) that the SCM launches | The single most important value — where does this service actually point? A path outside `Program Files`/`Windows`/`System32` is the top red flag (see below) |
| `Start` | When the service starts | `0x00` = Boot driver (loaded by the boot loader itself) · `0x01` = System driver (loaded during kernel init) · `0x02` = Auto-start — **the classic persistence configuration**, runs at every boot with zero user interaction · `0x03` = Manual/Demand-start (only runs when explicitly started) · `0x04` = Disabled |
| `Type` | Own-process EXE vs shared-process service DLL | `0x10` = own-process (`SERVICE_WIN32_OWN_PROCESS`) — a standalone executable · `0x20` = shared-process (`SERVICE_WIN32_SHARE_PROCESS`) — hosted inside a generic `svchost.exe -k <group>` process; see Service DLL Abuse below and Windows OS Fundamentals & Versions (note 01) for what a *normal* `svchost.exe` process tree looks like · `0x01`/`0x02` = kernel/file-system driver types |
| `ObjectName` | The account context the service runs as | `LocalSystem`, `NetworkService`, `LocalService`, or a specific domain/local account. Flag any suspicious service running as `LocalSystem` or a highly-privileged domain account when the service's stated function doesn't plausibly need that level of access |
| `DisplayName` / `Description` | Human-readable name and description shown in `services.msc` | Legitimate Microsoft services almost always populate `Description`; its absence, or a generic/short `DisplayName`, is a mild but real signal — see Red Flags below |

🔴 **`Start = 0x02` (Auto-start) is the value to key on when hunting.** It is the direct registry equivalent of a Run key — Windows runs the target unconditionally at every boot, before any user logs on, with no scheduling logic to reason about. A suspicious service is far more concerning when it's Auto-start than when it's Manual (Manual only runs if something explicitly starts it — worth asking *what*, but it's not self-sustaining persistence on its own).

### PowerShell

List services using the cmdlet to get status and start type, though this gives limited detail:

```powershell
Get-Service | Select-Object Name, DisplayName, Status, StartType
```

For comprehensive enumeration including the critical `ImagePath` and `StartName` values, use `Win32_Service`:

```powershell
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, StartName, State | Sort-Object Name
```

For a complete direct registry read of every service key — equivalent to walking `SYSTEM\CurrentControlSet\Services\<Name>` in an offline hive:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
    Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue |
        Select-Object PSChildName, ImagePath, Start, Type, ObjectName, DisplayName, Description
}
```

When analyzing service `ImagePath` values, split the executable from its arguments — the argument portion often contains a `svchost -k <group>` grouping or suspicious command-line flags that signal abuse:

```powershell
Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
    if ($_.PathName -match '^"?([^"]+\.exe)"?\s*(.*)$') {
        [PSCustomObject]@{ Name = $_.Name; Executable = $Matches[1]; Arguments = $Matches[2] }
    }
}
```

## Service DLL Abuse (svchost-Hosted)

Rather than register itself as its own standalone executable, malware can register as a **service DLL** loaded by a generic, legitimate-looking `svchost.exe -k <group>` process. The registry path for this is one level deeper than the standard service key:

```
SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters\ServiceDll
```

Instead of `ImagePath` pointing straight at a suspicious executable, `ImagePath` points at the ordinary-looking `%SystemRoot%\System32\svchost.exe -k <group>`, and the actual malicious code lives in the DLL named by `ServiceDll` — loaded into a process that, on the surface, is indistinguishable from the dozens of other legitimate `svchost.exe` instances covered in Windows OS Fundamentals & Versions (note 01). This is a favorite technique precisely because it avoids ever creating a standalone process with a suspicious name or an unusual parent/child relationship — the process tree still shows `services.exe` → `svchost.exe`, exactly as expected. The tell isn't in the process list at all; it's in the `Services\<ServiceName>\Parameters\ServiceDll` registry value, which is why registry-side inspection of the service key (not just live process enumeration) matters even when the running process looks completely normal.

### PowerShell

Enumerate every `svchost`-hosted service and pull its `ServiceDll` value. The process list alone cannot distinguish a legitimate grouping from an abused one — the only tell is in the registry:

```powershell
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
    $svc = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($svc.ImagePath -match 'svchost\.exe') {
        $dll = (Get-ItemProperty "$($_.PSPath)\Parameters" -ErrorAction SilentlyContinue).ServiceDll
        [PSCustomObject]@{ Service = $_.PSChildName; ImagePath = $svc.ImagePath; ServiceDll = $dll }
    }
}
```

Inspect the output for `ServiceDll` values that point outside `System32`. Legitimate Windows services keep their DLLs there; any deviation is suspicious.

## Remote Service Creation for Lateral Movement

Because the Service Control Manager accepts remote connections from an authenticated, sufficiently-privileged user, `sc.exe` can create and start a service on a remote host in two commands:

```
sc \\host create servicename binpath= "c:\temp\evil.exe"
sc \\host start servicename
```

This is both a lateral-movement technique (the attacker already has credentials and is pivoting to a new host) and, from that new host's perspective, a fresh persistence mechanism — the created service key behaves exactly like the locally-installed services described above. Full source/destination lateral-movement depth (session semantics, credential requirements, how this compares to WMI/PowerShell Remoting/remote scheduled tasks) belongs in Lateral Movement (note 12); the table below is the destination-host evidence chain this technique leaves behind, per the FOR508 poster's lateral-movement panel.

| Evidence Source | What It Shows | Notes |
|---|---|---|
| Security log 4624 (Logon Type 3) | Network logon from the source host | Establishes who connected and from where |
| Security log 4672 | Admin-equivalent privileges assigned at logon | Confirms the account had the rights needed to create a remote service |
| Security log 4697 (service install) | Direct record of a new service being installed | 🔴 Requires **non-default auditing** ("Audit Security System Extension" / service-install auditing) to be enabled — a real detection gap; do not assume 4697 will be present just because a service was installed |
| System log 7045 (service installed) | Records every new service installation | **Primary detection recommendation** — enabled by default from Windows Server 2008 R2 / Windows 7 onward, far more reliably present than 4697 |
| System log 7034 / 7035 / 7036 / 7040 | Service crashed unexpectedly (7034) · start/stop control sent (7035) · service started or stopped (7036) · start type changed, e.g. Boot ↔ On Request ↔ Disabled (7040) | Useful for confirming the service actually ran, not just that it was installed |
| `SYSTEM\CurrentControlSet\Services\<Name>` key creation | The service's own registry footprint on the destination host | Same structure as any locally-created service — `ImagePath`, `Start`, `Type`, `ObjectName` all apply |
| ShimCache / Amcache | First/last-seen evidence of the dropped executable | See ShimCache (AppCompatCache).md and Amcache.md (note 06) — Amcache's SHA1 hash is particularly useful for confirming the exact binary; ShimCache records presence but is bypassed if the malware is implemented purely as a service DLL rather than a standalone executable |
| Prefetch | Confirms the dropped executable actually ran, with run count and timestamps | See Prefetch.md (note 06) |

### PowerShell

Pull recent System log 7045 events (service installation) and cross-check each installed service name against its current registry state. This identifies services that were installed but have since been modified or removed, which might otherwise be missed:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 50 | ForEach-Object {
    $name = $_.Properties[0].Value
    $current = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        TimeCreated        = $_.TimeCreated
        ServiceName        = $name
        InstalledImagePath = $_.Properties[1].Value
        CurrentImagePath   = $current.ImagePath
        CurrentStart       = $current.Start
    }
}
```

Compare `InstalledImagePath` against `CurrentImagePath` — if they differ, the service configuration was modified post-installation. If `CurrentImagePath` is null, the service was removed.

## PsExec Special Case

PsExec (Sysinternals) deserves its own subsection because it's the single most common tool built on top of the remote-service primitive above, and it leaves a distinctive, well-documented evidence chain of its own. This is a persistence-angle summary only — full PsExec lateral-movement depth belongs in Lateral Movement (note 12).

**How it works:** PsExec copies its service component to the target over the `ADMIN$` administrative share, installs and starts it as a temporary Windows service — named `PSEXESVC` by default — which then executes the specified command and relays output back over a named pipe, and finally removes the service when finished (unless it crashes or is killed mid-run, in which case remnants can survive).

🔴 **The `-r` option lets an attacker rename the service** away from the default `PSEXESVC` to something less recognizable — don't anchor detection solely on that literal service name.

| Evidence | Location | Notes |
|---|---|---|
| `EulaAccepted` value | `NTUSER.DAT\Software\SysInternals\PsExec\EulaAccepted` | 🔴 High-value, very specific artifact — proves PsExec was run **interactively**, on **this specific host**, under **this specific user profile**, at least once (the EULA prompt only appears on first interactive run, or if run with `-accepteula` from a script — either way the key gets written) |
| Dropped service executable | `psexesvc.exe` (or the renamed equivalent) and any pushed executables (e.g. `evil.exe`) appearing under `ADMIN$` → `C:\Windows\` (or `C:\Windows\System32\` context) | File creation time on the destination is a reasonable proxy for time of copy |
| Prefetch / ShimCache / Amcache | Entries for `psexesvc.exe` and any executable it launched | Same execution-evidence logic as the general remote-service chain above — see note 06 |
| Security log 4624 (Logon Type 3, or Type 2 if `-u` alternate credentials used) + 4672 + 5140 (share access to `ADMIN$`) | Session and share-access evidence for the PsExec connection itself | Mirrors the general remote-execution chain; `-u` triggers explicit alternate-credential logon (also visible as 4648 on the source host) |

## Red Flags Specific to Services

- **`ImagePath` outside `Program Files`/`Windows`/`System32`.** A service pointing into `%APPDATA%`, `%TEMP%`, `%ProgramData%`, or a user profile directory is the service-persistence equivalent of the Run-key drop-and-persist pattern — legitimate services essentially never live in user-writable locations.
- **`ObjectName` = `LocalSystem` with no plausible need.** A service that has no legitimate reason to run with SYSTEM-level privilege — e.g. something purporting to be a simple utility or update helper — running as `LocalSystem` anyway is a strong privilege-escalation signal.
- **Typosquatted service names.** A name closely mimicking a legitimate Windows service — e.g. "Windows Update Serivce" (misspelled), or a name one character off from a real service — banks on an analyst pattern-matching on the name alone rather than checking `ImagePath` and signature.
- **Unusually short or generic `DisplayName`.** Legitimate services (Microsoft's and most reputable third-party software) tend to have descriptive, specific display names; a bare or generic name is a mild signal worth a second look.
- **Missing `Description` string.** Legitimate Microsoft services almost always populate this value; its absence isn't damning on its own but raises the priority of checking everything else about the service.

### PowerShell

To sweep an estate for outlier services (present on only a handful of hosts), collect service lists across multiple hosts and find the services that don't appear on at least half your fleet:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
$results = Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-CimInstance Win32_Service | Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, Name, PathName, StartMode, StartName
}
$results | Group-Object Name | Where-Object Count -lt ($computers.Count * 0.5) | Select-Object Name, Count
$results | Export-Csv C:\hunt\service_sweep.csv -NoTypeInformation
```

Verify the Authenticode signature on a suspect service's binary:

```powershell
$svc = Get-CimInstance Win32_Service -Filter "Name='suspectsvc'"
if ($svc.PathName -match '^"?([^"]+\.exe)"?') { Get-AuthenticodeSignature $Matches[1] | Select-Object Path, Status, SignerCertificate }
```

When remediating a suspicious service, preserve evidence first — always export the full configuration before any change, then stop/disable, and finally delete as a last step:

```powershell
# Evidence-first: export the current config before any change
Get-CimInstance Win32_Service -Filter "Name='suspectsvc'" | Export-Clixml C:\hunt\suspectsvc_config_before_removal.xml

# Stop and disable - halts execution and prevents restart at next boot, without destroying the registry evidence
Stop-Service -Name 'suspectsvc' -Force
Set-Service -Name 'suspectsvc' -StartupType Disabled

# Full removal - sc.exe delete is still the native tool for this; Windows PowerShell 5.1 has no built-in delete-service cmdlet (Remove-Service exists in PowerShell 6+/7)
sc.exe delete suspectsvc
```

## Tooling

| Tool | Use |
|---|---|
| **`sc.exe query`** | Live enumeration of running/stopped services and their current state on a host |
| **`sc.exe qc <name>`** | Live query of a specific service's configuration — `ImagePath`, `Start` type, `ObjectName`, dependencies — the fastest way to pull the values covered in this note from a live system |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `SYSTEM\CurrentControlSet\Services\<Name>` (and its `Parameters\ServiceDll` subkey) when working from an acquired hive rather than a live host — see Registry Forensics Fundamentals (note 04) for hive access mechanics |
| **Autoruns** (Sysinternals) | Already introduced in Autostart (Run/RunOnce) Keys — enumerates services as part of its comprehensive autostart view, with code-signing and VirusTotal cross-reference, so a suspicious service surfaces alongside every other autostart mechanism in one pass rather than requiring a dedicated services-only sweep |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `ImagePath` pointing into `%APPDATA%`, `%TEMP%`, `%ProgramData%`, or a user profile | Classic drop-and-persist — legitimate services essentially never live in user-writable locations |
| `ObjectName` = `LocalSystem` (or a privileged domain account) for a service with no plausible need for that privilege | Privilege-escalation signal — verify the service's stated function actually requires SYSTEM-level access |
| Service name closely mimics a legitimate Windows service (typosquatting) | Banks on the analyst recognizing the name and skipping verification of path/signature |
| No `Description` string, or an unusually short/generic `DisplayName` | Legitimate Microsoft services almost always populate `Description` — absence is a mild but real signal |
| `Type = 0x20` (shared-process) with an unfamiliar `ServiceDll` under `Parameters` | Service-DLL abuse — the process tree looks like a normal `svchost.exe`, so the registry value is the only place this surfaces |
| System log 7045 present with no corresponding change-management record | Primary, reliably-logged signal of an unauthorized service install — investigate before checking for the audited-only 4697 |
| 4697 absent | Does not mean no service was installed — this event requires non-default auditing; rely on 7045 as the baseline detection |
| `EulaAccepted` present under a user's `NTUSER.DAT\Software\SysInternals\PsExec` who shouldn't have run it | Proves interactive PsExec use under that specific profile on that specific host |
| Service named something other than `PSEXESVC` but with an otherwise identical PsExec evidence chain (ADMIN$ drop, EULA key, matching Prefetch/ShimCache/Amcache pattern) | `-r` renaming — don't anchor PsExec detection on the default service name alone |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all five persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure, `CurrentControlSet` resolution, transaction-log mechanics used to read the `Services` key correctly | Registry Forensics Fundamentals (note 04) |
| What a *normal* `svchost.exe` process tree looks like, to judge service-DLL abuse against a real baseline | Windows OS Fundamentals & Versions (note 01) |
| First/last-seen evidence and hash identity of a dropped service executable | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual execution of a dropped service executable | Prefetch.md (note 06) |
| Task-based persistence and its own event/registry/filesystem evidence chain | Scheduled Tasks |
| Fileless, event-triggered persistence in the WMI repository | WMI Event Consumers |
| Search-order/DLL side-loading persistence with no service or registry-key footprint of its own | DLL Hijacking |
| Full lateral-movement depth — source/destination pairing for `sc`, PsExec, WMI/WMIC, PowerShell Remoting, remote scheduled tasks, `net use` | Lateral Movement (note 12) |
| Security/System log event mechanics (4624/4672/4697/7045/etc.) in full | Event Log Analysis (note 11) |

## Resources

- SANS FOR508 poster, "Hunt Evil: Lateral Movement" — Services and PsExec panels — coverage checklist for the event/registry/filesystem chains, rewritten in this note's own words
- SANS FOR508 poster — Malware Persistence coverage checklist
- Sysinternals PsExec — https://learn.microsoft.com/sysinternals/downloads/psexec
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- MITRE ATT&CK T1543.003 (Create or Modify System Process: Windows Service) — https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK T1021.002 (Remote Services: SMB/Windows Admin Shares) — https://attack.mitre.org/techniques/T1021/002/
