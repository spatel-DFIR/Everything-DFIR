# Command Processor & Environment Variable Hijacking

This note covers two related, registry-anchored techniques that neither plant a service nor register a scheduled task nor touch a Run key, and yet both achieve the same durable outcome: code that executes automatically, every time, without the attacker having to do anything further after the initial registry write. Command Processor AutoRun rides on top of `cmd.exe` itself — arguably the single most commonly invoked program on any Windows host, used constantly by legitimate admin tooling, installers, and scripts that shell out to it without a second thought. Environment variable hijacking abuses the fact that several well-known environment variables are read and trusted by name at process-launch time, letting a value set once in the registry silently redirect what code runs inside every subsequent process that reads that variable — .NET's CLR profiling hook chief among them.

Both techniques share a property worth calling out up front: they require a **new process or a new logon** to take effect. Neither retroactively affects anything already running — setting `COR_PROFILER` doesn't inject into .NET processes that are already executing, and writing a Command Processor `AutoRun` value doesn't do anything to a `cmd.exe` session that's already open. That "on next launch" characteristic is exactly what makes both of these durable, low-maintenance persistence: the attacker plants the value once and waits for the host's own normal operational rhythm — someone opening a command prompt, a scheduled job shelling out, a .NET service restarting — to trigger it.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table.

> 🔴 **Neither technique has a dedicated MITRE ATT&CK sub-technique ID of its own for the specific registry mechanics covered here (Command Processor `AutoRun`, or `windir`/`PATH` search-order tampering via the registry environment keys) — this repo marks those `Unmapped` deliberately, not as a placeholder.** `COR_PROFILER` abuse is the one technique in this note that *is* cleanly mapped (T1574.012) — see Resources. A finding here is suspicious the same way every other value in this family is: not because the registry location exists (both are 100% legitimate Windows functionality), but because the specific value it holds points somewhere it shouldn't.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Command Processor AutoRun](#command-processor-autorun)
- [Environment Variable Hijacking](#environment-variable-hijacking)
- [Red Flags Specific to Command Processor & Environment Variable Hijacking](#red-flags-specific-to-command-processor--environment-variable-hijacking)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, registry-read-only triage — every value covered here is a single `Get-ItemProperty` call away, no third-party parser required.

```powershell
# Command Processor AutoRun in both hives - the value that fires on essentially every new cmd.exe process
'HKCU:\Software\Microsoft\Command Processor', 'HKLM:\SOFTWARE\Microsoft\Command Processor' | ForEach-Object {
    Get-ItemProperty -Path $_ -Name AutoRun -ErrorAction SilentlyContinue |
        Select-Object @{N='Hive';E={$_.PSParentPath}}, AutoRun
}

# COR_PROFILER / COR_ENABLE_PROFILING set anywhere (system or per-user) - the .NET CLR hijack primitive
'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'HKCU:\Environment' | ForEach-Object {
    Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue |
        Select-Object @{N='Hive';E={$_}}, COR_ENABLE_PROFILING, COR_PROFILER, COR_PROFILER_PATH |
        Where-Object { $_.COR_PROFILER -or $_.COR_ENABLE_PROFILING }
}

# Live process view - confirm the environment variables above are actually in effect right now for a running process
[System.Environment]::GetEnvironmentVariable('COR_ENABLE_PROFILING', 'Machine')
[System.Environment]::GetEnvironmentVariable('COR_PROFILER', 'Machine')
[System.Environment]::GetEnvironmentVariable('COR_PROFILER', 'User')

# System PATH entries that are user-writable rather than the expected Windows/Program Files locations
($env:Path -split ';') | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
    $acl = Get-Acl $_
    [PSCustomObject]@{ Directory = $_; Owner = $acl.Owner }
} | Where-Object { $_.Owner -notmatch 'TrustedInstaller|SYSTEM|Administrators' }

# windir tampering check - confirm the registry-level windir value still points at the real Windows directory
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').windir

# COR_PROFILER's registered COM CLSID, if the profiler is registered rather than an in-process path (COR_PROFILER_PATH)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name COR_PROFILER -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$($_.COR_PROFILER)\InprocServer32" -ErrorAction SilentlyContinue }
```

## Command Processor AutoRun

Two registry values, checked by `cmd.exe` itself every time it starts, both of type `REG_SZ` or `REG_EXPAND_SZ`:

```
HKEY_CURRENT_USER\Software\Microsoft\Command Processor\AutoRun
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor\AutoRun
```

When `cmd.exe` launches, it checks both locations and executes whatever is present before doing anything else — commonly understood to run HKLM's value first, then HKCU's, when both are populated. This fires for essentially every new `cmd.exe` process — an interactive session opened by a user, a `/c` one-shot command invoked by a script or another program shelling out to `cmd.exe`, and command execution triggered from within batch files — with one documented exception: a `cmd.exe` session explicitly started with the `/D` switch skips AutoRun entirely. Because that switch has to be deliberately specified by whatever is launching `cmd.exe`, the overwhelming majority of everyday `cmd.exe` invocations — including the enormous volume of legitimate scripting, batch automation, and admin tooling that still shells out through `cmd.exe` rather than PowerShell — will trigger AutoRun if it's set. That ubiquity is exactly what makes this technique valuable: an attacker doesn't need to predict *when* the target will use `cmd.exe`, only that they eventually will, on a host where `cmd.exe` remains as central to daily operations as it is on most Windows estates.

Both HKCU and HKLM are legitimate, documented configuration points — some enterprise environments genuinely use AutoRun for environment setup (adding `cd\` behavior, setting a custom prompt, mapping a drive). That legitimate use is precisely why finding *a* value here isn't the signal; finding a value that decodes to something suspicious is.

### PowerShell

Check both hives for a populated AutoRun value — the entire hunt for this technique in one command:

```powershell
'HKCU:\Software\Microsoft\Command Processor', 'HKLM:\SOFTWARE\Microsoft\Command Processor' | ForEach-Object {
    Get-ItemProperty -Path $_ -Name AutoRun -ErrorAction SilentlyContinue | Select-Object PSPath, AutoRun
}
```

Sweep an estate for hosts carrying a non-default AutoRun value, since a clean baseline host should return nothing from either key:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    'HKCU:\Software\Microsoft\Command Processor', 'HKLM:\SOFTWARE\Microsoft\Command Processor' | ForEach-Object {
        Get-ItemProperty -Path $_ -Name AutoRun -ErrorAction SilentlyContinue |
            Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, PSPath, AutoRun
    }
} | Export-Csv C:\hunt\autorun_sweep.csv -NoTypeInformation
```

Remove a confirmed-malicious AutoRun value once its content has been documented — this is a plain registry-value delete, no service or task unregistration involved:

```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Command Processor' -Name AutoRun
```

## Environment Variable Hijacking

Several well-documented environment variables are trusted by name — read once at process launch and used to decide what code loads or where a binary resolves from — and setting one at the system or per-user level silently affects every subsequent process that reads it, without touching a single file that belongs to the target application.

**`COR_PROFILER` / `COR_ENABLE_PROFILING`.** The .NET Framework's CLR profiling API is designed for legitimate application-performance-monitoring tooling: set `COR_ENABLE_PROFILING=1` and `COR_PROFILER=<CLSID or path>`, and the CLR loads the named profiler DLL into **every** .NET process that initializes the CLR while those variables are in effect — a own-goal-shaped hook, since it was built to be exactly this powerful for legitimate diagnostic tooling. Historically the profiler had to be a registered COM object referenced by CLSID; starting with .NET Framework 4, an unregistered DLL can be loaded directly by path via `COR_PROFILER_PATH`, which removes even the COM-registration footprint an analyst might otherwise check. Set system-wide or per-user, this becomes a durable, broad-scope code-injection primitive that fires the moment any .NET process — a scheduled .NET utility, an application service, PowerShell itself in some configurations — spins up the CLR.

**`windir`/`PATH` tampering.** Distinct from classic DLL search-order or side-loading abuse (see DLL Hijacking in this family), this variant works one level up, at the environment-variable and command-resolution layer rather than the loader's DLL search order: an attacker prepends a malicious directory to the `PATH` environment variable so that when a process or script invokes a common binary by name alone (no full path — `ping`, `notepad`, a vendor utility), the shell or the CreateProcess-style resolution logic finds the attacker's same-named binary in the prepended directory before it ever reaches the legitimate one in `System32` or `Program Files`. Tampering with `windir` itself is a related but rarer variant — because so much of the OS resolves paths relative to `%windir%`, a redirected value has broad and often destabilizing effects, making it a comparatively noisy, high-collateral-damage technique next to the more surgical `PATH`-prepend approach.

Both classes of variable live in the same two registry locations:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment    (system-wide)
HKCU\Environment                                                     (per-user)
```

A value written to either location does not retroactively affect anything currently running — it takes effect the next time a process launches and inherits the environment (or, for interactive sessions, generally the next logon), which is the same "on next launch" characteristic that makes Command Processor AutoRun durable rather than a one-shot trigger.

### PowerShell

Check both the system-wide and per-user `Environment` keys for the CLR-hijack pair:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' | Select-Object COR_ENABLE_PROFILING, COR_PROFILER, COR_PROFILER_PATH
Get-ItemProperty 'HKCU:\Environment' | Select-Object COR_ENABLE_PROFILING, COR_PROFILER, COR_PROFILER_PATH
```

If `COR_PROFILER` holds a CLSID rather than a bare path (indicating a registered COM profiler rather than the newer `COR_PROFILER_PATH` direct-load form), resolve it back to the actual DLL the way any COM CLSID is resolved:

```powershell
$clsid = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').COR_PROFILER
Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue | Select-Object '(default)'
```

Enumerate the system `PATH` and flag any directory that isn't under the expected `Windows`/`Program Files` locations and isn't owned by a trusted principal — the shape of a `PATH`-prepend hijack:

```powershell
($env:Path -split ';') | Where-Object { $_ } | ForEach-Object {
    [PSCustomObject]@{ Directory = $_; Exists = Test-Path $_; Owner = (Get-Acl $_ -ErrorAction SilentlyContinue).Owner }
}
```

## Red Flags Specific to Command Processor & Environment Variable Hijacking

- **A Command Processor `AutoRun` value that decodes to encoded PowerShell, a download cradle, or a reference to a binary outside expected system locations.** The same obfuscation red flags applied to Run-key values elsewhere in this family (base64 `-EncodedCommand`, `-WindowStyle Hidden`, LOLBIN chains) apply here identically — the delivery mechanism is different, the payload analysis is the same.
- **`COR_PROFILER`/`COR_ENABLE_PROFILING` set at all on a host with no legitimate APM/profiling tooling installed.** Because these variables have essentially no benign default-Windows use case — they exist for third-party diagnostic products, which are usually well-known and inventoried in an enterprise — their mere presence is a far stronger standalone signal than most other findings in this family, where the location itself is routinely legitimate.
- **`COR_PROFILER_PATH` pointing at a DLL outside `Program Files` or a known APM vendor's install directory.** The unregistered-DLL load path introduced in .NET Framework 4 removes the COM-registration footprint an analyst might otherwise check, so the environment variable itself becomes the primary artifact to inspect.
- **A `PATH` entry prepended ahead of `%SystemRoot%\System32` that is writable by a non-administrative account.** This is the setup step for the binary-name-resolution hijack — the directory doesn't need to contain anything malicious yet to be a red flag; its writability and position in the order are the finding.
- **`windir` pointing anywhere other than the actual Windows installation directory.** Given how pervasively the OS relies on `%windir%` internally, a tampered value is both a rare and a high-confidence finding — legitimate reasons to change it essentially don't exist on a standard single-boot Windows install.
- **Environment-variable values that differ between the system-wide `Session Manager\Environment` key and what a live process actually reports via `[System.Environment]::GetEnvironmentVariable`.** A mismatch suggests the value was changed after the affected process already launched, or that per-user/per-process overrides are masking the system-wide finding — worth reconciling both readings.

## Tooling

| Tool | Use |
|---|---|
| **`reg query`** / `Get-ItemProperty` | Direct read of both `Command Processor\AutoRun` locations and both `Environment` keys — no third-party tool needed for any value covered in this note |
| **Autoruns** (Sysinternals) | Enumerates Command Processor AutoRun as part of its comprehensive autostart view (Logon tab or similar), alongside every other autostart mechanism in this family — does not specifically call out `COR_PROFILER`/`PATH` tampering, so treat those two as a manual check on top of an Autoruns pass |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of both `SOFTWARE\Microsoft\Command Processor` and `SYSTEM\CurrentControlSet\Control\Session Manager\Environment` when working from an acquired hive rather than a live host |
| `[System.Environment]::GetEnvironmentVariable()` | Confirms what a live process actually sees, as opposed to what the registry currently holds — useful for catching a value changed after the fact |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Command Processor `AutoRun` present with obfuscated or download-cradle content | Fires on essentially every new `cmd.exe` process — an enormous, low-effort execution surface given how much legitimate tooling still shells out through `cmd.exe` |
| `COR_PROFILER`/`COR_ENABLE_PROFILING` set with no known APM/profiling product installed | Near-zero legitimate default-Windows use case — presence alone is a strong signal |
| `COR_PROFILER_PATH` pointing outside `Program Files`/a known vendor directory | Unregistered-DLL load path with no COM-registration footprint to fall back on for verification |
| `PATH` entry prepended ahead of `System32` and writable by a non-admin account | Sets up common-binary-name resolution to favor an attacker-planted file over the legitimate one |
| `windir` value pointing anywhere other than the real Windows directory | Rare, high-collateral, high-confidence tampering finding |
| Registry-reported environment value differs from what a live process actually reports | Suggests post-launch modification or a masking per-user/per-process override |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all Persistence Mechanisms notes | Autostart (Run/RunOnce) Keys |
| Registry hive access mechanics for `Command Processor` and `Session Manager\Environment` | Registry Forensics Fundamentals (note 04) |
| The broader, general-purpose loader search-order hijack family this note's `PATH` tampering is adjacent to but distinct from | DLL Hijacking |
| Run-key obfuscation/LOLBIN red-flag patterns applied identically to AutoRun content | Autostart (Run/RunOnce) Keys |
| Confirming actual execution of a binary reached via `AutoRun` or a hijacked `PATH` resolution | Prefetch.md (note 06) |
| First/last-seen and hash identity of a planted `PATH`-hijack binary or `COR_PROFILER_PATH` DLL | ShimCache (AppCompatCache).md, Amcache.md (note 06) |

## Resources

- MITRE ATT&CK T1574.012 (Hijack Execution Flow: COR_PROFILER) — https://attack.mitre.org/techniques/T1574/012/
- MITRE ATT&CK T1574.007 (Hijack Execution Flow: Path Interception by PATH Environment Variable) — https://attack.mitre.org/techniques/T1574/007/
- Command Processor AutoRun — **Unmapped** (no dedicated MITRE ATT&CK sub-technique ID for this specific registry mechanism)
- `windir` tampering — **Unmapped** (no dedicated MITRE ATT&CK sub-technique ID; related in spirit to T1574.007 but not the same mechanism)
- Microsoft, Setting Up a Profiling Environment (.NET Framework) — https://learn.microsoft.com/dotnet/framework/unmanaged-api/profiling/setting-up-a-profiling-environment
- Red Canary, Detecting COR_PROFILER manipulation for persistence — https://redcanary.com/blog/threat-detection/cor_profiler-for-persistence/
- Microsoft, The Old New Thing — Hidden gotcha: the command processor's AutoRun setting — https://devblogs.microsoft.com/oldnewthing/20071121-00/?p=24433
- persistence-info.github.io, cmd.exe AutoRun — https://persistence-info.github.io/Data/cmdautorun.html
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
