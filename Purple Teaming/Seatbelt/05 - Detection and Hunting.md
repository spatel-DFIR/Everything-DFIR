# Seatbelt — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

Seatbelt exposes several operator choices that materially change its footprint: `-full` (no evidence-shape impact — a filtering choice only), `-randomizeorder`/`-delaycommands=` (spread/reorder the same underlying activity, don't remove any of it), `-group=`/exclusion syntax (change **which** checks run, so **which** evidence classes are produced), and — the single biggest variable — **standalone-binary vs. in-memory/loader-hosted execution** (changes whether a distinct process/file ever exists at all). Rank hunts by what survives that last variable first, since it's the one that eliminates entire evidence categories rather than just reducing volume:

| Rank | Signal | Survives `-randomizeorder`/`-delaycommands=`? | Survives `-group=` scoping (fewer checks run)? | Survives in-memory/loader-hosted execution (`TECHNIQUE SELF`/`--in-process`)? |
|---|---|---|---|---|
| 1 (strongest) | Loader/C2-side task log showing the `execute-assembly`/`execute_dotnet_assembly` invocation and full argument string | ✅ Yes | ✅ Yes | ✅ Yes — this is the loader's own record, independent of how Seatbelt itself ran |
| 2 | WMI-Activity Operational log (5857/5858) for `root\SecurityCenter2`/`root\cimv2` queries | ✅ Yes — same queries, just spread out or reordered | ❌ **Only if a WMI-based check was actually included** in the scoped group/command list | ✅ Yes — the WMI query itself happens regardless of hosting process |
| 3 | Process creation (Sysmon 1 / Security 4688) for a distinct `Seatbelt.exe` or CLR-hosting spawned process (e.g. Meterpreter's `SPAWN_AND_INJECT` default of `notepad.exe`) | ✅ Yes | ✅ Yes — the process exists regardless of which checks are scoped | ❌ **No** — `TECHNIQUE SELF`/`--in-process` runs inside the implant's own already-existing process, no new process is created |
| 4 | Sysmon 7 (Image Load) for `clr.dll`/`mscoree.dll` in a process that doesn't normally host the CLR | ✅ Yes | ✅ Yes | ⚠️ **Partial** — still fires for `SELF`/`--in-process` if the implant's own process doesn't already host a CLR for other reasons, but loses value as a distinguishing signal if the implant already routinely hosts .NET (many modern C2 implants do) |
| 5 (weakest) | Static/hash-based AV/EDR signature on the binary | ❌ **No** — trivially defeated by recompiling from source with renamed types (no canonical hash exists in the first place) | N/A | ❌ **No** — never applicable to in-memory execution, there's no file to scan |

**Build hunts on rank 1 where you have visibility into loader/C2 infrastructure (red-team self-review, purple-team exercises with shared visibility, or seized attacker infrastructure) — it's the only signal that survives every operator choice Seatbelt itself exposes. On the target side alone, rank 2 (WMI-Activity) is the strongest signal that doesn't depend on standalone-binary execution, since Seatbelt's AV/system checks routinely hit `root\SecurityCenter2`/`root\cimv2` regardless of hosting method.**

## Hunting on Source

Meaningful only in the two cases where a genuine source-side footprint exists: a standalone-binary run, or the remote-enumeration case (`-computername=`). See `03 - Source Evidence.md` for why in-memory/`TECHNIQUE SELF` execution against the *local* host leaves nothing here to hunt.

```powershell
# Standalone-binary process check (won't catch in-memory/reflective execution)
Get-Process | Where-Object { $_.ProcessName -match 'seatbelt' }

# Command-line history for the invocation and any embedded remote credentials —
# HIGH VALUE if -computername= was combined with explicit -username=/-password=
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'seatbelt|-group=|-computername=|-delaycommands='

# Outbound connections to a second host's RPC Endpoint Mapper — the
# remote-enumeration case only
Get-NetTCPConnection -RemotePort 135 -ErrorAction SilentlyContinue
```

## Hunting on Target

```powershell
# 1. Process creation for a standalone binary or an anomalous CLR-hosting
#    spawned process — HIGHEST-PRIORITY signal that doesn't require
#    loader/C2-side visibility (rank 3 in the priority table)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'seatbelt|-group=(all|user|system|slack|chromium|remote|misc)|-delaycommands=' }

# 2. Unexpected CLR hosting in a process that shouldn't have one — catches
#    Meterpreter's SPAWN_AND_INJECT default (notepad.exe) and similar
#    spawn-and-inject patterns from other loaders
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { $_.Message -match 'clr\.dll|clrjit\.dll|mscoree\.dll' -and $_.Message -notmatch 'powershell|w3wp|dotnet' }

# 3. WMI-Activity Operational — query errors specifically flag root\SecurityCenter2
#    hits on non-workstation SKUs (rank 2 in the priority table), and Event 5857
#    shows provider loads tied to whichever process triggered them
Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' -MaxEvents 500 -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'SecurityCenter2|AntiVirusProduct|StdRegProv' }

# 4. Command-line auditing, if enabled — full argument visibility including
#    -group=/-full/-computername=
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'seatbelt|-group=' }

# 5. Named-pipe creation matching the short-random-name pattern Meterpreter's
#    execute_dotnet_assembly module uses for output streaming (8-char
#    alphanumeric pipe name) — low-confidence alone, corroborating only
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\\\\.\\pipe\\[a-zA-Z0-9]{8}$' }
```

## Fleet-Wide Sweep

```powershell
# WMI-based sweep for the most reliable target-side signal (rank 2) across
# the estate — root\SecurityCenter2/AntiVirusProduct queries from processes
# that aren't a known security-tooling agent
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'SecurityCenter2|AntiVirusProduct' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='ClientProcessId';e={($_.Message | Select-String -Pattern 'ClientProcessId = (\d+)').Matches.Groups[1].Value}}
} -ErrorAction SilentlyContinue

# Group by host to find a burst — multiple queries against unrelated
# namespaces (SecurityCenter2 + registry via StdRegProv) from the SAME
# process ID in a tight window is the fleet-scale fingerprint
$results | Group-Object Host | Sort-Object Count -Descending | Select-Object -First 20 Count, Name

$results | Export-Csv -Path .\seatbelt_sweep_results.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — pull the relevant Sysmon 1/7 events, WMI-Activity log entries, and (if accessible) any loader/C2-side task logs before taking remediation action, since Seatbelt's on-host footprint is thin enough that acting first (isolating the host, killing the hosting process) can destroy the only recoverable evidence — especially the in-memory-only artifacts covered in `04 - Target Evidence.md`'s Memory Forensics section, which don't survive a reboot or process termination.

Seatbelt itself isn't the thing to "fix" — it's a legitimate recon tool exploiting the fact that Windows exposes broad, unauthenticated-to-the-check WMI/registry/filesystem read access to any process running as the current user (or as SYSTEM/an elevated user, for the fleet-wide case). The actual hardening targets are the access paths it rides:

```powershell
# Enable command-line auditing for process creation — the single highest-
# value native control for this tool class, since it's currently NOT
# enabled by default and materially weakens rank 3 in the priority table
# above if left off:
# Computer Configuration > Administrative Templates > System > Audit
# Process Creation > "Include command line in process creation events" = Enabled

# Restrict remote WMI/DCOM access where it isn't operationally required —
# closes the -computername= remote-enumeration path entirely for hosts
# that don't need to be WMI-manageable from arbitrary sources:
# dcomcnfg.exe > Component Services > Computers > My Computer > COM Security
# (tighten Access/Launch permissions), or via GPO:
# Computer Configuration > Windows Firewall > "Windows Management
# Instrumentation (WMI)" inbound rule group — scope to management hosts only

# Ensure EDR behavioral/heuristic detection (not just AV signature scanning)
# is enabled — the durable signal against this tool class given no canonical
# hash exists and in-memory execution defeats file-based scanning entirely
```

Enabling Sysmon (Event IDs 1 and 7 specifically) where it isn't already deployed is the single highest-leverage compensating control from this note's perspective — it's the only native-logging source that reliably survives both the standalone-binary and (partially, via Image Load) the in-memory execution paths, per the priority table above.
