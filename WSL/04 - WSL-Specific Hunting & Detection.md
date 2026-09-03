# WSL-Specific Hunting & Detection

Beyond analyzing a **known** WSL installation, this note focuses on **hunting** for WSL activity, unauthorized distro installation, cross-OS pivots, and suspicious behavioral patterns that indicate an attacker is using WSL to evade Windows EDR.

> 🔴 WSL is a **threat actor favorite** because Windows EDR typically cannot see inside the Linux VM — a malware binary, persistence, or exfiltration channel running in WSL is invisible to Windows security tools. Detection must focus on the **boundary artifacts**: registry changes, vhdx access patterns, wsl.exe process ancestry, and Windows-side execution traces that reveal Linux-side activity.

## Contents

- [VHD Access Patterns and Forensic Timestamps](#vhd-access-patterns-and-forensic-timestamps)
- [Registry Change Detection](#registry-change-detection)
- [Process Ancestry and Interop Pivots](#process-ancestry-and-interop-pivots)
- [Event Log Hunting](#event-log-hunting)
- [File Access Patterns and Mounted Distros](#file-access-patterns-and-mounted-distros)
- [Unauthorized Distro Installation Hunting](#unauthorized-distro-installation-hunting)
- [Cross-OS Activity Detection](#cross-os-activity-detection)
- [WSL Persistence Hunting](#wsl-persistence-hunting)
- [Timeline Correlation](#timeline-correlation)
- [Correlate With](#correlate-with)
- [Hunting Checklist](#hunting-checklist)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## VHD Access Patterns and Forensic Timestamps

The `ext4.vhdx` file is the entire Linux filesystem. Access to it reveals WSL activity:

### Detecting VHD Access

```powershell
# File access artifacts: MFT $SI and $FN timestamps
Get-ChildItem -Path "$env:LOCALAPPDATA\Packages\*\LocalState\ext4.vhdx" -Force -ErrorAction SilentlyContinue |
  Select-Object FullName, LastAccessTime, LastWriteTime, CreationTime

# Compare against distro installation time to detect suspicious access:
# - Access after distro was supposed to be idle = activity
# - Access during off-hours = suspicious
# - Multiple rapid accesses = distro actively running / busy
```

### Key Forensic Insight

The `ext4.vhdx` has three timestamps:

| Timestamp | Meaning | Forensic Value |
|-----------|---------|-----------------|
| **CreationTime** | When the distro was installed | Baseline for distro lifecycle |
| **LastWriteTime** | Last time anything inside the Linux FS was modified | Detects active distro usage; correlate with logon sessions |
| **LastAccessTime** | Last time the vhdx was accessed (unreliable on modern NTFS) | **🔴 If recent but distro is idle**: suspicious; indicates someone accessed the vhdx (live exploration, mounting, forensic acquisition) |

### Timeline Building

```bash
# Linux side: build timeline of the ext4 filesystem (once mounted)
# See Linux → 13 - Timelining for full details
mactime -b /path/to/ext4.vhdx > vhdx_timeline.csv

# Correlate with Windows timeline (prefetch, MFT) to tie Windows and Linux events
```

---

## Registry Change Detection

The Lxss registry keys change when:
1. A new distro is installed
2. Interop, mounts, or other settings are toggled
3. An attacker imports a sideloaded distro

### Hunt for Distro Registration

```powershell
# Export all Lxss keys with timestamps
$lxssPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
Get-ChildItem -Path $lxssPath -Recurse -ErrorAction SilentlyContinue |
  ForEach-Object {
    $key = $_
    $lastWrite = $key.GetValue('')  # LastWrite time
    Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue |
      Select-Object @{N='Path';E={$key.PSPath}}, @{N='LastWrite';E={$lastWrite}}, * -ExcludeProperty PSPath, PSProvider, PSChildName
  } | Export-Csv -Path lxss_inventory.csv -NoTypeInformation
```

### Detect Unauthorized Imports

```powershell
# Hunt for non-Store distros (missing PackageFamilyName)
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*' -ErrorAction SilentlyContinue |
  Where-Object {$null -eq $_.PackageFamilyName} |
  Select-Object PSChildName, DistributionName, BasePath, DefaultUid, Version

# Hunt for root-default distros
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*' -ErrorAction SilentlyContinue |
  Where-Object {$_.DefaultUid -eq 0} |
  Select-Object PSChildName, DistributionName, DefaultUid, BasePath
```

### Registry Tampering Timeline

```powershell
# Compare current registry with a baseline or previous snapshot
# If a new distro GUID appears or an existing one's Flags/DefaultUid changes,
# that's a hunt lead.

# Export current state
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss" lxss_current.reg

# Compare against baseline (if available):
# diff baseline_snapshot.reg lxss_current.reg
```

---

## Process Ancestry and Interop Pivots

Attackers use WSL to evade Windows EDR, but the **process ancestry** reveals the cross-OS pivot:

### wsl.exe Launch Patterns

```powershell
# Hunt for wsl.exe process creation events (Event 4688 or Prefetch analysis)
# Windows → 06 - Evidence of Program Execution for Prefetch parsing

Get-ChildItem -Path "$env:WINDIR\Prefetch\*wsl*.pf" -ErrorAction SilentlyContinue |
  Select-Object Name, LastWriteTime

# Command-line arguments to wsl.exe reveal what was executed:
# wsl.exe -e /bin/bash -c '...'      # Run a bash command
# wsl.exe -d Ubuntu-22.04 -e whoami  # Run whoami inside a specific distro
# wsl.exe --import MyDistro ...      # Import a custom distro
```

**Red flags:**
- `wsl.exe -e powershell.exe` — Windows-side PowerShell launched from inside WSL (interop pivot)
- `wsl.exe -e /bin/bash -c 'curl http://...'` — Exfiltration from inside WSL
- `wsl.exe -e chmod 777 /mnt/c/...` — Linux changing Windows file permissions (cross-OS tampering)

### Detect Hidden Interop Execution

```powershell
# If a Windows process tree shows:
#   Explorer.exe → cmd.exe → wsl.exe → bash.exe
# Then bash.exe actually ran with Explorer's privileges (not direct subprocess).
# This is suspicious interop chaining.

# Use Volatility or live Process Monitor to detect:
# Process Monitor filter: Image contains "wsl.exe" or "wslhost.exe"
# Look for parent/child pairs:
#   - wsl.exe → powershell.exe / cmd.exe = interop execution
#   - explorer.exe → wsl.exe = GUI launcher
#   - services.exe → wsl.exe = scheduled/service launcher
```

### Bash.exe Ancestry

```powershell
# bash.exe is the Windows-side WSL shim; if it appears in Process Explorer,
# a distro is running.
# Red flags:
#   - bash.exe parent is NOT wslhost.exe (unexpected launcher)
#   - bash.exe spawning .exe processes (interop)
#   - Multiple bash.exe instances at unusual times (multi-distro activity)

Get-ChildItem -Path "$env:WINDIR\Prefetch\*bash*.pf" -ErrorAction SilentlyContinue
```

---

## Event Log Hunting

### Lxss Manager Events

Windows logs WSL activity in the **LxssManager** service provider:

```powershell
# Query the System event log for Lxss provider events
Get-WinEvent -FilterHashtable @{
  ProviderName = 'LxssManager'
  LogName = 'System'
} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message |
  Format-Table -AutoSize
```

**Relevant event IDs:**
- **1001**: Distro registration
- **1002**: Distro start
- **1003**: Distro stop

### Hyper-V Events

WSL2 uses Hyper-V VM infrastructure; relevant events live in `Microsoft-Windows-Hyper-V-*` provider:

```powershell
Get-WinEvent -FilterHashtable @{
  ProviderName = 'Microsoft-Windows-Hyper-V-Hypervisor'
  LogName = 'System'
} -ErrorAction SilentlyContinue |
  Where-Object {$_.Message -match 'wsl'}
```

### Process Creation Events

```powershell
# Hunt for wsl.exe / wslhost.exe / bash.exe in Security event log (Event 4688)
# Requires "Include command line in process creation events" GPO

Get-WinEvent -FilterHashtable @{
  ProviderName = 'Microsoft-Windows-Security-Auditing'
  LogName = 'Security'
  Id = 4688
} -ErrorAction SilentlyContinue |
  Where-Object {$_.Message -match 'wsl|wslhost|bash'} |
  Select-Object TimeCreated, Message
```

**Hunting query (if Event 4688 with cmdline is enabled):**

```powershell
Get-WinEvent -FilterHashtable @{
  ProviderName = 'Microsoft-Windows-Security-Auditing'
  LogName = 'Security'
  Id = 4688
} -ErrorAction SilentlyContinue |
  Where-Object {$_.Message -match 'wsl\.exe.*-e|powershell|cmd'} |
  Select-Object TimeCreated, @{N='ProcessName'; E={$_.Properties[5].Value}}, @{N='CommandLine'; E={$_.Properties[8].Value}}
```

---

## File Access Patterns and Mounted Distros

### Detecting Mounted Distro Access

```powershell
# If WSL distro is running, it's accessible via \\wsl$\<distro>\ (network share)
# This shows as file access on the host

# Monitor for:
# - Unexpected \\wsl$\ access in file audit logs
# - Windows tools accessing the Linux filesystem (copy, archive, etc.)

# Check running distros:
wsl --list --verbose
```

### VHD Attachment/Detachment

When a distro mounts/unmounts, the vhdx is opened/closed:

```powershell
# File audit logs (if enabled) show vhdx access
# Look for:
# - vhdx opened (distro starting) at unexpected times
# - vhdx repeatedly opened/closed (distro cycling)

# Query NTFS file audit (requires File Auditing GPO)
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id = 4663  # File object accessed
} -ErrorAction SilentlyContinue |
  Where-Object {$_.Message -match 'ext4\.vhdx'}
```

---

## Unauthorized Distro Installation Hunting

### Periodic Scan for New Distros

```powershell
# Baseline all Lxss keys, then periodically re-scan
# If new GUIDs appear, distros were added.

function Get-WSLDistros {
  Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue |
    Where-Object {$_.PSChildName -match '^\{[a-f0-9-]+\}$'} |
    ForEach-Object {
      Get-ItemProperty -Path $_.PSPath |
        Select-Object @{N='GUID';E={$_.PSChildName}}, DistributionName, BasePath, DefaultUid, PackageFamilyName, Version
    }
}

$current = Get-WSLDistros
$baseline = @()  # Load from file if available

$new = $current | Where-Object {$_.GUID -notin $baseline.GUID}
if ($new) {
  Write-Host "🔴 NEW DISTROS DETECTED:" -ForegroundColor Red
  $new | Format-Table
}
```

### Hunt for Suspicious BasePaths

```powershell
# Distros in Temp, Downloads, or other non-standard paths are red flags

Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*' -ErrorAction SilentlyContinue |
  Where-Object {
    $_.BasePath -match 'Temp|Downloads|AppData\\Roaming|%TEMP%'
  } |
  Select-Object PSChildName, DistributionName, BasePath
```

### Hunt for Distros with Missing PackageFamilyName

```powershell
# Non-Store distros (imported via `wsl --import`)
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*' -ErrorAction SilentlyContinue |
  Where-Object {$null -eq $_.PackageFamilyName} |
  Select-Object PSChildName, DistributionName, BasePath, DefaultUid, Version
```

---

## Cross-OS Activity Detection

### Windows Accessing `/mnt/c`

Attackers often stage payloads in `/mnt/c` (Windows filesystem) for later execution:

```bash
# Inside WSL: hunt for /mnt/c access in shell history
grep -r '/mnt/c' /home/*/.bash_history /root/.bash_history 2>/dev/null

# Suspicious patterns:
grep -E '(cp|mv|curl|wget).*\/mnt\/c' /home/*/.bash_history
```

### Linux Launching Windows Executables

Interop allows Linux to execute Windows .exe:

```bash
# Inside WSL: hunt for .exe launches in history
grep -E '\.exe|powershell|cmd\.exe|notepad' /home/*/.bash_history /root/.bash_history 2>/dev/null

# Staging payloads on Windows:
grep '/mnt/c/Users' /home/*/.bash_history 2>/dev/null
```

### Windows Detecting Interop Use

```powershell
# If a Windows process spawned from wsl.exe / bash.exe, interop was used
# Process Monitor captures this directly:
# - Image: bash.exe (or similar)
# - CreateRemoteThread / WriteProcessMemory events toward powershell.exe / cmd.exe

# Event Viewer (if process-creation logging enabled):
# Hunt for 4688 events where:
#   ParentImage = bash.exe or wsl.exe
#   Image = powershell.exe or cmd.exe
```

---

## WSL Persistence Hunting

### `[boot] command=` in wsl.conf

The most critical WSL persistence vector:

```bash
# Inside the distro (once mounted):
grep -A2 '\[boot\]' /etc/wsl.conf 2>/dev/null

# Red flags:
grep -E 'command=.*(curl|wget|powershell|/mnt/c|base64)' /etc/wsl.conf
```

### Shell Startup Files

```bash
# Distro-level bash startup
for file in /home/*/.bashrc /home/*/.bash_profile /root/.bashrc /root/.bash_profile /etc/bash.bashrc /etc/profile.d/*; do
  echo "=== $file ==="
  grep -v '^#' "$file" 2>/dev/null | grep -E 'curl|wget|nc|bash -i|/mnt/c|powershell'
done
```

### Systemd Units (if Enabled)

```bash
# If [boot] systemd=true, systemd units run on startup
ls -la /etc/systemd/system/*.service 2>/dev/null | head -5
cat /etc/systemd/system/my-backdoor.service 2>/dev/null
```

### Cron Jobs (if Enabled)

```bash
# Cron often doesn't run in WSL by default, but check if it does:
crontab -l 2>/dev/null
cat /etc/cron.d/* 2>/dev/null
```

---

## Timeline Correlation

### Building a Cross-OS Timeline

1. **Windows-side events:** Prefetch, MFT, event logs (wsl.exe execution)
2. **Distro boundary:** vhdx access times, registry LastWrite
3. **Linux-side events:** ext4 mtime/ctime from the mounted filesystem, shell history timestamps

```bash
# Step 1: Build Windows timeline
# Use Windows → 18 - Timeline Analysis for Prefetch + MFT + Event Log timeline

# Step 2: Mount vhdx and build Linux timeline
mactime -b /path/to/ext4.vhdx > linux_timeline.csv

# Step 3: Merge timelines
# Correlate wsl.exe execution time with ext4 filesystem activity
# If wsl.exe runs at 14:00 and ext4 has new files at 14:01, they're related
```

### Detecting Anti-Forensics

```bash
# Timestamps out of order?
# - wsl.exe execution at 10:00 but vhdx LastWriteTime at 09:00 = suspicious
# - ext4 files with future timestamps = timestomping
# - vhdx with many rapid access patterns = forensic imaging/acquisition

# Hunt for history clearing
for f in /home/*/.bash_history /home/*/.zsh_history /root/.bash_history /root/.zsh_history; do
  if [ -f "$f" ]; then
    tail -5 "$f"  # Last 5 entries: are they a history wipe?
  fi
done
```

---

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| wsl.exe execution timeline from Prefetch | [**Windows → 06 - Evidence of Program Execution → Prefetch**](<../Windows/06 - Evidence of Program Execution/Prefetch.md>) — execution count, full command line, run times |
| vhdx access timestamps and MFT analysis | [**Windows → NTFS → 02 - $STANDARD_INFORMATION and $FILE_NAME**](<../Windows/NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md>) — MACE behavior, timestomping detection |
| Process ancestry and interop chaining | [**Windows → 06 - Evidence of Program Execution**](<../Windows/06 - Evidence of Program Execution/Prefetch.md>) — parent/child process trees |
| Event log hunting (LxssManager, Hyper-V events) | [**Windows → 11 - Event Log Analysis**](<../Windows/11 - Event Log Analysis.md>) — event ID interpretation, log structure |
| Inside-distro persistence (shell startup, cron) | [**WSL → 02 - Investigating Linux Inside WSL**](<02 - Investigating Linux Inside WSL.md>) — wsl.conf hunting, persistence vector prioritization |
| Linux shell history + command execution timeline | [**Linux → 04 - Shells and Command History**](<../Linux/04 - Shells and Command History.md>) — history format, anti-forensics detection |
| ext4 timeline + deleted-file recovery | [**Linux → 13 - Timelining**](<../Linux/13 - Timelining.md>) — mactime, Plaso, ext4 journal carving |
| Registry parsing and timeline correlation | [**WSL → 03 - WSL Registry & Configuration Deep-Dive**](<03 - WSL Registry & Configuration Deep-Dive.md>) — registry LastWrite, Flags interpretation |

---

## Hunting Checklist

Use this checklist during a WSL-suspected incident:

```
☐ Registry scan for all Lxss distros (count, names, locations)
☐ Baseline check: are there distros you don't expect?
☐ Check each distro's BasePath — is it in a suspicious location?
☐ Check DefaultUid for each distro — is any 0 (root)?
☐ Check PackageFamilyName — are any missing (imported/sideloaded)?
☐ Check Flags bits — are interop or drive mounting disabled?
☐ Check vhdx LastWriteTime — was the distro recently active?
☐ Check wsl.exe Prefetch — when was it last run? How many times?
☐ Check LxssManager event log — distro registration, start/stop times
☐ Mount the vhdx and inspect:
   ☐ /etc/wsl.conf for [boot] command= persistence
   ☐ /home/*/.bash_history and /root/.bash_history for suspicious commands
   ☐ /etc/cron.d / /var/spool/cron for scheduled tasks
   ☐ /etc/systemd/system for rogue units (if systemd enabled)
   ☐ /mnt/c access patterns (cross-OS activity)
☐ Timeline correlation:
   ☐ wsl.exe execution time vs. vhdx LastWriteTime
   ☐ vhdx LastWriteTime vs. ext4 mtime on suspicious files
☐ Anti-forensics check:
   ☐ Timestamps out of order? (future-dated files = timestomping)
   ☐ History truncated or emptied?
   ☐ vhdx file size changes (deletion, anti-forensics)
```

---

## Red Flags

| 🔴 Finding | Hunting Focus |
|-----------|---------------|
| Unexpected distro in registry | What's inside? Malware? Persistence? |
| Distro with `DefaultUid=0` | Everything runs as root; inspect for privilege escalation vectors |
| Missing `PackageFamilyName` | Manually imported; inspect the rootfs and BasePath |
| Recent vhdx `LastWriteTime` but distro is idle | Who accessed it? Forensic imaging? Live exploration? |
| wsl.exe run but no corresponding vhdx access | Distro not actually launched, or vhdx access not logged (log tampering?) |
| Interop disabled (`Flags` bit 0 = 0) on a running distro | Why the restriction? Attacker isolation strategy? |
| Shell history contains `.exe`, `/mnt/c`, or `powershell` | Interop pivot; cross-OS activity detected |
| `/etc/wsl.conf` has `[boot] command=` | WSL-native persistence; extract and analyze the payload |
| Multiple rapid wsl.exe invocations at the same time | Attacker scripting WSL for bulk operations (mass exfil, scanning) |
| vhdx in an encrypted container (BitLocker, VeraCrypt) | Attacker hiding the Linux payload; may require decryption key |
| Systemd enabled + rogue unit files | Standard Linux persistence now applies; hunt systemd units |

---

## Resources

- **MITRE ATT&CK T1564.008 (Masquerading via WSL):** https://attack.mitre.org/techniques/T1564/008/
- **Microsoft WSL documentation:** https://learn.microsoft.com/windows/wsl/
- **Process Monitor (for real-time file/registry/process hunting):** https://learn.microsoft.com/sysinternals/downloads/procmon
- **Event Viewer filter guides:** https://learn.microsoft.com/en-us/windows/win32/wmiext/wmi-security-descriptor-helper
- **Prefetch analysis tools:** PECmd (Eric Zimmerman), RegRipper (Harlan Carvey)
