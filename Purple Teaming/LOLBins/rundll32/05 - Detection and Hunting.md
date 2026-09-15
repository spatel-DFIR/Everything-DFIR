# LOLBins — rundll32.exe — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`rundll32.exe` DLL execution has clear evasion surfaces: binary renaming, obfuscated DLL paths, and the possibility of remote DLL loading from attacker-controlled servers. Rank hunts by signal reliability:

| Rank | Signal | Survives binary rename/relocation? | Survives fileless (in-memory DLL)? | Notes |
|---|---|---|---|---|
| 1 (strongest) | Command-line **DLL path/URL + function name** in Sysmon 1 or Security 4688 | ✅ Yes — argument survives rename | ✅ Yes — captures remote URL if specified | Requires command-line auditing. **The DLL path is forensically invaluable**. |
| 2 | **DLL load into rundll32** (Sysmon Event 7, Image Loaded) | ✅ Yes | ✅ Yes | Directly names the DLL being loaded. Survives without command-line logging; requires Sysmon 7. |
| 3 | **Unsigned or suspicious-source DLL** in Image Loaded | ✅ Yes | ✅ Yes | Attacker-authored DLLs are typically unsigned; system DLLs are Microsoft-signed. Combine with unusual path context. |
| 4 | **Rare parent-child spawn** — rundll32 spawning cmd.exe/PowerShell | ✅ Yes | ❌ No — only fires if DLL's export spawns children | Many modern payloads inject instead of spawning, so this signal can be absent in sophisticated attacks |
| 5 (weakest) | Bare `rundll32.exe` process-creation frequency | ❌ No | ❌ No | High false-positive rate in any enterprise with legitimate COM/DLL invocation. Never hunt on this alone. |

**Build hunts on ranks 1-2 as primary detections.** Treat rank 3 as enrichment. Ranks 4-5 are supporting artifacts only.

## Hunting on Target

```powershell
# 1. PRIMARY: Command-line argument pattern (Sysmon 1 or Security 4688)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { 
    $_.Message -match '(?i)rundll32\.exe' -and
    $_.Message -match '(?i)(\.dll|\.ocx)' 
  } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# Refined to catch suspicious DLL paths (not System32)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { 
    $_.Message -match '(?i)rundll32\.exe' -and
    $_.Message -match '(?i)(\.dll|\.ocx)' -and
    $_.Message -notmatch 'System32|System64|SystemRoot'
  }

# 2. Same hunt against native Security 4688
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { 
    $_.Message -match '(?i)rundll32' -and
    $_.Message -match '(?i)(\.dll|\.ocx)'
  }

# 3. SECONDARY: DLL load into rundll32 (Sysmon Event 7)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { $_.Message -match 'Image:.*rundll32\.exe' } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='ImageLoaded';e={($_.Message -split "`n" | Select-String 'ImageLoaded:').ToString()}},
    @{n='Signed';e={($_.Message -split "`n" | Select-String 'Signed:').ToString()}}

# Refined: Look for unsigned DLLs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { 
    $_.Message -match 'Image:.*rundll32\.exe' -and
    $_.Message -match 'Signed:\s*false'
  }

# 4. TERTIARY: Unusual rundll32 → child process spawn
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { 
    $_.Message -match 'ParentImage:.*rundll32\.exe' -and
    $_.Message -match '(?i)(cmd\.exe|powershell\.exe|rundll32\.exe|mshta\.exe)'
  }

# 5. ENRICHMENT: DLL in unusual paths
Get-ChildItem -Path $env:TEMP, $env:USERPROFILE\Downloads, $env:USERPROFILE\AppData -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue | 
  Where-Object { $_.LastWriteTime -gt [datetime]::Now.AddHours(-1) }

# 6. Prefetch examination for rundll32 + suspicious DLLs
Get-ChildItem -Path "C:\Windows\Prefetch\RUNDLL32.EXE-*.pf" -ErrorAction SilentlyContinue
# (Requires specialized prefetch parser to extract DLL references)
```

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  # Command-line hunt
  $cmdHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { 
      $_.Message -match '(?i)rundll32\.exe' -and
      $_.Message -match '(?i)(\.dll|\.ocx)' 
    }

  # DLL load hunt
  $dllHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Image:.*rundll32\.exe' }

  [PSCustomObject]@{
    Host       = $env:COMPUTERNAME
    CmdHitCount = ($cmdHits | Measure-Object).Count
    LatestCmd   = ($cmdHits | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    DllHitCount = ($dllHits | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.CmdHitCount -gt 0 -or $_.DllHitCount -gt 0 } | Sort-Object LatestCmd -Descending
$results | Export-Csv -Path .\rundll32_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

```
# Zeek: HTTP requests for .dll files (remote DLL loading)
zeek-cut ts id.orig_h id.resp_h uri < http.log |
  grep -iE "\.dll|\.ocx"

# Proxy logs: Requests matching rundll32 User-Agent patterns
grep -iE "rundll32|Mozilla/4.0.*Windows" proxy.log | grep -iE "\.dll"
```

## Remediation

```powershell
# Kill the process if live
Get-Process -Name rundll32 -ErrorAction SilentlyContinue | Stop-Process -Force

# Capture the command-line DLL path for investigation
$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'rundll32' }
# Extract and log the CommandLine field

# Check for secondary child processes
Get-Process | Where-Object { $_.ParentProcessId -eq (Get-Process rundll32 -ErrorAction SilentlyContinue).Id }

# Locate and quarantine the malicious DLL
Get-Item -Path "<DLL-path-from-logs>" -ErrorAction SilentlyContinue
Move-Item -Path "<DLL-path>" "C:\Quarantine\" -Force -ErrorAction SilentlyContinue

# Block attacker's domain at proxy/firewall/DNS (if remote loading occurred)
```

**Real hardening:**
- **Enable command-line process auditing** (Sysmon or Security 4688 with command-line logging)
- **Enable Sysmon Event 7** (Image Loaded) to catch DLL loads into rundll32
- **Restrict rundll32.exe via AppLocker/WDAC** on non-developer/non-admin workstations
- **Block outbound `.dll` downloads** — proxy rule blocking HTTP/HTTPS responses with `.dll` or `.ocx` extensions
- **Monitor for DLLs in `%TEMP%` and `%USERPROFILE%`** — alert on DLL creation in temporary locations
- **Disable rundll32 if not needed** — Group Policy can disable this utility for security-sensitive environments, though application compatibility must be tested first
- **DLL reputation scoring** — if available, integrate threat intelligence to flag unknown/attacker-authored DLLs

**Detection rule pattern (Splunk/ELK/Sentinel):**
```
source="sysmon" EventCode=1 
| search process="rundll32.exe" AND (CommandLine="*.dll*" OR CommandLine="*.ocx*") 
| where command NOT in ("System32", "System64")
| stats count by host, user, CommandLine, ParentImage
```
