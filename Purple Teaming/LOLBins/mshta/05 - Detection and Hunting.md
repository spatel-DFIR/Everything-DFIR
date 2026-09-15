# LOLBins — mshta.exe — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`mshta.exe` HTA execution has limited evasion surface — the command-line URL/path argument is the defining tell. Rank hunts by signal reliability:

| Rank | Signal | Survives binary rename/relocation? | Survives local file execution? | Notes |
|---|---|---|---|---|
| 1 (strongest) | Command-line **argument shape** (URL/path) in Sysmon 1 or Security 4688 | ✅ Yes — the operator must pass a URL/path; argument survives rename | ✅ Yes — works for HTTP/HTTPS and local/UNC paths | Requires command-line auditing; the URL itself is **forensically invaluable**. |
| 2 | **Script engine DLL load** — `jscript.dll` or `vbscript.dll` loaded into `mshta.exe` (Sysmon 7) | ✅ Yes — binary rename doesn't change this | ✅ Yes | Survives even without command-line logging; requires Sysmon 7 |
| 3 | **Suspicious child process spawn** — mshta spawning `cmd.exe`, `powershell.exe`, etc. (Sysmon 1) | ✅ Yes | ✅ Yes | Only fires if the HTA's script spawns a child; many stagers spawn nothing |
| 4 | **IE cache artifacts** in `INetCache\` with `.hta` extension | ✅ Yes | ❌ No — local file execution doesn't cache | Forensically valuable but requires file-system access |
| 5 (weakest) | Bare `mshta.exe` process-creation frequency | ❌ No | ❌ No | High false-positive rate in any enterprise with legacy HTA applications. Never hunt on this alone. |

**Build hunts on ranks 1-2 as primary detections.** Treat rank 3 as enrichment. Ranks 4-5 are supporting artifacts only.

## Hunting on Target

```powershell
# 1. PRIMARY: Command-line argument shape — URL/path pattern (Sysmon 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { 
    $_.Message -match '(?i)mshta\.exe' -and
    $_.Message -match '(?i)(http://|https://|file://|\\\\)'
  } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 2. Same hunt against native Security 4688
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { 
    $_.Message -match '(?i)mshta' -and
    $_.Message -match '(?i)(http://|https://|file://|\\\\)'
  }

# 3. SECONDARY: Script engine DLL load into mshta (Sysmon Event 7)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { 
    $_.Message -match 'Image:.*mshta\.exe' -and
    $_.Message -match '(?i)(jscript\.dll|vbscript\.dll)'
  }

# 4. TERTIARY: Suspicious parent-child spawn — mshta spawning shell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { 
    $_.Message -match 'ParentImage:.*mshta\.exe' -and
    $_.Message -match '(?i)(cmd\.exe|powershell\.exe|rundll32\.exe)'
  }

# 5. ENRICHMENT: IE cache examination
Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache\" -Recurse -Filter "*.hta" -ErrorAction SilentlyContinue
```

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  # Command-line hunt
  $cmdHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { 
      $_.Message -match '(?i)mshta\.exe' -and
      $_.Message -match '(?i)(http://|https://|file://|\\\\)'
    }

  # Script engine hunt
  $scriptHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { 
      $_.Message -match 'Image:.*mshta\.exe' -and
      $_.Message -match '(?i)(jscript\.dll|vbscript\.dll)'
    }

  [PSCustomObject]@{
    Host         = $env:COMPUTERNAME
    CmdHitCount  = ($cmdHits | Measure-Object).Count
    LatestCmdHit = ($cmdHits | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    ScriptHits   = ($scriptHits | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.CmdHitCount -gt 0 -or $_.ScriptHits -gt 0 } | Sort-Object LatestCmdHit -Descending
$results | Export-Csv -Path .\mshta_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

```
# Zeek: HTTP requests matching mshta patterns
zeek-cut ts id.orig_h id.resp_h user_agent uri < http.log |
  grep -iE "\.hta|mshta" 

# Proxy logs: User-Agent from IE/mshta
grep -iE "MSIE|Mozilla/4.0.*Windows" proxy.log | grep -iE "\.hta"
```

## Remediation

```powershell
# Kill the process if live
Get-Process -Name mshta -ErrorAction SilentlyContinue | Stop-Process -Force

# Capture the command-line URL for investigation
$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'mshta' }
# Extract and log the CommandLine field for evidence collection

# Check for secondary process spawns
Get-Process | Where-Object { $_.ParentProcessId -eq (Get-Process mshta -ErrorAction SilentlyContinue).Id }

# Look for cached HTA files
Get-ChildItem -Path "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache\" -Filter "*.hta" -Recurse -ErrorAction SilentlyContinue

# Block the attacker's domain at proxy/firewall/DNS
```

**Real hardening:**
- **Enable command-line process auditing** (Sysmon or Security 4688)
- **Enable Sysmon Event 7** (Image Loaded) to catch script engine DLL loads into mshta
- **Disable HTAs via Group Policy** (if no legitimate HTA applications are in use) — `Computer Configuration → Administrative Templates → Windows Components → Internet Explorer → Disable running HTA files`
- **Block outbound `.hta` downloads** — proxy rule blocking HTTP/HTTPS responses with `.hta` extension
- **Restrict AppLocker/WDAC** on mshta.exe for non-developer workstations
