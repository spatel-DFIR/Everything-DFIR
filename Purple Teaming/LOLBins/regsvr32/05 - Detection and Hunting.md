# LOLBins — regsvr32.exe — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`regsvr32.exe` Squiblydoo abuse has limited evasion surface — the `/i:<URL>` or `/i:<path>` argument is the defining tell, and the scriptlet execution (loading `jscript.dll` or `vbscript.dll` into `regsvr32.exe`) is nearly impossible to hide without disabling the entire scriptlet engine. Rank hunts by what survives which operator choices:

| Rank | Signal | Survives binary rename/relocation? | Survives local scriptlet (no network)? | Notes |
|---|---|---|---|---|
| 1 (strongest) | Command-line **argument shape** (`/i:...` + URL or path) in Sysmon 1 or Security 4688 | ✅ Yes — the operator must use `/i:` to load any scriptlet; renaming the binary doesn't change how it parses its own arguments | ✅ Yes — works for both remote HTTP/HTTPS and local file/UNC path scriptlets | Requires Sysmon or 4688 command-line auditing deployed — without it, this rank is invisible. The URL or path in the argument is often the **single most forensically valuable piece of data** in the entire investigation. |
| 2 | **Script engine DLL load** — `jscript.dll` or `vbscript.dll` loaded into `regsvr32.exe` process (Sysmon 7) | ✅ Yes — the Windows Script Host engine must be loaded to execute any JScript/VBScript; binary rename doesn't change this | ✅ Yes — applies to all Squiblydoo variants, including local scriptlets | Survives even if command-line logging is absent; however, Sysmon 7 (Image Loaded) requires Sysmon to be deployed |
| 3 | **Suspicious parent-child spawns** — `regsvr32.exe` spawning `cmd.exe`, `powershell.exe`, `mshta.exe`, etc. (Sysmon 1, Security 4688) | ✅ Yes — renamed binary still follows same code path | ✅ Yes | Only fires if the scriptlet's own JScript code explicitly spawns a child process; some stagers/payloads spawn nothing (e.g., injecting into an existing process) — so this signal can be absent in stealthy attacks |
| 4 | **Authenticode/OriginalFileName check** — a signed binary with `OriginalFileName: REGSVR32.EXE` running from outside `System32`/`SysWOW64` (Sysmon 1) | ❌ No — defeats itself if the operator runs the **unmodified** binary in the original location; only catches the copied/relocated variant | ✅ Yes | Combine with field validation to catch a renamed-but-genuine binary specifically |
| 5 | **Bare `regsvr32.exe` process-creation frequency** | ❌ No | ❌ No | High false-positive rate in enterprises where legacy COM components are registered regularly (Windows service installation, application setup). Never hunt on this alone. |

**Build hunts on ranks 1-2 as primary detections — rank 1 (command-line argument shape) is the single most reliable, evasion-proof signal and should be the foundation of any regsvr32 Squiblydoo detection rule.** Treat rank 3 as a secondary enrichment. Treat ranks 4-5 as statistical anomaly detection only.

## Hunting on Source

Source-side hunting for this tool means pivoting through the infrastructure/tasking layer described in `03 - Source Evidence.md`, not an "operator machine" in the usual sense of this module:

```
# If attacker web-hosting infrastructure is ever recovered: grep access logs for
# requests matching the scriptlet URL, identify source IPs (victim hosts)
grep -E "\.sct|regsvr32" access.log

# If C2 server task history is available (red-team retrospective, or recovered
# attacker infrastructure): search issued-command history for regsvr32 commands
grep -i "regsvr32" c2_task_history.log

# If the operator's staging box is recovered: look for .sct files and
# scriptlet-generation tool execution (msfvenom, Empire launcher scripts, etc.)
Get-ChildItem -Path $env:TEMP, $env:USERPROFILE\Downloads -Filter "*.sct" -Recurse -ErrorAction SilentlyContinue
```

See this module's `Sliver/`, `PowerShell Empire/`, and other C2-framework folders for how each framework's own task-history logging is structured.

## Hunting on Target

```powershell
# 1. PRIMARY: Command-line argument shape in Sysmon Event 1 — the most reliable
#    regsvr32 Squiblydoo detection
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)regsvr32.*\s+/i:' } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 2. Same hunt against native Security 4688, if Sysmon isn't deployed
#    but command-line auditing IS enabled
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match '(?i)regsvr32.*\s+/i:' }

# 3. SECONDARY: Script engine DLL load into regsvr32 (Sysmon Event 7) —
#    survives binary rename and detects even fileless execution
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} |
  Where-Object { 
    $_.Message -match 'Image:.*regsvr32\.exe' -and
    $_.Message -match '(?i)(jscript\.dll|vbscript\.dll)'
  } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='ImageLoaded';e={($_.Message -split "`n" | Select-String 'ImageLoaded:').ToString()}}

# 4. TERTIARY: Suspicious parent-child spawn — regsvr32 spawning command shell or PowerShell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { 
    $_.Message -match 'ParentImage:.*regsvr32\.exe' -and
    $_.Message -match '(?i)(cmd\.exe|powershell\.exe|rundll32\.exe|mshta\.exe|cscript\.exe|wscript\.exe)'
  }

# 5. ENRICHMENT: Rare/suspicious regsvr32 locations — binary from outside System32/SysWOW64
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match 'OriginalFileName:\s*REGSVR32\.EXE' -and
    $_.Message -notmatch 'Image:.*\\(System32|SysWOW64)\\regsvr32\.exe'
  }

# 6. Network signal: outbound HTTP/HTTPS to .sct resource
#    (requires network capture or Sysmon 3 with network event logging)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} |
  Where-Object { 
    $_.Message -match 'Image:.*regsvr32\.exe' -and
    $_.Message -match '(?i)\.sct'
  }
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — the fleet-level
# signal is the same regsvr32 command (especially the scriptlet URL) appearing
# across multiple hosts within a tight time window
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  # Primary: Command-line arg hunt
  $sysmonHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '(?i)regsvr32.*\s+/i:' }

  # Secondary: Script engine load hunt
  $scriptEngineHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=7} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { 
      $_.Message -match 'Image:.*regsvr32\.exe' -and
      $_.Message -match '(?i)(jscript\.dll|vbscript\.dll)'
    }

  [PSCustomObject]@{
    Host              = $env:COMPUTERNAME
    SysmonHitCount    = ($sysmonHits | Measure-Object).Count
    LatestSysmonHit   = ($sysmonHits | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    ScriptEngineHits  = ($scriptEngineHits | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.SysmonHitCount -gt 0 -or $_.ScriptEngineHits -gt 0 } |
  Sort-Object LatestSysmonHit -Descending

$results | Export-Csv -Path .\regsvr32_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

For environments with a network sensor (Zeek, Suricata, proxy logs):

```
# Zeek: HTTP requests for .sct files or scriptlet-named resources
zeek-cut ts id.orig_h id.resp_h uri < http.log |
  grep -iE "\.sct|scriptlet|payload"

# Proxy logs: requests for .sct files or from regsvr32 User-Agent
grep -iE "\.sct|RegSvcs" proxy.log |
  awk '{print $1, $5, $7}' # timestamp, destination, URI
```

## Remediation

**Capture evidence first** — export the Sysmon 1/Security 4688 command-line record (it carries the scriptlet URL on its own), the Sysmon 7 DLL-load record if available, and any network-capture evidence (proxy logs, packet captures) showing the HTTP/HTTPS connection to the scriptlet host. The scriptlet URL is often the **only surviving record of where the payload came from** if network logs aren't maintained.

```powershell
# Kill the process if caught live
Get-Process -Name regsvr32 -ErrorAction SilentlyContinue | Stop-Process -Force

# Check for any secondary child processes the scriptlet may have spawned
Get-Process | Where-Object { $_.ParentProcessId -eq (Get-Process regsvr32).Id }

# If any secondary processes exist (cmd.exe, powershell.exe, rundll32.exe under regsvr32),
# terminate those as well after capturing their command-line arguments

# Look for dropped files from the scriptlet (if the script saved anything to disk)
Get-ChildItem -Path $env:TEMP, $env:APPDATA, $env:USERPROFILE -Filter "*.sct" -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.exe" -ErrorAction SilentlyContinue | 
  Where-Object { $_.LastWriteTime -gt [datetime]::Now.AddMinutes(-5) }

# Quarantine any discovered files
Move-Item "<RecoveredFilePath>" "C:\Quarantine\" -Force -ErrorAction SilentlyContinue
```

Address whatever the downloaded/decoded payload actually was — a C2 agent, a ransomware stage, a credential stealer — using that payload's own dedicated tool folder in this module or the relevant `Windows/Threat Landscape and Playbooks/` playbook; this section covers only the regsvr32 delivery step itself.

**Real hardening** — beyond evidence capture:

- **Enable command-line process auditing** (Security 4688 with command-line logging, or deploy Sysmon) — without it, rank-1 in the priority table above is entirely invisible.
- **Enable Sysmon Image Loaded events (Event 7)** — this provides rank-2 coverage even without command-line logging.
- **Constrain `regsvr32.exe` via AppLocker/WDAC** on hosts that have no legitimate COM-registration need for it — many modern enterprises use MSI-based installation or PowerShell instead. A default-deny or alert-on-execution policy for regsvr32 on non-admin/developer workstations meaningfully shrinks this technique's usable footprint.
- **Block outbound `.sct` file downloads** — proxy/firewall rules that block HTTP/HTTPS responses with `.sct` in the URI or MIME type.
- **DNS sinkholing for known attacker domains** — if the regsvr32 scriptlet URL is discovered, block that domain at the DNS layer to prevent future infections.
- **Script Engine hardening** — disable or restrict JScript/VBScript in enterprise group policy where possible, though this is a blunt control with real application compatibility implications. More surgical: disable running scripts via the Shell.Execute mechanism (`CreateObject("WScript.Shell")`).

**Detection rule pattern (Splunk/ELK/Sentinel):**
```
source="sysmon" OR source="security" EventCode=1 OR EventCode=4688
| search CommandLine="*regsvr32*" AND CommandLine="*/i:*"
| stats count by host, user, CommandLine
| where count > 0
```
