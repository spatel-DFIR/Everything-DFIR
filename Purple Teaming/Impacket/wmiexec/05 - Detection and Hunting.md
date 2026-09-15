# Impacket — wmiexec.py — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`wmiexec.py` exposes far fewer blend-in flags than `psexec.py` — there's no service or binary name to rename, because neither is created. Its real evasion surface is narrower but sharper: `-silentcommand` and `-nooutput` remove entire artifact *classes* rather than just renaming them. Rank hunts by **invariant strength**, strongest first:

| Rank | Signal | Survives `-nooutput`? | Survives `-silentcommand`? | Survives `-shell-type powershell`? |
|---|---|---|---|---|
| 1 (strongest) | `WmiPrvSE.exe` spawning **any** unexpected child process, following a recent inbound DCOM/RPC authentication | ✅ Yes | ✅ Yes — `WmiPrvSE.exe` is *always* the direct parent of whatever gets created, `cmd.exe` or not | ✅ Yes |
| 2 | WMI-Activity Operational 5857 (`HostProcess=wmiprvse.exe`) correlated to an external-source Security 4624 | ✅ Yes | ✅ Yes — the WMI provider load happens regardless of output/wrapper settings | ✅ Yes |
| 3 | Event-sequence timing (DCOM auth → 5857 → Sysmon 1 in a tight window) | ✅ Yes | ✅ Yes | ✅ Yes |
| 4 | `__<timestamp>` output-relay file create/read/delete on an admin share | ❌ **No** — no output means no file at all | ❌ **No** — same reason | ✅ Yes (unaffected) |
| 5 | `cmd.exe` as an intermediate hop between `WmiPrvSE.exe` and the real command | ✅ Yes (still wrapped) | ❌ **No** — this is exactly what `-silentcommand` removes | ✅ Yes (still wrapped, unless combined with `-silentcommand`) |
| 6 (weakest) | Security 5140/5145 (`ADMIN$`/share access) | ❌ **No** | ❌ **No** | ✅ Yes (unaffected) |

**Build hunts on ranks 1-3 as your primary detections; treat ranks 4-6 as high-confidence enrichment when present, not sole detection logic — a real operator using `-silentcommand` defeats all of them at once.**

## Hunting on Source

```bash
# Shell history for any wmiexec/impacket invocation (credentials may be exposed in the match)
grep -iE "wmiexec|impacket" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process check — argv is visible to any local user via /proc, not just root
ps aux | grep -i wmiexec

# Confirm impacket install + locate the script and its version on disk
pip3 show impacket 2>/dev/null
find / -iname "wmiexec.py" 2>/dev/null

# Live DCOM/RPC connection to a target — ALWAYS present regardless of output flags,
# the single most reliable source-side network indicator for this tool
ss -tnp | grep -E ':135\b'

# Live SMB connection — only present if output capture is enabled (default)
ss -tnp | grep -E ':445\b'

# smbclient-style auth files left on disk from -A usage
find / -iname "*.auth" -newer /etc/hostname 2>/dev/null

# If auditd is enabled, pull the execve record even after the process has exited
ausearch -x wmiexec.py 2>/dev/null

# .pyc bytecode-cache mtimes can bound "first run on this box" even after history -c
find / -path "*/impacket/*" -name "*.pyc" -newer /etc/hostname 2>/dev/null
```

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE: WmiPrvSE.exe spawning an unexpected child process.
#    This is the ONE artifact that survives every evasion flag this tool exposes,
#    because Win32_Process.Create() always makes WmiPrvSE.exe the direct parent.
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe' } |
  Select-Object TimeCreated,
    @{n='Parent';e={($_.Message -split "`n" | Select-String 'ParentImage:').ToString()}},
    @{n='Child';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 2. WMI-Activity Operational 5857 — fires for every WMI provider load, including
#    ordinary local WMI use, so correlate against an external-source 4624 to cut noise
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5857} |
  Where-Object { $_.Message -match 'wmiprvse\.exe' } |
  Select-Object TimeCreated, Message

# 3. Network logons (Type 3) immediately preceding a WmiPrvSE.exe spawn -> correlate source IP.
#    Expect up to TWO per session (DCOM auth + SMB auth) if output capture was enabled.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Properties[8].Value -eq 3 } |
  Select-Object TimeCreated, @{n='Account';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[18].Value}}

# 4. Transient output-relay file — likely gone by the time you look, but catch it live
#    or via $MFT/USN journal for the naming pattern. Absent entirely under -nooutput/-silentcommand.
Get-ChildItem C:\Windows\*, C:\* -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^__\d{10}\.\d+$' }

# 5. PowerShell-specific: decoded Script Block Logging content for the -Enc wrapper,
#    only relevant when -shell-type powershell was used
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Where-Object { $_.Message -match '-NoP -NoL -sta -NonI -W Hidden -Exec Bypass' -or $_.Message -match 'EncodedCommand' }

# 6. Failed-attempt indicator: WMI-Activity client failures (access denied, blocked by EDR, etc.)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5858} |
  Select-Object TimeCreated, Message

# 7. Command-line audit trail (requires 4688 command-line auditing enabled) —
#    shows WmiPrvSE.exe -> cmd.exe/powershell.exe/raw command as a chain
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'wmiprvse\.exe' }
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — the fleet-level
# signal for wmiexec is a burst of WmiPrvSE.exe spawns across many hosts in a tight
# window, not any single host's filesystem artifact (which may not exist at all
# if the operator used -silentcommand for the mass-execution scenario in 02)
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'ParentImage:.*WmiPrvSE\.exe' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}
} -ErrorAction SilentlyContinue

# Group by time window to spot a burst (mass lateral movement / ransomware staging)
# vs. isolated single-host use
$results | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10 Count, Name

$results | Export-Csv -Path .\wmiexec_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

For environments with a network sensor (Zeek, Suricata, etc.) — the DCOM/RPC channel is the one signal that's never optional for this tool, making it especially valuable in segments without endpoint logging:

```
# Zeek: DCE/RPC bind + operations against the WMI interface, over the RPC
# endpoint-mapper-negotiated dynamic port — present in EVERY wmiexec session,
# including -nooutput/-silentcommand ones that leave no SMB trace at all
zeek-cut ts id.orig_h id.resp_h endpoint operation < dce_rpc.log | grep -iE 'IWbem|135'

# Zeek: SMB tree-connects to ADMIN$/C$ followed by a tiny file write/read/delete —
# only present when output capture was enabled
zeek-cut ts id.orig_h id.resp_h path < smb_mapping.log | grep -iE 'ADMIN\$|C\$'
```

## Remediation

**Capture evidence first** — export the WMI-Activity 5857 records, the Sysmon 1 `WmiPrvSE.exe` parent-child chain, and (if present) the `__<timestamp>` file's hash before touching anything, since remediation destroys the artifacts this note is built around.

```powershell
# Kill any live command process still hanging off WmiPrvSE.exe, if caught live
Get-CimInstance Win32_Process -Filter "ParentProcessId = $wmiprvsePid" |
  Where-Object { $_.Name -notin @('WmiPrvSE.exe') } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Remove the output-relay file if it's still present (usually already deleted by the tool itself)
Remove-Item "C:\Windows\__<timestamp>" -Force -ErrorAction SilentlyContinue
```

Real hardening — beyond evidence capture:

- **Restrict WMI/DCOM remote access** to a management subnet via the built-in "Windows Management Instrumentation (WMI-In)" firewall rule group, rather than leaving it open host-wide.
- **Restrict DCOM launch/activation permissions** (`dcomcnfg.exe` → Component Services → *My Computer* → COM Security) to only the accounts/groups that legitimately need remote WMI access — the same admin-equivalence requirement this tool depends on is also the lever to shrink its blast radius.
- **Enable and centrally collect the WMI-Activity Operational log** — it's not enabled/forwarded by default in many environments, and it's this tool's single richest signal.
- **Enable command-line process auditing** (Security 4688 with command-line logging) and, where PowerShell is in scope, **PowerShell Script Block Logging + Module Logging** — the `-shell-type powershell` variant is otherwise materially harder to recover in plaintext.
- **Reduce standing local-admin exposure** (LAPS, tiered administration) — `wmiexec.py`, like `psexec.py`, is entirely gated on the authenticating account already being a local administrator on the target; shrinking that population shrinks the set of hosts any recovered credential can reach.
