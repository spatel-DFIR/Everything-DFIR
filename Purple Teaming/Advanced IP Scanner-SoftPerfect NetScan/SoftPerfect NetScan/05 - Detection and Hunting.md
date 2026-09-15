# SoftPerfect Network Scanner — Detection and Hunting

Scope note: NetScan's real evasion surface is wider than `Advanced IP Scanner/`'s — a genuinely documented CLI, config-file-driven silent operation, and a rename convention CISA has directly observed in the field (Black Basta's `Intel.exe`/`Dell.exe`). Rank signals by which of **rename**, **silent/`/hide` CLI use**, and **portable vs. installed deployment** they survive.

## Contents
- [Hunting Priority — What Survives Which Evasion Choice](#hunting-priority--what-survives-which-evasion-choice)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — What Survives Which Evasion Choice

| Rank | Signal | Survives rename (`Intel.exe`/`Dell.exe`)? | Survives `/hide` silent CLI? | Survives portable mode? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | PE metadata — `FileDescription`/`ProductName` = "Network Scanner" / "Application for scanning networks" via Sysmon 1 | ✅ Yes — embedded in the compiled binary | ✅ Yes — metadata is independent of any launch flag | ✅ Yes | Exactly the field CISA's Black Basta observation defeats at the filename level but not here — this is the rule verified in SigmaHQ's own `proc_creation_win_pua_netscan` |
| 2 | Target-side Security 4624/4634 + WMI-Activity 5857 correlation for authenticated deep-query hits | ✅ Yes — target event logs don't care what the source binary was named | ✅ Yes | ✅ Yes | Only fires for hosts that received a genuine WMI/registry query, not a plain unauthenticated sweep — narrower scope, but very high confidence when it fires |
| 3 | `netscan.xml`/`netscan.lic` presence next to the executable | ✅ Yes — regenerates regardless of binary name | ✅ Yes | ✅ Yes — written adjacent to a portable copy too | Rich (scan history, config) but trivially deleted by an operator who thinks to clean up |
| 4 | Command-line pattern (`/hide /auto:... /range:...` etc.) | N/A | ❌ **This is the evasion flag itself** — `/hide` suppresses the window, not the command line, so Sysmon 1 still captures the full argument string | N/A | Command-line logging still catches `/hide` invocations in full — the silent-mode flag doesn't hide from a defender with command-line visibility, only from a human watching the screen |
| 5 | Network-layer ARP/ICMP + protocol-diverse (WMI/SNMP/SSH) traffic signature | N/A | ✅ Yes — traffic pattern is unaffected by UI visibility | ✅ Yes | Strong corroboration, requires network-sensor visibility already in place |
| 6 (weakest) | Filesystem/install-path presence (`C:\Program Files\SoftPerfect Network Scanner\`) | ❌ **No — this is exactly what the rename+relocate evasion defeats**, per CISA's own documented `C:\Intel.exe` observation | N/A | ❌ Portable mode never uses this path at all | The evasion CISA specifically documented is built to beat this exact signal — don't rely on it alone |

**Build primary hunts on ranks 1-2** — PE metadata survives every evasion choice this tool exposes, and the target-side event correlation is independently verifiable without touching the source host at all. Rank 4's lesson is important on its own: `/hide` is a **UI-visibility** flag, not a logging-evasion flag — don't assume silent-mode use implies command-line invisibility too.

## Hunting on Source

```powershell
# 1. PE metadata via Sysmon 1 — rank 1, survives rename, /hide, and portable mode
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Network Scanner|Application for scanning networks' }

# 2. netscan.xml / netscan.lic presence — rank 3
Get-ChildItem "$env:APPDATA\SoftPerfect Network Scanner\", 'C:\', 'C:\Windows\Temp\' -ErrorAction SilentlyContinue -Recurse -Include 'netscan.xml','netscan.lic' -Depth 2

# 3. Command-line pattern — rank 4, /hide does NOT hide this from Sysmon
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '/hide|/auto:|/live:|/wolfile:|/mpass:' }

# Extract any /mpass: value captured on the command line — treat as compromised credential material
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Select-String '/mpass:(\S+)'

# 4. Known rename convention from CISA's Black Basta advisory — check root of C: for
#    innocuously-named executables that are actually netscan.exe by hash/metadata
Get-ChildItem 'C:\' -File -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match '^(Intel|Dell|nv|ns)\.exe$'
} | ForEach-Object {
  $vi = (Get-Item $_.FullName).VersionInfo
  if ($vi.FileDescription -match 'Network Scanner') { $_ }
}
```

## Hunting on Target

```powershell
# 1. Authenticated deep-query correlation — rank 2, survives every source-side evasion
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Logon Type:\s*3' } |
  Select-Object TimeCreated, @{n='Account';e={($_.Message | Select-String 'Account Name:\s*(\S+)').Matches.Groups[1].Value}},
                @{n='SourceIP';e={($_.Message | Select-String 'Source Network Address:\s*(\S+)').Matches.Groups[1].Value}}

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5857} -ErrorAction SilentlyContinue

# Join both on timestamp/source IP proximity to confirm a WMI query rode a specific
# authenticated logon session, rather than treating either event in isolation

# 2. Network-layer signature — same Zeek pattern as Advanced IP Scanner/, plus
#    protocol-diverse ports (135 WMI/RPC, 161 SNMP, 22 SSH, 445 remote registry)
#    from one source IP within the same short window
```

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ErrorAction SilentlyContinue -ScriptBlock {
  $hits = [System.Collections.Generic.List[object]]::new()

  # PE-metadata match regardless of filename/location — rank 1
  Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $vi = (Get-Item $_.ExecutablePath -ErrorAction Stop).VersionInfo
      if ($vi.ProductName -eq 'Network Scanner' -or $vi.FileDescription -match 'scanning networks') {
        $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'pe-metadata'; Path = $_.ExecutablePath })
      }
    } catch {}
  }

  # Root-of-C: rename convention — rank 6, but cheap and CISA-documented enough to check anyway
  Get-ChildItem 'C:\' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(Intel|Dell|nv|ns)\.exe$' } |
    ForEach-Object { $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'suspicious-root-binary'; Path = $_.FullName }) }

  # netscan.xml/lic presence — rank 3
  Get-ChildItem "$env:APPDATA\SoftPerfect Network Scanner\" -ErrorAction SilentlyContinue |
    ForEach-Object { $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'config-file'; Path = $_.FullName }) }

  $hits
}

$results | Group-Object Host | Sort-Object Count -Descending
$results | Export-Csv -Path .\netscan_sweep_results.csv -NoTypeInformation
```

## Remediation

**Capture before removing** — `netscan.xml` and any exported result file (especially a `.db` export) are the richest available artifacts and are trivially deleted by a departing operator; pull them first.

```powershell
# Preserve config/result artifacts before touching the host
Copy-Item "$env:APPDATA\SoftPerfect Network Scanner\netscan.xml" .\evidence\ -ErrorAction SilentlyContinue
Get-ChildItem 'C:\', 'C:\Windows\Temp\' -Include '*.db','*.xml','*.csv' -Recurse -Depth 2 -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'result|scan|netscan' }

# If a /mpass: value was captured on the command line (Hunting on Source, above),
# treat it as a disclosed credential and rotate/revoke it — it protected a config
# file, not the operator's actual operational credentials, but reuse across both
# is common enough to check
```

Block or scope `netscan.exe` and its documented alternate names (`nv.exe`, `ns.exe`) via AppLocker/WDAC matched on **PE metadata** (`ProductName`/`FileDescription`), not filename — the CISA-documented rename-to-`Intel.exe`/`Dell.exe` evasion exists specifically to beat a filename or path rule. Where the organization runs NetScan legitimately for IT asset inventory, scope its Credential Manager usage to a dedicated, tightly-audited service account rather than a general admin credential, so a WMI/registry 4624 hit from an unexpected source IP against that specific account is immediately actionable.
