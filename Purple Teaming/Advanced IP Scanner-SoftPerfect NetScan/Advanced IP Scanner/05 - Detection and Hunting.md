# Advanced IP Scanner — Detection and Hunting

Scope note: this tool has a narrow evasion surface — no Malleable-style customization, no encoders. The real operator choices that change what survives are **portable vs. installed mode**, **binary rename**, **GUI vs. console/scripted use**, and **post-use cleanup**. Rank every signal by which of those it survives.

## Contents
- [Hunting Priority — What Survives Which Evasion Choice](#hunting-priority--what-survives-which-evasion-choice)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target (Network Layer)](#hunting-on-target-network-layer)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — What Survives Which Evasion Choice

| Rank | Signal | Survives portable mode? | Survives rename? | Survives cleanup? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | Registry MRU (`IpRangesMruList`, `LastRangeUsed`, `locale_timestamp` under `HKEY_USERS\<SID>\SOFTWARE\Famatech\advanced_ip_scanner`) | ✅ Yes — written regardless of install method | ✅ Yes — keyed to the vendor/product name baked into the app, not the on-disk filename | ✅ Usually — uninstallers rarely touch per-user HKCU app-data keys | The single most durable artifact; per-user, so it also attributes to a specific profile/SID |
| 2 | Network-layer ARP-broadcast + multi-port-SYN burst from one source IP (Zeek/NSM) | ✅ Yes | ✅ Yes — network behavior is independent of the binary's name | ⚠️ Only if captured **at the time** — nothing to see in hindsight without a network sensor already logging | Requires network visibility infrastructure already in place; can't be reconstructed after the fact from host artifacts alone |
| 3 | PE metadata (`OriginalFileName`/`Description` fields via Sysmon 1) | ✅ Yes | ✅ Yes — embedded in the compiled binary, unrelated to on-disk filename | ❌ No new events post-deletion, but past events persist in the log | Defeated only by recompiling, which an operator cannot do against Famatech's closed-source build |
| 4 | Command-line pattern (`/portable` + `/lng` together, or `/r:`/`/s:`/`/f:` on the console binary) | N/A | N/A | N/A | Only fires for scripted/console use or an explicit portable-mode launch with language flag — pure interactive GUI use with no arguments won't trigger a command-line-based rule at all |
| 5 | Filesystem presence (Program Files / Portable path / Temp working folder) | ❌ No — portable mode never touches Program Files | N/A | ❌ Deleted trivially by the operator | Weakest signal, structurally blind to the tool's most evasive use case |
| 6 (context-dependent) | PUA/HackTool AV signature on the binary itself | ✅/❌ varies by product | ❌ No — signature checks file content, not name | N/A | Often set to detect-only given broad legitimate use — a policy decision, not a technical limitation |

**Build primary hunts on ranks 1-3** — they're the only signals that survive portable mode, rename, and typical post-use cleanup simultaneously. Rank 4 is valuable but only catches scripted/console use, not the default interactive GUI path. Rank 6 answers a policy question (is this tool part of your approved baseline at all) before any of the others matter.

## Hunting on Source

```powershell
# 1. Registry MRU trail — rank 1, survives portable mode, rename, and typical cleanup
Get-ChildItem 'Registry::HKEY_USERS\*\SOFTWARE\Famatech\advanced_ip_scanner' -ErrorAction SilentlyContinue -Recurse |
  Select-Object PSPath, Property

Get-ItemProperty 'Registry::HKEY_USERS\*\SOFTWARE\Famatech\advanced_ip_scanner\State' -ErrorAction SilentlyContinue |
  Select-Object LastRangeUsed, LastPortsUsed, IpRangesMruList, locale_timestamp

# Convert locale_timestamp (epoch) to a readable date
[DateTimeOffset]::FromUnixTimeSeconds($epochValue).UtcDateTime

# 2. PE metadata via Sysmon 1 — rank 3, survives rename
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'OriginalFileName:\s*advanced_ip_scanner' -or $_.Message -match 'Advanced IP Scanner' }

# 3. Command-line pattern for portable/console use — rank 4
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '/portable.*\s+/lng|/r:.*\s+/f:' }

# 4. Filesystem presence — rank 5, weakest, but cheap to check
Get-ChildItem 'C:\Program Files (x86)\Advanced IP Scanner\',
  "$env:LOCALAPPDATA\Programs\Advanced IP Scanner Portable\",
  "$env:LOCALAPPDATA\Temp\Advanced IP Scanner 2\" -ErrorAction SilentlyContinue -Recurse

# 5. Trojanized-installer indicator (01 - Overview.md) — check for the side-loaded DLL
Get-ChildItem 'C:\Program Files (x86)\Advanced IP Scanner\pcre.dll' -ErrorAction SilentlyContinue |
  Get-FileHash
# Compare against the known-malicious sample MD5 21cdd0a64e8ac9ed58de9b88986c8983 — a match means
# this install is the trojanized supply-chain variant, not a genuine operator-run copy
```

## Hunting on Target (Network Layer)

```
# Zeek — single source hitting many hosts on the same ports in a short window
# arp.log: high count of distinct target IPs replying to one source MAC within seconds
# conn.log: single source IP, ports {4899,3389,445,80,443,21}, dozens+ of distinct destinations,
#           short-lived connections, tight time window

# Example Zeek/conn.log-style pivot (adjust field names to your SIEM's Zeek ingestion schema)
index=zeek sourcetype=conn
| stats dc(dest_ip) as unique_targets, dc(dest_port) as unique_ports by src_ip, _time
| where unique_targets > 20 AND unique_ports >= 3
```

```powershell
# Per-host Sysmon 3 equivalent — a scanned host's own view of being probed
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -ErrorAction SilentlyContinue |
  Group-Object { ($_.Message | Select-String 'SourceIp:\s*(\S+)').Matches.Groups[1].Value } |
  Where-Object { $_.Count -gt 10 } |
  Select-Object Name, Count
```

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ErrorAction SilentlyContinue -ScriptBlock {
  $hits = [System.Collections.Generic.List[object]]::new()

  # Registry MRU trail across every profile on the box
  Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | ForEach-Object {
    $key = "$($_.PSPath)\SOFTWARE\Famatech\advanced_ip_scanner\State"
    if (Test-Path $key) {
      $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
      $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'registry-mru'; SID = $_.PSChildName; LastRange = $props.LastRangeUsed })
    }
  }

  # PE-metadata match regardless of filename
  Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $vi = (Get-Item $_.ExecutablePath -ErrorAction Stop).VersionInfo
      if ($vi.FileDescription -match 'Advanced IP Scanner') {
        $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'pe-metadata'; Path = $_.ExecutablePath })
      }
    } catch {}
  }

  $hits
}

$results | Group-Object Host | Sort-Object Count -Descending
$results | Export-Csv -Path .\ais_sweep_results.csv -NoTypeInformation
```

## Remediation

**Capture the registry MRU values before any remediation touches the profile** — `reg export HKU\<SID>\SOFTWARE\Famatech\advanced_ip_scanner .\ais_evidence.reg` preserves the full scan-history trail, since a subsequent uninstall/profile-cleanup pass may not remove it but a full profile wipe (common in incident response) will.

```powershell
# Pull the exported target-list file if it still exists — often the richest single artifact
Get-ChildItem -Path $env:USERPROFILE -Recurse -Include '*.xml','*.csv' -ErrorAction SilentlyContinue |
  Where-Object { (Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match 'Favorites|IPScanner' }

# If this host's own copy shows the trojanized-installer indicator (01 - Overview.md),
# treat it as a compromised endpoint in its own right, not just a scanning pivot —
# isolate before continuing standard IR steps
```

Block or allowlist-scope `advanced_ip_scanner.exe`/`advanced_ip_scanner_console.exe` via AppLocker/WDAC on hosts with no legitimate network-admin function, matched on PE metadata (`FileDescription`) rather than filename — the same rename-resistance rationale as `AnyDesk/05 - Detection and Hunting.md`'s remediation guidance. Where the tool is part of an approved admin toolkit, scope its legitimate use to specific admin accounts/jump hosts so an unexpected profile SID showing the registry trail is meaningful on its own.
