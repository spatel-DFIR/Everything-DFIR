# AnyDesk — Detection and Hunting

Scope note: this file hunts for exactly what `03 - Source Evidence.md` and `04 - Target Evidence.md` already document. AnyDesk's evasion surface is narrower than a customizable C2 framework's — there's no Malleable-style profile to rewrite network content — but it does expose three real operator choices that change what survives: **portable vs. installed mode**, **binary rename**, and **uninstall-after-use**. Rank every signal by which of those three it survives, not by treating every artifact as equally durable.

## Contents
- [Hunting Priority — What Survives Which Evasion Choice](#hunting-priority--what-survives-which-evasion-choice)
- [Hunting on Target](#hunting-on-target)
- [Hunting on Source (Where Recoverable)](#hunting-on-source-where-recoverable)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — What Survives Which Evasion Choice

| Rank | Signal | Survives portable mode? | Survives binary rename? | Survives uninstall/`--remove`? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | DNS/network connection to `*.net.anydesk.com`, TCP 80/443/6568 | ✅ Yes | ✅ Yes — network destination is independent of filename | ⚠️ Only if captured **at the time** — Zeek/proxy/DNS logs from before an uninstall still hold, but nothing new generates afterward | The one signal an operator cannot change without abandoning AnyDesk's own network entirely — this is why `01 - Overview.md`'s red-flag callout leads with it |
| 2 | Sysmon 1 `OriginalFileName: AnyDesk.exe` | ✅ Yes | ✅ Yes — this is the PE's own embedded metadata, unrelated to the on-disk filename | ❌ No new events after removal, but past events persist in the log | Structural — defeating this requires recompiling the binary, which an operator cannot do against a closed-source, Authenticode-signed vendor product |
| 3 | Trace files (`ad.trace`, `connection_trace.txt`, `ad_svc.trace`, `file_transfer_trace.txt`) | ✅ Yes (`ad.trace`/`connection_trace.txt` write even in portable mode); ❌ `ad_svc.trace` needs installed mode | N/A — these log session content, not the invoking filename | ❌ **No** — `--remove` uninstalls the application but does not delete the data folder/trace files; however an operator who separately deletes that folder removes this evidence entirely, unlike event logs | Rich content (source IP, auth method, file-transfer byte counts) but the single most fragile signal against a deliberate cleanup pass |
| 4 | System 7045 (service install), registry (`HKLM\SYSTEM\...\Services\AnyDesk`, `HKLM\SOFTWARE\AnyDesk`) | ❌ **No — does not exist at all in portable mode** | N/A | ✅ 7045 already logged, survives; registry keys are removed by `--remove` itself | Strongest **only** against installed-mode deployments; structurally blind to the portable-mode use case this tool is specifically documented as being abused for |
| 5 | Endpoint security product flag on the binary itself | ❌ Mostly no — legitimate vendor signature is allowlisted by design | ❌ No — rename doesn't change the signature check outcome either way | N/A | Only productive against the narrow, verified exception: pre-8.0.8 clients carrying the Feb-2024-compromised certificate, or pre-9.0.1 clients vulnerable to CVE-2024-12754 |
| 6 (weakest standalone) | Presence of AnyDesk anywhere in the environment at all | ✅/❌ depends entirely on whether your org has a legitimate baseline | N/A | N/A | Per CISA's own Akira-advisory framing: worthless as a standalone signal if your org runs AnyDesk legitimately, but the **single most productive signal** if it isn't part of your approved tool baseline at all — block outright via AppLocker/WDAC in that case |

**Build primary hunts on ranks 1-2 wherever you have DNS/Zeek/Sysmon visibility — they're the two signals that survive all three evasion choices simultaneously.** Rank 3 is usually available and rich but is the first thing a careful operator's post-engagement cleanup removes. Rank 4 is strong evidence of an *installed* deployment specifically but tells you nothing about a portable-mode intrusion. Rank 6 is a policy question, not a technical hunt — answer it first, since it reframes every other rank's confidence.

## Hunting on Target

```powershell
# 1. DNS/network destination — rank 1, survives portable mode and rename
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'net\.anydesk\.com' }

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match ':(80|443|6568)\b' }

# 2. OriginalFileName PE metadata — rank 2, survives rename
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'OriginalFileName:\s*AnyDesk\.exe' }

# 3. Trace files on disk — rank 3, rich but fragile to deliberate cleanup
Get-ChildItem -Path "$env:APPDATA\AnyDesk", "$env:PROGRAMDATA\AnyDesk" -ErrorAction SilentlyContinue -Recurse |
  Where-Object { $_.Name -match 'ad\.trace|ad_svc\.trace|connection_trace\.txt|file_transfer_trace\.txt' }

# Parse connection_trace.txt for inbound sessions and auth method used
Get-Content "$env:PROGRAMDATA\AnyDesk\connection_trace.txt" -ErrorAction SilentlyContinue |
  Select-String 'Incoming|Passwd|Token|REJECTED'

# 4. Installed-mode-only signals — rank 4, blind to portable-mode use
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'AnyDesk' }
Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\AnyDesk' -ErrorAction SilentlyContinue
Get-Item 'HKLM:\SOFTWARE\AnyDesk' -ErrorAction SilentlyContinue

# 5. Feb-2024-compromised-certificate window and pre-CVE-2024-12754 patch level —
#    rank 5, the one case where the vendor signature itself is a productive signal
Get-WmiObject Win32_Process -Filter "Name='AnyDesk.exe'" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.ExecutablePath
    $ver = (Get-Item $_.ExecutablePath).VersionInfo.ProductVersion
    [pscustomobject]@{ Path = $_.ExecutablePath; Version = $ver; CertThumbprint = $sig.SignerCertificate.Thumbprint }
  }
# Compare Version against the 7.0.15+/8.0.8+ (cert incident) and 9.0.1+ (CVE-2024-12754) fixed thresholds

# 6. CVE-2024-12754 artifact — unexplained junction/reparse point under Temp
#    coinciding with an AnyDesk session-initiation timestamp
fsutil reparsepoint query "C:\Windows\Temp\<suspected-filename>"
```

## Hunting on Source (Where Recoverable)

Per `03 - Source Evidence.md`'s reframe, this only applies where a genuine operator-side/jump-box host is in scope — otherwise the target-side hunts above already capture the best available source-attribution data (the `External address` field in `ad.trace`, the `connection_trace.txt` `Incoming` entries).

```powershell
# Same artifact catalog as Hunting on Target, run against the suspected jump-box host —
# remember connection_trace.txt on THIS host only shows sessions where it was the
# receiving end, not sessions it initiated outbound (03 - Source Evidence.md)
Get-Content "$env:APPDATA\AnyDesk\ad.trace" -ErrorAction SilentlyContinue |
  Select-String 'External address'

# Command-line history for scripted outbound connections/credential-setting —
# note --set-password/--with-password values appear in full (01 - Overview.md)
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue |
  Select-String 'AnyDesk|--with-password|--set-password|--get-id'
```

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ErrorAction SilentlyContinue -ScriptBlock {
  $hits = [System.Collections.Generic.List[object]]::new()

  # Rank 1/2: any AnyDesk process by PE metadata, regardless of filename
  Get-WmiObject Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $vi = (Get-Item $_.ExecutablePath -ErrorAction Stop).VersionInfo
      if ($vi.OriginalFilename -eq 'AnyDesk.exe') {
        $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'anydesk-pe-metadata'; Path = $_.ExecutablePath; Version = $vi.ProductVersion })
      }
    } catch {}
  }

  # Rank 3: trace-file presence (portable OR installed)
  Get-ChildItem "$env:APPDATA\AnyDesk", "$env:PROGRAMDATA\AnyDesk" -ErrorAction SilentlyContinue -Recurse |
    Where-Object { $_.Name -match 'trace|connection_trace' } | ForEach-Object {
      $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'trace-file'; Path = $_.FullName; LastWrite = $_.LastWriteTime })
    }

  # Rank 4: installed-mode service/registry
  if (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\AnyDesk' -ErrorAction SilentlyContinue) {
    $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'installed-service' })
  }

  $hits
}

# A host hit on multiple ranks (PE-metadata match + a trace file with a recent
# LastWriteTime + no matching change-management ticket) is a far stronger
# candidate than a bare filename/process-name grep alone
$results | Group-Object Host | Sort-Object Count -Descending
$results | Export-Csv -Path .\anydesk_sweep_results.csv -NoTypeInformation
```

Cross-reference every hit against the organization's own approved AnyDesk baseline (deployment method, expected ID/Alias set, GPO-managed install path) before triage — per CISA's Akira-advisory guidance, presence alone (rank 6 above) means nothing without that context.

## Remediation

**Capture evidence before uninstalling or isolating.** Running `--remove` or deleting the install directory destroys exactly the richest artifact this note covers — the trace-file set (`04 - Target Evidence.md`) — while the underlying event-log/Sysmon telemetry already generated survives regardless. Pull `ad.trace`/`ad_svc.trace`/`connection_trace.txt`/`file_transfer_trace.txt` from the data folder, Sysmon 1/3/11/22, System 7045, and (if installed mode) the registry service key **before** touching the host.

```powershell
# Immediately revoke persistent unattended access rather than waiting for a
# full uninstall cycle — invalidates every previously-issued session token
# (01 - Overview.md's token model)
echo "" | AnyDesk.exe --set-password    # blank/rotate, or:
AnyDesk.exe --remove-password

# Confirm patch level against both verified vulnerability thresholds
# (Get-Item $path).VersionInfo.ProductVersion -ge 8.0.8 (cert incident)
# and -ge 9.0.1 (CVE-2024-12754)

# If AnyDesk is not part of the organization's approved tool baseline at all,
# block outright rather than only monitoring:
New-CIPolicy / AppLocker rule denying AnyDesk.exe by OriginalFileName/publisher
# (per CISA's Akira-advisory recommendation to block via AppLocker/WDAC when
# an RMM tool isn't part of the expected baseline)

# If it IS approved and legitimately deployed, tighten the configuration
# rather than removing the tool:
#  - Enable the Access Control List (ACL) feature to whitelist authorized
#    IDs/aliases as the primary access control, per AnyDesk's own security
#    hardening guidance, rather than relying on password-only gating
#  - Enable two-factor authentication on Unattended Access
#  - Disable "Allow direct connections" in environments where forcing all
#    traffic through the relay (and therefore through a proxied, logged
#    path) is preferred over faster peer-to-peer sessions
```

Restrict outbound reachability to `*.net.anydesk.com` to only the hosts/user groups with an actual legitimate business need — since TCP 80/443/6568 egress is otherwise indistinguishable from ordinary web traffic at the port level alone, scoping *which hosts* can reach that destination at all is the most durable compensating control this note can offer, surviving portable mode, rename, and uninstall alike.
