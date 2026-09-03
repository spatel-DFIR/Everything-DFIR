# Rclone — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

Rclone exposes a real, multi-dimensional evasion surface: **renaming the binary** (defeats image-name matching, not PE metadata), **using a custom `--config` path or the connection-string/no-config-file syntax** (defeats a default-path config-file hunt, but pushes credentials into the command line instead), **encrypting the config with `RCLONE_CONFIG_PASS`** (defeats reading stored credentials, not the config file's existence), and **`--bwlimit` throttling** (defeats a volume/threshold-based network anomaly hunt). No single evasion option defeats all of the signals below — build hunts on the top of this table first.

| Rank | Signal | Survives binary rename? | Survives custom `--config`/connection-string (no default config file)? | Survives `RCLONE_CONFIG_PASS` encryption? | Survives `--bwlimit` throttling? |
|---|---|---|---|---|---|
| 1 (strongest) | Command-line content match on rclone's own verb/syntax vocabulary (`copy`/`sync`/`move`, `remote:path`, `--transfers`, `--bwlimit`, backend names) via Sysmon 1 / Security 4688 | ✅ Yes — the verbs/syntax don't change | ✅ Yes — connection-string syntax is *more* visible in the command line, not less | ✅ Yes — command-line logging is unrelated to config encryption | ✅ Yes — throttling flags are themselves part of the matched command line |
| 2 | PE metadata match — `OriginalFileName == rclone.exe` / `Description == "Rsync for cloud storage"` (Sysmon 1's PE fields, or an EDR product surfacing the same field) | ✅ Yes — this is specifically the field renaming doesn't touch | ✅ Yes | ✅ Yes | ✅ Yes |
| 3 | Default-path `rclone.conf` file creation/modification (Sysmon 11 / File Integrity Monitoring) | ✅ Yes — path doesn't depend on binary name | ❌ **No** — a custom `--config` path moves the file elsewhere (still findable if hunted by *content*/extension rather than fixed path), and the connection-string/no-config-file evasion creates **no config file at all** | ✅ Yes (the file still exists, just encrypted) | ✅ Yes |
| 4 | Config file **content** revealing stored (obscured or plaintext) destination credentials | ✅ Yes | ⚠️ Partial — depends on the config file existing at all | ❌ **No** — encrypted config content is unreadable without the password | ✅ Yes |
| 5 | Network destination match — TLS SNI/destination domain against known cloud-storage providers | ✅ Yes — network behavior is unaffected by the binary's filename | ✅ Yes | ✅ Yes | ✅ Yes — SNI is visible regardless of transfer speed |
| 6 (weakest) | Volume/threshold-based network anomaly detection (large sustained outbound transfer) | ✅ Yes | ✅ Yes | ✅ Yes | ❌ **No** — the entire point of `--bwlimit` is defeating exactly this kind of threshold-based alerting |
| — | Image-name-only match (`rclone.exe`, no PE-metadata check) | ❌ **No** — trivially defeated by rename, and renaming is now the documented norm (`svchost.exe`, `sihosts.exe`, `TrendFileSecurityCheck.exe`), not the exception | ✅ Yes | ✅ Yes | ✅ Yes |

**Build hunts on ranks 1–2 first.** They're unaffected by every evasion option rclone actually exposes and require no assumption about which config-file/encryption choices an operator made. Rank 6 (raw volume thresholds) is the weakest and most easily defeated signal in this table — treat it as supporting context, never a primary detection.

## Hunting on Source

```powershell
# 1. Sysmon Process Create — match on rclone's distinctive verb/syntax
#    vocabulary, independent of the image name used (catches renamed
#    binaries). Pattern adapted from SigmaHQ's "PUA - Rclone Execution"
#    rule (id e37db05d-d1f9-49c8-b464-cee1a4b11638).
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '\bcopy\b.*\w+:|--config |--bwlimit|--multi-thread-streams|--transfers \d|--ignore-existing|--auto-confirm' }

# 2. Same, anchored on PE metadata specifically — the strongest single
#    check against a renamed binary
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'OriginalFileName:\s*rclone\.exe' -or $_.Message -match 'Description:\s*Rsync for cloud storage' }

# 3. Security 4688, if command-line auditing is enabled
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\bcopy\b.*\w+:|\bsync\b.*\w+:|--bwlimit|--config ' }

# 4. rclone.conf at its default path — a real artifact whenever a saved
#    remote (not the connection-string evasion) was used
Get-ChildItem -Path "$env:APPDATA\rclone\rclone.conf","$env:USERPROFILE\.config\rclone\rclone.conf" -ErrorAction SilentlyContinue |
  Select-Object FullName, LastWriteTime

# 5. PowerShell/console history for the invocation, an RCLONE_CONFIG_PASS
#    assignment, or an embedded connection-string credential
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'rclone|RCLONE_CONFIG_PASS|access_key_id|secret_access_key'

# 6. Outbound connections consistent with an active or recent transfer
Get-NetTCPConnection -RemotePort 443,22,21,80 -State Established -ErrorAction SilentlyContinue
```

## Hunting on Target

Per `04 - Target Evidence.md`, target-side visibility here depends entirely on whether the source data lived on a separate, audited file server and whether the destination happens to be infrastructure the victim organization actually owns — neither is guaranteed:

```powershell
# 1. If object-access auditing was already enabled on a file server rclone
#    read from (non-default — verify before relying on it), a burst of
#    4663/5145 events from one account/host against a broad set of files
#    in a short window is the closest equivalent to a "target" signal
#    this tool produces
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663,5145} -ErrorAction SilentlyContinue |
  Group-Object -Property { $_.Properties[1].Value } |  # group by subject account
  Where-Object { $_.Count -gt 100 }

# 2. If the destination is a cloud account the victim organization itself
#    owns, that provider's own audit log (AWS CloudTrail PutObject, Azure
#    Storage/Entra sign-in logs, Google Workspace admin audit) is real
#    evidence — check tenant/account ownership first before assuming this
#    is unavailable
```

For anything beyond this, correlate back to `03 - Source Evidence.md`'s far stronger source-side process/command-line/config-file signals — network/target-side evidence alone tells you *that* data left and roughly *where to*, not what was actually inside it.

## Fleet-Wide Sweep

```powershell
# Sweep across the estate for Sysmon 1 events carrying rclone's
# distinctive command-line vocabulary or PE metadata, catching renamed
# binaries via the metadata check even where the image-name check misses
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Message -match 'OriginalFileName:\s*rclone\.exe' -or
      $_.Message -match '\bcopy\b.*\w+:|\bsync\b.*\w+:|--bwlimit|--multi-thread-streams'
    } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='CommandLine';e={($_.Message | Select-String -Pattern 'CommandLine:\s*(.+)').Matches.Groups[1].Value}}
} -ErrorAction SilentlyContinue

$results | Sort-Object TimeCreated | Export-Csv -Path .\rclone_sweep_results.csv -NoTypeInformation

# Also sweep for the config-file artifact directly, independent of any
# process-creation event retention window — SigmaHQ's "Rclone Config
# File Creation" rule (id 34986307-b7f4-49be-92f3-e7a4d01ac5db) targets
# exactly this path pattern
Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-ChildItem -Path "$env:APPDATA\rclone\rclone.conf","$env:USERPROFILE\.config\rclone\rclone.conf" -ErrorAction SilentlyContinue
} -ErrorAction SilentlyContinue
```

**Published detections worth knowing directly (verified live against each source):**

| Source | What it checks |
|---|---|
| SigmaHQ `proc_creation_win_pua_rclone_execution.yml` (id `e37db05d-...`, NCC Group authors) | Image ending in `rclone.exe` **or** PE `Description` of "Rsync for cloud storage", combined with command-line terms (`copy`, `sync`, `config`, `lsd`, `mega`, `pcloud`, `ftp`, `--ignore-existing`, `--auto-confirm`, `--transfers`, `--multi-thread-streams`, `--no-check-certificate`) |
| SigmaHQ `file_event_win_rclone_config_files.yml` (id `34986307-...`, NCC Group) | File creation matching `...\.config\rclone\...` under a user profile |
| Splunk `detect_renamed_rclone` (Michael Haag) | `Processes.original_file_name = rclone.exe AND Processes.process_name != rclone.exe` — a direct PE-metadata-vs-image-name mismatch hunt, the cleanest single query for the renamed-binary case specifically |
| Elastic "Potential Data Exfiltration via Rclone" | `process.name : rclone.exe OR process.pe.original_file_name : rclone.exe`, `process.args : (copy, sync)`, explicitly excluding the tool's own known-legitimate install path (`Program Files\rclone\...`) to reduce false positives from sanctioned enterprise use |

## Remediation

**Capture evidence first** — pull the Sysmon 1 events (full command line, PE metadata), any recoverable `rclone.conf`, and note the destination `remote:path`/domain before killing the process or isolating the host. Per `04`, the destination provider itself is usually outside the victim's visibility entirely — the source-side artifacts captured here may be the only complete record of what left and where it went.

Rclone itself isn't the thing to fix — it's a legitimate tool being run with credentials/access the operator already obtained. The durable controls target the execution and egress paths, not the binary:

```powershell
# Application control (AppLocker/WDAC): block execution of unsigned or
# unexpected rclone binaries by publisher/hash where rclone isn't a
# sanctioned enterprise tool — note this does NOT catch a renamed copy
# unless the control also inspects PE metadata rather than just image
# name/path, mirroring the same weakness the Hunting Priority table
# documents for detection

# Egress filtering: route outbound HTTPS through an authenticated proxy
# that only permits the organization's OWN sanctioned cloud-storage
# tenants (e.g. Microsoft 365 tenant restrictions, a CASB policy) rather
# than allowlisting entire provider domains outright — defeats the
# "attacker's own personal cloud account" pattern that dominates real
# incident reporting per 04's finding, without breaking legitimate use
# of the same providers under the corporate tenant

# Enable command-line process-creation auditing if not already present —
# per the Hunting Priority table, this is the one signal every evasion
# option rclone exposes fails to defeat:
# Computer Configuration > Administrative Templates > System > Audit
# Process Creation > "Include command line in process creation events" = Enabled
# (Sysmon, if deployed, already captures this regardless of this policy)

# Where sensitive file shares exist, enable Object Access auditing
# (4663/5145) on those shares specifically — closes the target-side gap
# 04 - Target Evidence.md documents, at the cost of real log volume, so
# scope it to genuinely sensitive shares rather than enabling broadly
```

Deploying Sysmon with command-line/PE-metadata capture (if not already present) is the single highest-leverage move here — per the priority table, it's the only signal class unaffected by every evasion option this tool actually exposes, and unlike egress filtering or object-access auditing it requires no assumption about tenant ownership or pre-existing audit configuration to be useful immediately.
