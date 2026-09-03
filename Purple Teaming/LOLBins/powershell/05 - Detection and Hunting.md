# LOLBins — powershell.exe / pwsh.exe — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

This tool has more independent evasion/customization knobs than any other single tool in this module — cosmetic switches (`-WindowStyle Hidden`, `-NoLogo`, `-NoProfile`, `-NonInteractive`), an obfuscation switch (`-EncodedCommand`), a policy switch (`-ExecutionPolicy Bypass`), and two distinct content-scanning bypasses (AMSI patching, the Warning-level script-block heuristic bypass) — and, uniquely for this module, **most of its strongest signals are off by default and require the target's own prior administrative configuration**, not anything the operator can control. Rank hunts accordingly:

| Rank | Signal | Survives `-WindowStyle Hidden`/`-NoLogo`/`-NoProfile`/`-NonInteractive`? | Decodes `-EncodedCommand`? | Survives `-ExecutionPolicy Bypass`? | Survives AMSI bypass? | On by default? |
|---|---|---|---|---|---|---|
| 1 (strongest) | **Event 4104 — Script Block Logging** | ✅ Yes — none of the four cosmetic switches touch the logging pipeline (`01`'s red-flag principle) | ✅ **Yes** — captures content post-decode, the single biggest reason this outranks command-line capture | ✅ Yes — execution policy and logging are separate subsystems | ✅ Yes — AMSI bypass and Script Block Logging are architecturally independent, per `04`'s verified distinction | ❌ **No** — requires the `EnableScriptBlockLogging` registry value or GPO. Partial exception: an automatic Warning-level 4104 fires for scripts matching a hardcoded suspicious-string list even unconfigured, but that heuristic has its own documented reflection-based bypass (`02`) |
| 2 | **Event 400 (classic "Windows PowerShell" log) / Sysmon 1 / Security 4688** | ✅ Yes | ❌ No — captures the **raw** Base64 blob, requires manual decoding | ✅ Yes | ✅ Yes | ✅ **Yes for Event 400** (engine-lifecycle logging is on by default, no GPO needed, per `04`'s corroborated finding) — Sysmon 1 requires Sysmon deployed; 4688 command-line detail requires the "Include command line in process creation events" policy separately enabled |
| 3 | **PSReadLine history (`ConsoleHost_history.txt`)** | ✅ Yes | ❌ No — records whatever was literally typed, encoded or not | ✅ Yes | ✅ Yes | ✅ Yes for **interactive** sessions only — **does not apply at all** to any scripted/`-Command`/`-EncodedCommand`/`-File` invocation, which is how most real attacker automation runs. Also the one signal here an operator with file-system access can simply delete post-session (`02`) |
| 4 | **Transcription** | ✅ Yes | ✅ Yes — records plaintext output, though not necessarily the pre-decode command itself | ✅ Yes | ✅ Yes | ❌ No — requires GPO or a manual `Start-Transcript` call the operator controls (and can `Stop-Transcript`/never start in the first place) |
| 5 | **Network-layer UA string / destination reputation** | ✅ Yes | N/A (download-cradle scenarios only) | ✅ Yes | N/A | ✅ Yes, but ❌ trivially overridden — a single extra line in the operator's script (`$wc.Headers.Add(...)`) defeats it entirely, unlike `certutil`'s harder-to-suppress CryptnetUrlCache signal |
| 6 (weakest) | Bare `powershell.exe`/`pwsh.exe` process-creation presence | ❌ No signal either way | ❌ No | ❌ No | ❌ No | High false-positive rate on any estate — legitimate PowerShell execution is constant background noise. Never hunt on this alone |

**Build hunts on rank 1 wherever it's available — it is the only signal in this table that survives every operator-side evasion this note documents.** Where 4104 isn't enabled (the more common real-world case per `01`), rank 2's Event 400 is the genuine detection floor: it exists with zero configuration, but the analyst must manually Base64-decode any `-EncodedCommand` value found in it to recover the actual payload — the hunting commands below automate that step.

## Hunting on Source

Source-side hunting for this tool means pivoting through the layers described in `03 - Source Evidence.md` — the operator's own pre-staging machine (if any), attacker web infrastructure, or a chained tool's own task history — rather than a dedicated "PowerShell operator box":

```
# If attacker web-hosting infrastructure is ever recovered: grep access logs for
# .ps1/encoded-payload requests and PowerShell-pattern User-Agent strings
grep -E "WindowsPowerShell|\.ps1(\?|$)" access.log

# If a C2 server's task history is available (red-team retrospective, or recovered
# attacker infrastructure): search issued-command history for PowerShell invocation
# patterns across every chained tool this note cross-links to
grep -iE "powershell(\.exe)?.*(-enc|-encodedcommand|-nop|-w hidden|-windowstyle hidden)" c2_task_history.log
```

See `Purple Teaming/PowerShell Empire/03 - Source Evidence.md` and each chained tool's own `03 - Source Evidence.md` (e.g. `Purple Teaming/Impacket/wmiexec/03 - Source Evidence.md`) for framework-specific tasking-log structure rather than re-deriving it here.

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE, SURVIVES EVERY OPERATOR-SIDE EVASION: Script Block Logging,
#    already-decoded content — only useful if this was enabled on the estate
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{n='ScriptBlockText';e={$_.Properties[2].Value}} |
  Where-Object { $_.ScriptBlockText -match '(?i)downloadstring|downloadfile|invoke-expression|\biex\b|net\.webclient|reflection\.assembly|amsiutils|-enc(odedcommand)?\s' }

# 1a. Same query against pwsh's SEPARATE log — a hunt against only the line above
#     misses every PowerShell 7/pwsh-generated 4104 event entirely (04's finding)
Get-WinEvent -FilterHashtable @{LogName='PowerShellCore/Operational'; Id=4104} -ErrorAction SilentlyContinue

# 2. DETECTION FLOOR, ON BY DEFAULT: classic engine-lifecycle log, full but UNDECODED
#    command line — decode any -EncodedCommand/-enc value found here manually
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; Id=400} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{n='HostApplication';e={($_.Message -split "`n" | Select-String 'HostApplication=').ToString()}}

# Helper: decode a captured -EncodedCommand/-enc Base64 value found in step 2 or
# in a Sysmon 1 / Security 4688 CommandLine field
function Decode-PSEncodedCommand {
    param([Parameter(Mandatory)][string]$EncodedCommand)
    [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($EncodedCommand))
}

# 3. Sysmon 1 / Security 4688 — command-line-shape hunt for the switch combinations
#    documented in 01/02, independent of whether PS-specific logging is configured
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Message -match '(?i)(powershell|pwsh)(\.exe)?' -and
    $_.Message -match '(?i)-enc(odedcommand)?\s|-w(indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass|downloadstring|downloadfile'
  } |
  Select-Object TimeCreated,
    @{n='ParentImage';e={($_.Message -split "`n" | Select-String '^ParentImage:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String '^CommandLine:').ToString()}}

# 4. PSReadLine history — interactive sessions only, per rank 3's scope caveat
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'downloadstring|downloadfile|invoke-expression|\biex\b|amsiutils|frombase64string'

# 5. Transcription files, if the GPO was ever enabled — default location per 04
Get-ChildItem "$env:USERPROFILE\Documents\PowerShell_transcript.*.txt" -ErrorAction SilentlyContinue

# 6. Corroboration only — do NOT hunt on this alone (rank 6, weakest)
Get-Process -Name powershell, pwsh -ErrorAction SilentlyContinue
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate — the fleet-level
# signal is many hosts independently generating the same decoded 4104 content (or
# the same undecoded Event 400 command line) within a tight overall window
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  $sblHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '(?i)downloadstring|invoke-expression|\biex\b|amsiutils' }

  $classicHits = Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; Id=400} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '(?i)-enc(odedcommand)?\s|-w(indowstyle)?\s+hidden' }

  [PSCustomObject]@{
    Host                   = $env:COMPUTERNAME
    ScriptBlockLoggingOn   = [bool](Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    SBLHitCount            = ($sblHits | Measure-Object).Count
    ClassicLogHitCount     = ($classicHits | Measure-Object).Count
    LatestHit              = (@($sblHits) + @($classicHits) | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.SBLHitCount -gt 0 -or $_.ClassicLogHitCount -gt 0 } |
  Sort-Object LatestHit -Descending

$results | Export-Csv -Path .\powershell_sweep_results.csv -NoTypeInformation
```

The `ScriptBlockLoggingOn` column doubles as a **coverage audit** — hosts reporting `$false` are exactly the ones where this sweep's rank-1 signal is unavailable and where Event 400's undecoded command line is doing all the real work; prioritize enabling logging on those hosts going forward rather than assuming the sweep's absence of hits on them means absence of activity.

## Network-Layer Hunting

```
# Zeek: PowerShell-pattern User-Agent strings against any destination — weaker and
# more easily overridden than certutil's UA signal (rank 5 in the priority table),
# still worth a pass for cradle scenarios where the operator didn't bother masking it
zeek-cut ts id.orig_h id.resp_h host uri user_agent < http.log |
  grep -iE "WindowsPowerShell|Microsoft\.PowerShell"

# Any request for a .ps1 path, or an unusually large single-request response body
# fetched by a host with no other legitimate reason to pull scripts remotely
zeek-cut ts id.orig_h id.resp_h host uri < http.log | grep -iE "\.ps1(\?|$)"
```

## Remediation

**Capture evidence first** — export any available 4104 content (already-decoded, the highest-value artifact if present), the Event 400/Sysmon 1/Security 4688 command line (decode any `-EncodedCommand` value before it's lost), and any transcription files, before killing the process or altering configuration.

```powershell
# Kill the process if caught live
Get-Process -Name powershell, pwsh -ErrorAction SilentlyContinue | Stop-Process -Force

# Preserve the PSReadLine history file before anything else touches it — it may be
# the only record of an interactively-typed command an operator didn't bother
# encoding, and it's trivially deletable by anyone with file access (02)
Copy-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" "C:\Quarantine\" -ErrorAction SilentlyContinue

# Quarantine any stage-to-disk payload recovered from a Sysmon 11 event or a
# decoded download-cradle command
Move-Item "<RecoveredOutFilePath>" "C:\Quarantine\" -Force -ErrorAction SilentlyContinue
```

Address whatever the executed script actually did — credential theft, a C2 agent, a persistence mechanism — using that payload's own dedicated tool folder in this module (`Mimikatz/`, `PowerShell Empire/`, `Sliver/`, etc.) or the relevant `Windows/Threat Landscape and Playbooks/` playbook; this section covers only the PowerShell execution step itself.

Real hardening — beyond evidence capture:

- **Enable Script Block Logging and Module Logging estate-wide** — per the priority table, this is the only signal that survives every documented operator-side evasion, and per `01`/`04`'s core finding, it is very likely **not** already on. Verify with the fleet-wide sweep's `ScriptBlockLoggingOn` column before assuming coverage exists.
- **Register the `pwsh.exe`/PowerShell 7 event provider** (`$PSHOME\RegisterManifest.ps1`, elevated) on any host where PowerShell 7 is deployed — per `04`, this doesn't happen automatically the way it does for Windows PowerShell 5.1, and its absence silently blinds `PowerShellCore/Operational` logging entirely.
- **Enable command-line process auditing** (Security 4688 with command-line logging) or deploy Sysmon — without either, rank 2 in the priority table is degraded to bare process-name visibility with no argument detail.
- **Constrain via Constrained Language Mode / AppLocker / WDAC** where PowerShell isn't operationally needed for a given host role — reduces the tool's usable capability surface (blocks .NET reflection, COM access, and other techniques the reflective-loading/AMSI-bypass scenarios in `02` depend on) independent of logging posture.
- **Treat `-ExecutionPolicy Bypass` and `-WindowStyle Hidden` as command-line enrichment signals, not standalone findings** — per `01`'s explicit framing, execution policy was never a security boundary by Microsoft's own design intent, and window visibility has no bearing on logging; alerting on either alone without the surrounding context in `01`'s Legitimate vs. Abused table produces high false-positive volume against routine unattended automation.
- **Consider Protected Event Logging** (Windows 10+, documented in `about_Logging`/`about_Logging_Windows`) once Script Block Logging is enabled broadly — encrypts logged script content with a deployed public key so a compromised host's own local event log doesn't hand an attacker back their own captured payloads (or anyone else's) in plaintext.
