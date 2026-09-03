# LOLBins — Netcat / Ncat / Socat — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

These three tools expose more independent evasion knobs than most single-binary entries in this module — renaming, recompiling from source, TLS-wrapping, and proxy-routing are all realistic operator choices. Rank hunts by what survives which:

| Rank | Signal | Survives binary rename/recompile? | Survives TLS (`--ssl`/`OPENSSL`)? | Survives Sysmon Event 3 not being enabled? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | **Parent-child process relationship** — a shell (`cmd.exe`, `powershell.exe`, `/bin/sh`, `/bin/bash`) whose `ParentImage`/parent PID is *any* unrecognized or network-connected binary | ✅ Yes — the relationship is mechanical to what `-e`/`--sh-exec`/`EXEC:` does, independent of the parent binary's name | ✅ Yes — encryption changes what's *inside* the connection, not the local process-tree relationship | ✅ Yes — this is Sysmon 1, not Sysmon 3 | The single most reliable signal in this note. A shell process whose parent is not a known shell/terminal/service host is inherently anomalous on almost any endpoint |
| 2 | Zeek/NetFlow connection-shape anomaly — long-lived, small-packet, bidirectional flow to a previously-unseen or non-standard-port destination | ✅ Yes | ✅ Yes — flow metadata doesn't require decrypting the payload | ✅ Yes — independent of Sysmon entirely | The best fallback when host-level telemetry is thin or absent; catches the connection even when nothing on the endpoint was logged |
| 3 | Static file signature / AV-EDR "hacktool"/PUA flag on the binary itself | ❌ No — trivially defeated by renaming or recompiling from source under a different name | N/A (pre-connection) | N/A | Materially stronger for these three tools than for a mainstream utility like WinRAR (see `04`'s Endpoint Security Product Signatures) precisely *because* they're commonly signature-flagged outright — but still the weakest layer against a competent operator |
| 4 | Sysmon Event 3 (Network Connect) command-line/process correlation | ✅ Yes | ✅ Yes (metadata only) | ❌ **No — disabled by default in Sysmon**, must be explicitly configured | High-value where enabled, but this note's `04` flags explicitly that it is off out of the box — never assume it's present without confirming the deployed config |
| 5 | TLS handshake fingerprint (JA3/JA3S) against Ncat's ephemeral self-signed cert or socat's `OPENSSL` stack | ⚠️ Partial — survives rename, but is entirely defeated if the operator supplies their own `--ssl-cert`/`cert=` rather than relying on Ncat's auto-generated ephemeral cert (which socat's `OPENSSL` requires by design in the first place — see `01`'s asymmetry note) | This *is* the TLS-specific signal | ✅ Yes — pulled from the handshake, not process telemetry | Best treated as corroborating evidence alongside rank 1-2, not a standalone detection — the asymmetry between Ncat's convenient-but-fingerprintable default and socat's mandatory-but-unfingerprinted custom cert means this signal's reliability genuinely depends on which of the two tools and which specific invocation was used |
| 6 (weakest) | Bare process-creation/presence of `nc`/`ncat`/`socat` | ❌ No | N/A | N/A | High false-positive rate anywhere these tools are legitimately installed for troubleshooting (see `02`'s Legitimate-Baseline Sysadmin Use). Never hunt on this alone |

**Build hunts on ranks 1-2 as primary detections — both survive every operator-side evasion covered in this note.** Rank 3 and 5 are valuable corroboration, not standalone triggers.

## Hunting on Source

Source-side hunting means looking at the attacker/pivot-host role described in `03 - Source Evidence.md` — most relevant in a red-team retrospective, a recovered pivot host during a real intrusion, or auditing your own infrastructure for policy compliance:

```sh
# Currently active or recently-closed nc/ncat/socat listeners on a host you control/administer
ss -tulpn | grep -E 'nc|ncat|socat'

# Linux auditd, if exec auditing is configured
ausearch -x nc -x ncat -x socat -i

# Shell history sweep across accounts on a suspected pivot host (requires access)
for u in /home/*; do grep -E 'nc |ncat |socat ' "$u/.bash_history" 2>/dev/null; done
```

See this module's `Sliver/`, `PowerShell Empire/`, and other C2-framework folders for how each framework's own task-history logging captures a tasked shell command, where one of these tools was launched via C2 tasking rather than typed interactively.

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE: a shell process whose parent is an unrecognized/
#    unexpected binary — the core rank-1 signal, Windows side
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match '(?i)\bImage:.*\\(cmd|powershell|pwsh)\.exe\b' -and
    $_.Message -notmatch '(?i)ParentImage:.*\\(explorer|cmd|powershell|pwsh|WindowsTerminal|conhost|services|wininit)\.exe\b'
  } |
  Select-Object TimeCreated,
    @{n='Image';e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='ParentImage';e={($_.Message -split "`n" | Select-String '^ParentImage:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String '^CommandLine:').ToString()}}

# 2. Direct name/hash-based check for the three binaries themselves — rank 6,
#    corroboration only, expect false positives on any host with legitimate use
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)\b(nc|ncat|socat)\.exe\b' }

# 3. Sysmon 3 (Network Connect) correlation — ONLY useful if this event type
#    was explicitly enabled in the deployed Sysmon config (off by default)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '(?i)\b(nc|ncat|socat)\.exe\b' }

# 4. Fallback if Sysmon isn't deployed but native command-line auditing is:
#    Security 4688 for the same rank-1 parent-child anomaly
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match '(?i)\b(cmd|powershell)\.exe\b' }
```

```sh
# Linux equivalent of the rank-1 parent-child hunt, via auditd
ausearch -k exec_watch -i | awk '
  /type=EXECVE/ { cmd=$0 }
  /type=SYSCALL/ && /exe="\/bin\/(sh|bash|dash)"/ { print cmd, $0 }
'

# Direct process-tree check on a live/suspected host
ps -eo pid,ppid,comm,args | awk '$3 ~ /^(sh|bash|dash)$/ { print }' | \
  while read pid ppid rest; do
    parent=$(ps -o comm= -p "$ppid" 2>/dev/null)
    echo "$rest  <- parent: $parent ($ppid)"
  done | grep -viE 'parent: (bash|sh|systemd|sshd|login|tmux|screen)'
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  $anomalousParents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Message -match '(?i)\bImage:.*\\(cmd|powershell|pwsh)\.exe\b' -and
      $_.Message -notmatch '(?i)ParentImage:.*\\(explorer|cmd|powershell|pwsh|WindowsTerminal|conhost|services|wininit)\.exe\b'
    }
  $toolPresence = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '(?i)\b(nc|ncat|socat)\.exe\b' }

  [PSCustomObject]@{
    Host                  = $env:COMPUTERNAME
    AnomalousParentCount  = ($anomalousParents | Measure-Object).Count
    ToolPresenceCount     = ($toolPresence | Measure-Object).Count
    LatestAnomalousHit    = ($anomalousParents | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.AnomalousParentCount -gt 0 -or $_.ToolPresenceCount -gt 0 } | Sort-Object LatestAnomalousHit -Descending

$results | Export-Csv -Path .\netcat_ncat_socat_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

```
# Zeek: long-lived, low-volume, bidirectional connections to previously-unseen
# or non-standard-port destinations — the connection-shape signature of an
# interactive shell rather than a bulk transfer or a brief -zv probe
zeek-cut ts id.orig_h id.resp_h duration orig_bytes resp_bytes < conn.log |
  awk '$4 > 300 && $5 < 100000 && $6 < 100000'   # tune thresholds to environment baseline

# Zeek ssl.log: JA3/JA3S fingerprint lookups against known Ncat/socat TLS-stack
# values, where a local baseline of "known good" JA3/JA3S exists to diff against
zeek-cut ts id.orig_h id.resp_h ja3 ja3s < ssl.log

# Proxy/firewall logs: outbound connections to non-standard high ports, or the
# same destination repeated across many hosts in a short window (fleet-wide signal)
```

## Remediation

**Capture evidence first** — the Sysmon 1 process-tree record (parent-child relationship and full command line), any Sysmon 3/Zeek `conn.log` entry for the connection itself, and a memory acquisition if the process is still live and the session was unencrypted (see `04`'s Memory Forensics section on session-content recovery) — before killing anything.

```powershell
# Kill the process if caught live
Get-Process -Name nc,ncat,socat -ErrorAction SilentlyContinue | Stop-Process -Force
```

```sh
# Linux equivalent
pkill -f 'nc |ncat |socat '
```

Address the underlying intrusion — whatever gained the code execution that launched the listener/shell in the first place — using that access vector's own dedicated tool folder in this module or the relevant `Windows/Threat Landscape and Playbooks/` playbook; this section covers only the network-tool step itself.

Real hardening — beyond evidence capture:

- **Enable Sysmon Event ID 3 (Network Connect) explicitly** — it is off by default, and per the Hunting Priority table above, its absence is the single biggest gap between what this note's hunts *could* see and what a default Sysmon deployment actually captures.
- **Enable process-creation command-line auditing** (Security 4688 with command-line logging, or deploy Sysmon) — without it, the full argument to `-e`/`--sh-exec`/`EXEC:` (and therefore what was actually executed) is invisible even when the process-creation event itself is captured.
- **Alert on the parent-child relationship, not the binary name** — per rank 1 in the priority table, this is the one signal that survives every evasion covered in this note; a shell process whose parent isn't a known shell/terminal/service host is worth investigating regardless of what the parent binary is named.
- **Constrain these binaries via AppLocker/WDAC on hosts with no legitimate need for them** — most server/DC-tier and non-admin endpoints have no genuine business reason to run `nc`/`ncat`/`socat`; given how commonly they're outright signature-flagged (see `04`), a default-deny policy on hosts without a documented troubleshooting need meaningfully shrinks the usable footprint.
- **Establish a JA3/JA3S baseline for the environment** — since Ncat's ephemeral self-signed certs and socat's `OPENSSL` stack produce TLS handshake fingerprints distinguishable from mainstream browser/server TLS libraries, a maintained baseline turns rank 5 in the priority table from a one-off curiosity into a repeatable detection.
- **Egress filtering on non-standard high ports** — since none of these tools enforce or expect a particular port (T1571), restricting egress to a known-necessary port set closes off a meaningful share of the reverse-shell/beacon use cases in `02` without touching legitimate low-port service traffic.
