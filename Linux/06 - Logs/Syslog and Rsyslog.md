# Syslog and Rsyslog

The plain-text system logs are the oldest and most portable evidence source on Linux, and on many servers they're where cron, kernel, mail, and daemon activity actually lands. They're easy to read with standard tools, but that same simplicity means they're easy to tamper with — a `sed -i` can excise a line, a `truncate` can wipe the file — so pair every read with the tamper checks from the Logging Architecture note. The other thing to establish early is whether the host *forwards* syslog to a central collector, because that off-host copy may survive local wiping.

> 🔴 If logs are forwarded to a SIEM or central syslog server, the remote copy is often your source of truth — it survives even when the attacker clears the local files. Conversely, an attacker who *disabled* forwarding created a deliberate blind spot. Check the rsyslog config for `@`/`@@` forwarding rules early.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [The Core Text Logs](#the-core-text-logs)
- [Kernel Log and dmesg](#kernel-log-and-dmesg)
- [Facilities and Severities](#facilities-and-severities)
- [Remote and Central Logging](#remote-and-central-logging)
- [Hunting in Syslog](#hunting-in-syslog)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Broad triage of the general log
grep -Ei "error|failed|denied|segfault|kill|oom|refused" /var/log/syslog /var/log/messages 2>/dev/null

# Suspicious execution paths mentioned anywhere
grep -Ei "/tmp/|/dev/shm/|/var/tmp/|/run/user/" /var/log/syslog /var/log/messages 2>/dev/null

# Kernel anomalies
dmesg | grep -Ei "segfault|taint|module|denied|oom"

# Cron execution
grep -i CRON /var/log/syslog /var/log/cron 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Payload/exec surfaced by a service? | `grep -Ei "curl\|/dev/tcp\|base64" /var/log/syslog /var/log/messages` |
| What did cron actually run? | `grep -Ei "CRON.*CMD" /var/log/syslog /var/log/cron` |
| Kernel exploit / rootkit signal? | `dmesg -T \| grep -Ei "segfault\|Call Trace\|taint\|module"` |
| Removable media inserted (ingress/exfil)? | `grep -Ei "usb-storage\|sd[b-z]:\|SerialNumber" /var/log/kern.log*` |
| Is logging forwarded off-box? | `grep -E '@@?[^ ]+:[0-9]+' /etc/rsyslog.conf /etc/rsyslog.d/*` |
| Was a log rule set to **drop** activity? | `grep -REn "stop\|discard\|~\|omprog" /etc/rsyslog.d/` |
| Which file holds a given facility? | read `/etc/rsyslog.conf` routing rules |
| Rebuild a time window across rotations? | `zcat -f /var/log/syslog* \| awk '/pattern/'` |

## The Core Text Logs

Which file holds what varies by distro, and several categories (cron, kernel) land in different places on Debian vs RHEL. This map keeps you from missing evidence because you looked in the wrong file:

| File | Distro | Content |
|------|--------|---------|
| `/var/log/syslog` | Debian/Ubuntu | Everything except auth (general system) |
| `/var/log/messages` | RHEL/CentOS/Fedora | General system + kernel |
| `/var/log/kern.log` | Debian | Kernel messages |
| `/var/log/cron` | RHEL | Cron execution (Debian folds into syslog) |
| `/var/log/mail.log` / `maillog` | both | Mail (exfil-via-mail, relay abuse) |
| `/var/log/boot.log` | both | Boot-time service output |
| `/var/log/daemon.log` | Debian | Daemon/service messages |

```bash
# Read + search (include rotated/compressed)
grep -i "keyword" /var/log/syslog

zgrep -i "keyword" /var/log/syslog.*.gz 2>/dev/null

# Reconstruct chronological order across rotations
zcat -f /var/log/syslog* | sort
```

## Kernel Log and dmesg

The kernel log is where low-level intrusion evidence surfaces — exploit crashes (`segfault`), rootkit module loads, MAC denials, and USB device insertions. It's easy to overlook because it's noisy, but the high-value lines are specific.

```bash
# Ring buffer with human timestamps
dmesg -T

# Kernel log file (Debian)
cat /var/log/kern.log

# High-value kernel events
dmesg -T | grep -Ei "segfault|general protection|taint|module|apparmor|avc|usb|oom-kill"
```

🔴 Kernel `taint` and unexpected `module` loads tie directly to rootkits and driver persistence; `apparmor="DENIED"`/`avc` lines are the MAC layer catching an intrusion; and `usb`/`sd[b-z]` insertion lines are physical-media device history — useful when exfil or ingress happened over a USB drive.

## Facilities and Severities

Every syslog message carries a *facility* (its source subsystem) and a *severity*. Filtering on these lets you cut through noise to the alerts and errors.

| Severity | Level | |
|----------|-------|-|
| 0 | emerg | system unusable |
| 1 | alert | 🔴 |
| 2 | crit | 🔴 |
| 3 | err | errors |
| 4 | warning | |
| 5 | notice | |
| 6 | info | |
| 7 | debug | |

Common facilities: `auth`/`authpriv` (→ auth.log/secure), `cron`, `kern`, `mail`, `daemon`, `user`, `local0-7` (app-defined). Where each facility is routed is defined in `/etc/rsyslog.conf` and `/etc/rsyslog.d/*` — reading that routing tells you which file to look in for a given source.

## Remote and Central Logging

```bash
# Is this host forwarding logs somewhere? (@ = UDP, @@ = TCP)
grep -E '^\*\.\*|@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null

# Is it a collector (receiving)?
grep -Ei "imudp|imtcp|InputTCPServerRun|ModLoad" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null
```

🔴 A forwarding rule (`*.* @@siem.internal:514`) means a copy of these logs exists off-host — pull it, because it likely survived any local tampering. If forwarding that *should* be configured is missing or was recently removed, the attacker may have cut it to blind the SOC.

## Hunting in Syslog

```bash
# Command execution / payload behaviour surfaced by services
grep -Ei "curl|wget|base64|nc |bash -c|python -c|perl -e" /var/log/syslog /var/log/messages 2>/dev/null

# Service start/stop/enable around the incident
grep -Ei "systemd|started|stopped|enabled|failed" /var/log/syslog 2>/dev/null

# USB / device insertions (kernel)
grep -i "usb" /var/log/kern.log /var/log/syslog 2>/dev/null

# Reconstruct a time window across rotations
zcat -f /var/log/syslog* | awk '$0 ~ /Apr 23 1[0-8]:/'
```

Remember RFC3164 syslog lines carry **no year** — infer it from the file or its rotation date when building a timeline, and normalize to the host timezone you established in note 01.

## Deep Threat Hunts

rsyslog is attacker-editable config as much as it is a log — hunt both the data and the pipeline. *(seasoned-DFIR)*

```bash
# 1. rsyslog rules that DROP/redirect specific logs (suppressing attacker activity)
grep -REn "stop|discard|[[:space:]]~[[:space:]]|omfwd" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null

# 2. rsyslog executing a program per message (exec / persistence via omprog)
grep -REn "omprog|binary=" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null

# 3. Forged syslog entries via the `logger` command (fake noise / cover story)
grep -E "logger(\[|:)" /var/log/syslog /var/log/messages 2>/dev/null

# 4. What cron actually executed (the (user) CMD lines)
grep -Ei "CRON.*CMD" /var/log/syslog /var/log/cron 2>/dev/null

# 5. Removable-media insertion history incl. serials (ingress/exfil)
grep -Ei "usb-storage|sd[b-z]:|new (high|full)-speed USB|Manufacturer:|SerialNumber" /var/log/kern.log* /var/log/syslog* 2>/dev/null

# 6. Kernel exploitation signals (crash/oops = often an exploit)
dmesg -T | grep -Ei "segfault|general protection|BUG:|Call Trace|Oops|taint|module verification"

# 7. Reconstruct a time window across ALL rotations, in order
zcat -f /var/log/syslog* | awk '$0 ~ /Apr 23 1[0-8]:/'

# 8. Off-host forwarding target (the copy that likely survived)
grep -E '@@?[0-9a-zA-Z._-]+:[0-9]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null
```

**Hunt ideas:**

- **rsyslog rules are tamper surface.** A `stop`/discard action for a specific program silently drops that program's logs locally — read *every* file in `/etc/rsyslog.d/`.
- **`omprog` turns rsyslog into a program launcher** — rare but a real exec/persistence spot; the `binary=` path is what runs.
- **`logger`-forged entries** let an attacker inject misleading noise; cross-check suspect lines against the structured journal, which is harder to forge.
- **USB serials in `kern.log`** map physical-media history — pair device-insert times with the exfil/ingress window.
- **`dmesg` "Call Trace"/"BUG:"/oops** is a kernel crash, frequently an exploit — pivot to the taint check and memory.

## Getting Max Value

- **Rebuild a continuous timeline** with `zcat -f /var/log/syslog* | sort` across rotations — but remember RFC3164 lines have **no year** (infer from the file's rotation date).
- **`dmesg` may be root-only** (`dmesg_restrict=1`) — fall back to `/var/log/kern.log`.
- **Cross-check the journal.** If `ForwardToSyslog` is on, the journal mirrors syslog in a structured, harder-to-tamper form — lines an attacker `sed`-ed out of text may still be there.
- **The off-host copy is the integrity anchor** — if forwarding is configured, pull the collector's data.
- **Normalize to the host timezone** (note 01) — syslog is local time with no offset.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Auth / SSH / sudo detail | **Authentication and Login Records** |
| A structured, harder-to-forge copy of the same events | **Systemd Journal** |
| The cron job a `CRON … CMD` line ran | **Persistence → Cron and at Jobs** |
| Meaning of kernel `taint` / `module` loads | **SELinux/Kernel** (05), **Kernel Modules** (persistence), **Rootkit Detection** (11c) |
| The central copy that survived local wiping | **Logging Architecture** (central logging) |
| Consolidated anti-forensics hunt | **Anti-Forensics and Evidence Destruction** (13b) |

## Scenarios

- **Off-host copy saves the case:** forwarded syslog on a collector is intact when the local files were wiped.
- **Suppressed logging:** an rsyslog `discard` rule hides one program's activity locally — the pipeline was tampered, not the file.
- **`omprog` exec:** the rsyslog config runs an attacker-supplied program on every matching message.
- **USB exfil:** `kern.log` device-insert lines (with serial) bracket the data theft.
- **Kernel exploit:** a `Call Trace`/`segfault` in `dmesg` at the intrusion moment marks the exploitation step.
- **Forged noise:** planted `logger` entries designed to mislead the timeline.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Payload commands (`curl\|bash`, base64) in syslog | Execution evidence |
| Kernel `taint` / unexpected `module` loads | Rootkit / driver persistence |
| `apparmor="DENIED"` / `avc` in kernel log | MAC caught the intrusion |
| Log forwarding disabled near incident | Blind spot created |
| Gaps or truncation vs rotation schedule | Local tampering (check the remote copy) |
| USB insert lines around exfil timeframe | Physical media used |
| `stop`/`discard` rule for a specific program in `rsyslog.d` | Activity suppressed at the pipeline |
| `omprog … binary=` in rsyslog config | rsyslog executing an attacker program per message |
| `logger`-sourced entries that don't fit normal activity | Forged/misleading log noise |
| `Call Trace`/`Oops`/`BUG:` in dmesg | Kernel crash — often exploitation |

## Resources

- `rsyslog.conf(5)`, `dmesg(1)`, `logger(1)`, `syslog(3)` man pages; RFC 5424 (syslog protocol)
- rsyslog `omprog`/`omfwd` module docs — https://www.rsyslog.com/doc/configuration/modules/
- MITRE ATT&CK: T1562.006 (Indicator Blocking), T1070.002 (Clear Logs), T1059.004 (Unix Shell), T1052.001 (Exfil over USB), T1200 (Hardware Additions)
