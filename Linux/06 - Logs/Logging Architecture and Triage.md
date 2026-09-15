# Logging Architecture and Triage

Before you trust any log — or conclude that the absence of one proves an event didn't happen — you need to understand how Linux logging is wired on *this* host. Two subsystems coexist (binary journald and text syslog), storage may be persistent or RAM-only, rotation quietly ages evidence out, and a competent attacker will have thinned or truncated the record. This note is the orientation layer for the whole `06 - Logs` folder: where logs live, how far back they really go, how to read them from a mounted image, and how to tell tampering from ordinary rotation.

> 🔴 "No evidence of X" is a claim you have to *earn*. If journald is volatile and the host rebooted, the journal is gone. If rotation is aggressive, last week is gone from the text logs. If the box forwards to a SIEM, the real record may live off-host and survive local wiping. Establish capability and retention first, then interpret gaps.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Two Logging Systems](#two-logging-systems)
- [Central and Remote Logging](#central-and-remote-logging)
- [Log Location Map](#log-location-map)
- [Rotation and Retention](#rotation-and-retention)
- [Reading Logs from a Mounted Image](#reading-logs-from-a-mounted-image)
- [Log Tampering and Anti-Forensics](#log-tampering-and-anti-forensics)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Is the journal persistent or RAM-only?
ls -d /var/log/journal 2>/dev/null && echo PERSISTENT || echo VOLATILE

# Journal integrity
journalctl --verify

# Quick multi-source triage of today
journalctl --since today | grep -Ei "failed|invalid|accepted|sudo|sshd|cron|curl|wget|error|authentication"

# Login record sanity (gaps/zeroing = tampering)
last -Faxn 20; ls -l /var/log/wtmp /var/log/btmp

# Zero-length or oddly small logs
find /var/log -type f -size 0 -ls 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Is the journal persistent or RAM-only? | `ls -d /var/log/journal` (persistent) vs `/run/log/journal` (volatile) |
| How far back does the record really go? | `journalctl --list-boots`; `ls /var/log/*.gz`; `cat /etc/logrotate.conf` |
| Is there an **off-host copy** that survived wiping? | `grep -R '@@' /etc/rsyslog*`; SIEM agents (`ps aux \| grep -Ei filebeat\|splunk\|wazuh`) |
| Was a log tampered vs just rotated? | `journalctl --verify`; log mtime vs rotation schedule; `find /var/log -size 0` |
| Was logging stopped during the incident? | `journalctl -u rsyslog -u systemd-journald \| grep -Ei stop\|start` |
| Which file holds auth on this distro? | Debian `auth.log` / RHEL `secure` (see location map) |
| Did the journal silently drop messages? | `journalctl \| grep -i "Suppressed .* messages"` (rate-limit gap) |
| Where's the login history + is it intact? | `last -F`; `utmpdump /var/log/wtmp`; `ls -l /var/log/wtmp /var/log/btmp` |

## Two Logging Systems

Most modern hosts run **both** logging systems, and knowing which holds what saves you from false conclusions. journald is the structured binary primary; it typically forwards to rsyslog, which writes the familiar plain-text files. If rsyslog is disabled you have only the binary journal; if journald is volatile you have only the text files.

| System | Store | Read with |
|--------|-------|-----------|
| **systemd-journald** | Binary journal in `/var/log/journal/` (persistent) or `/run/log/journal/` (volatile/RAM) | `journalctl` |
| **rsyslog / syslog-ng** | Plain text under `/var/log/` | `grep`, `zgrep`, `awk` |
| 🔴 **BusyBox syslogd** (Alpine, embedded, **containers**) | In-memory **ring buffer** by default, or `/var/log/messages` if `-O` file set | `logread` (ring), else `cat /var/log/messages` |

```bash
# Journald storage setting
grep -i '^Storage' /etc/systemd/journald.conf

# Is rsyslog running / forwarding?
systemctl status rsyslog 2>/dev/null

cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -Ev '^\s*#'

# Alpine / BusyBox syslogd — the ring buffer is VOLATILE (lost on container/host restart)
logread 2>/dev/null                       # dump the in-memory ring
logread -f 2>/dev/null                     # follow
cat /etc/conf.d/syslog 2>/dev/null; rc-service syslog status 2>/dev/null   # OpenRC service + config
cat /var/log/messages 2>/dev/null          # if syslogd was started with -O /var/log/messages
```

🔴 **Alpine/BusyBox logging is a container trap:** `syslogd` defaults to a small **RAM ring buffer** read with `logread` — there's no journald, no rsyslog, and often no persistent file. Grab `logread` output *before* the container/host restarts, and check whether logs are forwarded (BusyBox `syslogd -R <host>`) since that off-box copy may be the only durable record. The practical upshot for glibc hosts: if you find a gap in the text logs, check the journal (and vice-versa) before concluding anything was deleted — the event may simply have been routed to the other system.

## Central and Remote Logging

🔴 The single most valuable thing to establish early: **is there a copy the attacker couldn't reach?** If the host forwards to a central syslog server or ships logs to a SIEM, that off-host record may hold exactly what was wiped locally — request it before you rely on local files.

```bash
# rsyslog forwarding (@@ = TCP, @ = UDP, then host:port)
grep -REn '@@?[0-9a-zA-Z._-]+:[0-9]+' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null

# journald native remote upload
systemctl status systemd-journal-upload 2>/dev/null

grep -Ei 'ForwardToSyslog|^URL' /etc/systemd/journald.conf /etc/systemd/journal-upload.conf 2>/dev/null

# SIEM / log-shipper agents (the off-host copy)
ps aux | grep -Ei 'filebeat|fluent|fluent-bit|splunk|splunkd|wazuh|auditbeat|osqueryd|nxlog|rsyslog.*omfwd' | grep -v grep

ls -l /etc/filebeat /etc/fluent* /opt/splunkforwarder/etc 2>/dev/null
```

| Finding | Meaning |
|---------|---------|
| `@@server:514` in rsyslog config | 🔴 Logs forwarded off-box — a second copy likely exists |
| `filebeat`/`splunkd`/`wazuh` process running | Shipping to a SIEM — pull that data |
| Forwarding config present but agent **not** running | 🔴 Attacker may have killed the shipper — check when it stopped |

## Log Location Map

The same information lives at different paths per distro family — the most common trip-up being `auth.log` (Debian) vs `secure` (RHEL). This table is your lookup:

| Content | Debian / Ubuntu | RHEL / CentOS / Fedora |
|---------|-----------------|------------------------|
| Authentication | `/var/log/auth.log` | `/var/log/secure` |
| General system | `/var/log/syslog` | `/var/log/messages` |
| Kernel | `/var/log/kern.log` + `dmesg` | `/var/log/messages` + `dmesg` |
| Cron | `/var/log/syslog` (or `/var/log/cron.log`) | `/var/log/cron` |
| Boot | `/var/log/boot.log` | `/var/log/boot.log` |
| Package mgmt | `/var/log/apt/`, `/var/log/dpkg.log` | `/var/log/dnf.log`, `/var/log/yum.log` |
| Audit (if auditd) | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |
| Login records | `/var/log/wtmp` `/var/log/btmp` `/var/log/lastlog` | same |
| Web (Apache) | `/var/log/apache2/` | `/var/log/httpd/` |
| Journal (binary) | `/var/log/journal/` | `/var/log/journal/` |

## Rotation and Retention

Rotation is what bounds your evidence window. `logrotate` renames and compresses logs on a schedule (`.1`, `.2.gz`, …) and eventually deletes the oldest, so the incident you care about may already be a `.gz` — or gone. Always search the archives, and check whether the rotation policy was recently *changed* to shrink retention.

```bash
# Global + per-service rotation policy
cat /etc/logrotate.conf

ls -al /etc/logrotate.d/

# Rotated/compressed archives
ls -la /var/log/*.1 /var/log/*.gz 2>/dev/null

# Search compressed archives
zgrep -i "accepted" /var/log/auth.log.*.gz 2>/dev/null

zcat /var/log/syslog.*.gz 2>/dev/null

# Journal disk usage / oldest entry
journalctl --disk-usage

journalctl --list-boots
```

🔴 If rotation is aggressive — or was recently tightened — the text-log window you need may be gone. Fall back to the journal, `wtmp`, auditd, or the package logs, which rotate on different schedules and may still cover the period. A rotation config whose mtime lands inside the incident window is itself suspicious.

## Reading Logs from a Mounted Image

Working an acquired image, point the same tools at the mount root (`/mnt/evidence`). Note that journald and the binary login DBs need their own read flags rather than a plain `cat`:

```bash
# Text logs: just point at the mount
grep -i accepted /mnt/evidence/var/log/auth.log

# Journald from an image (directory of journal files)
journalctl -D /mnt/evidence/var/log/journal

# Or a single journal file
journalctl --file /mnt/evidence/var/log/journal/*/system.journal

# wtmp/btmp from a mounted file
last -F -f /mnt/evidence/var/log/wtmp

lastb -f /mnt/evidence/var/log/btmp

# auditd from a mounted file
ausearch -if /mnt/evidence/var/log/audit/audit.log -i
```

## Log Tampering and Anti-Forensics

🔴 Before you attribute a gap to rotation, rule out tampering. Attackers clear login records, truncate text logs, selectively delete lines with `sed -i`, or stop the logging service during their activity. Each leaves a different tell:

```bash
# Journal integrity (FSS/forward-secure sealing if enabled)
journalctl --verify

# Zero-length or truncated logs
find /var/log -type f \( -size 0 -o -size -10c \) -ls 2>/dev/null

# Login-record gaps: compare last write time to known activity
ls -l --time-style=full-iso /var/log/wtmp /var/log/btmp /var/log/lastlog

# Files an attacker might have edited to remove lines (mtime vs rotation schedule)
ls -l --time-style=full-iso /var/log/auth.log /var/log/syslog
```

| Tampering technique | Tell |
|---------------------|------|
| Selective line deletion (`sed -i`) | Log mtime updated off-schedule; sequence/PID gaps mid-file |
| Truncate/zero (`: > file`, `truncate`) | Size 0 or tiny; entries start mid-history |
| `wtmp`/`btmp` wiped | Zero size; `last` shows a suspiciously short history |
| Journal rotated/deleted | `journalctl --list-boots` missing the incident boot |
| Stop logging service during activity | Gap bracketed by `rsyslogd`/`journald` stop→start entries |
| `journalctl --verify` FAIL | A sealed journal was altered |

The strongest single check is comparing a log's mtime to the rotation schedule and to known activity: a text log last modified at an odd time (not a rotation boundary) hints that someone edited it by hand.

## Deep Threat Hunts

Cross-source tamper + coverage sweep. *(seasoned-DFIR; the point is to find the record the attacker missed)*

```bash
# 1. Off-host copies that survive local wiping — forwarding + SIEM agents
grep -REn '@@?[0-9a-zA-Z._-]+:[0-9]+' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null

ps aux | grep -Ei 'filebeat|fluent|splunk|wazuh|auditbeat|osquery|nxlog' | grep -v grep

# 2. journald dropping messages (rate-limit gap = silence that isn't deletion)
journalctl | grep -i "Suppressed .* messages"

grep -Ei 'RateLimit|MaxLevelStore|Storage|Compress|Seal' /etc/systemd/journald.conf

# 3. Every rotated/compressed archive across formats
ls -la /var/log/*.1 /var/log/*.gz /var/log/*.xz /var/log/*.zst 2>/dev/null

zgrep -i accepted /var/log/auth.log*.gz 2>/dev/null

xzgrep -i accepted /var/log/*.xz 2>/dev/null

# 4. Logging service stop/start bracketing a gap (deliberate blind spot)
journalctl -u rsyslog -u systemd-journald --no-pager | grep -Ei 'Stopp|Start'

# 5. Raw wtmp/btmp dump — spot edited/zeroed entries last smooths over
utmpdump /var/log/wtmp 2>/dev/null | tail

utmpdump /var/log/btmp 2>/dev/null | tail

# 6. Text logs modified OFF the rotation boundary (hand-edited)
find /var/log -type f -name '*.log' -newermt "-2 hours" -ls 2>/dev/null
```

**Hunt ideas:**

- **The off-host copy is your insurance.** A forwarder/SIEM config means the authoritative record may live where the attacker couldn't delete it — pull it first.
- **"Suppressed N messages" is journald rate-limiting, not an attacker** — but it's a real visibility gap. Note it and widen coverage with auditd.
- **Diff `journalctl --list-boots` against `last reboot`/uptime** — a missing boot id means that boot's journal was removed.
- **`utmpdump` reveals byte-level tampering** (zeroed hostnames, impossible overlapping sessions) that `last` hides.
- **Every text log's mtime should land on a rotation boundary** — an off-cycle mtime is a hand-edit tell.

## Getting Max Value

- **Preserve the whole log tree first** — including the volatile journal: `tar czf /evidence/logs.tgz /var/log /run/log/journal 2>/dev/null`.
- **Export the journal portably** with `journalctl -o export > /evidence/journal.export` — it survives without a matching systemd version on your analysis box.
- **Normalize time once.** journald stores UTC internally; text/syslog is local. Set your analysis timezone (note 01) and convert everything to UTC before correlating.
- **On live IR hosts, verify/enable FSS** (`journalctl --setup-keys`) so subsequent journal tampering becomes detectable via `--verify`.
- **Rotation schedules differ per source** — when one log's window is gone, journal, `wtmp`, auditd, and package logs may still cover the period.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Structured journal queries (fields, units, `_CMDLINE`) | **Systemd Journal** |
| Logins/logouts, brute force, `wtmp`/`btmp` | **Authentication and Login Records** |
| High-fidelity execution / syscalls | **Auditd** |
| Plain-text `syslog`/`messages`/`kern.log` | **Syslog and Rsyslog** |
| Endpoint EDR-style events | **Sysmon for Linux** |
| Web / DB application logs | **Application and Database Logs** |
| Consolidated anti-forensics hunt | **Anti-Forensics and Evidence Destruction** (13b) |
| Build the unified timeline | **Timelining** (13) |

## Scenarios

- **"Nothing in the logs":** prove capability + retention + no off-host copy before writing a non-finding.
- **Rotation ate it:** the incident text log is gone → pivot to journal/auditd/`wtmp`/package logs on different schedules.
- **Attacker stopped rsyslog:** the gap is bracketed by stop→start entries; that bracket times the activity.
- **Selective `sed -i` edit:** off-schedule log mtime plus a sequence/PID gap mid-file.
- **Volatile journal + reboot:** the journal is gone; `wtmp`/`auth.log` are your only login record.
- **SIEM save:** a forwarder config means the real record is off-host and intact — the local wipe failed.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `journalctl --verify` fails | Journal altered |
| Zero-length / truncated log files | Deliberate clearing |
| `wtmp`/`btmp` gaps or zero size | Login history wiped |
| Rotation policy recently shrunk | Evidence window deliberately reduced |
| Logging service stopped then restarted around incident | Blind spot created on purpose |
| Missing boot in `journalctl --list-boots` | Journal for the incident window removed |
| Forwarding configured but shipper process dead | Attacker may have killed off-host logging |
| `journalctl \| "Suppressed N messages"` around incident | Rate-limit gap — real (if benign) blind spot |
| `utmpdump` shows zeroed/overlapping session entries | Byte-level `wtmp`/`btmp` tampering |

## Resources

- `systemd-journald(8)`, `journalctl(1)`, `journald.conf(5)`, `logrotate(8)`, `rsyslog.conf(5)`, `utmpdump(1)` man pages
- systemd-journal-upload / -remote (central journald): https://www.freedesktop.org/software/systemd/man/systemd-journal-upload.html
- MITRE ATT&CK: T1070.002 (Clear Linux/Mac System Logs), T1562.001 (Impair Defenses: Disable Logging), T1562.006 (Indicator Blocking)
