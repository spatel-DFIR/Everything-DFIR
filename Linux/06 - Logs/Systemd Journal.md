# Systemd Journal

The systemd journal is usually the richest single log source on a modern host, because it doesn't just store text — it attaches structured metadata to every message: the exact binary that logged it (`_EXE`), its full command line (`_CMDLINE`), the process and parent PIDs, the owning systemd unit, the login UID, and the audit session. That means you can pivot on *fields* instead of grepping free text, and you can tie a log line back to a specific process and session with certainty. The catch is that it's binary (you need `journalctl`) and it may be volatile (RAM-only), so establishing its storage mode is step one.

> 🔴 If there is no `/var/log/journal/` directory, journald is **volatile** — the journal lives only in `/run/log/journal` in RAM and is destroyed on reboot. On a host that was rebooted after the incident, the journal is already gone, and you fall back to text logs, `wtmp`, and auditd. Check storage mode before you rely on the journal for anything.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Where the Journal Lives](#where-the-journal-lives)
- [Boot and Time Filtering](#boot-and-time-filtering)
- [Structured Fields and Output](#structured-fields-and-output)
- [Authentication and Login](#authentication-and-login)
- [Privilege Escalation](#privilege-escalation)
- [Execution and Payload Behaviour](#execution-and-payload-behaviour)
- [Persistence and Services](#persistence-and-services)
- [Fileless and Network Indicators](#fileless-and-network-indicators)
- [Kernel Anomalies](#kernel-anomalies)
- [Coredumps from Exploitation](#coredumps-from-exploitation)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# One-line multi-signal sweep of today
journalctl --since today | grep -Ei "failed|invalid|accepted|sudo|sshd|cron|curl|wget|bash|error|authentication"

# All SSH auth events
journalctl _COMM=sshd | grep -Ei "Accepted|Failed|Invalid"

# All sudo usage
journalctl _COMM=sudo

# Payload-shaped command lines
journalctl | grep -Ei "curl|wget|base64|nc |bash -c|python -c|perl -e|/dev/shm|/tmp/"

# Integrity check
journalctl --verify
```

## What to Check for What

| Investigative question | Command / filter |
|------------------------|------------------|
| What exact command did a process run? | `journalctl _PID=<pid> -o verbose` (read `_CMDLINE`) |
| Everything a program ever did | `journalctl _COMM=sshd` / `journalctl /usr/bin/sudo` |
| Everything one login session did | `journalctl _AUDIT_SESSION=<n> -o short-precise` |
| Attribute a root action to the human | `journalctl _AUDIT_LOGINUID=<uid>` (survives su/sudo) |
| Fast payload-shaped search | `journalctl -g 'curl\|/dev/tcp\|base64 -d' --since today` |
| Baseline: every program/unit that logged | `journalctl -F _COMM`; `journalctl -F _SYSTEMD_UNIT` |
| A specific service's activity | `journalctl -u <unit>`; `systemctl status <unit>` |
| Did an exploit crash a service? | `coredumpctl list`; `coredumpctl info <pid>` |
| Is auditd forwarding into the journal? | `journalctl _TRANSPORT=audit --since today` |
| Isolate the incident boot | `journalctl --list-boots`; `journalctl -b <id>` |

## Where the Journal Lives

```bash
# Persistent (survives reboot) vs volatile (RAM, lost on reboot)
ls -d /var/log/journal /run/log/journal 2>/dev/null

# From a mounted image
journalctl -D /mnt/evidence/var/log/journal

journalctl --file /mnt/evidence/var/log/journal/*/system.journal
```

🔴 Storage mode is set by `Storage=` in `/etc/systemd/journald.conf`. `persistent`/`auto` (with the directory present) means it survives reboots; `volatile` (or no directory) means it doesn't. This single fact determines whether the journal is even available to you after a reboot.

## Boot and Time Filtering

The journal is boot-aware: it tags every entry with a boot ID, so you can isolate exactly the boot session the incident happened in — very useful for separating "the attack" from noise across reboots.

```bash
# List boots (each with an index and ID)
journalctl --list-boots

# Current boot / previous boot
journalctl -b

journalctl -b -1

# Time windows
journalctl --since "1 hour ago"

journalctl --since today

journalctl --since "2026-04-23 10:00:00" --until "2026-04-23 18:00:00"

# Force UTC to match other evidence
journalctl --utc -o short
```

Always normalize to UTC (`--utc`) when you'll correlate journal entries against filesystem times or other logs — otherwise the journal shows local time and events won't line up.

## Structured Fields and Output

This is the journal's superpower. Instead of grepping text, filter on the machine-populated fields, and use `-o verbose`/`-o json` to see everything the journal recorded about an entry.

```bash
# By program, user, PID, unit
journalctl _COMM=sshd

journalctl _UID=1000

journalctl _PID=4242

journalctl -u ssh.service

# Kernel ring buffer only
journalctl -k

# By priority (0 emerg .. 7 debug); 0-3 = errors and worse
journalctl -p 0..3

# Full metadata for each entry (shows _EXE, _CMDLINE, _AUDIT_SESSION, etc.)
journalctl -o verbose

# JSON for parsing / timeline ingestion
journalctl -o json

# Microsecond-precision timestamps (best for timelines)
journalctl -o short-precise

# Native regex grep (indexed — faster than piping to grep)
journalctl -g 'curl|/dev/tcp|base64 -d' --since today

# Combine fields: AND across different fields, OR within same field
journalctl _COMM=sshd _UID=0

# Enumerate every value a field ever held (baselining)
journalctl -F _COMM

journalctl -F _SYSTEMD_UNIT

# Filter by message source: audit = forwarded auditd events
journalctl _TRANSPORT=audit

# Auto-context view of recent errors (RTR)
journalctl -xe
```

| Field | Value |
|-------|-------|
| `_COMM` / `_EXE` | Program name / full binary path that logged |
| `_CMDLINE` | 🔴 Full command line — often the attacker's exact invocation |
| `_PID` / `_PPID` | Process / parent PID |
| `_UID` / `_AUDIT_LOGINUID` | Effective UID / original login UID (survives `su`/`sudo`) |
| `_SYSTEMD_UNIT` | Owning service — ties a log line to a unit |
| `_AUDIT_SESSION` | Ties events to a single login session |

🔴 `_CMDLINE` frequently captures the full attacker command (`curl … | bash`, a base64 blob, a reverse-shell one-liner) even when the process is long gone, and `_AUDIT_LOGINUID` survives privilege changes — so you can attribute a root action back to the human who logged in and then `sudo`'d.

## Authentication and Login

```bash
journalctl _COMM=sshd | grep -Ei "Accepted|Failed|Invalid|authentication failure"

journalctl -u ssh -u sshd.service

journalctl | grep -Ei "pam_unix|authentication failure|session opened|session closed"
```

Because the journal ties these to `_AUDIT_SESSION` and `_AUDIT_LOGINUID`, you can follow a single login session from authentication through every command it spawned.

## Privilege Escalation

```bash
journalctl _COMM=sudo

journalctl | grep -Ei "sudo|su\[|COMMAND=|authentication failure"

# pkexec / polkit abuse
journalctl | grep -Ei "pkexec|polkit"
```

`sudo` entries record the invoking user, the target, and the `COMMAND=` run — a clean audit trail of privilege use. Watch for `pkexec`/`polkit` too, since several well-known local-privesc CVEs live there.

## Execution and Payload Behaviour

```bash
journalctl | grep -Ei "curl|wget|base64|nc |ncat|socat|bash -c|python -c|perl -e"

# Anything executed out of a temp/staging path
journalctl | grep -Ei "/tmp/|/var/tmp/|/dev/shm/|/run/user/|memfd"
```

Services that log their child commands (or auditd forwarding into the journal) make this a powerful execution view. Execution out of `/tmp`, `/dev/shm`, or `memfd` is the fileless/staging tell (see the Live Response note).

## Persistence and Services

```bash
# Service state changes and enable events
journalctl | grep -Ei "systemctl|Started|Stopped|Reloading|enabled|masked"

# Cron / timer / at
journalctl | grep -Ei "cron|CRON|crontab|systemd-timer|atd"

# New units being loaded
journalctl -u systemd | grep -Ei "Reloading|Reexecuting"
```

🔴 A `Started <unknown>.service` or a `systemd Reloading` around the incident time can mark the moment a persistence unit was installed and activated — cross-reference with the Persistence note.

## Fileless and Network Indicators

```bash
# Temp/memory execution paths
journalctl | grep -Ei "/dev/shm|/tmp|/run/user|/proc/self|memfd"

# Connection-shaped messages
journalctl | grep -Ei "connection|connected|established|refused|timeout|dns"
```

## Kernel Anomalies

```bash
journalctl -k | grep -Ei "segfault|oom|denied|error|kill|panic|taint|module"

# AppArmor / SELinux denials surfaced in the kernel log
journalctl -k | grep -Ei "apparmor|avc"
```

Kernel-side signals — a `segfault` from a crashing exploit, an unexpected `module` load, `taint`, or MAC `denied`/`avc` lines — often mark the exploitation or rootkit step of an intrusion.

## Coredumps from Exploitation

🔴 An underused pivot: when a process crashes (a memory-corruption exploit that fails or destabilizes its target), `systemd-coredump` captures a core with a **backtrace, the faulting binary, and the exact time** — a near-free "something exploited this service" signal.

```bash
# List captured crashes (comm, PID, signal, time)
coredumpctl list

# Full detail incl. backtrace for a crash
coredumpctl info <PID|comm>

# Extract the core for malware/exploit triage (feed to ELF/Memory notes)
coredumpctl dump <PID|comm> > /evidence/core.<comm>

# Crashes stored on disk
ls -l /var/lib/systemd/coredump/ 2>/dev/null
```

| Signal | Meaning |
|--------|---------|
| Repeated crashes of one service (`nginx`, `sshd`) | 🔴 Exploit attempts against that service |
| A crash whose `_CMDLINE`/`exe` is odd or in `/tmp` | 🔴 The payload itself faulted |
| Crash timestamp bracketing other suspicious activity | Marks the exploitation moment |

## Deep Threat Hunts

Field-driven hunts that grep can't do. *(seasoned-DFIR; RTR patterns are folded above)*

```bash
# 1. Native regex payload sweep (faster than | grep on big journals)
journalctl -g 'curl|wget|/dev/tcp|base64 -d|bash -i|nc |python -c' --since today

# 2. Baseline: enumerate everything that ever logged, spot the outlier
journalctl -F _COMM | sort

journalctl -F _SYSTEMD_UNIT | sort

# 3. A service account running a shell (webshell/RCE) — www-data = uid 33 (Debian)
journalctl _UID=33 -g 'bash|sh|python|perl|nc' --since today

# 4. Replay one login session end to end
journalctl _AUDIT_SESSION=<N> -o short-precise

# 5. Tie every root action back to the human who sudo'd
journalctl _AUDIT_LOGINUID=1000 --since today

# 6. Forwarded auditd (EXECVE-grade) events living inside the journal
journalctl _TRANSPORT=audit --since today

# 7. Exploit-crash artifacts
coredumpctl list 2>/dev/null

# 8. Persistence unit installed/started around the incident
journalctl -u systemd -g 'Reloading|Started|enabled' --since "2026-04-23 10:00:00"
```

**Hunt ideas:**

- **`journalctl -F <field>` is a baselining tool** — list every `_COMM`/`_SYSTEMD_UNIT`/`_AUDIT_LOGINUID` that ever appeared; the odd one out is your lead.
- **`coredumpctl` is a free exploit detector** — a crash backtrace names the faulting service and time; correlate with the rest of the timeline.
- **`_TRANSPORT=audit`** means auditd forwards into the journal — you may already have EXECVE-grade telemetry without touching `audit.log`.
- **`_AUDIT_LOGINUID` is journald's `auid`** — it survives `su`/`sudo`, so root actions attribute to the original human.
- **Prefer `-g`/`--grep` + field filters over `| grep`** — indexed and far faster, and the field AND/OR logic slices noise grep can't.

## Getting Max Value

- **Export portably:** `journalctl -o export > /evidence/journal.export` (survives without a matching systemd version), or copy `/var/log/journal` **and** `/run/log/journal`.
- **Never `--vacuum`/`--rotate` on evidence** — both delete journal data.
- **Normalize with `--utc`** whenever correlating against filesystem times or other logs.
- **`-o json` → `jq`/timeline tools; `-o short-precise`** for microsecond ordering.
- **Field filters cut noise massively** — `_SYSTEMD_UNIT=`, `_UID=`, `_AUDIT_SESSION=` turn a firehose into a focused view.
- **`coredumpctl dump`** recovers the crashed binary/core for malware and exploit triage.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Login/logout detail + `wtmp`/`btmp` | **Authentication and Login Records** |
| Syscall/`EXECVE`-grade execution | **Auditd** |
| The persistence unit a "Started" line implies | **Persistence → Systemd Units Timers and Generators** |
| Turn a crash into the exploited binary | **ELF and Malware Triage** (11b), **Memory Forensics** (11) |
| A live `/dev/shm`/`memfd` process | **Live Response** (10) |
| Meaning of `avc`/`apparmor` denials | **SELinux AppArmor and Kernel Hardening** (05) |
| Plain-text equivalents (non-journald hosts) | **Syslog and Rsyslog** |

## Scenarios

- **Richest single source:** `_CMDLINE` captures the attacker's exact invocation (`curl|bash`, base64, reverse shell) even after the process exits.
- **Session replay:** `_AUDIT_SESSION` follows one login through every child command it spawned.
- **Attribution across sudo:** `_AUDIT_LOGINUID` ties a root action back to the human who logged in.
- **Exploit crash:** `coredumpctl` shows a service faulting with a backtrace at the intrusion moment.
- **Volatile trap:** no `/var/log/journal` + a post-incident reboot = the journal is already gone.
- **Audit-in-journal:** `_TRANSPORT=audit` gives execution telemetry even if you can't read `audit.log` directly.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Volatile journal + post-incident reboot | Evidence gone; capture immediately |
| `_CMDLINE` showing `curl\|bash`, base64, reverse shell | Payload execution captured verbatim |
| Execution from `/tmp` `/dev/shm` `memfd` | Fileless / staged malware |
| sudo/pkexec bursts from an unexpected user | Privilege escalation |
| New/`enabled` service around incident time | Persistence |
| `journalctl --verify` failure | Journal tampered |
| Missing incident boot in `--list-boots` | Journal for that window removed |
| Repeated service crashes in `coredumpctl list` | Exploit attempts against that service |
| Service account (`_UID=33` etc.) spawning a shell | Webshell / RCE through the app |
| `_TRANSPORT=audit` events stop mid-incident | auditd forwarding was killed |

## Resources

- `journalctl(1)`, `systemd.journal-fields(7)`, `coredumpctl(1)`, `systemd-coredump(8)` man pages
- MITRE ATT&CK: T1059.004 (Unix Shell), T1543.002 (Systemd Service), T1070.002 (Clear Logs), T1078 (Valid Accounts)
