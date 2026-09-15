# Sysmon for Linux

Sysmon for Linux (from the Sysinternals project) instruments the kernel via eBPF and emits detailed process, network, and file events in an XML-style format to syslog or the journal. It's uncommon in the field, but when a host has it, the telemetry is a major upgrade over stock logging — you get process-create events with full command lines, hashes, and parent lineage, plus network connections tied to the process that made them. Like auditd, its coverage is entirely config-driven, so check the config before trusting an absence.

> 🔴 Sysmon events chain by **ProcessId + Image**: identify a suspicious PID in an EventID 1 (process create), then grep that PID across all events to reconstruct its network (EventID 3), file (11), and injection (8/10) activity. That pivot turns a single alert into a full behavioral picture.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Is Sysmon Present](#is-sysmon-present)
- [Event IDs](#event-ids)
- [Process Execution and Chaining](#process-execution-and-chaining)
- [Network and File Events](#network-and-file-events)
- [Suspicious Patterns](#suspicious-patterns)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Is it running?
systemctl status sysmon 2>/dev/null

# Where it logs (syslog or journald depending on config)
grep -i sysmon /var/log/syslog 2>/dev/null | head

journalctl -t sysmon 2>/dev/null | head

# Process-create events
grep 'EventID=1' /var/log/syslog 2>/dev/null

# Network-connect events
grep 'EventID=3' /var/log/syslog 2>/dev/null
```

## What to Check for What

| Investigative question | Command / filter |
|------------------------|------------------|
| Is Sysmon even capturing this? | `sysmon -c` (the effective config, like auditd rules) |
| What ran (cmdline + hash + parent)? | `grep 'EventID=1'` → Image/CommandLine/Hashes/ParentImage |
| Reliable chaining across a process's life? | pivot on **ProcessGuid**, not PID (PIDs get reused) |
| What did a process connect to? | `grep 'EventID=3' \| grep ProcessId` (→ remote IP/port) |
| What domains were resolved? | `grep 'EventID=22'` (DNS — C2 domains) |
| A rogue library loaded? | `grep 'EventID=7'` (image/.so load — LD_PRELOAD analog) |
| Injection / credential theft? | `grep -E 'EventID=8\|EventID=10'` |
| Was monitoring blinded? | `grep -E 'EventID=4\|EventID=16'` (service/config change) |
| Human-readable rendering? | `cat /var/log/syslog \| /opt/sysmon/sysmonLogView` |

## Is Sysmon Present

```bash
# Service + config
systemctl status sysmon

# Effective config (what it captures)
sysmon -c 2>/dev/null

# Log destination
ls -l /var/log/sysmon* 2>/dev/null

grep -i sysmon /var/log/syslog 2>/dev/null | head
```

Coverage is defined by the XML config, exactly like auditd's ruleset: Sysmon only records the event types and filters the config selects. If a category you care about (say, network connections) isn't configured, its absence proves nothing — check `sysmon -c` first.

## Event IDs

Sysmon for Linux implements a subset of the Windows event set (registry and some Windows-only IDs won't appear on Linux, though they may show in cross-platform log schemas). The high-value ones for Linux DFIR:

| ID | Event | DFIR value |
|----|-------|------------|
| 1 | Process Create | 🔴 Execution + full cmdline + hashes + parent + ProcessGuid |
| 3 | Network Connection | 🔴 Process ↔ remote IP/port |
| 22 | DNS Query | 🔴 Domain resolution (C2 domains) |
| 7 | Image Loaded | 🔴 Library/`.so` load — the Linux "DLL injection" / `LD_PRELOAD` analog |
| 5 | Process Terminated | Session/lifetime bounds |
| 9 | Raw Access Read | Disk scraping / access-check bypass |
| 10 | Process Access | Injection / credential-theft attempts |
| 11 | File Create | Dropped files (TargetFilename) |
| 15 | File Create Stream Hash | Integrity / stream tracking |
| 16 | Sysmon Config Change | 🔴 Someone altered monitoring |
| 17 / 18 | Named Pipe Created / Connected | IPC / lateral movement / C2 |
| 23 / 26 | File Delete (logged) | Anti-forensics deletion |
| 4 | Sysmon Service State Changed | 🔴 Monitoring stopped/started |
| 6 | Driver / kernel module Loaded | Rootkit / driver persistence |

🔴 EventID 4 and 16 are the ones that betray an attacker who noticed the monitoring — a service-state change or a config change around the incident means they tried to blind Sysmon.

## Process Execution and Chaining

```bash
# Extract image paths from process-create events
grep 'EventID=1' /var/log/syslog | sed -n 's/.*<Data Name="Image">\([^<]*\)<\/Data>.*/\1/p'

# Pull ProcessId values
grep 'EventID=1' /var/log/syslog | grep -o 'ProcessId[^<]*'

# Parent/child linkage
grep 'ParentImage' /var/log/syslog

grep 'ProcessId' /var/log/syslog | grep -E "bash|sh|python|curl"
```

The workflow: find a suspicious `EventID=1` (an interpreter spawned by a web server, or a binary in `/tmp`), note its `ProcessGuid`, then grep that Guid across every event to build the process's full story — what it connected to, what it wrote, what it injected into.

```bash
# Human-readable rendering of the XML events (Sysinternals viewer)
cat /var/log/syslog | /opt/sysmon/sysmonLogView 2>/dev/null

# Chain reliably by ProcessGuid (survives PID reuse), not just PID
grep -o 'ProcessGuid[^<]*' /var/log/syslog | sort | uniq -c | sort -nr | head

# Pull the rich fields from a process-create event
grep 'EventID=1' /var/log/syslog | grep -oE '<Data Name="(Image|CommandLine|Hashes|ParentImage|User|ProcessGuid)">[^<]*'
```

🔴 **Chain by `ProcessGuid`, not `ProcessId`.** PIDs are reused by the kernel, so a raw PID grep can splice two unrelated processes together; the Guid uniquely identifies one process across its entire lifetime.

## Network and File Events

```bash
# Network connections tied to a process
grep 'EventID=3' /var/log/syslog | grep 'ProcessId'

# File creations in staging areas
grep 'EventID=11' /var/log/syslog | grep -Ei "/tmp|/dev/shm|/var/tmp"
```

EventID 3 is the piece stock Linux logging usually lacks — a direct process-to-remote-endpoint mapping, letting you attribute a C2 connection to the exact binary that opened it.

## Suspicious Patterns

```bash
# Interpreters / download tooling being spawned
grep -E "bash|sh|python|perl|curl|wget|nc |socat" /var/log/syslog | grep EventID=1

# Execution from temp/staging paths
grep -E "/tmp|/dev/shm|/var/tmp" /var/log/syslog | grep -E "EventID=1|EventID=11"

# Injection / remote-thread / process-access
grep -E "EventID=8|EventID=10" /var/log/syslog
```

## Deep Threat Hunts

*(seasoned-DFIR; Sysmon's edge is hash + full lineage + network/DNS tied to the process)*

```bash
# 1. Webshell/RCE: a web-server parent spawning a shell (EventID 1)
grep 'EventID=1' /var/log/syslog | grep -Ei 'ParentImage.*(nginx|apache|httpd|php-fpm)' | grep -Ei 'bash|sh|python|nc|perl'

# 2. Hash pivot: unique SHA256s of everything that executed -> reputation check
grep 'EventID=1' /var/log/syslog | grep -oE 'SHA256=[A-Fa-f0-9]{64}' | sort -u

# 3. Full C2 conversation: DNS (22) + connection (3) tied to a process
grep -E 'EventID=22|EventID=3' /var/log/syslog | grep 'ProcessId'

# 4. Rogue library load from a staging path (LD_PRELOAD / malicious .so)
grep 'EventID=7' /var/log/syslog | grep -Ei "/tmp|/dev/shm|/var/tmp|preload"

# 5. Injection / credential-theft attempts
grep -E 'EventID=8|EventID=10' /var/log/syslog

# 6. Monitoring-tamper: attacker blinding Sysmon
grep -E 'EventID=4|EventID=16' /var/log/syslog

# 7. Anti-forensics deletions of logs/tools
grep -E 'EventID=23|EventID=26' /var/log/syslog
```

**Hunt ideas:**

- **Chain by ProcessGuid, then fan out** — one suspicious `EventID=1` Guid grepped across 3/22/7/11 gives the whole behavioral story (connected → resolved → loaded → wrote).
- **The SHA256 in EventID 1 is a free reputation pivot** — dump uniques and check them against known-bad / your IOC set.
- **EventID 22 + 3 together map C2** — domain → IP → the exact process that reached out.
- **EventID 7 from `/tmp` or `/dev/shm`** is the Linux "DLL injection" — a rogue `.so` or `LD_PRELOAD` load.
- **EventID 4/16 around the incident** means the attacker noticed and tried to blind Sysmon — a strong signal in itself.

## Getting Max Value

- **Confirm coverage with `sysmon -c` first** — like auditd, Sysmon only records what its XML config selects; an absent event type proves nothing until you check the config.
- **Render for humans, parse for timelines** — `sysmonLogView` (or `xmllint`) for readable analysis; extract fields to structured form for the master timeline.
- **EventID 1 is richer than journald `_CMDLINE`** — it bundles cmdline + **hash** + parent + Guid in one record; prefer it when present.
- **Pivot on ProcessGuid + hash**, and always tie the network/DNS events back to the process that made them.
- **Cross-check auditd/journal** to fill any category the Sysmon config didn't capture.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Fill categories the Sysmon config missed | **Auditd**, **Systemd Journal** |
| Full process tree around a Guid/PID | **Process Trees and Execution Lineage** (10b) |
| Reputation / triage of a hashed binary | **ELF and Malware Triage** (11b), **IOC and YARA Scanning** (11d) |
| The nature of the C2 endpoint/domain | **Network and PCAP Forensics** (10c) |
| The `.so` an EventID 7 loaded | **Persistence → Preload Hijacking**, **Live Response** (10) |
| Whether monitoring was disabled | **Anti-Forensics and Evidence Destruction** (13b) |

## Scenarios

- **Best-case telemetry:** EventID 1 gives cmdline+hash+parent, 3+22 give the C2 — a full behavioral story from one alert.
- **Webshell:** a web-server `ParentImage` spawning a shell in EventID 1.
- **Injection:** EventID 8/10 (remote-thread / process-access) against a target process.
- **Rogue library:** EventID 7 loading a `.so` out of `/tmp`.
- **Monitoring blinded:** EventID 4/16 at the incident time.
- **PID-reuse trap avoided:** chaining by ProcessGuid prevents mis-attributing a reused PID.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| EventID 4/16 (service state / config change) | Monitoring tampered or disabled |
| EventID 1 spawning shells/interpreters from web or temp paths | Exploitation → execution |
| EventID 3 to unfamiliar external IPs from odd processes | C2 / exfil |
| EventID 10/8 process-access / remote-thread | Injection / credential theft |
| EventID 6 driver/module load | Rootkit / driver persistence |
| EventID 23/26 deleting logs or tools | Anti-forensics |
| EventID 7 image/`.so` load from `/tmp` or `/dev/shm` | Rogue library / `LD_PRELOAD` |
| EventID 22 DNS query to a suspicious/DGA domain | C2 domain resolution |
| EventID 1 SHA256 matching known-bad | Confirmed malicious binary executed |

## Resources

- Sysmon for Linux — https://github.com/Sysinternals/SysmonForLinux
- Sysmon config reference (schema/event fields) — https://learn.microsoft.com/sysinternals/downloads/sysmon
- MITRE ATT&CK: T1059.004 (Unix Shell), T1071 (Application Layer Protocol / C2), T1055 (Process Injection), T1574.006 (LD_PRELOAD), T1562.001 (Impair Defenses)
