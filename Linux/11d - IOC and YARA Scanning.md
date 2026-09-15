# IOC and YARA Scanning

Once you have indicators — from your own triage, a threat-intel report, or a recovered sample — scanning turns them into a fleet-wide answer to "where else is this?" This note covers YARA (pattern-matching against files and process memory), IOC scanners (Loki/THOR/Fenrir and similar) that bundle rules for known threats, and how to drive scans across many hosts. It's the bridge between analyzing one artifact and finding every affected system, and it feeds directly into the fleet-hunt step of every playbook.

> 🔴 Scanning is only as good as your rules, and running an unknown ruleset blindly produces noise. Start from *your* confirmed IOCs (hashes, strings, C2, file paths from the ELF/Malware Triage note), plus vetted public rules — then scan both **disk and process memory**, because a fileless payload won't match a file scan but will match a memory scan.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Hash and Simple IOC Matching](#hash-and-simple-ioc-matching)
- [YARA Basics](#yara-basics)
- [Scanning Files with YARA](#scanning-files-with-yara)
- [Scanning Process Memory](#scanning-process-memory)
- [IOC Scanners](#ioc-scanners)
- [Fleet Scanning](#fleet-scanning)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Hunt a known-bad hash across the filesystem
find / -type f -exec sha256sum {} + 2>/dev/null | grep -Ff known_bad_hashes.txt

# YARA scan a directory recursively
yara -r rules.yar /

# YARA scan running process memory (fileless detection)
for pid in $(ls /proc | grep -E '^[0-9]+$'); do yara rules.yar $pid 2>/dev/null && echo "  ^ pid $pid"; done

# Loki IOC scanner (bundled rules + your IOCs)
python3 loki.py -p /
```

## What to Check for What

| Investigative question | Command |
|------------------------|---------|
| Is a known-bad hash present? | `find / -exec sha256sum {} + \| grep -Ff bad_hashes` |
| Payload family on disk? | `yara -r rules.yar /tmp /var/tmp /dev/shm /var/www` |
| **Fileless** (memory-only) payload? | `yara rules.yar <PID>` per process |
| Trusted scan on a rootkitted host? | `vol -f mem.lime yarascan.YaraScan` (RAM image) |
| Known-bad IP in connections/logs? | `ss -tunap \| grep -Ff bad_ips`; `grep -rFf bad_ips /var/log` |
| Broad coverage fast? | Loki / Fenrir (bundled rules + IOCs) |
| Every affected host in the fleet? | osquery `yara` table / Velociraptor hunt |
| Log-based detection? | Sigma rules over the logs (complements YARA) |

## Hash and Simple IOC Matching

The simplest scan is matching known-bad hashes, IPs, or paths — fast and unambiguous when you already have concrete IOCs.

```bash
# Match file hashes against an IOC list
find / -type f -exec sha256sum {} + 2>/dev/null | grep -Ff known_bad_hashes.txt

# Known-bad IPs in current connections / logs
ss -tunap | grep -Ff bad_ips.txt

grep -rFf bad_ips.txt /var/log/ 2>/dev/null

# Known-bad filenames / paths
find / \( -path /proc -o -path /sys \) -prune -o -type f -name "kdevtmpfsi" -o -name "xmrig" -print 2>/dev/null
```

## YARA Basics

YARA rules describe malware by strings and conditions — a single rule can match a family across many variants, which is why it's the workhorse of content-based hunting. A minimal rule:

```
rule Linux_Miner_Generic {
  meta:
    description = "Generic Linux cryptominer indicators"
  strings:
    $a = "stratum+tcp://" ascii
    $b = "--donate-level" ascii
    $c = "/dev/shm/" ascii
  condition:
    2 of them
}
```

You write rules from the IOCs you extracted during triage (strings, pool URLs, unique byte sequences), and you pull vetted rules from public repositories for known families.

🔴 **Scope the rule to ELFs for speed and fewer false positives** — add the ELF magic to the condition so a whole-filesystem scan skips text/config files:

```
condition:
  uint32(0) == 0x464c457f and 2 of them    // 0x7f 'E' 'L' 'F'
```

Also constrain with `filesize < 5MB` where the family is small, and **test every rule against a clean corpus** before a fleet hunt to kill false positives.

## Scanning Files with YARA

```bash
# Recursive scan of the whole filesystem (skip virtual FS for speed)
yara -r -f rules.yar / 2>/dev/null

# Scan a specific staging area
yara -r rules.yar /tmp /var/tmp /dev/shm

# Scan web roots for webshell rules
yara -r webshell_rules.yar /var/www

# Show matching strings (which indicator hit)
yara -r -s rules.yar /path

# Compile rules once for faster repeated scans
yarac rules.yar rules.compiled; yara -C rules.compiled /path
```

## Scanning Process Memory

🔴 This is the piece that catches fileless malware — YARA can scan a running process's memory by PID, matching payloads that exist only in RAM (unpacked code, `memfd` executables, injected libraries) and never appear as a file to match.

```bash
# Scan one process's memory
yara rules.yar <PID>

# Scan every running process
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  yara rules.yar "$pid" 2>/dev/null && echo "  ^ MATCH in pid $pid ($(cat /proc/$pid/comm 2>/dev/null))"
done

# Scan a memory image with YARA (via Volatility, see Memory note)
vol -f mem.lime yarascan.YaraScan --yara-file rules.yar
```

🔴 On a host you *suspect is rootkitted*, a live per-PID `yara <PID>` scan reads memory through the possibly-compromised kernel — prefer scanning the **RAM image** (`vol yarascan`) for a trusted result, exactly as with `psscan` (see Memory Forensics).

## IOC Scanners

Pre-built scanners bundle large rulesets (YARA rules, hashes, filename/regex IOCs) for known threats, so you don't start from scratch.

```bash
# Loki - simple IOC + YARA scanner (Python)
python3 loki.py -p / --noprocscan   # filesystem only

python3 loki.py -p /                # incl. process memory

# Update Loki's signature set
python3 loki-upgrader.py

# Fenrir - bash-based IOC scanner (no dependencies, good for locked-down hosts)
./fenrir.sh /

# THOR Lite / commercial THOR - broader ruleset (if licensed)
./thor-lite-linux-64 --quick
```

🔴 Loki and Fenrir scan both files and process memory and combine hash, filename, C2, and YARA matching — a fast way to get broad coverage on a single host. Fenrir being pure bash is handy on a minimal or air-gapped host where you can't install YARA/Python.

## Fleet Scanning

Scaling a scan across many hosts is the fleet-hunt payoff — push the same rules/IOCs everywhere and collect the matches centrally.

```bash
# Velociraptor - run a YARA hunt across the fleet (VQL artifact)
#   Server-side: launch a hunt with the Yara.* artifact + your rule

# osquery - hash/YARA matching fleet-wide (yara table)
osqueryi "SELECT path, matches FROM yara WHERE path LIKE '/tmp/%%' AND sigrule='$(cat rule.yar)';"

# Ansible/Salt fan-out: copy rules + run yara, gather results
ansible all -m script -a "scan_with_yara.sh"
```

The workflow: extract IOCs from the first compromised host (hashes, YARA rules built from its strings, C2 IPs), then hunt those across the fleet to enumerate every affected system before closing the incident.

## Deep Threat Hunts

Disk + memory + fleet, driven by *your* confirmed IOCs. *(seasoned-DFIR)*

```bash
# 1. Hash sweep against your IOC list (fast, unambiguous)
find / -xdev -type f -exec sha256sum {} + 2>/dev/null | grep -Ff known_bad_hashes.txt

# 2. YARA disk + PROCESS MEMORY in one pass (memory catches fileless)
yara -r rules.yar /tmp /var/tmp /dev/shm /var/www 2>/dev/null

for pid in $(ls /proc | grep -E '^[0-9]+$'); do
  yara rules.yar "$pid" 2>/dev/null && echo "  ^ pid $pid ($(cat /proc/$pid/comm 2>/dev/null))"
done

# 3. TRUSTED memory scan on a rootkitted host (RAM image, not live /proc)
vol -f mem.lime yarascan.YaraScan --yara-file rules.yar

# 4. Network + log IOCs
ss -tunap | grep -Ff bad_ips.txt; grep -rFf bad_ips.txt /var/log 2>/dev/null

# 5. Bundled scanners (files + memory, broad coverage)
python3 loki.py -p /; ./fenrir.sh /

# 6. Compile rules once for repeated/fleet scans
yarac rules.yar rules.compiled

# 7. Fleet fan-out — enumerate EVERY affected host
osqueryi "SELECT path,matches FROM yara WHERE path LIKE '/tmp/%' AND sigrule='$(cat rule.yar)';"
```

**Hunt ideas:**

- **Scan disk AND process memory** — a fileless payload matches only the memory scan.
- **On a suspected-rootkitted host, scan the RAM image** (`vol yarascan`) — a live `/proc` scan can be lied to.
- **Scope rules to ELF magic** (`uint32(0)==0x464c457f`) so a whole-FS scan is fast and skips false positives on text.
- **Build rules from *your* confirmed IOCs**, test on a clean corpus to kill FPs, then fleet-hunt.
- **The point is scope** — extract IOCs from host #1 and hunt fleet-wide to enumerate every affected system before you close.

## Getting Max Value

- **Start from your confirmed IOCs + vetted public rules**, not a blind ruleset (blind scans = noise).
- **Scan disk + memory**; on a rootkitted host use the RAM image for trusted results.
- **Compile rules (`yarac`)** for repeated and fleet-wide scans.
- **Test rules for false positives on a clean corpus** before the fleet hunt.
- **Feed matches into the timeline and the fleet hunt** — and use **Sigma** for the log side (YARA covers files/memory; Sigma covers log events).

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Build IOCs/YARA from a sample | **ELF and Malware Triage** (11b) |
| A fileless in-memory match | **Live Response** (10), **Memory Forensics** (11) |
| Trusted memory YARA scan | **Memory Forensics** (11, `vol yarascan`) |
| Network-IOC context | **Network and PCAP Forensics** (10c) |
| Fleet-hunt as a playbook step | the **15 - Threat Landscape and Playbooks** |
| Log-based detection (Sigma) | **06 - Logs** |

## Scenarios

- **Fleet enumeration:** a hash/YARA rule from host #1 finds 12 more affected systems.
- **Fileless catch:** a YARA match in process memory with no matching file on disk.
- **Webshell sweep:** webshell YARA rules hit under `/var/www`.
- **Trojaned binary:** Loki/THOR flags a modified system binary.
- **Trusted scan:** a rootkitted host is scanned via its RAM image instead of live `/proc`.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Known-bad hash present on a host | Confirmed known malware |
| YARA rule matches a file in a staging dir | Payload matching a family |
| YARA match in **process memory** but not on disk | Fileless / in-memory malware |
| Loki/THOR/Fenrir flags a system binary | Trojaned binary |
| Same IOC matches on multiple fleet hosts | Campaign scope |
| Webshell YARA rule hits under a web root | Webshell present |
| Memory YARA match with no matching file | Fileless / in-memory payload |

## Resources

- YARA — https://virustotal.github.io/yara
- Loki / THOR — https://github.com/Neo23x0/Loki ; Fenrir — https://github.com/Neo23x0/Fenrir
- Velociraptor YARA hunts — https://docs.velociraptor.app ; Sigma — https://github.com/SigmaHQ/sigma
- MITRE ATT&CK: T1595 (Active Scanning — defensive analog), T1046; hunting supports all techniques

