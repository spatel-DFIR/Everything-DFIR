# Masscan — Hands-On Use Cases

Every scenario below is the same stateless SYN-scan engine documented in `01 - Overview.md` §How It Works — what changes is scope, rate, port selection, and output handling. MITRE ATT&CK IDs are tagged per scenario: broad, unauthenticated network/Internet-facing sweeps map to **[T1595](https://attack.mitre.org/techniques/T1595/) (Active Scanning)** and its sub-techniques, while post-compromise sweeps of an internal network from a foothold map to **[T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery)** under the Discovery tactic — the same tool, but a different phase of the intrusion.

## Contents
- [Single-Port CIDR Sweep](#single-port-cidr-sweep)
- [Full Internet-Wide Scan with Exclude List](#full-internet-wide-scan-with-exclude-list)
- [Full-Port Sweep of a Specific Target Range](#full-port-sweep-of-a-specific-target-range)
- [Curated Port List for Internal Lateral-Movement Recon](#curated-port-list-for-internal-lateral-movement-recon)
- [UDP Service Discovery](#udp-service-discovery)
- [Banner Grabbing at Scale](#banner-grabbing-at-scale)
- [Spoofed Source IP for Clean Banner Grabs](#spoofed-source-ip-for-clean-banner-grabs)
- [Rate Tuning — Stealth vs. Speed](#rate-tuning--stealth-vs-speed)
- [IPv6 Target Scanning](#ipv6-target-scanning)
- [Output for Chaining into Other Tools](#output-for-chaining-into-other-tools)
- [Pausing and Resuming a Long-Running Scan](#pausing-and-resuming-a-long-running-scan)
- [Sharding a Scan Across Multiple Instances](#sharding-a-scan-across-multiple-instances)
- [Reproducible Scans with a Fixed Seed](#reproducible-scans-with-a-fixed-seed)
- [Custom HTTP Probing During Banner Grabs](#custom-http-probing-during-banner-grabs)

---

## Single-Port CIDR Sweep

**MITRE ATT&CK:** [T1595.001](https://attack.mitre.org/techniques/T1595/001/) (Active Scanning: Scanning IP Blocks)

```bash
masscan 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12 -p443 --open-only -oL rdp_open.lst
```

The baseline case — sweep every address in one or more ranges for a single port and print only hosts that answered SYN-ACK. This is the fastest way to answer "which hosts in this range have port 443 open" across a very large address space, something nmap's per-host state tracking makes impractically slow at this scale.

## Full Internet-Wide Scan with Exclude List

**MITRE ATT&CK:** T1595.001

```bash
masscan 0.0.0.0/0 -p22 --excludefile exclude.txt --rate 100000 -oX ssh_internet.xml
```

`--excludefile` is not optional at this scope — it keeps the scan off ranges an operator has explicitly agreed (or is legally obligated) not to touch. At the default 100 pps, one port across the full IPv4 address space (~4.29 billion addresses) would take roughly **16-17 months**; `--rate 100000` brings that same single-port sweep (minus exclusions) down to roughly **10 hours**, matching the tool's own documented example. This is squarely the scenario the man page's "Abuse Complaints" section warns about — expect ban-list and abuse-report traffic back at the scanning ASN.

## Full-Port Sweep of a Specific Target Range

**MITRE ATT&CK:** T1595.001

```bash
masscan 203.0.113.0/24 -p0-65535 --rate 25000 -oJ full_range.json
```

Every TCP port on every host in a /24 — the shape used when the goal is a complete attack-surface map of a known-in-scope range rather than hunting one specific service across a huge address space. `-p0-65535` covers the entire port space; note masscan has **no default port list** at all, unlike nmap's top-1000 default, so a bare `masscan <target>` with no `-p` scans nothing.

## Curated Port List for Internal Lateral-Movement Recon

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery)

```bash
masscan 10.10.10.0/24 -p22,135,139,445,3389,5985,5986 --rate 5000 -oG lateral_targets.grep
```

The internal, post-compromise flavor of the same scan — a curated list of ports associated with common lateral-movement paths (SSH, RPC endpoint mapper, SMB, RDP, WinRM) run from an already-compromised foothold against the local subnet. Grepable output (`-oG`) is a deliberate choice here — it chains directly into shell one-liners for the next step (e.g. filtering to hosts with 445 open before handing them to an Impacket sub-tool).

## UDP Service Discovery

**MITRE ATT&CK:** T1595.001, plus T1046 for the internal variant

```bash
masscan 10.10.10.0/24 -pU:53,U:161,U:123 --rate 2000 -oL udp_services.lst
```

UDP ports use the `U:` prefix inline in the port list rather than a separate `-sU` flag — this example checks for DNS (53), SNMP (161), and NTP (123). UDP scanning is inherently noisier and less reliable than TCP SYN scanning (many stacks silently drop unsolicited UDP with no ICMP port-unreachable), so treat negative results with more skepticism than a TCP closed/filtered determination.

## Banner Grabbing at Scale

**MITRE ATT&CK:** T1595.001, plus [T1592.002](https://attack.mitre.org/techniques/T1592/002/) (Gather Victim Host Information: Software) once banner content is used to fingerprint versions

```bash
masscan 198.51.100.0/24 -p80,443,22,21 --banners --rate 1000 -oJ banners.json
```

`--banners` upgrades the scan from a bare SYN probe to a completed handshake plus an application-layer read — HTTP titles, SSH version strings, FTP/SMTP banners, TLS certificate subjects, and more, all extracted automatically. This is the step that turns a port list into an actual service inventory, but see the next scenario for why it frequently needs a source-IP/source-port workaround to work reliably at all.

## Spoofed Source IP for Clean Banner Grabs

**MITRE ATT&CK:** T1595.001

```bash
# Requires 192.168.1.200 to be otherwise unused on the local subnet
masscan 10.0.0.0/8 -p80 --banners --source-ip 192.168.1.200
```

```bash
# Alternative: dedicate a source port and firewall it locally so the OS
# never sees (and therefore never RSTs) the replies
iptables -A INPUT -p tcp --dport 61000 -j DROP
masscan 10.0.0.0/8 -p80 --banners --source-port 61000
```

As covered in `01 - Overview.md`, masscan's packets never touch the local OS's TCP stack — so when a real SYN-ACK arrives, the kernel (which has no record of "sending" that SYN) will often fire back its own spurious RST before masscan's banner-grab logic can complete the handshake. Both fixes here are pulled directly from the tool's own documentation, and the man page states the spoofed-source-IP approach is the **preferred** of the two.

## Rate Tuning — Stealth vs. Speed

**MITRE ATT&CK:** T1595.001

```bash
# Stealth: near the 100 pps default, blends into background traffic
masscan 10.0.0.0/24 -p1-1024 --rate 50

# Speed: push toward what a native Linux NIC can sustain without PF_RING
masscan 10.0.0.0/8 -p443 --rate 1000000
```

`--rate` is the single biggest lever an operator has for balancing detectability against scan duration. The man page's own numbers: Windows/VM environments top out around 250–300K packets/second; native Linux reaches roughly 1.5–2.5 million packets/second; the PF_RING DNA driver is needed to approach the tool's theoretical 10–25 million packets/second ceiling. A rate anywhere above the low hundreds of packets/second per target subnet starts to visually resemble a SYN flood to a network-layer sensor — see `05 - Detection and Hunting.md`.

## IPv6 Target Scanning

**MITRE ATT&CK:** T1595.001

```bash
masscan 2001:db8::/32 -p443 --banners --source-ip 2001:db8::dead:beef --rate 500
```

IPv6 support is native — there is no `-6` flag, an IPv6 CIDR/range as the target is enough. Because the IPv6 address space per subnet is astronomically larger than IPv4, brute-force CIDR sweeps are only practical against small, specifically-known subnets; for anything larger, feed pre-identified addresses (from DNS enumeration, certificate transparency logs, etc.) in via `--includefile` instead of sweeping blind.

## Output for Chaining into Other Tools

**MITRE ATT&CK:** T1595.001

```bash
# Fast wide sweep, compact binary output
masscan 10.0.0.0/8 -p3389 --rate 200000 -oB rdp_hosts.scan

# Convert later, without re-scanning, into whatever format the next tool needs
masscan --readscan rdp_hosts.scan -oX rdp_hosts.xml
masscan --readscan rdp_hosts.scan -oJ rdp_hosts.json
```

The canonical masscan workflow is **wide-and-shallow first, deep-and-narrow second**: masscan establishes which hosts/ports are alive at Internet/enterprise scale, then that host list feeds a slower, deeper tool (nmap `-sV -A` for service/OS fingerprinting, or a protocol-specific tool like an RDP/SMB enumerator) against only the confirmed-live subset. `-oB` keeps disk usage low for very large scans; `--readscan` converts it after the fact into whatever downstream format is needed, without re-transmitting a single packet.

## Pausing and Resuming a Long-Running Scan

**MITRE ATT&CK:** T1595.001

```bash
masscan 0.0.0.0/0 -p0-65535 --excludefile exclude.txt --rate 50000 -oJ everything.json
# <Ctrl-C> — masscan stops transmitting, waits up to --wait seconds for
# outstanding replies, then writes its current position to paused.conf

masscan --resume paused.conf
```

A full port sweep of the entire IPv4 space is a multi-day undertaking even at a fast rate; `--resume` lets an operator stop and restart across sessions (a maintenance window, a reboot, a VPN drop) without losing progress or re-scanning already-covered ground. `--resume` also auto-enables `--append-output` so results accumulate in the same file rather than being overwritten.

## Sharding a Scan Across Multiple Instances

**MITRE ATT&CK:** T1595.001

```bash
# Run concurrently on three separate machines
masscan 0.0.0.0/0 -p0-65535 --shards 1/3
masscan 0.0.0.0/0 -p0-65535 --shards 2/3
masscan 0.0.0.0/0 -p0-65535 --shards 3/3
```

`--shards X/Y` splits one logical scan's index space across `Y` cooperating instances with no overlap and no coordination needed beyond agreeing on the same target/port spec — the standard way to distribute an Internet-scale scan across multiple cloud instances or team members for a fraction of the wall-clock time. `--resume-index`/`--resume-count` offer a lower-level, manually-chunked alternative to the same goal.

## Reproducible Scans with a Fixed Seed

**MITRE ATT&CK:** T1595.001

```bash
masscan 10.0.0.0/16 -p1-1024 --seed 424242 --rate 10000 -oJ week1.json
# ...one week later, identical target order for a delta comparison...
masscan 10.0.0.0/16 -p1-1024 --seed 424242 --rate 10000 -oJ week2.json
```

By default the permutation seed is drawn from the current time, so the scan order (and therefore the exact packet timing/sequence) differs run to run. Pinning `--seed` makes the scan order deterministic and repeatable — useful for change-detection sweeps run on a schedule, or for an operator who wants an auditable, reproducible scan plan for a report.

## Custom HTTP Probing During Banner Grabs

**MITRE ATT&CK:** T1595.001, plus [T1590](https://attack.mitre.org/techniques/T1590/) (Gather Victim Network Information) where the goal is WAF/CDN fingerprinting

```bash
masscan 198.51.100.0/24 -p80,443 --banners \
  --http-user-agent "Keurig K575 Coffee Maker" \
  --http-url /healthz \
  --http-field "X-Forwarded-For:127.0.0.1" \
  --rate 2000 -oJ http_probe.json
```

Overriding the HTTP method/URL/user-agent/headers lets an operator probe a specific application endpoint (e.g. a health-check path) or attempt to slip past user-agent-based WAF rules, rather than relying on masscan's default bare `GET /` request. This is also useful defensively — an analyst can recognize masscan's default (unmodified) HTTP probe signature in web-server access logs precisely because it's a distinctive, minimal `GET / HTTP/1.0`-style request unless one of these `--http-*` flags was used to disguise it (see `04 - Target Evidence.md`).
