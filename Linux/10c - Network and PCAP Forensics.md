# Network and PCAP Forensics

Live socket state (in the Live Response note) tells you what's connected *right now*; this note covers the deeper network layer — capturing and analyzing the traffic itself, reconstructing what left the host, and spotting the covert channels (DNS tunneling, encrypted C2 beacons, ICMP exfil) that a `ss`/`netstat` snapshot can't reveal. On a Linux host you often have the tools in place already (`tcpdump`, and sometimes Zeek/Suricata), and the host's own config (`/etc/hosts`, `resolv.conf`, firewall NAT rules) frequently holds the redirection tricks attackers use.

> 🔴 A point-in-time socket list misses low-and-slow C2 and any connection that was already torn down. If you suspect active C2 or exfil, capture traffic (`tcpdump -w`) and look at *behavior over time* — periodic same-size beacons, oversized DNS TXT queries, connections to a single external IP at a fixed interval — not just the current connection table.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Host Network Configuration](#host-network-configuration)
- [Capturing Traffic](#capturing-traffic)
- [Tie a Flow to a Process](#tie-a-flow-to-a-process)
- [Reading a Capture with tshark](#reading-a-capture-with-tshark)
- [DNS Analysis](#dns-analysis)
- [Beaconing and C2 Patterns](#beaconing-and-c2-patterns)
- [Encrypted C2 and JA3](#encrypted-c2-and-ja3)
- [Zeek and Suricata](#zeek-and-suricata)
- [Extracting Transferred Files](#extracting-transferred-files)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Capture to disk for offline analysis (rotate to avoid filling disk)
tcpdump -i any -w /evidence/capture.pcap -C 100 -W 10

# Live look at non-loopback traffic, no name resolution
tcpdump -i any -nn not host 127.0.0.1

# Top talkers in an existing capture
tshark -r capture.pcap -q -z conv,ip 2>/dev/null | sort -k9 -nr | head

# DNS queries (tunneling shows as long/odd names)
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -nr | head
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Which process owns a suspect flow? | `ss -tanp \| grep <ip>`; `lsof -i @<ip>`; `ausearch -sc connect` |
| Active + recent connections (between ss and pcap)? | `conntrack -L` |
| C2 beaconing? | SYN inter-arrival regularity to one dst |
| C2 over TLS (no decrypt)? | JA3 fingerprint + SNI + cert |
| DNS tunneling? | long high-entropy subdomains; TXT flood |
| Data exfil? | Zeek `conn.log` `orig_bytes >> resp_bytes` |
| Traffic redirected? | `/etc/hosts`, `resolv.conf`, NAT rules |
| A sniffer running on the host? | `ip link \| grep PROMISC` |
| Recover the transferred payload? | `tshark --export-objects`; Zeek file extraction |

## Host Network Configuration

Before capturing, read the host's own network config — it often reveals redirection and name-resolution tampering that explains where traffic is really going.

```bash
# Static name overrides (attacker can point a domain at their host)
cat /etc/hosts

# DNS resolvers (a rogue resolver enables interception)
cat /etc/resolv.conf; resolvectl status 2>/dev/null

# Interfaces, addresses, routes
ip a; ip route; ip -s link

# NAT / redirect rules (traffic being sent to an attacker host)
iptables -t nat -L -n -v; nft list ruleset 2>/dev/null

# Proxy environment (traffic tunneled through a proxy)
env | grep -i proxy; grep -riE "proxy" /etc/environment /etc/profile.d/ 2>/dev/null
```

🔴 A rogue entry in `/etc/hosts` (pinning a legitimate domain to an attacker IP), a changed `resolv.conf`, or a NAT redirect rule are all ways to silently reroute traffic — check these before concluding a connection is benign based on its apparent destination.

## Capturing Traffic

```bash
# Capture all interfaces to a rotating fileset (offline analysis)
tcpdump -i any -w /evidence/cap.pcap -C 100 -W 20 -Z root

# Filter to a suspect host or port (BPF syntax)
tcpdump -i any -nn host 203.0.113.5

tcpdump -i any -nn port 4444

# Capture with full packet contents (snaplen 0 = full)
tcpdump -i eth0 -s 0 -w /evidence/full.pcap

# Verbose live view with payload as ASCII (quick peek)
tcpdump -i any -nnA port 80
```

Prefer `-w` to a file over on-screen analysis — it preserves the evidence, lets you apply different filters later, and works with the richer tools below. Use `-C`/`-W` rotation so a long capture doesn't fill the disk.

## Tie a Flow to a Process

🔴 The pivot that turns "a connection" into "which malware": take a suspect external IP from the capture and map it to the owning PID on the host. This is the single most important step — a pcap alone tells you *what* talked to *whom*, not *which process*.

```bash
# Live: the process behind a connection to a suspect IP
ss -tanp | grep 203.0.113.5

lsof -i @203.0.113.5

# Historical (survives the connection tearing down) — auditd connect() records
ausearch -sc connect -i 2>/dev/null | grep 203.0.113.5

# The kernel connection table: active AND recently-closed (fills the gap between ss and pcap)
conntrack -L 2>/dev/null | grep 203.0.113.5

conntrack -L 2>/dev/null | awk '{print $6}' | sort | uniq -c | sort -nr | head
```

Once you have the PID, do the full `/proc` workup (Live Response) — recover the binary, read its `cmdline`/`environ`, and confirm it's the beacon.

## Reading a Capture with tshark

`tshark` (the CLI Wireshark) is the workhorse for offline capture analysis — statistics, field extraction, and protocol decoding without a GUI.

```bash
# Conversation/endpoint statistics
tshark -r cap.pcap -q -z conv,ip

tshark -r cap.pcap -q -z endpoints,ip

# Protocol hierarchy (what's actually in the capture)
tshark -r cap.pcap -q -z io,phs

# Extract specific fields (e.g. HTTP hosts + URIs)
tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri

# Follow a TCP stream
tshark -r cap.pcap -q -z follow,tcp,ascii,42

# TLS SNI (server names in encrypted sessions)
tshark -r cap.pcap -Y tls.handshake.extensions_server_name -T fields -e tls.handshake.extensions_server_name | sort | uniq -c
```

🔴 Even for encrypted C2 you can extract the **TLS SNI** and certificate details, which reveal the destination domain and often a self-signed or throwaway cert — useful IOCs when the payload itself is opaque.

## DNS Analysis

DNS is the most common covert channel because it's rarely blocked. Tunneling and DNS-based C2 produce telltale query patterns.

```bash
# All queried names, by frequency
tshark -r cap.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -nr

# Unusually long query names (data encoded in the subdomain)
tshark -r cap.pcap -Y dns -T fields -e dns.qry.name | awk '{ if (length($0) > 50) print }'

# TXT record queries (a classic tunneling carrier)
tshark -r cap.pcap -Y "dns.qry.type == 16" -T fields -e dns.qry.name

# High query volume to one domain (tunneling / DGA)
tshark -r cap.pcap -Y dns -T fields -e dns.qry.name | sed -E 's/^[^.]+\.//' | sort | uniq -c | sort -nr | head
```

🔴 Long, high-entropy subdomains, a flood of `TXT` queries, or a huge query volume to a single parent domain all indicate DNS tunneling or DNS-based C2 — the subdomains carry the encoded data or commands.

## Beaconing and C2 Patterns

Automated C2 beacons are periodic and uniform, which stands out from human-driven traffic once you look at timing and size.

```bash
# Connections to one external IP over time (look for fixed intervals)
tshark -r cap.pcap -Y "ip.dst == 203.0.113.5 && tcp.flags.syn == 1" -T fields -e frame.time_relative

# Same-size payloads repeating (uniform beacon)
tshark -r cap.pcap -Y "ip.dst == 203.0.113.5" -T fields -e frame.len | sort | uniq -c | sort -nr | head

# Destinations sorted by connection count (a single busy external IP = suspect)
tshark -r cap.pcap -q -z endpoints,ip | sort -k4 -nr | head
```

A destination contacted at a suspiciously regular cadence (every 30/60/300 seconds) with near-constant payload size is the signature of a beaconing implant — pivot to the process that owns the socket (Live Response note).

```bash
# Beacon MATH: SYN inter-arrival deltas to one dst — a tight cluster (low jitter) = automated
tshark -r cap.pcap -Y "ip.dst==203.0.113.5 && tcp.flags.syn==1" -T fields -e frame.time_epoch \
  | awk 'NR>1{printf "%.0f\n", $1-prev} {prev=$1}' | sort -n | uniq -c | sort -nr | head
```

🔴 Humans generate irregular timing; a wall of near-identical inter-arrival deltas (e.g. lots of `~60`s) is an implant's fixed callback interval.

## Encrypted C2 and JA3

🔴 You don't need to decrypt TLS to fingerprint the *client*. **JA3** hashes the TLS ClientHello (cipher suites, extensions, curves) — so a given C2 tool (Cobalt Strike, Metasploit, Sliver) produces a consistent JA3 regardless of the destination, and known-bad JA3s flag it even over encryption.

```bash
# JA3 client fingerprints in a capture (match against known-bad JA3 lists)
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3 -e ip.dst 2>/dev/null | sort | uniq -c | sort -nr

# SNI + certificate subject/issuer (destination domain + throwaway/self-signed tell)
tshark -r cap.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name | sort | uniq -c

tshark -r cap.pcap -Y 'tls.handshake.type==11' -T fields -e x509sat.printableString 2>/dev/null | sort -u
```

Zeek's `ssl.log` carries `ja3`/`ja3s` and cert fields too. A JA3 seen beaconing to a self-signed cert on a throwaway domain is high-confidence C2 without ever reading the plaintext.

## Zeek and Suricata

When present, these turn raw packets into structured logs and alerts that are far faster to triage than raw pcap.

```bash
# Zeek: generate connection/DNS/HTTP/SSL logs from a pcap
zeek -r cap.pcap

cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes

# Suricata: run rules over a pcap, read the alerts
suricata -r cap.pcap -l /evidence/suri/

cat /evidence/suri/eve.json | jq 'select(.event_type=="alert") | .alert.signature'
```

Zeek's `conn.log` (with `orig_bytes`/`resp_bytes`/`duration`) is excellent for spotting exfil — a connection that *sent* far more than it received, or long-lived low-volume connections (beacons).

## Extracting Transferred Files

```bash
# Carve files transferred over HTTP/SMB/etc. from a capture
tshark -r cap.pcap --export-objects http,/evidence/http_objects/

# Zeek file extraction (with the file-extraction script enabled)
zeek -r cap.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek

# Then hash + triage carved files (see the ELF/Malware Triage note)
sha256sum /evidence/http_objects/*
```

Recovering the actual bytes an attacker downloaded (a dropper, a tool) or exfiltrated (an archive) from the capture ties the network activity to a concrete artifact you can then analyze.

## Deep Threat Hunts

Behavior over time + pcap→process. *(seasoned-DFIR)*

```bash
# 1. Tie a suspect external IP to the owning process (the key pivot)
ss -tanp | grep 203.0.113.5; lsof -i @203.0.113.5; ausearch -sc connect -i 2>/dev/null | grep 203.0.113.5

# 2. Kernel connection table (active + recent — the gap between ss and pcap)
conntrack -L 2>/dev/null | awk '{print $6}' | sort | uniq -c | sort -nr | head

# 3. Beacon jitter to one dst (tight delta cluster = automated)
tshark -r cap.pcap -Y "ip.dst==203.0.113.5 && tcp.flags.syn==1" -T fields -e frame.time_epoch \
  | awk 'NR>1{printf "%.0f\n",$1-prev}{prev=$1}' | sort -n | uniq -c | sort -nr | head

# 4. JA3 C2-tool fingerprints over TLS
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3 2>/dev/null | sort | uniq -c | sort -nr

# 5. DNS tunneling (long high-entropy subdomains + TXT volume)
tshark -r cap.pcap -Y dns -T fields -e dns.qry.name | awk 'length>50' | head

# 6. Exfil (Zeek conn.log: sent >> received)
zeek -r cap.pcap && cat conn.log | zeek-cut id.resp_h orig_bytes resp_bytes | awk '$2>10*$3 && $2>1000000'

# 7. Sniffer on the host (promiscuous interface / ANOM_PROMISCUOUS)
ip link | grep -i PROMISC; ausearch -m ANOM_PROMISCUOUS -i 2>/dev/null

# 8. ICMP tunneling (oversized/patterned ping payloads)
tshark -r cap.pcap -Y 'icmp && data.len>48' -T fields -e ip.dst -e data.len 2>/dev/null | sort | uniq -c
```

**Hunt ideas:**

- **pcap→process is the critical pivot** — an IP alone is an IOC; tie it to a PID (`ss`/`lsof`/`ausearch connect`) to identify the actual malware.
- **JA3/JA3S fingerprint C2 tooling even over TLS** — known-bad JA3s flag Cobalt Strike/Metasploit/Sliver without decryption.
- **Beacon math beats eyeballing** — compute SYN inter-arrival deltas; low jitter (a tight delta cluster) is an automated callback, not a human.
- **`conntrack -L` bridges `ss` (now) and pcap (over time)** — it shows recently-closed connections a point-in-time `ss` missed.
- **A promiscuous interface / `ANOM_PROMISCUOUS`** means the attacker started a sniffer — credential/traffic capture.

## Getting Max Value

- **Capture to `-w` (rotated), analyze offline** — preserves evidence and lets you re-filter with the richer tools.
- **Always pivot pcap→process** — attribute every suspect flow to a PID, then do the `/proc` workup.
- **Even encrypted C2 leaks IOCs** — SNI, JA3/JA3S, and cert subject/issuer identify the tool and destination without plaintext.
- **`conntrack` catches what a socket snapshot missed** — recently-torn-down connections.
- **Extract + hash transferred files** to tie the network activity to a concrete droppable/exfil artifact.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Which process owns the flow | **Live Response** (10, `ss`/`lsof`), **Auditd** (`connect`) |
| Triage a carved payload | **ELF and Malware Triage** (11b), **IOC and YARA Scanning** (11d) |
| The live socket snapshot | **Live Response and Volatile Data** (10) |
| eBPF-based live network tracing | **eBPF Tooling for DFIR** (10d) |
| Resolution / redirect tampering | **Root Directory Structure** (01, `/etc/hosts`), **Live Response** |
| Fold C2 IOCs into the timeline | **Timelining** (13) |
| The malware behind a beacon | **Live Response** (10), **Cryptojacking / SSH-BF playbooks** (15) |

## Scenarios

- **Beacon:** regular same-size SYNs to one external IP at a fixed interval.
- **DNS tunnel:** long high-entropy subdomains or a `TXT`-query flood to one parent domain.
- **Exfil:** a connection that sent far more than it received (Zeek `conn.log`).
- **Encrypted C2:** a known-bad JA3 to a self-signed cert on a throwaway domain.
- **Redirection:** a rogue `/etc/hosts` entry or NAT rule rerouting traffic to the attacker.
- **Sniffer:** a promiscuous interface capturing credentials/traffic on the host.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Periodic same-size connections to one external IP | C2 beaconing |
| Long/high-entropy DNS subdomains or TXT flood | DNS tunneling / C2 |
| Connection that sent far more than it received | Data exfil |
| TLS to a self-signed cert / throwaway domain (SNI) | C2 over encryption |
| Rogue `/etc/hosts` entry or changed `resolv.conf` | Traffic redirection |
| NAT/redirect rule to an attacker host | Interception / tunneling |
| File carved from capture matching a dropper/tool | Concrete payload evidence |
| Known-bad JA3 fingerprint | C2 tooling identified over TLS |
| Promiscuous interface / `ANOM_PROMISCUOUS` | Sniffer capturing traffic/creds |

## Resources

- `tcpdump(1)`, Wireshark/`tshark` — https://www.wireshark.org
- Zeek — https://zeek.org ; Suricata — https://suricata.io
- JA3 TLS fingerprinting — https://github.com/salesforce/ja3
- `conntrack(8)` man page
- MITRE ATT&CK: T1071 (Application Layer Protocol), T1071.004 (DNS), T1572 (Protocol Tunneling), T1041 (Exfil over C2), T1040 (Network Sniffing)
