# Nmap — Hands-On Use Cases

Every scenario below draws on the phase pipeline documented in `01 - Overview.md` §How It Works — what changes is which phases run, how aggressively, and how much the operator tries to blend in. A note on ATT&CK mapping before the scenarios: Nmap is an **active** prober, so it always falls under [T1595](https://attack.mitre.org/techniques/T1595/) (Active Scanning), never [T1590](https://attack.mitre.org/techniques/T1590/) (Gather Victim Network Information) — T1590 is passive/OSINT (WHOIS, DNS records, public breach data) and Nmap never does that. When Nmap is run from an already-compromised internal host instead of external infrastructure, the more accurate tag shifts to [T1018](https://attack.mitre.org/techniques/T1018/) (Remote System Discovery) and/or [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery) — both are called out per scenario where relevant.

## Contents
- [Host Discovery / Ping Sweep Across a Subnet](#host-discovery--ping-sweep-across-a-subnet)
- [Full TCP Port Sweep](#full-tcp-port-sweep)
- [UDP Service Discovery](#udp-service-discovery)
- [Service and Version Detection](#service-and-version-detection)
- [OS Fingerprinting](#os-fingerprinting)
- [Firewall/ACL Rule Mapping with an ACK Scan](#firewallacl-rule-mapping-with-an-ack-scan)
- [NSE Vulnerability Scanning](#nse-vulnerability-scanning)
- [NSE Authentication and Brute-Force Scripts](#nse-authentication-and-brute-force-scripts)
- [Stealth Timing and Rate-Limited Evasion](#stealth-timing-and-rate-limited-evasion)
- [Fragmentation and MTU Evasion](#fragmentation-and-mtu-evasion)
- [Decoy Scanning](#decoy-scanning)
- [Idle (Zombie) Scanning for Blind Attribution](#idle-zombie-scanning-for-blind-attribution)
- [IPv6 Reconnaissance](#ipv6-reconnaissance)
- [Chaining Nmap's Output into Other Tooling](#chaining-nmaps-output-into-other-tooling)
- [Scripted Mass Recon from an Internal Foothold](#scripted-mass-recon-from-an-internal-foothold)

---

## Host Discovery / Ping Sweep Across a Subnet

**MITRE ATT&CK:** [T1595.001](https://attack.mitre.org/techniques/T1595/001/) (Active Scanning: Scanning IP Blocks) — or [T1018](https://attack.mitre.org/techniques/T1018/) (Remote System Discovery) if run from an internal foothold rather than external infrastructure.

```bash
# No port scan at all — just find what's alive
sudo nmap -sn 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' > live_hosts.txt
```
The cheapest, quietest recon step — establishes a target list before spending time/noise on port scanning. Root privilege gets the full discovery probe set (ICMP echo, SYN:443, ACK:80, ICMP timestamp, plus ARP automatically on-segment); unprivileged execution narrows this to SYN-equivalent probes on 80/443.

## Full TCP Port Sweep

**MITRE ATT&CK:** T1595.001, or T1046 (Network Service Discovery) internally.

```bash
# Default top-1000 ports, fast
sudo nmap -sS -T4 10.10.10.5

# Every TCP port, saved in all three output formats
sudo nmap -sS -p- -T4 10.10.10.5 -oA full_tcp_sweep
```
`-sS` is the default scan type when running as root; unprivileged execution silently substitutes `-sT`. `-p-` trades speed for completeness — services intentionally hidden above port 1024 (or above 49152, the ephemeral range some tools land services in specifically to dodge default scans) only show up here.

## UDP Service Discovery

**MITRE ATT&CK:** T1595.001, T1046.

```bash
sudo nmap -sU --top-ports 100 -T4 10.10.10.5
```
UDP scanning is inherently slow: an open port either replies with a protocol-specific payload or simply says nothing (`open|filtered`), and Linux by default rate-limits ICMP port-unreachable replies to about one per second — so a full 65535-port UDP sweep can take hours against a single closed-by-default host. Scoping with `--top-ports` (or a curated `-p` list of DNS/SNMP/NTP/DHCP/etc.) is standard practice rather than an evasion choice.

## Service and Version Detection

**MITRE ATT&CK:** T1595.001.

```bash
sudo nmap -sV --version-intensity 9 10.10.10.5
```
Turns a list of open ports into a list of *what's actually running* — the input every subsequent decision (exploit selection, credential-spray target list, vulnerability lookup) depends on. `--version-intensity 9` (`--version-all`) trades scan time for the highest match confidence; `--version-light` is the fast/quiet equivalent for a first pass.

## OS Fingerprinting

**MITRE ATT&CK:** T1595.001 — ATT&CK has no sub-technique specific to OS fingerprinting; it's covered under the same general Active Scanning umbrella.

```bash
sudo nmap -O --osscan-guess 10.10.10.5
```
Needs at least one confirmed open and one confirmed closed port to have a real chance at a match — run after a port scan, not standalone against an unscanned host. `--osscan-guess` widens the match when nothing in `nmap-os-db` fits exactly, at the cost of more false positives.

## Firewall/ACL Rule Mapping with an ACK Scan

**MITRE ATT&CK:** T1595.001.

```bash
sudo nmap -sA -p 1-1000 10.10.10.5
```
`-sA` can never report a port as "open" — every response is `unfiltered` (RST came back, so no stateful filter is dropping it) or `filtered` (nothing came back, or an ICMP error did). Used specifically to map *which ports a firewall is blocking*, independent of what's actually listening behind it — a reconnaissance step in its own right when the goal is understanding the perimeter, not the services.

## NSE Vulnerability Scanning

**MITRE ATT&CK:** [T1595.002](https://attack.mitre.org/techniques/T1595/002/) (Active Scanning: Vulnerability Scanning).

```bash
sudo nmap -sV --script vuln 10.10.10.5
```
Runs every script tagged `vuln` against identified services — CVE-specific checks, misconfiguration probes, known-exploitable-condition tests. Requires `-sV` (or at least open ports already known) since `vuln` scripts are `portrule`-gated to specific identified services.

## NSE Authentication and Brute-Force Scripts

**MITRE ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force), specifically [T1110.001](https://attack.mitre.org/techniques/T1110/001/) (Password Guessing) when a wordlist is supplied — plus T1595.002.

```bash
# Default/blank credential and anonymous-access checks
sudo nmap -sV --script "auth" 10.10.10.5

# Credential spray against a discovered service
sudo nmap -p 445 --script smb-brute \
  --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.5
```
The `auth` category checks for default creds, anonymous/null-session access, and weak authentication configuration without guessing; `brute` scripts (like `smb-brute`, `ftp-brute`, `ssh-brute`) actively spray credential lists supplied via `--script-args` — noisy, and the single most likely NSE use case to trigger account lockouts, so scope the target list and wordlist deliberately.

## Stealth Timing and Rate-Limited Evasion

**MITRE ATT&CK:** T1595.001 — timing/rate evasion is a modifier on the base technique, not a distinct ATT&CK ID.

```bash
# Paranoid: one probe at a time, 5-minute gaps — built for staying under long-window thresholds
sudo nmap -sS -T0 -p 22,80,443 10.10.10.5

# Finer control: explicit delay and a packet-rate ceiling instead of a template
sudo nmap -sS --scan-delay 10s --max-rate 5 10.10.10.0/24
```
`-T0`/`-T1` and manual `--scan-delay`/`--max-rate` values are aimed at rate-based scan-detection heuristics (N ports touched by one source within window T) rather than at hiding the packets themselves — the SYN packets are exactly as visible on the wire, just spread far enough apart that a short correlation window never sees enough of them to alert.

## Fragmentation and MTU Evasion

**MITRE ATT&CK:** T1595.001 — no distinct ATT&CK ID; a packet-crafting modifier on the base technique.

```bash
sudo nmap -sS -f 10.10.10.5

# Larger, still-fragmented packets via a custom offset
sudo nmap -sS --mtu 16 10.10.10.5
```
Splits each probe into 8-byte (or, with `--mtu`, larger multiples-of-8) IP fragments, aimed at packet filters/IDS sensors that inspect packets individually rather than reassembling the stream first. Has no effect on a target or intermediate device that reassembles fragments before inspection — which is the default posture on most modern stacks and NGFWs.

## Decoy Scanning

**MITRE ATT&CK:** T1595.001 — no distinct ATT&CK ID.

```bash
sudo nmap -sS -D RND:10,ME 10.10.10.5
```
Sends the real probes alongside spoofed packets that appear to come from additional (here, 10 random) source IPs. **The operator's real IP is still one of the addresses that touched the target** — decoys make *attribution* harder (which of these N source IPs is the real scanner), not detection itself; a target still sees a scan happen, from a larger apparent set of sources.

## Idle (Zombie) Scanning for Blind Attribution

**MITRE ATT&CK:** T1595.001 — no distinct ATT&CK ID; the defining characteristic of this variant is that the operator's real IP never appears in the target's logs at all.

```bash
sudo nmap -sI 192.0.2.50 10.10.10.5
```
Requires a "zombie" host with a predictable, low-traffic IP-ID sequence — Nmap infers port state purely by watching how the zombie's IP-ID counter increments in response to spoofed traffic, so **no packet the target sees ever carries the operator's actual source address**. Slower and far less reliable than a direct scan, and modern OSes with randomized IP-ID generation largely defeat it — but where a usable zombie exists, it is the single stealthiest scan type in the tool.

## IPv6 Reconnaissance

**MITRE ATT&CK:** T1595.001.

```bash
sudo nmap -6 -sS -sV 2001:db8::5
```
IPv6 support extends to host discovery, port scanning, version detection, and NSE — but not every scan type has full IPv6 parity, and Windows raw-socket IPv6 scanning specifically requires Vista or later on Ethernet interfaces. Worth deliberately checking IPv6-enabled targets that IPv4-only recon would otherwise miss entirely — a dual-stack host with a locked-down IPv4 firewall profile and an unmanaged IPv6 one is a common real-world gap.

## Chaining Nmap's Output into Other Tooling

**MITRE ATT&CK:** Not a technique in its own right — a tooling/workflow pattern layered on top of whichever scan produced the data.

```bash
# XML → feed into other tooling that consumes Nmap's schema
sudo nmap -sV -oX scan.xml 10.10.10.0/24

# Grepable → quick one-liner pivots without a parser
sudo nmap -sS -oG - 10.10.10.0/24 | grep "/open/" | cut -d' ' -f2
```
`-oX` is the format most downstream tooling (vulnerability scanners, asset-inventory pipelines, other offensive frameworks that ingest Nmap's XML schema) expects; `-oG`'s deprecated-but-still-scriptable one-line-per-host format remains popular for fast shell pipelines straight into `xargs`-driven follow-on tooling.

## Scripted Mass Recon from an Internal Foothold

**MITRE ATT&CK:** T1018 (Remote System Discovery) and T1046 (Network Service Discovery) — the internal, post-compromise counterpart to the external T1595 scenarios above.

```bash
# Run from an already-compromised host, sweeping internal ranges
for net in 10.10.10.0/24 10.10.20.0/24 10.10.30.0/24; do
  sudo nmap -sS -T4 --top-ports 200 -oA "sweep_$(echo $net | tr '/' '_')" "$net"
done
```
This is the shape internal recon takes once initial access is established — Nmap run from inside the perimeter, against internal ranges a purely external scan would never reach, usually as the direct precursor to lateral-movement tool selection (see the sibling `Impacket/` sub-tool folders for what typically follows a discovered SMB/WinRM/RPC service).
