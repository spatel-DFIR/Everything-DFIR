# Nmap — Overview

> 🔴 **Red Flag Principle:** A single source touching many destination ports with TCP SYN packets that never complete the three-way handshake — sequential or pseudo-random ports, no application data, sessions abandoned the instant a SYN/ACK comes back — is structurally impossible for normal client traffic and is Nmap's default (`-sS`) fingerprint. When OS detection (`-O`) is added, that fingerprint gets a second, even sharper tell: a burst of ~16 crafted TCP/ICMP/UDP probes with unusual flag/option combinations landing on one host within about 500ms.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Nmap ("Network Mapper") was written by **Gordon Lyon**, using the handle **Fyodor**, and first released as roughly 2,000 lines of Linux-only C in **Phrack Magazine, Issue 51, Article 11, on September 1, 1997**. It has been maintained continuously since under **The Nmap Project** / **Insecure.Org**, with **David Fifield** and **Daniel Miller** singled out by the project itself for their sustained multi-year contributions alongside Fyodor. Source and issue tracking live at [`github.com/nmap/nmap`](https://github.com/nmap/nmap) (a mirror of the canonical Subversion repo); the authoritative technical reference is the free online *Nmap Network Scanning* book at [nmap.org/book](https://nmap.org/book/). Nmap ships under the **Nmap Public Source License (NPSL)** — loosely GPLv2-based but not GPL-compatible, free for end-use, with a separate commercial OEM license funding development (Nmap Software LLC).

Selected version milestones (verified against [nmap.org/book/history-future.html](https://nmap.org/book/history-future.html)):

| Feature | Version | Date |
|---|---|---|
| OS detection | 2.00 | December 12, 1998 |
| Windows support | 2.54BETA16 | December 7, 2000 |
| macOS support | 3.00 | July 31, 2002 |
| IPv6 support | 3.10ALPHA1 | August 28, 2002 |
| Service/version detection (`-sV`) | 3.45 | September 16, 2003 |
| Nmap Scripting Engine (NSE) | 4.21ALPHA1 | December 10, 2006 |
| Zenmap GUI (replaced NmapFE) | 4.22SOC1 | July 8, 2007 |

## How It Works

A full-featured invocation runs as a pipeline of largely independent phases — which phases execute depends entirely on which flags are given:

```
nmap -sS -sV -O -sC -p- target.corp.local
─────────────────────────────────────────
Phase 1 — Target enumeration
  Expand target spec (CIDR, ranges, -iL file) into a flat list of IPs

Phase 2 — Host discovery                                    (skipped by -Pn)
  ICMP echo + TCP SYN:443 + TCP ACK:80 + ICMP timestamp ──▶  Target
  (unprivileged users: TCP-connect-equivalent SYN to 80/443 only;
   ARP used automatically instead of any of the above for on-segment targets)
  Response / no response ──▶  host marked "up" or dropped from later phases

Phase 3 — Port scanning                        (-sS/-sT/-sU/-sA/... — see table below)
  Raw probe packets to each targeted port ──▶  Target
  Response classified: open / closed / filtered / open|filtered / unfiltered

Phase 4 — Service & version detection                                    (-sV)
  nmap-service-probes probes sent to each OPEN port ──▶  Target
  Banner/response pattern-matched against ~1,000+ signatures, 180+ protocols

Phase 5 — OS detection                                                    (-O)
  16-probe TCP/ICMP/UDP burst (~500ms total) to 1 open + 1 closed port ──▶  Target
  Stack-behavior fingerprint compared against the nmap-os-db database

Phase 6 — NSE                                                (-sC / --script)
  Lua 5.4 scripts run per-phase (prerule/hostrule/portrule/postrule),
  many reconnecting to already-identified open ports ──▶  Target

Phase 7 — Output
  Results formatted per -oN/-oX/-oG/-oA and printed and/or written to disk
```

### Port-scan mechanics — how each scan type reads a response

All raw-packet scan types require **root/raw-socket privilege** on Unix-like systems (raw sockets); `-sT` is the sole exception and works unprivileged because it hands the connection off to the OS's own `connect()` syscall instead of crafting packets directly. Verified against [nmap.org/book/man-port-scanning-techniques.html](https://nmap.org/book/man-port-scanning-techniques.html):

| Scan | Flag | Privilege | Open | Closed | Filtered |
|---|---|---|---|---|---|
| TCP SYN ("half-open") | `-sS` | root | SYN/ACK returned, then Nmap sends RST — handshake never completes | RST returned | no response, or ICMP unreachable |
| TCP Connect | `-sT` | none | full 3-way handshake completes via OS `connect()` | RST returned | no response, or ICMP unreachable |
| TCP ACK | `-sA` | root | **cannot determine open** — used only to map firewall rulesets | RST returned → **unfiltered** | no response / ICMP unreachable → filtered |
| TCP Window | `-sW` | root | RST with a **positive** TCP window field | RST with a **zero** window field | same as ACK scan — unreliable, stack-dependent |
| TCP Null | `-sN` | root | no response → `open\|filtered` | RST returned | ICMP unreachable → filtered |
| TCP FIN | `-sF` | root | same as Null (single FIN flag) | RST returned | ICMP unreachable → filtered |
| TCP Xmas | `-sX` | root | same as Null (FIN+PSH+URG set — "lit up like a Christmas tree") | RST returned | ICMP unreachable → filtered |
| TCP Maimon | `-sM` | root | FIN/ACK probe; many BSD-derived stacks silently drop it → `open\|filtered` | RST returned | ICMP unreachable → filtered |
| UDP | `-sU` | root | protocol-specific response (e.g. DNS/SNMP payloads) → open | ICMP port unreachable (type 3, code 3) → closed | other ICMP error → filtered; no response → `open\|filtered` |
| SCTP INIT | `-sY` | root | INIT-ACK returned | ABORT returned | no response / ICMP unreachable |
| SCTP COOKIE ECHO | `-sZ` | root | packet silently dropped (RFC-compliant open behavior) — indistinguishable from filtered | ABORT returned | — |
| IP Protocol | `-sO` | root | any response at all | ICMP protocol unreachable (type 3, code 2) | no response → `open\|filtered` |
| Idle/Zombie | `-sI <zombie>` | root | inferred entirely from a **third-party host's** IP-ID sequence — no packet the target sees ever carries the operator's real IP | — | — |
| FTP Bounce | `-b user:pass@server:port` | none | abuses a vulnerable FTP server's `PORT` command to scan through it — mostly a historical curiosity today | — | — |

Null/FIN/Xmas/Maimon all lean on RFC 793's requirement that a closed port RST — but Windows, Cisco, and several other stacks reply with RST regardless of state, so these scans are largely a Unix-only technique in practice.

`-sS` never actually opens a connection: on an open port Nmap receives the SYN/ACK and immediately answers with **RST instead of the final ACK**, so the target's application layer never sees the connection ("half-open"). This is *why* it's stealthier than `-sT` toward application-level logging (nothing at Layer 7 ever sees it) — but not toward network-layer detection, since the SYN packet itself is exactly as visible either way.

```
Attacker (-sS)                              Target:445
───────────────                             ──────────
SYN ─────────────────────────────────────▶
                          port open:  ◀───── SYN/ACK
RST (torn down, ACK never sent) ─────────▶      (connection never reaches ESTABLISHED)

                          port closed: ◀───── RST
                          port filtered: ◀───── (nothing) or ICMP type 3 unreachable
```

### Service & version detection (`-sV`)

Nmap connects to each **open** port and sends a graduated sequence of probes drawn from the `nmap-service-probes` file — a purpose-built probe/match grammar (`Probe`, `match`, `softmatch`, `ports`, `sslports`, `rarity`, `fallback` directives) rather than a simple banner grab. `--version-intensity <0-9>` controls how many probes get tried (**default 7**); `--version-light` is shorthand for intensity 2 (fast, common services only), `--version-all` for intensity 9 (every probe, slow but thorough). The database recognizes **over 1,000 service signatures across 180+ protocols**.

### OS fingerprinting (`-O`)

Nmap sends up to **16 TCP/ICMP/UDP probes in roughly 500ms** against one confirmed open port and one confirmed closed port (OS detection is markedly less reliable without both), verified against [nmap.org/book/osdetect-methods.html](https://nmap.org/book/osdetect-methods.html):

| Probe set | Count | What it tests |
|---|---|---|
| SEQ | 6× TCP SYN, 100ms apart | ISN generation algorithm (GCD/ISR/SP), TCP option ordering, window scaling |
| ECN | 1× SYN with CWR+ECE set | Explicit Congestion Notification support |
| T2–T7 | 6× TCP, mixed flag combinations to open/closed ports | Flag-handling quirks (e.g. Null-flag or FIN+PSH+URG to an *open* port, SYN to a *closed* port) |
| IE | 2× ICMP echo request | DF-bit handling, ICMP payload-size behavior |
| U1 | 1× UDP to a closed port | ICMP port-unreachable message integrity (returned IP ID, checksums, payload echo) |

Every response attribute (TCP option order, IP-ID generation class — zero/random/incremental/broken-incremental, TTL, timestamp increment rate, and more) is assembled into a single fingerprint and compared against the reference signatures in `nmap-os-db`.

### The Nmap Scripting Engine (NSE)

Scripts are written in embedded **Lua 5.4** and run in one of four phases — `prerule` (before any scanning), `hostrule` (per host discovered), `portrule` (per matching open port), `postrule` (after everything else) — verified against [nmap.org/book/nse.html](https://nmap.org/book/nse.html). `-sC` runs the **`default`** category only; `--script` accepts individual script names, categories, or Lua boolean expressions across the 14 official categories: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`. `--script-args` passes key/value arguments (e.g. brute-force credential lists) straight into a script's Lua environment.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Network/Transport | Raw TCP, UDP, SCTP, ICMP, and arbitrary IP-protocol packets, crafted directly — bypasses the OS TCP stack for every scan type except `-sT` |
| Host discovery | ARP (automatic, on-segment), ICMP echo/timestamp/netmask, TCP SYN/ACK probes, UDP probes |
| Service identification | Application-layer probe/response matching (`nmap-service-probes`) — protocol-agnostic, works against any TCP/UDP service that responds |
| OS fingerprinting | TCP/IP stack behavior analysis (ISN generation, IP-ID sequencing, TCP option ordering/values, ICMP quirks) against `nmap-os-db` |
| Scripting | Lua 5.4 (NSE) — scripts can themselves speak higher-layer protocols (HTTP, SMB, LDAP, SSH, SNMP, FTP, etc.) once a port is identified |
| Evasion | IP fragmentation, decoy IP spoofing, source-port spoofing, MAC spoofing, idle/zombie scanning via a third-party IP-ID side channel |

## Command-Line Switches — Quick Reference

Full flag reference verified against the official [Nmap Reference Guide](https://nmap.org/book/man.html), written for a reader who has never run the tool.

**Target Specification & Host Discovery**

| Switch | Plain-English meaning |
|---|---|
| `-iL <file>` | Read targets from a file, one per line |
| `-iR <num>` | Pick `<num>` random public IPs to scan (internet-wide recon) |
| `--exclude` / `--excludefile` | Skip listed hosts even if they match the target spec |
| `-sL` | List-only — resolves names, sends **no packets** at all |
| `-sn` | Host discovery only, no port scan (default probes: ICMP echo, TCP SYN:443, TCP ACK:80, ICMP timestamp — reduces to SYN-only 80/443 unprivileged) |
| `-Pn` | Skip host discovery entirely, treat every target as up |
| `-PS/-PA/-PU/-PY <ports>` | Custom TCP SYN / TCP ACK / UDP / SCTP-INIT discovery probe, default ports 80/80/40125/80 respectively |
| `-PE/-PP/-PM` | ICMP echo / timestamp / address-mask discovery probes |
| `-PO <protocols>` | IP-protocol discovery probe (default protocols 1/ICMP, 2/IGMP, 4/IP-in-IP) |
| `-n` / `-R` | Never do reverse-DNS / always do reverse-DNS |
| `--traceroute` | Traceroute every target after scanning, using decreasing TTLs |

**Scan Techniques**

| Switch | Plain-English meaning |
|---|---|
| `-sS` | SYN ("half-open") scan — the default when run as root |
| `-sT` | Full TCP connect scan — the default when unprivileged |
| `-sU` | UDP scan — combinable with a TCP scan type in the same run |
| `-sA` / `-sW` | ACK / Window scan — firewall-ruleset mapping, never reports "open" |
| `-sN` / `-sF` / `-sX` | Null / FIN / Xmas scan — RFC-793 edge-case probes, Unix-reliable only |
| `-sM` | TCP Maimon scan (FIN/ACK) |
| `-sY` / `-sZ` | SCTP INIT / COOKIE ECHO scan |
| `-sO` | IP protocol scan |
| `-sI <zombie[:port]>` | Idle/zombie scan through a third-party host |
| `-b <ftp-relay>` | FTP bounce scan |
| `--scanflags <flags>` | Custom, arbitrary TCP flag combination |

**Port Specification**

| Switch | Plain-English meaning |
|---|---|
| `-p <ports>` | Explicit ports/ranges (`-p-` = all 65535); protocol prefixes `T:`/`U:`/`S:`/`P:` mix scan types per range |
| `-F` | Fast mode — top **100** ports instead of the default top **1,000** |
| `--top-ports <n>` | Scan the `n` most common ports per `nmap-services` frequency data |
| `--port-ratio <r>` | Scan every port above a given frequency ratio (0.0–1.0) |
| `-r` | Scan ports in sequential order rather than Nmap's default randomized order |
| `--exclude-ports` | Remove ports from every phase, including discovery |

**Service & Version Detection**

| Switch | Plain-English meaning |
|---|---|
| `-sV` | Enable service/version detection |
| `--version-intensity <0-9>` | How many probes to try per port. **Default 7** |
| `--version-light` | Shorthand for intensity 2 — fast, common services only |
| `--version-all` | Shorthand for intensity 9 — every probe, slowest, most thorough |
| `--version-trace` | Show the full probe/match exchange (debugging) |

**OS Detection**

| Switch | Plain-English meaning |
|---|---|
| `-O` | Enable OS fingerprinting (needs ≥1 open and ≥1 closed port for best accuracy) |
| `--osscan-limit` | Only attempt OS detection against hosts that already meet that condition |
| `--osscan-guess` | Guess more aggressively when there's no exact `nmap-os-db` match |

**NSE (Scripting)**

| Switch | Plain-English meaning |
|---|---|
| `-sC` | Run the `default` NSE script category |
| `--script <names/categories/expr>` | Run specific scripts, categories, or a Lua boolean expression across categories |
| `--script-args <k=v,...>` | Pass arguments into scripts (e.g. brute-force wordlists/credentials) |
| `--script-args-file` | Same, read from a file |
| `--script-trace` | Show script network traffic (debugging) |
| `--script-updatedb` | Rebuild the script database after adding/editing scripts |

**Timing & Performance**

| Switch | Plain-English meaning |
|---|---|
| `-T0`–`-T5` | Timing templates, Paranoid → Insane (see table below) |
| `--min-rate` / `--max-rate` | Floor/ceiling packets-per-second, overrides adaptive timing |
| `--scan-delay` / `--max-scan-delay` | Minimum/maximum time between probes to the same host |
| `--max-retries` | Probe retransmission cap. **Default (no `-T` template): 10** |
| `--host-timeout` | Give up on a host entirely after this long |
| `--min-hostgroup` / `--max-hostgroup` | Hosts scanned in parallel as one group — default starts at 5, scales up to 1024 |
| `--min-parallelism` / `--max-parallelism` | Outstanding probes in flight — default can drop to 1 on an unreliable network or rise to several hundred on a clean one |

| Template | Name | Behavior |
|---|---|---|
| `-T0` | Paranoid | One probe at a time, **5-minute** wait between probes |
| `-T1` | Sneaky | **15-second** wait between probes |
| `-T2` | Polite | **0.4-second** wait between probes |
| `-T3` | Normal | Default — no modification, adaptive timing |
| `-T4` | Aggressive | `--max-rtt-timeout 1250ms --min-rtt-timeout 100ms --initial-rtt-timeout 500ms --max-retries 6`, 10ms scan-delay cap |
| `-T5` | Insane | `--max-rtt-timeout 300ms --min-rtt-timeout 50ms --initial-rtt-timeout 250ms --max-retries 2 --host-timeout 15m`, 5ms scan-delay cap |

**Firewall / IDS Evasion**

| Switch | Plain-English meaning |
|---|---|
| `-f` | Fragment packets into 8-byte pieces after the IP header (`-f -f` / `-ff` → 16-byte pieces) |
| `--mtu <n>` | Custom fragment size, must be a multiple of 8 |
| `-D <decoy1,decoy2,...,ME,...>` | Scan alongside spoofed decoy source IPs so the target sees many apparent scanners; `RND`/`RND:<n>` generate random decoys; **the real source IP is still among them** — this obscures *which* IP is real, not *that* a scan happened |
| `-S <IP>` | Spoof the scan's source IP (typically paired with `-e` and `-Pn`, since replies won't come back to the operator) |
| `-e <iface>` | Force a specific network interface |
| `-g` / `--source-port <port>` | Spoof the source port (e.g. 53/20) to slip past firewalls that trust specific ports — raw-packet scans only |
| `--data-length <n>` | Append random padding bytes to most packets |
| `--data` / `--data-string` | Append a specific hex or string payload |
| `--randomize-hosts` | Shuffle target order (up to 16,384 hosts) before scanning |
| `--spoof-mac` | Spoof the source MAC address — random, literal, or by vendor-name lookup |
| `--badsum` | Send deliberately invalid checksums — only misconfigured stacks/firewalls that skip checksum validation will respond |

**Output**

| Switch | Plain-English meaning |
|---|---|
| `-oN <file>` | Normal (human-readable) output |
| `-oX <file>` | XML output — the machine-parseable format most tooling consumes |
| `-oG <file>` | Grepable output — deprecated but still widely scripted against (`.gnmap`) |
| `-oS <file>` | "Script kiddie" output — stylized text, novelty format |
| `-oA <basename>` | Write Normal + XML + Grepable simultaneously (`.nmap`/`.xml`/`.gnmap`) |
| `-v` / `-vv` | Increase verbosity |
| `-d` / `-dd`...`-d9` | Increase debug output |
| `--reason` | Show *why* each port/host was classified that way |
| `--open` | Only show open/open\|filtered/unfiltered results |
| `--packet-trace` | Print every packet sent and received |
| `--append-output` | Append to existing output files instead of overwriting |
| `--resume <file>` | Resume a previously interrupted scan from its saved output |

**Misc**

| Switch | Plain-English meaning |
|---|---|
| `-A` | Aggressive — enables `-O`, `-sV`, `-sC`, and `--traceroute` together (not timing/verbosity) |
| `-6` | Scan over IPv6 |
| `--privileged` / `--unprivileged` | Force-assume (or deny) raw-socket capability rather than autodetecting |
| `--send-eth` / `--send-ip` | Force raw Ethernet frames vs. raw IP packets |

## Quick Use-Case List

- Host discovery / ping sweep across a subnet
- Full TCP port sweep (top 1,000, top-N, or all 65,535)
- UDP service discovery
- Service and version detection
- OS fingerprinting
- Firewall/ACL rule mapping with an ACK scan
- NSE vulnerability scanning
- NSE authentication and brute-force scripts
- Stealth timing and rate-limited evasion
- Fragmentation and MTU evasion
- Decoy scanning
- Idle (zombie) scanning for blind attribution
- IPv6 reconnaissance
- Chaining Nmap's output into other tooling
- Scripted mass recon across a target list from an internal foothold

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Raw-socket privilege | Every scan type except `-sT` needs root (Unix) or an elevated/Npcap-capable context (Windows) — without it, Nmap silently falls back to `-sT` and ARP-based discovery for unprivileged users |
| Packet-capture driver | Npcap (Windows) or `libpcap` (Linux/macOS) for raw packet send/receive |
| Network reachability | Direct L3 reachability to targets; ARP works automatically for on-segment hosts, routed hosts need their designated discovery probes to pass any firewall in between |
| Two known port states, for `-O` | OS detection needs at least one confirmed **open** and one confirmed **closed** port on the target for a reliable match |
| A resolvable/live target | Kerberos, domain membership, and credentials are **not** prerequisites for the base tool — only NSE's `auth`/`brute` scripts need credential material, and only when targeting an authenticated service |
