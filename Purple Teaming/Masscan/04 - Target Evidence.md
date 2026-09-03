# Masscan — Target Evidence

Evidence left on and around the **scanned network**. Masscan never establishes a real session with a target unless `--banners` is used, so there is normally **no host-based log entry at all** on the target itself for a bare port scan — everything here is either network-layer (the only place a bare SYN scan leaves a trace) or, for `--banners` runs, the same kind of application-layer footprint a legitimate client connection leaves.

## Contents
- [The Packet-Level Fingerprint](#the-packet-level-fingerprint)
- [Network-Layer Evidence](#network-layer-evidence)
- [IDS/IPS Signatures](#idsips-signatures)
- [Firewall / Perimeter Logs](#firewall--perimeter-logs)
- [Application-Layer Evidence (--banners runs)](#application-layer-evidence---banners-runs)
- [Windows Event Logs (Rare, --banners Only)](#windows-event-logs-rare---banners-only)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing from Nmap and Normal Traffic](#distinguishing-from-nmap-and-normal-traffic)

---

## The Packet-Level Fingerprint

This is the **only** evidence a bare SYN scan (no `--banners`) leaves — there's no session, no log entry, nothing on the target host itself. It comes entirely from masscan's fixed packet template (`src/templ-pkt.c` in the official source), which is the same for every packet in every scan unless the operator recompiles the tool:

| Field | Value in masscan's default template | Why it matters |
|---|---|---|
| IP TTL | **255** (overridable with `--ttl`) | Most real OS stacks default to 64 (Linux/macOS) or 128 (Windows) — a SYN arriving at TTL 255 (or `255 - hop count`, if captured a few hops downstream) is already an outlier |
| IP "Don't Fragment" flag | **Clear (0)** | The overwhelming majority of modern OS TCP stacks set DF=1 on outgoing SYNs; masscan's default template does not — **not exposed via any CLI flag** |
| TCP window size | **1025** | Real stacks typically advertise a much larger, OS-characteristic window (e.g. 64240 on modern Windows, 65535/scaled on Linux) — **not exposed via any CLI flag** |
| TCP options | **Exactly one: MSS 1460.** No SACK-permitted, no timestamps, no window-scale option | A genuine OS SYN almost always carries 3-4 options in a specific, OS-fingerprintable order; masscan's minimal single-option SYN is itself a signature (comparable in spirit to p0f/JA4T-style OS fingerprinting, but trivially recognizable here since it doesn't match *any* real OS's default profile) — **not exposed via any CLI flag** |

Only TTL is operator-adjustable from the command line — window size, the DF bit, and the TCP options list require patching and recompiling the source. This makes the **window/options/DF combination the single most durable target-side signature** covered in this note; see the ranked priority table in `05 - Detection and Hunting.md`.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `conn.log` | A burst of `S0` (SYN sent, no reply — closed/filtered) or `SF`/`S1`-style (SYN-ACK observed, RST or nothing further — masscan never completes a normal handshake without `--banners`) connection states from one source IP against a very large number of distinct destination IPs and/or ports, all in a tight time window, each with tiny/zero payload byte counts |
| NetFlow / IPFIX | The clearest volumetric signal for a fast scan: one source IP, many destination IPs (horizontal) or many destination ports on few IPs (vertical), flow durations near-zero, near-uniform small packet sizes — visible even with zero endpoint logging anywhere on the network |
| Packet capture (full PCAP or a Zeek/Suricata extracted subset) | Enables direct verification of [the packet-level fingerprint](#the-packet-level-fingerprint) above — pull TTL, DF, window, and the TCP options list from any captured SYN and compare |
| ICMP responses (if `--ping` was used) | ICMP echo requests to the target range, interspersed with the TCP SYN probes — visible in `icmp.log`/flow records as an additional, correlated signal from the same source |

## IDS/IPS Signatures

Mainstream network IDS/IPS products (Suricata, Snort, commercial NGFW signature sets) commonly ship rules for **"possible portscan"**/"masscan-style scan" behavior based on connection-rate heuristics (many distinct destination ports/hosts from one source in a short window) rather than a masscan-specific static signature — because the *rate and breadth* of the behavior, not any single packet, is what's anomalous. Some rule sets do additionally fingerprint the packet-template characteristics above (fixed window/TTL/options combination) as a higher-confidence secondary signal layered on top of the rate-based alert. A target network with **no** scan-rate alerting at all (no IDS, or a threshold tuned far above masscan's realistic rates) will show nothing beyond the raw flow/NetFlow data.

## Firewall / Perimeter Logs

| Artifact | Notes |
|---|---|
| Perimeter firewall deny/drop logs | A single source IP generating a very high volume of denied/unmatched connection attempts across a wide port range in a short window is the classic firewall-log signature of an unauthorized external scan |
| Connection-rate/threshold alerts | Many commercial firewalls have a built-in "port scan detected" heuristic (distinct from a full IDS) that triggers purely on connection-attempt rate from one source — often the very first alert to fire, well before any IDS rule evaluates packet content |
| Threat-intel/reputation feeds | Because masscan is the tool of choice for several well-known Internet-wide research/scanning operations (Shodan, Censys, academic researchers) as well as malicious actors, some organizations subscribe to feeds that pre-tag known benign-research scanner source ranges — a source IP that does **not** match one of those known-benign ranges but exhibits masscan's packet fingerprint is a stronger indicator of hostile intent than the scan behavior alone |

## Application-Layer Evidence (--banners runs)

When `--banners` is used, masscan completes a **real** handshake and sends a real application-layer probe through its own embedded TCP stack — this leaves the same kind of footprint a legitimate client connection would:

| Service | What gets logged on the target |
|---|---|
| Web servers (HTTP/HTTPS) | A standard access-log entry — masscan's default request is a minimal, unmodified `GET / HTTP/1.0`-style request with no custom headers unless the operator used the `--http-*` flags from `01 - Overview.md`. The default `User-Agent` (or its absence) plus the total absence of a `Referer`/`Accept-Language`/other headers a real browser sends is itself distinctive in web logs |
| SSH | The banner exchange alone (before authentication) is typically logged at low verbosity or not logged at all by default `sshd` config — but any IDS watching the SSH port will see a completed TCP handshake with only a version-string exchange and no auth attempt, a shape distinguishable from both a real client and from a brute-force tool |
| TLS/SSL services | A completed TLS handshake up through certificate delivery, then an immediate teardown with no application data exchanged — visible in `ssl.log`/TLS-inspection logs as a handshake-only session |
| FTP/SMTP/POP3/IMAP4 | The service's own banner is read and the connection is torn down immediately — most of these daemons log the connection at the OS/service level (e.g. `vsftpd` connect log) even though no command beyond the banner grab was issued |

## Windows Event Logs (Rare, --banners Only)

Because masscan's engine never uses the target's authentication or session-management stack, it essentially never generates Windows Security event log entries the way an actual logon attempt would — **there is no 4624/4625 pattern to hunt for masscan itself.** The one narrow exception: if `--banners` completes a handshake against a Windows service that itself logs inbound TCP connections independent of authentication (e.g. an IIS access log, or a service with verbose connection-level logging enabled), that service's own log is the relevant artifact — not a generic Security-log signal. Don't expect Windows event-log evidence from a bare SYN sweep; this module's usual Windows Security/Sysmon-ID-driven approach genuinely doesn't apply here (see `Windows/11 - Event Log Analysis.md` for what *does* generate those events).

## Building a Timeline

The tightest anchor for a masscan sweep is purely **network-layer**: **first SYN observed (NetFlow/Zeek) → burst of SYN-ACK/RST replies across the target range within the scan's `--rate`-determined window → (if `--banners`) a wave of completed handshakes with application-layer reads immediately followed by RST teardown → last SYN observed.** The whole event typically spans seconds to low minutes for a subnet-sized sweep, or hours for an Internet-scale sweep at a moderate rate — the duration itself is a useful corroborating signal once `--rate` is estimated from the observed packets-per-second.

## Distinguishing from Nmap and Normal Traffic

> 🔴 **Key differentiator.** Nmap's default SYN scan (`-sS`) also crafts raw packets rather than using OS sockets, but nmap adapts its packet templates and timing per target/timing-template and (with `-O`/version detection) actively varies its probes to fingerprint the remote stack. Masscan does none of that — it has **no OS-fingerprinting logic at all**, so its packet template is identical across every target in every scan (barring a `--ttl` override), and its timing is governed purely by `--rate`, not nmap's adaptive per-host RTT-based timing templates (`-T0`-`-T5`). In practice: **uniform packet shape + uniform (rate-driven, not RTT-adaptive) inter-packet timing + zero host-discovery pings by default (`-Pn` permanently on) across a wide target set** is the combined signature that points at masscan (or a close cousin like ZMap) rather than nmap or a manually-driven client.

See `Windows/12 - Lateral Movement.md` and the network-evidence notes under `Windows/` for the broader internal-recon detection picture this note deliberately doesn't re-derive.
