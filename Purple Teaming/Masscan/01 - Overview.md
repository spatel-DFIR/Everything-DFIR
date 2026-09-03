# Masscan — Overview

> 🔴 **Red Flag Principle:** Masscan sends every SYN packet from a **fixed, hardcoded packet template** — TTL **255**, the **Don't Fragment bit clear**, a **1025-byte TCP window**, and exactly **one** TCP option (MSS 1460 — no SACK-permitted, no timestamps, no window scaling). That template is baked into the binary and never adapts per target or per engagement; only TTL is exposed via a CLI flag. Combined with a **fully-randomized destination order** (mandatory, can't be disabled) and rates that can reach millions of packets/second from a **custom user-mode network stack that bypasses the OS TCP/IP stack entirely**, this produces a structurally identical, engagement-wide packet fingerprint that survives almost every other option the tool exposes — the closest thing masscan has to a durable IOC.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Masscan was written by **Robert Graham** (Errata Security; @ErrataRob), first published in **2013** (copyright header in the project's `LICENSE`). It went public alongside a DEF CON 22 (2014) talk co-presented with Paul McMillan and Dan Tentler, *"Mass Scanning the Internet: Tips, Tricks, Results."* The project is licensed under the **GNU Affero General Public License v3**, and the canonical source remains [`github.com/robertdavidgraham/masscan`](https://github.com/robertdavidgraham/masscan) — still actively maintained as of this writing (commits as recent as April 2026, ~26,000 GitHub stars, not archived).

Graham built masscan to solve what the README calls the **"C10M problem"** — scaling an order of magnitude past the classic "C10K" (10,000 concurrent connections) barrier that async I/O (`select`/`epoll`) already solved. Rather than tune a normal socket-based scanner, masscan's design goal from day one was to **bypass the kernel entirely**: a custom network driver path (raw `libpcap`, or PF_RING DNA for extreme rates), a self-contained user-mode TCP/IP stack, and lock-free "ring" buffers instead of mutexes for transmit/receive-thread synchronization. The README states the design target plainly: **"scan the entire Internet in under 5 minutes, transmitting 10 million packets per second, from a single machine."** It sits in the same lineage as `scanrand`, `unicornscan`, and `ZMap` — asynchronous, stateless Internet-scale scanners — but the README notes masscan is "more flexible, allowing arbitrary port and address ranges." Its command-line and output formats are deliberately modeled on `nmap` for familiarity, even though the underlying engine is completely different.

## How It Works

Masscan is **stateless and asynchronous** by design — it never tracks per-probe state the way a normal TCP stack (or nmap's default scan engine) does. Instead, it encodes everything it needs to validate a reply directly into the packet itself, using a construction borrowed from classic SYN-cookie defenses:

```
Operator                                          Wire / Target
────────                                          ──────────────
1. Flatten (IP × port) targets into one linear
   index space, then permute that index space
   with blackrock — a Feistel-network,
   format-preserving-encryption construction
   (14 rounds by default) — producing a fully
   randomized, collision-free, 1-to-1 scan order.
   (--seed controls the permutation key; same
   seed + same targets = same scan order.)

2. TRANSMIT THREAD, throttled to --rate pps:
     for each index i (in permuted order):
       (ip, port) = unshuffle(i)
       cookie = SipHash(ip_them, port_them,
                         ip_me, port_me, entropy)
       seqnum = cookie              <- embedded directly
       craft raw SYN from the fixed    in the SYN's own
       template (TTL 255, DF=0,        sequence number —
       win=1025, MSS=1460 only)        no state stored
       send via libpcap / PF_RING ───▶ SYN ──────────────▶ target:port
       (never touches the OS               (bypasses local OS TCP/IP
        TCP/IP stack)                       stack — the kernel doesn't
                                             know this connection exists)

3. RECEIVE THREAD (independent of the transmit
   thread — synchronized via lock-free "rings",
   not mutexes, to avoid killing throughput):
                                        ◀─────────── SYN-ACK / RST /
                                                      ICMP unreachable
     recompute the same SipHash cookie for
     (ip, port) and compare it to
     (ackno - 1) on the reply
       match  -> genuine response to THIS scan;
                 record port state (open/closed)
       no match -> noise, backscatter, or a
                 spoofed/duplicate packet; discarded

4. (optional, --banners) masscan's own embedded
   user-mode TCP stack completes a REAL 3-way
   handshake and reads application data (HTTP,
   FTP, SSH, SMB, etc.) — still entirely outside
   the OS's TCP state machine — then tears the
   connection down with a RST.
```

Two consequences of this design are the most forensically important facts about the tool:

1. **No target ever gets special treatment.** Because there's no per-target state and no OS-fingerprinting/adaptive-template logic (unlike nmap's timing/OS-detection paths), every SYN masscan sends carries the *same* TTL/flags/window/options fingerprint described in the red-flag callout above — a target-side signature that persists across the entire scan, and across engagements unless the operator recompiles the tool.
2. **The local OS's own TCP/IP stack is a liability, not an ally.** Because masscan's packets never pass through the kernel's TCP state machine, the kernel has no idea a "connection" exists — so when a real reply (a SYN-ACK) arrives, the **local OS itself will often respond with a spurious RST**, since as far as the kernel is concerned that's an unsolicited packet. This is a non-issue for a bare port scan (masscan reads the reply off the wire before the kernel's RST lands), but it **breaks `--banners`**, which needs a real, surviving TCP session. The documented fix is to either scan from a second, unused local IP (`--adapter-ip`/`--source-ip`) or dedicate a source port the host firewall silently drops (`--adapter-port`/`--source-port` + an `iptables`/`pf` DROP rule) — see the [Command-Line Switches table](#command-line-switches--quick-reference) and `02 - Hands-On Use Cases.md`.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport | Raw SYN packets over Ethernet/IP, crafted and sent directly via `libpcap` (or PF_RING DNA for extreme rates) — **not** OS sockets |
| Scan type | TCP SYN scan only (`-sS` is permanently enabled; UDP probing is supported separately via `U:` port syntax, sending empty or payload-templated UDP datagrams rather than a handshake) |
| State tracking | None — stateless, SipHash-based SYN-cookie validation of replies (see above) instead of a connection table |
| Host discovery | Disabled by default (`-Pn` permanently enabled) — every specified target is probed regardless of whether it answers ICMP; `--ping` optionally adds an ICMP echo request alongside the port probe |
| Name resolution | None (`-n` permanently enabled) — targets must be IP addresses/ranges/CIDR, never hostnames |
| Randomization | Mandatory (`--randomize-hosts`, cannot be disabled) — Feistel-network index permutation (`blackrock`), reseedable via `--seed` |
| Banner grabbing | Masscan's own embedded user-mode TCP stack completes real handshakes and speaks enough of HTTP, FTP, IMAP4, memcached, POP3, SMTP, SSH, SSL/TLS, SMB, Telnet, RDP, and VNC to extract a banner |

## Command-Line Switches — Quick Reference

Verified against the official [man page](https://github.com/robertdavidgraham/masscan/blob/master/doc/masscan.8.markdown) and `src/main-conf.c`/`src/main.c` in the current [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) source, written for a reader who has never run the tool.

**Targets & Ports**

| Switch | Plain-English meaning |
|---|---|
| `<IP\|RANGE>` / `--range` | Target(s) — single IP, dash range (`10.0.0.1-10.0.0.100`), or CIDR (`10.0.0.0/8`). **No DNS names, no nmap-style `10.0.0-255.0-255` fuzzy ranges** |
| `-p PORT[,PORT..]`, `--ports` | Port(s) to scan — single (`-p80`), range (`-p20-25`), list (`-p80,20-25`), or UDP (`-pU:53`, `--ports U:161,U:1024-1100`). **No default port list — this is effectively required** |
| `--exclude <IP\|RANGE>` | Blacklist an address/range — overrides target specs, guarantees it's never scanned |
| `--excludefile FILE` | Same as `--exclude` but reads ranges from a file — strongly recommended for any Internet-wide scan |
| `-iL FILE`, `--includefile FILE` | Read target ranges from a file instead of the command line — supports millions of entries |

**Rate & Scan Control**

| Switch | Plain-English meaning |
|---|---|
| `--rate RATE` | Transmit rate in packets/second. **Default: 100.** Accepts fractions (`0.1` = one packet every 10 seconds) up to millions |
| `--ping` | Also sends an ICMP echo request alongside the port probe (host discovery is otherwise fully disabled) |
| `--retries NUM` | Retransmit each probe this many additional times, spaced ~1 second apart. Since the scanner is stateless, retries are sent unconditionally, not just on packet loss |
| `--ttl NUM` | TTL of outgoing packets. **Default: 255** |
| `--wait SECONDS` | How long to keep listening for replies after the last packet is sent, before exiting. **Default: 10** (or `forever`) |
| `--seed INT` | Seeds the random-order permutation. Default is the current time — set explicitly for a **repeatable** scan order across runs |
| `--shards X/Y` | Splits one logical scan across `Y` cooperating instances; this instance sends shard `X` (e.g. `--shards 1/3`, `--shards 2/3`, `--shards 3/3`) |
| `--offline` | Don't actually transmit — used with `--packet-trace` to preview what *would* be sent, or with a high `--rate` to benchmark throughput |
| `-sL` | Don't scan — just generate the randomized target list (useful for feeding into another tool) |

**Network / Adapter (the "spurious RST" workaround)**

| Switch | Plain-English meaning |
|---|---|
| `-e IFNAME`, `--adapter` | Raw network interface to send/receive on. Default: first interface with a gateway |
| `--adapter-ip`, `--source-ip` | Source IP to send from. Needed for `--banners` to avoid the local OS sending spurious RSTs (see How It Works) — the spoofed IP must be otherwise unused on the local subnet |
| `--adapter-port PORT` | Source port to send from. Default: random 40000–60000. Pair with a host firewall rule dropping inbound traffic to that port, so the OS never sees (and doesn't RST) the replies |
| `--adapter-mac MAC` | Source MAC address. Default: the interface's own MAC |
| `--adapter-vlan VLANID` | Tag outgoing packets with an 802.1q VLAN ID |
| `--router-mac MAC` | Destination MAC for outgoing packets. Default: ARP-resolved gateway MAC |
| `--iflist` | List available interfaces and exit |

**Output**

| Switch | Plain-English meaning |
|---|---|
| `--output-format FMT` | `xml` (default) \| `binary` \| `grepable` \| `list` \| `json` — requires `--output-filename` |
| `--output-filename FILE` | Output file path |
| `-oX FILE` | Shortcut for XML output |
| `-oB FILE` | Shortcut for masscan's compact **binary** format — smallest on disk, must be converted with `--readscan` before it's human-readable |
| `-oG FILE` | Shortcut for grepable (nmap `-oG`-compatible) output |
| `-oJ FILE` | Shortcut for JSON output |
| `-oL FILE` | Shortcut for simple list output: `<state> <proto> <port> <IP> <POSIX timestamp>` |
| `--readscan FILE` | Read a `-oB` binary file back and re-emit it as XML/JSON/etc. |
| `--append-output` | Append to the output file instead of overwriting — used automatically by `--resume` |
| `--show [open\|closed]` / `--noshow` | Which port states to display. Default: open only |
| `--pcap FILE` | Save received (not sent) packets to a libpcap file |
| `--packet-trace` | Print every sent/received packet to the console — only usable at low rates |
| `--interactive` | Print results to the console in real time (implied unless `--output-format`/`--output-filename` is set) |

**Banner Grabbing & Protocol Customization**

| Switch | Plain-English meaning |
|---|---|
| `--banners` | Complete a real handshake and grab an application banner (HTTP, FTP, IMAP4, memcached, POP3, SMTP, SSH, SSL/TLS, SMB, Telnet, RDP, VNC) — only on each protocol's standard port unless overridden with `--hello-*` |
| `--connection-timeout SECS` | Max seconds to hold a banner-grab TCP connection open. Default: 30 |
| `--hello-file[PORT] FILE` / `--hello-string[PORT] BASE64` | Send custom bytes (from a file, or a base64 string) immediately after connecting on a given port, instead of the built-in protocol probe |
| `--capture TYPE` / `--nocapture TYPE` | Control what's captured from a banner (`html`, `cert`) — e.g. `--nocapture cert` to skip full certificate capture on TLS |
| `--http-method` / `--http-url` / `--http-version` / `--http-host` / `--http-user-agent` | Override the corresponding field of the HTTP request line/headers masscan sends |
| `--http-field NAME:VALUE` | Add/replace an arbitrary HTTP header field |
| `--http-field-remove NAME` | Remove a header field |
| `--http-cookie VALUE` | Add a `Cookie:` header even if one already exists |
| `--http-payload STR` | Add an HTTP body (auto-sets `Content-Length`) |
| `--pcap-payloads FILE` / `--nmap-payloads FILE` | Load custom UDP payloads per destination port from a pcap file or an nmap-format `nmap-payloads` file, instead of sending empty UDP datagrams |

**Resume, Config File, Misc**

| Switch | Plain-English meaning |
|---|---|
| `-c FILE`, `--conf FILE` | Load settings from a config file (`name = value` lines). Default: `/etc/masscan/masscan.conf` is always loaded first |
| `--echo` | Print the fully-resolved current configuration (useful for saving to a config file) and exit without scanning |
| `--resume FILE` | Resume a scan from a saved state file (see Ctrl-C behavior below) — equivalent to `-c` plus auto-setting `--append-output` |
| `--resume-index INDEX` / `--resume-count NUM` | Manually specify the scan's starting index and how many probes to send before exiting — a lower-level alternative to `--shards` for splitting work |
| `--rotate TIME` / `--rotate-offset` / `--rotate-size` / `--rotate-dir` | Automatically rotate the output file by elapsed time or size, into a target directory |
| `--pfring` | Force the PF_RING DNA driver (exits if unavailable) — needed for the highest transmit rates |
| `--regress` | Run masscan's internal self-test suite and exit |
| `--nmap` | Print nmap-compatible flag aliases masscan also accepts |

**Ctrl-C / Pause & Resume:** pressing **Ctrl-C** stops transmission and writes the scan's current state to `paused.conf` in the working directory (then waits up to `--wait` seconds for outstanding replies before exiting). Resume later with `masscan --resume paused.conf`.

## Quick Use-Case List

- Internet-wide or large-CIDR port sweeps for a single port (recon/attack-surface mapping)
- Full-port (`-p0-65535`) sweeps of a specific target range
- Banner grabbing at scale (`--banners`) across a discovered port list
- Rate tuning for stealth (near the 100 pps default, or lower) vs. maximum speed (hundreds of thousands to millions of pps)
- Targeted service discovery with a specific, curated port list (e.g. RDP/SMB/WinRM for internal lateral-movement recon)
- UDP service discovery (`U:` port syntax) against common UDP services (DNS, SNMP, NTP)
- Chaining output into another tool via XML/JSON/grepable formats (e.g. feeding results into Nmap `-sV`/`-A` for deep service fingerprinting, or into a banner-parsing pipeline)
- Exclude-list-driven scanning to stay off sensitive/prohibited ranges during a broad sweep
- Pausing (Ctrl-C) and resuming a long-running scan across sessions
- Sharding one logical scan across multiple hosts/instances for speed
- IPv6 target scanning (native support, no special flag — just an IPv6 range/CIDR as the target)
- Spoofed source-IP/source-port banner grabbing to avoid local-OS RST interference
- Fixed-seed scans for a reproducible, auditable scan order across repeated engagements
- Compiling scan results to a compact binary file (`-oB`) for later offline conversion (`--readscan`)
- Custom HTTP request crafting (method/headers/cookie/payload) during banner grabs, e.g. to probe behind auth-gated landing pages or fingerprint WAFs

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Raw packet access | Masscan crafts and sends its own raw Ethernet/IP frames — requires root/Administrator privilege (or `CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux) and a supported `libpcap`/Npcap/PF_RING driver bound to the chosen interface |
| Network reachability | Direct L2/L3 reachability to the target range from the interface masscan binds to (`-e`/`--adapter`); no proxying/pivoting support built in |
| Explicit port list | `-p` (or `--ports`/`-oL`-style config) is functionally required — there's no default port set the way nmap has one |
| A second usable local IP or a firewall rule | Only needed for `--banners` — see the spurious-RST workaround above |
| Authorization | Given the scan rates involved, written authorization/scope is essential — the tool's own man page has a dedicated "Abuse Complaints" section warning that Internet- or org-wide scanning generates abuse reports and can get an operator's account/organization firewalled or fired |
