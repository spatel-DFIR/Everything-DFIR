# Pcredz — Overview

> 🔴 **Red Flag Principle:** Pcredz is a **pure listener, never a poisoner** — in live mode it puts the capture NIC into promiscuous mode and reads whatever traffic already reaches it, but (unlike `Responder/`) it never sends a single forged packet of its own. On a modern switched network that means Pcredz alone sees only unicast traffic to/from its own host; it becomes dangerous only when paired with a traffic-redirection technique — ARP poisoning, `Responder/`'s LLMNR/NBT-NS/mDNS poisoning, or infrastructure-level access to a SPAN/mirror port or tap. The single most distinctive detection principle is therefore architectural: **Pcredz itself leaves almost no target-side footprint** — the footprint belongs to whatever got the traffic onto the wire Pcredz is listening on, and to Pcredz's own operator host.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Pcredz was created by **Laurent Gaffié** — the same author as `Responder/`, already built in this repo — and has been maintained under his own GitHub account since the repo's creation on **2014-04-07**. The canonical upstream repository is [`github.com/lgandx/PCredz`](https://github.com/lgandx/PCredz), licensed under **GPLv3**. As of this build (2026-08-11) the repo shows 2,539 stars, 454 forks, and a last push of **2026-03-02** — actively maintained, not abandoned.

Notable milestones, verified against the live commit history and tags:

- **v1.0.0 (2014-11-27)** — early Python 2/3 script built on `pylibpcap`/`python-libpcap`. An early contributor on record is **byt3bl33d3r** (the original author of CrackMapExec, whose successor `NetExec/` is already built in this repo) — a "Added more support to detect http auths" PR merged 2014-11-26.
- **v1.9.0 / v2.0.0 (2020-06-03)** — Python-3-only cutover; the script began hard-exiting with `"This version only supports python3"` if run under Python 2.
- **v2.0.2 / v2.0.3 (2021-04-05)** — the version most third-party cheat sheets, blog posts, and course material (including most SANS-era references) describe. This era's dependency is **`pylibpcap`/`python-libpcap`** (`pip3 install python-libpcap`, plus `libpcap-dev` and Cython) — this is the "python-libpcap" dependency most commonly cited for Pcredz.
- **v2.1.0 (2025-12-30, current)** — a **major rewrite**, confirmed directly against the commit log: `pylibpcap` was dropped entirely in favor of **`pcapy-ng`** (a maintained fork of `pcapy`), the argument parser and extraction logic were rewritten with pre-compiled regex and in-memory caching for a claimed 10-100x I/O speedup, and host-exclusion (`--exclude-host`) plus per-protocol filtering (`--disable`) were added for the first time.

**Corrections worth flagging explicitly — verified by reading the live `Pcredz` script (v2.1.0) line by line, not just the README:**

- **The README's own "Supported Protocols" list overclaims relative to the actual v2.1.0 source in three separate, independently-verifiable ways:**
  1. **IMAP and POP3 are listed as supported protocols in the README, but there is no IMAP or POP3 parsing code anywhere in the current script** — no `imap`/`pop3` string appears anywhere in the file, and neither protocol appears as a `--disable` option (whose own list — `NTLM, HTTP, FTP, IRC, LDAP, SMTP, Kerberos, SNMP, MSSQL` — is internally consistent with the source, just not with the README's prose above it). Both existed in v2.0.3 (`IMAP-Plaintext.txt`, `POP-Plaintext.txt`) and were silently dropped in the 2.1.0 rewrite. **Citrix ICA credential capture (`CTX1-Plaintext.txt` in v2.0.3) was also dropped** and isn't even claimed in the current README.
  2. **Credit-card scanning (`-c` flag) is present but functionally vestigial.** v2.0.3 had a real Luhn-check credit-card extractor; v2.1.0 keeps the `-c` flag and its startup banner ("CC number scanning activated/deactivated") but **the Luhn function and all card-number regex logic were removed** — the flag now toggles a variable that is checked exactly once, only to print that banner line. The README still lists "Credit Cards: Card number extraction (optional)" as a supported feature.
  3. **The README claims "Extract credentials from both IPv4 and IPv6 traffic," but the packet parser only detects IPv4.** The link-layer/IP auto-detection logic (`process_packet()`) tests each candidate offset for `(byte & 0xF0) == 0x40` — the IPv4 version nibble — and there is no equivalent `0x60` (IPv6) check or IPv6 fixed-header parsing path anywhere in the file. An IPv6-only or dual-stack segment will not have its IPv6 traffic parsed by the current version, contrary to the README.
- The dependency most operators and analysts still associate with Pcredz — **`python-libpcap`** — is now historical (pre-2.1.0). The current version's actual runtime dependency is **`pcapy-ng`** plus `libpcap-dev`; this matters directly for `03 - Source Evidence.md`, since the installed-package fingerprint on an operator's box differs by version.

## How It Works

Pcredz operates in one of two input modes — **live interface capture** or **offline file parsing** — feeding every packet through the same shared extraction pipeline. It never itself generates traffic; it only reads what's already on the wire or already saved to disk.

### Stage 1 — Packet acquisition

| Mode | Mechanism |
|---|---|
| `-i <interface>` | `pcapy.open_live(interface, 65536, True, 100)` — opens the interface with a 65536-byte snapshot length, **promiscuous mode enabled** (`True`), and a 100ms read timeout. No BPF capture filter is ever applied — Pcredz reads every packet the NIC delivers and does its own in-software matching, rather than filtering at the kernel/libpcap level. |
| `-f <file>` | `pcapy.open_offline(file)` — reads a single `.pcap`/`.pcapng` file to completion, one packet at a time, then exits. |
| `-d <dir>` | Recursively walks the directory (`os.walk`), processing every file ending in `.pcap` or `.pcapng` in turn — each file gets its own fresh in-memory state (NTLM challenge cache, dedup set) reset before parsing starts. |

### Stage 2 — Link-layer and IP-header normalization

Every packet passes through `process_packet()`, which auto-detects the link-layer offset **once** (cached for the rest of the session/file) by testing offsets `16` (Linux Cooked Capture / `DLT_LINUX_SLL`), `14` (Ethernet / `DLT_EN10MB`), and `0` (Raw IP / `DLT_RAW`) in that order, looking for the IPv4 version nibble at each candidate offset. Once the IP header is located, source/destination IP, transport protocol (TCP=6, UDP=17), and source/destination ports are extracted directly from the raw bytes — Pcredz does not use a general-purpose packet-dissection library (no Scapy, no dpkt) for this step, it hand-parses the IPv4/TCP/UDP headers itself.

### Stage 3 — Protocol-specific credential extraction

Every TCP/UDP payload is run through a fixed sequence of extractor functions, each independently gated by `is_protocol_disabled()` (see `--disable` below) and its own port/content check:

```
Raw packet
   │
   ├─▶ extract_ntlm()                — scans the WHOLE IP payload (not just one
   │                                    protocol's payload) for the literal magic
   │                                    bytes b'NTLMSSP\x00', REGARDLESS of port.
   │                                    This is why the README can truthfully claim
   │                                    NTLM capture "from HTTP, SMB, LDAP, MSSQL,
   │                                    DCE-RPC, and more" — it isn't parsing any of
   │                                    those protocols, it's magic-byte-scanning
   │                                    for the NTLMSSP blob any of them might carry.
   │
   ├─▶ extract_ntlm_from_http()      — additionally handles NTLM carried inside
   │                                    base64 HTTP WWW-Authenticate/Authorization
   │                                    headers (a second, header-aware path layered
   │                                    on top of the raw magic-byte scan)
   │
   ├─▶ extract_http_basic()          — regex match on "Authorization: Basic <b64>"
   ├─▶ extract_http_password_fields()— regex match on common password/token/API-key
   │                                    form-field names in cleartext HTTP bodies,
   │                                    explicitly SKIPPED on ports 443/8443 (a crude
   │                                    "probably TLS" heuristic — Pcredz never
   │                                    attempts TLS interception/stripping of any kind)
   ├─▶ extract_smtp_auth()           — AUTH PLAIN (single base64 line) and AUTH LOGIN
   │                                    (two-step base64 exchange, correlated across
   │                                    packets via an in-memory per-TCP-flow cache)
   │                                    on ports 25/587/465
   ├─▶ extract_ldap_simple_bind()    — hand-rolled ASN.1/BER walk of the LDAP
   │                                    BindRequest structure on ports 389/636,
   │                                    extracting the bind DN and a Simple Bind
   │                                    cleartext password (or flags an empty one)
   ├─▶ extract_kerberos()            — only invoked on port 88; parses a Kerberos
   │                                    AS-REQ's PA-DATA for etype 23 (RC4-HMAC)
   │                                    pre-authentication, producing a hashcat-ready
   │                                    $krb5pa$23$... hash — this is a PASSIVELY
   │                                    OBSERVED value the client sends on every
   │                                    normal logon, not an actively solicited one
   │                                    (contrast with AS-REP Roasting/Kerberoasting,
   │                                    which are active LDAP-driven techniques)
   └─▶ extract_cleartext()           — IRC (NICK/USER/PASS), FTP (USER/PASS), SNMP
                                        (v1/v2c community strings via a hand-rolled
                                        BER walk on ports 161/162), and MSSQL (TDS
                                        LOGIN7 packet, password de-obfuscated via the
                                        protocol's standard XOR 0xA5 encoding)
```

### Stage 4 — Deduplication and output

Every successful extraction calls `write_data(filename, data, key)`, which deduplicates on `(filename, key)` **unconditionally** — this dedup applies regardless of `-v`. `-v` (verbose) only controls **console** print repetition; the underlying `logs/*.txt` files are always deduplicated, and the session log (`CredentialDump-Session.log`) is **always appended to on every match**, verbose or not, since it's written via a Python `logging` handler that isn't gated by the verbose flag at all. See `03 - Source Evidence.md` for the exact file layout this produces.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Capture mechanism | `libpcap` via `pcapy-ng` (current, v2.1.0+) or `pylibpcap`/`python-libpcap` (historical, pre-2.1.0) — promiscuous-mode live capture or offline `.pcap`/`.pcapng` file parsing, no BPF kernel filter applied |
| Credential-bearing protocols parsed | NTLM (magic-byte scan, protocol-agnostic — carries HTTP, SMB, LDAP, MSSQL, DCE-RPC, and any other NTLMSSP-negotiating protocol), Kerberos (AS-REQ pre-auth etype 23), HTTP Basic auth, HTTP cleartext form/token fields, FTP, IRC, SMTP (AUTH PLAIN/LOGIN), LDAP (Simple Bind), SNMP (v1/v2c community strings), MSSQL (TDS LOGIN7) |
| Hash/credential formats produced | NetNTLMv1 (`user::domain:LM-response:NT-response:challenge`, hashcat `-m 5500`), NetNTLMv2 (`user::domain:challenge:HMAC:blob`, hashcat `-m 5600`), Kerberos AS-REQ pre-auth (`$krb5pa$23$user$REALM$dummy$hash`, hashcat `-m 7500` — a distinct hash type from the `-m 13100`/`-m 18200` Kerberoasting/AS-REP-Roasting hashes Impacket's `GetUserSPNs.py`/`secretsdump.py` produce), assorted cleartext credential pairs |
| What it explicitly does **not** do | Send any packet of its own (no poisoning, no ARP spoofing, no injection); decrypt or intercept TLS/HTTPS traffic in any way; persist captured material to a database (no SQLite equivalent of Responder's `Responder.db` — state is in-memory only, reset per file/session) |

## Command-Line Switches — Quick Reference

Verified directly against the live `argparse` definition in [`lgandx/PCredz`](https://github.com/lgandx/PCredz)'s `Pcredz` script (v2.1.0, current `master`).

**Input mode (mutually exclusive, exactly one required)**

| Switch | Plain-English meaning |
|---|---|
| `-f <file>` | Parse a single, already-captured `.pcap`/`.pcapng` file — the offline/forensic mode, no network access needed |
| `-d <dir>` | Recursively walk a directory and parse every `.pcap`/`.pcapng` file found — bulk/forensic-dataset processing |
| `-i <interface>` | Live capture on a network interface — requires root (or equivalent capture capability) and puts the NIC into promiscuous mode |

**Behavior**

| Switch | Plain-English meaning |
|---|---|
| `-c` | **Deactivates** credit-card-number scanning (default: "activated"). **Caveat:** as of v2.1.0 this flag only toggles a startup banner message — the credit-card extraction logic itself no longer exists in the current source (see History's corrections), so this flag currently has no functional effect on output either way |
| `-t` | Prepend a timestamp to every printed/logged match — useful for building a timeline without cross-referencing file mtimes |
| `-v` | Verbose mode — print every duplicate match to the console as it's seen, not just the first occurrence. Does **not** affect what's written to `logs/*.txt` (those are always deduplicated) |
| `-o <dir>` | Output directory for `logs/` and the session log (default: current directory) |
| `--disable <PROTO>` | Disable a specific protocol's extraction entirely — repeatable. Valid values: `NTLM`, `HTTP`, `FTP`, `IRC`, `LDAP`, `SMTP`, `Kerberos`, `SNMP`, `MSSQL`. A disabled protocol produces **zero** output (console, file, or session log) — the extractor function returns before any logging call is reached |
| `--exclude-host <IP>` | Exclude a specific source/destination IP from all capture and extraction — repeatable. Checked before any protocol parsing occurs |
| `-h` | Standard `argparse`-generated help/usage text |

## Quick Use-Case List

- Offline parsing of a single, already-captured pcap file (`-f`) — the core forensic/analyst use case
- Bulk, recursive parsing of an entire directory of captures (`-d`) — processing a multi-file forensic dataset or a day's worth of rotated captures in one pass
- Live interface capture as an operator, run alongside (or independent of) an active MitM position (`-i`)
- Live capture with verbose output (`-v`) to watch every match, including repeats, in real time
- Timestamped extraction (`-t`) for direct timeline construction without cross-referencing file metadata
- Custom output directory per engagement/target (`-o`) to keep multi-engagement evidence separated
- Protocol-scoped extraction via repeated `--disable` flags — e.g. NTLM-only capture to cut noise from a busy segment
- Host exclusion (`--exclude-host`) to filter the operator's own traffic (or a known-noisy host) out of the results
- Chained use directly alongside `Responder/` — Pcredz parsing the same interface (or Responder's own resulting traffic) as a second, independent extraction pass over material Responder's poisoning generated
- Feeding a `.pcap` **exported from Wireshark/tcpdump during a live triage** into Pcredz for fast bulk credential extraction, rather than manually filtering in a GUI
- Passive, fully offline forensic use against a **seized or IR-collected pcap**, with zero live network access and no attacker intent at all — pure blue-team/DFIR use
- Fleet/segment-wide passive collection from a SPAN/mirror port or network tap, positioned to see many hosts' traffic without any per-host poisoning
- Feeding captured NetNTLMv1/v2 or Kerberos AS-REQ pre-auth hashes into `Hashcat/` for offline password recovery
- Docker-based deployment (`docker run --rm -v $(pwd):/data pcredz -f /data/capture.pcap`) to avoid `pcapy-ng`/`libpcap-dev` build friction on the operator's own host
- Running against a **legacy pcap toolchain** where a v2.0.x install (still on `python-libpcap`) is deliberately kept for compatibility with an older environment

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Traffic visibility | Pcredz only sees what already reaches its capture interface. On a switched network this means: same host as a compromised box with a MitM position already established, a SPAN/mirror port, a network tap, or paired with an active poisoning/redirection tool like `Responder/` or ARP spoofing. For `-f`/`-d` mode, only a copy of the capture file is needed — no live network position at all |
| Privileges (live mode only) | Root/administrator, or an equivalent capture capability (e.g. Linux `CAP_NET_RAW`/`CAP_NET_ADMIN` via `setcap` on the Python interpreter or a compiled wrapper) — `pcapy-ng`'s promiscuous-mode `open_live()` call requires it |
| Dependencies (current, v2.1.0+) | Python 3, `pcapy-ng` (`pip3 install pcapy-ng`), `libpcap-dev`/`libpcap-devel`, a C compiler (`gcc`/`g++`) to build `pcapy-ng`'s extension module — or the official Docker image, which bundles all of this |
| Dependencies (legacy, pre-2.1.0) | `pylibpcap`/`python-libpcap`, `Cython`, `libpcap-dev` — relevant only if deliberately running an older checkout |
| No target-side prerequisite | Unlike an active tool, Pcredz requires nothing on the victim/target side — it is entirely a function of what traffic reaches the capture point |
