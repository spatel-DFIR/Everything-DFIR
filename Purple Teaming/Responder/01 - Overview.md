# Responder — Overview

> 🔴 **Red Flag Principle:** Windows has **no built-in trust check for LLMNR, NBT-NS, or mDNS name-resolution replies** — any host on the local broadcast segment can answer a query for a name it doesn't own, and the querying client will simply believe it. The single most distinctive detection principle for Responder is therefore not any one protocol quirk but the pattern itself: **a host answering name-resolution broadcasts for hostnames that don't belong to it**, especially paired with a rogue WPAD/PAC response steering browser traffic through that same host. Any tool implementing that pattern — Responder is simply the reference implementation — produces this fingerprint.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Responder was originally written by **Laurent Gaffié** and first published under **SpiderLabs/Trustwave**, with copyright headers dating to 2013. Gaffié has continued to maintain the project independently since, and the canonical upstream repository today is [`github.com/lgandx/Responder`](https://github.com/lgandx/Responder), licensed under **GPLv3**.

Notable milestones, verified against the repo's `CHANGELOG.md`:

- **v2.0.1 (2014-01-30)** — an early, well-documented release; WPAD was changed to **off by default** at this point, requiring an explicit `-w` to enable (a defensive-minded default that persists conceptually today, since WPAD is still an opt-in flag).
- **v3.0.0.0 (2020-01-09)** — a major rewrite adding **Python 2 and 3 compatibility** and substantial bugfixes; this is the codebase this note is verified against.
- **v3.1.1.0** — `fingerprint.py` (Responder's original built-in OS-fingerprinting module) was **removed from `Responder.py` itself**. Fingerprinting now lives only as the standalone `tools/RunFinger.py` script — **there is no `-f` flag on `Responder.py` in the current version**, despite older write-ups and cheat sheets still listing one.
- **v3.1.3.0 (2022-07-26)** — the `-r` flag (a legacy toggle for responding to NBT-NS Node Status queries) was **removed from the codebase and help text**. Protocol on/off control for LLMNR, NBT-NS, and MDNS now lives **exclusively in `Responder.conf`**, not as command-line switches.
- **v3.0.8.0 (2021-12-03)** — `RunFinger.py` gained a SQLite results database and companion `Report.py`, formalizing it as a standalone recon tool distinct from the poisoning engine.

**Correction worth flagging explicitly:** several widely-circulated Responder cheat sheets (and this note's own initial brief) reference `-f` for fingerprinting and `-r` for an NBT-NS toggle as if they were still current `Responder.py` flags. Verified against the live `Responder.py` argparse/optparse definitions in the current `master` branch, **neither exists today** — see [Command-Line Switches](#command-line-switches--quick-reference) below for the actual current flag set, and `02 - Hands-On Use Cases.md`'s "Fingerprinting Hosts with RunFinger.py" use case for where that capability actually lives now.

## How It Works

Responder operates in two conceptually separate stages that run simultaneously once launched: **(1) name-resolution poisoning** (getting a victim to connect to the attacker at all) and **(2) rogue authentication servers** (capturing whatever credential material the victim offers once it connects).

### Stage 1 — Poisoning the broadcast/multicast name-resolution protocols

Modern Windows hosts fall back to broadcast/multicast name resolution whenever a hostname **fails standard DNS resolution** — a mistyped share name, a decommissioned host, a printer name guessed by autocomplete, or an application probing for infrastructure that doesn't exist (WPAD lookups are a classic example — see Stage 3). Three protocols are tried, in this general order on modern Windows, all of which Responder listens for and can answer:

| Protocol | Port | Scope |
|---|---|---|
| LLMNR (Link-Local Multicast Name Resolution) | UDP 5355 (multicast) | Single broadcast segment |
| NBT-NS (NetBIOS Name Service) | UDP 137 (broadcast) | Single broadcast segment |
| mDNS (Multicast DNS) | UDP 5353 (multicast) | Single broadcast segment (also used by macOS/Linux/IoT, not just Windows) |

Responder's `poisoners/` modules (`LLMNR.py`, `NBTNS.py`, `MDNS.py`, plus `DHCP.py` and `RDNSS.py` for the DHCP/IPv6-router-advertisement variants covered in Stage 3) each bind to their protocol's socket, watch for a query, and — when enabled in `Responder.conf` — answer with Responder's own IP address as if it were the authoritative owner of that name. There is no authentication or trust model in any of these three protocols; the **first, or most convincing, reply wins**, and a malicious host on the same segment is exactly as credible as a legitimate one.

### Stage 2 — The credential-capture handoff

Once the victim believes Responder's host **is** the name it asked for, it initiates whatever protocol its original request implied — most commonly SMB (a mistyped `\\share\path`), but also HTTP, LDAP, MSSQL, or one of Responder's other rogue servers if the victim's own tooling reaches out on those ports. Responder's `servers/` modules (one Python file per protocol — `SMB.py`, `HTTP.py`, `FTP.py`, `LDAP.py`, `MSSQL.py`, `IMAP.py`, `POP3.py`, `SMTP.py`, and others) are all listening simultaneously, and each implements just enough of its protocol's authentication handshake to **request and capture credentials**, then typically returns a failure/redirect rather than completing a real session.

### Stage 3 — WPAD/PAC injection (a distinct, higher-value path)

Independent of LLMNR/NBT-NS/mDNS poisoning, Windows hosts by default also try to auto-discover a proxy server via **WPAD (Web Proxy Auto-Discovery)** — a `wpad` hostname lookup followed by a fetch of `http://wpad/wpad.dat`, a JavaScript `FindProxyForURL()` PAC (Proxy Auto-Config) file. The `wpad` hostname lookup itself typically fails DNS and falls through to the same LLMNR/NBT-NS broadcast poisoning as Stage 1 — so Responder's `-w` flag serves that `wpad.dat` request once a client lands on it, auto-generating a PAC script that points `FindProxyForURL()` at Responder's own IP as the proxy for all traffic. Every subsequent web request the victim makes then routes through Responder, which can demand proxy authentication (`-P`) — a technique the project's own README calls out as "highly effective" precisely because proxy-auth prompts are far less suspicious to end users than an unexpected file-share credential prompt.

### Protocol sequence — the core poisoning → capture flow

```
Victim host                                Responder (attacker, same segment)
────────────                                ───────────────────────────────────
1. App/user mistypes a share, or DNS
   lookup for a real name fails ──────────▶  (nothing yet — broadcast not sent)

2. Broadcast/multicast query:
   LLMNR (UDP 5355) or                                Responder's poisoners/
   NBT-NS (UDP 137) or                                 LLMNR.py / NBTNS.py / MDNS.py
   mDNS (UDP 5353) for "FILESERVER" ──────▶            is listening on the segment

3.                                          ◀────────  Forged reply: "I am FILESERVER,
                                                         my IP is <responder-ip>"
                                                         (no protocol-level trust check
                                                          exists to reject this)

4. Victim connects to <responder-ip>
   over whatever protocol the original
   request implied (usually SMB) ─────────▶            servers/SMB.py (or HTTP.py,
                                                         LDAP.py, MSSQL.py, ...) accepts
                                                         the connection

5. Victim authenticates —
   NTLMSSP negotiate/challenge/
   authenticate handshake ────────────────▶            Server sends an NTLM challenge;
                                                         victim responds with a
                                                         NetNTLMv1/v2 hash tied to that
                                                         challenge

6.                                          ◀────────  Auth typically fails/redirects
                                                         (server has no real share to
                                                          offer) — victim sees an error
                                                         or, for WPAD, gets a working
                                                         proxy config and never notices

                                             Captured NetNTLMv2 hash written to
                                             logs/SMB-NTLMv2-Client-<victim-ip>.txt
                                             (see 03 - Source Evidence.md)
```

The victim's own machine does all the cryptographic work — Responder never needs to intercept traffic in-flight (no ARP spoofing required for the poisoning itself); it only needs to **win the name-resolution race**, which on an unhardened segment it almost always does since it can answer instantly and legitimate name resolution has already failed by definition.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Name resolution poisoning | LLMNR (UDP 5355), NBT-NS (UDP 137), mDNS (UDP 5353) |
| Proxy auto-discovery abuse | WPAD hostname resolution + PAC (`wpad.dat`) file injection over HTTP/HTTPS |
| DHCP-based poisoning | Rogue DHCPv4 (`-d`/`-D`) and DHCPv6 (`--dhcpv6`) responses injecting a WPAD URL or a malicious DNS server network-wide, not just to one victim |
| Router-advertisement poisoning | IPv6 Router Advertisement with RDNSS (`--rdnss`), setting Responder as the victim's IPv6 DNS server |
| Credential capture | Rogue implementations of SMB, HTTP, HTTPS, FTP, LDAP, MSSQL, IMAP, POP3, and SMTP authentication handshakes — the current codebase (`servers/`) also ships RDP, WinRM, Kerberos (AS-REP capture), DNS, DCERPC, SNMP, MQTT, MySQL, and QUIC listeners, beyond the core set this note focuses on |
| Authentication material captured | NetNTLMv1, NetNTLMv2 (via NTLMSSP), cleartext credentials (Basic auth, FTP, SMTP/IMAP/POP3 plaintext AUTH), CRAM-MD5/DIGEST-MD5 challenge-response, Kerberos AS-REP hashes |
| Relay handoff | NTLM material captured by Responder is designed to be **relayed**, not just cracked — either via the bundled `tools/MultiRelay.py` or by disabling Responder's own SMB/HTTP servers and handing the poisoning off to Impacket's `ntlmrelayx.py` (see `02 - Hands-On Use Cases.md`) |

## Command-Line Switches — Quick Reference

Full flag reference verified against the current `Responder.py` argument parser in the official [lgandx/Responder](https://github.com/lgandx/Responder) repository. **Protocol on/off toggles (LLMNR, NBT-NS, mDNS, SMB, HTTP, etc.) are not command-line flags** — they live in `Responder.conf` (see below).

**Required**

| Switch | Plain-English meaning |
|---|---|
| `-I, --interface <iface>` | Network interface to bind and listen on. `ALL` listens on every interface simultaneously |

**Poisoning behavior**

| Switch | Plain-English meaning |
|---|---|
| `-A, --analyze` | **Analyze-only mode** — passively logs LLMNR/NBT-NS/mDNS queries it sees **without sending any poisoned replies**. Used to map what names are being requested before deciding whether/what to poison |
| `-e, --externalip <IP>` | Answer poisoned queries with an IPv4 address other than Responder's own (e.g. pointing victims at a separate relay/redirector host) |
| `-6, --externalip6 <IPv6>` | Same, for IPv6 |
| `-t, --ttl <hex>` | TTL value included in poisoned answers (hex, e.g. `1e` for 30s), or the literal string `random` |
| `-N, --AnswerName <name>` | Overrides the canonical hostname returned in LLMNR answers — used for Kerberos-relay-over-HTTP scenarios where the returned name matters |
| `--rdnss` | Poison via IPv6 Router Advertisements carrying an RDNSS option, making Responder the victim's IPv6 DNS server |
| `--dnssl <domain>` | Inject a DNS Search List suffix via Router Advertisement alongside `--rdnss` |

**DHCP poisoning**

| Switch | Plain-English meaning |
|---|---|
| `-d, --DHCP` | Enable rogue DHCPv4 poisoning — injects a WPAD URL into DHCP responses, network-wide rather than per-victim |
| `-D, --DHCP-DNS` | Same DHCPv4 poisoning path, but injects a rogue DNS server option instead of WPAD |
| `--dhcpv6` | Enable rogue DHCPv6 poisoning. The tool's own help text warns this **may disrupt the network** — it's a noisy, high-impact option |

**WPAD / proxy**

| Switch | Plain-English meaning |
|---|---|
| `-w, --wpad` | Start the rogue WPAD proxy server — serves a PAC file pointing `FindProxyForURL()` at Responder's own IP |
| `-F, --ForceWpadAuth` | Force NTLM/Basic authentication before serving `wpad.dat` — more aggressive, may pop a visible credential prompt |
| `-P, --ProxyAuth` | Force proxy authentication directly (not via `-w`'s PAC-file path) — the README's own words: "highly effective." **Mutually exclusive with `-w`** |
| `-u, --upstream-proxy <host:port>` | Chain the rogue proxy server to a real upstream proxy so victim web traffic still resolves (keeps the attack invisible instead of just breaking browsing) |

**Authentication downgrade**

| Switch | Plain-English meaning |
|---|---|
| `-b, --basic` | Return an HTTP Basic-auth challenge instead of NTLM — yields cleartext passwords rather than hashes, at the cost of a more visible browser credential prompt |
| `--lm` | Force LM hash downgrade (targets legacy Windows XP/2003 clients that still negotiate LM) |
| `--disable-ess` | Disable Extended Session Security — downgrades the exchange toward NTLMv1, which cracks dramatically faster than NTLMv2 |
| `-E, --ErrorCode` | Return `STATUS_LOGON_FAILURE` instead of Responder's normal response — enables capturing credentials via WebDAV auth flows |

**Output / platform**

| Switch | Plain-English meaning |
|---|---|
| `-v, --verbose` | Increase console verbosity — recommended for live operation |
| `-Q, --quiet` | Minimal console output |
| `-i, --ip <IP>` | Manually specify the local IP to use (macOS only, where interface IP auto-detection is less reliable) |

**`Responder.conf` — the actual protocol toggles**

Command-line flags control *behavior*; which protocols actually run is set in `Responder.conf`'s `[Responder Core]` section:

| Setting | Default | Notes |
|---|---|---|
| `LLMNR` | `On` | |
| `NBTNS` | `On` | |
| `MDNS` | `On` | |
| `DHCPv6` | `Off` | |
| `SMB`, `HTTP`, `HTTPS`, `FTP`, `LDAP`, `SQL` (MSSQL), `POP`, `SMTP`, `IMAP` | `On` | The rogue servers this note focuses on |
| `RDP`, `Kerberos`, `DNS`, `DCERPC`, `WINRM`, `SNMP`, `MQTT`, `MYSQL`, `QUIC` | `On` | Additional servers shipped in the current codebase, out of this note's primary scope |
| `Challenge` | `Random` | A fresh NTLM challenge per session by default (older behavior used a fixed challenge, which made multi-victim hash correlation trivial but was also easier to blocklist) |
| `CaptureMultipleHashFromSameHost` | `On` | Whether repeat auth attempts from a host already captured get logged again |
| `SessionLog` / `PoisonersLog` / `AnalyzeLog` | `Responder-Session.log` / `Poisoners-Session.log` / `Analyzer-Session.log` | See `03 - Source Evidence.md` |

## Quick Use-Case List

- Passive analyze mode — mapping what names get queried before poisoning anything (`-A`)
- Default broadcast-segment poisoning across LLMNR + NBT-NS + mDNS simultaneously
- Protocol-scoped poisoning — disabling one or two protocols in `Responder.conf` to reduce noise or evade a specific detection
- WPAD/PAC injection for transparent proxy credential capture (`-w`)
- Forced proxy authentication for a more aggressive, higher-yield WPAD variant (`-P`)
- DHCP-based WPAD injection across an entire broadcast domain, not just per-victim (`-d`/`-D`)
- IPv6 Router Advertisement / DHCPv6 poisoning to hijack DNS resolution network-wide (`--rdnss`, `--dhcpv6`)
- Forcing HTTP Basic auth for cleartext credentials instead of hashes (`-b`)
- Downgrading to NTLMv1/LM for faster offline cracking (`--lm`, `--disable-ess`)
- Targeted poisoning against a single host via `RespondTo`/`RespondToName` in `Responder.conf`, vs. broadcast-segment-wide by default
- Fingerprinting live hosts (OS version, patch level, SMB signing) with the companion `tools/RunFinger.py` script
- Handing captured NTLM auth off to a relay tool — either the bundled `tools/MultiRelay.py` or Impacket's `ntlmrelayx.py` — instead of just cracking hashes offline
- Cracking captured hashes offline with hashcat, matched to the correct mode per captured format
- Chained use as the opening move in a broader intrusion — poisoning to get initial credential material, then pivoting into lateral movement with a separate tool

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Network position | Attacker host must be on the **same broadcast/multicast segment** as intended victims — LLMNR, NBT-NS, and mDNS are all link-local; this does not work across routed subnets without being physically/logically on that segment (e.g. via a compromised host, a rogue AP, or VLAN access) |
| Privileges | Root/administrator on the attacking host — Responder binds low-numbered privileged ports (53, 88, 137, 139, 389, 445, etc.) directly |
| Port availability | The target ports for whichever servers are enabled in `Responder.conf` must be free on the attacking host — a real Samba/SMB service or an existing web server on the same box will collide with Responder's own listeners |
| Name-resolution failure conditions | The technique only fires when the victim's own DNS lookup for a name **fails first** — a fully clean, correctly-configured DNS environment naturally suppresses the LLMNR/NBT-NS fallback path (not the WPAD path, which is attempted independent of any specific DNS failure) |
| For DHCP/RA-based variants (`-d`, `-D`, `--dhcpv6`, `--rdnss`) | No legitimate DHCP/RA server should already be answering faster — these compete directly with the real infrastructure and are explicitly noisier/riskier per the tool's own help text |
| For relay hand-off | Requires Responder's own `SMB`/`HTTP` servers to be turned **off** in `Responder.conf` so the relay tool (MultiRelay or `ntlmrelayx.py`) can bind those ports instead — see `02 - Hands-On Use Cases.md` |
