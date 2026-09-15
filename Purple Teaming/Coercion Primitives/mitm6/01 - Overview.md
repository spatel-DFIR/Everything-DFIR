# mitm6 — Overview

> 🔴 **Red Flag Principle:** A single host answering **unsolicited ICMPv6 Router Advertisements** (RA) with a malicious IPv6 prefix + DHCP server advertisement effectively **reroutes the entire IPv6 subnet's autoconfiguration traffic** to attacker-controlled DNS — no credentials required, no trust needed, pure network-layer takeover. A host seeing `DHCPv6 Solicit` traffic answered by an unexpected DHCP server is the most distinctive signal.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

mitm6 was written by **Dirk-jan Mollema** (@dirkjanm) and published under the `dirkjanm/mitm6` GitHub repository (no dedicated GitHub org, maintained by Mollema independently). Licensed under **GPLv2**.

Verified against the live repository state:
- **Initial release (2016)** — original IPv6 DHCP spoofing + DNS poison framework.
- **v0.2.0 (2017-02)** — significant refinement of IPv6 RA/DHCP mechanics and WinRM relay integration.
- **v0.3.0 (2019-07)** — integration with Impacket's `ntlmrelayx.py` as a seamless NTLM relay partner (the `-relay` flag / relay-handler architecture).
- **Maintained through 2026** — actively updated for protocol/OS compatibility changes.

**Design philosophy:** mitm6 is explicitly a *relay-transport tool*, not a credential-capture tool on its own — it forces a target to authenticate to an attacker-controlled WPAD/DHCP/DNS authority (via IPv6 autoconfiguration), then passes the NTLM authentication traffic to `ntlmrelayx.py` for actual relay exploitation. The two tools are functionally inseparable in real operations.

## How It Works

mitm6 exploits a fundamental difference between **IPv4 and IPv6 address autoconfiguration** that Windows prioritizes IPv6 whenever it's available but provides no built-in defense against unauthorized DHCP servers or DNS servers on the IPv6 segment.

### Stage 1 — IPv6 prefix advertisement (getting targets to configure IPv6)

On modern Windows (Vista+, all modern versions), a host boots and **immediately probes for IPv6 address assignment via Router Advertisements (RAs)** — a multicast request asking "is there an IPv6 router on this segment?" mitm6's first module binds to the all-nodes multicast address (`ff02::1`) and listens for these solicitations (or sends unsolicited RAs continuously). When a solicited or unsolicited RA is received, it responds with:

1. **A valid ICMPv6 RA packet** claiming to be the network's legitimate IPv6 router.
2. **An embedded Prefix Information Option** advertising a malicious IPv6 prefix (typically `fd00::/64` — a Unique Local Address — or operator-controlled global prefix).
3. **DHCPv6 flag set** — instructing clients to use DHCPv6 for further address/DNS configuration rather than SLAAC (Stateless Address Autoconfiguration).

**Why this works:** No cryptographic validation of RA sources exists — any host on the local segment can send an RA, and Windows will accept it. The multicast scope is local-link only, but that is exactly the attacker's position (same segment). Modern Windows has no setting to disable IPv6 entirely (only to disable specific components), and even if DHCP is disabled on IPv4, IPv6 DHCP is often still active.

### Stage 2 — DHCPv6 spoofing (assigning attacker-controlled DNS)

Once the target has configured an IPv6 address from the attacker's advertised prefix (typically via SLAAC or DHCPv6), it needs to resolve names. The DHCP server mitm6 runs on port 546/UDP responds to `DHCPv6 Solicit` packets with a `DHCPv6 Advertise` offering:

- A **DHCPv6-assigned IPv6 address** in the attacker's advertised range (e.g., `fd00::1001`).
- **DNS server option (OPTION_DNS_SERVERS, 23)** pointing to mitm6's own IP as the resolver.

The target client accepts this offer and begins resolving all names via mitm6's embedded DNS server.

### Stage 3 — DNS/WPAD spoofing (intercepting resolution and serving proxy config)

Once mitm6 controls DNS, it:

1. **Intercepts every DNS query** and responds with mitm6's own IP for any hostname the target asks for.
2. **Serves a malicious WPAD PAC file** (via HTTP on port 80) at `http://wpad/wpad.dat` when the target's browser/system tries to auto-discover a proxy.
3. **The PAC script** instructs all HTTP traffic to route through a proxy server at mitm6's own IP (port 8080 by default).

### Stage 4 — NTLM capture / relay handoff

When the target tries to use the proxy, it must authenticate. The embedded proxy server requests **NTLM authentication**, and the target responds with its NetNTLMv2 hash. mitm6's `-relay` mode immediately passes this authentication traffic **to ntlmrelayx.py** over a local socket, allowing relay attacks (SMB relay, LDAP relay, etc.) to proceed as if `ntlmrelayx.py` itself had captured the hash.

The whole chain: **ICMPv6 RA poison → DHCPv6 DNS spoofing → WPAD PAC redirect → proxy-auth capture → ntlmrelayx relay**.

### Protocol sequence

```
Victim host (needs IPv6 config)                    mitm6 (attacker)
──────────────────────────────                    ────────────────
1. Boot/IPv6 probe:
   ICMPv6 Router Solicitation ────────────────▶   (listening on ff02::1)
   (or periodic multicast)
                                                   
2.                                      ◀────────  ICMPv6 Router Advertisement:
                                                    - Prefix: fd00::/64
                                                    - DHCPv6 flag set
                                                    - No credential check

3. Victim configures IPv6 address
   (e.g., fd00::1001) from advertised prefix
   
4. DHCPv6 Solicit:                 ────────────▶   DHCPv6 server (port 546)
   "I need a DHCPv6 address"
                                                   
5.                                      ◀────────  DHCPv6 Advertise:
                                                    - IPv6: fd00::2
                                                    - DNS: <mitm6-ip>
                                                    - (Lease accepted)

6. Victim resolves all names via
   mitm6's DNS (queries to port 53)
   
7. Browser tries "wpad" name ───────────────────▶  DNS responds with
   for proxy discovery                             mitm6's IP
   
8. Browser fetches
   http://wpad/wpad.dat ──────────────────────▶   HTTP server (port 80)
                                                   returns PAC file
   
9. PAC sets proxy to                       ◀────────  PAC content:
   <mitm6-ip>:8080                                  FindProxyForURL()
                                                    → PROXY <attacker>:8080
   
10. Browser/app connects to proxy
    and sends NTLM auth ───────────────────────▶   Proxy listener
                                                   captures hash & sends
                                                   to ntlmrelayx.py
```

## Techniques / Protocols Used

| Protocol/Mechanism | Detail | Impact |
|---|---|---|
| **ICMPv6 Router Advertisement (RA)** | Unsolicited network-prefix advertisement, no auth | Forces target to configure attacker's IPv6 prefix |
| **DHCPv6 (Dynamic Host Configuration Protocol v6)** | Address + DNS server assignment via DHCP | Assigns attacker's IP as DNS resolver |
| **DNS spoofing** | All hostname queries answered with attacker IP | Forces HTTP/proxy connections to attacker |
| **WPAD (Web Proxy Auto-Discovery)** | Browser/system auto-discovery of proxy config | Redirects web traffic through proxy |
| **HTTP PAC (Proxy Auto-Config)** | JavaScript file defining proxy rules | Instructs clients to proxy through attacker |
| **NTLM authentication** | Challenge/response over proxy connection | Captured and relayed (not cracked) |
| **CVE-2016-3088 (partial)** — IPv6 RA spoofing is not a CVE per se (by design in the protocol), but is widely exploited; no numbered CVE tracks "ICMPv6 RA spoofing" as a whole, since it's a protocol-level design choice |

## Command-Line Switches — Quick Reference

mitm6's CLI is minimal — most configuration lives in `mitm6.conf` (the configuration file, auto-generated on first run). The main `mitm6` binary is thin and primarily controls startup options:

| Flag | Argument | Default | Purpose |
|---|---|---|---|
| `-i IFACE` | Interface name (e.g., eth0, ens0) | — | **Required**: bind to specified network interface |
| `-v` | (none) | — | Verbose output (show DNS queries, DHCP offers, etc.) |
| `-vv` | (none) | — | Very verbose (full packet hex dumps) |
| `--logfile LOG` | Path to log file | `mitm6.log` | Write all traffic/auth to file |
| `--domain DOMAIN` | Active Directory domain (e.g., corp.local) | `(empty)` | Used for WPAD/DNS spoofing context; primarily informational |
| `--host HOSTNAME` | Attacker's hostname in the domain | `mitm6` | Hostname to advertise in RA/DHCP (not critical) |
| `--relay IP:PORT` | ntlmrelayx listener address | `127.0.0.1:6666` | Forward captured NTLM to ntlmrelayx on this socket |
| `--no-http` | (none) | (enabled) | Disable HTTP PAC server (WPAD delivery); WPAD still served if DHCPv6-forced DNS resolution lands on mitm6 |
| `--ipv6-prefix PREFIX` | IPv6 prefix (e.g., fd00::/64) | `fd00::/64` | Advertise this prefix in RA; private ULA recommended |
| `--dhcp-leases LEASE-FILE` | File to store DHCP leases | `mitm6.leases` | Track issued IPv6 addresses (mostly logging, not security-relevant) |

**Caveat:** mitm6 has **no CLI authentication/credential arguments**. It operates entirely at the network layer (IPv6/DHCP/DNS) with zero credential exchange — the tool does not know about or validate any domain credentials. All NTLM capture is implicit via the proxy-auth request.

## Quick Use-Case List

1. **Domain-wide NTLM relay via forced IPv6 autoconfiguration** — Force all users on a segment to authenticate to mitm6's proxy, relay their NTLM auth to a DC/file server for lateral movement / domain escalation.
2. **DNS poisoning for credential capture** — Intercept name resolution and serve malicious WPAD, capturing credentials from any service that auto-discovers proxy.
3. **Chained relay: SMB + LDAP** — Capture NTLM from proxy auth, relay to both SMB (dump SAM) and LDAP (modify ACLs, grant rights) in the same session.
4. **Privilege escalation via relay to DC** — Relay a user's NTLM from proxy auth to the DC's LDAP service, granting the attacker DCSync rights or similar.
5. **Print server / file server takeover via relay** — Relay credentials to administrative shares (ADMIN$, C$) on file/print infrastructure for lateral movement.
6. **Credential harvesting for offline cracking** — Capture NetNTLMv2 hashes for hashcat (unlike relay, which uses hashes in-flight without cracking).
7. **IPv6 "stealth" persistence** — Many network monitoring/IDS tools still focus on IPv4; IPv6 DHCP can persist longer without detection on legacy infrastructure.
8. **Segment-wide reconnaissance** — Map all hosts and their current DNS resolutions by observing DHCP/RA traffic (passive variant).

## Prerequisites

1. **Network position:** Must be on the **same local broadcast segment** as targets (ARP-adjacent). Not routable across VLANs/subnets without L2 breaching or spoofing upstream routers.
2. **IPv6 enabled on targets:** Targets must have IPv6 enabled and active (true by default on Windows Vista+, but can be disabled, rare in practice).
3. **Privileged network access:** Binding to raw sockets (ICMP, DHCP port 546/UDP, DNS port 53/UDP, HTTP port 80) requires **root/Administrator** on the attacker's host.
4. **ntlmrelayx.py installed:** For actual relay exploitation. mitm6 can run standalone (capturing hashes to logs) but is nearly always paired with ntlmrelayx.
5. **No IPv6 filtering / RA-guard:** If the network has RA-guard (RFC 6105) enabled on switch ports, ICMPv6 RAs are blocked — mitm6 is completely defeated. Similarly, if DHCPv6-Guard is enabled, mitm6's DHCPv6 is dropped. Both are rare in practice (typically only in large managed enterprise networks).
6. **DNS port available:** Port 53/UDP must be available on the attacker's host; if something else is running (e.g., a real DNS resolver), conflicts will occur.

---

**Next:** See `02 - Hands-On Use Cases.md` for full command walkthroughs, `03 - Source Evidence.md` for attacker-side artifacts (logs, network state), `04 - Target Evidence.md` for victim-side evidence (DHCPv6 logs, DNS queries), and `05 - Detection and Hunting.md` for detection/evasion strategies.
