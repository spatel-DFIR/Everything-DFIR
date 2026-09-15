# 01 - Overview

🔴 **Scapy is a low-level packet-crafting library that lets operators build arbitrary network packets and bypass protocol constraints entirely — the single strongest signal is Python process execution with script source code on the attacker's host, since Scapy itself writes no persistent artifacts unless the script does.**

## History

**Scapy** is a Python-based interactive packet manipulation library developed by Philippe Biondi in 2003. The project is currently maintained by the SecDev team (Pierre Lalet, Gabriel Potter, Guillaume Valadon, Nils Weiss) at [github.com/secdev/scapy](https://github.com/secdev/scapy). Licensed under GPLv2, Scapy is production-stable and actively developed, supporting Python 3.7+.

The tool fills a gap that standalone CLI tools like `nmap`, `hping`, and `arpspoof` cannot: arbitrary packet construction and fuzzing, where an operator writes Python code to craft packets that violate protocol expectations. From a DFIR perspective, this makes Scapy fundamentally a **library/framework** rather than a discrete binary — operators embed it in custom exploit scripts, network-recon loops, and protocol testing harnesses that are unique per engagement.

## How It Works

Scapy abstracts network packet construction into a layered, composable API. An operator writes Python code to:

1. **Define packet layers** — each protocol (IP, TCP, UDP, ICMP, DNS, Kerberos, etc.) is a Python class with fields corresponding to that protocol's header.
2. **Stack layers** — use Python's `/` operator to compose layers (e.g., `IP()/TCP()/Raw()` builds an IP+TCP+payload packet).
3. **Set field values** — each layer's fields are configurable; fields not explicitly set use sensible defaults.
4. **Send or receive** — use one of Scapy's built-in send/receive functions to emit the packet on the wire or capture responses.
5. **Parse responses** — Scapy automatically dissects incoming packets back into their layered structure for inspection.
6. **Fuzz/mutate** — the `fuzz()` function randomly corrupts packet fields to test protocol robustness or trigger bugs.

This composability is Scapy's defining power: an operator can build a TCP packet stacked over a VLAN layer stacked over an 802.11 frame with custom flags that no RFC-compliant tool would allow, then send it to probe for vulnerabilities or to trigger unexpected behavior on the target.

**Protocol sequence diagram (basic packet crafting → sending → response parsing):**

```
Attacker host                          Target
   |                                      |
   | Python script imports Scapy          |
   | p = IP(dst="target")/TCP(dport=80)   |
   | r = sr1(p)                           |
   |------- send raw IP+TCP ---------->   |
   |                    (target's network |
   |                     stack processes) |
   |          <------ TCP RST/ACK (or SYN-ACK) -----
   | Scapy parses response into layers    |
   | if TCP in r:  print(r[TCP].flags)    |
   |                                      |
```

**Process tree (Scapy is always embedded; no separate binary):**

```
bash/python (operator shell)
  └─ python3 script.py (or: python3 -c "from scapy.all import *; ...")
      └─ (Scapy runs within this process; opens raw socket to send packets)
```

## Techniques & Protocols Used

**OSI Layer Focus:** Scapy spans layers 2–7, with particular strength in layers 2–4 (physical/link/network/transport).

**Core Protocols (built-in layers):** IP, IPv6, TCP, UDP, ICMP, IGMP, ARP, DNS, DHCP, DHCPv6, HTTP, HTTPS/TLS, SSH, Kerberos, LDAP, NTLM, SMB/SMB2, 802.1Q VLAN, 802.11 (WiFi), PPP, L2TP, MPLS, RTP, SIP, SNMP, NTP, TFTP, RADIUS, IKE/IPSec, Bluetooth, ZigBee, VoIP codecs, and ~45 more.

**Attack/Recon Techniques:**
- Network scanning (stateless SYN, ICMP ping variants, UDP probes)
- Protocol manipulation (malformed packets, flag injection, payload injection)
- Credential/data exfiltration (crafted DNS queries, DNS exfil over ICMP, Kerberos ticket extraction)
- ARP spoofing/poisoning
- VLAN hopping
- 802.11 frame injection and raw WiFi exploitation
- Protocol fuzzing (bit-flipping, field randomization)
- Exploit delivery (shellcode embedding in crafted packets)

**MITRE ATT&CK Coverage:**
- **T1595.001** — Active Scanning: Network Service Discovery (custom port probes)
- **T1046** — Network Service Scanning (via crafted packets)
- **T1040** — Traffic Capture (sniff() function)
- **T1566.002** — Phishing: Spearphishing via Service (VoIP/SIP packet manipulation)
- **T1204** — User Execution (embedded in larger attack chains)
- **T1548** — Abuse Elevation Control Mechanism (no direct elevation; used post-compromise)
- **T1557.002** — Adversary-in-the-Middle: ARP Cache Poisoning (crafted ARP packets)
- **T1583.006** — Acquire Infrastructure: Vulnerabilities (protocol testing)

## Command-Line Switches — Quick Reference

**Note:** Scapy is a library, not a CLI tool. It is invoked via Python scripts or the interactive shell. The parameters below are constructor/function arguments used within Python code, not command-line flags.

### Interactive Shell

| Command | Usage | Purpose |
|---------|-------|---------|
| `./run_scapy` or `python -m scapy.main` | Start interactive shell | Drop into an interactive Scapy session (requires `sudo` for raw socket access) |
| `quit()` or `exit()` | Exit shell | Leave the Scapy interactive session |

### Core Functions (used within Python code)

| Function | Signature | Purpose |
|----------|-----------|---------|
| `send()` | `send(packets, iface=None, loop=False, interval=0, count=None, verbose=None)` | Send layer-3 packets without expecting responses; returns nothing |
| `sendp()` | `sendp(packets, iface=None, pktlen=None, ...)` | Send raw layer-2 packets (requires raw socket); useful for 802.11, VLAN, etc. |
| `sr()` | `sr(x, timeout=2, promisc=None, filter=None, nofilter=0, ...)` | **Send and Receive** at layer 3; returns answered + unanswered packet pairs |
| `sr1()` | `sr1(x, timeout=2, ...)` | Send one packet and get one response (convenience wrapper around `sr()`) |
| `srp()` | `srp(x, iface=None, timeout=2, filter=None, ...)` | Send and Receive at layer 2 (Ethernet) |
| `srp1()` | `srp1(x, iface=None, timeout=2, ...)` | Send one Ethernet packet and get one response |
| `sniff()` | `sniff(prn=None, iface=None, filter=None, count=0, timeout=None, store=True, ...)` | Capture and optionally parse incoming packets; returns packet list or runs callback function |
| `fuzz()` | `fuzz(packet)` | Randomly corrupt packet fields to test protocol robustness; returns mutated packet |
| `IP()`, `TCP()`, `UDP()`, etc. | Constructor calls | Build protocol-layer objects; fields are set as kwargs (e.g., `IP(dst="1.2.3.4", ttl=64)`) |
| `packet1 / packet2` | `/` operator | Stack layers together (e.g., `IP()/TCP()/Raw(load=b"data")`) |

### Packet Inspection (within Python)

| Method/Property | Usage | Purpose |
|---------|-------|---------|
| `packet[LayerName]` | `pkt[TCP]` to get TCP layer; `if TCP in pkt:` to check | Access or test for a specific layer |
| `packet.show()` | `pkt.show()` | Pretty-print packet fields |
| `packet.summary()` | `pkt.summary()` | One-line summary of packet structure |
| `bytes(packet)` | `raw = bytes(pkt)` | Convert packet to raw bytes |
| `packet.hexdump()` | `pkt.hexdump()` | Print hex/ASCII view |

### Installation & Setup

| Action | Command | Notes |
|--------|---------|-------|
| Install basic | `pip install scapy` | Standalone, no external Python dependencies on Linux/BSD |
| Install with extras | `pip install scapy[optional]` | Adds `cryptography` (for TLS/IPSec), `pycryptodome` (for more ciphers), `matplotlib` (for graphing) |
| Run interactive shell | `sudo python -m scapy.main` | Requires root/admin for raw socket access |
| Import in script | `from scapy.all import *` | Imports all built-in layers and functions; used in most scripts |

## Quick Use-Case List

1. **Basic packet crafting** — Construct and send an IP+TCP packet with custom fields to a target.
2. **Stateless SYN scanning** — Send SYN packets to a range of IPs/ports and collect RST/SYN-ACK responses to detect open ports without maintaining connection state.
3. **ICMP reconnaissance** — Craft ICMP Echo Requests with custom TTL, timestamps, or malformed payloads to probe firewalls and OS fingerprinting.
4. **ARP reconnaissance & spoofing** — Broadcast ARP requests to enumerate hosts on a network; craft spoofed ARP replies for cache-poisoning or MITM attacks.
5. **DNS query crafting** — Build custom DNS packets with spoofed headers, custom flags, or unusual field values to probe DNS servers or trigger bugs.
6. **Protocol fuzzing** — Mutate packet fields randomly via `fuzz()` to discover protocol-parsing bugs or crash targets.
7. **Exploit payload delivery** — Embed shellcode or malicious data into crafted packets (e.g., within a TCP payload or ICMP data field) and deliver to a target.
8. **VoIP/SIP manipulation** — Craft or replay SIP/RTP packets to enumerate VoIP infrastructure or trigger call-handling bugs.
9. **Kerberos ticket construction** — Build raw AS-REQ/TGS-REQ packets to interact with Kerberos services without a full Kerberos client library.
10. **Custom protocol implementation** — Define a custom protocol layer in Scapy to test proprietary or legacy protocols.
11. **Metasploit integration** — Use Scapy-crafted packets within Metasploit modules or feed results into Metasploit payloads for chained exploitation.
12. **Network fingerprinting evasion** — Craft packets with unusual TTL, fragmentation, or flag combinations to evade passive OS-detection signatures.

## Prerequisites

- **Python 3.7+** installed on the attacker's host.
- **`scapy` package** installed via `pip install scapy`.
- **Raw socket access:** On Linux/BSD, requires root or the `CAP_NET_RAW` Linux capability. On Windows, requires Administrator privileges. On macOS, typically requires `sudo`.
- **Script or interactive shell:** Either write a `.py` script that imports Scapy, or run `python -m scapy.main` interactively (requires `sudo`).
- **Network interface access:** The interface used for sending/receiving packets must be accessible (usually the default gateway interface or a specified `-i` iface).
- **Optional: Cryptography libraries** for TLS/SSL interception or IPSec — `pip install scapy[optional]` adds `cryptography` and `pycryptodome`.

### Prerequisites by Use Case

| Use Case | Required | Optional |
|----------|----------|----------|
| Basic packet crafting | Python 3.7+, Scapy, raw socket access | — |
| SYN scanning | Python 3.7+, Scapy, raw socket access, network connectivity | — |
| ICMP reconnaissance | Python 3.7+, Scapy, raw socket access, network connectivity | — |
| ARP spoofing | Python 3.7+, Scapy, raw socket access, Ethernet access (not VPN) | — |
| DNS crafting | Python 3.7+, Scapy, raw socket access OR unprivileged UDP socket (sendp vs. send) | — |
| Protocol fuzzing | Python 3.7+, Scapy, raw socket access, target host or lab environment | — |
| Exploit payload delivery | Python 3.7+, Scapy, raw socket access, network access to target, understanding of target vulnerability | Custom shellcode or payload binary |
| VoIP/SIP manipulation | Python 3.7+, Scapy, network access to VoIP infrastructure | VoIP-specific payloads or call signaling knowledge |
| Kerberos crafting | Python 3.7+, Scapy, network access to KDC (port 88), optional `cryptography` for encryption | Knowledge of Kerberos protocol |
| Custom protocol | Python 3.7+, Scapy, understanding of protocol specification | — |
| Metasploit integration | Python 3.7+, Scapy, Metasploit Framework installed and running | Exploit module knowledge |
| Network fingerprinting | Python 3.7+, Scapy, raw socket access, target host | — |
