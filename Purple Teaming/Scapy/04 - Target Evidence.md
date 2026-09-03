# 04 - Target Evidence

**Key principle:** Scapy crafts arbitrary network packets. The target-side evidence depends entirely on the protocol being exploited and the target's logging posture. This section focuses on the network-layer perspective (Zeek, Wireshark, tcpdump) and service-specific logs triggered by Scapy-crafted packets.

## Network-Layer Evidence (Wire Protocol)

### Packet Structure & Anomalies

Scapy-crafted packets are transmitted as raw bytes onto the network. A packet capture (pcap) from the target's network interface shows the exact bytes sent.

**Example: SYN scan via Scapy**

Captured via tcpdump on the target:

```
15:23:45.123456 IP attacker.12345 > target.22: Flags [S], seq 0, win 8192, length 0
15:23:45.123789 IP attacker.12346 > target.80: Flags [S], seq 0, win 8192, length 0
15:23:45.124012 IP attacker.12347 > target.443: Flags [S], seq 0, win 8192, length 0
```

**Key fields that reveal Scapy crafting:**

| Field | Scapy Default | Real OS | Forensic Significance |
|-------|----------|---------|----------------------|
| TTL | 64 | Varies (Linux 64, Windows 128, macOS 64) | Helps fingerprint attacker OS |
| TCP Window Size | 8192 | Varies (often larger) | May indicate non-native OS stack |
| TCP Flags | Raw bits (set via `flags="S"`) | Rarely invalid combinations | Scapy allows SYN+FIN (invalid), revealing custom crafting |
| IP ID | 0 or random | Usually incremental | Scapy defaults to 0; real OS increment per packet |
| Don't Fragment (DF) | Not set by default | Often set by modern OS | Scapy lets you control this explicitly |
| TCP Options | Minimal (MSS, Window Scale) | Rich (SACK, Timestamps) | Scapy packets often lack expected TCP options |
| TCP Sequence Number | 0 or random (operator's choice) | Random, non-zero | Scapy allows seq=0; real clients avoid it |
| MAC Address | Spoofable | Real MAC of sending interface | Scapy can forge MACs (when using `sendp()` at layer 2) |
| ICMP Checksum | Auto-calculated | Auto-calculated | Both match, but payload may be anomalous |

### Stateless Scanning Patterns

A Scapy SYN scan produces a distinctive pattern:

1. **No connection state:** SYN packets are sent, responses are received, but no ACK is ever sent (unlike `nmap -sS` which may send reset packets).
2. **Rapid-fire probes:** Multiple SYN packets to different ports on the same target within seconds, from the same source port range.
3. **No three-way handshake:** The attacker never completes the TCP handshake; connections stay in SYN_RECEIVED state on the target until timeout.

**Target observation (via `netstat` or `ss` -t):**

```
$ netstat -an | grep SYN_RECV
tcp    128    0  target:22     attacker:12345    SYN_RECV
tcp    128    0  target:80     attacker:12346    SYN_RECV
tcp    128    0  target:443    attacker:12347    SYN_RECV
```

These connections hang for several minutes before timing out (usually 60 seconds on modern Linux).

### Protocol-Specific Anomalies

**DNS (Scapy crafted query):**

```
15:23:45.500000 IP attacker > target.53: query(z) A? example.com (31)
```

Suspicious fields:
- `z` bit set (Reserved, should be 0)
- Unusual DNS flags (e.g., `QR=1` in a query — should be query, not response)
- Custom payload in additional section (Scapy allows arbitrary data)

**ICMP (Scapy with malformed payload):**

```
15:23:45.600000 IP attacker > target: ICMP echo request, id 1000, seq 1, length 1500
15:23:45.600100 IP target > attacker: ICMP echo reply, id 1000, seq 1, length 1500
```

Suspicious:
- Unusually large ICMP payload (1500 bytes; typically 56 bytes)
- Malformed data in payload (if Scapy used `Raw(load=b"corrupted_data")`)

**TCP (Scapy with invalid flag combinations):**

```
15:23:45.700000 IP attacker.12345 > target.80: Flags [S F R A], seq 0, ack 0, win 0, length 0
```

Highly suspicious: SYN + FIN + RST + ACK together is never valid in real TCP.

---

## Service-Specific Logs

### HTTP Server Logs (Apache, Nginx, IIS)

When Scapy sends HTTP-layer packets (via `send(IP()/TCP(dport=80)/Raw(load=b"GET /"))`), HTTP servers log the connection attempt.

**Apache access.log:**

```
attacker - - [11/Sep/2024:15:23:45 +0000] "GET / HTTP/1.0" 400 0 "-" "-"
```

Key indicators:
- Malformed HTTP request (missing headers, invalid version)
- Empty User-Agent or unusual User-Agent (if Scapy appended one)
- Unusual port access (e.g., multiple SYN packets to port 80 without completing handshake)

**Nginx error.log:**

```
2024/09/11 15:23:45 [error] 1234#1234: *456 malformed HTTP request line
```

### SSH Server Logs (sshd)

When Scapy sends raw packets to port 22 (e.g., `send(IP()/TCP(dport=22))`), sshd logs the connection:

**Linux /var/log/auth.log or /var/log/secure:**

```
Sep 11 15:23:45 target sshd[1234]: Invalid user from attacker 192.168.1.99 port 12345
Sep 11 15:23:45 target sshd[1234]: Received disconnect from attacker 192.168.1.99: 11: Bye Bye [preauth]
```

Or if Scapy sends only a SYN without completing handshake:

```
Sep 11 15:23:45 target sshd[1234]: Connection closed by authenticating user from 192.168.1.99 port 12345 [preauth]
```

### DNS Server Logs (BIND, Unbound)

When Scapy crafts DNS queries:

**BIND querylog (if enabled):**

```
11-Sep-2024 15:23:45.123 queries: client 192.168.1.99#12345 (example.com): query +[A] example.com IN A -ED
```

Suspicious patterns:
- Repeated queries for the same domain (recon)
- Unusual flags (z-bit, rcode values)
- Zone transfer attempts (AXFR queries)
- Requests for non-existent records (CHAOS class queries)

---

## Firewall & IDS/IPS Logs

### Palo Alto Networks (Firewall)

```
2024-09-11 15:23:45 attacker 192.168.1.99 target 192.168.1.100 22 tcp Allow
2024-09-11 15:23:45 attacker 192.168.1.99 target 192.168.1.100 80 tcp Allow
2024-09-11 15:23:45 attacker 192.168.1.99 target 192.168.1.100 443 tcp Allow
```

**Alert context:** Multiple connection attempts to different ports within milliseconds = likely port scan.

### Suricata IDS

Suricata detects Scapy-specific patterns via heuristics:

```
Alert tcp 192.168.1.99 any -> 192.168.1.100 [22,80,443] (msg:"Possible port scan"; flow:stateless; content:"S"; http_method; ...)
Alert ip 192.168.1.99 any -> 192.168.1.100 any (msg:"Anomalous TTL"; ttl:0-32 or ttl:254; sid:1000001;)
```

**Real-world example (Zeek):**

```json
{
  "ts": 1694425425.123,
  "src": "192.168.1.99",
  "src_port": 12345,
  "dst": "192.168.1.100",
  "dst_port": 22,
  "proto": "tcp",
  "service": "ssh",
  "duration": 0.001,
  "orig_pkts": 1,
  "orig_ip_bytes": 40,
  "resp_pkts": 1,
  "resp_ip_bytes": 40,
  "conn_state": "SH",
  "history": "S",
  "tunnel_parents": [],
  "flags": "S"
}
```

The connection state `SH` (SYN sent, FIN-ACK received = half-open) is a dead giveaway of a SYN scan.

---

## Network Capture Analysis (Wireshark / tcpdump on Target or Network Tap)

### Full Packet Capture (pcap)

If the target network has a SPAN port or network tap, all Scapy traffic is captured:

```bash
$ tcpdump -i eth0 -w /tmp/capture.pcap 'src 192.168.1.99'

$ wireshark /tmp/capture.pcap
```

**In Wireshark, right-click a packet:**
- **Analyze > Follow > TCP Stream** — shows the exact bytes sent/received
- **Packet Details** — reveals every field (TTL, flags, options) that indicates Scapy crafting

### Heuristic Detection in Wireshark

Wireshark flags unusual packets with expert-level alerts:

```
[Warning] TCP: "SYN+FIN" flags
[Warning] TCP: "RST+ACK" for connection not in Wireshark's state table
```

---

## Host-Based Event Logs (Windows)

### Event ID 4688: Process Creation

When the target is Windows and a service is compromised via Scapy-delivered exploit, the resulting process creation is logged:

```
Event ID: 4688
Time: 2024-09-11 15:23:46
Creator Process: svchost.exe (PID 456)
Process Name: C:\Windows\System32\cmd.exe
Command Line: cmd.exe /c ... (exploit payload)
```

The process creation chain reveals:
- The service that was exploited (svchost, lsass, spoolsv, etc.)
- The process spawned (cmd.exe, powershell.exe, etc.)
- The command executed (often reverse shell command)

### Event ID 4697: A service was installed in the system

If the Scapy exploit creates a new service (e.g., for persistence):

```
Event ID: 4697
Time: 2024-09-11 15:23:47
Service Name: MyService
Display Name: My Service
Status: Install
```

This indicates post-exploitation activity (persistence), not the Scapy attack itself, but correlates with the initial exploit delivery.

---

## Protocol-Specific Detection

### ARP Spoofing (Scapy-crafted ARP packets)

**Target observation (if victim is running `arpwatch`):**

```
2024-09-11 15:23:45 192.168.1.1 changed from 00:11:22:33:44:55 to aa:bb:cc:dd:ee:ff
```

**In ARP traffic (tcpdump):**

```
15:23:45.123456 ARP, Request who-has 192.168.1.1 tell 192.168.1.99, length 28
15:23:45.123789 ARP, Reply 192.168.1.1 is-at aa:bb:cc:dd:ee:ff, length 28
```

A sudden change in MAC address for a known IP is a strong indicator of ARP spoofing.

### DNS Poisoning / DNS Rebinding

If Scapy sends fake DNS responses:

**Victim DNS resolver queries:**

```
15:23:45.123 example.com A? (from victim)
15:23:45.124 example.com A -> 10.0.0.1 (spoofed response from attacker)
```

**On the victim's DNS cache:**

```
$ nslookup example.com
Server: 192.168.1.1
Address: 192.168.1.1#53

Name: example.com
Address: 10.0.0.1 (WRONG — should be real IP)
```

### Kerberos Manipulation

If Scapy crafts Kerberos AS-REQ packets (without pre-auth):

**DC logs (Event ID 4768: Kerberos Authentication Ticket Request):**

```
Event ID: 4768
Time: 2024-09-11 15:23:45
Account Name: attacker-principal
Supplied Realm Name: DOMAIN.COM
Service Name (SPN): krbtgt/DOMAIN.COM@DOMAIN.COM
Status Code: 0x6 (KDC_ERR_PREAUTH_REQUIRED)
```

The status code `0x6` indicates a pre-auth failure, revealing that the attacker's Scapy-crafted AS-REQ lacked proper pre-authentication.

---

## Behavioral Timeline on Target

### Example: SYN Scan Attack

**T0 (15:23:45.100) - Attack Starts**

1. First SYN packet arrives at target port 22
2. Target's TCP stack responds with SYN-ACK (sent back to attacker)
3. Firewall logs: "New connection from 192.168.1.99:12345 → target:22"

**T1 (15:23:45.200) - More Probes**

4. SYN packet arrives at target port 80
5. SYN packet arrives at target port 443
6. Firewall logs 2 more new connections
7. IDS/IPS may alert: "Possible port scan detected from 192.168.1.99"

**T2 (15:23:46) - Attack Ends**

8. No more packets from attacker
9. Connections enter SYN_RECEIVED state on target
10. After 60 seconds (default timeout), connections are cleaned up
11. Firewall logs: "Connection timeout from 192.168.1.99:12345"

**Complete timeline in Zeek (JSON):**

```json
{
  "events": [
    {
      "ts": 1694425425.100,
      "src": "192.168.1.99",
      "event": "SYN received",
      "dst_port": 22,
      "flags": "S"
    },
    {
      "ts": 1694425425.200,
      "src": "192.168.1.99",
      "event": "SYN received",
      "dst_port": 80,
      "flags": "S"
    },
    {
      "ts": 1694425425.300,
      "src": "192.168.1.99",
      "event": "SYN received",
      "dst_port": 443,
      "flags": "S"
    }
  ]
}
```

---

## Exploiting the Exploit: Detection Strategies

### Real-Time Detection

| Signal | Confidence | Method |
|--------|-----------|--------|
| Multiple SYN packets from same source to different ports within <1 second | High | Firewall/IDS rule (port scan signature) |
| TCP packets with invalid flag combinations | Very High | IDS alert (e.g., SYN+FIN) |
| Anomalous TTL values (e.g., TTL < 32 or TTL = 254) | Medium | Heuristic IDS rule |
| Half-open TCP connections (SYN sent, no ACK) | High | Connection state analysis (Zeek, sysmon) |
| DNS queries with unusual flags or AXFR attempts | Medium–High | DNS query inspection |
| ARP cache changes without corresponding legitimate traffic | High | arpwatch, gratuitous-ARP monitoring |

### Post-Incident Analysis

| Artifact | Recovery Method | Forensic Value |
|----------|-------------|-----------|
| Network pcap from SPAN/tap | tcpdump, Wireshark, Zeek | High (full packet recovery) |
| Firewall connection logs | Firewall syslog export | High (timing, source, destination) |
| IDS alerts | Suricata EVE JSON, Snort alert file | High (rule context, packet summary) |
| Service logs (SSH, HTTP, DNS) | /var/log/* or Windows Event Log | Medium–High (context-dependent) |
| Windows Event Logs | Get-EventLog (Windows) or Zeek logs | Medium (connection state) |
| Network-based endpoint telemetry | Sysmon (Windows), auditd (Linux) | Medium–High (system context) |

---

## Distinguishing Scapy from Other Tools

### Scapy vs. Nmap

| Aspect | Scapy | Nmap |
|--------|-------|------|
| Packet structure | Arbitrary (can be malformed) | RFC-compliant with options |
| TCP options | Minimal | Rich (MSS, SACK, Timestamps) |
| TTL handling | Operator-controlled (often default 64) | Adaptive; varies per scan type |
| Scan speed | Depends on script; typically slower | Highly optimized; very fast |
| Error recovery | Manual (script must handle retries) | Built-in (automatic retries) |
| Signature | Raw sockets + Python process | /usr/bin/nmap or /usr/bin/nmap6 |

**On the wire:** Scapy-crafted packets often lack the TCP options and optimizations that Nmap includes, making them slightly easier to fingerprint.

### Scapy vs. Metasploit

| Aspect | Scapy | Metasploit |
|--------|-------|-----------|
| Abstraction | Low-level (layer-by-layer) | High-level (exploits, payloads) |
| Flexibility | Maximum (craft anything) | Limited to pre-built modules |
| Script language | Python | Ruby (MSF framework) or embedded scripts |
| Packet sophistication | Can be naive (missing options) | Mature (handles RFC compliance) |
| Detection signature | Python process + raw socket | Metasploit binary + modules |

---

## Summary: Target Evidence Priority

**Ranked by strength of attribution to Scapy use:**

1. **Network pcap + analysis** (Very High) — Full packets visible; operator's crafting choices exposed
2. **IDS/firewall logs + behavioral patterns** (High) — Rapid probes, invalid flags, half-open connections
3. **Exploit success + process creation logs** (High) — Indicates successful payload delivery
4. **Service logs** (Medium) — Context-dependent; requires knowledge of target service
5. **Protocol anomalies** (Medium–High) — Malformed DNS, invalid TCP options, unusual TTL

**Critical note:** Target evidence alone does not prove Scapy was used — only that custom packet crafting occurred. Scapy attribution is strengthened by corroborating source-host evidence (Python process, script source code, memory artifacts).
