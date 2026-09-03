# mitm6 — Source Evidence

Evidence on the **attacker's host** following a mitm6 operation. These artifacts are left on the operator's machine, not on targets.

---

## Process and Memory

### Process: mitm6 Python process

- **Process name:** `python3` or `python` (depends on shebang/how invoked).
- **Command line:** `sudo mitm6 -i eth0 --relay 127.0.0.1:6666 --domain corp.local -vv` or similar.
- **Parent process:** Often `sudo` (if run with privilege escalation) or shell.
- **Child processes:** Typically none (mitm6 is single-threaded in the Python sense, multithreaded internally).

**Detection (forensic):** Process name is generic, but command-line arguments (`mitm6`, `--relay`, `--domain`) are distinctive. Presence of `--relay` is a strong signal for NTLM-relay-attack infrastructure.

### Memory artifacts

- mitm6 maintains in-memory state of:
  - **DHCPv6 leases:** IPv6 addresses issued to victims.
  - **DNS queries:** All hostname resolutions answered.
  - **Captured NTLM hashes:** If not immediately relayed, cached in memory.
  - **HTTP requests:** Any WPAD/proxy-auth requests.

Memory dump (e.g., via `python-fmem` or `memdump`) would reveal these, but not typically captured in incident response (requires live capture).

---

## Network Connections and Sockets

### Listening ports (attacker's host)

| Port | Protocol | Purpose |
|---|---|---|
| 53 | UDP | DNS server (spoofed responses) |
| 80 | TCP | HTTP server (WPAD PAC delivery) |
| 546 | UDP | DHCPv6 server (address + DNS assignment) |
| 6666 | TCP (local) | Relay socket (receives NTLM from mitm6, forwards to ntlmrelayx) |
| 8080 | TCP | Proxy server (WPAD-redirected HTTP proxy) |

**netstat / ss output (on attacker):**

```bash
# Show all listening ports
ss -tulnp | grep -E '(mitm6|python)'

# Expected output:
# LISTEN     0      128       0.0.0.0:53     0.0.0.0:*     users:(("python3",pid=12345,...))
# LISTEN     0      128       0.0.0.0:80     0.0.0.0:*     users:(("python3",pid=12345,...))
# LISTEN     0      128       0.0.0.0:546    0.0.0.0:*     users:(("python3",pid=12345,...))
# LISTEN     0      128     127.0.0.1:6666   127.0.0.1:*   users:(("python3",pid=12345,...))
# LISTEN     0      128       0.0.0.0:8080   0.0.0.0:*     users:(("python3",pid=12345,...))
```

### Outbound connections

- **To ntlmrelayx:** TCP 127.0.0.1:6666 (relay handoff).
- **Possibly to Responder (if running in parallel):** Depends on configuration.

**netstat output:**

```bash
# Show established connections
ss -tnp | grep python3

# Example:
# ESTAB     0      0     127.0.0.1:12345  127.0.0.1:6666  users:(("python3",pid=12345,...))
# (relay traffic)
```

---

## Log Files

### mitm6.log (default log file)

Located in the directory where mitm6 was launched (typically current working directory). Contains:

```
[*] Starting mitm6 on interface eth0
[*] ICMPv6 RA sender started, sending to ff02::1
[*] DHCPv6 server started on port 546
[*] DNS server started on port 53
[*] HTTP server started on port 80
[*] Waiting for clients...

--- When targets interact: ---

[*] RA sent to ff02::1
[*] DHCPv6 Solicit from fe80::1234:5678:9abc:def0 (192.168.1.100)
[*] Offering IPv6 address fd00::1001
[+] DHCPv6 ACK sent to fe80::1234:5678:9abc:def0
[*] DNS query from 192.168.1.100: wpad.corp.local -> <mitm6-ip>
[*] HTTP request: GET /wpad.dat from 192.168.1.100 (User-Agent: Mozilla/5.0...)
[*] NTLM auth from 192.168.1.100 (CORP\alice)
[*] NetNTLMv2: CORP\alice::CORP:1122334455667788:8899aabbccddeeff...
[*] Relaying to ntlmrelayx on 127.0.0.1:6666
```

**Forensic value:**
- Exact times of RA/DHCP/DNS/HTTP traffic.
- Captured NTLM challenge/response (full hash).
- Victim IP addresses and usernames.
- Relay destinations.

**Discovery:** Search attacker's filesystem for `mitm6.log` or the custom logfile specified in command-line (`--logfile`).

### Filesystem: mitm6 configuration and state files

- **mitm6.conf** — Configuration file (auto-generated if missing). Not critical to operation; mostly informational.
- **mitm6.leases** — DHCPv6 lease database (default). JSON or CSV file tracking IPv6 addresses issued.

**Example mitm6.leases:**

```json
{
  "fd00::1001": {
    "hw_addr": "001122334455",
    "timestamp": 1692374400,
    "domain": "corp.local"
  },
  "fd00::1002": {
    "hw_addr": "aabbccddeeff",
    "timestamp": 1692374410,
    "domain": "corp.local"
  }
}
```

**Forensic value:** Maps IPv6 addresses to MAC addresses (helps correlate with DHCP logs).

---

## Bash/Command History

If attacker used interactive shell before launching mitm6:

```bash
# In ~/.bash_history or ~/.zsh_history:
sudo mitm6 -i eth0 --relay 127.0.0.1:6666 --domain corp.local -vv
# Or:
python3 -m mitm6 --interface eth0 --relay 127.0.0.1:6666
```

**Detection:** Presence of `mitm6` or `ntlmrelayx` in shell history is a direct attribution signal.

---

## Network Artifacts (pcap/packet captures)

### ICMPv6 Router Advertisement (sent by mitm6)

If attacker's network traffic is captured (e.g., via tcpdump on a monitor port):

```
Packet: ICMPv6 Router Advertisement
  Source: <mitm6-attacker-ip> (fe80::...)
  Destination: ff02::1 (all-nodes multicast)
  Flags: M (Managed), O (Other)
  Prefix: fd00::/64 (or custom)
  Router Lifetime: 1800 seconds
  Reachable Time: 0 ms
  Retrans Timer: 0 ms
  DHCPv6 flag: Set
```

### DHCPv6 Advertise (from mitm6)

```
Packet: DHCPv6 Advertise
  Source: <mitm6-ip> port 546
  Destination: <victim-ip> port 546/UDP
  Message Type: Advertise (2)
  Transaction ID: 0xabcdef
  Option: IA_NA (Identity Association for Non-temporary Address)
    IPv6 Address: fd00::1001
    Preferred Lifetime: 3600 seconds
  Option: DNS Servers (23)
    DNS: <mitm6-ip>
```

### DNS Responses (from mitm6)

```
Packet: DNS Response
  Source: <mitm6-ip> port 53
  Destination: <victim-ip> port 53/UDP
  Query: wpad.corp.local?
  Response: wpad.corp.local -> <mitm6-ip>
```

### HTTP GET /wpad.dat

```
Packet: HTTP GET
  Source: <victim-ip>
  Destination: <mitm6-ip> port 80
  Method: GET
  URI: /wpad.dat
  Host: wpad
  User-Agent: (browser or Windows-native)
```

### NTLM over HTTP Proxy-Authentication

```
Packet: HTTP with Proxy-Authenticate
  Source: <victim-ip>
  Destination: <mitm6-ip> port 8080
  Original Request: CONNECT <any-host>:443
  Response: 407 Proxy Authentication Required
            Proxy-Authenticate: NTLM
  
  Follow-up: HTTP with Proxy-Authorization
  Proxy-Authorization: NTLM TlRMTVNTUAECAAAA...
  (base64-encoded NTLM challenge/response)
```

**Detection:** If pcap is analyzed, all of the above are observable and distinctive. Modern Zeek/Suricata rules should flag unsolicited RA with M/O flags set.

---

## Responder Integration (if running in parallel)

If attacker ran **both** mitm6 and Responder on the same segment:

- mitm6 forces IPv6 + WPAD redirect to mitm6's proxy.
- Responder captures IPv4 LLMNR/NBT-NS/DHCP traffic.

Both would log separately:
- **mitm6.log** — IPv6/DHCPv6 traffic, NTLM from proxy auth.
- **Responder/logs/SMB-NTLMv2-Client-*.txt** — NTLM from IPv4 SMB connections.

**Combined footprint:** Presence of both tools' artifacts on the same host is a strong signal for coordinated network-level attack infrastructure.

---

## Forensic Timeline (Source Perspective)

| Time | Event | Artifact |
|---|---|---|
| T0 | mitm6 started | Process creation, listening ports, mitm6.log entry |
| T0+5s | RA sent to ff02::1 | Network packet (ICMPv6), mitm6.log entry |
| T0+10s | Victim receives RA, configures IPv6 | (No attacker-side artifact; victim-side only) |
| T0+15s | Victim issues DHCPv6 Solicit | Network packet (DHCPv6), mitm6.log entry |
| T0+16s | mitm6 replies with DHCPv6 Advertise | Network packet, mitm6.log entry |
| T0+20s | Victim resolves wpad via DNS | Network packet (DNS), mitm6.log entry |
| T0+25s | Victim fetches WPAD PAC from mitm6 | Network packet (HTTP), mitm6.log entry |
| T0+30s | Victim connects to proxy:8080, requests auth | Network packet (HTTP), mitm6.log entry |
| T0+35s | Victim sends NTLM Negotiate | Network packet, mitm6.log entry |
| T0+36s | mitm6 forwards to ntlmrelayx | Relay traffic to 127.0.0.1:6666 |
| T0+40s | Relay attack succeeds (DC/SMB) | ntlmrelayx.log, target-side events (not attacker-side) |

---

## Summary: Strongest Signals (Source)

1. **mitm6 process + command line** — Python process with `mitm6` + `--relay` is unmistakable.
2. **Listening ports 53, 80, 546, 8080** — Unusual combination (especially 546 DHCPv6).
3. **mitm6.log + captured NTLM hashes** — Direct evidence of credential capture.
4. **ICMPv6 RA with M/O flags + fd00::/64 prefix** — Spoofed RA distinctive in pcap.
5. **Shell history** — `sudo mitm6 ...` in bash_history.

**Evasion resistance:** High. mitm6's network-layer position makes it difficult to hide in pcap analysis. Killing the process removes most evidence, but logs/leases would survive (unless explicitly deleted).

---

**Next:** See `04 - Target Evidence.md` for victim-side artifacts.
