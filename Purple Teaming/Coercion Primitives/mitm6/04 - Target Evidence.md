# mitm6 — Target Evidence

Evidence on the **victim/target host** following a mitm6 IPv6 spoofing attack.

---

## IPv6 Address Configuration

### ipconfig (Windows)

```
Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : corp.local
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   
   IPv6 Address. . . . . . . . . . . : fd00::1001      <-- SUSPICIOUS: ULA prefix (not legit DHCPv6)
   Link-local IPv6 Address . . . . . : fe80::1234:5678:9abc:def0
   IPv6 Default Gateway . . . . . . : fe80::abcd:ef00:1234:5678 <-- SUSPICIOUS: doesn't match router
   DNS Servers . . . . . . . . . . . : <attacker-ip>   <-- PRIMARY SIGNAL
   Lease Obtained. . . . . . . . . . : [recent time]
```

**Detection:** 
- IPv6 address from unexpected prefix (e.g., `fd00::/64` instead of organization's real prefix).
- DNS server pointing to non-standard IP (attacker's address).
- Default gateway (router) IPv6 address doesn't match known infrastructure.

### netsh (Windows command-line query)

```bash
netsh interface ipv6 show address

# Output:
# Interface 7: Ethernet
# ...
# Address            : fd00::1001
# Prefix Length      : 64
# Scope ID           : 0
# Type               : Other (DHCP-assigned)
# DHCP State         : Enabled
# Valid Lifetime     : 3599 seconds
# Preferred Lifetime : 3599 seconds
# DAD State          : Preferred
```

**Forensic value:** Shows IPv6 was assigned via DHCPv6 from attacker-controlled DHCP server.

### DHCPv6 Lease File (Windows)

**Location:** `C:\Windows\System32\dhcp\`

No standalone DHCPv6 lease file exists on Windows (unlike `dhclient.leases` on Linux). Instead, configuration is stored in:

- **Registry:** `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{GUID}\`
  - `Dhcp6ServerAddresses` — IPv6 address of DHCP server.
  - `Dhcp6NameServers` — DNS servers assigned via DHCPv6.

### ip / ipconfig6 (Linux/macOS)

```bash
# On Linux:
ip addr show eth0 | grep -A 5 "inet6"

# Output:
# inet6 fd00::1001/64 scope global dynamic mngtmpaddr
#       valid_lft 3599sec preferred_lft 3599sec

# On macOS:
ifconfig en0 | grep inet6

# Output:
# inet6 fd00::1001%en0 prefixlen 64 deprecated 
# inet6 fe80::1234:5678:9abc:def0%en0 prefixlen 64 scopeid 0x5
```

---

## DNS Configuration and Queries

### /etc/resolv.conf (Linux) or Registry (Windows)

**Windows Registry:**
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{GUID}
  - NameServer: <attacker-ip>
  - DhcpNameServer: <attacker-ip>
```

**Output of nslookup:**

```
C:\> nslookup google.com

Server:  <attacker-ip>
Address: <attacker-ip>#53

Non-authoritative answer:
Name:    google.com
Address: <attacker-ip>  <-- SUSPICIOUS: all names resolve to attacker

C:\> nslookup wpad

Server:  <attacker-ip>
Address: <attacker-ip>#53

Name:    wpad.corp.local
Address: <attacker-ip>  <-- Direct evidence of spoofing
```

### DNS Query Log (Event Viewer or dns.log)

**Windows Event ID 1014 (Operational) or raw DNS logs:**

```
DNS Query Log:
  Client: 192.168.1.100
  Query: wpad.corp.local
  Query Type: A (IPv4) + AAAA (IPv6)
  Server: <attacker-ip>
  Response: <attacker-ip>
  Timestamp: [time of incident]
```

---

## Proxy Configuration

### WPAD/PAC Auto-Discovery

**Browser/Windows stored PAC location:**

- **IE/Edge Registry:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL`
  - Value: `http://wpad/wpad.dat` (or `http://wpad.corp.local/wpad.dat`)
  - Resolved to: `<attacker-ip>`

### browser's Proxy Config (Chrome, Firefox)

- **Chrome:** Settings → Advanced → System → Open Proxy Settings (launches Windows settings).
- **Firefox:** Preferences → Network Settings → Automatic proxy configuration URL
  - May be set to `http://wpad/wpad.dat`

### netsh Proxy Query (Windows)

```bash
netsh winhttp show proxy

# Output (if WPAD is active):
# Current WinHTTP proxy settings:
# 
#     AutoConfig URL  : http://wpad/wpad.dat
#     Bypass List     : (none)
```

**Forensic value:** Shows victim's system was configured to auto-discover and use a proxy (attacker's WPAD).

---

## HTTP Proxy Authentication Logs

### IIS logs (if running on attacker's HTTP server)

**Location:** `C:\inetpub\logs\LogFiles\W3SVC\`

(Not typically on victim, unless victim is also running a web server — unlikely unless attacker compromised target.)

### Browser proxy-authentication cache

**Chrome/Edge:** `%APPDATA%\Local\Microsoft\Windows\INetCache\`

Stores cached proxy-auth credentials (encrypted but recoverable).

**Firefox:** `%APPDATA%\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite`

May contain proxy-auth cookies if `-authentication-remember` was selected.

---

## Event Logs

### Event ID 4648 (Logon with explicit credentials)

**Location:** Security Event Log (Event Viewer → Windows Logs → Security)

When proxy-auth requests NTLM, Windows logs:

```
Event ID: 4648
Logon Type: 9 (NewCredentials / RunAs)
Logon Process: User32
Authentication Package: Negotiate (NTLM fallback)
Caller User Name: alice
Caller Domain: CORP
Target User Name: alice
Target Domain: CORP
Target Logon GUID: {12345678-...}
Process Name: C:\Program Files\Internet Explorer\iexplore.exe (or chrome.exe, etc.)
Target Server Name: <attacker-ip> (or "wpad")
Target Server Port: 8080
```

**Forensic value:** Logs NTLM auth to unexpected server (attacker). Presence of Event 4648 with **Logon Type 9** and a non-standard server IP is a strong signal.

### Event ID 5140 (SMB Network Share Object Accessed)

**If relay succeeded and attacker accessed administrative shares:**

```
Event ID: 5140
Network Share Name: \\<attacker-or-relayed-server>\ADMIN$
Source Address: 192.168.1.100 (victim's own IP, not attacker's — relay obscures source)
Source Port: (high ephemeral port)
Share Access: WriteData/CreateFile
Accesses: Modify (0x4)
File Name: (service binary, DLL, etc.)
```

This log would appear on the **relayed target** (DC, file server), not on the victim. See the relay-attack section for details.

### Event ID 6278 (Kerberos PreAuth failure) or similar

Unlikely to trigger (mitm6 doesn't force Kerberos auth, only NTLM via proxy). However, if the target tries to auth to a non-existent domain or computer, errors may appear.

---

## Network Artifacts

### Packet Captures / tcpdump / netsh trace

If victim's network traffic is captured:

```
ICMPv6 Router Advertisement (from attacker):
  Source MAC: <attacker-mac>
  Source IP: fe80::... (attacker's link-local)
  Destination: ff02::1 (all-nodes)
  Prefix: fd00::/64
  M flag: Set (Managed, DHCPv6)
  O flag: Set (Other, DHCPv6)
  
DHCPv6 Solicit / Advertise exchange:
  Client MAC: <victim-mac>
  DHCP Solicit: "I need a DHCPv6 address"
  DHCP Advertise: "Here's fd00::1001, DNS is <attacker-ip>"
  DHCP Request: "I accept that offer"
  DHCP Reply: "Confirmed"
  
DNS Queries (to attacker's port 53):
  Query: wpad -> Response: <attacker-ip>
  Query: wpad.corp.local -> Response: <attacker-ip>
  (all subsequent queries answered with attacker's IP)
  
HTTP GET /wpad.dat (to attacker's port 80):
  GET /wpad.dat HTTP/1.1
  Host: wpad
  (Response: PAC file with PROXY <attacker>:8080)
  
HTTP Proxy-Authentication (to attacker's port 8080):
  CONNECT <any-server>:443 HTTP/1.1
  (Server responds 407 Proxy Authentication Required)
  Proxy-Authenticate: NTLM
  Proxy-Authorization: NTLM <base64-NTLM-response>
```

**Detection:** Network packet analysis should show all of the above.

---

## File System Artifacts

### Browser Cache

**Chrome:** `%APPDATA%\Local\Google\Chrome\User Data\Default\Cache\`

May contain the WPAD PAC file fetched from `http://wpad/wpad.dat`.

**Firefox:** `%APPDATA%\Roaming\Mozilla\Firefox\Profiles\*\cache2\`

May contain cached PAC or HTTP responses from attacker.

### Temporary Files

**Windows Temp:** `C:\Users\<username>\AppData\Local\Temp\`

Unlikely to contain mitm6-specific artifacts (mitm6 doesn't write to targets).

---

## Forensic Timeline (Target Perspective)

| Time | Event | Artifact |
|---|---|---|
| T0 | Victim boots or IPv6 probe fires | (No artifact yet) |
| T0+2s | Attacker's RA arrives | Packet capture shows ICMPv6 RA with M/O flags |
| T0+3s | Victim processes RA, configures IPv6 address | ipconfig shows fd00::1001 assigned |
| T0+5s | Victim's DHCPv6 client runs | DHCPv6 request packet visible in pcap |
| T0+6s | Attacker's DHCP response arrives with DNS setting | DHCPv6 Advertise packet in pcap; registry updated with attacker IP |
| T0+10s | Victim resolves wpad hostname | nslookup/DNS query packet to attacker; attacker IP in Temp DNS cache |
| T0+15s | Browser/OS fetches WPAD PAC | HTTP GET /wpad.dat packet; PAC cached locally |
| T0+20s | Browser connects to proxy:8080 | TCP connection attempt to attacker's port 8080 |
| T0+25s | Browser/app sends NTLM Negotiate to proxy | Proxy-Authorization header in HTTP request |
| T0+30s | NTLM Challenge/Response exchange | Event 4648 logged (proxy-auth attempt) |
| T0+35s | (If relay successful on target) | Relay-target's SMB 5140 / LDAP 5136 events, not victim's |

---

## Strongest Signals (Target)

1. **IPv6 address from `fd00::/64` (ULA) or unusual prefix** — Legitimate enterprise IPv6 should use organization's prefix, not ULA.
2. **DNS server pointing to unexpected IP** — Should point to organization's DNS, not random host.
3. **Proxy auto-config URL resolving to same unexpected IP** — WPAD PAC server and DNS should not both point to random host.
4. **Event 4648 (explicit credentials / proxy auth)** with **Logon Type 9** to non-standard server.
5. **RA packets from non-infrastructure MAC address** — Attacker's MAC is unusual.

**Evasion Resistance:** Medium-High. The IPv6 address assignment and DNS configuration changes are persistent (survive reboot until DHCP lease expires, typically 3600s). Event logs survive indefinitely.

---

**Next:** See `05 - Detection and Hunting.md` for detection strategies and hunting commands.
