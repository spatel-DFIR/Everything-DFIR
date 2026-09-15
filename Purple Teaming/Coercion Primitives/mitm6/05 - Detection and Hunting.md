# mitm6 — Detection and Hunting

---

## Hunting on Source (Attacker Host)

### Hunt 1: Process execution — mitm6 binary

```bash
# Look for mitm6 process or Python running with mitm6 arguments
ps aux | grep -i mitm6

# Output (if active):
# root      12345  0.5  0.8 524288 16384 ?  S  10:23  0:45 /usr/bin/python3 /usr/local/bin/mitm6 -i eth0 --relay 127.0.0.1:6666 -vv
```

**Scope:** Check all running processes; if mitm6 was run and terminated, will not appear.

### Hunt 2: Listening ports — network sockets

```bash
# Look for unusual listening ports (53, 80, 546, 8080 simultaneously)
ss -tulnp | grep -E ':(53|80|546|8080)'

# Or netstat (older systems):
netstat -tulnp | grep -E ':(53|80|546|8080)'

# Expected output (if active):
# tcp     0   0  0.0.0.0:53    0.0.0.0:*  LISTEN  12345/python3
# tcp     0   0  0.0.0.0:80    0.0.0.0:*  LISTEN  12345/python3
# tcp     0   0  0.0.0.0:546   0.0.0.0:*  LISTEN  12345/python3
# tcp     0   0  0.0.0.0:8080  0.0.0.0:*  LISTEN  12345/python3
```

**Scope:** Post-incident (process terminated), ports will not be listening. If running as background service, ports will persist.

### Hunt 3: Log files — mitm6.log and derivatives

```bash
# Search for mitm6 log files in common locations
find / -name "mitm6*.log" -o -name "*dhcp*.log" 2>/dev/null

# Or grep recent shell history
grep -i mitm6 ~/.bash_history ~/.zsh_history /root/.bash_history 2>/dev/null

# Output (if found):
# /tmp/mitm6.log
# /home/attacker/mitm6_hashes.log
# (in history) sudo mitm6 -i eth0 --relay 127.0.0.1:6666
```

**Scope:** May not be deleted (log files in /tmp or /var may persist). Check attacker's working directory.

### Hunt 4: Attacker's ntlmrelayx connection

```bash
# Look for ntlmrelayx running (relay partner)
ps aux | grep -i "ntlmrelayx"

# Check listening relay socket (localhost:6666)
ss -tnp | grep 6666

# Expected (if relay active):
# LISTEN  127.0.0.1:6666  users:(("python3",pid=...))
```

**Scope:** If ntlmrelayx is running, it's evidence of active relay infrastructure.

---

## Hunting on Target (Victim Host)

### Hunt 1: IPv6 configuration — unexpected prefix

```powershell
# PowerShell (Windows)
Get-NetIPAddress -AddressFamily IPv6 | Select-Object IPAddress, PrefixLength, InterfaceAlias

# Output (suspicious):
# IPAddress          PrefixLength InterfaceAlias
# ─────────────────  ──────────── ───────────────
# fd00::1001         64           Ethernet
# fe80::1234:5678... 10           Ethernet
```

**Red flags:**
- IPv6 address from `fd00::/64` (ULA) when organization uses different prefix.
- Multiple IPv6 addresses with different prefixes (uncommon).
- Address recently assigned (check lease times).

### Hunt 2: DNS server configuration — unexpected IP

```powershell
# PowerShell (Windows)
Get-DnsClientServerAddress -AddressFamily IPv6 | Select-Object InterfaceAlias, ServerAddresses

# Output (suspicious):
# InterfaceAlias ServerAddresses
# ───────────────── ──────────────
# Ethernet          {<unexpected-ip>, fd00::1}
```

```bash
# Linux/macOS
cat /etc/resolv.conf | grep nameserver
# or
scutil --dns  (macOS)
```

**Red flags:**
- DNS server IP not in organization's known range.
- DNS points to a host on the local segment (especially on `fd00::/64`).
- Multiple DNS servers, one of which is unknown.

### Hunt 3: Proxy auto-config (WPAD)

```powershell
# PowerShell (Windows)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\*" -Name "NameServer" 2>/dev/null

# Or for user-level proxy config:
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoConfigURL"

# Output (suspicious):
# AutoConfigURL : http://wpad/wpad.dat
# NameServer    : <unexpected-ip>
```

**Red flags:**
- AutoConfigURL set to http://wpad (auto-discovery enabled).
- WPAD resolves to unexpected IP (via nslookup/ping).
- Both WPAD server and DNS point to same unexpected IP.

### Hunt 4: Event log — proxy authentication (4648)

```powershell
# PowerShell (Windows)
Get-EventLog -LogName Security -EventID 4648 -After (Get-Date).AddHours(-24) | 
  Where-Object { $_.Message -match "proxy|wpad|port 8080" } | 
  Format-Table TimeGenerated, Message -AutoSize

# Or with FilterHashtable (newer):
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=4648
  StartTime=(Get-Date).AddHours(-24)
} | Select-Object TimeGenerated, Message
```

**Red flags:**
- Event 4648 (explicit credentials) with **Logon Type 9** (NewCredentials).
- Target server is not a recognized domain server (check against known DCs/servers).
- Process name is browser (iexplore.exe, chrome.exe, firefox.exe) or system process.

### Hunt 5: Browser cache / WPAD PAC file

```powershell
# Look for cached WPAD PAC file
Get-ChildItem -Path "$env:APPDATA\Local\Google\Chrome\User Data\Default\Cache\" -Recurse | 
  Select-String "wpad.dat" 2>/dev/null

# Or Firefox:
Get-ChildItem -Path "$env:APPDATA\Roaming\Mozilla\Firefox\Profiles\*\cache2\" -Recurse | 
  Select-String "FindProxyForURL" 2>/dev/null
```

**Red flags:**
- PAC file exists with proxy pointing to unexpected IP.
- PAC file timestamp recent (within incident window).

### Hunt 6: Network packet analysis (tcpdump / Wireshark)

```bash
# Capture ICMPv6 RA with M/O flags (attacker's RA)
sudo tcpdump -i eth0 "icmp6 and ip6[40:1] == 134" -vvv

# Capture DHCPv6 traffic
sudo tcpdump -i eth0 "udp port 546" -vvv

# Capture DNS queries to unexpected server
sudo tcpdump -i eth0 "dns and dst <unexpected-ip>" -vvv

# Capture HTTP to port 8080 (proxy)
sudo tcpdump -i eth0 "tcp port 8080" -vvv
```

**In Wireshark (GUI):**
- Filter: `icmpv6.type == 134 && ipv6.dst == ff02::1`
- Look for RA packets with Managed (M) flag set.
- Look for DHCPv6 Advertise packets with non-standard IPv6 prefix.

**Red flags:**
- RA packets from non-infrastructure MAC address.
- DHCPv6 offers with `fd00::/64` prefix.
- DNS responses to `wpad` from unexpected IP.
- Proxy-Authenticate NTLM challenges (HTTP Proxy-Authorization header).

---

## Hunting on Domain Controller / Relay Target

### Hunt 1: SMB relay to administrative shares

```powershell
# Look for Event 5140 (SMB object accessed) on ADMIN$ / C$
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=5140
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object { $_.Message -match "ADMIN\$|C\$" } | 
  Select-Object TimeGenerated, Message

# Check for suspicious source IPs (not domain users)
Get-EventLog -LogName Security -EventID 5140 -After (Get-Date).AddHours(-24) | 
  Where-Object { $_.Message -notmatch "192\.168\.1\.[1-9]|10\.0\.0" }
```

**Red flags:**
- Event 5140 on ADMIN$ / C$ from unexpected source IP.
- Access from system (LocalSystem) or unusual user during odd hours.

### Hunt 2: LDAP directory service changes (5136)

```powershell
# Look for Event 5136 (Directory Service Changes) on sensitive attributes
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=5136
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object { $_.Message -match "dSHeuristics|msDS-AllowedToDelegateTo|nTSecurityDescriptor" } | 
  Select-Object TimeGenerated, Message

# Check for attacker-to-admin privilege escalation
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=4735  # Security-enabled global group modified
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object { $_.Message -match "Domain Admins" }
```

**Red flags:**
- Event 5136 on sensitive attributes (ACLs, group memberships).
- New user added to Domain Admins / Enterprise Admins.
- ACL grants WriteProperty to unexpected user (attacker).

### Hunt 3: Kerberos golden ticket forgery (secondary indicator)

If relay used Kerberos (less common with mitm6, but possible):

```powershell
# Look for Event 4768 (Kerberos TGT issued) with unusual attributes
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=4768
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object { $_.Message -match "krbtgt|Trust" }
```

**Red flags:**
- TGT issued for krbtgt account (implies DCSync or golden ticket).
- TGT issued from non-standard Kerberos client (attacker's host).

---

## Evasion Resistance Ranking

| Signal | Evasion Difficulty | Notes |
|---|---|---|
| **ICMPv6 RA with M/O flags** | Very High | Network-layer, observable in pcap; can only be defeated by RA-guard (rare) |
| **IPv6 address from ULA prefix** | Very High | Persists in configuration until DHCP lease expires (~3600s); survives reboot within lease window |
| **DNS server pointing to attacker IP** | Very High | Persists in registry; requires system admin to manually change; survives reboot |
| **DHCPv6 Advertise packet** | Very High | Observable in pcap; requires DHCPv6-Guard to prevent (rare) |
| **Event 4648 (proxy auth, Logon Type 9)** | High | Logged indefinitely; can be deleted only by admin with "Clear event log" privilege; may be backed up |
| **Mitm6 process / listening ports** | Low | Only present if process running; deleted once terminated |
| **mitm6.log / shell history** | Low | Can be deleted if attacker has file system access; may be overwritten |
| **Browser cache (WPAD PAC)** | Medium | Survives even if process terminated; persists across reboots until cache purge (~30 days) |
| **Packet captures** | High | If captured during incident, fully observable; if no capture, no evidence |

**Most evasion-proof signal:** IPv6 address configuration + DNS server setting + Event 4648 combo is nearly impossible to hide without full system reset or DHCP lease expiration.

---

## Detection Rules (Pseudocode)

### Sigma Rule: ICMPv6 RA Spoofing (Network)

```yaml
title: Potential mitm6 IPv6 Router Advertisement Spoofing
logsource:
  product: zeek
  service: dhcpv6
detection:
  icmpv6_ra:
    event_type: icmpv6
    icmpv6_type: 134  # Router Advertisement
    flags: M|O        # Managed or Other flag set
  filter_internal:
    src_mac: NOT (known_router_macs)
  condition: icmpv6_ra and NOT filter_internal
falsepositives:
  - Legitimate IPv6 router on segment (rare)
action: alert
```

### Windows Event Log Correlation Rule

```powershell
# Correlate Event 4648 (proxy auth) + recent IPv6 config change
$events = Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=4648
  StartTime=(Get-Date).AddHours(-1)
}
$suspiciousEvents = $events | Where-Object {
  $_.Message -match "port 8080" -and 
  $_.Properties[5] -notmatch "known_servers"
}
if ($suspiciousEvents) {
  Write-Host "Potential WPAD/mitm6 attack detected"
}
```

### DNS Query Anomaly (unusual resolver)

```bash
# Look for DNS queries going to non-standard server
# This can be detected via Sysmon Event 22 (DNS query) + unexpected ServerIP
```

---

## Remediation

1. **Immediate:** Disable IPv6 on affected systems (not scalable, but short-term).
   ```powershell
   netsh int ipv6 set state disabled
   ipconfig /release6  # Release DHCPv6 lease
   ```

2. **Network-level:** Enable RA-guard and DHCPv6-Guard on switches (if available).

3. **DC-level:** Require SMB signing and LDAP signing (defeats relay attacks).
   ```powershell
   Set-SMBServerConfiguration -RequireSecuritySignature $true
   ```

4. **Detection:** Monitor for RA packets from non-infrastructure sources (Zeek/Suricata rules).

5. **Reset:** Full password reset for compromised accounts; revoke any granted privileges.

---

**Next:** See `00 - Coercion Primitives Overview.md` for comparison with Coercer, PetitPotam, PrinterBug.
