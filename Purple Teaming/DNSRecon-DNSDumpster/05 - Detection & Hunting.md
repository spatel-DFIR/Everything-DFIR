# DNSRecon-DNSDumpster — Detection & Hunting

## Contents
- [Hunting Priority — DNSRecon vs. DNSDumpster](#hunting-priority--dnsrecon-vs-dnsdumpster)
- [Hunting DNSRecon](#hunting-dnsrecon)
- [Hunting DNSDumpster](#hunting-dnsdumpster)
- [Evasion and Resilience](#evasion-and-resilience)
- [Remediation](#remediation)

---

## Hunting Priority — DNSRecon vs. DNSDumpster

| Rank | Signal | Tool | Survives HTTPS/TLS encryption? | Survives domain obfuscation? | Reliability |
|---|---|---|---|---|---|
| 1 (Strongest) | DNS query log pattern: high volume from single source IP, many NXDOMAIN (brute-force signature) | DNSRecon | ✅ Yes (DNS runs on port 53, typically unencrypted; even with DoH/DoT, query volume pattern is visible) | ❌ No — the queried subdomains appear in plaintext in the query log | **Very high** (DNS logs are application-level, not transport-dependent) |
| 2 | Process creation log: `python.*dnsrecon` or `dnsrecon` command with target domain in CLI | DNSRecon | ✅ Yes (process logging is local, unrelated to network encryption) | ✅ Yes (command line captures domain and enum type) | **High** (Sysmon 1 / Security 4688) |
| 3 | Shell history for `dnsrecon` invocation | DNSRecon | ✅ Yes | ✅ Yes | **Medium** (operator can clear bash_history, but less common than deleting files) |
| 4 | Browser history for `dnsdumpster.com` search | DNSDumpster | ✅ Yes (browser history is local file, unrelated to network encryption) | ✅ Yes (URL search parameters include domain queried) | **Very high** (persistent, recoverable via forensic carving) |
| 5 | Outbound HTTPS connection to `dnsdumpster.com` | DNSDumpster | N/A (already TLS) | ✅ Partial (destination domain is visible; queried domain is encrypted in request body) | **Medium** (many legitimate HTTPS connections; requires filtering on `dnsdumpster.com` specifically) |
| 6 (Weakest) | Firewall/proxy log for query sent to public nameserver (8.8.8.8, 1.1.1.1) | DNSRecon | ⚠️ Partial (connection metadata is visible; query content depends on DNS privacy settings) | ✅ Partial (source IP pattern and port are visible, but query content is opaque if encrypted) | **Low** (public DNS is legitimate; high false-positive rate) |

**Build hunts on ranks 1–3 first** for DNSRecon. **Rank 4 first for DNSDumpster** (browser history is the most reliable and persistent artifact).

---

## Hunting DNSRecon

### DNS Query Log Pattern Matching

```powershell
# BIND query log (on authoritative NS or recursive resolver)
# Look for high volume from single source IP over short time window

Get-Content /var/log/named/query.log -Tail 10000 | `
  Where-Object { $_ -match '\bNXDOMAIN\b' } | `
  Group-Object { $_ -split '\s' | Select-Object -Index 1 } | `
  Where-Object { $_.Count -gt 100 } | `
  ForEach-Object { "Source IP: $($_.Name), Query count: $($_.Count)" }

# Cloudflare DNS query logs (via API)
curl -X GET https://api.cloudflare.com/client/v4/zones/{zone_id}/dns/query_logs \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" | jq '.result[] | select(.response_cached == false) | .client_ip' | sort | uniq -c | sort -rn | head -10
```

### Process Creation Logging (Sysmon 1 / Security 4688)

```powershell
# Sysmon — match on dnsrecon invocation with target domain
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} | `
  Where-Object { $_.Message -match 'dnsrecon|python.*-m.*dnsrecon|-d ' } | `
  Select-Object TimeCreated, @{n='CommandLine';e={($_.Message | Select-String -Pattern 'CommandLine:\s*(.+)').Matches.Groups[1].Value}}, `
    @{n='TargetObject';e={($_.Message | Select-String -Pattern 'TargetObject:\s*(.+)').Matches.Groups[1].Value}}

# Security Event 4688 (if enabled)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue | `
  Where-Object { $_.Message -match 'dnsrecon|-t (std|axfr|brt|ipv4range)' } | Select-Object TimeCreated, Message
```

### Shell History Hunt

```bash
# On Linux/macOS host that may have run dnsrecon
grep -E 'dnsrecon|-t (std|axfr|brt)|-d ' ~/.bash_history ~/.zsh_history ~/.history 2>/dev/null

# Check for dnsrecon output files (operator often specifies `-o` to save results)
find ~ -name "*recon*.txt" -o -name "*dns*.json" -o -name "*dns*.xml" 2>/dev/null | xargs ls -lt
```

---

## Hunting DNSDumpster

### Browser History Analysis

```powershell
# Firefox (Unix/Linux)
sqlite3 ~/.mozilla/firefox/*/places.sqlite "SELECT datetime(visit_date/1000000, 'unixepoch'), url FROM moz_historyvisits JOIN moz_places ON moz_historyvisits.place_id = moz_places.id WHERE url LIKE '%dnsdumpster%' ORDER BY visit_date DESC"

# Chrome (Windows)
$chromePath = "$env:APPDATA\Local\Google\Chrome\User Data\Default\History"
(sqlite3 $chromePath "SELECT datetime(last_visit_time/1000000 - 11644473600, 'unixepoch'), url FROM urls WHERE url LIKE '%dnsdumpster%' ORDER BY last_visit_time DESC") | Format-Table -AutoSize

# All browsers (generic approach)
Get-ChildItem "$env:APPDATA\Local\Google\Chrome\User Data\Default\", "$env:APPDATA\Local\Microsoft\Edge\User Data\Default\" -Filter History -ErrorAction SilentlyContinue | `
  ForEach-Object { sqlite3 $_.FullName "SELECT url FROM urls WHERE url LIKE '%dnsdumpster%'" }
```

### HTTP Proxy / Firewall Log Analysis

```bash
# If proxy logs HTTPS destination (URL rewriting, TLS inspection, or via SNI)
grep -i 'dnsdumpster.com' /var/log/squid/access.log /var/log/proxy.log 2>/dev/null

# Firewall: outbound HTTPS to HackerTarget's known IP ranges (104.21.0.0/16, etc.)
grep -E '104\.21\.' /var/log/firewall.log | grep 'HTTPS|443'
```

### DNS-Over-HTTPS (DoH) Detection

If the operator used a DoH client (e.g., `curl --doh-url`), standard DNS query logs won't show the query. Hunting here is network-based: HTTPS to a DoH provider's known IP + high query volume pattern. Less reliable; most operators won't use DoH for reconnaissance.

---

## Evasion and Resilience

| Evasion Technique | DNSRecon | DNSDumpster | Counter |
|---|---|---|---|
| **Clear shell history** | `history -c && history -w` (bash) / `rm ~/.zsh_history` (zsh) | Not applicable | Sysmon 1 / Security 4688 logs are not clearable by the user (centralized log ingestion required); check process logs first |
| **Rename dnsrecon binary** | `cp dnsrecon.py my_script.py` | N/A | Python interpreter still shows up in `ps` as `python`, and the module import remains visible in Sysmon 1's command line |
| **Use public DNS (8.8.8.8, 1.1.1.1)** | `dnsrecon -N 8.8.8.8 -d target.com` | N/A | Legitimate use of public DNS makes detection noisier; requires correlation with process logs to confirm DNSRecon use (not just DNS traffic) |
| **Encrypt DNS queries (DoT/DoH)** | `dnsrecon --dns-tcp` or DoH client | N/A | Query content is encrypted, but process logs and shell history remain; query volume/frequency patterns may still be visible at network layer |
| **Clear browser history** | N/A | `Ctrl+Shift+Delete` or browser settings | Browser forensics can recover deleted history via file carving (SQLite WAL files, unallocated space); Wayback Machine may cache DNSDumpster results; EDR network logs still show HTTPS to `dnsdumpster.com` |
| **Use VPN / proxy** | Outbound DNS appears to come from VPN IP, not operator's real IP | Outbound HTTPS to `dnsdumpster.com` appears to come from VPN IP | Doesn't hide the activity itself, just the source IP; if the VPN/proxy is managed by the organization, logs are still available upstream |

**Most resilient signal:** Process creation logs (Sysmon 1 / Security 4688) for DNSRecon, and browser history (especially forensic recovery) for DNSDumpster. Neither can be completely evaded without sophisticated anti-logging or trusted-mode protections.

---

## Remediation

### Capture Evidence First

1. **DNSRecon:** Collect Sysmon 1 events, Security 4688 logs (if enabled), shell history files, and any output files (`-o` targets) before isolating the host.
2. **DNSDumpster:** Export browser history databases, proxy logs, and any saved result files.

### Network-Level Controls

```powershell
# Block outbound DNS to unauthenticated recursive resolvers (force internal resolver)
# Firewall rule: block UDP/TCP 53 to non-internal IPs except approved (8.8.8.8, 1.1.1.1, ISP resolver)

# Block or monitor outbound HTTPS to dnsdumpster.com and related passive DNS sites
# Firewall rule: block HTTPS to *.dnsdumpster.com, *.hackertarget.com, etc.
```

### Host-Level Controls

```powershell
# Enable command-line auditing for process creation (captures dnsrecon invocation)
# Computer Configuration > Administrative Templates > System > Audit Process Creation > "Include command line in process creation events" = Enabled

# Deploy Sysmon with rules matching dnsrecon process creation
# Reference: https://github.com/SwiftOnSecurity/sysmon-config

# Monitor for high-volume DNS queries (brute-force pattern)
# Configure BIND / Windows DNS Server query logging (not on by default)
```

### Threat Hunting Automation

```powershell
# Weekly sweep for Sysmon 1 + dnsrecon
$results = Invoke-Command -ComputerName (Get-Content .\corp_hosts.txt) -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | `
    Where-Object { $_.Message -match 'dnsrecon|python.*-m|dnsdumpster' } | `
    Select-Object TimeCreated, PSComputerName, Message
} -ErrorAction SilentlyContinue

$results | Sort-Object TimeCreated | Export-Csv -Path dns_recon_sweep.csv -NoTypeInformation
```

### Segmentation / Access Controls

- **Restrict recursive resolver access** to internal-only (block external IPs from querying your org's DNS)
- **Monitor domain registration** for newly registered domains mimicking your real domains (anti-squatting; DNSRecon often precedes phishing campaigns that use lookalike domains)
- **DNSSEC + DANE** — if your domain supports DNSSEC validation, it adds a layer of integrity to DNS responses (not a reconnaissance blocker, but hardens the infrastructure)
