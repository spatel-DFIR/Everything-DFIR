# DNSRecon — Detection and Hunting

Hunting signals organized by **source host** (attacker's machine) and **target DNS infrastructure**, ranked by invariant strength (which survive evasion attempts).

## Contents
- [Hunting Priority Table](#hunting-priority-table)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)

---

## Hunting Priority Table

| Rank | Signal | Evasion-Resistant | Notes |
|---|---|---|---|
| 1 | AXFR REFUSED response in DNS logs | Very High | Zone transfer attempts are intrinsic to the tool; operator cannot evade without abandoning the technique entirely. Any AXFR attempt is a direct recon indicator. |
| 2 | Query-type diversity burst (A+AAAA+MX+NS+TXT in <1 sec) | High | Standard enumeration queries multiple types; difficult to evade without splitting across time/source. |
| 3 | Rapid NXDOMAIN burst (>50 per minute from one source) | High | Brute-forcing generates NXDOMAIN bulk; operator cannot avoid this without slowing enumeration to unacceptable levels. |
| 4 | Shell history: CLI command line (`dnsrecon ...`) | High | Only evasion is shell history clearing, which itself is suspicious. |
| 5 | Non-existent subdomain query (random UUID suffix) | Medium | Wildcard-detection signature; operator can skip with `-t std` only (omitting wildcard test). |
| 6 | TLD expansion query pattern | Medium | Operator can skip via `-t` flag selection (use `-t std` or `-t brt` only, omit `-t tld`). |
| 7 | Output files (.txt/.xml with DNS results) | Medium | Operator can delete/redirect to stdout, but DNS recon's value is in the results — operators keep the files. |
| 8 | Shodan API key in shell history | High (if Shodan was used) | Operator evades via env var (`SHODAN_API_KEY`), but the env var itself appears in env dumps. |
| 9 | Source IP in nameserver logs | Medium | Operator could use a proxy/VPN, but this just shifts the origin IP, not eliminating the pattern. |

---

## Hunting on Source

### Shell History Search

**PowerShell (if attacker used WSL or a Windows shell):**
```powershell
Get-Content $PROFILE\..\History.txt -ErrorAction SilentlyContinue | Select-String "dnsrecon"
(Get-PSReadlineOption).HistorySavePath | ForEach-Object { Get-Content $_ | Select-String "dnsrecon" }
```

**Bash/Zsh (on Linux/macOS or Linux-on-Windows via WSL):**
```bash
grep -r "dnsrecon" ~/.bash_history ~/.zsh_history ~/.history 2>/dev/null
history | grep dnsrecon
```

**Expected Output:**
```
uv run dnsrecon -d example.com -t std -f dns.txt
uv run dnsrecon -d example.com -t brt --threads 20
uv run dnsrecon -d example.com -a -s -w --shodan-key 5c8e2a7b3f9d1e4a
```

**Forensic Value:** High. The command line names the target domain and shows enumeration methods used. If the Shodan API key is present, it identifies the attacker's Shodan account.

---

### Process Execution Search

**Windows (Sysmon / Windows Defender for Endpoint):**
```
DeviceProcessEvents | where FileName has "python" and CommandLine has "dnsrecon"
| summarize count() by CommandLine, Timestamp, InitiatingProcessName
```

**Linux (auditd):**
```bash
ausearch -c uv | grep dnsrecon
ausearch -c python3 | grep -i "dnsrecon"
```

**Expected Output:**
- Process name: `python3` or `uv`
- Command line: `dnsrecon -d example.com -t std ...`
- Parent: shell (bash, zsh, cmd.exe)
- Timestamp: when enumeration occurred

**Forensic Value:** Medium. Shows execution context and timing. Does not appear if the tool was never executed (e.g., tool was installed but not run).

---

### Output File Search

**Find all DNS enumeration output files:**

```bash
# Text output files
find ~ -type f -name "*dns*.txt" -o -name "*dnsrecon*.txt" -o -name "*enum*.txt" 2>/dev/null
find ~ -type f -name "*.txt" -newer /tmp/marker_file 2>/dev/null | xargs grep -l "SOA\|NS\|MX" 2>/dev/null

# XML output files
find ~ -type f -name "*dns*.xml" -o -name "*dnsrecon*.xml" 2>/dev/null
```

**Expected Output:**
```
/home/attacker/dns_results/example.com_std.txt
/home/attacker/dns_results/example.com_brt.txt
/tmp/shodan_enum.xml
```

**File Content Analysis:**
```bash
grep -A 5 "SOA\|NS\|Nameserver" /home/attacker/dns_results/example.com_std.txt
xmllint --format /tmp/shodan_enum.xml | head -20
```

**Forensic Value:** High. Output files prove enumeration occurred and name the exact targets and infrastructure discovered.

---

### Shodan API Key Search

**In Shell Environment (if key is stored as env var):**

```bash
env | grep SHODAN
printenv SHODAN_API_KEY
```

**In Shell History (if key was passed on CLI):**

```bash
grep -r "shodan-key\|SHODAN" ~/.bash_history ~/.zsh_history 2>/dev/null
grep -o "shodan-key [^ ]*\|SHODAN_API_KEY=[^ ]*" ~/.bash_history
```

**Expected Output:**
```
SHODAN_API_KEY=5c8e2a7b3f9d1e4a
uv run dnsrecon -d example.com --shodan-key 5c8e2a7b3f9d1e4a
```

**Forensic Value:** Critical. The API key identifies the operator's Shodan account and can be used to query Shodan's audit logs (timestamp, search queries, source IP).

**Cross-Reference:** Contact Shodan security team with the API key to retrieve historical query logs for the attacker's account.

---

### Python Module/Dependency Check

**Check for dnsrecon installation:**

```bash
# Via uv/pip
pip list | grep dnsrecon
python3 -c "import dnsrecon; print(dnsrecon.__file__)"

# Via filesystem
find ~ -type d -name "dnsrecon" 2>/dev/null
ls -la ~/.local/lib/python*/site-packages/dnsrecon* 2>/dev/null
```

**Check for Shodan client installation (if Shodan integration was used):**

```bash
pip list | grep shodan
```

**Forensic Value:** Low to Medium. Confirms the tool was installed but not when or if it was actually executed.

---

### REST API Server Detection

**If REST API mode was used:**

```bash
# Check for listening Flask server
netstat -tlnp | grep 5000
lsof -i :5000

# Check for Flask process in process list
ps aux | grep "[f]lask\|[u]v run restdnsrecon"

# Check Flask access logs (if available)
find ~ -name "*flask*.log" -o -name "*access*.log" | xargs grep -l "dnsrecon\|general_enum" 2>/dev/null
```

**Expected Output:**
```
tcp  0 0 127.0.0.1:5000  0.0.0.0:*  LISTEN  12345/python3
```

**Forensic Value:** Medium. Indicates the operator intended to use the REST API (likely for C2 integration), but provides no enumeration details.

---

## Hunting on Target

### DNS Server Query Log Analysis

**BIND (named.log):**

```bash
# Extract all queries from a specific source IP
grep "client 192.168.1.100" /var/log/named/query.log | awk '{print $NF}' | sort | uniq -c | sort -rn

# Find AXFR attempts
grep "zone transfer" /var/log/named/query.log | grep "192.168.1.100"

# Find rapid query bursts (>10 queries in 1 second)
awk '/client 192.168.1.100/ {print $1, $2, $NF}' /var/log/named/query.log | awk '{time=$1" "$2; print time}' | sort | uniq -c | awk '$1 > 10 {print $0, "BURST DETECTED"}'
```

**Expected Output:**
```
zone transfer (AXFR) from 192.168.1.100 denied
1 192.168.1.100 query example.com A
50 192.168.1.100 query *.example.com NXDOMAIN (within 1 second)
```

**Forensic Value:** High. Clearly indicates DNS enumeration activity and timing.

---

### PowerShell (Windows DNS Server):**

```powershell
# Query Windows DNS event logs for high query volume from a single IP
Get-WinEvent -LogName "DNS Server" | Where-Object {
  $_.Properties[3] -eq "192.168.1.100" -and $_.ID -eq 257
} | Group-Object {$_.TimeCreated.Second} | Where-Object {$_.Count -gt 50}

# Find AXFR attempts (Event ID 6, zone transfer errors)
Get-WinEvent -LogName "DNS Server" | Where-Object {
  $_.Properties[0] -match "AXFR" -and $_.ID -eq 6
}
```

**Forensic Value:** Medium (Windows-specific, less common target platform for DNS enumeration).

---

### NXDOMAIN Bulk Detection

**Detect rapid NXDOMAIN bursts (brute-forcing signature):**

**BIND:**
```bash
grep "NXDOMAIN\|SERVFAIL" /var/log/named/query.log | awk '{print $NF}' | grep -o "[^ ]*\.example\.com" | sort | uniq | wc -l
```

**Expected Output:**
```
487  # 487 unique non-existent subdomains queried
```

**Forensic Value:** High. >100 NXDOMAINs for a single domain in a short time is a strong indicator of brute-forcing.

---

### DNS Query Pattern Analysis

**Detect multi-type query bursts (standard enumeration):**

```bash
# Extract all query types for a single domain from a single source
grep "192.168.1.100" /var/log/named/query.log | grep "example.com" | awk '{print $NF}' | sort | uniq -c

# Look for patterns: if you see A, AAAA, MX, NS, SOA, TXT in rapid succession, it's enumeration
```

**Expected Output:**
```
 10 example.com A
  8 example.com AAAA
  5 example.com MX
  3 example.com NS
  2 example.com SOA
  1 example.com TXT
 (All within <5 seconds = enumeration signature)
```

**Forensic Value:** High. Multiple record types queried in sequence is not typical of user traffic; it's a signature of automated tools.

---

### TLD Expansion Detection

**Find sequential TLD queries for the same base domain:**

```bash
# Extract domain queries, group by base name
grep "192.168.1.100" /var/log/named/query.log | awk '{print $NF}' | sed 's/\. A\|AAAA\|MX.*//' | sort | uniq -c | grep "example"

# Expected: example.com, example.co.uk, example.de, example.org, etc. in rapid sequence
```

**Forensic Value:** Medium. TLD expansion is a clear automated-tool signature.

---

### Rate-Limiting and Blacklist Detection

**Look for sudden query volume drops (rate-limiting signature):**

```bash
# Count queries per minute from a source IP
awk '/client 192.168.1.100/ {print $1, $2}' /var/log/named/query.log | cut -d':' -f1-2 | sort | uniq -c | sort -n

# Expected: steady climb to 100+/min, then drops to 0 (blocked or rate-limited)
```

**Expected Output:**
```
 120 11:23:45 (queries)
 150 11:23:46 (queries)
  45 11:23:47 (rate-limited, partial responses)
   0 11:23:48 (blocked entirely)
```

**Forensic Value:** Medium. Sudden query drops indicate the source IP was rate-limited or blocked.

---

### External SOC / Managed DNS Services

**If the target uses Cloudflare, Akamai, or another managed DNS:**

Contact the DNS provider with the attacker's source IP and timestamp; they will provide:
- Query volume and type breakdown
- Countries/ASNs originating queries
- Whether the source was rate-limited or blocked
- Timestamp-aligned queries (may differ slightly from on-site logs due to caching)

**Forensic Value:** High. Managed DNS providers retain detailed logs and can correlate attack timing.

---

### Shodan API Activity Correlation (External)

**Contact Shodan with the API key found in source evidence:**

```
Shodan API key: 5c8e2a7b3f9d1e4a
Request: Account activity logs for searches/netblock queries matching target domain
```

Shodan will provide:
- Timestamp of each API query
- Search term (netblock, domain, IP)
- Operator's source IP at query time
- Quota used

**Forensic Value:** Critical. Shodan logs directly correlate on-host evidence to external reconnaissance activity.

---

### IDS/Network Monitoring Alerts

**Zeek / Suricata DNS signatures will alert on:**
- High query volume from single source (>100/min)
- Zone transfer attempts (AXFR)
- Random-UUID subdomain queries (wildcard test)
- Query-type diversity bursts

**Example Zeek notice:**
```
Zeek::Notice
  ts: 2026-08-11T10:23:45
  uid: DNS:abcd1234
  id.orig_h: 192.168.1.100
  id.resp_h: 93.184.216.34
  proto: udp
  note: DNS::Suspicious_Dnsrecon
  message: High-volume DNS queries detected from 192.168.1.100
  sub: 487 unique subdomains queried for example.com in 45 seconds
```

**Forensic Value:** High. IDS/network monitoring provides real-time detection.

---

### Cross-Reference to Artifact Repositories

For comprehensive DNS query logging details, refer to:
- `Windows/15 - Network Communications/DNS Forensics.md` — Windows DNS event IDs, log format, querying methodologies
- `Linux/10 - Network Services/DNS and BIND.md` — BIND logging configuration, query.log format, troubleshooting

DNSRecon generates standard DNS queries — the evidence is in the **volume, timing, and pattern**, not in tool-specific artifacts. Any DNS scanner (Nmap, Masscan, custom scripts) will leave similar evidence.
