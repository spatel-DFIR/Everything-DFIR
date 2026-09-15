# DNSDumpster — Detection and Hunting

Hunting signals organized by **source host** (attacker's machine) only, since DNSDumpster leaves minimal-to-no target-side evidence. Ranked by invariant strength (which survive evasion attempts).

## Contents
- [Hunting Priority Table](#hunting-priority-table)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target (Sparse)](#hunting-on-target-sparse)

---

## Hunting Priority Table

| Rank | Signal | Evasion-Resistant | Notes |
|---|---|---|---|
| 1 | Browser history: dnsdumpster.com visits with domain names in URL | Very High | Only evasion is browser history clearing (artifact itself). Web form queries encode domain in URL. |
| 2 | Output files (.json, .xlsx) containing DNS enumeration results | High | Operator can delete/redirect to /dev/null, but results have value — operators keep files. Deletion itself is forensic (temp file recovery). |
| 3 | Shell history: curl/python API calls to api.dnsdumpster.com | High | Only evasion is history clearing. API calls to dnsdumpster.com domain are specific and identifiable. |
| 4 | API key in shell history or config file | Critical (if present) | Operator evades via env var, but env var itself appears in env dumps or memory. |
| 5 | Outbound HTTPS connections to dnsdumpster.com (network logs) | High | Operator can proxy/tunnel, but connection to dnsdumpster.com is still required. |
| 6 | Bulk script execution (callDumpster, Python automation script) | Medium | Operator can avoid scripting tools entirely, but bulk enumeration needs some process. |
| 7 | Browser cookies/cache from dnsdumpster.com | Medium | Operator can clear cache, but clearing itself is suspicious. Browser data survives unless explicitly cleaned. |
| 8 | IDS alert on dnsdumpster.com HTTPS connections | Medium | Rare (dnsdumpster.com is a legitimate service); only triggers if network has specific dnsdumpster.com signature. |

---

## Hunting on Source

### Browser History Search

**Windows (Chrome/Edge):**

```powershell
# Query Chrome history database
$ChromePath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
$Query = "SELECT url, title, visit_time FROM urls WHERE url LIKE '%dnsdumpster%' ORDER BY visit_time DESC"
$DB = New-Object System.Data.SQLite.SQLiteConnection
$DB.ConnectionString = "Data Source=$ChromePath"
$DB.Open()
$Cmd = $DB.CreateCommand()
$Cmd.CommandText = $Query
$Reader = $Cmd.ExecuteReader()
while ($Reader.Read()) {
  Write-Host "$($Reader['url']) | Title: $($Reader['title'])"
}
$DB.Close()
```

**Linux/macOS (Firefox):**

```bash
sqlite3 ~/.mozilla/firefox/*/places.sqlite "SELECT url, title, visit_date FROM moz_places WHERE url LIKE '%dnsdumpster%' ORDER BY visit_date DESC;"
```

**Expected Output:**
```
https://dnsdumpster.com/?q=example.com | DNSDumpster | 2026-08-11 10:15:23
https://dnsdumpster.com/?q=example.co.uk | DNSDumpster | 2026-08-11 10:15:47
https://api.dnsdumpster.com/domain/partner.com | ... | ...
```

**Forensic Value:** High. Browser history directly names every domain queried.

---

### Output File Search

**Locate DNS enumeration results:**

```bash
# Find JSON results
find ~ -type f -name "*dnsdumpster*.json" -o -name "*dns*.json" 2>/dev/null | head -20

# Find Excel reports
find ~ -type f -name "*.xlsx" -newer /tmp/marker 2>/dev/null | xargs file | grep "Microsoft Excel"

# Find shell-script-generated results
find ~ -type f \( -name "*recon*.json" -o -name "*enum*.json" \) 2>/dev/null
```

**Expected Output:**
```
/home/attacker/dnsdumpster_results/example_com_results.json
/home/attacker/dnsdumpster_report.xlsx
/tmp/dns_enum_results.json
```

**File Content Analysis:**

```bash
# Show structure of JSON results
jq 'keys' /home/attacker/dnsdumpster_results/example_com_results.json

# Count discovered hosts
jq '.dns_records | length' /home/attacker/dnsdumpster_results/example_com_results.json

# Extract domains queried from multiple result files
for f in /home/attacker/dnsdumpster_results/*.json; do
  jq -r '.domain' "$f"
done | sort -u
```

**Forensic Value:** High. JSON/XLSX files prove enumeration occurred and name exact targets.

---

### Shell History Analysis

**Bash/Zsh:**

```bash
grep -r "dnsdumpster\|api.dnsdumpster\|callDumpster" ~/.bash_history ~/.zsh_history 2>/dev/null

# Extract unique domains queried
grep "dnsdumpster" ~/.bash_history | grep -oP '(?<=-d\s)\S+|(?<=domain/)\S+(?=\?|$)' | sort -u
```

**Expected Output:**
```
curl "https://api.dnsdumpster.com/domain/example.com"
python callDumpster.py -k 5c8e2a7b3f9d1e4a -d example.com
python dnsdumpster_bulk.py
```

**Forensic Value:** High. Commands name domains and timestamps of queries. API keys (if exposed) identify operator's account.

---

### API Key Discovery

**In Environment Variables:**

```bash
env | grep -i dnsdumpster
printenv | grep -i "api.*key\|key.*api"
```

**In Config Files:**

```bash
find ~ -type f \( -name "*.ini" -o -name "*.conf" -o -name "*.config" \) -exec grep -l "dnsdumpster" {} \; 2>/dev/null
grep -r "DNSDUMPSTER_API_KEY\|api_key.*dnsdumpster" ~/.config ~/.bashrc ~/.zshrc 2>/dev/null
```

**In Python Scripts:**

```bash
grep -r "api.dnsdumpster.com\|DNSDUMPSTER" ~/.local/share/ ~/Documents/ ~/Desktop/ 2>/dev/null | grep -v ".pyc"
```

**Expected Output:**
```
DNSDUMPSTER_API_KEY=5c8e2a7b3f9d1e4a
api_key = "5c8e2a7b3f9d1e4a"
https://api.dnsdumpster.com/domain/example.com?api_key=5c8e2a7b3f9d1e4a
```

**Forensic Value:** Critical. API key identifies operator's HackerTarget account.

**External Cross-Reference:** Contact HackerTarget with API key; they will provide:
- Query history (domain, timestamp, source IP, query count)
- Abuse logs if account was used for scanning

---

### Browser Cache & Cookies

**Chrome/Chromium Cache:**

```bash
# List all dnsdumpster.com cached content
find ~/.config/google-chrome/Default/Cache -type f -exec strings {} \; | grep -i dnsdumpster | head -10
```

**Firefox Cookies:**

```bash
sqlite3 ~/.mozilla/firefox/*/cookies.sqlite "SELECT host, name, value FROM moz_cookies WHERE host LIKE '%dnsdumpster%';"
```

**Expected Output:**
```
Cached HTML pages from dnsdumpster.com
Session cookies for dnsdumpster.com
```

**Forensic Value:** Low to Medium. Cache/cookies confirm visits but don't necessarily contain query results (especially for dynamic API queries).

---

### Bulk Script Detection

**callDumpster Installation:**

```bash
find ~ -type d -name "callDumpster" 2>/dev/null
pip list | grep -i calldumpster
```

**Custom Python Scripts:**

```bash
find ~ -type f -name "*.py" -exec grep -l "dnsdumpster\|api.dnsdumpster.com" {} \; 2>/dev/null

# Check for recent modifications (script was recently edited)
find ~ -type f -name "*.py" -mtime -7 -exec grep -l "dnsdumpster" {} \; 2>/dev/null
```

**Forensic Value:** Medium. Script presence indicates intent to automate reconnaissance; script creation/modification timestamps add timeline detail.

---

### Process Execution (API-Driven)

**Sysmon/auditd (if API queries were CLI-based):**

```powershell
# Windows (Sysmon)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='CommandLine'] [contains(., 'curl')] or contains(., 'python')]]" | 
  Where-Object {$_.Properties[10] -match "dnsdumpster"} | 
  Select-Object TimeCreated, Properties
```

```bash
# Linux (auditd)
ausearch -c curl -k | grep dnsdumpster
ausearch -c python3 -k | grep dnsdumpster
```

**Expected Output:**
```
ProcessCreate:
  UtcTime: 2026-08-11T10:23:45
  CommandLine: curl https://api.dnsdumpster.com/domain/example.com
  Image: C:\Windows\System32\curl.exe
```

**Forensic Value:** Medium. Shows execution timing and confirms tool invocation (but less specific than shell history).

---

## Hunting on Target (Sparse)

### External Reconnaissance Indicators (Indirect)

Since DNSDumpster queries don't originate from the operator's IP, the target would only observe:

1. **HackerTarget's routine crawling** (pre-existing, not specific to the operator)
2. **The operator's network activity to dnsdumpster.com** (if traffic inspection monitors outbound HTTPS)

### Network Boundary Monitoring (If Operator on Target's Network)

**If the operator is already compromised/inside the target network:**

```
Firewall egress log: 
  Source: 192.168.1.100 (attacker's compromised host)
  Dest: dnsdumpster.com (resolved to HackerTarget IP)
  Protocol: HTTPS/443
  Timestamp: 2026-08-11 10:23:45
```

**Forensic Value:** Medium. Firewall logs show outbound connections to dnsdumpster.com, indicating reconnaissance activity occurring inside the network.

### DNS Query Logs (For dnsdumpster.com Resolution)

If the target's DNS logs are monitored:

```
2026-08-11 10:23:40 Query: dnsdumpster.com A (from 192.168.1.100)
2026-08-11 10:23:41 Query: api.dnsdumpster.com A (from 192.168.1.100)
```

**Forensic Value:** Medium. DNS logs confirm the internal host resolved dnsdumpster.com, suggesting reconnaissance from inside the network.

### Endpoint Detection (On Compromised Host Inside Network)

If EDR/endpoint-security tools monitor the compromised host:

```
Alert: outbound HTTPS connection to dnsdumpster.com
Alert: browser history shows dnsdumpster.com/?q=internal-domain.local
Alert: API call detected: curl to api.dnsdumpster.com
```

**Forensic Value:** Medium to High. EDR tools can catch the reconnaissance activity if the host is monitored.

---

### Hunting Summary for Target

**Low-Detection Scenario (Default):**
- Operator queries DNSDumpster from external network
- Target sees no evidence; only HackerTarget's routine crawling appears in logs
- **Hunting Action:** Focus on source-host indicators (browser history, output files)

**Medium-Detection Scenario (Inside Network):**
- Operator compromised a host inside the target network
- Firewall/DNS logs show dnsdumpster.com connections from internal IP
- **Hunting Action:** Correlate firewall logs with internal EDR/process logs for the endpoint

---

## Cross-Reference

For comparison to DNSRecon's target-side hunting signals, refer to `DNSRecon/05 - Detection and Hunting.md`. DNSRecon leaves **high-value DNS server logs on the target**, while DNSDumpster's passive approach leaves **minimal target-side evidence**.

**Key Difference in Hunting Approach:**
- **DNSRecon:** Hunt on target's DNS logs (easy, high confidence)
- **DNSDumpster:** Hunt on source host's browser history/output files (requires access to attacker's machine)
