# EyeWitness: Source Evidence

## Artifacts Left on Attacker's System

When EyeWitness is executed, the following artifacts are created on the operator's machine. These are critical for DFIR investigations of compromised workstations used for reconnaissance.

---

## Directory Structure

```
./EyeWitness-Results-[TIMESTAMP]/
├── index.html                  # Main interactive report
├── source/                     # Page source code copies (optional, --full-page)
│   ├── 192.168.1.1_80.html
│   ├── 192.168.1.2_443.html
│   └── ...
├── screenshots/                # PNG screenshots of each URL
│   ├── 192.168.1.1_80.png
│   ├── 192.168.1.2_443.png
│   └── ...
├── report.csv                  # Tabular summary (IP, port, title, response code)
├── log.txt                     # Execution log (targets, errors, timing)
└── [optional] credentials.txt  # If --user/--password flags used
```

---

## Key Artifacts

### 1. Index.html (Primary Report)

**Content:**
- Interactive dashboard with sortable/filterable web application metadata
- Embedded PNG screenshots (base64-encoded or linked)
- HTTP response codes, page titles, server version headers
- Clickable elements linking to full-page source
- Timestamp of when report was generated

**Forensic Significance:**
- Timeline of reconnaissance: report metadata shows when scan was run
- Favicon hashing allows identification of specific application versions
- JavaScript and CSS references reveal target environment technologies
- Cookie/session data sometimes captured in screenshots

**Typical Size:** 2–50 MB (depending on number of targets and embedded images)

---

### 2. Screenshots Directory (PNG Files)

**Content:**
- Full-page or viewport screenshots of each discovered web application
- Includes rendered content (images, forms, UI elements)
- Filename pattern: `<IP>_<PORT>.png` or `<DOMAIN>_<PORT>.png`

**Forensic Significance:**
- Timestamp metadata (EXIF, file system) confirms when reconnaissance occurred
- Visual artifacts may reveal usernames, employee names, or internal IP addresses visible in UI
- Screenshot series shows attacker's targeting priorities (what they photographed)
- Metadata can be stripped or spoofed; examine file creation time vs. filesystem timestamp

**Typical Size:** 50–500 KB per screenshot

---

### 3. report.csv

**Content:**
```
IP,Port,Protocol,Title,Server,Response Code,Redirect,StatusReason
192.168.1.1,80,http,Welcome to IIS,IIS/10.0,200,None,200 OK
192.168.1.1,443,https,Admin Panel,Apache/2.4.41,200,None,200 OK
192.168.1.2,8080,http,Tomcat Server,Apache Tomcat/8.5.23,200,None,200 OK
```

**Forensic Significance:**
- Parsing CSV reveals: targeted IPs, ports scanned, and application versions
- Server header field matches T1592.003 passive fingerprinting technique
- Redirect entries show internal application architecture (proxy chains, load balancers)
- Absence of entries for known ports (e.g., 443 missing on IP) suggests filtering/WAF

---

### 4. log.txt (Execution Log)

**Sample Content:**
```
[*] Starting EyeWitness reconnaissance
[*] Threads: 20
[*] Timeout: 10 seconds
[*] Starting scan: 192.168.0.0/22 (1024 hosts)
[+] Successfully captured: 192.168.1.1:80 (title: "Welcome")
[+] Successfully captured: 192.168.1.1:443 (title: "Secure Area")
[-] Error on 192.168.1.5:22 (not HTTP/HTTPS)
[*] Scan completed in 127 seconds
[*] Screenshots: 432, Failed: 18, Timeouts: 3
```

**Forensic Significance:**
- Execution timeline (start/end timestamps)
- Successful vs. failed targets reveal network accessibility and firewall rules
- Timeout patterns indicate large network scans (adversary probing large ranges)
- Thread count reveals parallelization strategy

---

### 5. Source Code Copies (Optional)

**Content:** Full HTML source of each target application (if `--full-page` flag used)

**Forensic Significance:**
- Reveals what attacker captured during reconnaissance
- Source comments may expose internal paths, API endpoints, or development notes
- Meta tags contain author information, generator software
- Collected during open-source intelligence (OSINT) phase

**File Naming:** `<IP>_<PORT>.html` or similar; typically 10–500 KB per file

---

### 6. Browser Cache & Temporary Files

**Location:** OS-dependent temp directory (Windows: `%TEMP%`, Linux: `/tmp`)

**Content:**
- Temporary screenshots before consolidation into report
- Cached downloaded assets (favicons, CSS, JavaScript)
- Browser profile data (cookies, session storage if captured)

**Forensic Significance:**
- Browser artifacts show which URLs were accessed and in what order
- Cache timestamps may precede report generation (attacker ran local browser for screenshots)
- Temporary files often deleted by attacker cleanup, but recovery via unallocated space analysis is possible

---

## Analyst Detection Checklist

| Artifact | What to Look For | Forensic Value |
|----------|------------------|-----------------|
| **index.html timestamp** | Creation time vs. file system time (metadata mismatch suggests spoofing) | High |
| **Screenshot PNG EXIF** | Embedded timestamps, camera model (if any) | Medium |
| **report.csv** | Targeting patterns (which ports/services prioritized) | High |
| **log.txt existence** | Presence indicates EyeWitness was run locally (not remote) | High |
| **Source HTML** | Passive fingerprinting data (versions, technologies) | Medium |
| **Directory size** | Large report directory (>100 MB) suggests large-scale network scan | Medium |
| **File access times** | Sequential access patterns (parallel processing threads) | Medium |

---

## Persistence Indicators

- **Attacker Retention:** Large report directories (10+ GB) stored in `/tmp` or user profile; rarely cleaned
- **Automated Runs:** Cron jobs or scheduled tasks running EyeWitness repeatedly (detected via `crontab` or Task Scheduler)
- **Integration with Other Tools:** CSV reports imported into spreadsheets, databases, or passed to exploit frameworks (check recent files, clipboard history)

