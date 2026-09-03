# EyeWitness: Hands-On Use Cases

## Scenario 1: CIDR Range Reconnaissance (External)

**Objective:** Purple teamer scans organization's external IP space (10.0.0.0/16 example) to identify web-facing applications before phishing or exploitation.

```bash
# Generate list of IPs and common web ports
nmap -p 80,443,8080,8443,3000,5000 -oX scan.xml 10.0.0.0/16

# Run EyeWitness on nmap output
python3 EyeWitness.py -x scan.xml --web --disable-logging
```

**Expected Result:** HTML report with 47–200+ screenshots (depending on CIDR size), categorized by web framework (Apache, Nginx, IIS, Node.js, etc.). Attacker uses this to identify outdated or vulnerable versions (e.g., "Apache 2.2.15 EOL"), then correlates with CVE databases.

---

## Scenario 2: Subdomain Enumeration + Fingerprinting

**Objective:** OSINT-driven reconnaissance of all discovered subdomains for a target organization.

```bash
# Feed subdomain list from Subfinder or Amass
subfinder -d target.com -o subdomains.txt

# Screenshot each subdomain
python3 EyeWitness.py -f subdomains.txt --web --threads 20 --disable-logging
```

**Expected Result:** Interactive HTML report reveals: company VPN login portals, staging/dev environments (often unpatched), employee directories, cloud storage misconfigurations. Attacker prioritizes weak subdomains for initial access.

---

## Scenario 3: Internal Network Reconnaissance (Post-Compromise)

**Objective:** Compromised workstation user runs EyeWitness internally to map intranet applications and administrative interfaces.

```bash
# Port scan internal network
nmap -sV -p 80,443,8080-8090,9000-9999 192.168.1.0/24 -oX internal.xml

# Screenshot intranet applications with credentials (optional)
python3 EyeWitness.py -x internal.xml --web --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --proxy http://internal-proxy:8080
```

**Expected Result:** Identifies internal management dashboards, legacy business-critical apps (often with weak auth), employee tools (SharePoint, Jira, wiki). Facilitates lateral movement and privilege escalation vectors.

---

## Scenario 4: Credential Default Vulnerability Chaining

**Objective:** EyeWitness identifies web app version; combined with known default credentials, attacker automates compromise.

```bash
# Screenshot and log version headers
python3 EyeWitness.py -f ips.txt --web --full-page --web-timeout 5

# Manual inspection or scripted correlation: "Tomcat 8.0.x defaults to admin/admin"
# Result: Access to application server management console
```

**Expected Result:** Attacker correlates EyeWitness screenshots with known CVE/default credential databases (Shodan, Censys), then attempts lateral movement or RCE.

---

## Scenario 5: Timing & Behavioral Targeting

**Objective:** Attacker runs EyeWitness multiple times to identify when applications are updated or maintenance windows occur (UAT vs. production differentiation).

```bash
# Initial reconnaissance
python3 EyeWitness.py -f targets.txt --web --threads 30 -d report_day1/

# Follow-up after 7 days
python3 EyeWitness.py -f targets.txt --web --threads 30 -d report_day8/

# Compare HTML reports for changes (version bumps, UI changes, new subdomains)
diff report_day1/index.html report_day8/index.html
```

**Expected Result:** Attacker identifies deployment windows, test environments, or unpatched systems by comparing visual changes across scans. Informs timing of phishing campaigns or zero-day deployments.

---

## Common Command Options

| Option | Purpose | Example |
|--------|---------|---------|
| `-f <file>` | Input file (URLs/IPs, one per line) | `-f targets.txt` |
| `-x <nmap.xml>` | Input from Nmap XML output | `-x scan.xml` |
| `--web` | Assume input is web URLs | `--web` |
| `--threads <N>` | Parallel threads (default: 10) | `--threads 20` |
| `--disable-logging` | Suppress verbose output | (flag) |
| `--user-agent <UA>` | Custom User-Agent string | `--user-agent "Mozilla/5.0..."` |
| `--proxy <url>` | Route traffic through proxy | `--proxy http://proxy:8080` |
| `--web-timeout <sec>` | Page load timeout | `--web-timeout 10` |
| `-d <dir>` | Output directory | `-d reports/` |

