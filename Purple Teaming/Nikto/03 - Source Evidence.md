# Nikto — Source Evidence

## Nikto Binary/Script and Installation

**Location on attacker's host:**
- Cloned repository: `/path/to/nikto/program/nikto.pl` (the main executable)
- Docker container: entrypoint is `perl nikto.pl` (if using Docker deployment)
- Package installation (Linux distros): `/usr/bin/nikto` or `/usr/local/bin/nikto` (symlink or wrapper script)

**Artifact value:** Nikto's presence on an attacker-controlled system is itself an indicator of reconnaissance capability. If found during forensic analysis of a compromised system (post-exploitation), its presence signals that the attacker either:
1. Brought Nikto with them (intentional toolkit)
2. Downloaded it post-breach (separate reconnaissance phase)

## Shell History and Command Artifacts

**Locations:**
- Bash: `~/.bash_history` (or `~/.zsh_history` for zsh)
- PowerShell (if WSL): `~/.local/share/powershell/history.clixml` or `~/.PSReadline/ConsoleHost_history.txt`
- Command-line argument log (if audited): see audit logs section below

**Content signature:**
```bash
# Typical Nikto invocation in shell history:
./nikto.pl -host http://target.com -output scan.html
perl nikto.pl -host https://target.com:8443 -ssl -Tuning 1,2,3
./nikto.pl -host target.com -evasion 1,2,7 -Pause 2

# Full-featured reconnaissance scan:
./nikto.pl -host http://192.168.1.50 -port 80,443,8080 -root /app/ -output results.json -Format json
```

**Evidentiary value:** High. Shell history is one of the **primary artifacts** documenting an attacker's Nikto usage. Contains:
- Target host/IP addresses (potential victim identification)
- Ports scanned (indication of reconnaissance scope)
- Evasion/tuning flags used (indication of sophistication/caution)
- Timing (when reconnaissance was performed)
- Output file paths (may lead to stored scan results)

---

## Nikto Output Files

**Default location:** wherever `-output` flag specifies (current directory by default):
- `nikto_scan_TIMESTAMP.txt` (auto-named if `-output .`)
- Specified filename if `-output /path/to/file` is given

**Artifact types:**

### Text Report (.txt)
```
Nikto v2.6.1 - http://www.cirt.net/nikto2

Target IP:          192.168.1.100
Target Hostname:    target.local
Target Port:        80
Starting:           2026-08-12 14:30:15

+ Server: Apache/2.4.41 (Ubuntu)
+ Root page / redirects to: http://target.local:80/index.html
+ Apache/2.4.41 - some vulnerabilities exist (see db_outdated)
+ Allowed HTTP Methods: GET, POST, HEAD, OPTIONS, PUT
+ PUT method allowed - could allow file upload
+ /admin/ found (Code 200)
+ /backup.zip found (Code 200) - backup file accessible
+ /config.php found (Code 200) - application config (may contain credentials)
+ /.env found (Code 200) - environment variables file
+ /wp-login.php found (Code 200) - WordPress login
+ Nikto completed at 2026-08-12 14:35:22 (327 seconds)
```

### JSON Report (.json)
```json
{
  "scaninfo": {
    "scanstart": "2026-08-12 14:30:15",
    "scanend": "2026-08-12 14:35:22",
    "niktover": "2.6.1",
    "targetip": "192.168.1.100",
    "targethostname": "target.local",
    "targetport": 80,
    "targetbanner": "Apache/2.4.41 (Ubuntu)"
  },
  "vulnerabilities": [
    {
      "id": "1",
      "method": "GET",
      "uri": "/admin/",
      "description": "/admin/ found",
      "severity": "medium",
      "msg": "Code 200"
    },
    {
      "id": "2",
      "method": "GET",
      "uri": "/.env",
      "description": "Environment variables file found",
      "severity": "high",
      "msg": "Code 200"
    }
  ]
}
```

### HTML Report (.html)
Viewable in browser; includes summary tables, vulnerability listings, and categorized findings. Human-readable format suitable for client delivery.

### CSV Report (.csv)
```
URI,Method,Description,HTTP Code,Severity
/admin/,GET,/admin/ found,200,medium
/.env,GET,Environment variables file,200,high
/backup.zip,GET,Backup file accessible,200,high
/wp-login.php,GET,WordPress login,200,info
```

**Evidentiary value:**
- **High** — Scan reports directly document target vulnerabilities/misconfigurations discovered by the attacker
- **Timeline** — scan start/end times indicate when reconnaissance occurred
- **Scope** — which targets/ports were scanned
- **Findings** — what vulnerabilities/files were discovered (may lead to follow-on exploitation)

---

## Nikto Configuration Files

**Locations:**
- User config: `~/.niktorc` (rarely used, most rely on defaults)
- Custom config via `-config /path/to/nikto.conf` (if specified)
- Bundled default: `program/nikto.conf.default` in repository

**Common customizations (if present):**
```conf
# nikto.conf snippet
PROXYIP=http://proxy.internal.company:3128
PROXYPORT=3128
RFIURL=http://internal-server.local/rfi_test.txt
LW_SSL_ENGINE=Net::SSLeay
NOLOOKUP=1
USERAGENT=Mozilla/5.0 (custom agent)
```

**Evidentiary value:** Moderate. Custom configuration reveals:
- Proxy settings (network routing preferences)
- Custom RFI test URLs (may indicate internal targets)
- SSL engine choices (security posture)
- Pre-configured options (convenience + potential operational security strategy)

---

## Nikto Database/Plugin Modifications

**Locations:**
- Custom databases: `program/udb_*` files (user-defined database files)
- Modified stock databases: changes to `program/databases/db_tests`, etc.

**Signature:** If an attacker creates custom test files (udb_custom_tests) or modifies db_tests to add/remove specific checks, this indicates:
- Targeted reconnaissance (focus on specific vulnerability types)
- Operational adjustment (custom payloads or evasion signatures)

**Evidentiary value:** Low-to-moderate. Custom databases are rare in practice; most operators use default Nikto unchanged.

---

## Process and Network Artifacts

### Process List / Process Tree
When Nikto runs, it appears in the process list as:
```
perl /path/to/nikto.pl -host http://target.com -output scan.html
```

**Processes spawned by Nikto:**
- None by default — Nikto is a single-process Perl script
- Potential child: `curl`, `wget`, or `openssl` if configured to use external SSL libraries (rare)

**Evidentiary value:** Moderate. Process tree/command-line captures show Nikto invocation with target/arguments.

### Network Connections

Nikto initiates outbound TCP connections to target web servers:

```
Local IP:Port       -> Target IP:Port (80 or 443)
192.168.1.101:51234 -> 192.168.1.100:80

Connection state: ESTABLISHED (during scan), then CLOSED
Multiple connections may be open simultaneously if Nikto uses threading (default: single-threaded, but configurable)
```

**Netstat/ss artifact:**
```bash
ss -tnpe | grep perl
ESTAB 0 0 192.168.1.101:51234 192.168.1.100:80 users:(("perl", 1234, 4))
```

**Evidentiary value:** High. Shows:
- Source IP (attacker's machine)
- Destination IP/port (target web server)
- Timing (when connections were established)
- Count (how many concurrent connections)

### Firewall/Network Logs

Firewalls and network monitoring tools log Nikto's network activity:
```
[2026-08-12 14:30:15] NEW_CONNECTION tcp 192.168.1.101 -> 192.168.1.100:80 (HTTP)
[2026-08-12 14:30:15] TRAFFIC_FLOW tcp 192.168.1.101:51234 -> 192.168.1.100:80 (HTTP)
  [packets=127, bytes=15234, duration=327s]
```

**Evidentiary value:** Very High. External network logs (ISP, upstream firewall) may provide:
- Timing of reconnaissance
- Volume of traffic to target
- Source IP geolocation (if external)

---

## Disk Artifacts from Output Saving

### Response Cache (if `-Save /path` is used)

When Nikto finds a positive match, it can optionally save the HTTP response to disk:

```bash
./nikto.pl -host http://target.com -Save /tmp/nikto_findings
```

Generates files like:
```
/tmp/nikto_findings/
├── 192.168.1.100_80_admin
├── 192.168.1.100_80_backup.zip
├── 192.168.1.100_80_config.php
├── 192.168.1.100_80_wp-login.php
└── 192.168.1.100_80_.env
```

Each file contains the raw HTTP response (headers + body) for that finding. **Highly evidentiary** — shows exactly what the attacker discovered.

**Evidentiary value:** Very High. Directly shows attacker-discovered artifacts (file contents, error messages, version strings).

---

## Memory Artifacts

### Active Scan State
While Nikto is running, memory contains:
- Target IP/hostname (in command-line args visible via `/proc/[PID]/cmdline` on Linux)
- Current scan position (which test is being executed)
- Cached HTTP responses (in Perl data structures)
- Database entries (loaded test signatures in memory)

**Artifact locations (Linux):**
- `/proc/[PID]/cmdline` — command-line arguments
- `/proc/[PID]/environ` — environment variables (less useful for Nikto)
- Memory dump via `gcore` or `memdump` tools

**Evidentiary value:** Moderate-to-High. Memory forensics can recover:
- Active targets
- Partial response data
- Configuration state

On Windows, similar artifacts exist in the process Virtual Address Space (accessible via debuggers or memory forensics tools).

---

## Correlating Source Evidence Timeline

**Typical timeline during a Nikto reconnaissance:**

1. **T-5 min:** Nikto repository/binary acquired (git clone or package installation)
2. **T-0:** Nikto executed (shell history entry, process spawn)
3. **T+0 to T+5 min:** HTTP requests generated (network logs, firewall logs)
4. **T+5 min:** Output file written (scan report .txt/.json/.html)
5. **T+5 to T+∞:** Output file remains on disk (discoverable during forensics)

**Evidentiary linkage:**
- Shell history → target IP/arguments
- Process tree → process ID, parent process (if initiated by script or C2)
- Network logs → source IP, destination, byte/packet counts, timing
- Output files → findings, timestamps, target details
- Disk artifacts → response bodies, specific URLs discovered

**Defensive value:**
If an operator attempts to cover tracks, the following artifacts survive longest and are hardest to erase:
1. Network logs (if exfiltrated outside attacker's control)
2. Web server target-side logs (covered separately in `04 - Target Evidence.md`)
3. Shell history (deleted but may be recoverable via filesystem recovery if not securely wiped)
4. Output files (deleted but recoverable via filesystem recovery if not securely wiped)

**Fastest artifact to erase (in order of attacker's typical behavior):**
1. Shell history (`history -c`, `rm ~/.bash_history`)
2. Output files (`rm scan*.html scan*.json`, etc.)
3. Process artifacts (terminate process, but process accounting logs may survive)
4. Network connection state (reboot or close connections, but firewall logs are out of attacker's control)

