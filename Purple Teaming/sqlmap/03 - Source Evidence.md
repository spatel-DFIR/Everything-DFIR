# sqlmap — Source Evidence

---

## Overview

**Source evidence** = artifacts left on the **attacking/operator's machine** after running sqlmap. These are malleable (easily hidden via custom prefix/suffix/tamper scripts), ephemeral (often deleted automatically), and only recoverable if you seize the operator's system. However, they offer timeline correlation opportunities and can fingerprint a specific operator's tactics.

---

## Session Cache Directory (`.sqlmap/`)

### Location

- **Linux/macOS:** `~/.sqlmap/` (home directory)
- **Windows:** `%LOCALAPPDATA%/sqlmap/` (e.g., `C:\Users\operator\AppData\Local\sqlmap/`)

### Structure

```
~/.sqlmap/
├── subdomain_or_ip_hash/
│   ├── target_url_hash/
│   │   ├── session.sqlite
│   │   ├── <parameter_name>.xml
│   │   ├── <parameter_name>_union.xml
│   │   ├── <parameter_name>_time.xml
│   │   ├── <parameter_name>_error.xml
│   │   ├── options.pkl (Python pickle, contains all --flags)
│   │   └── profiles/
│   │       ├── 2024-08-12_14-30-45/
│   │       │   ├── queries_output.csv
│   │       │   ├── tables_dump.csv
│   │       │   └── crawled_urls.txt
```

### Key Files

| File | Purpose | Forensic Value |
|------|---------|-----------------|
| `session.sqlite` | SQLite database of cached results (SQL injection detection data, DBMS fingerprinting, enumeration results). | **High** — contains exact payloads tested, responses received, confirmed injection methods, database contents retrieved. Tables: `scan`, `injection_point`, `payload`, `fingerprint`. Can be queried directly with sqlite3. |
| `<parameter>.xml` | Cached test results for a specific parameter (boolean-based, time-based, error-based payloads and their responses). | **High** — shows which injection techniques were attempted, which succeeded, specific payload strings, and response signatures that triggered detection. |
| `options.pkl` | Python pickle file containing all command-line flags passed to sqlmap (--tamper, --level, --risk, --dbms, --proxy, etc.). | **High** — reveals operator's exact intentions, evasion tactics, DBMS assumptions, network routing (proxy details if stored). Requires Python to unpickle. |
| `queries_output.csv` / `tables_dump.csv` | Enumeration results (if `--dump` or `--dbs` was run). | **Extreme** — direct evidence of what data the operator extracted (user hashes, credentials, sensitive DB contents). |

### Recovery

Assuming the attacker didn't run `--flush-session`, this directory persists indefinitely. On Linux/macOS, if the operator's home directory is mounted or accessible via file-system forensics, you can:

```bash
# List all cached targets
ls ~/.sqlmap/*/

# Query a session database directly
sqlite3 ~/.sqlmap/*/session.sqlite "SELECT * FROM scan LIMIT 10;"

# Unpickle the options file (Python)
python3 -c "import pickle; print(pickle.load(open('~/.sqlmap/options.pkl', 'rb')))"
```

---

## Shell History (`.bash_history`, `.zsh_history`, PowerShell)

### Linux/macOS

**Location:** `~/.bash_history`, `~/.zsh_history`, or per-shell equivalent

**What it contains:** Command-line invocations like:
```bash
python3 sqlmap.py -u "http://target.com/id=1" --dbs --batch
sqlmap.py -r burp_request.txt --dump -D webapp --tamper=space2comment
```

### Windows (PowerShell)

**Location:** `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

**What it contains:** The same sqlmap command history as any other PowerShell tool.

### Forensic Value

**High.** Shell history directly names:
- Target URLs (in-the-clear or base64-encoded if using `-r`).
- Specific parameters tested.
- DBMS assumptions (--dbms flag).
- Evasion tactics (--tamper scripts).
- Data extracted (--dump database.table).
- Timing and operator's workflow (multiple commands in sequence reveal step-by-step exploitation).

**Caveat:** Operators may clear history via `history -c` (bash) or `Remove-Item` (PowerShell) before exfil.

---

## Proxy/Burp Request Files (`-r` flag artifacts)

If the operator used `-r request.txt` to load a captured HTTP request, that file may remain on disk:

**Typical location:** Working directory, Desktop, or project folder (operator-dependent).

**Example file content:**
```http
GET /search.php?q=test HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
Cookie: PHPSESSID=abc123
Connection: close
```

### Forensic Value

**Medium.** Request files show the exact URL/endpoint tested but are usually ephemeral (deleted after use). However, if the operator stored requests in a persistent location (Burp Suite project folder, etc.), they may survive.

---

## Temporary Payload/Injection Logs

If run with high verbosity (`-v 6`), sqlmap generates detailed console output that may be captured to a log file:

```bash
python3 sqlmap.py -u "http://target.com/id=1" -v 6 2>&1 | tee sqlmap_debug.log
```

**Typical log content:**
```
[hh:mm:ss] [DEBUG] Testing GET parameter 'id'
[hh:mm:ss] [PAYLOAD] id=1 OR 1=1 -- 
[hh:mm:ss] [RESPONSE] Page status: 200, Length: 2341
[hh:mm:ss] [PAYLOAD] id=1 AND SLEEP(5)
[hh:mm:ss] [RESPONSE] Response time: 5.2 seconds — vulnerable!
```

### Forensic Value

**Very High** (if captured). Shows exact payloads, timing measurements, responses, and detection logic. Reveals operator's real-time decision-making and which injection technique succeeded.

**Caveat:** Not created by default; only if operator explicitly redirects output to a file.

---

## Configuration File (`sqlmap.conf`)

If the operator used a configuration file (`-c sqlmap.conf`), it may remain on disk:

**Example:**
```ini
[Target]
url = http://target.com/vulnerable.php?id=1
cookie = PHPSESSID=xyz

[Injection]
level = 3
risk = 2
technique = BEUST
tamper = space2comment,between

[Enumeration]
dbs = true
tables = true
dump = true
```

### Forensic Value

**Very High.** Configuration files are operator-written and reveal their exact playbook for the engagement (target selection, evasion strategy, data extraction goals).

---

## Python Tamper Scripts (if custom)

If the operator wrote custom tamper scripts (beyond the 76 built-in ones), those may be in the `sqlmap/tamper/` directory or a custom scripts folder:

**Location:** `./tamper/custom_script.py` (if running sqlmap from a working directory)

**Example custom tamper:**
```python
#!/usr/bin/env python3
import random
def tamper(payload, **kwargs):
    """Replace spaces with random Unicode zero-width characters"""
    return payload.replace(' ', f'%{random.randint(0,255):02x}')
```

### Forensic Value

**Very High.** Custom tamper scripts show operator ingenuity in evasion and may reveal specific WAF signatures they're aware of.

---

## Network Traffic (Operator-Side)

### Proxy Logs (if using --proxy)

If the operator routed sqlmap through an HTTP proxy (`--proxy=http://127.0.0.1:8080`), the proxy server's logs (Burp Suite, mitmproxy, Fiddler) capture sqlmap's HTTP requests:

**Example Burp Suite HTTP history:**
```
GET /search.php?q=1%27%20OR%20%271%27%3D%271 HTTP/1.1
GET /search.php?q=1%20AND%20SLEEP(5) HTTP/1.1
GET /search.php?q=1%20UNION%20SELECT%20user(),database()%20-- 
```

### Forensic Value

**Extreme.** Proxy logs are the closest thing to a "smoking gun" — they show exact payloads, timing, and in-order execution. If you control the proxy, you have perfect operator visibility.

**Caveat:** Only accessible if operator used a personal proxy or you control the infrastructure.

### Tor/VPN Metadata (--tor flag)

If the operator used `--tor`, outbound connections originate from a Tor exit node. Depending on network monitoring:

- **On-path monitoring (NAT, firewall):** You see outbound connections to Tor directory servers and guard nodes, but not the target (encrypted).
- **On-target monitoring (target application):** The HTTP requests appear to originate from a Tor exit IP, which is known but non-geolocatable.

---

## Operating System Process State (volatile)

If you have real-time visibility (EDR, host monitoring), you can observe:

1. **Process creation:** `python3 sqlmap.py -u http://...`
2. **Child processes:** Web browser (if Tor is configured), proxy processes, python subprocesses.
3. **Network connections (netstat):** Outbound connections to target, proxy, DNS servers.
4. **Memory (memdump):** Unencrypted payloads, responses, credential material in python process heap.

### Timeline Correlation

```
14:32:05 — sqlmap.py started (process creation)
14:32:06–14:32:45 — 40 HTTP requests to target (rapid-fire SQLi testing)
14:32:46–14:32:58 — Pause (operator reading output)
14:32:59–14:33:15 — 16 more requests (narrowing down injection technique)
14:33:16–14:35:00 — Data enumeration (--dump active, larger response payloads)
14:35:01 — Process exit
```

This timeline, combined with target-side logs, creates a precise attack narrative.

---

## Memory Forensics

If the operator's machine is captured (or you have memory-forensics capability via Velociraptor, live-response, etc.):

**Python process memory** contains:
- Unencrypted HTTP request/response bodies
- SQL payloads before URL-encoding
- Database credentials (from --dbms-cred flag)
- Session data (usernames, passwords) if enumeration was run
- sqlmap configuration and options

**Recovery tool:** Volatility framework, manual strings/grep on memory dump.

---

## Package and Installation Artifacts

### Python Package Metadata

If sqlmap was installed via pip:
```
~/.local/lib/python3.9/site-packages/sqlmap/  (Linux)
%APPDATA%/Python/site-packages/sqlmap/       (Windows)
C:\Program Files\Python39\Lib\site-packages/ (Windows system-wide)
```

Presence of sqlmap in site-packages indicates the tool was installed (not just used as a git clone).

### Git Clone Artifacts

If the operator cloned sqlmap directly:
```bash
git clone https://github.com/sqlmapproject/sqlmap.git
```

Check for `.git/` directory and logs:
```bash
git log --oneline | head -5
# Reveals exact commit checked out (helps date the activity)
```

### Forensic Value

**Low-Medium.** Installation presence isn't strong evidence (sqlmap is public), but commit metadata can narrow the timeframe.

---

## User Behavior / Opsec Indicators

### Operator Mistakes (High-Value Indicators)

1. **Unencrypted passwords in shell history:**
   ```bash
   python3 sqlmap.py ... --dbms-cred admin:SuperSecret123 ...
   # This ends up in ~/.bash_history in plaintext!
   ```

2. **Hardcoded target URLs in scripts:**
   ```bash
   cat scripts/enum_webapp.sh
   # sqlmap.py -u "http://10.10.1.50/internal" ...  # Real IP, possibly attributed to operator
   ```

3. **Proxy credentials in options.pkl:**
   The pickle file may contain proxy URLs like `http://user:pass@proxy.internal:8080`.

4. **DNS queries (if --dns-domain):**
   Operator's own DNS server queries appear in recursive resolver logs:
   ```
   query: [base64-encoded-data].attacker.com A
   ```

### Forensic Value

**Extreme.** Opsec mistakes reveal operator identity, infrastructure, and intentions.

---

## Timeline Correlation (Operator ↔ Target)

### Realistic Scenario

**Operator's machine (source evidence):**
```
14:30:00 — sqlmap.py invoked
14:30:05 — 50 SQLi payloads generated and sent (seen in shell history, proxy logs)
14:30:06–14:30:12 — Database enumeration (--dbs, --tables)
14:35:00 — Table dump (--dump, large payload traffic)
14:40:00 — Process exits
```

**Target's machine (target evidence):**
```
14:30:05 — HTTP request with payload `id=1' OR '1'='1` (web server log)
14:30:06 — SQL error: "Syntax error near 'OR'" (database log)
14:30:07 — Multiple queries from same session probing database structure (DB query log)
14:30:08 — SELECT information_schema.tables query (DB query log)
14:35:00 — SELECT * FROM users query executed (DB query log, data exfiltration begins)
14:40:00 — Session terminates abnormally (connection drop)
```

**Correlation:** Exact timestamps match. Operators often don't spoof timing or introduce delays; shell commands execute in real-time. A forensic investigator can tie source-side session cache (session.sqlite, options.pkl) to target-side database logs to build a definitive narrative.

---

## Detection (Hunting on Operator's Machine)

### Command-Line Forensics

```bash
# Linux/macOS: Search shell history for sqlmap invocations
grep -r "sqlmap" ~/.bash_history ~/.zsh_history ~/.ksh_history 2>/dev/null

# Windows: Search PowerShell history
Get-Content $PROFILE\..\PSReadLine\ConsoleHost_history.txt | Select-String "sqlmap"
```

### Session Cache Search

```bash
# Find all sqlmap sessions
find ~/.sqlmap -name "session.sqlite" 2>/dev/null | wc -l

# List all targets scanned (via directory names)
ls -la ~/.sqlmap/*/
```

### Python Pickle Inspection (Defensive Tool)

```python
import pickle
import sys

with open(sys.argv[1], 'rb') as f:
    data = pickle.load(f)
    for key, value in data.items():
        print(f"{key}: {value}")
```

Running this on `options.pkl` reveals the exact flags and configuration used.

---

## Evasion/Cleanup

**Operators aware of forensics may:**

1. **Flush sessions:**
   ```bash
   sqlmap.py -u "http://target.com/id=1" --flush-session
   ```
   This deletes the `.sqlmap/` cache entirely.

2. **Clear shell history:**
   ```bash
   history -c          # bash/zsh
   Remove-Item -Path $PROFILE\..\PSReadLine\ConsoleHost_history.txt  # PowerShell
   ```

3. **Disable history logging:**
   ```bash
   set +o history      # bash
   ```

4. **Use temporary OS shells:**
   Run sqlmap from a throwaway VM or container that's deleted after use.

5. **Memory-only execution:**
   Some frameworks (e.g., Cobalt Strike, Metasploit) can execute sqlmap in-memory via Python interpreters, leaving no disk artifacts.

---

## Key Takeaway

Source evidence is **fragile but high-value**. Operators who don't specifically flush sessions or clear history leave a detailed forensic trail that correlates perfectly with target-side database/application logs. The absence of source evidence (clean `.sqlmap/`, no shell history) is itself a signal of operational security awareness and may indicate an organized threat actor.

