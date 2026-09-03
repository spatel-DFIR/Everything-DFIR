# DNSRecon — Source Evidence

Artifacts left on the **attacker/source host** during DNSRecon reconnaissance. Since DNSRecon is a stateless DNS client that leaves no special services or backdoors, source evidence is dominated by **shell history and output files** rather than registry/system-level traces.

## Contents
- [Shell History & Process Execution](#shell-history--process-execution)
- [Output Files](#output-files)
- [Network Connection State](#network-connection-state)
- [Python-Level Artifacts](#python-level-artifacts)
- [Shodan Integration Traces](#shodan-integration-traces)
- [REST API Server State](#rest-api-server-state)
- [Timeline Correlation](#timeline-correlation)

---

## Shell History & Process Execution

### Bash/Zsh History

**File Path:** `~/.bash_history`, `~/.zsh_history` (or equivalent for other shells)

**Content:**
```
uv run dnsrecon -d example.com -t std -f example_dns.txt
uv run dnsrecon -d example.com -t brt --threads 20 -f example_brt.txt
uv run dnsrecon -d example.com -t all -s -w --shodan-key "xxxxxxx" -f full_enum.txt
```

Each DNSRecon command is logged as a full command line. **Shodan API keys passed on the command line are recorded verbatim in history** (unless the operator pre-clears history or uses the `SHODAN_API_KEY` environment variable instead). History file timestamps and line ordering provide chronological sequencing of DNS reconnaissance activities.

**Forensic Value:** High. The command line names the target domain, enumeration type(s), and any API keys. An analyst can reconstruct the scope, timing, and operator methodology from history alone.

### Process Tree (Sysmon / auditd / Process Explorer)

**Linux (auditd):**
```
type=EXECVE msg=audit(timestamp): argc=8 a0="uv" a1="run" a2="dnsrecon" a3="-d" a4="example.com" a5="-t" a6="std" a7="-f" a8="dns.txt"
```

**Windows (Sysmon 1 equivalent via Linux procmon):**
- Process: `python3` or `uv` (depending on how the tool is invoked)
- Command: Full CLI string including domain and flags
- Parent: shell (bash, zsh, cmd.exe)
- Child processes: None (DNSRecon does not spawn child processes — all DNS queries are from the main process)

**Forensic Value:** Medium. Reveals execution context and parent-child relationships, confirming the enumeration was intentional and not part of a different workflow.

### Environment Variables

**Potential Exposure:**
```bash
echo $SHODAN_API_KEY  # API key stored in shell environment during the session
env | grep SHODAN     # If Shodan integration was used
env | grep PROXY      # If running through a proxy
```

If Shodan integration was used and the API key was stored as an environment variable (to avoid command-line logging), the variable is accessible to any process running in the same shell session. An analyst reviewing memory or running `ps aux` might see the key in environment dumps.

**Forensic Value:** High (if Shodan integration was used). The API key is a credential and identifies the operator's Shodan account.

---

## Output Files

### Text Output Files

**Path:** Specified via `-f <file>` or stdout if `-f` omitted.

**Example Content (`example_dns.txt` from `uv run dnsrecon -d example.com -t std -f example_dns.txt`):**
```
[*] Attempting Standard Enumeration of example.com
[+] SOA: ns1.example.com
[+] NS: ns1.example.com, ns2.example.com, ns3.example.com
[+] A: 93.184.216.34
[+] AAAA: 2606:2800:220:1:248:1893:25c8:1946
[+] MX: mail1.example.com (priority 10), mail2.example.com (priority 20)
[+] TXT: "v=spf1 include:_spf.google.com ~all"
[+] Wildcard test: NXDOMAIN (no wildcard)

[*] Attempting zone transfer against ns1.example.com
[-] Zone transfer failed: REFUSED

[*] Enumeration complete.
```

**Forensic Value:** High. The output file names discovered infrastructure — every subdomain, IP, mail server, and SPF policy found. An analyst reading this file learns exactly what the attacker discovered about the target.

### XML Output Files

**Path:** Specified via `-f <file>.xml` (tool automatically chooses XML format if extension is `.xml`).

**Example Structure:**
```xml
<dnsrecon>
  <domain name="example.com">
    <record type="A" name="example.com" value="93.184.216.34" />
    <record type="AAAA" name="example.com" value="2606:2800:220:1:248:1893:25c8:1946" />
    <record type="MX" name="example.com" value="mail1.example.com" priority="10" />
    <record type="NS" name="example.com" value="ns1.example.com" />
    <record type="TXT" name="example.com" value="v=spf1 include:_spf.google.com ~all" />
  </domain>
  <zone_transfer status="failed" />
  <subdomains>
    <subdomain name="www.example.com" ip="93.184.216.35" />
    <subdomain name="mail.example.com" ip="93.184.216.36" />
  </subdomains>
</dnsrecon>
```

**Forensic Value:** High. XML structure is machine-parseable, often easier for an analyst to ingest into threat intelligence platforms or correlation systems than text format.

---

## Network Connection State

### Outbound DNS Queries (netstat / lsof)

**Netstat View (during active enumeration):**
```
UDP  127.0.0.1:54321  -->  8.8.8.8:53        (to public resolver)
UDP  127.0.0.1:54322  -->  ns1.example.com:53 (to authoritative NS)
UDP  127.0.0.1:54323  -->  ns2.example.com:53 (to authoritative NS)
```

**Forensic Value:** Low (during operation) to Medium (post-operation). Live netstat shows active DNS queries; post-operation, the attacker's source host retains no DNS session state (UDP is stateless, no connections retained).

### DNS Query Logs (systemd-resolved, dnsmasq, bind logs)

If the source host is running a local DNS cache or resolver (systemd-resolved, dnsmasq, etc.), query logs may capture the target domains being enumerated.

**Example (systemd-resolved query log, if enabled):**
```
example.com A 192.168.1.100
ns1.example.com A 192.168.1.100
api.example.com NXDOMAIN 192.168.1.100
mail.example.com A 192.168.1.100
```

**Forensic Value:** Medium. Reveals the exact domains queried; useful for timeline correlation if the source host's resolver logs are available.

---

## Python-Level Artifacts

### Python Site-Packages Cache

**Path:** `~/.local/share/uv/cache/` (for `uv` package manager) or `~/.cache/pip/` (for pip)

DNSRecon dependencies (like the Shodan Python client) are cached after first install. The cache directory contains:
- Downloaded wheels (`.whl` files) for `dnsrecon` and all its dependencies
- Version information and checksums

**Forensic Value:** Low. Confirms the tool was installed but does not reveal enumeration details.

### Python Bytecode Cache

**Path:** `~/.cache/dnsrecon/__pycache__/` (if caching is enabled)

Compiled Python bytecode (`.pyc` files) for the DNSRecon module. Useful for timeline analysis (modification time indicates when the tool was last run).

**Forensic Value:** Very Low. Bytecode is not human-readable and does not contain enumeration results.

---

## Shodan Integration Traces

### API Key Exposure

**High-Risk Artifact:** If the API key was passed on the command line (rather than via environment variable or a config file), it appears in:
- Shell history (`.bash_history`, `.zsh_history`)
- Sysmon/auditd process-creation logs
- Any security logging capturing command-line arguments

**API Key in Environment:**
```bash
export SHODAN_API_KEY="5c8e2a7b3f9d1e4a"
env | grep SHODAN
```

If the key is stored as an environment variable, it persists for the shell session and can be dumped via memory forensics or process-environment reads.

**Forensic Value:** Critical. The Shodan API key identifies the operator and can be used to query Shodan's abuse logs for historical searches and API activity.

### Shodan Query Logs (External)

**Location:** `api.shodan.io` server logs (not on the attacker's host)

Every Shodan query made via DNSRecon is logged on Shodan's own infrastructure. Shodan records:
- The API key used
- The search query (netblock, domain, etc.)
- Timestamp
- Attacker IP (if traceable)

**Forensic Value:** Critical (but not on the source host). The target organization may request Shodan logs from the attacker's IP during an investigation. This is an **external artifact** but worth noting here as it correlates to on-host Shodan API key usage.

---

## REST API Server State

If the operator launched `uv run restdnsrecon`, the following artifacts appear:

### Flask Process

**Running Process:**
```
python3 -m flask run --host 127.0.0.1 --port 5000
```

Visible in process trees (ps, Sysmon 1) while the server is active. Stops cleanly when killed (no persistence).

**Forensic Value:** Medium. Reveals the intent to use the REST API mode, likely for C2 integration or to avoid CLI logging.

### Network Listener

**Netstat View:**
```
TCP  127.0.0.1:5000  LISTEN  (Python/Flask process)
```

The server listens on `127.0.0.1:5000` only (localhost), so remote access is not possible by default.

**Forensic Value:** Low to Medium. Confirms a listening service; does not reveal enumeration data.

### HTTP Request Logs (Flask access logs)

**Location:** `~/.local/share/dnsrecon/flask_access.log` or stdout (if not redirected)

**Example Entry:**
```
127.0.0.1 - - [11/Aug/2026 14:23:45] "GET /general_enum?domain=example.com&do_spf=true&do_whois=true HTTP/1.1" 200 -
```

If a C2 agent queries the REST API, the Flask logs capture the request (domain, parameters, timestamp, response status).

**Forensic Value:** High. Reveals which domains were enumerated via the API and the timestamp of each query.

---

## Timeline Correlation

**Key Artifacts for Timeline Building:**

1. **Timestamp of tool installation** → First `uv sync` or `pip install dnsrecon`
2. **Shell history entries** → Exact commands run, domains targeted, timing
3. **Output file modification time** → When enumeration completed
4. **Process creation logs** (Sysmon 1, auditd) → Process parent-child chains, CLI arguments
5. **Network connection state** → Active DNS queries during operation (live forensics only)
6. **API key usage** (Shodan) → External logs correlate to on-host history

**Example Timeline:**
```
2026-08-11 10:23:15  - Shell history: "uv run dnsrecon -d example.com -t std"
2026-08-11 10:23:18  - example_dns.txt created (3 seconds of DNS queries)
2026-08-11 10:24:00  - Shell history: "uv run dnsrecon -d example.com -t brt --threads 20"
2026-08-11 10:28:45  - example_brt.txt created (4 minutes 45 seconds of subdomain brute-forcing)
2026-08-11 10:30:12  - Shodan API query logs (external): 2 netblock searches at 10:30:10–10:30:12
2026-08-11 10:30:20  - Shell history: "uv run dnsrecon -d example.com -t all -s -w --shodan-key ..."
```

This timeline shows a progression from passive enumeration → active brute-forcing → Shodan enrichment, painting a clear picture of the attacker's reconnaissance workflow.
