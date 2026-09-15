# Burp Suite — Source Evidence

All artifacts documented here reside on the **operator's own host** (attacker-controlled machine), not the target.

---

## Burp Project Files

**Location:**
- Windows: `C:\Users\<username>\Documents\`, `C:\Users\<username>\Downloads\`, or custom directory
- Linux/macOS: `~/Documents/`, `~/Downloads/`, `~/.BurpSuite/projects/` (if configured)

**Format:** `.burp` files are **SQLite 3 databases**, containing the complete request/response history, crawled site maps, scan results, and project configuration.

**File Structure (verified via SQLite schema inspection):**
```
burp_project.burp (SQLite database)
├── Metadata table
│   ├── project_version: Version of Burp used to create/last-modify the project
│   ├── project_name: User-assigned project name
│   ├── project_description: Optional project description
│
├── Requests table (raw HTTP request capture)
│   ├── request_id: Unique ID
│   ├── host: Target hostname/IP
│   ├── port: Target port
│   ├── protocol: http/https
│   ├── method: GET/POST/etc.
│   ├── url: Full URL path
│   ├── request_body: Raw HTTP body (form data, JSON, XML, etc.)
│   ├── request_headers: Raw HTTP headers
│   ├── timestamp: Date-time of request
│   ├── comment: User-added annotation (e.g., "SQLi attempt", "Credential stuffing")
│
├── Responses table (cached HTTP responses)
│   ├── response_id: Unique ID
│   ├── request_id: Link to corresponding request
│   ├── response_status: HTTP status code (200, 401, 500, etc.)
│   ├── response_body: Raw HTTP body (HTML, JSON, etc.)
│   ├── response_headers: Raw HTTP response headers
│   ├── timestamp: Date-time of response
│
├── Issues table (Scanner findings)
│   ├── issue_id: Unique ID
│   ├── issue_type: Issue classification (SQL Injection, XSS, etc.)
│   ├── severity: High/Medium/Low/Info
│   ├── confidence: Certain/Firm/Tentative
│   ├── url: Vulnerable URL
│   ├── request_index: Link to triggering request
│   ├── evidence: Description of the vulnerability
│   ├── remediation: Fix recommendation
│   ├── cwe: CWE ID (e.g., CWE-89 for SQL Injection)
│   ├── owasp: OWASP Top 10 mapping (A03, A07, etc.)
│   ├── timestamp: Date-time of discovery
│
├── Cookies table (captured cookies)
│   ├── cookie_name, cookie_value, domain, path, expires, http_only, secure, same_site
│
├── Macros table (recorded multi-step sequences)
│   ├── macro_id, macro_name, macro_description
│   ├── macro_steps: Serialized XML or binary representation of the step sequence
```

**Forensic Significance:**
- **Proof of reconnaissance:** the URLs crawled reveal the attack surface the operator discovered.
- **Proof of exploitation:** the Scanner findings table lists every vulnerability found, along with request/response pairs proving the discovery.
- **Credential leakage:** request bodies may contain passwords, API keys, CSRF tokens captured during testing.
- **Timeline reconstruction:** timestamp fields correlate operator activity with target-side event-log entries.

**Evasion Note:** A deleted `.burp` file can be recovered via file carving if the drive hasn't been securely wiped (SQLite database blocks leave recognizable magic bytes `SQLite format 3`).

---

## Burp Request History and Saved Requests

**Location (Desktop mode):**
- In-memory while Burp is running (not persisted to disk unless saved to a `.burp` project).
- If unsaved, lost on Burp exit.

**Saved Requests (manual export):**
- Right-click a request in **Proxy** → **History** → **Save item** → exports to `.txt` or `.req` file (raw HTTP format).
- Location: operator-specified (typically `~/Desktop/`, `~/Documents/`, or a working directory).

**Format of Exported `.txt` Request:**
```
GET /api/users?id=1 HTTP/1.1
Host: target.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Authorization: Bearer token_abc123def456
Accept: application/json

[body, if POST]
```

**Forensic Significance:**
- Reveals specific endpoints targeted, parameters fuzzed, and authentication methods used.
- If Intruder payloads are exported, the wordlists used become visible.

---

## Intruder Attack Results and Payload Wordlists

**Intruder Results (in-memory, unless saved manually):**
- Accessible in the **Intruder** tab during/after an attack.
- Shows every payload sent, response status, response length, and response time.
- Can be exported via **Save** → `.txt` (tabular format) or `.csv`.

**Example Intruder Export (CSV):**
```
Payload,Status,Length,Time(ms),Comments
password,401,892,120,
password1,401,892,145,
password123,200,5234,50,"SUCCESS"
admin,401,892,100,
admin123,200,5234,60,"SUCCESS"
```

**Wordlist Files (operator-provided):**
- Location: `~/wordlists/`, `/usr/share/wordlists/`, or custom directory.
- Files like `rockyou.txt` (432 MB, 14M lines), `SecLists/` (GitHub project, common passwords/usernames), or organization-specific lists.
- If found on attacker's machine, directly proves credential-stuffing intent and capability.

**Forensic Significance:**
- Wordlist names and sizes (e.g., `rockyou_top_100.txt`) indicate attack sophistication.
- Custom wordlists (e.g., `company-employee-names.txt`, `default-passwords-2024.txt`) indicate targeted preparation.

---

## Burp Configuration and Macro Files

**Global Configuration:**
- Location: `~/.BurpSuite/config.xml` (Linux/macOS) or `C:\Users\<username>\AppData\Roaming\BurpSuite\config.xml` (Windows).
- Contains: proxy port, upstream proxy settings, cookie jar, CA certificate path, extension list, macro definitions.

**Project-Specific Configuration (inside `.burp` file):**
- The `.burp` SQLite database contains a `Configuration` table with project-specific settings.

**Macro XML Files (if saved separately):**
- Location: operator-specified, often `~/.BurpSuite/macros/` or inside the `.burp` project.
- Example macro file (`authenticate_macro.xml`):
```xml
<?xml version="1.0"?>
<Macros>
  <Macro name="Authenticate">
    <Step>
      <Request method="POST" url="https://target.local/login">
        <Headers>
          <Header name="Content-Type">application/x-www-form-urlencoded</Header>
        </Headers>
        <Body>username=admin&amp;password=SecurePassword123&amp;csrf_token=${csrf_token}</Body>
      </Request>
      <SessionHandling>
        <!-- Extract SESSIONID from Set-Cookie header -->
        <VariableAssignment name="sessionid" source="response_header" header="Set-Cookie" regex="SESSIONID=([^;]+)" />
      </SessionHandling>
    </Step>
  </Macro>
</Macros>
```

**Forensic Significance:**
- Macro files reveal the multi-step attack workflow and which credentials were used.
- Session-variable definitions show what data the operator extracted from responses (e.g., session tokens, CSRF tokens).

---

## Burp Extensions and Custom Plugins

**Location:**
- Windows: `C:\Users\<username>\AppData\Roaming\BurpSuite\extensions\`
- Linux/macOS: `~/.BurpSuite/extensions/`

**File Types:**
- `.jar` files (Java/Kotlin compiled extensions)
- `.py` files (Jython-based extensions, older versions only)

**Example Extension Artifacts:**
```
~/.BurpSuite/extensions/
├── BurpCollaboratorAutomator.jar
├── CustomPayloadGenerator.jar
├── SplunkLogger.jar
└── NucleiIntegration.jar
```

**Extension Metadata (inside `.jar`):**
- Manifest file (`META-INF/MANIFEST.MF`) may contain extension author, version, description.
- Source code (if not obfuscated) reveals custom attack logic, logging, or exfiltration capabilities.

**Forensic Significance:**
- Presence of specific extensions (e.g., `SplunkLogger.jar`, `NucleiIntegration.jar`) indicates integration with external SIEM or scanning frameworks.
- Custom extensions written by the operator reveal their custom attack capabilities (e.g., a `WAFBypassExtension` indicates knowledge of WAF evasion).

---

## Proxy Listener Configuration and Certificates

**Proxy CA Certificate (self-signed):**
- Location: `~/.BurpSuite/certs/` or operator-specified.
- File: typically `burp.cer` (X.509 certificate) or `burp.pem`.
- Content: self-signed CA cert used by Burp to MITM traffic. Operator's browser trust store has imported this cert.

**Example Certificate Fingerprint (SHA-256):**
```
Issuer: PortSwigger Web Security
Subject: PortSwigger Web Security
Serial: 1234567890abcdef
Validity: Not Before: 2024-01-01, Not After: 2026-01-01
```

**Proxy Listener Log (if enabled):**
- Optional log file capturing all proxy traffic summary (not request bodies, just connection metadata).
- Location: `~/.BurpSuite/proxy.log` or operator-specified.
- Content:
```
[12:34:56] 127.0.0.1 → 8080 → GET /search HTTP/1.1 [200 OK, 2345 bytes, 123ms]
[12:34:57] 127.0.0.1 → 8080 → POST /login HTTP/1.1 [401 Unauthorized, 892 bytes, 245ms]
```

**Forensic Significance:**
- The CA certificate thumbprint/serial is unique to this Burp installation, tying the proxy to a specific operator/machine.
- Proxy logs establish a timeline of when the operator was actively testing which endpoints.

---

## Browser Profile and Installed Extensions Configuration

**Operator's Browser (if proxying through Burp):**
- **Browser proxy settings:** typically stored in the browser's own settings file (Chrome: `~/.config/google-chrome/Default/Preferences`, Firefox: `~/.mozilla/firefox/<profile>/prefs.js`).
- **Trusted CA Store:** the Burp CA certificate is installed in the browser's certificate store.
- **Browser history:** if the operator browsed through Burp's proxy, the browser history will contain URLs of target applications tested.

**Forensic Significance:**
- Browser history + Burp project timeline can correlate when the operator accessed which targets.
- If the browser's password manager is configured (e.g., browser synced to cloud account), credentials may be recoverable.

---

## Command-Line History and Shell Environment

**Bash/Zsh Shell History:**
- Location: `~/.bash_history`, `~/.zsh_history`, `~/.history`.
- Content (if operator used CLI to launch Burp):
```bash
java -jar burp.jar --project-file target_assessment.burp
burpctl scan start --url https://target.local --config-file scan_config.xml
```

**PowerShell History (Windows):**
- Location: `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`.
- Content (if used via PowerShell):
```
java -jar burp.jar --headless --batch-mode --config-file config.xml --logfile scan_output.txt
```

**Environment Variables:**
- `BURP_HOME`: Burp installation directory (if set).
- `BURP_API_TOKEN`: if using burpctl, the API token may be in `~/.bashrc` or `~/.env` (security risk).

**Forensic Significance:**
- Shell history reveals exactly how the operator invoked Burp (headless scanning, project file name, config settings).
- API tokens in shell history are credentials and signal CI/CD integration.

---

## Java Process Memory and Crash Dumps

**Running Burp Process:**
- Java process name: `java` or `Burp` (depending on launcher).
- Process ID (PID) shown in task manager or `ps aux | grep burp`.
- Memory: Burp typically uses 1–4 GB RAM (configurable via JVM heap size: `-Xmx4g`).

**Crash Dump (if Burp crashes):**
- Location: `~/.BurpSuite/logs/`, `~/BurpSuiteLogs/`, or JVM default (typically current working directory).
- File: typically `hs_err_pid<PID>.log` (hotspot error log).
- Content: JVM stack trace, memory state at crash, loaded classes (may include extension names and project file paths).

**Forensic Significance:**
- Memory dump of a running Burp process could be analyzed to extract cached request/response data, credentials, or session tokens still in RAM.
- JVM crash dumps can reveal which extensions are loaded and the project file name.

---

## Timeline Correlation with Target-Side Evidence

**Operator-Side Timeline Construction:**

| Operator-Side Artifact | Timestamp | Forensic Interpretation |
|---|---|---|
| Burp project created | 2024-06-15 10:23 | Assessment campaign started |
| First Scanner run | 2024-06-15 10:25 | Active scanning commenced |
| Intruder attack exported | 2024-06-15 11:45 | Credential stuffing campaign timestamp |
| Macro created | 2024-06-15 12:00 | Multi-step authenticated attack planned |
| `.burp` file modified (last access) | 2024-06-15 14:30 | Last engagement activity |

**Correlate with Target-Side Logs:**

- Target event log shows HTTP 4xx/5xx requests at 10:25–14:30 UTC from the attacker IP.
- Target WAF log shows `Burp/2024.x` User-Agent at 10:25–14:30 UTC.
- Target database access logs show `SELECT * FROM users` queries (SQL injection attempts) at 11:45 UTC, matching Intruder attack timestamp.

**Timeline Gap Analysis:**
- If operator-side artifacts span 06-15 10:00–14:30, but target-side logs show activity starting at 06-15 15:00 (1-hour gap), this may indicate:
  - Operator was staging/preparing locally before engaging the target.
  - Time zone mismatch between source and target clocks.
  - Operator delayed the attack after preparation (reconnaissance vs. exploitation phases).

---

## Forensic Collection Priority

**Highest Priority (preserve immediately):**
1. `.burp` project files (SQLite — database core data).
2. Macro `.xml` files (multi-step attack workflows).
3. Extension `.jar` files (custom attack logic).
4. Shell history (`~/.bash_history`, PowerShell history).

**Medium Priority:**
5. Configuration files (`config.xml`, `burpctl.auth`).
6. Browser history and CA certificate store.
7. Proxy certificates and listener logs.

**Lower Priority (lower forensic value, but useful for context):**
8. Intruder result exports (already contained in `.burp` database).
9. Wordlist files (indicates attack capability, not unique to this operator).

---

## Defense and Evasion

**Operator Evasion Tactics (observed in incidents):**
- **Project-file obfuscation:** Rename `.burp` files to `.zip` or generic filenames (SQLite header still identifiable via file carving).
- **In-memory-only operation:** Run Burp without saving project files (`--batch-mode`, no `--project-file`), discarding history on exit (CLI only, reduces forensic footprint).
- **Temporary file cleanup:** Delete shell history, `.burp` files, and extensions after engagement (`rm ~/.bash_history`, `shred -f .burp`).
- **Credentialed account usage:** Run Burp under a separate user account, delete that account after engagement (account recovery still possible on NTFS).
- **Live-USB/VM operation:** Run Burp on a disposable virtual machine or live-booted Linux, destroying the VM/USB after engagement (eliminates persistent artifacts).

**Counterintelligence:**
- **File carving:** Deleted `.burp` SQLite databases remain recoverable from unallocated sectors (use `sqlite-carver` or `scalpel` to recover).
- **Memory forensics:** If Burp process is still running or a crash dump exists, extract in-memory cached requests via Volatility or GDB.
- **Browser artifact recovery:** Browser history, cache, and cookies (often in SQLite databases themselves) survive account deletion and can be extracted via carving or shadow-copy recovery.

