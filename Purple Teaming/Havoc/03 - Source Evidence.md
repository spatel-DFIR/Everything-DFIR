# Havoc C2 — Source Evidence

Artifacts left on the **operator's/attacker's machine** (Team Server host, operator workstation, or relay infrastructure). Unlike target-side evidence, source-side artifacts are recoverable only if the operator's own infrastructure is seized or logs from an egress-monitoring device (proxy, firewall) are captured.

---

## Team Server Host Artifacts

### YAOTL Profile File

**Location:** Anywhere on disk; typically `/home/<user>/Havoc/profiles/havoc.yaotl` or in Docker container at `/data/profiles/<name>.yaotl`

**Evidence value:** **CRITICAL** — the profile file defines the entire C2 network behavior (listener ports, HTTP templates, user-agent strings, URI paths, response formats, operator credentials, sleep obfuscation strategy). If seized, the profile directly reveals:
- Embedded operator usernames/passwords (plaintext)
- Listener configuration (ports, TLS cert paths, Let's Encrypt domains)
- Demon defaults (sleep interval, jitter %, process-injection targets)
- Custom traffic encoders
- External C2 endpoint (if configured)

**Example recovered profile reveals:**
```yaml
Operators {
    user "attacker" {
        Password = "SuperSecure123!"  ← PLAINTEXT PASSWORD
    }
}

Listeners "api-mimic" {
    Port = 8080
    UserAgent = "Mozilla/5.0 ..."
    uripath = "/api/inventory", "/api/status"
}

Demon {
    Sleep = 2
    Jitter = 15
    Obfuscation = "ekko"  ← Evasion method
    Injection {
        Spawn64 = "C:\\Windows\\System32\\svchost.exe"
    }
}
```

**Forensic recovery:** Profile file itself is plaintext; grep for "Operators", "Listeners", "Demon" blocks. Deleted profiles may be recoverable from filesystem slack/unallocated space or shadow copies if Team Server is hosted on Windows.

---

### Team Server SQLite Database

**Location:** Typically `/home/<user>/Havoc/data/havoc.db` or `/data/havoc.db` (Docker)

**Evidence value:** **CRITICAL** — contains all operational state:
- **Sessions table:** every agent callback, hostname, username, process info, session tokens
- **Tasks table:** every command queued and executed (execute-assembly, shell commands, token operations, etc.)
- **Results table:** output from every task (file listings, registry dumps, process enumeration, credential harvests)
- **Operators table:** operator accounts and authentication tokens
- **Listeners table:** listener job history (which ports opened, when, for how long)

**Database schema (inferred from Havoc source):**
```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    username TEXT,
    process_id INTEGER,
    architecture TEXT,
    integrity TEXT,
    os TEXT,
    timestamp DATETIME
);

CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    command TEXT,
    arguments TEXT,
    queued_time DATETIME,
    executed_time DATETIME
);

CREATE TABLE results (
    id TEXT PRIMARY KEY,
    task_id TEXT,
    output BLOB,
    timestamp DATETIME
);

CREATE TABLE listeners (
    id TEXT PRIMARY KEY,
    type TEXT,  -- 'HTTP', 'HTTPS', 'SMB', etc.
    port INTEGER,
    started_time DATETIME,
    stopped_time DATETIME
);
```

**Forensic recovery:** SQLite database file persists on disk. If deleted, recovery may be possible from unallocated clusters. Live database queries (if Team Server still running) reveal active sessions; historical queries reveal past campaigns.

**Timeline correlation:** Database timestamps can be correlated with target-side Windows event logs (4688 process creation, network logs) to tie operator actions to target-side effects.

---

### Team Server Process Memory and Logs

**Location:** `/var/log/havoc/` or operator-specified logging directory; in-memory logs if verbose mode enabled

**Evidence value:** MEDIUM — contains:
- Verbose startup messages: listener port assignments, profile parsing, compiler configuration
- Incoming operator connections (IP, username, authentication success/failure)
- Agent callback receipts (session IDs, hostnames, check-in times)
- Command queueing logs
- Error messages (e.g., failed payload compilation, listener startup failures)

**Example log output:**
```
[2025-12-18 14:23:15] Havoc Team Server starting
[2025-12-18 14:23:16] Profile loaded: /data/profiles/havoc.yaotl
[2025-12-18 14:23:17] Listeners configured: HTTP:8080, HTTPS:443
[2025-12-18 14:23:18] Operator 'attacker' connected from 192.168.1.50:51234 (authenticated)
[2025-12-18 14:23:45] New agent callback: demon-2d9f1a42 (CORP-WKS-001\analyst, PID 4024)
[2025-12-18 14:24:12] Task queued: execute-assembly SharpUp.exe
[2025-12-18 14:24:45] Task result received: demon-2d9f1a42
```

**Forensic recovery:** Logs are plaintext; grep for "callback", "authenticated", "connected", "task". Memory dumps from running Team Server process may contain plaintext operator passwords, agent session tokens, and partial task output.

---

## Operator Workstation Artifacts

### Havoc Client Configuration and Credentials

**Location:** `~/.havoc/config.json` or per-profile `alice.cfg`, `bob.cfg`, etc. (as created by `./teamserver operator --save <name>.cfg`)

**Evidence value:** MEDIUM-HIGH — operator credential files contain:
- Team Server IP address and port
- Operator username
- Client certificate (for mTLS authentication to Team Server)
- Operator's assigned permissions/role (if implemented)

**Example operator config (alice.cfg):**
```json
{
    "teamserver": "192.168.1.100:40056",
    "username": "alice",
    "cert": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKx1...\n-----END CERTIFICATE-----",
    "key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQE...\n-----END PRIVATE KEY-----"
}
```

**Forensic recovery:** Config files are plaintext/JSON; grep for "teamserver", "username". Deleted configs recoverable from filesystem slack. Certificates within configs can be analyzed to determine certificate authority, validity period, and subject CN (may include operator name or engagement code).

---

### Havoc Client Build/Payload Directory

**Location:** `~/Havoc/builds/` or operator-configured output directory

**Evidence value:** HIGH — contains generated Demon payloads (exe, shellcode, DLL) with embedded configuration:
- **Embedded C2 endpoints:** Team Server IP:port encoded in binary
- **Per-binary keypair:** asymmetric encryption keys specific to each agent
- **Sleep configuration:** interval, jitter, obfuscation method
- **Process-injection targets:** spawn process names
- **Callback URIs:** HTTP path(s) the agent uses

**File signatures:**
- **Havoc Demon exe:** PE binary, x64/x86, embedded Go runtime. Look for strings: "Demon", "havoc", "c2", "callback", "sleep", "inject", process names (svchost.exe, notepad.exe, etc.)
- **Havoc Demon shellcode:** raw position-independent code, smaller than exe, harder to fingerprint statically
- **Havoc Demon DLL:** reflectively loadable, embedded export table for DLL-injection APIs

**Forensic recovery:** Payloads are binary files on disk; YARA rules can identify Havoc Demon signatures (Go runtime markers, embedded process-injection target strings). Deleted payloads recoverable from unallocated space; file carving may reconstruct binaries.

**Reverse engineering:** Havoc payloads, if obtained, can be disassembled to recover embedded Team Server IP, port, and callback URIs. No code signing by default; payloads are unsigned unless operator applies `--spoof-metadata` flag.

---

### Havoc Client Session Logs / Command History

**Location:** `~/.havoc/history` or in-memory console history

**Evidence value:** HIGH — contains:
- Every command issued by the operator (generate, listen, tasks, etc.)
- Session IDs and target hostnames (if visible in command line)
- Payload format/architecture selections
- Module loads and results retrieval

**Example command history:**
```bash
generate demon-payload --arch x64 --format exe
listener http 192.168.1.100:8080
sessions
select demon-2d9f1a42
execute-assembly SharpUp.exe
token steal 5820
psexec \\CORP-SRV-001 cmd.exe
modules load keylogger.dll
modules results keylogger
```

**Forensic recovery:** Shell history is plaintext; stored in `~/.havoc/history` or in memory if the GUI client doesn't persist history to disk. Operator's terminal session history (bash_history, PowerShell history, zsh_history) may also contain Havoc CLI commands if issued from shell.

---

## Network-Level Artifacts (Operator → Team Server)

### Incoming Client Connection Logs

**Location:** Firewall logs, IDS/proxy logs on the network between operator and Team Server

**Evidence value:** MEDIUM — shows:
- **Operator IP address(es)** — source of Havoc client connections
- **Team Server IP:port** — listener configuration
- **TLS handshake metadata** — client certificate CN, issuer (may name the operator)
- **Connection frequency and duration** — pattern of operator activity
- **Connection failures** — if operator misconfigured server IP/port, failed connection attempts are logged

**Firewall log example:**
```
2025-12-18 14:23:45 ALLOW TCP 192.168.1.50:51234 → 192.168.1.100:40056 (TLS handshake)
2025-12-18 14:23:46 ALLOW TCP 192.168.1.50:51235 → 192.168.1.100:40056 (TLS established)
```

**IDS/proxy log example (if TLS is terminated):**
```
[TLS_HANDSHAKE] Client: 192.168.1.50, Server: 192.168.1.100:40056
  Client Certificate CN: alice@operator.local
  Handshake Duration: 0.2s
  Cipher: TLS_AES_256_GCM_SHA384
```

---

### Team Server Egress Traffic (Agent Callbacks)

**Location:** Firewall/egress-proxy logs monitoring Team Server's outbound connections to targets

**Evidence value:** MEDIUM-HIGH — reveals:
- **Demon agent callback IPs** — which targets have checked in to the Team Server
- **Callback protocol** — HTTP/HTTPS (port 80/443 or custom per profile)
- **Callback frequency** — check-in intervals (if callbacks are synchronized, may indicate default profile)
- **Traffic volume** — per-agent payload size (rough indicator of task complexity)

**Firewall log example:**
```
2025-12-18 14:24:10 ALLOW TCP 192.168.1.100:8080 → 10.0.1.50:54321 (Demon A callback)
2025-12-18 14:24:12 ALLOW TCP 192.168.1.100:8080 → 10.0.1.51:54322 (Demon B callback)
2025-12-18 14:24:15 ALLOW TCP 192.168.1.100:8080 → 10.0.1.52:54323 (Demon C callback)
(Pattern: callbacks occur every 2-3 seconds, indicating 2s sleep interval + jitter)
```

---

## Docker Container Artifacts (if Team Server is containerized)

### Docker Image Layers

**Location:** Docker image registry or local Docker daemon storage (`/var/lib/docker/overlay2/<hash>/`)

**Evidence value:** MEDIUM — Docker layers contain:
- Base image (Linux distro, Go runtime)
- Compiled Team Server binary
- YAOTL profile(s) baked into the image (if profile is `COPY`'d during build)
- SSL certificates (if included in image)

**Docker build history example:**
```dockerfile
FROM golang:1.18
RUN apt-get install -y build-essential
COPY teamserver /app/teamserver
COPY profiles/havoc.yaotl /app/profiles/havoc.yaotl  ← Profile in image
COPY certs/tls.crt /app/certs/tls.crt
ENTRYPOINT ["/app/teamserver", "server", "--profile", "/app/profiles/havoc.yaotl"]
```

**Forensic recovery:** Docker images can be extracted and analyzed layer-by-layer using tools like `docker image inspect` or `docker save`. Plaintext files (profiles, certs) are recoverable from layers. Deleted or overwritten files in layers may be recoverable from slack space within the compressed layer tarball.

### Docker Container Logs

**Location:** `/var/lib/docker/containers/<container-id>/<container-id>-json.log` (if driver=json-file)

**Evidence value:** MEDIUM — contains Team Server startup messages, operator connections, agent callbacks (same as Team Server logs above, but stored in Docker logging driver).

**Recovery:** Docker logs are plaintext JSON; can be grepped for "callback", "connected", "listener".

---

## Operator Infrastructure Artifacts

### Third-Party C2 Relay Server Logs

**Location:** If operator uses External C2 relay, logs on the relay server (`./external-c2-relay.py --log-file relay.log`)

**Evidence value:** HIGH — relay server logs contain:
- **Agent connection times and IPs** — when each Demon checked in via relay, from which target IP
- **Traffic volume and timing** — check-in patterns, command frequency
- **Relay server connectivity failures** — if relay lost connection to Team Server

**Example relay log:**
```
[14:24:10] Agent demon-2d9f1a42 connected from 10.0.1.50:54321
[14:24:11] Relaying 256 bytes → 192.168.1.100:40056
[14:24:12] Response received (512 bytes) ← relay to agent
[14:26:15] Agent demo-2d9f1a42 check-in interval (expected 120s ± jitter)
```

---

## Compiler / Build Artifacts

### Mingw32 Cross-Compiler Cache

**Location:** On Team Server host, typically `/usr/bin/x86_64-w64-mingw32-gcc`, `/usr/bin/i686-w64-mingw32-gcc`, or in Docker `/data/x86_64-w64-mingw32-cross/bin/`

**Evidence value:** LOW — compiler itself is a standard, publicly-available tool. No Havoc-specific evidence, but presence on a Linux system with the specific versions used by Havoc (Havoc profiles often specify exact compiler paths) can indicate Team Server deployment.

**Forensic indicator:** If system is seized, presence of mingw32 cross-compilers on a non-development Linux system (no other C/C++ tools present, isolated network) is an indicator of potential C2 infrastructure.

---

## Timeline Correlation: Operator Actions → Target Impact

### Example operational timeline:

```
Operator Timeline                                    Target Timeline
──────────────────────────────────────────────────────────────────

2025-12-18 14:23:45 (Operator PC)                  
 - connect to havoc --config alice.cfg
   (IP: 192.168.1.50)
                                                    2025-12-18 14:23:46 (Target)
                                                     [No activity yet]

2025-12-18 14:23:50 (Operator PC)
 - generate demon-payload --arch x64 --format exe
   (Binary saved to ~/Havoc/builds/)

2025-12-18 14:23:55 (Operator PC)
 - operator deploys binary to target (email, USB, web)
                                                    2025-12-18 14:24:00 (Target)
                                                     [Target user executes attachment]
                                                     PID 4024: demon-payload.exe starts
                                                     (Network: HTTP GET /api/inventory)

2025-12-18 14:24:05 (Operator PC + Team Server)
 - Client console: [+] New session demon-2d9f1a42
   (192.168.1.100:40056 Database: sessions table updated)

2025-12-18 14:24:12 (Operator PC)
 - execute-assembly SharpUp.exe
                                                    2025-12-18 14:24:15 (Target)
                                                     [Task queued, on next check-in cycle]
                                                     PID 5820: notepad.exe (sacrificial)
                                                      └─ .NET CLR injection
                                                      └─ SharpUp.exe loaded
                                                     Event 10 (Sysmon): Process access
                                                      (source: explorer.exe→demon 
                                                       target: lsass.exe [token theft])

2025-12-18 14:24:45 (Operator PC)
 - Client console: [+] Task result: SharpUp.exe
   (Output: unquoted service paths detected)

2025-12-18 14:25:00 (Operator PC)
 - psexec \\CORP-SRV-001 cmd.exe /c ipconfig
                                                    2025-12-18 14:25:02 (Target)
                                                     [Lateral movement attempt]
                                                     Event 3: Network connection
                                                      (source: CORP-WKS-001, 
                                                       dest: CORP-SRV-001:445/SMB)
                                                     Event 7045: Service created
                                                      ("PSEXESVC" or random name)

2025-12-18 14:25:15 (Operator PC)
 - Client console: [+] Session on CORP-SRV-001 established
   (demon-5f7a3c11, CORP\administrator)
```

**Forensic correlation:** By comparing operator-side timestamps (client logs, Team Server database) with target-side timestamps (Windows event logs, Sysmon), an analyst can:
1. **Tie operator IP to specific targets** — source IP from Havoc client connection logs matches attacker's external IP recovered from proxy/firewall logs.
2. **Reconstruct attack chain** — operator generates payload at T1, target receives callback at T2, lateral movement queued at T3, second target compromised at T4.
3. **Quantify dwell time** — time between initial compromise and lateral movement (operator caution, reconnaissance delay, etc.).
4. **Identify operator shift patterns** — if Team Server logs show operator connections at specific times of day (e.g., 9-5 UTC+2), may indicate operator location/timezone.

---

## OPSEC Implications

**Havoc profile as gating artifact:** Unlike Cobalt Strike (where Malleable C2 is operator-configurable post-deployment), Havoc's YAOTL profile **defines Team Server behavior at startup**. If an operator's Team Server is compromised/seized:
- Profile file directly reveals all network IOCs (listener ports, URIs, user-agents)
- SQLite database exposes all operational history
- Operator credentials are plaintext in the profile file

**Mitigation:** Operators should:
1. Use **ephemeral profiles** — regenerate profiles frequently, different per-engagement
2. **Isolate Team Server** — network-segment Team Server from operator workstations; use jump boxes
3. **Use External C2 relays** — operator's direct connection to Team Server is hidden behind intermediate relay (adds traffic lag but isolates operator IP)
4. **Delete artifacts aggressively** — Team Server should run with minimal logging, profiles/databases deleted after campaigns
5. **Use Docker with ephemeral volumes** — `docker run -v havoc-c2-data:/data` with volume deletion after campaign closes

**Non-mitigated risks:**
- **Agent callbacks are inherently trackable** — Demon binary contains embedded Team Server IP:port; reverse engineering any Demon payload reveals C2 infrastructure
- **Callback timing is a signature** — default 2s sleep + 15% jitter creates a recognizable check-in pattern even if traffic is encrypted
- **Operator IP leakage** — if Team Server/proxy logs are captured, operator's outbound connection IP is logged
