# Mythic C2 — Source Evidence

Source evidence is what remains on the **operator's own host** — typically a Linux VM or dedicated machine running the Mythic server and all Docker containers. This is not the target host, but the attacker's infrastructure.

## Docker Containers and Image Artifacts

### Container Processes

Running Mythic leaves a distinctive set of container processes on the operator's host:

```bash
# docker ps output on Mythic server:

CONTAINER ID    IMAGE                           STATUS          NAMES
abc12345        itsafeaturemythic/mythic_go     Up 2 hours      mythic_go
def67890        postgres:13                     Up 2 hours      mythic-postgres
ghi11111        rabbitmq:3-management           Up 2 hours      mythic-rabbitmq
jkl22222        itsafeaturemythic/mythic_react  Up 2 hours      mythic-react
mno33333        itsafeaturemythic/mythic_python_base  Up 2 hours  poseidon
pqr44444        itsafeaturemythic/mythic_go_dotnet   Up 2 hours  apollo
```

**Hunt Signal:** All containers start with `mythic_` or `itsafeaturemythic/` image names. Process listing will show `docker run` with mount points for the Mythic data directories.

### Docker Volume Mounts

Mythic persists data via Docker volumes (mapped to the host filesystem):

```bash
# docker inspect mythic_go | grep -A5 Mounts

"Mounts": [
  {
    "Type": "volume",
    "Source": "mythic_database",          # PostgreSQL database
    "Destination": "/postgres/data"
  },
  {
    "Type": "bind",
    "Source": "/root/Mythic/PayloadsGenerated",  # Generated payloads (staged binaries)
    "Destination": "/payloads"
  },
  {
    "Type": "bind",
    "Source": "/root/Mythic/InstalledServices",  # Agent/C2 profile source code
    "Destination": "/InstalledServices"
  }
]
```

**Key directories on operator's host:**
- `/root/Mythic/PayloadsGenerated/` — every generated payload (.exe, .elf, .bin, etc.) is stored here.
- `/root/Mythic/InstalledServices/` — cloned agent and C2 profile repositories (GitHub source code).
- Docker volumes (usually in `/var/lib/docker/volumes/`) — PostgreSQL database files, RabbitMQ queues.

---

## PostgreSQL Database Artifacts

The PostgreSQL database (`mythic-postgres` container) is the central repository for all operational data. If this database is seized, an attacker can directly recover:

### Database Structure (Hasura schema)

```
Table: payload
  - id (unique identifier)
  - operation_id (which operation this payload belongs to)
  - payload_type (Poseidon, Apollo, Rogue, etc.)
  - c2_profile (HTTP, DNS, SMB, etc.)
  - callback_host (operator's C2 server hostname/IP)
  - callback_port (C2 listening port)
  - architecture (x86, x64)
  - creation_time (when generated)
  - signed_payload (the binary blob itself)

Table: callback
  - id (unique session ID)
  - operation_id
  - agent_type (Poseidon, Apollo, etc.)
  - user (logged-in user on target)
  - host (target hostname)
  - pid (process ID on target)
  - architecture (x86/x64)
  - os (Windows/Linux/macOS)
  - extra_info (additional enumeration data)
  - active (whether still checking in)
  - last_checkin (timestamp of last contact)

Table: task
  - id (task ID)
  - callback_id (which callback this task is for)
  - command (the command string, e.g., "shell whoami")
  - status (submitted/processed/complete)
  - timestamp_submitted (when operator queued it)
  - timestamp_completed (when agent executed it)
  - response (the command output/result)

Table: operation
  - id (operation ID)
  - name (engagement name)
  - admin (operator username)
  - complete (whether operation is archived)
  - start_time, end_time
  - webhook (Slack/Teams notification webhook, if configured)

Table: operator
  - username
  - password_hash (bcrypt hash)
  - api_token (for CLI/bot access)
  - admin (boolean)
  - last_login (timestamp)
  - creation_time
```

**Evidence value:** A PostgreSQL dump reveals:
- Every payload generated (binary hashes, configurations, C2 endpoints).
- Every callback registered (target hostnames, IPs, users, processes).
- Every command executed and its results (full operational timeline).
- Operator usernames and password hashes (crackable via bcrypt/hashcat).
- API tokens for non-interactive access (reusable for continued access post-seizure).

### Database Backup Files

Operators regularly back up the database (for disaster recovery):

```bash
# Common backup locations:
/root/Mythic/backups/mythic_backup_2025-08-12.sql
/root/Mythic/backups/mythic_backup_2025-08-13.sql
~/.mythic/backups/dump_20250812_120000.sql
/var/backups/mythic_db_*.sql.gz

# Backup contains:
# - Entire PostgreSQL schema dump (DDL + DML)
# - All operational data in plaintext SQL
# - Can be restored to a new PostgreSQL instance to recover the operation
```

**Hunt signal:** Look for `.sql`, `.sql.gz`, or `.dump` files on the operator's filesystem, especially in `~/.mythic/`, `/root/Mythic/backups/`, `/var/backups/`.

---

## Staged Payload Artifacts

### Generated Payloads (Binary Files)

Every payload generated in Mythic is stored as a file:

```bash
# Directory: /root/Mythic/PayloadsGenerated/

ls -la /root/Mythic/PayloadsGenerated/

-rw-r--r-- poseidon_http_v1_2025_08_12_001.exe  (100 KB)
-rw-r--r-- apollo_http_v2_2025_08_12_003.exe    (250 KB)
-rw-r--r-- poseidon_dns_v1_2025_08_12_005.exe   (105 KB)
-rw-r--r-- rogue_smb_2025_08_12_002.elf         (35 KB)
-rw-r--r-- poseidon_dns_2025_08_13_001.exe      (105 KB)

# Metadata available:
# - Creation time (filesystem timestamps)
# - File size (payload size)
# - File name pattern: <agent>_<profile>_v<n>_<date>_<seq>.<ext>
```

**Evidence value:**
- File hash (MD5/SHA256) can be compared against known malware IOCs to identify Mythic variants.
- Filename pattern and date sequencing reveals operational timeline (e.g., 5 payloads generated over 2 days suggests an active multi-stage operation).
- Payload binary itself can be decompiled (C#/Go/Python) to recover C2 configuration (callback host, encryption keys, agent commands).

### Configuration Metadata

Within the payload binaries, configuration is embedded at compile time:

```
[Poseidon Payload Binary Structure]
- Encrypted agent code (Go, compiled)
- Embedded config: callback host "attacker.com", port 8080
- Encryption key (AES-256 key used for C2 traffic)
- Agent type identifier (Poseidon v1.0)
- Evasion flags (if enabled: AMSI bypass, ETW patching)
```

**Extraction:** Running `strings` on a Poseidon binary can recover plaintext configuration if the binary isn't stripped:

```bash
strings poseidon_http_v1.exe | grep -i "attacker.com"
# Output: attacker.com
```

---

## Agent and C2 Profile Source Code

### Installed Agent Repositories

When operators install agents via `mythic-cli install github`, the source code is cloned to the operator's host:

```bash
# Directory: /root/Mythic/InstalledServices/

ls /root/Mythic/InstalledServices/
- Poseidon/           # Cloned from github.com/MythicAgents/poseidon
- Apollo/             # Cloned from github.com/MythicAgents/apollo
- http/               # Cloned from github.com/MythicC2Profiles/http
- dns/                # Cloned from github.com/MythicC2Profiles/dns

# Full source code (Python, C#, Go) is available
```

**Hunt signal:**
- Directory listing of InstalledServices reveals which agents/profiles are available.
- Git history (`.git/` folder within each repo) shows commits, author info, branch changes.
- `requirements.txt`, `package.json`, or `go.mod` files indicate dependencies.

### Dockerfile and Build Scripts

Each installed service includes its Dockerfile:

```dockerfile
# /root/Mythic/InstalledServices/Poseidon/Dockerfile
FROM itsafeaturemythic/mythic_python_base:latest
COPY . /agent
WORKDIR /agent
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "agent_code/poseidon/agent.py"]
```

**Evidence value:** Dockerfiles reveal:
- Build environment (Python 3.9+, Go 1.18+, etc.).
- Dependencies (revealed by build-time pip installs, go get commands).
- Entry point (the command that starts the container, often revealing the agent's RPC bridge).

---

## Docker Network and Port Mapping Artifacts

### Network Bindings

Mythic containers expose services on the operator's host network:

```bash
# netstat / ss output on Mythic server:

LISTEN     0     128     0.0.0.0:8443            # HTTPS web UI (Mythic React)
LISTEN     0     128     0.0.0.0:80              # HTTP C2 listener (if profile installed)
LISTEN     0     128     0.0.0.0:443             # HTTPS C2 listener (if profile installed)
LISTEN     0     128     0.0.0.0:53              # DNS C2 listener (if profile installed)
LISTEN     0     128     0.0.0.0:5432            # PostgreSQL (internal docker network, not exposed)
LISTEN     0     128     0.0.0.0:15672           # RabbitMQ management UI

# Process tree:
docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8443 -container-ip 172.17.0.2 -container-port 8443
docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 80 -container-ip 172.17.0.3 -container-port 80
```

**Hunt signal:** Port 8443 (Mythic UI), 80/443 (HTTP/HTTPS C2), 53 (DNS C2), 15672 (RabbitMQ UI) in LISTEN state on the same host is a strong indicator of Mythic C2 infrastructure.

### Docker Bridge Network

All Mythic containers communicate via an internal Docker bridge (172.17.0.0/16 by default):

```bash
# docker network ls
NETWORK ID    NAME        DRIVER    SCOPE
abc123        bridge      bridge    local
def456        mythic      bridge    local  # Mythic's custom network

# docker inspect mythic
# "Containers": {
#   "abc123..._mythic_go": {"IPv4Address": "172.17.0.2"},
#   "def456..._postgres": {"IPv4Address": "172.17.0.3"},
#   "ghi789..._rabbitmq": {"IPv4Address": "172.17.0.4"},
# }
```

**Hunt signal:** Docker's internal network configuration (`/var/lib/docker/network/files/local-kv.db`) can be extracted post-seizure to map container communication patterns.

---

## Operator Session State and Logs

### Web UI Session Cookies

The Mythic React web UI stores session cookies in the browser:

```
Browser: Developer Tools → Application → Cookies → localhost:8443

Cookie: mythic_session_token=<JWT-token>
# This JWT token identifies the logged-in operator and can be used for authentication bypass if stolen
```

**Hunt signal:** Session tokens can be extracted from browser memory (if the operator's workstation is seized while logged in).

### Command-Line Tool Cache

The `mythic-cli` tool stores authentication state:

```bash
# ~/.mythic/ or ~/.config/mythic/
~/.mythic/login_token        # API token for non-interactive access
~/.mythic/last_server        # Last-used Mythic server IP/hostname
~/.mythic/config.json        # Stored configuration (database credentials in plaintext if auto-saved)
```

**Hunt signal:** These files are cleartext and highly sensitive.

### Container Logs

Docker container logs are stored on the operator's host:

```bash
# docker logs mythic_go
# Output: All Mythic server operations logged
# - Agent registrations ("callback registered from Host1\User1")
# - Task completions ("task 123 completed: whoami = DOMAIN\User")
# - C2 profile registrations and listener starts
# - Operator logins

# Log location:
/var/lib/docker/containers/<container-id>/<container-id>-json.log

# Example:
[2025-08-12T10:34:12Z] Callback registered: ID=456, Agent=Poseidon, User=DOMAIN\Admin, Host=WKS-001
[2025-08-12T10:35:01Z] Task completed: 456.123 (shell whoami) = DOMAIN\Admin
[2025-08-12T10:35:45Z] HTTP C2 listener started on port 80
```

**Evidence value:** Logs provide an audit trail of:
- Agent registrations (timestamps, callback IDs, target identities).
- Command execution (task IDs, timestamps, command strings, results).
- C2 listener status changes.
- Operator actions (if logging is enabled).

---

## Firewall Configuration and Network Egress Logs

### UFW / iptables Rules

If the operator's host has a firewall, the rules reveal C2 listener ports:

```bash
sudo iptables -L -n -v

Chain INPUT (policy DROP)
target  prot  opt  in  out  source  destination
ACCEPT  tcp   --   *   *   0/0    0/0  tcp dpt:8443  # HTTPS web UI
ACCEPT  tcp   --   *   *   0/0    0/0  tcp dpt:80    # HTTP listener
ACCEPT  tcp   --   *   *   0/0    0/0  tcp dpt:443   # HTTPS listener
ACCEPT  udp   --   *   *   0/0    0/0  udp dpt:53    # DNS listener
```

**Hunt signal:** Port rules for 8443, 80/443, 53 indicate C2 infrastructure.

### Network Traffic and Packet Captures

If the operator's host is monitored by IDS/netflow appliances:

- **Inbound traffic:** targets connecting to 80/443/53/8443 (C2 callbacks arriving).
- **Outbound traffic:** operator's host connecting to GitHub (for `mythic-cli install`), Docker Hub (for pulling images).

**Example netflow record:**
```
Source: 192.168.1.50 (target)
Dest: 203.0.113.100 (operator's Mythic server)
Port: 80 (HTTP)
Protocol: TCP
Duration: 3 seconds
Bytes: 1024 up, 512 down
```

---

## Timeline Correlation: Operator-Side Events

Reconstructing the operational timeline requires correlating multiple artifacts:

| Time | Artifact | Event |
|---|---|---|
| 2025-08-12 08:00 | `/root/Mythic/InstalledServices/Poseidon/.git` commit | Operator cloned Poseidon agent |
| 2025-08-12 08:15 | Docker image `poseidon:latest` in `docker images` | Container image built |
| 2025-08-12 08:20 | `mythic_go` container log | "Payload builder registered: Poseidon" |
| 2025-08-12 09:00 | `/root/Mythic/PayloadsGenerated/poseidon_http_*.exe` (file ctime) | Payload generated |
| 2025-08-12 09:30 | PostgreSQL table `callback` (via dump) | First callback registered from target |
| 2025-08-12 09:35 | PostgreSQL table `task` (via dump) | First command executed on target |
| 2025-08-12 10:00 | Docker container logs + task table | Multiple commands queued and completed |
| 2025-08-13 12:00 | Backup file `/root/Mythic/backups/mythic_backup_2025_08_13.sql` (ctime) | Database backed up |

This timeline, reconstructed from multiple sources, provides an **evidentiary chain** linking operator setup → payload generation → target compromise → command execution.

---

## Memory-Forensics Angle

If the operator's host is running Mythic when seized:

### Process Memory (Docker/Go)

The `mythic_go` process holds in-memory state:

```
- Active callback handles (network connections to active targets)
- Decrypted task queues (commands waiting to be sent to agents)
- Encryption keys (AES-256 keys used for C2 channel encryption)
- Operator credentials (if not yet invalidated)
```

**Hunt signal:** Volatility analysis of a memory dump from the `mythic_go` process can recover:
- Active callback IDs and target identities.
- Queued command strings.
- Operator session tokens.

### PostgreSQL Memory

The PostgreSQL process (`postgres` running in a container) holds:

- Decoded operational database (all tables, queries in execution).
- Client authentication tokens.
- Intermediate query results (if a long-running query was in progress).

**Hunt signal:** Memory dump of the PostgreSQL container can recover recent queries and decrypted data.

---

## Evasion and Cleanup Artifacts

### Cleanup Mistakes

Operators who try to clean up after an engagement often leave traces:

```bash
# Incomplete deletion of payload directory:
# Operator runs: rm -r /root/Mythic/PayloadsGenerated/
# But filesystem still contains deleted inodes recoverable via carving

# Incomplete deletion of database:
# Operator runs: docker volume rm mythic_database
# But PostgreSQL's filesystem journal/wal files remain in /var/lib/docker/volumes/

# Cleared docker logs:
# Operator truncates: > /var/lib/docker/containers/*/docker-json.log
# But syslog copies remain in /var/log/syslog
```

### Configuration Obfuscation

Some operators modify docker-compose.yml to:
- Change container names (mythic_go → admin_service)
- Change port bindings (8443 → 18443)
- Use custom image names (itsafeaturemythic/mythic_go → mycompany/service)

**Counter:** These changes are still detectable via:
- Process network bindings (`netstat -tlnp | grep docker-proxy`)
- Docker API queries (`docker ps`, `docker inspect`)
- Git/version history if docker-compose.yml is tracked in git

---

## IOC Summary for Source Host Detection

| Category | IOC | Strength |
|---|---|---|
| **Network** | Port 8443 (Mythic UI) LISTENING | High — distinctive Mythic default |
| **Network** | Ports 80/443/53 LISTENING (C2 listeners) | Medium — common services, need corroboration |
| **Process** | `docker-proxy` with port 8443 | High |
| **Process** | Multiple `docker` containers named `mythic_*` | High |
| **File System** | `/root/Mythic/PayloadsGenerated/` directory | High |
| **File System** | `/root/Mythic/InstalledServices/` with git repos | High |
| **Database** | PostgreSQL dump with Mythic schema (tables: callback, task, payload, operation) | Very High |
| **Logs** | Docker container logs mentioning "callback registered" | Medium — agent-specific phrasing |
| **Git** | Commits in `.git/` of InstalledServices repos | Medium — shows access time |
| **Backup** | `.sql` or `.sql.gz` files in backups/ | Medium — common for all DB tools, but pattern + DB schema confirmatory |
| **Memory** | `mythic_go` process with Mythic-specific strings in memory | Medium — requires memory access |

---

## Defense and Remediation: Securing the Source Host

### Immediate Actions (If Mythic Server is Compromised)

1. **Assume all operational data is compromised** — every callback, every command, every credential is exposed.
2. **Rotate all operator credentials** — password hashes in the database may be cracked.
3. **Invalidate API tokens** — issued tokens can be used for post-compromise access.
4. **Regenerate encryption keys** — old keys may be recovered from database or process memory.
5. **Archive and isolate the compromised server** — preserve logs for forensics, do not reuse.

### Preventive Measures

1. **Network isolation** — run Mythic server on a segregated network segment; restrict inbound connections to operator's IP only.
2. **Encrypted backups** — backup PostgreSQL database with encryption at rest (`gpg -c mythic_backup.sql`).
3. **Memory encryption** — use Linux's encrypted swap to prevent swapped database/process memory from being readable post-seizure.
4. **Audit logging** — enable PostgreSQL logging (`log_connections`, `log_statement`) for a full query audit.
5. **Firewall rules** — restrict outbound connections from Mythic server to only necessary IPs (GitHub for installs, target networks for C2).
6. **Regular key rotation** — periodically invalidate and regenerate C2 encryption keys.
