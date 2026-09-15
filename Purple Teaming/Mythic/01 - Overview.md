# Mythic C2 — Overview

> 🔴 **Red Flag Principle:** Mythic's modular, plugin-based architecture means there is **no single universal signature** for its agents or listeners — every agent is registered/installed separately as a custom payload type, and every C2 profile is installed as a plugin, making signature-based detection structurally unreliable. The durable detection surface is **behavioral and traffic-level**: the gRPC/HTTP protocol shapes between implant and server, the database schema artifacts on the operator's host (Mythic operates on PostgreSQL with Hasura GraphQL on top), Docker container process patterns, and the standardized `mythic-container` PyPI module's inter-process communication that all agent containers leverage. Hunt the infrastructure and container patterns, not the implant binary.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Mythic is developed and maintained by **[its-a-feature](https://github.com/its-a-feature)**, a security researcher/operator, as an open-source **"cross-platform, post-exploit, red teaming framework."** The canonical upstream repository is [`github.com/its-a-feature/Mythic`](https://github.com/its-a-feature/Mythic), licensed under **GPLv3**. Verified directly against the repo/release metadata via the GitHub API:

- **Repository created 2018-06-07** — Mythic began as a Docker-centric alternative to Cobalt Strike and Metasploit, betting on modular plugin architecture and modern browser UI rather than monolithic feature parity.
- **v3.0.0 (2020-08-15)** — initial stable 3.x release, the point at which the plugin-based payload type/C2 profile system and the Hasura GraphQL API became the framework's core design (replacing an earlier ad-hoc REST API).
- **v3.2.20 (2024-08-28)** — final release of the 3.2 line, the "last release of Mythic 3.2 before switching over to Mythic 3.3" per the release note itself.
- **v3.3.0.133 (2025-08-26)** — 3.3 line stable, released as "Mythic 3.3.1-rc90."
- **v3.4.0.5 (2025-10-10)** — current latest tagged release at time of writing; this note's architecture/defaults are verified against the current `master` branch source (version **3.4.36** per the repository's `VERSION` file).

The repository carries **7,000+ GitHub stars** and is actively maintained (commits landing on `master` weekly).

## How It Works

### Architecture — container-native infrastructure, gRPC everywhere

Verified against the project's README, GitHub Actions workflows, and docker-compose examples:

Mythic is architecturally **container-first**: every component (Mythic server, React UI, database, message broker, installed agents, installed C2 profiles) runs in its own container, orchestrated via docker-compose. The design **centralizes all agent/operator communication** through a single PostgreSQL database (with Hasura GraphQL exposing queries/mutations on top), eschewing direct socket connections between operator and agent.

```
Operator's Browser          Operator's CLI (mythic-cli)
      ↓                              ↓
      [HTTPS/UI] ← → [React UI Container]
                          ↓
                   [Mythic Server (Go)]
                          ↓
                   [PostgreSQL Database]
                   [Hasura GraphQL API]
                          ↓
                   [RabbitMQ Message Bus]
                          ↓
        ↙━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━↖
      [Agent Container]    [C2 Profile Container]
        (Python/Go/etc)    (HTTP/DNS/etc profile)
        (via mythic-       (via mythic-container)
         container lib)
            ↓                         ↓
        [mythic-container PyPI / MythicContainer Go module]
         (bi-directional RPC bridge to Mythic server)
            ↓
    [Target Host]
```

- **Mythic Server** (`mythic_go` container) — implements the task dispatcher, payload type registry, C2 profile registry, and database schema. All operator/agent comms flow through this central point.
- **PostgreSQL Database** — stores operations, agents, callbacks, tasks, payloads, C2 profiles, credentials, files, operators, and permissions. Every query from operator to agent or vice versa is a database transaction.
- **Hasura GraphQL** — provides the query/mutation API surface on top of PostgreSQL. Every operator CLI command translates to a GraphQL query.
- **RabbitMQ Message Bus** — coordinates task dispatch between Mythic server and installed agent/C2 containers. Agents and C2 profiles subscribe to tasks targeted at them via queue subscriptions.
- **Agent Containers** — one per installed agent type (Apfell, Poseidon, etc.). Each is a standalone, self-contained Docker image running a Python script (or Go binary) that:
  - Registers itself with the Mythic server at startup (announcing its commands, parameters, return types).
  - Subscribes to RabbitMQ queue for tasks sent to its agent type.
  - Returns task results back to the server (which writes them to the database).
  - Each agent is installed via `mythic-cli install github https://github.com/MythicAgents/<agent-name>`.
- **C2 Profile Containers** — one per installed C2 profile type (HTTP, DNS, SMB, etc.). Each handles the protocol-level details of implant-to-server communication:
  - Listens for incoming implant callbacks on a specific transport (HTTP POST, DNS queries, named pipes, etc.).
  - Encrypts/decrypts data between implant and server (using AES-256-GCM per the Mythic encryption spec).
  - Translates the transport's format into internal Mythic messages.
  - Each C2 profile is installed via `mythic-cli install github https://github.com/MythicC2Profiles/<profile-name>`.

### Payload Generation — per-agent customization, compile-time configuration

Every agent installation includes a "payload builder" — a Docker image entrypoint script that compiles/configures the agent for a specific target. When an operator requests a new payload:

1. The operator selects a **Payload Type** (e.g., "Apfell") and **C2 Profile** (e.g., "HTTP").
2. The operator specifies **build parameters** (e.g., callback host/port, encryption key, jitter, architecture).
3. Mythic server invokes the Apfell container's build function with those parameters.
4. The agent container compiles/packages a binary with the configuration baked in (encryption keys, callback endpoints, etc.).
5. The binary is returned to the operator and staged to the target.

**No two payloads from the same agent type are identical** in encryption keys or callback configuration, but the **source code and command structure** are the same across all builds.

### Sessions and Tasks — asynchronous callback model

Mythic uses an **asynchronous, callback-driven** model, not persistent reverse shells:

1. **Callback Registration** — when the implant first reaches out to a C2 profile, it registers itself in the database as a new "callback" (Mythic's term for agent session). The callback includes: agent type, operator-assigned name/description, callback host/timestamp, architecture, user/hostname/PID/process-name, and implant-side encryption key.
2. **Task Queuing** — when an operator issues a command (e.g., `shell whoami`), Mythic creates a **Task** in the database, tagged with the target callback ID. The agent's next check-in retrieves queued tasks, executes them, and uploads results.
3. **Exit Strategy** — the implant can be configured to exit after N failed callback attempts or after a specific datetime (configured at build time via `limit-datetime`). Some agents support interactive sessions where the operator can flip to a lower-latency reverse-shell mode, but the default is poll-based.

### Agent Ecosystems — current payload types

Mythic does **not** ship agents in the core repository. Instead, operators install agents from the MythicAgents namespace. Current/popular installed agents include (verified against the MythicMeta GitHub organization):

| Agent Name | Language | OS Support | Build Status | Notes |
|---|---|---|---|---|
| **Apfell** | Python | macOS / Linux | Archived (2021) | The canonical early-stage agent, primarily educational / demonstration |
| **Poseidon** | Python | Windows / macOS / Linux | Active | Full-featured post-exploitation agent, module-rich |
| **Rogue** | Go | Windows / macOS / Linux | Active | Cross-platform Go agent, faster execution than Python |
| **Apollo** | C# | Windows | Active | Windows-native agent, uses .NET reflection for low-visibility execution |
| **Merlin** | Go | Windows / macOS / Linux | Active | Modular Go agent, flexible command structure |
| **Artemis** | Go | Linux | Active | Linux-focused agent, built-in privilege-escalation toolkit |
| **Aspen** | Python | Windows | Active | Windows agent, focus on Active Directory enumeration |
| **Medusa** | C | Linux | Active | C-written Linux agent for low-resource environments |

**The agent list is not exhaustive** — Mythic's plugin model means operators can write custom agents; the MythicAgents GitHub org hosts the publicly-available ones.

### C2 Profiles — available listeners

Similarly, C2 profiles are installed separately. Current/popular profiles include:

| Profile Name | Transport | Encryption | Build Status | Notes |
|---|---|---|---|---|
| **HTTP(S)** | HTTP POST (customizable User-Agent, headers, URIs) | AES-256-GCM | Active | Most common, profiles define request/response format (Mythic provides templates) |
| **DNS** | DNS TXT record queries/responses | AES-256-GCM | Active | Requires operator-controlled domain, slower throughput, low-profile |
| **SMB** | Named pipes (Windows-only) | AES-256-GCM | Active | Peer-to-peer C2, one implant relays for another via SMB pipes |
| **TCP/Websocket** | Raw TCP or WebSocket | AES-256-GCM | Active | Direct TCP tunnel, useful for egress-restricted networks with socket access |
| **gRPC** | gRPC (binary protobuf) | AES-256-GCM | Active | Native Go/proto support, lower overhead than HTTP |
| **Custom** | Operator-written transport | User-defined | Active | Mythic's plugin model allows arbitrary protocol implementation |

**Like agents, the profile list grows via community contribution** — Mythic doesn't mandate or limit transports.

## Techniques / Protocols Used

| Protocol / Technique | Category | MITRE ID | Notes |
|---|---|---|---|
| **HTTP(S)** | Command & Control (C2) | T1071.001 (Application Layer Protocol: Web Protocols) | Most common C2 profile, HTTP POST callbacks |
| **DNS** | Command & Control (C2) | T1071.004 (Application Layer Protocol: DNS) | DNS TXT record tunneling for out-of-band C2 |
| **SMB/Named Pipes** | Lateral Movement / Pivoting | T1021.002 (Remote Services: SMB/Windows Admin Shares) | Peer-to-peer agent relay |
| **gRPC** | Command & Control (C2) | T1071.001 (implied, binary protobuf over HTTP/2) | Modern RPC framework C2 |
| **AES-256-GCM** | Encryption | N/A | Mythic's standard encryption cipher for all C2 traffic |
| **Docker Containers** | Infrastructure / Evasion | T1480 (Execution Environments) | Agent/profile containerization obscures host-side execution |
| **RabbitMQ** | Infrastructure | N/A | Message broker for inter-container task dispatch, runs on the operator's host only |
| **PostgreSQL** | Infrastructure | N/A | Central database, runs on operator's host only, contains all operational data |
| **Process Injection** | Execution / Defense Evasion | T1055 (Process Injection) | Agent-dependent; supported by Apollo/Poseidon/others via reflective loading |
| **Lateral Movement (SMB/Named Pipe Pivoting)** | Lateral Movement | T1021.002 / T1570 | Agent-dependent; multi-agent relaying |
| **OPSEC: Limit Datetime** | Defense Evasion | T1140 / T1564 | Agents configured to self-destruct after a specific date/time |
| **OPSEC: Limit Domain-Joined** | Defense Evasion | T1140 | Agents self-abort if the host is not domain-joined (useful for targeted engagement scope) |

## Command-Line Switches — Quick Reference

Mythic operations are driven by the **`mythic-cli`** binary, which communicates with the Mythic server via GraphQL queries (not direct TCP sockets). All commands follow the pattern `sudo mythic-cli <command> [flags]`.

### Core Commands

| Command | Flags | Description | Example |
|---|---|---|---|
| **start** | `--compose-file` (default: `docker-compose.yml`) | Bring up all Mythic containers | `sudo mythic-cli start` |
| **stop** | None | Shut down all containers | `sudo mythic-cli stop` |
| **logs** | `-f` (follow), `<container-name>` (optional) | Display container logs | `sudo mythic-cli logs -f mythic_go` |
| **install** | `github <url> [-b branch] [-f]` | Install a new agent or C2 profile from GitHub. `-f` force reinstall | `sudo mythic-cli install github https://github.com/MythicAgents/poseidon` |
| **uninstall** | `<agent-or-profile-name>` | Remove an installed agent/C2 profile | `sudo mythic-cli uninstall poseidon` |
| **config** | `set <key> <value>` | Modify Mythic server configuration (password, admin user, listening IP/port, etc.) | `sudo mythic-cli config set MYTHIC_PASSWORD newpass123` |
| **status** | None | Display current container status | `sudo mythic-cli status` |

### Web UI Access

- **Default URL:** `https://localhost:8443` (HTTPS enforced)
- **Default Credentials:** `admin:password` (changeable via `mythic-cli config`)
- **Browser Warning:** Self-signed cert by default, browser will warn on first access

### Database Access (Advanced)

| Command | Purpose | Example |
|---|---|---|
| `sudo mythic-cli database shell` | Open PostgreSQL interactive shell | Query operations, callbacks, tasks directly |
| `sudo mythic-cli database backup <output-path>` | Backup PostgreSQL database | `sudo mythic-cli database backup ./mythic-backup-$(date +%s).sql` |

## Quick Use-Case List

1. **Initial Foothold & Enumeration** — stage multi-stage payload via HTTP C2 profile, callback to Mythic server, enumerate host architecture/users/processes via built-in agent commands (e.g., Poseidon's `ps`, `whoami`, `systeminfo`).
2. **Active Directory Recon** — deploy Windows agent (Apollo/Poseidon on Windows), use `Get-ADUsers` / `Get-ADComputers` module to enumerate domain structure (cross-linked to `Aspen` agent's AD-focused commands).
3. **Lateral Movement via SMB** — use SMB C2 profile to set up peer-to-peer pivot, first implant relays callbacks for a second implant on an unreachable subnet via `\\target\IPC$` named pipes.
4. **Low-Profile DNS Tunneling** — swap HTTP profile for DNS profile mid-engagement, operator-controlled domain as C2 channel, slower but evades typical HTTP DLP filters (DNS less inspected).
5. **Cross-Platform Persistence** — deploy Poseidon on Linux, use agent's `persist_cron` / `persist_launchd` (macOS) modules to maintain foothold across reboots.
6. **Credential Harvesting** — Apollo/Poseidon agents include modules to dump LSASS (Windows), extract browser credentials, query Credential Manager, keylogging; results stored in Mythic database.
7. **Process Injection & Evasion** — Apollo supports in-memory DLL/shellcode injection via reflective loading; Poseidon supports similar via Python's ctypes; operator doesn't need to drop a new binary to disk.
8. **Multi-Agent Coordination** — queue commands against multiple callbacks in a single Mythic operation, results aggregated in the database; operators can pivot/coordinate across agents in a single interface.
9. **File Exfil & Download** — agents support `upload` / `download` commands; Mythic stores files in the database, operator can retrieve via web UI or CLI.
10. **Custom Command Development** — extend agents via Mythic's plugin system (add new command to agent source, rebuild, reinstall); custom C2 profiles likewise can be written for arbitrary protocols.
11. **Encrypted Out-of-Band C2** — gRPC or DNS profiles provide encrypted, potentially low-detectability C2 independent of HTTP (useful if HTTP inspection is active).
12. **Post-Engagement Cleanup** — agents configured with `limit-datetime` self-destruct after engagement end-date, automated OPSEC trigger.

## Prerequisites

### Operator Host (Running Mythic Server)

- **Docker & Docker-Compose** — Mythic is entirely containerized. Requires `docker` daemon and `docker-compose` installed.
- **Linux host** — Mythic is designed for Linux operators (Debian/Ubuntu/Kali verified); macOS/Windows operators typically run Mythic in a VM or cloud instance.
- **Minimum resources:** 4 GB RAM, 20 GB disk (grows with operations/agent logs).
- **Network egress:** Mythic server needs outbound access to GitHub (for `mythic-cli install` commands) and the target networks (depending on C2 profile — HTTP profiles need Internet access, DNS profiles need access to DNS resolver on target network, SMB profiles need network access to target LAN).

### Agent Payload Host (Target)

**Depends on the agent type:**

| Agent | OS | Privileges | Notes |
|---|---|---|---|
| **Poseidon** | Windows / macOS / Linux | User-level (admin for some modules) | Universal agent, works unprivileged for basic recon |
| **Apollo** | Windows | User-level (admin for LSASS dump) | Requires .NET Framework 4.x (modern Windows has this) |
| **Rogue** | Windows / macOS / Linux | User-level | Low resource footprint, Go runtime embedded |
| **Aspen** | Windows | User-level (admin for domain query) | Requires .NET, AD domain access for full capability |
| **Artemis** | Linux | User-level (root for privilege escalation modules) | Requires Linux libc |

### Network Prerequisites

- **C2 Profile-dependent:**
  - **HTTP(S):** Target must have outbound HTTPS access to operator's Mythic server (or C2 redirector).
  - **DNS:** Target must be able to query a DNS resolver; operator's domain NS records pointed at Mythic DNS listener.
  - **SMB:** Target must have network access to a already-compromised implant's SMB share (peer-to-peer relay model).
  - **gRPC:** Similar to HTTPS, requires outbound access to operator's Mythic server.

### Operator Capabilities

- **Familiarity with Docker** — understanding of container lifecycle, logs, networking.
- **Familiarity with agent types** — each agent has different command syntax, modules, OPSEC trade-offs.
- **Programming ability (optional)** — writing custom agents/C2 profiles requires Python (for agent containers) or Go (for C2 profiles).
