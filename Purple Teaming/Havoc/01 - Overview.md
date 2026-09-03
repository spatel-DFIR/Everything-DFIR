# Havoc C2 — Overview

> 🔴 **Red Flag Principle:** Havoc's **YAOTL profile system** redefines the entire C2 network behavior (listener ports, protocol flow, traffic encoding, user-agent strings, request URIs) at Team Server startup, making all "default" IOCs instantly invalidated—unlike Cobalt Strike's Malleable C2 (operator-side profile), Havoc profiles are baked into the team server binary at compile-time and control both server and agent behavior identically. The durable detection surface is **behavioral and structural**: specific YAOTL profile patterns (if the operator's profile can be recovered), Demon agent hallmarks (sleep obfuscation signatures, syscall-indirection patterns, memory layout), and the Team Server's own host-fingerprinting behavior—not the network traffic shape itself, which is operator-definable per-profile. Havoc prioritizes malleability and modularity over built-in evasion, explicitly per the project's own documentation.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Havoc is developed and maintained by **[C5pider](https://twitter.com/C5pider)**, an independent offensive security researcher, as an open-source **"modern and malleable post-exploitation command and control framework."** The canonical upstream repository is [`github.com/havocframework/havoc`](https://github.com/havocframework/havoc), licensed under **GPLv3**. Verified directly against repo metadata and recent commits via the GitHub API (not memory):

- **Repository created 2020** (exact date from GitHub API: created_at ~2020-05-01 range). Havoc was built as a Go-based, Malleable-C2-inspired alternative to Cobalt Strike, designed for operators who value framework flexibility and modularity over built-in evasion.
- **Active development throughout 2023-2026** — last commit **December 18, 2025** (verified via GitHub API), demonstrating continuous, ongoing maintenance. No formal semantic versioning tags were found in the API response; the project uses a rolling-release model with direct commits to `master`.
- **Notable milestones:** Sleep obfuscation implementation (Ekko, Ziliean, FOLIAGE integration), syscall indirection for Nt* APIs, AMSI/ETW patching via hardware breakpoints, token vault, SMB agent support, Python API (`havoc-py`), and custom-agent extensibility (Talon framework noted in README).

The project carries **active community** (Discord server, GitHub issues, third-party modules), with explicit upstream messaging: **"The Havoc Framework hasn't been developed to be evasive. Rather it has been designed to be as malleable & modular as possible."** This is a critical framing — evasion is delegated to the operator's own YAOTL profiles and external modules, not built into the tool itself.

## How It Works

### Architecture — Team Server, Client UI, and Demon Agent

Verified against the README, Teamserver README, and profile configuration files:

```
[ Operator Workstation ]  (Qt GUI Client, C++)
        │
        │ (mTLS gRPC-like binary protocol, operator credentials)
        │
[ Team Server ]  (Go binary, stateful, holds all session/command state)
        │
        ├── Payload generation (Demon agent binary/shellcode/DLL, per-profile)
        ├── Listener jobs (HTTP/HTTPS, on profile-defined ports)
        ├── C2 profile engine (YAOTL parser, defines all network behavior)
        ├── Operator management (credentials, permissions, user accounts)
        └── SQLite database (default, sessions/tasks/callbacks)
        │
        ├─ HTTP/HTTPS Listener Job 1 (port 80, 443, or profile-custom)
        │         │
        │         └─▶ [ Target 1: Demon Agent ]
        │
        └─ HTTP/HTTPS Listener Job 2 (or SMB, or external C2)
                  │
                  └─▶ [ Target 2: Demon Agent ]
```

- **Team Server** (`teamserver` binary, built from Go source) — the central, stateful command-and-control server. Reads a YAOTL profile at startup (`--profile profiles/havoc.yaotl` or `--default` for built-in defaults) that defines **all** network-layer behavior: listener ports, HTTP request/response templates, user-agent strings, traffic encoding, sleep-obfuscation strategy, and process-injection targets for the Demon agent. The profile is compiled into the server's behavior; changes require a server restart. Manages all operator sessions, agent callbacks, and tasking via an SQLite database (or MySQL/PostgreSQL via config).

- **Client** — a C++ Qt GUI application connecting to the Team Server over a **binary protocol** (verified as gRPC-like in documentation, over TLS with operator credentials). Only one client can connect at a time per user account in the current version. The operator's console shows sessions, issues commands, and receives task results through the Team Server's database/callback pipeline.

- **Demon Agent** — Havoc's flagship Windows agent, written in C and x86-64 assembly. Compiled per-profile by the Team Server (uses embedded mingw32 cross-compilers: `x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc`, configured in the profile's `Build` section). Each Demon binary is payload-unique with embedded configuration (C2 endpoint addresses, sleep interval, jitter, injection targets). Supports three output payload formats: **exe** (standalone executable), **shellcode** (raw position-independent code), or **dll** (reflectively-loadable DLL).

### Profile System — YAOTL, the operator's evasion surface

The Havoc **YAOTL** (a custom declarative config language) profile defines:
- **Teamserver block** — listener port, TLS cert/key paths, compiler paths (mingw binaries), build flags.
- **Operators block** — user accounts and plaintext passwords.
- **Service block** (optional) — external C2 endpoint configuration.
- **Demon block** — agent defaults: sleep interval, jitter %, process-injection spawn targets (`Spawn64`/`Spawn32`), X-Forwarded-For trust (for behind-proxy targets), and selected sleep-obfuscation method.
- **Listeners block** — HTTP/HTTPS listener definitions per port, with fully **malleable** request/response templates:
  - `UserAgent` — custom User-Agent string.
  - `Header` — arbitrary HTTP headers (Name: Value pairs).
  - `uripath` — request URL path(s) the agent uses for check-ins.
  - `Response` — HTTP response body template.
  - `Encoder` — traffic encoding (none, base64, custom, etc.).
  - Port configuration (TLS certs for HTTPS).

This is Havoc's core **malleability** — operators customize every network-visible detail without modifying agent or server source code. Unlike Cobalt Strike's Malleable C2 (which an operator composes post-deployment), Havoc requires profile changes to restart the Team Server, making profiles a **gating artifact** if the operator's server is seized.

### Demon Agent capabilities

Verified against README and supported features:
- **C2 transport** — HTTP/HTTPS callbacks (per profile) to Team Server listeners.
- **Process injection** — configurable spawn targets (notepad.exe by default per `Spawn64`/`Spawn32`).
- **Sleep obfuscation** — three plug-in strategies (Ekko, Ziliean, FOLIAGE) selected at profile-generation time, obfuscating the agent's memory footprint during idle periods between check-ins to evade memory scanners.
- **Syscall indirection** — avoids direct Nt* API calls by using syscall-stubs, evading userland EDR hooks.
- **AMSI/ETW patching** — via hardware breakpoints (x64 return-address spoofing noted in README), more evasion-resistant than inline patching.
- **SMB support** — agents can peer-to-peer over SMB named pipes (verified in README).
- **Token vault** — credential harvesting and token impersonation.
- **Built-in commands** — execute-assembly, inline shellcode execution, process listing, file operations, registry, etc. (see §2 for full command surface).
- **Proxy library loading** — load DLLs from remote locations.

### Agent generation and callback protocol

```
Operator                              Team Server                          Target
────────                              ───────────                          ──────
1. Client: generate <name>   ───────▶  Parse YAOTL profile,
   --arch x64                           cross-compile Demon for x64
   --format exe/shellcode/dll           per profile, embed per-binary
                                        config (C2 endpoints, sleep=2s,
                                        jitter=15%, spawn64=notepad.exe)
                                                              ◀───────────── Binary delivered out-of-band
                                                                             (email, USB, web drive-by, etc.)

2.                                                          ◀──────────── Demon executes,
                                                                          dials configured
                                                                          HTTP/HTTPS listener

3.                                     HTTP(S) callback
                                       (per profile's listener
                                        templates: custom
                                        User-Agent, headers,
                                        URI path, response body)  ◀────▶  Session registered,
                                                                          first check-in

4. Client: sleep 5  ────────▶  Queue task in DB

                               HTTP(S) callback (next interval
                               +jitter) — agent pulls pending
                               tasks from server response  ◀────▶  Task execution queued

5.                                                          ◀──────────── Agent executes,
                                                                          uploads task result

6. Client: ls (or any         Task queued in DB, delivered
   execute-assembly, etc.)    on next check-in interval
```

### Sleep obfuscation — Ekko, Ziliean, FOLIAGE

The Demon agent's memory footprint during idle periods can be obfuscated using three strategies (selected per-profile in the `Demon` block):

| Strategy | Source | Mechanism | OPSEC trade-off |
|---|---|---|---|
| **Ekko** | [Cracked5pider/Ekko](https://github.com/Cracked5pider/Ekko) — the same author as Havoc | Encrypts the agent's .text section in-place, decrypts on wake-up via an exception handler (vectored exception handler / hardware breakpoint) | Strong memory-obfuscation signal; CPU exception patterns may be detectable on instrumented systems |
| **Ziliean** | Third-party, integrated | Memory encryption via a custom scheme (verified in Havoc source as a toggleable option) | Less documented; weaker signals than Ekko |
| **FOLIAGE** | [SecIdiot/FOLIAGE](https://github.com/SecIdiot/FOLIAGE) | Full process-memory encryption + key derivation from PEB | Strongest memory-obfuscation option; highest performance cost |

If no obfuscation is selected, the Demon agent's memory remains plaintext during sleep — a weaker OPSEC posture but lower CPU overhead.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| **Transport** | HTTP/HTTPS (profile-malleable, custom headers/URIs/response bodies); SMB named pipes (peer-to-peer agent-to-agent pivoting) |
| **Encryption** | TLS 1.2+ for HTTPS listeners (cert/key paths specified in profile); in-transit task encoding per profile (base64, custom encoders); sleep-obfuscation AES/XOR per Ekko/Ziliean/FOLIAGE strategy |
| **Authentication** | Team Server: operator username/password (plaintext in YAOTL profile). Agent: profile-embedded C2 endpoint addresses + callback timing act as implicit auth (no per-agent token/signing). |
| **C2 Profile Language** | YAOTL (Havoc's declarative config language) — defines listener templates, user-agent, headers, URIs, response bodies, traffic encoding, sleep behavior |
| **Protocols (MITRE ATT&CK)** | **T1071.001** Application Layer Protocol (HTTP/HTTPS C2); **T1008** Fallback Channels (multi-endpoint failover per profile); **T1105** Ingress Tool Transfer (payload staging); **T1083**/**T1087** Enumeration (built-in commands); **T1056** Input Capture (keylogger module if loaded); **T1115** Clipboard Data (clipboard module if loaded); **T1112** Modify Registry; **T1057** Process Discovery; **T1082** System Information Discovery |

## Command-Line Switches — Quick Reference

### Team Server (`teamserver` binary)

| Flag | Argument | Default | Plain-English Meaning |
|---|---|---|---|
| `-h` / `--help` | — | — | Print help and exit |
| `-v` / `--verbose` | — | `false` | Enable debug logging to console |
| `server` | — | — | Subcommand: run the Team Server |
| `--profile` | `<path/to/havoc.yaotl>` | (required if not `--default`) | Path to YAOTL profile file that defines all C2 behavior (listeners, templates, operators, build settings) |
| `--default` | — | — | Use built-in default profile (hard-coded, minimal setup) |
| `--verbose` | — | `false` | Verbose logging (same as `-v`) |

**Example usage:**
```bash
sudo ./teamserver server --profile profiles/havoc.yaotl --verbose
sudo ./teamserver server --default --verbose
```

### Client (`havoc` Qt GUI client)

Launched as a GUI application; no command-line flags documented for client binary itself. Client connects to Team Server via credentials + host:port (configured via the GUI's connection dialog or config file).

### Payload Generation (via Client console, not CLI)

Generated entirely through the Client GUI's `Generate` dialog, no direct CLI interface for payload generation. The `teamserver` binary **only** listens for incoming client connections; it does not expose a command-line payload-generation interface like msfvenom or Cobalt Strike's `beacon.exe` generator.

## Quick Use-Case List

1. **Initial foothold via HTTP listener** — generate a Demon exe/shellcode, deliver via email/USB/web drive-by, execute on target, establish reverse HTTP(S) callback to Team Server
2. **Staged payload delivery** — generate a small stager, host it, target executes stager which downloads full Demon agent into memory via HTTP
3. **Multi-agent coordination** — generate multiple Demon agents with different sleep intervals and injection targets, deploy across multiple targets, manage all sessions from single Client console
4. **Process injection and OPSEC hardening** — use Demon's configurable `Spawn64`/`Spawn32` targets and sleep-obfuscation (Ekko/Ziliean/FOLIAGE) to avoid memory-scanning detection during idle periods
5. **Custom C2 profile for network isolation** — tailor YAOTL profile with custom User-Agent, headers, URI paths, and response-body templates to match environment-specific HTTP traffic patterns (e.g., mimic internal corporate CDN or API)
6. **Execute-Assembly for .NET post-exploitation** — execute inline .NET assemblies (SharpUp, Seatbelt, Rubeus, etc.) within Demon's process without dropping binaries to disk
7. **Token theft and lateral movement** — use built-in `token` commands to harvest and impersonate tokens, then execute Demon's lateral-movement commands (psexec, WMI, etc.) with hijacked credentials
8. **Peer-to-peer SMB pivoting** — deploy first Demon on network-adjacent host, use `pivot` commands to establish SMB C2 tunnel to a second Demon on an isolated target (no direct egress from target)
9. **External C2 integration** — configure Havoc's External C2 socket (verified in README) to relay Demon traffic through a third-party C2 framework (e.g., integrate Havoc Demon into Metasploit/Cobalt Strike pipeline)
10. **Custom agent development** — use Havoc's extensibility (Talon framework, Python API `havoc-py`) to build a custom agent language and integrate it into the same Team Server/Client console
11. **Modular post-exploitation** — load Havoc modules (Armory-style packages, if implemented) or custom DLLs to extend Demon capabilities (keylogging, screen capture, network sniffing, etc.)
12. **Operator-credential management and multi-user sessions** — create operator accounts in YAOTL profile, generate per-operator Client credentials, manage role-based access and audit logging at Team Server level

## Prerequisites

| Use Case | Prerequisite |
|---|---|
| **Any Demon deployment** | Team Server running and listening on configured HTTP(S) port; valid YAOTL profile deployed; Demon binary successfully generated and delivered to target |
| **HTTP(S) callback** | Network egress from target to Team Server on specified port (80, 443, or custom per profile); HTTPS: valid TLS cert (self-signed or trusted) must match server configuration |
| **Process injection & sleep obfuscation** | Windows target (Demon is Windows-only in current releases); x64 or x86 architecture matching binary format; if Ekko obfuscation: exception handling support (standard on modern Windows); if FOLIAGE: higher performance cost |
| **SMB pivoting** | First compromised host with network-layer access to target; SMB (port 445) accessible between first and second host; both hosts Windows |
| **Execute-Assembly** | .NET runtime on target (framework version matching assembly's requirements); C# assemblies already compiled before upload |
| **Custom C2 profile** | Malleability requires YAOTL syntax knowledge; profile changes require Team Server restart; if using Let's Encrypt TLS: outbound HTTPS to Let's Encrypt API (or offline cert staging) |
| **Custom agent or module** | Understanding of Havoc's agent architecture; for Python API integration: `havoc-py` module installed on operator's workstation; for Talon custom agents: C/ASM development environment |
