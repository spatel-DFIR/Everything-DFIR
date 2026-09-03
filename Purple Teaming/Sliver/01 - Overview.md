# Sliver — Overview

> 🔴 **Red Flag Principle:** Sliver implants are **dynamically compiled per-generation** — every binary gets a fresh asymmetric keypair, a randomized set of C2 endpoint values, and (unless `--skip-symbols` is dropped) obfuscated symbols, so there is no stable file hash, PE metadata, or static string to blocklist across an engagement. The durable detection surface is **behavioral and protocol-level**: procedurally-generated but structurally consistent HTTP(S) URL patterns per C2 profile, the mTLS/gRPC handshake shape between implant and server, DNS query patterns for `dns` C2, and — most reliably — the beacon check-in cadence itself (interval + jitter) once a candidate host is identified. Chase the traffic pattern, not the binary.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Sliver is developed and maintained by **[Bishop Fox](https://bishopfox.com/tools/sliver)**, a professional offensive-security consultancy, as an open-source **"Adversary Emulation Framework."** The canonical upstream repository is [`github.com/BishopFox/sliver`](https://github.com/BishopFox/sliver), licensed under **GPLv3**. Verified directly against the repo/release metadata via the GitHub API (not memory):

- **Repository created 2019-01-17.** Sliver was built explicitly as a red-team-usable, cross-platform alternative in the space Cobalt Strike and Meterpreter occupied — Go's native cross-compilation was the core design bet (one codebase, implants for Windows/macOS/Linux with no separate per-OS toolchain).
- **`v0.0.5-alpha` (2019-06-03)** — earliest tagged public release.
- **`v1.0.0-beta` (2020-05-15)** — first beta of the 1.x line, the point at which the current mTLS/HTTP(S)/DNS multi-transport architecture was already the framework's core design.
- **`v1.5.0` (2022-01-24)** — introduced the **Armory** package manager for aliases and BOF/extension distribution (see [Extensions/Armory](#extensionsarmory-ecosystem) below), formalizing third-party tool integration (Rubeus, Seatbelt, SharpWMI, etc.) as an install-on-demand system rather than manual DLL/assembly staging.
- **`v1.6.0`** — a console/CLI rewrite onto the `spf13/cobra` command framework (replacing the earlier `desertbit/grumble` REPL), the version this note's command syntax is verified against.
- **`v1.7.3`** — current latest tagged release at time of writing; this note's flags and defaults are verified against the `master` branch source as of this build.

At the time of writing the repository carries **11,600+ GitHub stars**, actively maintained (commits landing on `master` within the current week).

## How It Works

### Architecture — four components, one RPC surface

Verified against the project's own (historical, now-migrated-to-`sliver.sh/docs`) wiki **Architecture** page, cross-checked against current source:

> "There are four major components to the Sliver ecosystem: **Server Console**, **Sliver Server**, **Client Console**, **Implant**. ... By implementing all functionality over this gRPC interface, and only differing the in-memory/mTLS connection types, the client code doesn't 'know' if it's running in the server console or the client console."

```
[ Server Console ] --(In-Memory gRPC)--> [ Sliver Server ] --(mTLS / HTTP(S) / DNS / WireGuard)--> [ Implant ]
                                                ^
                                                |
                                           (mTLS gRPC, multiplayer)
                                                |
                                        [ Client Console ]  (one or more operators)
```

- **Sliver Server** (`sliver-server` binary) — the central process: manages the implant/loot/task database (SQLite by default via GORM, with MySQL/PostgreSQL supported as alternate backends per the server's ORM driver dependencies), starts/stops C2 listener jobs, and exposes **all** functionality over a single gRPC API. By default this gRPC interface is **in-memory only**, reachable exclusively from the server's own built-in console.
- **Multiplayer mode** — running `operator --name <op> --lhost <ip> --lport <port> --permissions <perms> --save <path>` on the server (verified against `server/cli/operator.go`) generates a `.cfg` operator config file containing an mTLS client certificate. Distributing that file lets a `sliver-client` instance connect to the server's gRPC interface over the network, authenticated by mutual TLS — this is what "multiplayer" means: multiple operators, same server, same session/beacon state, each cryptographically distinct.
- **Client Console** — the operator-facing console (`sliver-client`, or the in-process console on the server itself). Because both share the same command implementations against the same gRPC contract, every command behaves identically whether you're on the server box or connecting remotely.
- **Implant** — the Go binary (or shellcode/shared-library/service/archive, depending on `--format`) that runs on the target and talks back to the server over one of the configured C2 channels.

### Implant generation — one build, embedded config

`generate` (see the switches table below) compiles a fresh implant server-side using the server's embedded Go toolchain, cross-compiling for the requested `--os`/`--arch` pair. Each build embeds:
- A **per-binary asymmetric keypair** (mTLS certs / WireGuard keys / HTTP encryption keys depending on transport) — no two implants share key material even from the same profile.
- The **C2 endpoint configuration** — one or more transport connection strings (`--mtls`, `--http`, `--dns`, `--wg`, `--named-pipe`, `--tcp-pivot`), tried in order or per `--strategy` (random / random-domain / sequential) with `--reconnect`/`--poll-timeout`/`--max-errors` governing retry behavior.
- Optional **execution limits** (`--limit-datetime`, `--limit-domainjoined`, `--limit-username`, `--limit-hostname`, `--limit-fileexists`, `--limit-locale`) — implant self-checks that abort execution outside a defined target scope, a sandbox/OPSEC control.

### Sessions vs. Beacons — the core operational fork

Sliver implants ship in two behavioral modes, selected at generation time:

| | **Session** (`generate`) | **Beacon** (`generate beacon`) |
|---|---|---|
| Connection model | Persistent, synchronous — implant holds an open connection and executes commands in near-real-time | Asynchronous — implant connects, pulls any queued tasks, executes them, uploads results, then **disconnects** until the next interval |
| Check-in behavior | Continuous | Interval-driven: `--days`/`--hours`/`--minutes`/`--seconds` (default 60s) plus `--jitter` (default 30s) of randomized additional delay per check-in |
| OPSEC posture | Higher network footprint — a live connection is easier to fingerprint via duration/volume | The more OPSEC-conscious default for long engagements — short, infrequent, jittered check-ins blend into background traffic far more easily |
| Operator experience | Interactive, like a shell | Commands are **queued** against the beacon and collected on its next check-in — not instant |

Both modes support the full command surface (`execute-assembly`, `sideload`, filesystem, process, pivoting, etc.) — the difference is purely the connection/scheduling model, not available capability.

### C2 channel options

| Transport | Generate flag | Listener command | Default port | Notes |
|---|---|---|---|---|
| Mutual TLS (mTLS) | `--mtls` | `mtls` | TCP **8888** | The framework's original/native transport — implant and server hold matching client/CA certs, gRPC directly over mTLS |
| HTTP(S) | `--http` | `http` / `https` | TCP **80** / **443** | Procedurally-generated URL paths per C2 profile (`--c2profile`) so requests don't share a static path signature; HTTPS supports `--cert`/`--key` or `--lets-encrypt` |
| DNS | `--dns` | `dns` | UDP **53** | Requires the operator to control a delegated domain (an `NS` record pointed at the listener) since resolution has to reach the Sliver server; `--no-canaries` disables built-in DNS-canary-domain monitoring evasion |
| WireGuard | `--wg` | `wg` | UDP **53** (listener default), plus a virtual-interface port (**8888**) and key-exchange port (**1337**) | A full VPN tunnel used as a C2 transport — least common in the wild, but gives the implant a routable virtual IP on the operator's WG interface |
| Named Pipe (SMB pivot) | `--named-pipe` | `pivots named-pipe` (session-level) | n/a (SMB/IPC) | Peer-to-peer — one already-compromised implant pivots C2 traffic for a second implant over an SMB named pipe, no direct egress needed from the second host |
| TCP pivot | `--tcp-pivot` | `pivots tcp` | TCP **9898** (default) | Same peer-to-peer pivot concept as named-pipe, over raw TCP instead of SMB — useful cross-platform (named-pipe pivoting is Windows-only) |

**Correction worth flagging:** several older tutorials and the pre-2022 project wiki document `named-pipe` and `tcp-pivot` as flat, top-level session commands. Verified against the current `master` branch (`client/command/pivots/commands.go`), both now live as **subcommands of `pivots`** — `pivots named-pipe` and `pivots tcp` — part of the same cobra-based CLI restructure noted in History above.

### Staged vs. stageless payloads

By default `generate` produces a **stageless** implant — the full binary, embedded config and all, delivered in one shot. For size-constrained delivery contexts, `generate stager` produces a small stub that connects to a `stage-listener` job and downloads the full implant (Sliver-format shellcode, or via `msfvenom`) into memory at runtime — see `02 - Hands-On Use Cases.md`'s staging scenario.

### In-memory execution & lateral tradecraft surface

- **`execute-assembly`** — loads and runs a .NET assembly in a **sandboxed child process** by default (`--process`, default `notepad.exe`), or in the implant's own process with `--in-process` (which also unlocks `--amsi-bypass`/`--etw-bypass`). This is Sliver's direct answer to Cobalt Strike's `execute-assembly` / Meterpreter's `execute -m` — the mechanism red teams use to run SharpUp, Seatbelt, Rubeus, etc. without dropping a binary to disk.
- **`sideload`** — loads and executes a shared library (DLL/`.so`/`.dylib`) in a remote/hosting process, unmanaged-code equivalent of `execute-assembly`.
- **`spawn-dll`** — loads and executes a **Reflective DLL** in a remote process (`--export`, default entrypoint `ReflectiveLoader`).
- **`migrate`** — moves the implant's running context into another process by PID or name, with an optional `--shellcode-encoder` applied to the migration shellcode.
- **`execute-shellcode`** — runs raw shellcode in the implant's own process (`--pid 0`) or injects into another PID, with an optional Shikata Ga Nai (`--shikata-ga-nai`) encoding pass and Donut-based shellcode-generation options for PE→shellcode conversion (entropy, compression, exit behavior).
- **`psexec`** — Sliver's own PsExec-style remote-service execution against a Windows host, generating (or using a `--custom-exe`) a service binary and registering it via `--service-name`/`--service-description`.
- **`msf` / `msf-inject`** — executes or injects a Metasploit payload (`--payload`, default `meterpreter_reverse_https`) directly from the implant, bridging into the MSF ecosystem without a separate handoff tool.

### Armor/evasion options

The `generate`/`profiles new` flag set includes `-e, --evasion` — described directly in source as enabling **"evasion features (e.g. overwrite user space hooks)"** — i.e. patching/unhooking userland API hooks that EDR products place for telemetry. Beyond that single flag, the broader evasion surface is compositional rather than one switch:

- **`--skip-symbols`** — skips Go symbol-table obfuscation (obfuscation is applied **by default**; this flag turns it *off*, useful for debugging, not for stealth).
- **`--shellcode-encoder`** at generate/migrate/execute-shellcode time — Sliver ships its own **Shikata Ga Nai** implementation (the same polymorphic XOR-additive-feedback encoder used by `msfvenom`), plus `xor` and `xor_dynamic` encoders, selectable per shellcode artifact.
- **Traffic encoders** (`generate traffic-encoders`) — WASM-based pluggable encoders for the wire format of C2 traffic itself, added/managed server-side (`traffic-encoders add/rm`), layered independently of shellcode encoding.
- **`--spoof-metadata`** — overwrites PE version-info/metadata fields (or copies them from a donor executable) so the compiled implant's file properties don't read as a generic Go binary.
- **Donut-based shellcode conversion options** (`--shellcode-entropy`, `--shellcode-compress`, `--shellcode-thread`, etc.) for PE→shellcode transforms on Windows shellcode formats.

The project's own stance (per its wiki's Anti-Virus Evasion page): AV/EDR evasion is explicitly **out of primary project scope** — Sliver aims to be *interoperable* with external evasion tooling (packers, crypters, external builders) rather than to win the AV arms race itself. Bishop Fox's own public messaging frames Sliver as an adversary-emulation/detection-engineering tool, not a "stay undetected" product — treat any evasion claim beyond what's verified above with that framing in mind.

### Extensions/Armory ecosystem

The **Armory** (`armory` command, introduced v1.5.0) is Sliver's package manager for **aliases** (wrapping a standalone executable, e.g. a .NET assembly, as a native console command) and **extensions** (implant-loaded capability, including **BOF/COFF** — Beacon Object File / Common Object File Format — support added alongside Armory in v1.5). `armory search <regex>`, `armory install <name>`, `armory update` pull from the default `https://sliver.re` armory index (or an operator-added custom armory via `armory add`); installed packages surface as new top-level console commands (e.g. installing the community `Rubeus` package adds a `rubeus` command). BOF execution generally requires no code changes on Sliver's side — only a manifest (`alias.json`/extension manifest) describing arguments/types — meaning the same BOF ecosystem used by Cobalt Strike/Havoc is largely portable into Sliver. See `extensions load/install/rm/list` for locally-sourced (non-Armory) extensions.

### Protocol sequence — generate → listen → callback → task

```
Operator                              Sliver Server                         Target/Implant
────────                              ─────────────                         ──────────────
1. mtls -L 0.0.0.0 -l 8888   ────────▶ Listener job started
   (or http/https/dns/wg)              (jobs table entry)

2. generate --mtls <serverIP>:8888
   --os windows --arch amd64  ────────▶ Server compiles Go implant,
                                         embeds per-binary keypair +
                                         C2 config    ◀──────────────────── Compiled binary
                                                                              delivered to target
                                                                              (out of band — email,
                                                                               drive-by, USB, etc.)

3.                                                          ◀──────────────  Implant executes,
                                                                              dials configured C2
                                                                              endpoint(s) per
                                                                              --strategy

4.                                     mTLS/gRPC (or HTTP(S)/
                                        DNS/WG) handshake completes  ◀─────▶  Session established
                                        (session) or first check-in
                                        recorded (beacon)

5. Session/beacon shows in
   `sessions`/`beacons`        ◀────── Operator issues commands
                                        (execute-assembly, sideload,
                                        filesystem, etc.)             ────▶  Beacon: queued until
                                                                              next check-in interval
                                                                              (+jitter). Session:
                                                                              executed near-immediately
```

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| C2 transport | mTLS (TCP 8888 default), HTTP/HTTPS (TCP 80/443 default), DNS (UDP 53 default), WireGuard (UDP 53 listener default + 8888/1337 auxiliary) |
| Pivoting | SMB named-pipe pivot (Windows-only, peer-to-peer through an already-compromised host), raw TCP pivot (cross-platform) |
| Cryptography | Mutual TLS + RSA for key exchange (implant/server certs); AES-GCM-256 for session-key encryption of gRPC/application-layer traffic — per MITRE ATT&CK's S0633 entry |
| In-memory execution | .NET assembly execution (`execute-assembly`), unmanaged DLL/shared-object sideloading (`sideload`), Reflective DLL injection (`spawn-dll`), raw shellcode execution/injection (`execute-shellcode`), process migration (`migrate`) |
| Credential access | Built-in `procdump`-style LSASS memory dumping (MITRE-documented capability) |
| Discovery | Filesystem enumeration, network configuration/connection discovery, process listing |
| Proxying/tunneling | Built-in SOCKS5 proxy, port forwarding, reverse port forwarding |
| Extension ecosystem | BOF/COFF loading, .NET-assembly and shared-library aliases via the Armory package manager |
| Obfuscation | Go symbol-table obfuscation (`garble`/`gobfuscate`-style, default-on unless `--skip-symbols`), compile-time string encryption, Shikata Ga Nai / XOR shellcode encoders |

## Command-Line Switches — Quick Reference

All flags below verified directly against `master`-branch source in [BishopFox/sliver](https://github.com/BishopFox/sliver) (`client/command/generate/commands.go`, `client/command/jobs/commands.go`, `client/command/pivots/commands.go`, `client/command/exec/commands.go`, `client/command/armory/commands.go`) — not from memory or secondhand tutorials, several of which document stale flag/command names (see the pivot-command correction above).

**`generate` / `generate beacon` — core implant-compile flags**

| Switch | Plain-English meaning |
|---|---|
| `-o, --os` | Target OS to compile for (default `windows`) |
| `-a, --arch` | Target CPU architecture (default `amd64`) |
| `-N, --name` | Explicit agent/implant name (random codename if omitted) |
| `-f, --format` | Output artifact type: `exe`, `shared` (DLL/`.so`), `archive` (Go c-archive), `service` (for `psexec`), or `shellcode` |
| `-e, --evasion` | Enable evasion features (e.g. overwrite userland API hooks) |
| `-l, --skip-symbols` | Skip Go symbol-table obfuscation (obfuscation is on by default) |
| `--shellcode-encoder` | Apply a shellcode encoder (`shikata_ga_nai`, `xor`, `xor_dynamic`) to shellcode-format output |
| `-v, --exports` | Comma-separated DLL export names for `shared`-format implants |
| `-c, --canary` | Embed a DNS canary domain — pings that domain if the binary is decompiled/analyzed under conditions that would trigger it |
| `-m, --mtls` | mTLS C2 connection string(s) |
| `-g, --wg` | WireGuard C2 connection string(s) |
| `-b, --http` | HTTP(S) C2 connection string(s) |
| `-n, --dns` | DNS C2 connection string(s) |
| `-p, --named-pipe` | Named-pipe pivot connection string (format `HOSTNAME//./pipe/NAME`) |
| `-i, --tcp-pivot` | TCP-pivot connection string (format `IP:PORT`) |
| `--all-protocols` | Force-include every supported transport regardless of what's explicitly specified |
| `-Z, --strategy` | Multi-endpoint connection order: `r` (random), `rd` (random domain), `s` (sequential) |
| `-j, --reconnect` | Seconds between reconnect attempts (default per source) |
| `-P, --poll-timeout` | Long-poll request timeout |
| `-k, --max-errors` | Max consecutive connection errors before giving up |
| `-C, --c2profile` | HTTP C2 profile to use (URL/header shaping) |
| `-w, --limit-datetime` / `-x, --limit-domainjoined` / `-y, --limit-username` / `-z, --limit-hostname` / `-F, --limit-fileexists` / `-L, --limit-locale` | Execution guardrails — implant self-checks that abort outside the defined target scope |
| `--spoof-metadata` | Spoof PE version-info metadata (optionally from a donor executable) |
| `-s, --save` | Directory/file path to save the compiled implant to *(compile-time only, not on profiles)* |

**`generate beacon` — additional interval flags**

| Switch | Plain-English meaning |
|---|---|
| `-D, --days` / `-H, --hours` / `-M, --minutes` / `-S, --seconds` | Beacon check-in interval (seconds defaults to 60 if none specified) |
| `-J, --jitter` | Random additional delay (seconds) added per check-in, default 30 |

**Listener jobs (`mtls`, `wg`, `dns`, `http`, `https`)**

| Switch | Plain-English meaning |
|---|---|
| `-L, --lhost` | Interface/IP to bind the listener to |
| `-l, --lport` | Listen port (defaults: mTLS 8888, WG 53, DNS 53, HTTP 80, HTTPS 443) |
| `-d, --domains` *(dns)* | Parent domain(s) delegated to this DNS listener |
| `-c, --no-canaries` *(dns)* | Disable DNS-canary-domain monitoring |
| `-d, --domain` *(http/https)* | Limit responses to a specific Host header/domain |
| `-w, --website` *(http/https)* | Serve a configured decoy website alongside C2 (see `websites` command) |
| `-D, --disable-otp` *(http/https)* | Disable one-time-password request authentication |
| `-c, --cert` / `-k, --key` *(https)* | Supply a PEM cert/key pair manually |
| `-e, --lets-encrypt` *(https)* | Auto-provision a Let's Encrypt certificate |
| `-n, --nport` / `-x, --key-port` *(wg)* | WireGuard virtual-interface data port / key-exchange port |

**Pivot listeners (session-level: `pivots named-pipe`, `pivots tcp`)**

| Switch | Plain-English meaning |
|---|---|
| `-b, --bind` | Named-pipe name (`named-pipe`) or interface to bind (`tcp`) |
| `-a, --allow-all` *(named-pipe)* | Allow any local user to connect to the pivot pipe, not just the implant's own security context |
| `-l, --lport` *(tcp)* | TCP pivot listen port (default 9898) |

**In-memory execution (`execute-assembly`, `sideload`, `spawn-dll`, `migrate`, `execute-shellcode`)**

| Switch | Plain-English meaning |
|---|---|
| `-p, --process` | Hosting/target process for injection (default varies by command, often `notepad.exe`) |
| `-i, --in-process` *(execute-assembly)* | Run the assembly inside the implant's own process instead of spawning a sandboxed child |
| `-M, --amsi-bypass` / `-E, --etw-bypass` *(execute-assembly, with `--in-process`)* | Patch AMSI / ETW before loading the assembly |
| `-m, --method` / `-c, --class` *(execute-assembly)* | Method/class entrypoint for a .NET DLL (required for DLLs, not EXEs) |
| `-a, --arch` *(execute-assembly)* | Target architecture: `x86`, `x64`, or `x84` (both) |
| `-e, --entry-point` *(sideload)* | DLL export/entrypoint to call |
| `-e, --export` *(spawn-dll)* | Reflective DLL export entrypoint (default `ReflectiveLoader`) |
| `-p, --pid` / `-n, --process-name` *(migrate)* | Target process to migrate into, by PID or name |
| `-S, --shikata-ga-nai` *(execute-shellcode)* | Encode shellcode with Shikata Ga Nai before execution |
| `-r, --rwx-pages` *(execute-shellcode)* | Use RWX memory page permissions instead of the default RX-after-write pattern |

**Armory / Extensions**

| Switch | Plain-English meaning |
|---|---|
| `armory search <regex>` | Search the configured armory index by name |
| `armory install <name>` `-f, --force` | Install a package, optionally overwriting an existing copy |
| `armory update` | Update all installed aliases/extensions |
| `extensions load <path>` | Temporarily load an extension from a local directory (not via Armory) |
| `extensions install <path/.tar.gz>` | Permanently install a local extension |

## Quick Use-Case List

- Standing up a multiplayer server and issuing an mTLS operator config for a second analyst/operator
- Starting an mTLS listener and generating a matching session implant (baseline case)
- Generating a **beacon** implant with a tuned interval/jitter for a long, low-noise engagement
- Standing up an HTTP(S) listener with a custom C2 profile for egress-friendly, web-blending traffic
- Standing up a DNS listener for environments with tightly restricted HTTP(S)/direct-TCP egress but permissive internal DNS resolution
- Building a staged payload (small stager + `stage-listener`) for size-constrained delivery
- Catching an implant's first callback and triaging session vs. beacon metadata
- Running `execute-assembly` to execute .NET tooling (Seatbelt, Rubeus, SharpWMI, etc.) in-memory in a target process
- `sideload`ing an unmanaged DLL/shared object into a remote process
- `migrate`-ing the implant into a longer-lived host process for persistence/OPSEC
- Running raw shellcode via `execute-shellcode`, optionally Shikata-Ga-Nai-encoded
- Pivoting a second implant through a compromised host via SMB named-pipe C2 (no direct egress needed from the second host)
- Pivoting via raw TCP where SMB isn't available or the target is non-Windows
- Installing and running a third-party BOF/.NET tool via the Armory (`armory install`) rather than manual staging
- Using `psexec` for lateral movement/remote service execution against a Windows host with valid credentials
- Injecting/executing a Metasploit payload from within a Sliver implant (`msf`/`msf-inject`) to bridge into MSF tradecraft
- Pivoting network access through an implant with SOCKS5 proxying or port-forwarding rather than executing commands directly
- Dumping LSASS memory for offline credential extraction (built-in `procdump`-style capability)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Server infrastructure | A host to run `sliver-server` — self-contained (single binary), no external database service required by default (SQLite embedded) |
| Network egress from target | At least one C2 transport must be reachable from the target: direct TCP/UDP to the server (mTLS/HTTP/WG), or DNS resolution reaching a domain delegated to the Sliver DNS listener, or SMB/TCP reachability to a pivot host for peer-to-peer variants |
| DNS delegation (DNS C2 only) | Operator must control a registered domain and configure its `NS` record(s) to point at the Sliver DNS listener — DNS C2 does not work without this delegation |
| TLS certificate (HTTPS with `--lets-encrypt`) | The HTTPS listener's bound host/port must be reachable from the internet on the relevant port for ACME HTTP-01 challenge validation, or a manually supplied `--cert`/`--key` pair used instead |
| Multiplayer mode | An operator config (`.cfg`) generated server-side via `operator --name ... --lhost ... --lport ... --permissions ...`, distributed out-of-band to each additional operator |
| `execute-assembly` / `sideload` / `spawn-dll` | Windows target (all three are Windows-only mechanisms); a running session or beacon with sufficient privilege in the target process context |
| Named-pipe pivoting | Windows targets on both ends (pivot host and pivoted implant); SMB/IPC reachability between them |
| Armory installs | Outbound HTTPS reachability from the **operator's** client machine to the armory index (default `sliver.re`) at install time — not from the target |