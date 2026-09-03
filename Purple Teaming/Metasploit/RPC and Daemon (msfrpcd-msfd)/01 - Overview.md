# Metasploit — RPC and Daemon (msfrpcd / msfd) — Overview

> 🔴 **Red Flag Principle:** these two daemons trade msfconsole's interactivity for network reachability, and each does it with a different — and differently dangerous — trust model. **`msfd` (default TCP/55554) ships a full, shared, interactive `msfconsole` session to *anyone who can open a TCP socket to it* — no username, no password, nothing. The plugin's own source comment says it outright: "the console instance that spawns on the port is entirely unauthenticated, so realize that you have been warned."** `msfrpcd` (default TCP/55553) is authenticated and TLS-wrapped by default, but the entire API is one HTTP endpoint carrying MessagePack — `POST /api`, `Content-Type: binary/message-pack` — so a single captured token, or the `-U`/`-P` credentials themselves if an operator ran with `-S` (disable SSL), is full remote control over module execution, live sessions, and the credential/loot database. Either daemon reachable from an unexpected network is a critical finding on its own — this is Metasploit's actual remote-control surface, not a side feature.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Both daemons are older than most operators assume. Metasploit's public GitHub mirror ([`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework), 3-clause BSD license, maintained by **Rapid7, Inc.** — see `../00 - Metasploit Overview.md` for the Framework's own 2003 origin) preserves the project's earlier Subversion history, and the earliest traceable commits against each daemon's current source path give a verifiable, if approximate, timeline:

| Component | Earliest traceable commit | Message |
|---|---|---|
| `plugins/msfd.rb` | **2005-11-28** (SVN r3151) | *"implemented msfd as a plugin"* |
| `msfrpcd` (root script) | **2008-12-02** | *"This patch introduces a really basic RPC service. It is still a long way from its final version"* |
| `plugins/msgrpc.rb` (the MessagePack backend `msfrpcd` invokes today) | **2011-05-14** | *"This adds a basic RPC server that operates over HTTP and uses MessagePack. The client/server wrappers are still being finalized."* |

Read together, this traces a real architectural shift: **`msfd`** (2005) is the original, console-sharing remote-access mechanism, predating even the Ruby 3.0 rewrite's public completion. **`msfrpcd`** (2008) introduced a structured RPC service — the Ruby client (`lib/msf/core/rpc/v10/client.rb`) still carries a now-unused `require 'xmlrpc/client'` line, a fossil of that original transport. **`msgrpc`** (2011) replaced the wire format with **MessagePack over HTTP**, and is the plugin `msfrpcd` loads by default today (the script sets `RPC_TYPE = 'Msg'` and loads the plugin named `#{RPC_TYPE.downcase}rpc` — i.e. `msgrpc`). A separate, newer **JSON-RPC** mode (`msfrpcd -j`) also exists in current source, backed by a Thin web server rather than the classic MessagePack path — see [How It Works](#how-it-works) below. **This timeline reflects the earliest commit touching each file's current path in the public git history; it does not claim these are the components' literal first-ever lines of code, since earlier renames/moves in the pre-GitHub SVN tree aren't fully traceable from the API used to verify this.**

## How It Works

### msfrpcd / msgrpc — authenticated MessagePack-RPC over HTTP(S)

`msfrpcd` is a thin wrapper: parse CLI flags, then hand off to `Msf::Simple::Framework.create` and load the `msgrpc` plugin, which stands up an `Msf::RPC::Service` — an `Rex::Proto::Http::Server` instance bound to one URI (default `/api`) that accepts `POST` requests only, with a `Content-Type` of exactly `binary/message-pack`. Every request body is a **MessagePack-encoded array**: `[method_name, token_if_required, *args]`. Every response body is the same format back.

```
Client (Ruby / Python / curl+msgpack)                    msfrpcd (Msg RPC Service on :55553)
──────────────────────────────────────                    ────────────────────────────────────
1. POST /api  Content-Type: binary/message-pack
   body = msgpack(["auth.login", "<user>", "<pass>"])
                                                ────────▶  RPC_Auth#rpc_login_noauth checks
                                                             in-memory users + DB-backed
                                                             Mdm::ApiKey records. On failure:
                                                             401, plus a random 0.5-3.5s stall
                                                             (anti-bruteforce)
                                                ◀────────  {"result":"success",
                                                             "token":"TEMP"+28 random alnum
                                                             chars (32 total)}

2. POST /api
   body = msgpack(["console.create", "<token>"])
                                                ────────▶  spins up a hidden Msf::Ui::Web::Driver
                                                             console instance, tracked by an
                                                             internal id
                                                ◀────────  {"id":"0","prompt":"msf6 > ","busy":false}

3. POST /api
   body = msgpack(["console.write","<token>","0",
                    "use exploit/windows/smb/ms17_010_eternalblue\r\n"])
                                                ────────▶  writes bytes into that console's
                                                             input stream — same as typing
                                                             at an interactive prompt
                                                ◀────────  {"wrote": 47}

4. POST /api
   body = msgpack(["console.read","<token>","0"])
                                                ────────▶  drains buffered console output
                                                             produced since the last read
                                                ◀────────  {"data":"...","prompt":"msf6 exploit(...) > ",
                                                             "busy":false}
```

Every RPC token is issued by `auth.login` and stored server-side in `service.tokens`, keyed with creation/last-use timestamps; a token not explicitly made permanent (`auth.token_add`/`auth.token_generate`, or a `Mdm::ApiKey` row when the database is connected) is purged after `TokenTimeout` seconds of inactivity (default **300s / 5 minutes**, `-t` to override). Nine handler groups make up the API surface — `health`, `core`, `auth`, `console`, `module`, `session`, `job`, `db`, `plugin` — see the method tables below. Critically, `console.*` means **the entire `search`/`use`/`set`/`run` vocabulary documented in `../msfconsole/01 - Overview.md` is reachable over this API** — RPC doesn't replace msfconsole's command surface, it relays it. `module.execute` is the alternative, non-interactive path: fire a module directly with an options hash and poll for results via `module.results`/`module.ack`, no console instance needed at all.

A newer code path (`msfrpcd -j`) skips the classic MessagePack service entirely and instead starts a **Thin-based JSON-RPC web service** (config `msf-json-rpc.ru`) at `/api/v1/json-rpc`, using TLS certs generated by `msfdb init` (`~/.msf4/msf-ws-key.pem` / `~/.msf4/msf-ws-cert.pem`) by default. This is a separate implementation from the MessagePack path above, not just a different serialization of the same server.

### msfd — raw, unauthenticated console-over-TCP

`msfd` is mechanically much simpler, and that simplicity is exactly the finding: it opens a raw `Rex::Socket::TcpServer` (optionally TLS-wrapped with `-s`), and on every accepted connection, hands the socket directly to a **new `Msf::Ui::Console::Driver` instance** — the same driver class that backs interactive `msfconsole` — wired so its input/output stream *is* that TCP socket. There is no login step, no token, no `Content-Type` check, nothing to parse: connect, and you have a live `msf6 >` prompt against the framework instance running on that host, banner included unless `-q` suppressed it. Every connected client shares **the same underlying `Msf::Simple::Framework` instance** — one process, one module cache, one set of active sessions and (if connected) one database — so two people connected to the same `msfd` at once are working against the same live state, not isolated sandboxes.

```
Client (netcat / telnet / ncat)                           msfd (TCP :55554)
────────────────────────────────                           ──────────────────
1. TCP connect to <host>:55554  ─────────────────────────▶  Rex::Socket::TcpServer#accept.
                                                              NO credential exchange of any kind.
2. (nothing sent by client)      ◀───────────────────────   Framework banner (unless -q) +
                                                              "msf6 > " prompt streamed
                                                              immediately over the raw socket
3. search eternalblue\r\n        ─────────────────────────▶  Msf::Ui::Console::Driver processes
                                                              it exactly as if typed locally
```

The only compensating controls `msfd` offers are network-layer, not credential-layer: `-A`/`-D` allow/deny lists checked against the connecting peer's resolved address before the driver is even spawned, and whatever host binding (`-a`, default loopback-only) and OS firewall sit in front of it.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport (msfrpcd / msgrpc) | HTTP or HTTPS — TLS enabled and a self-signed cert used **by default**; `-S` disables TLS entirely, leaving MessagePack (including credentials and every token) in cleartext |
| Serialization (msfrpcd / msgrpc) | MessagePack — `Content-Type: binary/message-pack`. Request body: `[method, token(if the method requires auth), *args]`. Response body: a MessagePack-encoded Hash |
| Auth (msfrpcd / msgrpc) | `auth.login(user, pass)` → temporary token (`"TEMP"` + 28 random alphanumeric chars, 32 total), expires after `TokenTimeout` inactivity (default 300s) unless made permanent via `auth.token_add`/`auth.token_generate` or backed by a `Mdm::ApiKey` database row |
| RPC surface (msfrpcd / msgrpc) | 9 handler groups — `health` (unauthenticated liveness check), `core`, `auth`, `console`, `module`, `session`, `job`, `db`, `plugin` |
| JSON-RPC mode (msfrpcd -j) | Separate implementation — Thin web server, `POST /api/v1/json-rpc`, TLS certs sourced from `msfdb init`'s generated key/cert pair by default |
| Transport (msfd) | Raw TCP, optionally SSL-wrapped (`-s`) — no framing protocol, no content negotiation, no auth of any kind |
| Underlying execution | Whatever the driven module implements — identical to `../msfconsole/01 - Overview.md`'s Techniques/Protocols table; RPC/daemon access is a **control-plane** layer on top of the exact same module execution path, not a separate attack surface of its own |
| HTTP server fingerprint | The `Rex::Proto::Http::Server` class backing `msgrpc` sets `Server: Rex` in its response headers by default (`Rex::Proto::Http::Server::DefaultServer = "Rex"`), unless the operator explicitly overrides it — a concrete, verifiable network fingerprint, covered further in `04 - Target Evidence.md` |

## Command-Line Switches — Quick Reference

Verified against the official [`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework) source — the `msfrpcd` and `msfd` scripts at the repo root, and `plugins/msgrpc.rb` for the plugin-level defaults used when `msgrpc` is loaded a different way (`load msgrpc` from inside an already-running `msfconsole`) — not from memory or older cheat sheets.

### msfrpcd Flags

| Flag | Plain-English meaning |
|---|---|
| `-a <addr>` | Bind address (default `0.0.0.0` — **all interfaces**, not loopback) |
| `-p <port>` | Bind port (default **55553**) |
| `-U <user>` | RPC username. Also settable via the `MSF_RPC_USER` environment variable — used by Metasploit's own auto-start tooling specifically to avoid putting credentials in the process argument list |
| `-P <pass>` | RPC password. **Required** — `msfrpcd` refuses to start without one (`"Error: a password must be specified (-P)"`). Also settable via `MSF_RPC_PASS` |
| `-u <uri>` | Custom URI path for the RPC endpoint (overrides the plugin's own default) |
| `-t <seconds>` | Token inactivity timeout before a non-permanent token is purged (default **300**) |
| `-S` | **Disable SSL/TLS** on the RPC socket — every request/response, including the `-U`/`-P` credentials sent during `auth.login` and every token used afterward, travels as cleartext HTTP |
| `-f` | Run in the foreground instead of forking to the background |
| `-n` | Disable the framework database for this daemon instance (`DisableDatabase`) |
| `-j` | Start the newer **JSON-RPC** web service (Thin-backed, `/api/v1/json-rpc`) instead of the classic MessagePack `msgrpc` path |
| `-k <path>` | *(JSON-RPC only)* Path to the TLS private key (default `~/.msf4/msf-ws-key.pem`) |
| `-c <path>` | *(JSON-RPC only)* Path to the TLS certificate (default `~/.msf4/msf-ws-cert.pem`) |
| `-v` | *(JSON-RPC only)* Enable SSL client-certificate verification (off/disabled by default) |
| `-h` | Help banner |

### msfd Flags

| Flag | Plain-English meaning |
|---|---|
| `-a <addr>` | Bind address (default **loopback only**, `127.0.0.1`) |
| `-p <port>` | Bind port (default **55554**) |
| `-s` | Enable SSL/TLS — **off by default**, so out of the box `msfd` traffic (the entire interactive console session) is plaintext |
| `-f` | Run in the foreground |
| `-A <hosts>` | Comma-separated allow-list of client source addresses — the closest thing `msfd` has to access control, since there is no authentication step |
| `-D <hosts>` | Comma-separated deny-list of client source addresses |
| `-q` | Suppress the startup banner sent to each connecting client |
| `-h` | Help banner |

### msgrpc Plugin Defaults (when loaded via `load msgrpc` inside msfconsole, not via the `msfrpcd` script)

| Setting | Default | Notes |
|---|---|---|
| Host | `127.0.0.1` | Different from the `msfrpcd` script's own default of `0.0.0.0` — the plugin itself defaults to loopback-only |
| Port | **55552** | Different from `msfrpcd`'s script-level default of 55553 — this distinction matters for hunting: which port you see tells you *how* the RPC service was started |
| Username | `msf` | Used if `User`/`-U` isn't supplied |
| Password | Random 8-character alphanumeric string | Generated and **printed to console output** (`print_status`) if `Pass`/`-P` isn't supplied — not silent, but easy to miss in scrollback |

### RPC Method Groups (msfrpcd / msgrpc)

| Group | Representative methods | Purpose |
|---|---|---|
| `health` | `health.check` (unauthenticated) | Liveness/readiness probe — the one call that needs no token at all |
| `auth` | `auth.login`, `auth.logout`, `auth.token_list`, `auth.token_add`, `auth.token_generate` | Session/token lifecycle |
| `core` | `core.version`, `core.stop`, `core.getg`/`core.setg`/`core.unsetg`, `core.save`, `core.reload_modules`, `core.thread_list`/`core.thread_kill` | Framework-level control and global datastore management |
| `console` | `console.create`, `console.list`, `console.destroy`, `console.read`, `console.write`, `console.tabs`, `console.session_kill`, `console.session_detach` | Drive a real, hidden `msfconsole` instance non-interactively — same command surface as `../msfconsole/` |
| `module` | `module.exploits`/`auxiliary`/`post`/`payloads`/`encoders`/`nops`, `module.info`, `module.search`, `module.options`, `module.execute`, `module.check`, `module.results`, `module.ack` | Enumerate and run modules directly without a console instance |
| `session` | `session.list`, `session.shell_read`/`shell_write`, `session.meterpreter_read`/`meterpreter_write`, `session.meterpreter_run_single`, `session.meterpreter_script`, `session.stop` | Interact with and fan commands out across live sessions |
| `job` | `job.list`, `job.info`, `job.stop` | Manage background jobs (handlers, running scanners) |
| `db` | `db.hosts`, `db.services`, `db.creds`, `db.workspaces`, `db.report_host`, `db.import_data`, and the rest of the `hosts`/`services`/`creds`/`loot`/`vulns` command family from `../msfconsole/01 - Overview.md` | Programmatic access to the same Postgres-backed database `msfconsole` uses |
| `plugin` | `plugin.load`, `plugin.unload`, `plugin.loaded` | Load/unload Framework plugins remotely |

## Quick Use-Case List

- Standing up `msfrpcd` as a headless automation backend for scripted engagements
- Authenticating and issuing calls from the official Ruby client (`Msf::RPC::Client`, bundled with the Framework)
- Authenticating and issuing calls from Python via the third-party `pymetasploit3` library
- Talking to the API at the raw wire level (`curl` + a MessagePack encoder) — no client library at all
- Driving a full, non-interactive `msfconsole` session remotely via `console.create`/`write`/`read`
- One-shot module execution via `module.execute` — no console instance needed
- Team-server-style shared access: multiple operators, one live `Msf::Framework` instance, shared sessions/database
- Fleet-wide scanning by scripting many `module.execute` calls against a target list
- Fan-out command execution across every currently live session (`session.list` + `session.shell_write`/`meterpreter_write`)
- Persistent, long-lived API tokens for integrations that shouldn't have to re-authenticate every run
- Running `msfrpcd` as an always-on backend service (e.g. under `systemd`)
- Chaining Metasploit into another automation/C2/SOAR pipeline as an exploitation backend
- OPSEC/evasion variant: disabling TLS (`-S`) for local/trusted-network automation, at the cost of cleartext credentials and commands
- Legacy `msfd` usage: zero-setup shared console access on an isolated lab/range network
- Discovering (as a hunter, or as an attacker who found someone else's forgotten instance) an externally reachable `msfrpcd`/`msfd` port

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Metasploit Framework installed | `msfrpcd`/`msfd` ship as root-level scripts alongside `msfconsole`; the `msgrpc`/`msfd` plugins live under `plugins/` |
| Credentials (`msfrpcd`) | `-U`/`-P` (or `MSF_RPC_USER`/`MSF_RPC_PASS`) — the daemon will not start without a password |
| No credentials at all (`msfd`) | This is the finding, not a gap — reachability to the port is the *only* prerequisite for full console access |
| Network reachability to the service port | 55553 (`msfrpcd` default), 55554 (`msfd` default), 55552 (`msgrpc` plugin default when loaded via `load msgrpc`) — all unprivileged ports, no elevated OS privilege needed to bind them |
| TLS certificate material (`msfrpcd -j` JSON-RPC mode only) | `msfdb init` must have run to generate `~/.msf4/msf-ws-key.pem`/`msf-ws-cert.pem`, or explicit `-k`/`-c` paths supplied |
| A MessagePack-capable client (`msfrpcd`) | Any language with MessagePack + HTTPS support. Bundled: `Msf::RPC::Client` (Ruby). Third-party: `pymetasploit3` (Python) |
| Framework database (optional) | Needed for `db.*` calls and for persistent `Mdm::ApiKey`-backed tokens to survive a daemon restart — same `msfdb init` setup as `../msfconsole/01 - Overview.md`'s Prerequisites |
