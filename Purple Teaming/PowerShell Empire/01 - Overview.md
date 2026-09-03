# PowerShell Empire — Overview

> 🔴 **Red Flag Principle:** Every Empire listener ships with the **same hardcoded default `StagingKey` value — `2c103f2c4ed1e59c0b4e2e01821770fa`** — baked directly into the `http`/`http_foreign` listener source as the pre-shared key for the stage-0 handshake. It has been the literal default since the original PowerShell Empire project and is unchanged in BC-Security's current v6.7.1 source. Alongside it, the default listener ships a static communication profile (`/admin/get.php,/news.php,/login/process.php`), a static cookie name (`session`) that smuggles the base64 routing packet, a spoofed `Server: Microsoft-IIS/7.5` header, and — for the SMB listener — a static named pipe (`empire_pipe`). None of these require decrypting a single byte of traffic to check for; they're string matches against whatever an operator didn't bother to change. And even where every value *is* randomized, the multi-stage EKE handshake shape itself (stage-0 GET → encrypted stager body → stage-1 key exchange POST → stage-2 sysinfo POST → tasking poll loop) is structurally invariant — chase the shape when the strings are gone.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line / API — Quick Reference](#command-line--api--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

**This note documents [`BC-SECURITY/Empire`](https://github.com/BC-SECURITY/Empire), the actively maintained continuation of the project — not the original, discontinued `EmpireProject/Empire`.** That distinction matters: a large fraction of public Empire write-ups (including many still-circulating "cheat sheets") describe the original PowerShell-only, `(Empire) >`-console architecture that no longer exists in the current codebase. Verified directly against the repo's own commit/release/changelog history, not memory:

- **2015 (BSidesLV)** — the original **PowerShell Empire** debuts, built by **Will Schroeder (@harmj0y)**, **Justin Warner (@sixdub)**, along with **@enigma0x3**, **@rvrsh3ll**, **@killswitch_gui**, and **@xorrior** (several affiliated with Veris Group at the time) — a pure-PowerShell post-exploitation agent framework demonstrating that an entire attack chain could run without dropping a binary to disk, at a time when PowerShell logging/AMSI defenses were far less mature.
- **2016 (HackMiami)** — **EmPyre**, a sibling Python 2.7 agent project from the Veil-Framework team, ships as a separate but architecturally similar framework for Linux/macOS targets.
- **Empire 3.0** — PowerShell Empire and EmPyre are **merged into one project**, giving Empire its first cross-platform (PowerShell + Python) agent story and the multi-agent design philosophy the framework still follows today.
- **2019-07-31** — the original project's discontinuation is publicly announced (by then-maintainer Chris Ross), citing that Empire had achieved its original purpose of demonstrating PowerShell's post-exploitation potential, plus the point being made moot by Microsoft's own PowerShell security investments in the intervening years (AMSI, enhanced ScriptBlock logging, Constrained Language Mode). The original `EmpireProject/Empire` repository stops receiving updates.
- **BC Security** (an offensive-security/red-team consultancy) forks the already-merged 3.x codebase and republishes it as **"Empire 3.0 Strikes Back,"** porting the Python 2.7-only codebase to Python 2.7/3.x compatibility and consolidating fragmented community branches — this is the point at which `github.com/BC-SECURITY/Empire` becomes the project's living upstream.
- **Empire 4.0** — a substantial rewrite: **Python 3-only server**, an integrated Roslyn-based C# compiler (derived from the Covenant C2 project's compiler work), the **C# agent (Sharpire)** and **IronPython agent** added alongside the original PowerShell and Python agents, and **Starkiller** — a standalone Electron/web GUI client — introduced as a companion project.
- **Empire 5.0** — the **v2 RESTful API** (built on FastAPI) replaces the older v1 API; Starkiller is bundled into the main repo as a git submodule rather than a separate install step.
- **Empire 6.0 (2025-03-25)** — a further architectural break, confirmed directly against `CHANGELOG.md`: the **command-line client was removed entirely** ("Removed the command line client. Use Starkiller instead."), **Go agent (Gopire)** support was added, a **Plugin Marketplace** shipped, C# compilation moved to a downloadable **Empire-Compiler** service, and three legacy listeners were dropped — **HTTP COM** (PowerShell-only, built on an outdated COM object), **OneDrive**, and **Dropbox** (both broken by upstream API changes) — none of which exist in current source despite still appearing in older tutorials.
- **Current release: `v6.7.1`** (2025-07-25 per `CHANGELOG.md`, tagged 2026-08-02), **BSD-3-Clause** licensed, 5,200+ GitHub stars, commits landing on `main` within the current week. This note's mechanics, defaults, and API surface are verified directly against this release's source.

**The single biggest gotcha for anyone returning to Empire after Empire 4/5-era familiarity:** there is no more interactive console. `Empire-Cli` — a separate `python-prompt-toolkit`-based REPL project — was merged into the main repo at Empire 4.0, then removed outright at 6.0; its standalone repo (`BC-SECURITY/Empire-Cli`) has had no commits since 2021 and its own README now reads "This project has been integrated into the main Empire repository." Today, operators interact **only** via the RESTful API (curl, Python, Postman, the built-in Swagger UI) or via **[Starkiller](https://github.com/BC-SECURITY/Starkiller)**, a browser-based GUI served directly from the API process. Treat both as first-class, current, source-verified — not a downgrade from a "real" CLI that still exists.

## How It Works

### Architecture — API server, database, two client paths

```
                              ┌──────────────────────────┐
                              │   Empire Server process   │
                              │   (`ps-empire server`)    │
                              │                            │
   Operator ── HTTPS/JWT ──▶  │  FastAPI RESTful API      │ ── owns ──▶  SQLite/MySQL DB
   (curl / scripts /          │  (default :1337, HTTP     │              (agents, tasks,
    Swagger UI /docs)         │   unless --secure-api)    │               listeners, creds,
                              │                            │               modules, users)
   Operator ── browser ────▶  │  Starkiller (bundled       │
   (web GUI, same API)        │  submodule, served at /)  │
                              │                            │
                              │  Listener job(s)           │ ── C2 traffic ──▶  Agent
                              │  (http / http_malleable /  │  (per listener      (target)
                              │   http_foreign / http_hop  │   transport)
                              │   / smb / port_forward_    │
                              │   pivot)                   │
                              └──────────────────────────┘
```

- **Server** (`ps-empire server`, a thin bash wrapper around `empire.py server`) — a single Python 3 process hosting the FastAPI RESTful API, all listener jobs, and the module/plugin/bypass/obfuscation engines. Persists state to **SQLite** (`empire.db`, the lightweight default) or **MySQL** (the install script optionally provisions a local MySQL instance with default credentials `empire_user`/`empire_password` — verified against `setup/install.sh`).
- **Authentication** — JSON Web Tokens. `POST /token` with the default credentials (`empireadmin`/`password123`, verified against `empire/server/config.yaml`'s `database.defaults` block) returns an `access_token`, sent on every subsequent request as `Authorization: Bearer <token>`. Multiple users can be provisioned via `/api/v2/users` for multi-operator engagements — each with independent credentials, no shared console session.
- **Starkiller** — the GUI client, a git submodule of the main repo since 5.0, served by the same API process (accessed at the API root, `/`, over the same port). It's a thin web frontend over the identical REST surface — nothing Starkiller can do is unavailable to a raw API caller, and vice versa.
- **Swagger UI** (`/docs`) — FastAPI's auto-generated interactive API explorer; the fastest way to see every endpoint/schema without reading source.

### Listener → Stager → Agent → Tasking — the C2 lifecycle

```
Operator                        Empire Server                          Target
────────                        ─────────────                          ──────

1. POST /api/v2/listeners/
   {template:"http", options:{Port:"80", StagingKey:..., ...}}
                          ─────▶  Listener job started
                                  (Flask app bound to Port)

2. POST /api/v2/stagers/
   {template:"multi_launcher",
    options:{Listener:"...", Language:"powershell"}}
                          ─────▶  Server renders a stage-0
                                  one-liner launcher, embeds
                                  the listener's Host/URI/
                                  StagingKey    ◀──────────────  Stager text/file
                                                                 delivered to target
                                                                 (out of band)

3.                                                    ◀───────  Target executes launcher

4.                               GET <one of DefaultProfile's   ─────▶  Stage-0 request
                                  URIs> with Cookie: session=
                                  <b64 routing packet>
                                  Server decrypts routing
                                  packet w/ StagingKey (PSK,
                                  ChaCha20-Poly1305)   ────────────────▶ Returns encrypted
                                                                          stager body (case-
                                                                          randomized)

5.                               Stage-1: agent generates      ◀─────▶  RSA keypair (PowerShell)
                                  or Diffie-Hellman keypair              or DH (Python/IronPython/
                                  (other agents), POSTs                  C#/Go), gets back an
                                  encrypted pubkey; server                8-char session ID + AES
                                  returns session key + ID                session key (encrypted)

6.                               Stage-2: agent POSTs          ◀─────▶  sysinfo (hostname, user,
                                  AES-encrypted sysinfo;                 OS, process, high-integrity
                                  server responds with the                flag, language/version)
                                  full agent, patched with
                                  delay/jitter/kill-date/
                                  working-hours config

7. GET /api/v2/agents            Agent now polls the listener   ◀─────▶  Agent checks in every
   (lists checked-in agents)      on its configured delay+                DefaultDelay seconds
                                  jitter interval for queued              (±jitter), pulls any
   POST /api/v2/agents/{id}       tasks                                  queued tasks, executes,
   /tasks/module (or /shell,                                             POSTs results back
   /upload, /download, ...)
```

### Stageless vs. staged, and pivoting off an existing agent

- `multi_launcher` (the default stager) is a **stage-0 one-liner** — small, delivered by any means, that pulls the rest of the agent live from the listener at run time (steps 4-6 above).
- `multi_generate_agent` produces a **fully stageless** agent file — stage 0/1/2 collapsed into one artifact — for debugging, pre-staging in outbound-restricted environments, or reducing the number of distinct network requests an EDR/proxy can flag (verified against `docs/stagers/multi_generate_agent.md`; supported for PowerShell/Python/IronPython only — C# and Go agents are already-compiled binaries and don't have a meaningful "stageless vs. staged" distinction).
- **`http_foreign`** lets *this* Empire server generate stagers/agents that actually check in to a **different** Empire server's listener — useful for splitting infrastructure roles.
- **`http_hop`** drops a small PHP redirector (`empire/server/data/misc/hop.php` in source) on an intermediary web host, which blindly forwards agent traffic to the real `RedirectListener` — classic domain-fronting-adjacent redirector tradecraft without needing a full reverse proxy.
- **`smb`** is a peer-to-peer, named-pipe listener (default pipe name `empire_pipe`, verified against `empire/server/listeners/smb.py`) for pivoting a second agent through an already-compromised host with no direct egress of its own — **currently IronPython-agent-only**, per the project's own listener docs.
- **`port_forward_pivot`** chains a new listener through an already-active, **elevated** agent's own port-forward capability — the agent itself becomes the relay.

### Module execution model

Modules are YAML-defined (`empire/server/modules/<language>/<category>/...`), each carrying a **MITRE ATT&CK tactic/technique mapping baked into the YAML itself** (`tactics: [...]`, `techniques: [...]`) — this is real, source-verified metadata, not something bolted on for this note. A module's **ID is its file path, slash-to-underscore-slugified and lowercased** — e.g. `empire/server/modules/powershell/credentials/mimikatz/logonpasswords.yaml` becomes module ID `powershell_credentials_mimikatz_logonpasswords`, confirmed against `string_util.slugify()` and `module_service._load_module()`. Module categories on disk: `situational_awareness`, `collection`, `credentials`, `lateral_movement`, `persistence`, `privesc`, `code_execution`, `exploitation`, `exfil`/`exfiltration`, `management`, `recon`/`discovery`, `trollsploit`, plus a dedicated `bof` (Beacon Object File) tree. Tasking a module is `POST /api/v2/agents/{id}/tasks/module` with `{"module_id": "...", "options": {...}}` — the server renders the module's PowerShell/Python/C#/BOF source with the supplied options, optionally obfuscates it, and queues it for the agent's next check-in.

### Bypasses and obfuscation — applied at generation time, not runtime

- **Bypasses** are small pre-written PowerShell snippets prepended to stagers/modules to defeat specific defenses before the payload runs — shipped: `mattifestation` (the well-known `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` AMSI patch, credited to Matt Graeber), `etw`, `rastamouse`, `liberman`, `scriptblocklog` (verified file listing in `empire/server/bypasses/`). Default-applied bypasses (`mattifestation` + `etw`) are configured in `config.yaml`'s `database.defaults.bypasses`.
- **Obfuscation** is per-language: **Invoke-Obfuscation** for PowerShell (token/string/encoding-layer obfuscation, `ObfuscateCommand` e.g. `Token\All\1`), **ConfuserEx 2** for C#, and a Python obfuscator module — all disabled by default per `config.yaml`, opt-in per stager/module.
- **JA3/JA3S evasion** — an `http`/`http_malleable` listener option (`JA3_Evasion`, default `False`) that randomizes the TLS cipher list on HTTPS listeners to defeat static JA3/JA3S fingerprinting; only takes effect when a `CertPath` is configured (i.e., HTTPS, not plain HTTP).

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| C2 transport | HTTP/HTTPS (TCP 80/443 default, `http` listener), Malleable HTTP (`http_malleable`, Cobalt-Strike-compatible `.profile` files), SMB named-pipe P2P (`smb`, IronPython-only), PHP-redirector hop (`http_hop`), cross-server foreign stager generation (`http_foreign`), agent-relayed port-forward pivot (`port_forward_pivot`) |
| Key exchange / crypto | Encrypted Key Exchange (EKE) staging model: **RSA** keypair for the PowerShell agent, **Diffie-Hellman** for Python/IronPython/C#/Go agents; **AES** for the negotiated session key; **ChaCha20-Poly1305** (PSK = the listener's `StagingKey`) for the stage-0 stager body and the cookie-carried routing packet |
| Malleable C2 | Empire ingests the **Global Options** and **HTTP/S blocks** of Cobalt Strike-format Malleable C2 profiles (via a fork of Johneiser's parser) — not the full CS 4.0 feature set; see [`BC-SECURITY/Malleable-C2-Profiles`](https://github.com/BC-SECURITY/Malleable-C2-Profiles) for ready-made profiles |
| Agent languages | PowerShell (the original agent), Python 3, C# (Sharpire), IronPython 3 (runs Python/C#/PowerShell taskings inside the .NET CLR), Go (Gopire — Windows/HTTP-only) — plus an experimental C agent (Cpire, sponsors-only) |
| In-memory execution | .NET assembly execution (Invoke-Assembly-style module), BOF/COFF execution (via `Invoke-Bof`), Roslyn/Empire-Compiler-driven C# compile-and-run |
| Credential access | Bundled Mimikatz module family (`sekurlsa`, `lsadump`/DCSync, ticket forging), Rubeus C# module (Kerberoasting, ticket ops), LSASS minidump modules |
| Discovery | Seatbelt C# module, SharpHound/BloodHound ingestor module, PowerView-derived AD recon modules |
| Obfuscation | Invoke-Obfuscation (PowerShell), ConfuserEx 2 (C#), per-language keyword replacement, JA3/S TLS-cipher randomization |
| MITRE integration | Every module YAML carries `tactics`/`techniques` fields mapped to ATT&CK IDs directly in source — Empire itself is cataloged as MITRE ATT&CK Software **[S0363](https://attack.mitre.org/software/S0363/)** |

## Command-Line / API — Quick Reference

There is no interactive console (see History) — the two interaction surfaces are the `ps-empire` shell wrapper (server lifecycle only) and the RESTful API (everything else).

**`ps-empire` — server lifecycle**

| Command | Plain-English meaning |
|---|---|
| `./ps-empire install -y` | Runs the install script; `-y` auto-answers prompts, `-f` forces install as root, `-c` compiles Empire-Compiler from source, `-o` overrides the OS-support check |
| `./ps-empire server` | Starts the Empire server (API + listener host) |
| `./ps-empire server -l DEBUG` / `-d` | Sets/raises the log level (`-d` is shorthand for `DEBUG`) |
| `./ps-empire server --reset` | Drops and reinitializes the database; keeps config and Starkiller/Empire-Compiler files |
| `./ps-empire server --clean` | Same as `--reset`, but also removes Starkiller/Empire-Compiler files |
| `./ps-empire server -v` | Prints the current Empire version |
| `./ps-empire server --config <path>` | Uses a `config.yaml` other than the default `empire/server/config.yaml` |
| `./ps-empire setup` | Syncs Starkiller/Empire-Compiler/plugin registries and auto-installs any plugins listed in `config.yaml` |
| `./ps-empire test [pytest args]` | Convenience wrapper around the project's own pytest suite |

**RESTful API — core endpoints** (all under `/api/v2/`, JWT-authenticated; default base `http://<server>:1337`)

| Endpoint | Method(s) | Plain-English meaning |
|---|---|---|
| `/token` | POST | Log in (`username`/`password`), returns the JWT `access_token` |
| `/listener-templates/` | GET | List available listener *types* (`http`, `http_malleable`, `http_foreign`, `http_hop`, `smb`, `port_forward_pivot`) and their option schemas |
| `/listeners/` | GET, POST, PUT, DELETE | List/create/update/delete listener jobs. Must be **disabled** before updating |
| `/stager-templates/` | GET | List available stager *types* (e.g. `multi_launcher`, `multi_generate_agent`, `windows_csharp_exe`, `windows_dll`, `linux_pyinstaller`, `osx_macho`, ...) and their option schemas |
| `/stagers/` | GET, POST, PUT, DELETE | Generate a stager against a listener; `save=false` returns the artifact without persisting it |
| `/agents/` | GET, PUT, DELETE | List/rename/kill (archive) checked-in agents |
| `/agents/{id}/checkins/` | GET | View an agent's check-in history |
| `/agents/{id}/tasks/shell` | POST | Run a raw shell command on the agent |
| `/agents/{id}/tasks/module` | POST | Execute a module by `module_id` with an `options` dict |
| `/agents/{id}/tasks/upload` \| `/download` | POST | Push/pull a file to/from the agent |
| `/agents/{id}/tasks/sysinfo` \| `/sleep` \| `/kill_date` \| `/working_hours` \| `/exit` \| `/socks` | POST | Refresh sysinfo, change delay/jitter, set a kill date, set working hours, exit the agent, or start a SOCKS proxy through it |
| `/agents/{id}/tasks/jobs` \| `/kill_job` \| `/stop_job` | POST | Manage background jobs running on the agent (e.g. a long-running keylogger) |
| `/agents/{id}/files/` | GET | Read-only view of files enumerated on the agent's host (populated by `ls`/`DirectoryList` tasks) |
| `/modules/` | GET, PUT | List loaded modules; enable/disable a module (disabled modules can't execute) |
| `/hosts/` | GET | Read-only: hosts inferred from checked-in agents |
| `/downloads/` | GET, POST | Pull any server-tracked file artifact (stagers, agent downloads, task output); upload a file for later use in a module |
| `/credentials/` | CRUD | Store/retrieve harvested credentials, including those a module writes automatically |
| `/malleable-profiles/` | CRUD | Manage Malleable C2 `.profile` files usable by the `http_malleable` listener |
| `/bypasses/` | CRUD | Manage the AMSI/ETW/etc. bypass snippets applied to stagers/modules |
| `/obfuscation/*` | GET/POST | Configure and trigger per-language obfuscation, including pre-obfuscating specific modules |
| `/plugins/` | GET, POST (`/execute`) | List and run installed plugins (server-side automation extensions) |
| `/users/` | CRUD | Manage operator accounts — this is how multiplayer works, no shared console session required |
| `/meta` | GET | Server version/metadata |

Interactive exploration of the full, current schema: **Swagger UI at `/docs`** on any running server.

## Quick Use-Case List

- Baseline HTTP listener + `multi_launcher` PowerShell stager (the default-config case)
- HTTPS listener with a real certificate and `JA3_Evasion` enabled for internet-facing engagements
- `http_malleable` listener with a Cobalt-Strike-style profile to blend into a specific threat's known traffic shape
- Generating an alternate-language agent — Python 3 for a Linux/macOS target
- Generating a C# (Sharpire) agent stager
- Generating an IronPython agent — the only agent type that can use the `smb` listener
- Generating a Go (Gopire) agent for a lightweight, Windows-only, HTTP-only footprint
- `http_foreign` — generating a stager/agent that checks in to a *different* Empire server's listener
- `http_hop` — routing agent traffic through a PHP redirector on an intermediary host
- `smb` peer-to-peer pivot — reaching a segmented host through an already-compromised one, no direct egress required
- `port_forward_pivot` — chaining a new listener through an existing elevated agent's own port forward
- Module-based credential harvesting (Mimikatz `logonpasswords`/`sekurlsa`, DCSync, Rubeus Kerberoasting) — see `Purple Teaming/Mimikatz/`
- Lateral movement via built-in modules (`invoke_psexec`, `invoke_wmi`, `invoke_dcom`, `invoke_psremoting`)
- Persistence modules — registry Run keys, scheduled tasks, WMI event subscriptions, golden-ticket-based persistence
- Situational-awareness recon via the Seatbelt C# module or the SharpHound/BloodHound ingestor module — see `Purple Teaming/Seatbelt/` and `Purple Teaming/BloodHound/`
- Applying AMSI/ETW bypasses (`mattifestation`, `etw`, `rastamouse`, `liberman`) at stager/module generation time
- Applying obfuscation (Invoke-Obfuscation for PowerShell, ConfuserEx 2 for C#) before delivery
- Operating entirely via raw REST API calls (automation/scripting) vs. the Starkiller GUI — same underlying API, different client
- Multi-operator engagement via independently provisioned API users (`/api/v2/users`), no shared console state
- Installing and running a Plugin Marketplace plugin (e.g. automated attack-path chaining, report generation, a SOCKS proxy server) for server-side workflow extension

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Server host | Linux (Ubuntu 22.04/24.04, Debian 11/12/13, Kali, ParrotOS tested/supported) running Python 3.13+; installed via `./ps-empire install -y`, Docker image, or Kali's `powershell-empire` package (may lag latest release) |
| Database | SQLite (`empire.db`, zero-setup default) or MySQL (install script can provision one locally with default creds `empire_user`/`empire_password` — change these before any real engagement) |
| Network egress from target | At least one listener transport reachable from the target: direct TCP to an `http`/`http_malleable` listener, SMB/IPC reachability to an `smb` pivot host, or reachability to an `http_hop` redirector |
| API access | Valid JWT — obtained via `POST /token` against a provisioned user (default `empireadmin`/`password123`, change immediately) |
| Starkiller (optional) | No separate install as of 5.0+ — bundled as a git submodule, served from the same API process; requires `git clone --recursive` |
| C#/Sharpire agents | Empire-Compiler (auto-downloaded at startup, or `-c` to build from source at install time) for Roslyn-based compilation |
| `http_hop` | An intermediary web host capable of running the generated `hop.php` redirector, reachable from the target and able to reach the real listener |
| `port_forward_pivot` | An existing, **elevated** agent session on the pivot host |
| Malleable profiles | A `.profile` file (Cobalt Strike format, Global Options + HTTP/S blocks only) loaded via `/api/v2/malleable-profiles` before use on an `http_malleable` listener |
| Sponsors features (C agent/Cpire, sponsors Starkiller build) | SSH access to BC-Security's private sponsor repositories |
