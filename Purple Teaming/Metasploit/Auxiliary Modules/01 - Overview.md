# Metasploit — Auxiliary Modules (`auxiliary/*`) — Overview

> 🔴 **Red Flag Principle:** Exploit modules make one quiet decision at a time — one target, one trigger, one session. Auxiliary modules are built to run **wide**: `THREADS` fans a single `run` invocation out across an entire `RHOSTS` range, so one `run` command against a `/24` can generate hundreds of authentication attempts, port probes, or protocol handshakes in the time it takes to read this sentence. That volume is the module class's defining forensic property — a `scanner/ssh/ssh_login` sweep against 200 hosts isn't one login attempt to hunt for, it's 200 near-simultaneous Security 4625 events from a single source IP, which is far louder and far easier to catch than almost anything in `exploit/*`. If nobody's watching authentication and connection logs for volume, this entire module class walks in unnoticed; if somebody is, it's usually the loudest thing an operator does all engagement.

This page covers `auxiliary/*` as a **class of module** — the shared anatomy every one of the Framework's several thousand auxiliary modules follows, spanning scanning, admin-access abuse, information gathering, denial-of-service, fuzzing, and spoofing — not one specific module. It's anchored by one fully worked, source-verified example: **`auxiliary/scanner/smb/smb_login`**, the SMB credential-validation scanner, chosen because it pairs directly with the fleet-wide credential-spraying workflows already covered in `../../NetExec/` and `../../Hydra/` elsewhere in this repo. `exploit/*` module anatomy (Rank, Targets, Payload, `check`) is covered in `../Exploit Modules/01 - Overview.md` and isn't restated here except by direct contrast.

## Contents
- [History](#history)
- [How It Works — Module Anatomy](#how-it-works--module-anatomy)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [msfconsole Command Reference — Auxiliary Module Lifecycle](#msfconsole-command-reference--auxiliary-module-lifecycle)
- [Major Sub-Categories, With Verified Examples](#major-sub-categories-with-verified-examples)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`auxiliary/*` has been a first-class module type in the Framework since the msf3 Ruby rewrite (2007) — the base `Msf::Auxiliary` class lives at [`lib/msf/core/auxiliary.rb`](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/auxiliary.rb) in the official [`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework) repository, and every individual module's source lives under `modules/auxiliary/`. The class's own doc comment states its purpose plainly:

```ruby
# The auxiliary class acts as a base class for all modules that perform
# reconnaissance, retrieve data, brute force logins, or any other action
# that doesn't fit our concept of an 'exploit' (involving payloads and
# targets and whatnot).
class Auxiliary < Msf::Module
```

That one comment is the entire design rationale for this module class: **everything that isn't "deliver a payload to a target"** — scanning, credential validation, data gathering, protocol abuse, fuzzing, denial-of-service — lives here instead of in `exploit/*`. See `../00 - Metasploit Overview.md` for the Framework's full origin story; this page doesn't restate it.

## How It Works — Module Anatomy

Every auxiliary module shares the same base class and lifecycle, but the specific methods it must implement — and which datastore options get auto-registered — depend on which mixins it includes. Understanding this is what lets an operator read `info`/`show options` on an unfamiliar auxiliary module and predict its behavior, and lets an analyst infer *what kind* of activity a logged module invocation represents.

### `run` — the only entry point (no `exploit`/`check` split by default)

Every auxiliary module implements `run` as its execution entry point — verified directly in the base class:

```ruby
def run
  print_status("Running the default Auxiliary handler")
end
```

Unlike exploit modules, there is **no separate verb** for "fire it" — `run` is the only command (`exploit` is not valid against an auxiliary module context; `check` is optional and not every module implements it, same `CheckCode` mechanism described in `../Exploit Modules/01 - Overview.md`, used mainly so a scanner module can double as an exploit module's `CheckModule` — `auxiliary/scanner/smb/smb_ms17_010` backing `exploit/windows/smb/ms17_010_eternalblue`'s `check` is the worked example there).

What `run` actually does depends on which execution mixin the module includes:

| Mixin | Method the module must implement | Behavior |
|---|---|---|
| *(none — bare `Msf::Auxiliary`)* | `run` | Single-shot: whatever the module does, it does once, synchronously, against however many hosts/targets its own code loops over |
| `Msf::Auxiliary::Scanner` | `run_host(ip)` | Framework-managed **per-host threading** — `run` itself is inherited from the mixin and fans `run_host` out across `RHOSTS` up to `THREADS` concurrent threads (see below) |
| `Msf::Auxiliary::UDPScanner` / `run_batch` pattern | `run_batch(batch)` | Framework-managed **batch threading** — hosts are grouped into batches (size from `run_batch_size()`) and each batch runs in its own thread, used where per-host UDP probes benefit from being sent as a group (e.g. `scanner/discovery/udp_sweep`) |

### `THREADS` — Scanner Concurrency

For any module including `Msf::Auxiliary::Scanner`, `THREADS` and `RHOSTS` are auto-registered by the mixin itself — verified directly from [`lib/msf/core/auxiliary/scanner.rb`](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/auxiliary/scanner.rb):

```ruby
register_options([
    Opt::RHOSTS,
    OptInt.new('THREADS', [ true, "The number of concurrent threads (max one per host)", 1 ] )
  ], Auxiliary::Scanner)
```

`THREADS` defaults to **1** (fully serial) on every scanner module unless the operator raises it. The mixin's `run` method walks `RHOSTS` (via `Msf::RhostsWalker`, which understands CIDR, ranges, and `file:` lists) and spawns one framework thread per host, up to the `THREADS` cap, calling `run_host(ip)` in each — as a finished thread frees a slot, the walker feeds it the next queued host:

```
set RHOSTS 10.10.10.0/24        (254 hosts queued)
set THREADS 20
run

RhostsWalker (254 targets) ──▶ Thread pool (cap = THREADS = 20)
   ├─ Thread 1  → module.replicant → run_host(10.10.10.1)  ──▶ per-host probe/auth attempt(s)
   ├─ Thread 2  → module.replicant → run_host(10.10.10.2)  ──▶ per-host probe/auth attempt(s)
   ├─ ...
   └─ Thread 20 → module.replicant → run_host(10.10.10.20) ──▶ per-host probe/auth attempt(s)
        (as each thread finishes, the walker immediately feeds it the next queued host)
```

The scanner mixin also silently caps `THREADS` at runtime, verified from the same source: **16 on Windows** operator hosts, **200 on Cygwin**, and forced down to **1** whenever `CPORT` (a fixed source port) is set — a fixed source port can't be shared across concurrent connections. There's no equivalent throttle for `DELAY`/`JITTER` — those are per-module options some scanners expose (e.g. `scanner/portscan/tcp`'s `DELAY`/`JITTER`, covered below) for operators who want to deliberately slow a sweep down, not a framework-wide default.

### `ActionList` / `Action` — One Module, Multiple Behaviors

Many auxiliary modules expose more than one distinct behavior through a single module path via the `ACTION` datastore option, rather than shipping near-duplicate modules. This is handled by the `HasActions` mixin, which `Msf::Auxiliary` includes directly at the base class level — verified: `include HasActions` in `auxiliary.rb`. A module declares its actions in the `info` hash passed to `initialize`, following the pattern in the Framework's own canonical template, [`modules/auxiliary/example.rb`](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/example.rb):

```ruby
'Actions' => [
  [ 'Default Action', { 'Description' => 'This does something' } ],
  [ 'Another Action', { 'Description' => 'This does a different thing' } ]
],
'DefaultAction' => 'Default Action'
```

Declaring `Actions` auto-registers the `ACTION` datastore option — the operator never manually defines it. At runtime, `self.action` (case-insensitive lookup against `datastore['ACTION']`, falling back to `DefaultAction` if unset or invalid — verified from [`lib/msf/core/module/has_actions.rb`](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/module/has_actions.rb)) tells `run` which branch to take, typically via a `case action.name` dispatch. A real, verified example — `auxiliary/gather/ldap_query`, which offers `RUN_QUERY_FILE` (execute a batch of queries from a file) and `RUN_SINGLE_QUERY` (execute one ad hoc query) as reserved actions, plus one dynamically-generated action per built-in predefined LDAP query:

```
'Actions'       => [ [ 'RUN_QUERY_FILE',   {'Description' => '...'} ],
                      [ 'RUN_SINGLE_QUERY', {'Description' => '...'} ], ... ]
'DefaultAction' => 'RUN_QUERY_FILE'  (or the first predefined query, if any loaded)
        │
        ▼
msf6 auxiliary(gather/ldap_query) > set ACTION RUN_SINGLE_QUERY
        │
        ▼
def run
  case action.name
  when 'RUN_QUERY_FILE'   then # load + execute queries from QUERY_FILE
  when 'RUN_SINGLE_QUERY' then # execute QUERY_FILTER / QUERY_ATTRIBUTES   ◀── dispatched here
  else                          # look up a predefined named query
  end
end
```

Run `show actions` after `use` to list a module's available actions before configuring `ACTION`.

### How This Differs Structurally From `exploit/*`

| Exploit-module concept (`../Exploit Modules/01 - Overview.md`) | Auxiliary equivalent |
|---|---|
| `Rank` (`Excellent`→`Manual`, reliability/stability claim) | **Technically inherited** — `Msf::Module::Ranking` is mixed in at the base `Msf::Module` level (verified: `lib/msf/core/module/ranking.rb`), so every module, including auxiliary, has a `.rank` method that defaults to `NormalRanking` if unset. In practice, auxiliary module source essentially never sets `Rank =` explicitly (none of the modules verified for this page do), and `search`/`info` don't surface it as an operational decision point for auxiliary results the way they do for exploits. Treat "no Rank system" as true in the *practical, operator-facing* sense, not the literal class-hierarchy sense |
| `Targets` array + `TARGET` | **Absent.** No `Targets` array, no OS/arch auto-detection branch — an auxiliary module either works against whatever it's pointed at or it doesn't; there's no per-target code-path selection mechanism |
| `Payload` hash + `PAYLOAD`/`LHOST`/`LPORT` | **Absent.** Auxiliary modules don't deliver payloads or open sessions by default — the one documented exception is `scanner/smb/smb_login`'s `CreateSession` option (worked example below), which opens a session as a *side effect of a successful login*, not via a `Payload` mechanism |
| `exploit` / `run` (interchangeable) | **`run` only** — `exploit` is not a valid verb in an auxiliary module's context |
| `check` → `CheckCode` | **Same mechanism, optional and less universal** — many auxiliary modules (especially in `scanner/`) implement `check`/`check_host` specifically so an *exploit* module can delegate to them via `CheckModule`, as covered in `../Exploit Modules/01 - Overview.md` |
| `ActionList`/`Action` | **N/A for exploits** — this is an auxiliary/post-specific mechanism (`HasActions` is included by `Msf::Auxiliary` and `Msf::Post`, not by `Msf::Exploit`) |

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Primary ATT&CK techniques | [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery) and [T1595.002](https://attack.mitre.org/techniques/T1595/002/) (Active Scanning: Vulnerability Scanning) for the `scanner/*` class broadly; [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force) for login-validation scanners; category-specific IDs below |
| Protocol (varies by module) | Whatever the target service speaks — SMB, SSH, HTTP, TDS (MSSQL), FTP, LDAP, ARP, raw TCP/UDP. `auxiliary/*` is protocol-agnostic as a class, same as `exploit/*` |
| Execution context | Runs entirely on the **operator's** msfconsole host — unlike a successful exploit, a successful auxiliary-module run does not by itself place code or a session on the target (again excepting `CreateSession`-style opt-in session creation) |

## msfconsole Command Reference — Auxiliary Module Lifecycle

| Command | Plain-English meaning |
|---|---|
| `search type:auxiliary <keyword>` | Query the local module database restricted to auxiliary-type modules; also accepts `platform:`, `disclosure_date:` filters (no `rank:` filter — see the Rank nuance above) |
| `use <module path>` | Load a module into the active context; prompt changes to `msf6 auxiliary(...) >` |
| `info` | Print full module metadata — description, author, references (often including ATT&CK IDs directly, verified in the worked example below), and the full option list |
| `show actions` | List the module's `Actions` array entries, if any — empty/absent for modules with no `HasActions` declaration |
| `set ACTION <name>` | Select a specific behavior for modules exposing multiple actions |
| `show options` | List every configurable option, required and optional, with current values and defaults |
| `set RHOSTS <ip/range>` | Target(s) — single IP, CIDR, range, or `file:targets.txt` (scanner-class modules only; some auxiliary modules use `RHOST`/session-based targeting instead, e.g. `admin/mssql/mssql_enum` against an existing session) |
| `set THREADS <n>` | Concurrency for scanner-class modules — defaults to 1, capped per-platform (see above) |
| `set <OTHER OPTION> <value>` | Any other option surfaced by `show options` |
| `check` | Verify state without running the full module, **where implemented** — not universal for this class |
| `run` | Execute the module. **The only verb** — `exploit` is not valid here |
| `run -j` | Run as a **background job** — used for scanners sweeping large ranges without blocking the console, and for anything long-running or persistent (e.g. a DoS flood, a listener-style capture module) |
| `jobs -l` / `jobs -k <id>` | List / kill background jobs — the way to stop a `run -j` DoS or long sweep early |
| `back` | Exit the current module context without running it |

Results land in the workspace database — `hosts`, `services`, `vulns`, `creds`, `loot` — exactly as described in `../msfconsole/03 - Source Evidence.md`; this page doesn't re-derive that schema.

## Major Sub-Categories, With Verified Examples

| Namespace | What Lives There | Verified Example (this page) |
|---|---|---|
| `scanner/*` | By far the largest category — port/service discovery, version fingerprinting, credential validation at scale | `scanner/smb/smb_version` (SMB Version Detection); `scanner/portscan/tcp` (TCP Port Scanner); `scanner/ssh/ssh_login` (SSH Login Check Scanner); `scanner/smb/smb_login` (worked example, below) |
| `admin/*` | Authenticated (and occasionally unauthenticated) administrative-interface abuse — configuration changes, data extraction, privileged actions against management planes | `admin/mssql/mssql_enum` (Microsoft SQL Server Configuration Enumerator) |
| `gather/*` | Information/credential/data collection — both internal (against an authenticated session or service) and external (OSINT against public search engines) | `gather/search_email_collector` (Search Engine Domain Email Address Collector) |
| `dos/*` | Denial-of-service — deliberately degrades or crashes a target service/OS. **High-risk, rarely authorized in a live engagement** — see the callout in `02 - Hands-On Use Cases.md` | `dos/tcp/synflood` (TCP SYN Flooder) |
| `fuzzers/*` | Protocol fuzzing — malformed/boundary input sent to a service to surface crash-class bugs, typically in a lab/pre-authorization context rather than a production engagement | `fuzzers/ftp/ftp_pre_post` (Simple FTP Fuzzer) |
| `spoof/*` | Network-identity spoofing to enable MITM positioning or disruption | `spoof/arp/arp_poisoning` (ARP Spoof) |

Full walkthroughs with commands and MITRE ATT&CK mapping for every category live in `02 - Hands-On Use Cases.md`.

## Quick Use-Case List

- Fleet-wide TCP port discovery across a subnet (`scanner/portscan/tcp`)
- Service/version fingerprinting sweep to build a target inventory (`scanner/smb/smb_version`)
- Credential validation / spraying at scale against a single protocol (`scanner/ssh/ssh_login`, `scanner/smb/smb_login` — worked example)
- Vulnerability-presence verification without exploiting, including feeding a paired exploit module's `check` (cross-link `../Exploit Modules/01 - Overview.md`)
- Authenticated administrative-interface abuse once credentials are already in hand (`admin/mssql/mssql_enum`)
- Post-credential configuration/account enumeration as a privilege-escalation-planning step
- OSINT/external data collection with **zero footprint on the target organization's own network** (`gather/search_email_collector`)
- Protocol fuzzing to find crash-class bugs pre-authorization or in a lab environment (`fuzzers/ftp/ftp_pre_post`)
- Deliberate denial-of-service testing — flagged high-risk, rarely in scope for a live engagement (`dos/tcp/synflood`)
- Network-identity spoofing to enable MITM positioning or disruption (`spoof/arp/arp_poisoning`)
- Multi-behavior modules where a single module path exposes several distinct actions via `ACTION` (`gather/ldap_query`)
- Chaining a scanner's positive detection directly into an exploit module (cross-link `../Exploit Modules/02 - Hands-On Use Cases.md`)
- Fleet-wide automation via resource scripts (`.rc`) for repeatable sweep sequences (cross-link `../msfconsole/01 - Overview.md`)
- Persisting scan/credential/loot results into the workspace database for later correlation (cross-link `../msfconsole/03 - Source Evidence.md`)

## Prerequisites

| Requirement | Notes |
|---|---|
| Network reachability to the target service/port | Varies per module — TCP 445 for SMB scanners, TCP 22 for SSH, TCP 1433 for MSSQL, etc. |
| `RHOSTS` syntax familiarity | CIDR, ranges, or `file:targets.txt` — scanner-class modules only; some (e.g. `admin/mssql/mssql_enum` run against an active session) target differently |
| `THREADS` tuned to the environment | Too high risks account lockouts (login scanners), IDS/IPS alerting, or saturating a constrained network segment; too low makes a large sweep impractically slow — see the worked example's tuning guidance in `02 - Hands-On Use Cases.md` |
| Credential material | Required for login-validation scanners and most `admin/*` modules — username/password, file lists, or an existing authenticated session |
| Explicit written authorization for `dos/*` and most `fuzzers/*` use | Crash/outage risk is not incidental for this sub-class the way it is for a merely `Average`-ranked exploit — it is the *point* of the module. Confirm scope in writing before running anything in `dos/*` against anything but a lab target |
| Raw-socket / packet-capture privileges | `dos/tcp/synflood` and `spoof/arp/arp_poisoning` craft raw packets via PacketFu and require root/`CAP_NET_RAW`-equivalent privileges on the operator host |
| `msfconsole` + database connectivity | Not required to run a module, but needed for results to persist into `hosts`/`services`/`creds`/`loot` — see `../00 - Metasploit Overview.md` and `../msfconsole/03 - Source Evidence.md` |
