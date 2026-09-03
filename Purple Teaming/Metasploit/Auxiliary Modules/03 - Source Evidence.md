# Metasploit — Auxiliary Modules — Source Evidence

Evidence left on the **operator/attacking** host. The generic Framework-operator footprint — `~/.msf4/history`, the workspace database, resource scripts as artifacts, live process/socket state, `auditd`, memory forensics — is identical regardless of which module type ran it, and is already covered in full in `../Exploit Modules/03 - Source Evidence.md` and, in even more depth, `../msfconsole/03 - Source Evidence.md`. This page doesn't re-derive that ground — it covers what's genuinely **different** about running an `auxiliary/*` module from the operator side: the concurrency footprint `THREADS` produces, the `ACTION` selection appearing in history, and category-specific angles (`dos/*`/`spoof/*` raw-socket requirements, `gather/*`'s external-service traffic).

## Contents
- [What's Generic — Cross-Links](#whats-generic--cross-links)
- [`~/.msf4/history` — Reading an Auxiliary Session](#msf4history--reading-an-auxiliary-session)
- [The Concurrency Footprint of `THREADS`](#the-concurrency-footprint-of-threads)
- [Category-Specific Operator-Side Signals](#category-specific-operator-side-signals)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## What's Generic — Cross-Links

Covered in full elsewhere in this module, not restated here:

| Artifact | Where it's covered |
|---|---|
| `~/.msf4/history`, `~/.msf4/config`, `~/.msf4/logs/*` | `../msfconsole/03 - Source Evidence.md` (Framework State Directory) |
| Workspace database (`hosts`/`services`/`vulns`/`creds`/`loot`) | `../msfconsole/03 - Source Evidence.md` (Database Contents) |
| Resource scripts (`.rc`) as artifacts | `../msfconsole/03 - Source Evidence.md` (Resource Scripts as Artifacts) |
| Shell history for the outer `msfconsole` invocation itself | `../msfconsole/03 - Source Evidence.md` (Shell History) |
| `auditd`/`ausearch` survivability against history deletion | `../Exploit Modules/03 - Source Evidence.md` (OS-Level Audit Trail) |
| Ruby process memory retaining recently-used option strings/credentials | `../msfconsole/03 - Source Evidence.md` (Memory Forensics) |

## `~/.msf4/history` — Reading an Auxiliary Session

The command sequence itself tells an analyst which flavor of module class ran, without needing to have captured any output:

```
use auxiliary/scanner/smb/smb_login
set RHOSTS file:in_scope_hosts.txt
set THREADS 20
set ACTION ...
run
```

A history line reading `run` immediately after a `use auxiliary/...` line — never `exploit` — is itself a class signature; `exploit`/`run` interchangeability in a history file only ever applies to `exploit/*` module context lines (`../Exploit Modules/01 - Overview.md`). A `set ACTION <value>` line is unique to modules implementing `HasActions` (`01 - Overview.md`) and narrows exactly which behavior of a multi-action module (e.g. which `ldap_query` action) was actually run — critical context `~/.msf4/history` alone won't otherwise disambiguate, since the module path is identical across every action.

## The Concurrency Footprint of `THREADS`

This is the one operator-side signal genuinely unique to `Msf::Auxiliary::Scanner`-class modules (`01 - Overview.md`): a `run` against a large `RHOSTS` set with `THREADS` raised well above the default of `1` produces a **live thread/socket footprint scaled to the setting itself**, visible independent of anything logged to disk:

```bash
ps -T -p <msfconsole_pid> | wc -l          # thread count roughly tracks THREADS + framework overhead
ss -tnp | grep <msfconsole_pid> | wc -l    # concurrent outbound connections, one per active run_host thread
```

A `THREADS` value recovered from `~/.msf4/history` (or the workspace `config` snapshot) is a direct, quantifiable claim about how aggressive the sweep was — `THREADS 1` (the default, meaning the operator never touched it) implies a slow, serial, low-noise run; `THREADS 50+` implies a deliberate fast/loud fleet-wide sweep. This maps directly onto the target-side detection volume covered in `04 - Target Evidence.md` — the operator-side setting and the target-side event count are the same fact observed from two sides.

## Category-Specific Operator-Side Signals

| Category | Operator-side signal beyond the generic footprint above |
|---|---|
| `scanner/*` (login/credential modules) | `USER_FILE`/`PASS_FILE`/`USERPASS_FILE` values in history/config point to **wordlist files on disk** — recovering those files themselves (not just their path) shows exactly what credential material was tried, which is often more revealing than the scan results alone |
| `admin/*` | `USERNAME`/`PASSWORD` values passed directly as `set` commands land in `~/.msf4/history` in **plaintext** — the same exposure noted for exploit modules' authenticated variants in `../Exploit Modules/03 - Source Evidence.md`, but here it's the *entire point* of the module rather than an optional auth path |
| `gather/*` (OSINT modules, e.g. `search_email_collector`) | Outbound HTTPS connections to public search engines (`google.com`, `bing.com`, `search.yahoo.com`) from the operator host, **not** to any target-organization infrastructure — `ss -tnp` / proxy logs on the operator's own egress path are the only place this traffic is visible at all. `OUTFILE`, if set, is a flat file of harvested data sitting on the operator's disk, same evidentiary weight as any other loot file |
| `dos/*`, `spoof/*` (raw-socket modules) | Require elevated privileges (root / `CAP_NET_RAW`) on the operator host to construct raw packets via PacketFu — `ps aux` showing `msfconsole`/`ruby` running as root (rather than the operator's normal unprivileged account) is itself a signal worth noting when reconstructing operator intent, since most other module classes in this repo run unprivileged |
| `fuzzers/*` | Long-running, single-target, high-connection-attempt-count sessions — `ss -tnp` showing thousands of sequential connect/disconnect cycles against one `RHOST:RPORT` pair over an extended window is a distinct shape from a scanner's broad-and-shallow `RHOSTS` sweep |

## Timeline Correlation Value

Same principle as `../Exploit Modules/03 - Source Evidence.md`'s closing section: none of the operator-side artifacts above carry standalone weight — their value is **correlating** a specific `run` invocation's timestamp (from `~/.msf4/history` context, a `loot`/`creds` row's timestamp, or live process/thread state if the box is captured mid-run) against the corresponding burst of target-side authentication, connection, or crash events documented in `04 - Target Evidence.md`. For `THREADS`-driven scanner modules specifically, the operator-side thread count and the target-side event-burst size should be **roughly proportional** — a mismatch (e.g. `THREADS 1` in history but a massive simultaneous multi-host event burst on the target side) is itself worth investigating as a sign of a second, uncaptured operator source.
