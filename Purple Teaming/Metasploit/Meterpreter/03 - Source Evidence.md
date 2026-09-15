# Metasploit — Meterpreter — Source Evidence

Evidence left on the **attacking/operator** host — the box `msfconsole` was run from and where the Meterpreter handler lived. Unlike a lightweight single-purpose tool, Metasploit is a full framework with its own persistent state directory, database, and logging, so the operator-side footprint here is considerably richer than a typical CLI tool's shell-history-only trail.

## Contents
- [Framework State Directory](#framework-state-directory)
- [Database Contents](#database-contents)
- [Shell History](#shell-history)
- [Live Process and Socket State](#live-process-and-socket-state)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Framework State Directory

By default, Metasploit keeps all of its persistent state under `~/.msf4/` on the operator's machine:

| Path | Contents |
|---|---|
| `~/.msf4/history` | Every command typed at the `msfconsole` prompt, in order — the single richest artifact on this host, showing the exact `use`/`set`/`run` sequence for every module invoked, including any inline credentials passed via `set` |
| `~/.msf4/logs/` | Per-session and framework logs, if logging was enabled (`spool` command, or `set ConsoleLogging true`) — can contain full console I/O transcripts |
| `~/.msf4/loot/` | Auto-saved output from extensions and modules, each file timestamped and named by session/host — a direct manifest of what was harvested and when. What lands here scales with which extensions were loaded: `hashdump`/`kiwi` credential dumps, `screenshot` captures, `webcam_snap` stills and `record_mic` `.wav` clips, `clipboard_monitor_dump` text, `extapi`'s `ntds_parse` output, and anything pulled via `download` |
| `~/.msf4/db/` | The local PostgreSQL data directory backing the Framework database (hosts, services, credentials, session records) — see [Database Contents](#database-contents) below |
| `~/.msf4/local/` | Files staged for `upload`, or output from `download` — a direct record of file transfer activity per session |
| `*.rc` resource scripts | Wherever the operator saved them — a reusable, literal record of the exact module sequence used, often reused across engagements (see `../00 - Metasploit Overview.md`) |

## Database Contents

If the Framework database was initialized (`msfdb init` — the default on most installs), `msf_database` under PostgreSQL persists structured records independent of the console history:

```
msf6 > hosts
msf6 > services
msf6 > creds
msf6 > sessions -l   # historical + active sessions, if logging retained them
msf6 > loot
```
These tables are a direct, queryable record of every host touched, every credential recovered (including from `hashdump`/`kiwi`), and every session opened during any engagement run from this installation — unless the operator explicitly worked in a different `workspace` per engagement or ran `db_nuke`/deleted `~/.msf4/db/` to wipe it.

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Records the `msfconsole` invocation itself and any `msfvenom`/`msfrpcd` command lines run outside the console — but **not** the module-level activity, which lives in `~/.msf4/history` instead |
| zsh | `~/.zsh_history` | Same scope as bash — outer shell invocation only |

The split matters for investigators: shell history shows *that* Metasploit was launched; `~/.msf4/history` shows *what was done inside it*. Both are needed for a complete picture.

## Live Process and Socket State

```bash
ps aux | grep -iE "msfconsole|ruby.*metasploit|msfrpcd"
```
`msfconsole` runs as a long-lived Ruby process for the duration of the engagement; a backgrounded exploit handler (`exploit -j`) keeps a listening socket open even while the operator works elsewhere in the console. `msfrpcd`, if used for automation, runs as a separate daemon process independent of any interactive console.

```bash
ss -tlnp | grep -E ':4444|:8443'    # common handler ports, verify against LPORT actually configured
ss -tnp  | grep ESTAB               # active Meterpreter sessions mid-engagement
```
Argv for these processes is visible via `/proc/<pid>/cmdline` to any local user on a shared operator box, same exposure risk as any other CLI tool.

## Network Evidence

| Artifact | Command | Notes |
|---|---|---|
| Listening handler socket | `ss -tlnp` | A `reverse_tcp`/`reverse_https`/`reverse_http` handler is a **listening** socket on the operator side waiting for the target to connect *in* — opposite direction from `psexec`-style tools that connect *out* to the target |
| Established session sockets | `ss -tnp \| grep ESTAB` | One established connection per live Meterpreter session; correlate the remote IP against `hosts`/`sessions -l` in the Framework database |
| `bind_tcp` outbound connections | `ss -tnp` | For `bind_tcp` payloads, the operator's box is the one connecting *out* to the target's listener — the reverse direction from the transports above |
| `reverse_http`/`reverse_https` request pattern | Handler-side HTTP access pattern (if a reverse proxy sits in front of the handler) | Poll-based check-ins rather than one continuously held socket, since the underlying transport is WinInet-driven HTTP(S) on the target side — see `01 - Overview.md` |

## OS-Level Audit Trail

```bash
ausearch -x msfconsole 2>/dev/null
ausearch -x ruby 2>/dev/null       # msfconsole/msfrpcd run under the ruby interpreter
```
As with any tool, `auditd` syscall records (if enabled) are the artifact class most likely to survive deletion of `~/.msf4/history` or the shell history files, since they're generated independent of the application layer.

## Memory Forensics

If the operator box is imaged as part of an insider-threat or compromised-infrastructure investigation:
- A running `msfconsole`/`msfrpcd` process's memory can contain plaintext credentials passed via `set SMBPass`, `set PASSWORD`, etc., along with the **per-session RSA-negotiated AES-256-CBC keys** used for encrypted TLV traffic on Framework 6.0+ (see `01 - Overview.md`) — recovering a session key from operator-side memory, correlated with a captured PCAP of the encrypted channel, is a viable (if resource-intensive) path to decrypting recorded Meterpreter traffic after the fact.
- Loot and credential material that only ever touched the database/loot directory (never written to a log file) can still be present in Ruby's process memory well after use, due to garbage-collection timing — a full memory capture is a broader recovery path than the on-disk artifacts above.

## Timeline Correlation Value

`~/.msf4/history` timestamps are not recorded per-line by default (it's a flat command log, not a structured timestamped one) — bound activity using the surrounding artifacts instead: the loot file timestamps in `~/.msf4/loot/`, the database's `sessions.opened_at`/`closed_at` columns, and OS-level `auditd`/shell-history timestamps. Correlating an operator-side session-open timestamp (database or loot-file mtime) against the target-side process-creation and network-connection timestamps in `04 - Target Evidence.md` is what ties a specific operator box to a specific compromised host with confidence, exactly as with any other lateral-movement tool covered in this module.
