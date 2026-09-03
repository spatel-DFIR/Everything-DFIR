# Metasploit — msfconsole — Source Evidence

Evidence left on the **attacking/operator** host — the box `msfconsole` was actually run from. Because msfconsole is a full framework with its own persistent state directory and database rather than a lightweight single-purpose script, its operator-side footprint is unusually rich compared to most tools in this module — closer to investigating an application than a CLI utility. Much of the `~/.msf4/` directory below is shared ground with `../Meterpreter/03 - Source Evidence.md` and `../msfvenom/03 - Source Evidence.md` (those pages cover the same directory from the session/payload-generation angle); this page is the canonical breakdown of the directory itself, since msfconsole is what actually creates and writes to it.

## Contents
- [Framework State Directory (`~/.msf4/`)](#framework-state-directory-msf4)
- [Database Contents](#database-contents)
- [Resource Scripts as Artifacts](#resource-scripts-as-artifacts)
- [Shell History](#shell-history)
- [Live Process and Socket State](#live-process-and-socket-state)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Framework State Directory (`~/.msf4/`)

| Path | Contents | Notes |
|---|---|---|
| `~/.msf4/history` | Every command typed at the `msfconsole` prompt, in order — the single richest artifact on this host | Flat, unencrypted, **no per-line timestamp**. Any line prefixed with a leading space is deliberately excluded — a documented suppression convention, same intent as bash's `HISTCONTROL=ignorespace`. A custom `-H`/`--history-file` path at launch redirects this entirely away from the default location |
| `~/.msf4/msfconsole.rc` | A resource script that runs **automatically every time `msfconsole` starts**, before any interactive input | Not a session log — an operator-authored startup configuration file (commonly `setg` values, an auto-loaded handler, etc.). Its presence and contents show what the operator wanted primed on *every* launch, not just one session |
| `~/.msf4/config` | The datastore snapshot written by the `save` command | Persists anything set with `set`/`setg` (including credentials passed as option values) across restarts — auto-loaded on every future launch until overwritten by another `save` |
| `~/.msf4/database.yml` | Database connection settings | Overridable per-launch with `-y`/`--yaml` |
| `~/.msf4/db/` | The local PostgreSQL data directory backing the Framework database, if `msfdb init` was used | See [Database Contents](#database-contents) below |
| `~/.msf4/logs/framework.log` | Framework-internal log, verbosity controlled by the `LogLevel` global datastore option (0–3, default 0 — i.e. **off** by default) | Absence is the default state, not evidence of evasion; presence at a non-default verbosity means the operator deliberately raised it |
| `~/.msf4/logs/console.log` | Full console I/O transcript, written only if `ConsoleLogging` was set to `true` | Also off by default — same reasoning as above |
| `~/.msf4/loot/` | Auto-saved output from modules and extensions — credential dumps, screenshots, downloaded files — each entry timestamped and named by session/host | A direct manifest of what was harvested and when; see `../Meterpreter/03 - Source Evidence.md` for the extension-specific breakdown of what lands here |
| `~/.msf4/local/` | Files staged for `upload`, or output from `download`, during a Meterpreter session | Direct record of file-transfer activity |
| `~/.msf4/persist` | JSON records of payload-handler jobs marked with `jobs -p`/`-P` for auto-restart on the next launch | A durable, disk-resident configuration artifact — proves the operator intended a listener to survive a console restart, independent of anything in `history` |
| `~/.msf4/plugins/` | User-installed plugins, loaded via `load <plugin>` | Third-party or custom plugins here (vs. the Framework's own bundled `plugins/` directory) indicate the operator extended stock functionality |
| `*.rc` resource scripts | Wherever the operator saved them — not confined to `~/.msf4/` | See [Resource Scripts as Artifacts](#resource-scripts-as-artifacts) below |

## Database Contents

If the Framework database was initialized (`msfdb init` — the default on most installs) and not explicitly disabled with `-n`/`--no-database`, the Postgres-backed database persists structured, queryable records independent of `~/.msf4/history`:

```
msf6 > workspace -l       # every workspace (engagement) this install has ever touched
msf6 > hosts
msf6 > services
msf6 > creds
msf6 > loot
msf6 > vulns
msf6 > sessions -l        # historical + active sessions, if retained
```
These tables are a direct record of every host touched, every credential recovered, and every session opened across any engagement ever run from this installation — scoped per `workspace`, unless the operator explicitly worked everything in `default` or ran `db_nuke`/deleted `~/.msf4/db/` to wipe it. A `workspace -l` output listing multiple, differently-named workspaces is itself useful triage context: it tells an investigator how many distinct engagements (or intrusions) this one installation has been used for.

## Resource Scripts as Artifacts

Unlike `~/.msf4/history`'s unstructured, unordered command log, a `.rc` resource script is a **deliberately authored, literal record of an exact attack sequence** — an operator wrote it, presumably to reuse it. Where these turn up matters:

| Location | Significance |
|---|---|
| `~/.msf4/msfconsole.rc` | Auto-run on every launch — see above |
| Anywhere referenced by a `-r` flag in shell history | The exact path shows where the operator keeps their scripted attack chains, often a dedicated `scripts/`/`rc/` directory reused across engagements |
| Output of `makerc <file>` | A literal, ordered transcript of whatever commands preceded it in that session — functionally a curated excerpt of `~/.msf4/history` the operator considered worth keeping |
| `<install_dir>/scripts/resource/` | Framework-bundled example scripts (e.g. `autoexploit.rc`) — presence of a *modified* copy here, or timestamps inconsistent with the package install date, suggests operator customization |

A resource script recovered from an operator box is high-value evidence: unlike a single history line, it's the operator's own record of what they considered a "repeatable" sequence — read it and you're reading their playbook.

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Records the `msfconsole` invocation itself — including any `-r`/`-x`/`-p` flags — and any `msfvenom`/`msfrpcd` commands run outside the console. Does **not** capture module-level activity, which lives in `~/.msf4/history` instead |
| zsh | `~/.zsh_history` | Same scope as bash — outer shell invocation only |

The split matters: shell history shows *that* Metasploit was launched and *how* (quiet mode, a specific resource script, an inline `-x` chain); `~/.msf4/history` shows *what was done inside it*. A launch line using `-x "use exploit/multi/handler; set PAYLOAD ...; set LHOST ...; run -j"` is especially valuable — the **entire** operational intent of that invocation is visible in one shell-history line, with no need to separately recover the console's own history file at all.

## Live Process and Socket State

```bash
ps aux | grep -iE "msfconsole|ruby.*metasploit|msfrpcd"
```
`msfconsole` runs as a long-lived Ruby process for the duration of the engagement. A backgrounded `multi/handler` job (`exploit -j`) keeps a listening (or, for `bind_tcp`, outbound-connecting) socket open even while the operator works elsewhere in the console — it does not require the operator to still be actively typing.

```bash
ss -tlnp | grep -E ':4444|:8443'    # common handler ports — verify against configured LPORT, don't assume defaults
ss -tnp  | grep ESTAB               # active sessions mid-engagement
```
Full argv for these processes — including any credential material passed as CLI arguments rather than typed into `set` — is visible via `/proc/<pid>/cmdline` to any local user on a shared operator box, the same exposure risk as any other CLI tool covered in this module.

## Network Evidence

| Artifact | Command | Notes |
|---|---|---|
| Listening handler socket | `ss -tlnp` | A `reverse_tcp`/`reverse_https`/`reverse_http` handler is **listening**, waiting for a target to connect *in* — the opposite direction from tools elsewhere in this module (e.g. `psexec.py`) that connect *out* to a target |
| Established session sockets | `ss -tnp \| grep ESTAB` | One established connection per live session; correlate the remote IP against `hosts`/`sessions -l` in the Framework database |
| `bind_tcp` outbound connections | `ss -tnp` | For `bind_tcp` payloads, the operator's box is the one connecting *out* — reversed from the transports above |
| DNS/resolver activity | `systemd-resolved` journal | If the operator's `db_nmap`/module targets were hostnames rather than raw IPs |

## OS-Level Audit Trail

```bash
ausearch -x msfconsole 2>/dev/null
ausearch -x ruby 2>/dev/null       # msfconsole/msfrpcd both run under the ruby interpreter
```
If `auditd` is running with syscall auditing enabled (not default on most distros, but common on hardened operator boxes or monitored red-team infrastructure), this is the artifact class most likely to survive deletion of `~/.msf4/history`, `~/.msf4/config`, or the shell-history files entirely — it's generated at the kernel level, independent of anything the application layer chooses to write or suppress.

## Memory Forensics

If the operator box itself is imaged as part of an insider-threat or compromised-infrastructure investigation:
- A running `msfconsole`/`msfrpcd` process's memory can contain plaintext credentials passed via `set SMBPass`, `set PASSWORD`, or similar options, along with any Meterpreter session encryption keys currently negotiated (see `../Meterpreter/03 - Source Evidence.md` for the AES-256-CBC session-key detail specific to that payload).
- Ruby's own process memory retains recently-used string objects — including datastore values entered via `set`/`setg` — well past their last use in code, due to garbage-collection timing. A full memory capture (`gcore`, or a VM snapshot) followed by string/pattern search against known target IPs or credential formats is a viable recovery path this section's on-disk artifacts don't cover, particularly useful when `-H` was used to relocate the history file somewhere not yet found.

## Timeline Correlation Value

`~/.msf4/history` carries no per-line timestamp by default — bound activity using the artifacts around it instead: `~/.msf4/loot/` file mtimes, the database's `sessions.opened_at`/`closed_at` columns, `~/.msf4/config`'s own mtime (last time `save` ran), and OS-level `auditd`/shell-history timestamps. Correlating an operator-side session-open timestamp (database or loot-file mtime) against the target-side process-creation and network-connection timestamps documented in `04 - Target Evidence.md` (or, for the caught session itself, `../Meterpreter/04 - Target Evidence.md`) is what ties a specific operator box to a specific compromised host with confidence — exactly the same correlation principle used for every other lateral-movement tool in this module.
