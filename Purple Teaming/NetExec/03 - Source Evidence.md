# NetExec — Source Evidence

What an operation leaves on the **attacking/operator host** — verified directly against `nxc/paths.py`, `nxc/connection.py`, and `nxc/logger.py` in the live source, rather than assumed.

## Contents
- [The `~/.nxc/` Workspace — the Richest Single Artifact](#the-nxc-workspace--the-richest-single-artifact)
- [Per-Session Log Files](#per-session-log-files)
- [Shell/Command History](#shellcommand-history)
- [Process and Network-Connection Exposure](#process-and-network-connection-exposure)
- [Cached PowerShell Obfuscation Artifacts](#cached-powershell-obfuscation-artifacts)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline-Correlation Value](#timeline-correlation-value)

---

## The `~/.nxc/` Workspace — the Richest Single Artifact

Every install writes to a single, predictable, non-configurable-by-default base directory: **`~/.nxc/`** (overridable only by explicitly setting the `NXC_PATH` environment variable — confirmed directly in `nxc/paths.py`, `normpath(expanduser("~/.nxc"))` is the fallback with no CLI flag to relocate it). On a seized operator workstation or a cloud instance used as an attack platform, this single directory recovers most of an entire engagement's history:

```
~/.nxc/
├── nxc.conf                       # workspace name, pwn3d_label, BloodHound/Empire/MSF
│                                   #   integration credentials if configured
├── workspaces/
│   └── <workspace_name>/
│       ├── smb.db                 # SQLite: every host touched, every credential tried,
│       │                          #   every successful auth, admin status, loot metadata
│       ├── ldap.db
│       ├── winrm.db
│       ├── mssql.db
│       └── ...                    # one SQLite DB per protocol ever used in this workspace
├── logs/
│   └── <output_folder>/           # sam/ lsa/ ntds/ dpapi/ (one subfolder per artifact type)
│       └── <hostname>_<ip>_<YYYY-MM-DD_HHMMSS>.<ext>
└── tmp/                           # scratch files for in-flight operations
```

The **workspace SQLite databases are the single most valuable operator-host artifact this tool produces**, confirmed directly against the source: they persist every host contacted, every credential attempted (plaintext, hash, or Kerberos material), every successful authentication with its admin-rights status, and any loot/output-file metadata recorded by a module — a durable, structured, queryable record of the *entire* engagement scope, not just the most recent invocation. Recovering `~/.nxc/workspaces/*/smb.db` from an operator host is functionally equivalent to recovering their entire target list and credential-validation results in one file.

The **log tree's filename convention itself is directly informative**: every `--sam`/`--lsa`/`--ntds`/`--dpapi` output file is named `<hostname>_<ip>_<timestamp>.<ext>` — meaning the filenames alone (without opening a single file) enumerate exactly which hosts were dumped and precisely when, in a UTC-independent local-clock timestamp useful for timeline correlation against target-side event logs.

## Per-Session Log Files

Independent of the SQLite databases, NetExec writes a general per-target text transcript under `~/.nxc/logs/<hostname>_<ip>_<timestamp>` (the base, non-subfoldered filename set in `proto_flow()`) capturing the console output for that host's session — host info, auth result, and command/module output. `--log <path>` redirects/duplicates this to an operator-chosen location, which is itself worth checking for (a custom `--log` destination outside `~/.nxc/` is a deliberate operator choice to keep engagement data out of the default, well-known path).

## Shell/Command History

`nxc` is invoked from a normal interactive or scripted shell — standard shell-history artifacts apply and are the fastest way to reconstruct exact command lines and timing if the workspace database itself isn't recovered or was on a different host:

- Bash: `~/.bash_history` (if `HISTFILE`/`HISTCONTROL` weren't manipulated)
- Zsh: `~/.zsh_history`
- Any wrapping automation (a shell script looping `nxc` over a target file, common for the fleet-wide use cases in `02`) — the script file itself, if left on disk, documents the entire intended scope even without a single history line

Full `-u`/`-p`/`-H` credential material appears in plaintext on these command lines unless the operator deliberately avoided direct CLI credential passing (e.g., piping from a credential manager or using `-id` to reference an already-stored database credential instead of retyping it — itself a signal that a *prior* session's database is the richer artifact to pull).

## Process and Network-Connection Exposure

- **Process list**: `nxc` runs as a Python process (`python3` or the `nxc`/`netexec` pipx-shimmed entry point) — the full command line is visible in `ps aux`/`/proc/<pid>/cmdline` for the process's lifetime, same exposure window as any other CLI tool documented elsewhere in this module.
- **Network-connection state**: because the default thread count is **256**, a live `nxc` run against a large target range shows as a burst of simultaneous outbound TCP connections to the same destination port (445/389/5985/etc.) across dozens-to-hundreds of distinct destination IPs from the single operator host — `netstat`/`ss` output during (or shortly after, for `ESTABLISHED`/`TIME_WAIT` state) a run is a strong live-response indicator distinct from normal single-target tool usage.
- **DNS resolution cache**: if hostnames (rather than raw IPs) were used as targets, the operator host's local DNS resolver cache/logs carry a parallel record of every hostname resolved during the run.

## Cached PowerShell Obfuscation Artifacts

When `--obfs` is used with `-X`, NetExec caches generated obfuscated PowerShell scripts locally (`--clear-obfscripts` exists specifically to purge this cache) rather than regenerating one from scratch on every invocation. A left-behind obfuscation cache directory is direct evidence of `-X --obfs` having been used, and recovering it may allow reversing the obfuscation back to the literal PowerShell that was pushed to targets — a source-side shortcut around whatever target-side logging did or didn't capture the delivered payload in cleartext.

## Memory-Forensics Angle

NetExec is short-lived per invocation (it exits when the target loop completes) rather than a persistent daemon, so classic "dump a running process's memory" forensics has a narrow live window. What's more durable in memory forensics terms:

- **Credential material in the Python process's own memory** while running — plaintext passwords, NTLM hashes, and Kerberos keys/tickets used for the session are held in the interpreter's memory for the run's duration, recoverable via a memory dump captured *during* execution (a narrow live-response window, not a post-hoc artifact).
- **The SQLite workspace databases persist this same credential material to disk by design** — meaning for NetExec specifically, a live memory capture is far less valuable than simply recovering `~/.nxc/workspaces/` from disk, unlike tools that hold credential material only transiently in memory with no disk-persisted equivalent.

## Timeline-Correlation Value

Cross-referencing the workspace database's per-host authentication timestamps and the log-tree's per-file timestamps against the target-side event-log timestamps in `04 - Target Evidence.md` (Security 4624/4625, Sysmon Network Connect, the `\svcctl` admin-check RPC calls) gives a tight, minute-level bidirectional timeline: the operator host proves *intent and scope* (which hosts were targeted, in what order, with which credentials), while the target hosts prove *what actually landed* — the same source-proves-scope/target-proves-effect correlation pattern used throughout this module (e.g. `Rclone/03 - Source Evidence.md`'s config-file scope vs. target-side transfer volume).
