# Hydra — Source Evidence

What the **host running Hydra** leaves behind. Because every Hydra attempt is a real, complete authentication handshake against the target's own service (see `01`'s How It Works), there is no Hydra-specific wire artifact to find on the network layer — what's distinctive here is entirely local to the attacking host: shell history, the `hydra.restore` checkpoint file, process behavior, and the local network-connection state a high-parallelism run produces.

## Contents
- [Shell / Command History](#shell--command-history)
- [The `hydra.restore` Session File](#the-hydrarestore-session-file)
- [Process Artifacts](#process-artifacts)
- [Local Network-Connection State](#local-network-connection-state)
- [Wordlist and Output Files](#wordlist-and-output-files)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell / Command History

Hydra is invoked from an interactive shell or a script far more often than through any GUI (`xhydra` exists but is rarely the operational default) — so its command line is the richest single source-side artifact, and it's almost never sanitized:

- **`.bash_history`/`.zsh_history`** (or the shell-appropriate equivalent) on a Linux/macOS attacking host captures the full invocation verbatim — target, protocol, login/password-file paths, and any `-e`/`-C`/`-x` mode flags. Unlike some tools, Hydra's command line rarely contains raw credential *material* itself (the passwords live in the `-P`/`-C` file, not the command line) — but the **file paths themselves** are highly informative: a filename like `rockyou.txt`, `top1000_2026.txt`, or `breached_corp_pairs.txt` tells an analyst exactly what kind of attack was staged, and the target string names the victim directly.
- **PowerShell history** (`(Get-PSReadlineOption).HistorySavePath`, typically `ConsoleHost_history.txt`) if Hydra is run from a Windows-hosted attacking box (via WSL, Cygwin, or a compiled Windows port) — same content, same value.
- **Shell environment variables** — `HYDRA_PROXY`/`HYDRA_PROXY_HTTP`, if set via `export`, land in the shell's session environment and, depending on shell configuration, may also be visible in `.bashrc`/`.zshrc`/a wrapper script if the operator made the proxy setting persistent rather than one-off. A recovered proxy URL directly names the pivot/anonymization infrastructure the operator relied on.
- **Shell/terminal scrollback or `script`-recorded session logs**, where present, capture Hydra's live per-attempt console output (with `-v`/`-V`) — including every login/password pair actually tried, which is otherwise not written anywhere else unless `-o` was used.

## The `hydra.restore` Session File

The one artifact that is genuinely specific to Hydra rather than generic shell/process evidence. Verified directly against `hydra.c` source (`RESTOREFILE "./hydra.restore"`, `hydra_restore_write()`/`hydra_restore_read()`):

- **Location is relative, not fixed.** It is written to `./hydra.restore` — i.e., whatever directory the operator's shell had as its current working directory at the moment Hydra was launched. There is no single well-known absolute path to search; an analyst has to locate the operator's working directory first (shell history's `cd`/launch context, or a filesystem-wide search for files named `hydra.restore`).
- **Write timing:** a full binary checkpoint is written periodically during a long-running attack — the source enforces this at `time(NULL) - elapsed_restore > 299` seconds (roughly every 5 minutes, matching the README's own stated behavior), and again on clean exit or interrupt (Ctrl-C/SIGTERM). A **file modification timestamp on `hydra.restore` that's mid-run (not at process start or a round 5-minute boundary from start) is a reliable marker that the attack was still actively running at that point** — useful for bounding "when was this operator's attack still in progress" independent of any target-side evidence.
- **Content is a full session checkpoint**, sufficient to resume mid-list on `hydra -R`: target(s), protocol/module, remaining credential-list position, and run configuration. This means a recovered `hydra.restore` can itself reveal the target and attack parameters even if shell history was cleared or never captured — treat it as an independent source of the same information the command line would have shown.
- **Cross-platform/version portability is deliberately restricted.** `hydra_restore_read()` validates the file was written by a compatible Hydra version and rejects a restore file written on a different platform/endianness (the README states this explicitly). A recovered `hydra.restore` therefore also weakly fingerprints the operator's own build environment (same OS family/architecture as whatever host it can be replayed on).
- **Permissions/ownership as a forensic tell in their own right.** Current source (the in-progress `9.8-dev` hardening pass noted in `01`) opens the file `0600` and validates on read that it is a regular file owned by the invoking user, refusing to trust it otherwise — meaning on any reasonably current Hydra build, `hydra.restore`'s owning UID directly names the operator's own local account, even in a shared/multi-user attacking environment (a shared pentest jump box, for instance).
- **The file is not deleted after a successful resume or a completed run** unless the operator does so manually — a stale `hydra.restore` sitting in a directory long after the associated attack finished is a durable, easily-overlooked leftover artifact on shared or reused attacking infrastructure.

## Process Artifacts

- **Process list / `ps`/`Get-Process` output** during a live run shows the `hydra` process (or `xhydra` for the GUI) as the parent, with the full command line visible via `/proc/<pid>/cmdline` on Linux or equivalent Windows process-creation telemetry — this is the direct target for Sysmon Event ID 1/Security 4688-style logging (see below) or its Linux `auditd`/`execve` equivalent.
- **File descriptor / handle count** on the Hydra process during a high-`-t` run is unusually large — dozens to over a hundred simultaneous open sockets — visible via `lsof -p <pid>` or `/proc/<pid>/fd`, a coarse but real behavioral anomaly if the attacking host itself is under EDR/host-monitoring (relevant when Hydra is run from a compromised pivot host rather than the operator's own laptop).
- **Child processes**: none under normal operation — Hydra's protocol modules run in-process (or as internally-forked worker processes on Unix, per its `fork()`-based task model), not as separate spawned executables, so there is no distinctive child-process tree to hunt the way there is for tools that shell out.

## Local Network-Connection State

A live Hydra run against a single target with a meaningfully high `-t` produces a **burst of simultaneous outbound connections from one source process to one destination IP:port** — visible on the attacking host itself via `netstat`/`ss`/`Get-NetTCPConnection`, and directly correlatable against the target's own connection-log/NetFlow view of the same burst (see `04 - Target Evidence.md`'s network-layer section). On the source side specifically:

- The connection count roughly tracks `-t` (per-target) or `-T` (across an `-M` list) — a sustained double-digit-plus count of ESTABLISHED/SYN-SENT sockets to a single destination service port, sourced from one process, is the local-host mirror of the burst pattern a target-side analyst would independently notice.
- `-c` (the timing throttle) collapses this to effectively one connection at a time (`-c` forces `-t 1`) — a deliberately slowed/throttled run looks materially different in local connection-state terms from a default/fast run, which matters when correlating "was this operator trying to be quiet."
- If `HYDRA_PROXY`/`HYDRA_PROXY_HTTP` is set, the locally-visible destination is the **proxy**, not the real target — the attacking host's own connection table will show a single (or a rotating handful, for a proxy-list) destination that is itself worth identifying, since it's infrastructure the operator controls or was routing through.

## Wordlist and Output Files

- **Login/password list files** (`-L`/`-P`/`-C`) referenced by the command line persist on disk at whatever path was given — recovering these files directly (not just their filenames from history) shows the exact candidate set attempted, which can itself be fingerprinted (a well-known public wordlist like `rockyou.txt` vs. a custom, target-organization-specific list built from OSINT, which is a stronger indicator of a targeted rather than opportunistic operation).
- **`-o FILE` output**, if used, is a plaintext/JSON file of every successful login/password pair found — the single highest-value recovered artifact if present, since it directly states which credentials the operator confirmed valid, in the operator's own words, independent of anything the target-side logs can show about *which* attempt in a long burst actually succeeded.
- **`pw-inspector`-filtered wordlists** (Hydra's companion tool, used to trim a dictionary down to a target's known password-policy shape before running Hydra against it) may exist alongside the raw source list — their presence indicates the operator had prior reconnaissance on the target's password policy.

## Memory Forensics

Hydra holds the in-progress credential list, current position, and any already-found pairs in process memory for the duration of a run — a live memory capture of the Hydra process itself (not a target process) during execution can recover the full candidate list and results even before `-o` writes anything to disk or the periodic `hydra.restore` checkpoint fires. This matters specifically for a run interrupted **between** restore-file checkpoints (i.e., killed less than 5 minutes after its last automatic save) — the on-disk `hydra.restore` may be stale relative to the process's actual in-memory progress at the moment of capture.

## Timeline Correlation Value

`hydra.restore`'s periodic write timestamps and the shell-history invocation timestamp together bound the attack window precisely on the source side — invocation time as the start, the restore file's final modification time (or process-exit time, if captured live) as a lower bound on the end. That window is the anchor for correlating against `04 - Target Evidence.md`'s protocol-specific burst pattern: the target-side authentication-failure cluster should fall entirely within (or very shortly after) this source-side window, and any successful authentication event on the target that falls inside the window — but *outside* the timestamps a legitimate user's own known activity would explain — is the pivot point from "brute-force attempt" to "confirmed foothold." A recovered `-o` output file, where present, shortcuts this correlation entirely by stating the successful pair and (via its own file-modification timestamp) approximately when it was found.
