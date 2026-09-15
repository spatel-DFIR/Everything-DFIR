# Shells and Command History

Command history is one of the highest-yield artifacts on a compromised Linux host — when it survives, it's a near-verbatim transcript of what an interactive attacker typed. That's exactly why disabling or poisoning it is one of the first things a competent operator does, so this note covers both sides: every history artifact worth collecting, and every trick used to keep commands *out* of them. Shell startup files get equal weight because they're a dual artifact — they configure the shell *and* are a persistence vector, since a single appended line runs on every login.

> 🔴 Absence of history is itself evidence. A `.bash_history` that's empty, tiny, symlinked to `/dev/null`, or older than the account's last login means history was disabled or cleared — treat that as a finding, not a dead end, and pivot to auditd, journald, and `linux.bash` recovery from memory.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Shell Startup Files](#shell-startup-files)
- [History Files](#history-files)
- [History Hunting](#history-hunting)
- [History Anti-Forensics](#history-anti-forensics)
- [Timestamp Notes](#timestamp-notes)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# All shell histories, high-signal commands
grep -Ei "curl|wget|nc |ncat|socat|chmod \+x|base64|ssh|scp|sudo|su |python|perl|/dev/tcp" /home/*/.*_history /root/.*_history 2>/dev/null

# Every history-type file with modification time
find /home /root -type f \( -name "*history*" -o -name ".viminfo" -o -name ".lesshst" \) -ls 2>/dev/null

# History disabled or redirected (anti-forensics)
grep -RIEn "HISTFILE=/dev/null|unset HISTFILE|HISTSIZE=0|set \+o history" /home /root /etc 2>/dev/null

# Shell rc files modified recently (injected persistence)
find /home /root /etc -maxdepth 3 \( -name ".bashrc" -o -name ".bash_profile" -o -name ".profile" -o -name ".zshrc" \) -newermt "7 days ago" -ls 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| What did the attacker type interactively? | `grep -Ei "curl\|wget\|/dev/tcp\|base64" /home/*/.*_history /root/.*_history` |
| Was history disabled / poisoned? | `grep -RIEn "HISTFILE=/dev/null\|unset HISTFILE\|HISTSIZE=0\|ignorespace" /home /root /etc` |
| Persistence injected into a shell init file? | read `~/.bashrc`, `~/.profile`, `/etc/profile.d/*` fully; grep `BASH_ENV\|PROMPT_COMMAND\|LD_PRELOAD` |
| A script that runs on every SSH login? | `ls -l /home/*/.ssh/rc /etc/ssh/sshrc` |
| *When* did each command run? | zsh epoch (`: <epoch>:…`) / bash `HISTTIMEFORMAT` `#<epoch>` lines |
| Activity outside bash (editor/DB/less)? | `~/.viminfo`, `~/.lesshst`, `~/.mysql_history` |
| Is on-disk history stale (shell still running)? | compare `.bash_history` mtime vs `lastlog`; check `/proc/<shell>/environ` |
| Service-account (web/db) shell activity? | histories under `/var/www`, `/var/lib/*`, not just `/home` |

## Shell Startup Files

Whether a given startup file runs depends on how the shell was invoked — *login* vs *non-login*, *interactive* vs *non-interactive*. Attackers pick whichever fires most reliably for their access method (an SSH login sources the login files; an interactive shell sources `~/.bashrc`), which is why you check the whole set.

| Shell | System-wide | Per-user |
|-------|-------------|----------|
| bash (login) | `/etc/profile`, `/etc/profile.d/*` | `~/.bash_profile`, `~/.bash_login`, `~/.profile` |
| bash (interactive) | `/etc/bash.bashrc` | `~/.bashrc` |
| bash (logout) | — | `~/.bash_logout` |
| zsh | `/etc/zsh/zshrc`, `/etc/zsh/zprofile` | `~/.zshrc`, `~/.zprofile`, `~/.zlogin`, `~/.zshenv` |
| sh/dash | `/etc/profile` | `~/.profile` |
| 🔴 **ash / BusyBox** (Alpine, containers) | `/etc/profile`, `/etc/profile.d/*` | `$ENV` file (often `~/.ashrc` or `~/.profile`) |
| fish | `/etc/fish/config.fish` | `~/.config/fish/config.fish` |

🔴 **Alpine's default shell is `ash` (BusyBox), not bash** — its history file is `~/.ash_history`, and it reads the file named by the **`$ENV`** variable on startup (the ash analog of `BASH_ENV`), so a planted `ENV=/tmp/x` or a payload in `~/.ashrc` is the container-relevant persistence. Many minimal/container images have *no* bash at all.

**Also fires (non-rc execution hooks — easy to miss):**

| Trigger | What runs it |
|---------|--------------|
| `~/.ssh/rc`, `/etc/ssh/sshrc` | 🔴 Executed on **every SSH login** (before the shell) |
| `/etc/environment` | Sets env at login (e.g. a planted `LD_PRELOAD`) — not a script, but sourced by PAM |
| `BASH_ENV` / `ENV` env var | 🔴 Path sourced by **non-interactive** bash/sh (cron, scripts) |
| `PROMPT_COMMAND` | 🔴 Runs **before every prompt** — a payload here executes repeatedly |
| `~/.bash_logout` | Runs on logout (cleanup-on-exit trigger) |

```bash
# Inspect for injected commands
cat ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null

# System-wide injection points
ls -l /etc/profile.d/

cat /etc/profile /etc/bash.bashrc 2>/dev/null

# SSH-login hooks + env-based execution
ls -l /home/*/.ssh/rc /etc/ssh/sshrc 2>/dev/null

grep -REn "BASH_ENV|PROMPT_COMMAND|LD_PRELOAD" /etc/profile* /etc/bash.bashrc /home/*/.bashrc /root/.bashrc 2>/dev/null
```

🔴 **How this is abused:** a `curl … | bash`, an `LD_PRELOAD=` export, a reverse-shell one-liner, or a base64 blob appended to any of these files is persistence that fires on the next shell or login. `~/.bashrc` is the per-user favorite; `/etc/profile.d/*.sh` is the system-wide one — a single dropped file there backdoors every user's login shell. The subtler vectors are `BASH_ENV`/`PROMPT_COMMAND` (fire without an obvious rc edit) and `~/.ssh/rc` (fires on every SSH login). Because these files legitimately contain shell code, read them fully rather than grepping for a single pattern.

## History Files

Every shell and many interactive tools keep their own history file. Beyond the shell histories themselves, the tool histories (`.mysql_history`, `.viminfo`) often capture activity that never appeared in bash — credentials typed into a DB client, files an attacker opened in an editor.

| File | Shell / tool |
|------|--------------|
| `~/.bash_history` | bash |
| `~/.zsh_history` | zsh (extended format carries the epoch) |
| `~/.sh_history` / `~/.history` | ksh / others |
| `~/.python_history` | Python REPL |
| `~/.mysql_history` | mysql client 🔴 (creds, `INTO OUTFILE`) |
| `~/.psql_history` | psql |
| `~/.rediscli_history` | redis-cli |
| `~/.viminfo` | vim (recent files, search terms, register contents) |
| `~/.lesshst` | less (search history + shell-escape commands) |
| `~/.wget-hsts` | wget HSTS (hosts contacted) |
| `~/.node_repl_history` | Node REPL |
| `~/.local/share/fish/fish_history` | fish (YAML-style, carries timestamps) |
| `~/.sqlite_history` | sqlite3 client |
| `~/.ash_history` | 🔴 ash / BusyBox (Alpine, containers) |

History behavior is governed by environment variables, usually set in the rc files — check them, because they're both a legitimate config and an anti-forensics lever:

```bash
grep -E "HISTFILE|HISTSIZE|HISTFILESIZE|HISTTIMEFORMAT|HISTCONTROL|HISTIGNORE" /home/*/.bashrc /root/.bashrc /etc/profile* 2>/dev/null
```

## History Hunting

```bash
# High-value command patterns across all users
grep -Ei "curl|wget|git|apt|yum|dnf|chmod|nc |ncat|socat|bash|python|perl|\.sh|ssh|scp|sudo|su |ftp|base64|/dev/tcp|/dev/shm" /home/*/.*_history /root/.*_history 2>/dev/null

# Find and timestamp every history-type file
find /home /root -type f \( \
  -name "*history*" -o -name ".*history*" -o -name "*_history" -o \
  -name ".viminfo" -o -name ".lesshst" -o -name ".wget-hsts" -o -name ".nano_history" \
\) -ls 2>/dev/null

# zsh extended history includes the epoch: convert
grep -E '^: [0-9]+' ~/.zsh_history | head
```

zsh extended-history lines look like `: 1679084718:0;command` — the number after the first colon is the Unix epoch, giving you *when* each command ran. That per-command timestamp is a big advantage over plain bash history and lets you drop commands straight into a timeline.

## History Anti-Forensics

🔴 These are the standard ways operators keep commands out of history — hunt for *all* of them, because a single one blinds you to a whole session:

```bash
# Redirect or disable history in rc files or env
grep -RIEn "HISTFILE=/dev/null|unset HISTFILE|HISTFILESIZE=0|HISTSIZE=0|set \+o history|HISTCONTROL=ignorespace|HISTCONTROL=ignoreboth" \
  /home /root /etc 2>/dev/null

# Symlink history to /dev/null
find /home /root -name ".bash_history" -type l -ls 2>/dev/null

# History file suspiciously small/empty for an active account
find /home /root -name ".bash_history" -size 0 -ls 2>/dev/null
```

| Technique | Effect |
|-----------|--------|
| `HISTFILE=/dev/null` / `unset HISTFILE` | Nothing written to history |
| `HISTSIZE=0` / `HISTFILESIZE=0` | In-memory / on-disk history holds nothing |
| `HISTCONTROL=ignorespace` | 🔴 Any command typed with a *leading space* is not recorded |
| `set +o history` | Disables history for the session |
| `ln -sf /dev/null ~/.bash_history` | Permanent redirect to the bit bucket |
| `history -c` / `rm ~/.bash_history` | Clears the record (T1070.003) |
| `.bash_history` mtime older than last login | History wasn't updated during an active session → likely disabled |

The most insidious is `HISTCONTROL=ignorespace`: the attacker simply prefixes every command with a space and nothing is recorded, while the file looks perfectly normal. If you see `ignorespace`/`ignoreboth` set, assume the visible history is incomplete.

## Timestamp Notes

- Plain **bash** history has **no timestamps** unless `HISTTIMEFORMAT` is set — order is your only signal, and you can't directly place a command in time.
- With `HISTTIMEFORMAT` set, bash writes `#<epoch>` comment lines before commands.
- **zsh** extended history always carries the epoch (see above) — prefer it when present.
- Compare `.bash_history` mtime to the account's last login (`lastlog`, wtmp): if the file wasn't touched during a session the account clearly had, history was disabled for that session.

## Deep Threat Hunts

Consolidated shell-persistence + hidden-activity sweep. *(seasoned-DFIR additions on top of the RTR grep)*

```bash
# 1. Persistence payloads across EVERY shell init file (system + all users)
grep -REn "curl|wget|/dev/tcp|base64 -d|LD_PRELOAD|BASH_ENV|PROMPT_COMMAND|nc |bash -i" \
  /etc/profile /etc/bash.bashrc /etc/bashrc /etc/profile.d/ /etc/zsh/ \
  /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /home/*/.zshrc /root/.bashrc /root/.profile 2>/dev/null

# 2. SSH-login-triggered scripts (run on every ssh in)
ls -l /home/*/.ssh/rc /etc/ssh/sshrc 2>/dev/null

# 3. Env-based execution hooks (non-interactive shells source these)
grep -REn "BASH_ENV|^ENV=|PROMPT_COMMAND" /etc /home /root 2>/dev/null

# 4. HISTFILE pointed somewhere non-default (attacker's private/removable history)
grep -REn "HISTFILE=" /home /root /etc 2>/dev/null | grep -v "/.bash_history"

# 5. Running shells: live env may differ from on-disk rc (still-buffered history)
for p in $(pgrep -x bash; pgrep -x zsh 2>/dev/null); do
  echo "== pid $p =="; tr '\0' '\n' < /proc/$p/environ 2>/dev/null | grep -E 'HIST|PROMPT_COMMAND|LD_PRELOAD|BASH_ENV'
done

# 6. Service-account histories (web/db users are often the real attacker context)
grep -Ei "curl|wget|/dev/tcp|base64|chmod \+x" /var/www/.*history* /var/lib/*/.*history* /home/*/.*history* 2>/dev/null

# 7. Cleanup command caught in the buffer (cleared history, but the flush recorded it)
grep -HnE "history -c|rm .*history|shred .*history|>.*bash_history" /home/*/.bash_history /root/.bash_history 2>/dev/null
```

**Hunt ideas:**

- **On-disk history flushes only on clean shell exit.** A still-running attacker shell keeps its commands in RAM — if the on-disk copy is empty or stale, recover them from a memory image (`linux.bash` → Memory Forensics).
- **Time-correlate commands against logins.** A history command whose epoch has *no* surrounding interactive login (auth log / wtmp) was likely injected by cron/systemd, not typed.
- **`BASH_ENV`/`PROMPT_COMMAND`/`~/.ssh/rc` are underrated persistence** — they execute without an obvious edit to the top of `.bashrc`. Always check them.
- **mtime vs lastlog.** A `.bash_history` older than the account's last login means history wasn't written that session — assume it was disabled and pivot.

## Getting Max Value

- **Collect the whole dotfile + history set per user before touching anything** — reading bumps `atime`, and a live shell can overwrite `.bash_history` on exit. Grab `.*_history`, `.viminfo`, `.lesshst`, and all rc/init files together.
- **Prefer timestamped history** — zsh extended history and bash-with-`HISTTIMEFORMAT` give per-command epochs that drop straight into a timeline; plain bash gives order only.
- **Blank history is a lead, not a dead end** — pivot to auditd `EXECVE`, journald `_CMDLINE`, and memory `linux.bash`.
- **Parse `.viminfo` and `.lesshst`** — they capture what bash didn't: files opened in an editor, search terms, and `!cmd` shell escapes from within `less`/`vim`.
- **Don't stop at `/home`** — root's history and service-account histories (`/var/www`, `/var/lib/*`) are where the real attacker context often is.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Recover history the on-disk file lost | **Memory Forensics** (11, `linux.bash`) |
| Confirm a command actually executed (+ as whom) | **Auditd** (`EXECVE`), **Systemd Journal** (`_CMDLINE`) |
| Was an rc-file line real persistence? | **Persistence → Shell Startup and Profile Scripts** |
| `LD_PRELOAD` in an rc/env | **Persistence → Preload Hijacking** |
| Tie a command's time to a login session | **Authentication and Login Records** (`last`, wtmp) |
| Classify how the shell was launched (ssh/cron/web) | **Process Trees and Execution Lineage** (10b) |
| An rc edit's exact plant time | **Permissions** (timestomp check), **Timelining** (13) |

## Scenarios

- **Interactive attacker transcript:** a surviving `.bash_history`/`.zsh_history` is a near-verbatim log of what was typed — the fastest way to understand hands-on-keyboard activity.
- **History poisoned:** `HISTCONTROL=ignorespace` + space-prefixed commands, or `HISTFILE=/dev/null` — visible history looks normal but is incomplete; pivot to auditd/memory.
- **rc-file persistence:** a `curl|bash` or reverse-shell line in `~/.bashrc` or `/etc/profile.d/*.sh` re-establishes access on every login.
- **Stealth hook:** `BASH_ENV` or `PROMPT_COMMAND` set to a payload path — runs with no obvious rc edit.
- **Evidence outside bash:** `.viminfo` shows the attacker opened `/etc/shadow`; `.mysql_history` shows an `INTO OUTFILE` exfil.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `HISTFILE`/`HISTSIZE` disabled in rc or env | Deliberate history evasion |
| `~/.bash_history` symlinked to `/dev/null` | Permanent evasion |
| Empty/tiny history for an account that clearly logged in | History cleared or disabled |
| `curl\|bash`, reverse-shell, base64 blob in an rc file | Persistence on next shell |
| `HISTCONTROL=ignorespace`/`ignoreboth` set | Space-prefixed commands hidden |
| `.viminfo`/`.lesshst` referencing sensitive files an attacker opened | Activity evidence outside bash history |
| `.mysql_history` with `INTO OUTFILE`/creds | DB abuse / exfil |
| `BASH_ENV`/`PROMPT_COMMAND` set to a script path | Stealth persistence w/o obvious rc edit |
| `~/.ssh/rc` or `/etc/ssh/sshrc` present/modified | Runs on every SSH login |
| `HISTFILE=` pointed to a non-default/removable path | Attacker hiding their own history |
| `.bash_history` mtime older than account's last login | History disabled for that session |

## Resources

- `bash(1)` (HISTORY / STARTUP FILES sections), `zshoptions(1)`, `ssh(1)` (`~/.ssh/rc`), `pam_env(8)` man pages
- MITRE ATT&CK: T1070.003 (Clear Command History), T1546.004 (Unix Shell Configuration Modification), T1059.004 (Unix Shell), T1552.003 (Credentials in Bash History)
