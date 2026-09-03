# More Persistence Mechanisms

Beyond the major vectors with their own notes, Linux offers a long tail of smaller persistence spots — each less common, but each a real place attackers hide, and collectively the ones responders most often miss. This note groups them: event-triggered scripts (udev, NetworkManager), login-triggered scripts (XDG autostart, MOTD), legacy init, package and developer hooks, and privilege primitives left as re-entry. Each section is self-contained with its own detection.

> 🔴 These are the "did you check *everywhere*" mechanisms. When the major vectors come up clean but you're sure there's persistence, sweep this list — a `RUN+=` in a udev rule, a script in `/etc/update-motd.d/`, or a `core.hooksPath` in a developer's git config are all root- or user-level execution triggers that a standard persistence check skips.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [udev Rules](#udev-rules)
- [XDG Autostart](#xdg-autostart)
- [MOTD and update-motd](#motd-and-update-motd)
- [NetworkManager Dispatcher](#networkmanager-dispatcher)
- [Non-systemd Init](#non-systemd-init)
- [Package Manager Hooks](#package-manager-hooks)
- [Git Hooks and Language Ecosystems](#git-hooks-and-language-ecosystems)
- [More Overlooked Triggers](#more-overlooked-triggers)
- [Capabilities and SUID Re-entry](#capabilities-and-suid-re-entry)
- [Trojanized System Binaries](#trojanized-system-binaries)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Event/login-triggered script dirs, all at once
grep -rEl "RUN\+?=|Exec=|curl|wget|bash -c|/tmp/|/dev/shm" \
  /etc/udev/rules.d/ /lib/udev/rules.d/ /etc/xdg/autostart/ /home/*/.config/autostart/ \
  /etc/update-motd.d/ /etc/NetworkManager/dispatcher.d/ /etc/rc.local /etc/init.d/ 2>/dev/null

# Privilege primitives left for re-entry
getcap -r / 2>/dev/null | grep -E "cap_setuid|cap_dac"; find / -perm -4000 -newermt "7 days ago" -ls 2>/dev/null

# Trojaned system binaries
rpm -Va 2>/dev/null | grep -E '^..5' | grep -E "/bin/|/sbin/"; debsums -c 2>/dev/null
```

## What to Check for What

| Investigative question | Vector / command |
|------------------------|------------------|
| Device-event trigger? | udev `RUN+=` in `/etc/udev/rules.d/` |
| Root-on-login (Debian)? | `/etc/update-motd.d/` scripts |
| GUI-login trigger? | XDG `.desktop` `Exec=` |
| Connectivity trigger? | NetworkManager `dispatcher.d/` |
| Runs as root on **any crash**? | `cat /proc/sys/kernel/core_pattern` (leading `\|`) |
| File-type execution handler? | `/proc/sys/fs/binfmt_misc/` |
| Network backdoor listener? | `/etc/xinetd.d/`, `/etc/inetd.conf` |
| Package-operation trigger? | `Post-Invoke` in `/etc/apt/apt.conf.d/` |
| Dev-activity trigger? | `.git/hooks`, `core.hooksPath`, npm `postinstall` |
| Re-entry to root? | `getcap` `cap_setuid`; recent SUID-root binary |
| Trojaned system binary? | `rpm -Va`/`debsums` on `/bin`,`/sbin` |

## udev Rules

udev runs rules on device events (add/remove), and a rule with `RUN+=` executes a program — persistence that fires on hardware events or boot.

```bash
ls -l /etc/udev/rules.d/ /lib/udev/rules.d/ /run/udev/rules.d/ 2>/dev/null

# Rules that RUN a program
grep -rEH "RUN\+?=" /etc/udev/rules.d/ /lib/udev/rules.d/ 2>/dev/null
```

🔴 A `RUN+="/path/to/script"` (especially with `ACTION=="add"` on a common subsystem so it triggers reliably) pointing at an unexpected script is device-event persistence. Unowned rule files are the tell.

## XDG Autostart

Desktop-session persistence: a `.desktop` file with an `Exec=` line runs at graphical login.

```bash
ls -l /etc/xdg/autostart/ /home/*/.config/autostart/ 2>/dev/null

grep -rEH "Exec=" /etc/xdg/autostart/ /home/*/.config/autostart/ 2>/dev/null
```

🔴 `Exec=` pointing at a script in `/tmp`, a home dir, or `/dev/shm`, or a recently-added `.desktop` with `Hidden=false`, is GUI-login persistence (applies to workstations/jump boxes, not headless servers).

## MOTD and update-motd

On Debian/Ubuntu, scripts in `/etc/update-motd.d/` execute **as root** on interactive/SSH login to build the message-of-the-day banner — a well-known root-persistence spot.

```bash
ls -l /etc/update-motd.d/ 2>/dev/null

grep -rIE "curl|wget|base64|bash -c|/tmp/|/dev/shm" /etc/update-motd.d/ 2>/dev/null

# Unowned motd scripts
for f in /etc/update-motd.d/*; do dpkg -S "$f" >/dev/null 2>&1 || echo "UNOWNED: $f"; done
```

🔴 An unowned or modified script in `/etc/update-motd.d/` runs as root every time someone logs in — a payload there is high-impact and rarely inspected.

## NetworkManager Dispatcher

Scripts in the dispatcher directory run on network up/down events — persistence keyed to connectivity (handy for C2 that only phones home when online).

```bash
ls -l /etc/NetworkManager/dispatcher.d/ 2>/dev/null

cat /etc/NetworkManager/dispatcher.d/* 2>/dev/null
```

## Non-systemd Init

🔴 Not every host runs systemd — and its init system has its *own* boot-persistence surface. **OpenRC** (Alpine, Gentoo) and **runit** (Void, some Alpine) are the ones you'll hit, plus legacy **SysV**. On a systemd-only sweep these are blind spots.

```bash
# --- SysV / rc.local (legacy, still on many hosts) ---
cat /etc/rc.local /etc/rc.d/rc.local 2>/dev/null      # deprecated; non-empty = notable
ls -la /etc/init.d/ /etc/rc*.d/ 2>/dev/null            # init scripts + runlevel symlinks

# --- OpenRC (Alpine, Gentoo) ---
rc-status; rc-update show 2>/dev/null                  # enabled services per runlevel
ls -la /etc/init.d/ /etc/runlevels/*/ 2>/dev/null      # service scripts + enable symlinks
cat /etc/local.d/*.start 2>/dev/null                   # 🔴 the OpenRC rc.local - runs at boot
grep -rEn 'command=|command_args=' /etc/conf.d/ 2>/dev/null   # service config (arg/env injection)

# --- runit (Void, some Alpine) ---
ls -la /etc/sv/ /var/service/ /etc/service/ /etc/runit/runsvdir/*/ 2>/dev/null   # services + enabled symlinks
cat /etc/sv/*/run 2>/dev/null                          # 🔴 the run script = the payload
cat /etc/runit/1 /etc/runit/2 /etc/runit/3 2>/dev/null # boot / default / shutdown scripts
```

🔴 The high-value spots: **`/etc/local.d/*.start`** (OpenRC's `rc.local`, runs any script at boot — the Alpine equivalent of a systemd payload service), an unexpected **`/etc/sv/<name>/run`** (runit service) symlinked into `/var/service`, a rogue **`/etc/init.d/` script** enabled via `rc-update add`/a `/etc/runlevels/` symlink, and a `command=` in **`/etc/conf.d/`** hijacking a legit service's invocation. `/etc/rc.local` with a non-trivial command is itself worth explaining.

## Package Manager Hooks

Package managers run hooks on every operation, which an attacker can subvert for persistence that fires on the next update.

```bash
# APT hooks (run commands on apt operations)
grep -rEH "DPkg::|APT::Update::|Post-Invoke|Pre-Invoke" /etc/apt/apt.conf.d/ 2>/dev/null

# dnf plugins
ls -l /usr/lib/python*/site-packages/dnf-plugins/ /etc/dnf/plugins/ 2>/dev/null

# Maintainer scripts of installed packages (see Package Managers and Integrity)
ls -l /var/lib/dpkg/info/*.postinst 2>/dev/null
```

🔴 A `Post-Invoke` in `/etc/apt/apt.conf.d/` running an unexpected command executes on every `apt` run, as root.

## Git Hooks and Language Ecosystems

Developer-workstation persistence: hooks that run on normal dev activity.

```bash
# Git hooks in repos + a global hooks path
find / -type d -name hooks -path "*/.git/*" 2>/dev/null -exec ls -la {} \;

grep -rH "hooksPath" /home/*/.gitconfig /root/.gitconfig 2>/dev/null; git config --system --get core.hooksPath 2>/dev/null

# npm/pip pre/post scripts
grep -rEH "preinstall|postinstall" /home/*/package.json 2>/dev/null
```

🔴 A `.git/hooks/pre-commit` or a `core.hooksPath` pointing at attacker code runs whenever the developer commits/checks out — a targeted persistence on dev boxes and CI runners.

## More Overlooked Triggers

The deepest cuts — each a real execution trigger that a standard sweep skips:

| Vector | Fires when / why it matters |
|--------|------------------------------|
| 🔴 `kernel.core_pattern` = `\|/path` | Runs the program **as root on every process crash** (also a container-escape primitive) |
| `kernel.modprobe` sysctl | Points at the modprobe binary — repoint to a payload = root exec on module autoload |
| `binfmt_misc` handlers | Register an interpreter that runs when a file of a given magic/type is executed |
| `xinetd`/`inetd` | Spawn a service (e.g. a shell) on a network connection — a classic backdoor listener |
| 🔴 `LD_AUDIT` env var | LD_PRELOAD's cousin — same library injection via the linker's audit interface |
| `~/.forward` / `.procmailrc` | Pipe inbound **mail** to a command → mail-triggered execution |
| `/etc/inittab` `respawn` | Legacy SysV — respawns a process forever |

```bash
# core_pattern piped to a program (runs as root on any crash)
cat /proc/sys/kernel/core_pattern; sysctl kernel.core_pattern kernel.modprobe 2>/dev/null

# binfmt_misc registered handlers
ls -la /proc/sys/fs/binfmt_misc/ 2>/dev/null; cat /proc/sys/fs/binfmt_misc/* 2>/dev/null

# Legacy network-service backdoors
cat /etc/inetd.conf 2>/dev/null; ls -la /etc/xinetd.d/ 2>/dev/null

# LD_AUDIT (linker audit-interface injection)
grep -rIE 'LD_AUDIT' /etc /home /root 2>/dev/null

# Mail-triggered execution
find /home /root /var/mail -maxdepth 2 \( -name '.forward' -o -name '.procmailrc' \) 2>/dev/null
```

🔴 `kernel.core_pattern` starting with `|` is the sleeper: any crash (which an attacker can trigger on demand) runs their handler as root. It's used both for persistence and for container escapes — always read it.

## Capabilities and SUID Re-entry

Rather than a launch point, an attacker may leave a privilege-escalation primitive so they can regain root later (cross-ref the Permissions note).

```bash
# Dangerous capabilities left on a binary
getcap -r / 2>/dev/null | grep -E "cap_setuid|cap_dac|cap_sys_module"

# Recently-created SUID-root binaries
find / -type f -perm -4000 -newermt "7 days ago" -ls 2>/dev/null
```

🔴 A `cap_setuid+ep` on an odd binary, or a new SUID-root binary in `/home`/`/tmp`/`/opt`, is a re-entry primitive — not a scheduled launch, but a way back to root that persists until removed.

## Trojanized System Binaries

A replaced `sshd`, `login`, or a core utility can re-establish access or hide the attacker (cross-ref Package Managers and Integrity).

```bash
# Integrity verification catches replaced binaries
rpm -Va 2>/dev/null | grep -E '^..5' | grep -E "/bin/|/sbin/"

debsums -c 2>/dev/null
```

🔴 A trojaned `sshd` can capture passwords or accept a backdoor key; a trojaned `ps`/`ls`/`netstat` hides the attacker. Integrity failure on a system binary is the signal (see the ELF triage note to analyze the replacement).

## Deep Threat Hunts

The "did you check everywhere" sweep. *(seasoned-DFIR)*

```bash
# 1. Every event/login-triggered dir in one grep
grep -rEl 'RUN\+?=|Exec=|curl|wget|bash -c|/tmp/|/dev/shm|/dev/tcp' \
  /etc/udev/rules.d/ /lib/udev/rules.d/ /etc/xdg/autostart/ /home/*/.config/autostart/ \
  /etc/update-motd.d/ /etc/NetworkManager/dispatcher.d/ /etc/rc.local /etc/init.d/ 2>/dev/null

# 2. core_pattern pipe + kernel.modprobe (root exec triggers)
cat /proc/sys/kernel/core_pattern; sysctl kernel.modprobe 2>/dev/null

# 3. binfmt_misc + xinetd/inetd + LD_AUDIT + .forward
ls /proc/sys/fs/binfmt_misc/ 2>/dev/null; cat /etc/inetd.conf 2>/dev/null; ls /etc/xinetd.d/ 2>/dev/null

grep -rIE 'LD_AUDIT' /etc /home /root 2>/dev/null; find /home /root -name '.forward' 2>/dev/null

# 4. Unowned files across every long-tail dir (package-drop shortlist)
for d in /etc/udev/rules.d /etc/update-motd.d /etc/NetworkManager/dispatcher.d /etc/xdg/autostart; do
  for f in "$d"/*; do [ -e "$f" ] && { dpkg -S "$f" >/dev/null 2>&1 || rpm -qf "$f" >/dev/null 2>&1 || echo "UNOWNED: $f"; }; done
done

# 5. Package-operation + git hooks
grep -rEH 'Post-Invoke|Pre-Invoke' /etc/apt/apt.conf.d/ 2>/dev/null

grep -rH 'hooksPath' /home/*/.gitconfig /root/.gitconfig 2>/dev/null

# 6. Re-entry primitives + trojaned binaries (cross-cutting)
getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_dac|cap_sys_module'

rpm -Va 2>/dev/null | grep -E '^..5' | grep -E '/bin/|/sbin/'; debsums -c 2>/dev/null
```

**Hunt ideas:**

- **`kernel.core_pattern` beginning with `|`** runs a program as root on every crash — stealthy persistence *and* a container-escape primitive; check it first.
- **binfmt_misc** registers a handler that runs when a file of a given type is executed — a rarely-checked execution trigger.
- **`xinetd`/`inetd` spawn a service on connection** — the classic network-backdoor listener (a shell on a port).
- **`LD_AUDIT` is `LD_PRELOAD`'s cousin** — same injection via a different env var, missed by a preload-only sweep.
- **Unowned-file check every event/login dir** (udev/motd/NM/xdg/apt) — package-drop the shortlist.

## Getting Max Value

- **When the major vectors are clean but persistence is certain, sweep this long tail** — the misses hide here.
- **Read the two overlooked sysctls** — `core_pattern` (`|` pipe) and `kernel.modprobe` (repointed binary) both give root execution.
- **Package-map every event/login dir** — an unowned file in `udev/motd/NM/xdg` is the drop.
- **Read every hit fully** — these directories legitimately hold scripts.
- **Cross-ref the dedicated notes** (Systemd generators/socket/path/linger, Shell env hooks, Scheduled anacron/incron) so nothing is double-missed.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Systemd generators / socket / path / linger | **Systemd Units Timers and Generators** |
| Env-hook persistence (`BASH_ENV`, aliases) | **Shell Startup and Profile Scripts** |
| anacron / incron / transient timers | **Scheduled Tasks Spool and State** (08) |
| SUID/capability re-entry detail | **File and Directory Permissions** (02) |
| Trojaned-binary analysis | **Package Managers and Integrity** (08), **ELF and Malware Triage** (11b) |
| `LD_AUDIT`/`LD_PRELOAD` injection | **Preload Hijacking** |
| Remove it safely | **Remediation and Containment** (14) |

## Scenarios

- **Root-on-login:** an unowned `/etc/update-motd.d/` script runs as root every SSH login.
- **Device trigger:** a udev `RUN+=` with `ACTION=="add"` fires the payload on a device event or boot.
- **Crash trigger:** `kernel.core_pattern = |/tmp/x` runs as root whenever any process crashes.
- **Backdoor listener:** an `xinetd`/`inetd` service spawns a shell on a network port.
- **CI persistence:** a `.git/hooks/pre-commit` or `core.hooksPath` runs attacker code on every commit.
- **Re-entry primitive:** a `cap_setuid+ep` on an odd binary — a way back to root that isn't a scheduled launch.

## Red Flags

| 🔴 Finding | Vector |
|-----------|--------|
| `RUN+=` in an unowned udev rule | udev event persistence |
| `.desktop` autostart to a temp/home script | XDG login persistence |
| Unowned/modified script in `/etc/update-motd.d/` | Root-on-login |
| Script in NetworkManager `dispatcher.d/` | Connectivity-triggered persistence |
| `/etc/rc.local` present with a real command | Legacy boot persistence |
| `Post-Invoke` hook in `apt.conf.d/` | Package-operation persistence |
| `core.hooksPath` / `.git/hooks` to attacker code | Developer-activity persistence |
| `cap_setuid` on an odd binary / new SUID-root | Privilege re-entry primitive |
| System binary fails `rpm -Va`/`debsums` | Trojaned binary |
| `kernel.core_pattern` starting with `\|` | Root execution on any crash |
| `xinetd`/`inetd` service spawning a shell | Network backdoor listener |
| `LD_AUDIT` set / `binfmt_misc` custom handler | Linker-injection / file-type execution trigger |

## Resources

- `udev(7)`, `NetworkManager-dispatcher(8)`, `update-motd(5)`, `githooks(5)`, `core(5)` (core_pattern), `binfmt_misc`, `xinetd(8)` man pages
- MITRE ATT&CK: T1546 (Event Triggered Execution), T1037 (Boot/Logon Init Scripts), T1543 (Create/Modify System Process), T1574.006 (LD_PRELOAD/LD_AUDIT)
