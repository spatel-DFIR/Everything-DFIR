# Persistence Overview and Sweep

Persistence is how an attacker survives a reboot, a logout, or a killed process — and on Linux there are more places to hide it than on any other platform. This note is the map to the rest of the folder: it lists every mechanism (each has its own note), gives you the one-pass **master sweep** to find recent changes across all of them, and explains how to **rank** what you find so you spend time on the real footholds instead of legitimate churn.

> 🔴 Rank by *writability × noise*: a change in a rarely-touched, high-trust location (`/etc/ld.so.preload`, a kernel module, `/etc/systemd/system`) is far more suspicious than one in a busy per-user file. Timebox every sweep with `-mmin`/`-newermt` around the incident window, and remember the cron and PAM spools need **root** to read — a non-root sweep silently misses them.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [The Mechanisms](#the-mechanisms)
- [Master Sweep](#master-sweep)
- [Full Live Enumeration](#full-live-enumeration)
- [Ranking What You Find](#ranking-what-you-find)
- [Cross-Cutting Checks](#cross-cutting-checks)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Enabled services + timers + every user's crontab in one pass (root)
systemctl list-unit-files --state=enabled --type=service,timer

for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done

# The two silent classics
cat /etc/ld.so.preload 2>/dev/null; env | grep -i LD_PRELOAD; cat /proc/sys/kernel/tainted

# All authorized_keys anywhere
find / -name authorized_keys -exec ls -la {} \; -exec cat {} \; 2>/dev/null

# ExecStart / cron lines that fetch or interpret
grep -rIEl "curl|wget|base64|/tmp/|/dev/shm|bash -c|python -c" /etc/systemd /etc/cron* 2>/dev/null
```

## What to Check for What

| Investigative goal | Start here |
|--------------------|------------|
| Recent changes across *all* mechanisms | Master Sweep (below) |
| Everything set to run at boot/login now | Full Live Enumeration (below) |
| Passwordless re-entry that survives resets | **SSH Keys**, **PAM Backdoors** |
| Runs on every login shell | **Shell Startup and Profile Scripts** |
| Scheduled execution | **Cron and at Jobs**, **Systemd Units Timers** |
| Stealthiest / self-hiding | **Kernel Modules and LKM Rootkits**, **Preload Hijacking** |
| Fires on a device/network/GUI event | **More Persistence Mechanisms** (udev/NM/XDG) |
| **Non-systemd** host (Alpine/Gentoo/Void)? | **More Persistence → Non-systemd Init** (OpenRC/runit/SysV) |
| Is a finding armored against removal? | Cross-Cutting Checks (`lsattr` for `+i`) |
| Is a system binary trojaned? | Cross-Cutting Checks (`rpm -Va`/`debsums`) |

## The Mechanisms

Each row links to a dedicated note in this folder. Ranked roughly by how often they carry real intrusions and how stealthy they are.

| Mechanism | Note | ATT&CK | Why it matters |
|-----------|------|--------|----------------|
| Cron and at | Cron and at Jobs | T1053.003 | Simplest, most portable; `@reboot` + service accounts |
| Systemd units/timers/generators | Systemd Units Timers and Generators | T1543.002 / T1053.006 | The modern default; generators are stealthy 🔴 |
| Shell startup / profile | Shell Startup and Profile Scripts | T1546.004 | Fires on every login shell; `/etc/profile.d/*` hits all users |
| SSH keys | SSH Keys | T1098.004 | Passwordless re-entry; survives password resets |
| PAM backdoors | PAM Backdoors | T1556.003 | Skeleton-key auth; survives password change 🔴 |
| LD_PRELOAD / ld.so.preload | Preload Hijacking | T1574.006 | Userland rootkit + persistence in one 🔴 |
| Kernel modules / LKM rootkits | Kernel Modules and LKM Rootkits | T1547.006 | Stealthiest tier; hides itself 🔴 |
| udev, XDG autostart, MOTD, rc, package/git hooks, caps/SUID, trojaned bins | More Persistence Mechanisms | various | The long tail of minor vectors |

Read the mechanism-specific note before acting on a finding — each explains how that mechanism actually fires, where its legitimate uses are, and what separates a real implant from noise.

## Master Sweep

One `find` across every common persistence path, filtered to recent modification. Adjust the `-mmin -180` (last 3h) or swap in `-newermt "<start>" ! -newermt "<end>"` to bracket the incident.

```bash
find /etc /home /root /var/spool /usr/lib/systemd /lib/systemd /lib/udev /etc/udev -type f \( \
  -path "/etc/cron*" -o -path "/var/spool/cron*" -o -name ".*history*" -o -name ".bashrc" -o -name ".bash_profile" \
  -o -name ".bash_login" -o -name ".profile" -o -name ".zshrc" -o -name ".zprofile" -o -name ".zlogin" \
  -o -path "/etc/profile" -o -path "/etc/bash.bashrc" -o -path "/etc/profile.d/*" -o -path "/etc/init.d/*" \
  -o -path "/etc/rc.local" -o -path "*/systemd/*" -o -name "*.service" -o -name "*.timer" -o -path "/etc/ssh/*" \
  -o -path "*/.ssh/*" -o -path "/etc/udev/rules.d/*" -o -path "/lib/udev/rules.d/*" -o -path "*/.config/autostart/*" \
  -o -name ".zlogout" -o -name ".kshrc" -o -name ".cshrc" -o -name ".tcshrc" -o -name ".*_login" -o -name ".*_logout" \
  -o -path "/etc/xdg/autostart/*" -o -path "/etc/sudoers" -o -path "/etc/sudoers.d/*" \
  -o -path "/etc/NetworkManager/dispatcher.d/*" \
\) -mmin -180 -ls 2>/dev/null
```

This is a *lead generator*, not a verdict — it surfaces what changed recently. Take each hit into its mechanism note to decide whether it's malicious.

## Full Live Enumeration

Where the Master Sweep finds *recent changes*, this enumerates *everything currently armed* — the live persistence surface regardless of mtime (an implant planted before your window still shows here).

```bash
# systemd: running services, enabled units, and any temp-path ExecStart
systemctl list-units --type=service --state=running

systemctl list-unit-files --type=service,timer | grep -i enabled

grep -rIE 'ExecStart|ExecStartPre' /etc/systemd/system /usr/lib/systemd/system 2>/dev/null | grep -Ei 'curl|wget|/tmp/|/dev/shm|bash -c|base64'

# Every user's cron + the system cron surface
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done

cat /etc/crontab /etc/cron.d/* 2>/dev/null; ls /etc/cron.{hourly,daily,weekly,monthly}/ 2>/dev/null

# The silent classics
cat /etc/ld.so.preload 2>/dev/null; cat /proc/sys/kernel/tainted; lsmod | tail

# Event-driven vectors
cat /etc/rc.local 2>/dev/null

ls -la /etc/udev/rules.d/ /lib/udev/rules.d/ /etc/NetworkManager/dispatcher.d/ 2>/dev/null

# Re-entry
find / -name authorized_keys -exec ls -la {} \; -exec cat {} \; 2>/dev/null
```

**Hunt ideas:**

- **Sweep *and* enumerate** — the Master Sweep catches what changed in your window; Full Live Enumeration catches an implant planted *before* it. Run both.
- **Diff against a golden host** — `systemctl list-unit-files --state=enabled`, the crontab set, and `/etc/ld.so.preload` all diff cleanly against a known-good peer; the delta is the candidate.
- **Follow the payload shape, not the location** — grep every mechanism's command for `curl|bash`, base64, `/dev/tcp`, and `/tmp`/`/dev/shm` paths.
- **Stack signals before you call it** — one recent change is churn; recent + service-account owner + `/dev/shm` payload + `+i` is an implant.

## Ranking What You Find

For every hit, score these signals — stacked signals are what a real implant looks like:

| Signal | Suspicious when… |
|--------|------------------|
| Location writability × monitoring | High-trust, rarely-touched path changed (`/etc/ld.so.preload`, `/usr/lib/systemd`) |
| Payload shape | `curl\|bash`, base64, reverse shell, path in `/tmp`/`/dev/shm` |
| Owning account | A service account (`www-data`, `nobody`) owns a cron/unit/key it has no reason to |
| Timestamp | mtime/ctime inside the incident window; ctime newer than mtime (timestomp) |
| Immutable bit | `+i` set so it resists removal (armored persistence) |
| Signature/integrity | Trojaned system binary (`rpm -Va`/`debsums` fail) |
| Orphan / masquerade | Points at a missing binary, or a name mimicking a real service |

🔴 A single `RECENT` hit is usually legitimate churn (a package update touches units and profile.d files constantly). It's the **stack** — recent + `/dev/shm` payload + service-account owner + immutable bit — that marks an implant.

## Cross-Cutting Checks

Two checks apply to *every* mechanism and belong in every persistence sweep:

```bash
# Immutable bit hides armored persistence in any location
lsattr -R /etc /root /home /var/spool/cron 2>/dev/null | grep -E '^....i|^.....a'

# Trojaned system binaries re-establish access from any foothold
rpm -Va 2>/dev/null | grep -E '^..5' | grep -E "/bin/|/sbin/"; debsums -c 2>/dev/null
```

## Getting Max Value

- **Run as root** — cron spools (700), `/etc/shadow`, PAM, and some unit dirs are unreadable otherwise; a non-root sweep silently under-reports.
- **Run both sweeps** — Master Sweep (recent changes) *and* Full Live Enumeration (everything currently armed) — an implant planted before your window only shows in the second.
- **Timebox the sweep** with `-mmin`/`-newermt` around the incident, then widen once you have leads.
- **Baseline-diff** the enabled-units / crontab / preload set against a known-good peer of the same build — the delta is your candidate list.
- **Stack signals to rank** (Ranking table) — never call a lone recent change an implant.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| How a specific mechanism fires + noise vs implant | its dedicated note in this folder |
| When the persistence was planted | **Timelining** (13), file mtime/ctime |
| Whether the finding is timestomped/immutable | **File and Directory Permissions** (02) |
| Whether a system binary is trojaned | **Package Managers and Integrity** (08) |
| The execution the persistence launched | **Auditd**, **Systemd Journal**, **Process Trees** (10b) |
| A live-only implant (LKM, preload, memfd) | **Live Response** (10), **Memory Forensics** (11) |
| How to remove it safely | **Remediation and Containment** (14) |

## Scenarios

- **Reboot survival:** a `@reboot` cron or an enabled systemd service re-launches the payload on every boot.
- **Reset-proof re-entry:** an `authorized_keys` entry or a PAM backdoor survives every password change.
- **Stealth tier:** an LKM or `LD_PRELOAD` library that hides its own files/PIDs — found by inconsistency, not by listing.
- **Planted-before-window:** an implant older than your `-mmin` sweep — caught only by Full Live Enumeration.
- **Armored:** a persistence file with `+i` that `rm` won't remove until `chattr -i`.

## Red Flags

| Finding | Where to dig |
|---------|--------------|
| Populated `/etc/ld.so.preload` | Preload Hijacking |
| Unsigned/out-of-tree kernel module or taint set | Kernel Modules and LKM Rootkits |
| Unknown `pam_*.so` / `pam_exec.so` in a stack | PAM Backdoors |
| systemd unit/timer with a temp-path `ExecStart` | Systemd Units Timers and Generators |
| `@reboot` or service-account crontab | Cron and at Jobs |
| authorized_keys added recently / `ForceCommand` | SSH Keys |
| `.desktop` autostart / udev `RUN+=` / MOTD script | More Persistence Mechanisms |
| Any persistence file with `+i` immutable bit | (all — clear with `chattr -i` before removal) |

## Resources

- The Art of Linux Persistence (public research PDF)
- MITRE ATT&CK: T1053, T1543, T1546, T1547.006, T1556.003, T1574.006, T1098.004
