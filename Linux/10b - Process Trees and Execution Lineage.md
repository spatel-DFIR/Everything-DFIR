# Process Trees and Execution Lineage

When an alert fires on a process, the first question is **"what started it, as whom, and from where?"** That answer classifies the alert: a `curl` child of a shell under `sshd` is a remote operator; the same `curl` under `nginx` is web exploitation; under a `.service` cgroup it's a (possibly trojaned) daemon; reparented to PID 1 with a socket and a `/tmp` binary it's a daemonized implant. This note is the **reference set of Linux process trees** so you can place an alerted process fast and know where to look next.

> 🔴 On Linux, **PID 1 is `systemd`/`init` and adopts orphans**, so a **`PPID` of 1 does NOT mean "service."** A real service, a double-forked daemon, malware that detached, and any process whose parent died all show `PPID 1`. You disambiguate with **(1) the cgroup** (`/proc/PID/cgroup` — the authoritative owner on systemd), **(2) `systemctl status <PID>`** (maps a PID to its unit), **(3) the session/TTY and start time**, and **(4) the nearest meaningful ancestor**. Parent alone is a trap — even more so than on macOS, because Linux malware deliberately double-forks to land on PID 1.

## Contents

- [Quick Triage](#quick-triage)
- [The systemd Parenting Model](#the-systemd-parenting-model)
- [Why PPID 1 Is Ambiguous](#why-ppid-1-is-ambiguous)
- [Pulling a Process's Lineage](#pulling-a-processs-lineage)
- [cgroup Lineage the Authoritative Owner](#cgroup-lineage-the-authoritative-owner)
- [Reference Trees](#reference-trees)
- [Fast Classification Table](#fast-classification-table)
- [Kernel Threads and Masquerading](#kernel-threads-and-masquerading)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
PID=<alerted-pid>

# 1. One-liner lineage: walk parent -> parent up to PID 1
P=$PID; while [ "$P" -gt 1 ]; do ps -o pid=,ppid=,user=,lstart=,args= -p "$P"; P=$(ps -o ppid= -p "$P" | tr -d ' '); done

# 2. AUTHORITATIVE owner on systemd: which unit/cgroup does this PID belong to?
systemctl status "$PID"

cat /proc/$PID/cgroup

# 3. Full context: parent, session, controlling TTY, start time, owner
ps -o pid,ppid,pgid,sid,tty,user,lstart,args -p "$PID"

# 4. Visual ancestry
pstree -aps "$PID"
```

The two decisive commands are **`systemctl status <PID>`** (prints the owning `.service`/`.scope`/`.slice` — the systemd equivalent of "who launched me") and **`cat /proc/PID/cgroup`** (the raw cgroup path: `system.slice/foo.service` = a service, `user.slice/.../session-3.scope` = an interactive session, `docker/<id>` or `kubepods/...` = a container).

## The systemd Parenting Model

On a modern systemd host, execution is organized by **cgroups**, not just the parent chain:

- A **system service** → runs under `system.slice/<name>.service`; its main process is a child of `systemd` (PID 1) but is *tracked by cgroup*, not by staying a direct child.
- A **user session** (login, SSH, `su`) → runs under `user.slice/user-<uid>.slice/session-<n>.scope`, managed by a per-user `systemd --user` (itself a child of PID 1).
- A **transient/`systemd-run`** unit → its own `.scope` or `.service`, often used by attackers to launch a payload that looks systemd-managed.
- A **container** → `docker/<id>` or `kubepods/...` cgroup (see the Container section).
- A **cron/at job** → child of `cron`/`crond`/`atd`, under that daemon's slice.
- Only a process with a **live meaningful parent** keeps it: a command in a shell (parent = the shell → the terminal or `sshd`), a web payload (parent = `nginx`/`apache2`/`php-fpm`), a remote command (parent = `sshd`).

So the trick mirrors macOS but the authoritative field is the **cgroup**: find the nearest meaningful ancestor, and cross-check the cgroup/unit. On non-systemd hosts (Alpine/OpenRC, old SysV) fall back to the parent chain, session leader, and controlling TTY.

## Why PPID 1 Is Ambiguous

PID 1 adopts any orphan, and malware exploits this:

| PPID-1 process | What it actually is |
|----------------|---------------------|
| Under `system.slice/foo.service` cgroup, UID 0, alive since boot | Legit (or trojaned) system service |
| Under a `.scope`/no service cgroup, UID user, has a TTY | Reparented interactive process (parent shell exited) |
| **No service cgroup, socket open, exe in `/tmp` or `(deleted)`** | 🔴 Double-forked daemonized implant |
| Bracketed name like `[kworker/…]` but has a real `exe`/cmdline | 🔴 Masquerading malware (see below) |

🔴 **Double-forking to PID 1 is the classic Linux malware daemonization trick** — fork, parent exits, child is reparented to init and loses its lineage. The tell isn't the parent (it's gone); it's the *cgroup* (no legit unit), the *exe* (temp/deleted), and an *open socket*.

```bash
# Processes on PID 1 that are NOT owned by a systemd unit (candidates for daemonized malware)
for p in $(ps -eo pid=,ppid= | awk '$2==1{print $1}'); do
  cg=$(cat /proc/$p/cgroup 2>/dev/null | grep -v "system.slice\|init.scope\|user.slice")
  [ -n "$cg" ] && echo "PID $p: $(readlink /proc/$p/exe 2>/dev/null)  cg=$cg"
done
```

## Pulling a Process's Lineage

| Source | Gives you | Note |
|--------|-----------|------|
| `ps -o pid,ppid,pgid,sid,tty,user,lstart,args` | Parent, process group, session, TTY, owner, start time, argv | Start here; `lstart` pins the timeline, `tty` reveals interactive vs headless |
| `systemctl status <PID>` | The owning **unit** + its cgroup + recent journal lines | Authoritative "who owns this" on systemd |
| `cat /proc/PID/cgroup` | Raw cgroup path (service / session / container) | The classification field |
| `pstree -aps <PID>` | Visual ancestry with args, up to PID 1 | Fast tree view |
| `/proc/PID/stat` (fields 4,5,6,7,8) | ppid, pgrp, session, tty_nr, tpgid | Low-level, works when tools are trojaned |
| `journalctl _PID=<pid>` / `_SYSTEMD_UNIT=` | The process's own journal trail | Ties execution to logged events |
| auditd `EXECVE`/`SYSCALL` (ppid field) | Recorded parent + argv **even after exit** | Best historical source if auditd rules exist |

```bash
# Low-level parent/session/tty when you don't trust ps (fields: ppid pgrp session tty_nr)
awk '{print "ppid="$4" pgrp="$5" sess="$6" tty="$7}' /proc/$PID/stat

# The controlling terminal (a service should have none; "?" = no TTY)
ps -o tty= -p $PID

# Session leader (who owns the login session)
ps -o sid= -p $PID | xargs -I{} ps -o pid,user,args -p {}
```

## cgroup Lineage the Authoritative Owner

The cgroup answers "who is responsible" the way `launchctl procinfo` does on macOS:

```bash
# The unit that owns a PID
systemctl status $PID | head -3

# Raw cgroup (read the path)
cat /proc/$PID/cgroup
#  system.slice/nginx.service         -> a system service
#  user.slice/user-1000.slice/session-2.scope -> user 1000's login session
#  system.slice/sshd.service ... /session-5.scope -> an SSH session
#  docker/3f2a...  or  kubepods/besteffort/pod.../<id> -> a container

# The whole tree by unit (see what each service is running under it)
systemd-cgls

# Everything a specific unit is running (catches payloads hiding under a legit service)
systemctl status nginx.service
```

🔴 A shell or interpreter appearing **inside a service's cgroup that shouldn't spawn one** (e.g. `bash`/`python` under `nginx.service` or `mysql.service`) is exploitation of that service — the cgroup ties the payload to the compromised daemon even though the process "looks" like a normal child.

## Reference Trees

Each tree shows `name (pid, uid)` and how to confirm the classification.

### System service (systemd)
```
systemd (1, 0)
└── nginx (812, 0)                         [cgroup: system.slice/nginx.service]
    └── nginx worker (813, 33)
```
- **Owned by a `.service` cgroup.** `systemctl status 812` → the unit + its `ExecStart`. UID per the unit's `User=`.
- **Verdict driver:** cgroup `system.slice/<name>.service`. A service whose `ExecStart` path is under `/tmp`/`/home`, or a service running an unexpected binary, is planted persistence → see the Persistence note. A *shell* under a service cgroup = the service was exploited.

### SSH remote session
```
systemd (1, 0)
└── sshd (900, 0)
    └── sshd (1201, 0) [priv]
        └── sshd (1202, 1000) [user session]   [cgroup: .../session-5.scope]
            └── bash (1203, 1000)
                └── curl / payload (1204, 1000)
```
- Nearest meaningful ancestor is **`sshd`**; the session runs in a `session-N.scope` under `user.slice`.
- **Verdict driver:** ancestor `sshd` = remote/lateral execution. Cross-ref `last`/`w`/`auth.log` for the source IP and time (see Authentication and Login Records). A `curl|bash`/reverse shell here is hands-on-keyboard over SSH.

### Interactive local shell
```
systemd (1, 0)
└── login / gnome-terminal / tmux (1500, 1000)
    └── bash (1501, 1000)                  [has a controlling TTY: pts/0]
        └── payload (1502, 1000)
```
- Has a **controlling TTY** (`pts/N` or `tty1`); ancestor is a terminal/login, cgroup is a user `session`/`.scope`.
- **Verdict driver:** a real TTY + user session = someone at a keyboard (local or via a terminal multiplexer). Pull the shell history (see Shells and Command History) for the exact commands.

### Cron / at
```
systemd (1, 0)
└── cron / crond (410, 0)                  [cgroup: system.slice/cron.service]
    └── sh (5001, 1000)                    ← the crontab command line
        └── payload (5002, 1000)
```
- Nearest meaningful ancestor is **`cron`/`crond`/`atd`**; UID is whichever user's crontab fired it; typically **no TTY**.
- **Verdict driver:** ancestor `cron`/`atd` = scheduled execution → check that user's crontab and `/etc/cron.*` (see Scheduled Tasks / Persistence).

### Web server exploitation
```
systemd (1, 0)
└── apache2 / nginx / php-fpm (700, 0)     [cgroup: system.slice/apache2.service]
    └── php-fpm worker (701, 33 www-data)
        └── sh / bash (7100, 33)           ← webshell command execution
            └── curl / nc / payload (7101, 33)
```
- Ancestor is a **web server / app-server**, running as `www-data`/`apache`/`nginx`; a shell/interpreter child is the payload.
- **Verdict driver:** interpreter or shell child of a web/app server = **web exploitation → webshell/RCE** (the Linux equivalent of "IIS spawned cmd.exe"). Correlate with access logs + web-root file mtimes (see Application and Database Logs, Web Exploitation Playbook).

### Container process
```
systemd (1, 0)
└── containerd (600, 0)
    └── containerd-shim (1800, 0)
        └── <entrypoint> (1801, 0)         [cgroup: docker/3f2a... or kubepods/...]
            └── payload (1802, 0)
```
- Ancestor is a **`containerd-shim`/`runc`**; the cgroup is `docker/<id>` or `kubepods/...`; namespaces differ from the host (`ls -l /proc/PID/ns`).
- **Verdict driver:** container cgroup / shim ancestor = containerized execution. Map to the container and pivot to the Container section. A container process touching **host** paths = a possible escape.

### Double-forked daemonized implant
```
systemd (1, 0)
└── ./kdevtmpfsi (9001, 0)                 [NO service cgroup; exe in /tmp or (deleted); socket open]
```
- **`PPID 1`, no owning unit, temp/deleted exe, an open network socket, no TTY.** The real parent exited on purpose.
- **Verdict driver:** PPID 1 + no legit cgroup + temp/deleted exe + socket = malware that daemonized itself. Recover the binary from `/proc/PID/exe` and pivot to Live Response / Persistence.

### Kernel thread (baseline for comparison)
```
kthreadd (2, 0)
└── [kworker/0:1] (85, 0)                  ← real kernel thread: NO exe, NO cmdline
```
- Child of **`kthreadd` (PID 2)**, name in `[brackets]`, **empty `/proc/PID/cmdline`**, no `exe` link.
- **Verdict driver:** genuine kernel threads have an empty cmdline and parent PID 2. A "`[kworker]`" with a real cmdline/exe and a non-2 parent is malware masquerading (see below).

## Fast Classification Table

Find the nearest meaningful ancestor and the cgroup, then read across:

| Ancestor / cgroup signal | UID | TTY | Classification | Where next |
|--------------------------|-----|-----|----------------|------------|
| `sshd` / `session-N.scope` | user | pts/N | Remote SSH session | `last`, `w`, auth.log |
| Terminal / login + TTY | user | pts/N or tty1 | Local interactive | shell history |
| `cron`/`crond`/`atd` | user/root | none | Scheduled | crontab, cron.* |
| `nginx`/`apache2`/`php-fpm` → shell | www-data | none | **Web exploitation** | access logs, web root |
| `system.slice/<x>.service` | per unit | none | System service (maybe trojaned) | persistence sweep |
| `containerd-shim`/`runc`, `docker/…` cgroup | any | none | Container | Container section |
| **PID 1, no unit cgroup, temp/deleted exe, socket** | any | none | **Daemonized implant** | Live Response, Memory |
| `kthreadd` (PID 2), empty cmdline | 0 | none | Kernel thread (baseline) | — |

## Kernel Threads and Masquerading

```bash
# Genuine kernel threads: parent PID 2, EMPTY cmdline
ps -eo pid,ppid,args | awk '$2==2'

# Malware masquerading as a kernel thread: bracketed name BUT a real exe/cmdline
for p in /proc/[0-9]*; do
  n=$(basename "$p")
  cmd=$(tr -d '\0' < "$p/cmdline" 2>/dev/null)
  comm=$(cat "$p/comm" 2>/dev/null)
  # bracket-style comm but a non-empty cmdline or a real exe = fake kernel thread
  case "$comm" in
    \[*\]) [ -n "$cmd" ] && echo "FAKE kthread PID $n: comm=$comm exe=$(readlink $p/exe 2>/dev/null) cmd=$cmd";;
  esac
done
```

🔴 A process named `[kworker/…]`, `[kthreadd]`, `[migration/…]` etc. that has a **non-empty cmdline** or a **real `exe`** (kernel threads have neither) is malware wearing a kernel-thread costume — a very common Linux masquerade. Its parent will be something other than PID 2, and it'll usually have a socket or a temp/deleted binary.

## Getting Max Value

- **The cgroup is the authoritative owner** — `systemctl status <PID>` + `/proc/PID/cgroup` classify a process even when the parent chain lies (double-fork) or `ps` is trojaned.
- **`lstart` + session + TTY place the process in time and context** — a service should have no TTY; a TTY on a service account is hands-on-keyboard.
- **auditd `EXECVE` reconstructs lineage *after* exit** — the only source that survives a short-lived parent, if rules exist.
- **Read `exe` not `comm`** — `comm`/`ps` names are attacker-chosen and truncated; a `[kworker]` with a real `exe` is malware.
- **Recover the binary from `/proc/PID/exe` before the process exits** (→ Live Response) — daemonized implants delete their on-disk file.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Full `/proc` workup + recover the binary | **Live Response and Volatile Data** (10) |
| The source IP/time behind an `sshd` ancestor | **Authentication and Login Records** |
| The exact commands an interactive shell ran | **Shells and Command History** (04) |
| Web-server-parent → webshell confirmation | **Application and Database Logs**, **Web Exploitation Playbook** (15) |
| A `cron`/`atd` ancestor's job | **Scheduled Tasks** (08), **Persistence → Cron** |
| Map a container-cgroup process to its container | **Container** section |
| Recorded parent/argv after exit | **Auditd** (`EXECVE`/`SYSCALL` ppid) |
| Conclusive proof for a hidden/injected process | **Memory Forensics** (11), **Rootkit Detection** (11c) |

## Red Flags

| 🔴 Lineage | Likely meaning |
|-----------|----------------|
| Shell/interpreter child of `nginx`/`apache2`/`php-fpm`/`tomcat` | Web exploitation → webshell/RCE |
| Shell/interpreter inside a service cgroup that shouldn't spawn one | The service was exploited |
| `PPID 1`, no owning unit, exe in `/tmp`/`/dev/shm` or `(deleted)`, socket open | Double-forked daemonized implant |
| Bracketed `[kworker]`-style name with a real cmdline/exe | Malware masquerading as a kernel thread |
| Process reparented to 1 whose start time ≠ boot and with a network socket | Detached beacon/backdoor |
| `curl\|bash` / `base64 -d` / reverse-shell argv anywhere in the child chain | Downloader / fileless stage |
| Interactive shell (TTY) under a service account (`www-data`, `postgres`) | Service account being driven by hand |
| `systemd-run`/transient `.scope` launching an unexpected payload | Attacker using systemd to look legitimate |
| Ancestor `sshd` for a session with no matching `auth.log` entry | Log tampering or an unusual auth path |

## Resources

- `ps(1)`, `pstree(1)`, `systemctl(1)` (`status <pid>`), `systemd-cgls(1)`, `proc(5)` man pages
- `PR_SET_CHILD_SUBREAPER` — `prctl(2)` (why some orphans reparent to a subreaper, not PID 1)
