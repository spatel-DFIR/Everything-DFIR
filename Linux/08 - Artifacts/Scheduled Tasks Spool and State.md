# Scheduled Tasks Spool and State

Scheduling is one of the most reliable Linux persistence mechanisms, and this note covers the *artifacts* it leaves on disk — the cron spool, the `at` queue, and systemd timer units — from the perspective of "what do I collect and timeline." The detection and ranking logic lives in the Persistence note; here the goal is to enumerate every scheduled-execution artifact so none is missed, and to capture the proof that a job actually ran.

> 🔴 The user cron spool (`/var/spool/cron/…`) is mode 700 root-owned, so a non-root triage run reads *nothing* and can silently report "no cron jobs" — a dangerous false negative. Run these as root, and treat `at` jobs specially: `at` runs *once* at a set time, so a clean-looking cron doesn't mean the queue is empty.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Cron Spool and Directories](#cron-spool-and-directories)
- [at Jobs](#at-jobs)
- [Systemd Timers](#systemd-timers)
- [Other Schedulers](#other-schedulers)
- [Execution Evidence](#execution-evidence)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Per-user crontabs (root needed to read the spool)
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done

# System-wide cron
cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.{hourly,daily,weekly,monthly}/

# at jobs
atq; ls -la /var/spool/cron/atjobs/ /var/spool/at/ 2>/dev/null

# All timers, including inactive
systemctl list-timers --all
```

## What to Check for What

*(this note = collect + timeline the scheduling artifacts; detection/ranking → Persistence)*

| Investigative question | Command / source |
|------------------------|------------------|
| Every user's cron job? | `for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u; done` (root) |
| System-wide + drop-in cron? | `cat /etc/crontab /etc/cron.d/*`; `ls /etc/cron.{hourly,daily,weekly,monthly}` |
| One-shot `at` jobs? | `atq`; `at -c <id>`; `ls /var/spool/at* /var/spool/cron/atjobs` |
| systemd timers (incl. transient)? | `systemctl list-timers --all` |
| Timer with **no file on disk**? | transient `systemd-run` timers (only `list-timers` shows them) |
| Other schedulers? | anacron, incron, fcron (see Other Schedulers) |
| When was a schedule planted? | mtime-sort all cron/timer definition files |
| Did the job actually run? | `grep CRON.*CMD /var/log/cron`; timer journal; `/var/mail` |
| User-level (no-root) persistence? | `~/.config/systemd/user/*.timer`; user crontab |

## Cron Spool and Directories

Cron spreads its artifacts across several locations — per-user spool, the system crontab (which uniquely has a *user* field), and the drop-in directories. Enumerate all of them, because attackers pick whichever is least scrutinized.

| Path | Content |
|------|---------|
| `/var/spool/cron/crontabs/` (Debian) | Per-user crontabs (700, root:crontab) |
| `/var/spool/cron/` (RHEL) | Per-user crontabs |
| `/etc/crontab` | System crontab (has a user field) |
| `/etc/cron.d/` | Drop-in system cron files 🔴 (a favored hiding spot) |
| `/etc/cron.hourly,daily,weekly,monthly/` | Scripts run on those cadences |
| `/etc/cron.allow` / `/etc/cron.deny` | Who may use cron |
| `/var/log/cron` (RHEL) / syslog (Debian) | Cron **execution** log |

```bash
# List a user's crontab
crontab -l -u www-data

# Read system + drop-in cron
cat /etc/crontab

cat /etc/cron.d/*

ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly

# The raw spool (root)
ls -la /var/spool/cron/crontabs/ 2>/dev/null

cat /var/spool/cron/crontabs/* 2>/dev/null
```

🔴 The entries to read closely: `@reboot` (runs at every boot), jobs invoking `curl`/`wget`/`base64`/`bash -c` (download/exec), cron files with a recent mtime (freshly planted), and jobs owned by service accounts like `www-data` or `nobody` (which rarely have a legitimate reason to schedule anything).

## at Jobs

```bash
# Queued at jobs
atq

# Inspect a specific job's content
at -c <jobid>

# On-disk spool
ls -la /var/spool/cron/atjobs/ 2>/dev/null    # Debian

ls -la /var/spool/at/ 2>/dev/null             # RHEL

# atd execution appears in the auth/cron logs
grep -i atd /var/log/syslog /var/log/cron 2>/dev/null
```

🔴 `at` schedules a job to run **once**, which makes it easy to overlook — there's no recurring entry to catch your eye. An attacker can queue a single delayed execution (to run their payload after they log off, or at a quiet hour) and it won't appear in any crontab. Always check the queue even when cron looks clean.

## Systemd Timers

Timers are the modern equivalent of cron and are increasingly the attacker's choice because they blend into systemd. A `.timer` unit defines the schedule and triggers a matching `.service` unit that carries the payload — read them together.

```bash
# Active + inactive timers with next/last run
systemctl list-timers --all

# Timer unit files
ls -l /etc/systemd/system/*.timer /usr/lib/systemd/system/*.timer /run/systemd/system/*.timer 2>/dev/null

# A timer points at a matching .service (or OnCalendar/OnBootSec)
systemctl cat <name>.timer

# User-level timers (per-user persistence)
ls -l /home/*/.config/systemd/user/*.timer 2>/dev/null
```

🔴 A user-level timer under `~/.config/systemd/user/` is per-user persistence that doesn't require root to install, and it's easy to miss if you only look at system units. The `.timer` is the schedule; the `.service` it triggers is where the actual command lives.

## Other Schedulers

🔴 cron and systemd timers aren't the only games — enumerate the less-watched schedulers too, and remember that a **transient `systemd-run` timer leaves no unit file on disk** (it exists only in the running systemd state).

```bash
# anacron — runs jobs missed while the host was off (attacker-usable)
cat /etc/anacrontab 2>/dev/null

ls -la /var/spool/anacron/ 2>/dev/null

# incron — triggers commands on filesystem EVENTS (not time)
ls -la /etc/incron.d/ /var/spool/incron/ 2>/dev/null

# fcron — an alternative cron implementation
ls -la /var/spool/fcron/ 2>/dev/null

# Transient timers created by systemd-run (NO unit file — only listed here)
systemctl list-timers --all | grep -Ei 'run-r[0-9a-f]+'
```

`systemd-run --on-active=` / `--on-calendar=` schedules a job with no persistent file — if `list-timers` shows a `run-rXXXX.timer` you can't find on disk, that's a transient one worth explaining.

## Execution Evidence

Beyond the schedule *definitions*, capture proof the jobs actually ran — that's what ties a persistence mechanism to activity in your timeline.

```bash
# Cron execution (Debian folds into syslog; RHEL uses /var/log/cron)
grep -i CRON /var/log/syslog 2>/dev/null

cat /var/log/cron 2>/dev/null

# Timer/service starts in the journal
journalctl | grep -Ei "timer|Starting .*\.service|Started"

# MAILTO output or /var/mail entries from cron jobs
ls -la /var/mail/ /var/spool/mail/ 2>/dev/null
```

Cron output is also mailed locally by default (unless `MAILTO` is set or redirected), so `/var/mail/` can hold the stdout/stderr of a scheduled attacker job — occasionally a direct record of what it did.

## Deep Threat Hunts

Complete-enumeration + timeline + execution-proof sweep (collection focus; ranking → Persistence). *(seasoned-DFIR)*

```bash
# 1. ONE-PASS enumeration of EVERY scheduled-execution artifact (run as root)
{ for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s|^|[cron:$u] |"; done
  echo "== system =="; cat /etc/crontab /etc/cron.d/* 2>/dev/null
  ls /etc/cron.{hourly,daily,weekly,monthly}/ 2>/dev/null
  echo "== at =="; atq 2>/dev/null
  echo "== timers =="; systemctl list-timers --all 2>/dev/null; }

# 2. Timeline: mtime-sort every schedule definition (freshly planted floats up)
find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
     /etc/cron.monthly /var/spool/cron /etc/systemd/system /run/systemd/system \
     /home/*/.config/systemd/user -type f 2>/dev/null \
  | xargs -r ls -la --time-style=long-iso 2>/dev/null | sort -k6

# 3. Transient/other schedulers with no obvious file
systemctl list-timers --all | grep -Ei 'run-r[0-9a-f]+'

cat /etc/anacrontab 2>/dev/null; ls /etc/incron.d/ 2>/dev/null

# 4. PROOF a job ran (ties the schedule into the timeline)
grep -iE 'CRON.*CMD' /var/log/cron /var/log/syslog 2>/dev/null

journalctl -u '*.timer' --no-pager 2>/dev/null | tail

ls -la /var/mail/ /var/spool/mail/ 2>/dev/null

# 5. Collect the whole scheduling surface to evidence
tar czf /evidence/schedules.tgz /etc/cron* /var/spool/cron /etc/anacrontab \
  /etc/systemd/system/*.timer /home/*/.config/systemd/user/*.timer 2>/dev/null
```

**Hunt ideas:**

- **Enumerate every scheduler, not just cron** — `at`, systemd timers, anacron, incron, fcron, and transient `systemd-run` timers (which leave *no file* — only `list-timers` reveals them).
- **mtime-sort all schedule definitions** — the freshly planted job floats to the top, dating the plant.
- **Execution proof ties the schedule to the incident** — cron `CMD` lines, timer journal starts, and `/var/mail` output are what turn "a job exists" into "a job ran at this time."
- **Run as root** — the user spool is mode 700; a non-root sweep silently reports "no cron jobs."

## Getting Max Value

- **Collect definitions *and* execution proof together** — the schedule file plus the log line showing it fired.
- **Never trust a clean crontab alone** — check one-shot `at` jobs and transient `systemd-run` timers that leave no persistent file.
- **Timeline every schedule-file mtime** — a fresh one is the plant time; correlate with the rest of the incident.
- **On a mounted image**, read the spool/units directly (`list-timers` needs the live host — enumerate the timer *files* on an image).
- **Then hand off to Persistence** for the ranking/detection logic — this note's job is to make sure no scheduling artifact is missed.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Detection/ranking + how each mechanism works | **Persistence → Cron and at Jobs**, **Systemd Units Timers and Generators** |
| What the scheduled job actually executed | the payload script it points to; **Shells** (history) |
| Proof it ran + exactly when | **Systemd Journal**, **Syslog** (cron), **Timelining** (13) |
| The job's captured output | `/var/mail` (local mail delivery) |
| Whether the cron file is immutable-armored | **File and Directory Permissions** (02, `lsattr`) |

## Scenarios

- **Missed one-shot:** an `at` job runs once after the attacker logs off — cron looks clean, the queue isn't.
- **Fileless timer:** a transient `systemd-run` timer has no unit file; only `list-timers` reveals it.
- **Service-account cron:** `www-data`/`nobody` schedules a network fetch it has no business scheduling.
- **`@reboot` persistence:** the payload re-runs on every boot.
- **Execution proof:** `/var/mail` holds the stdout of a scheduled attacker job — a direct record of what it did.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `@reboot` or short-interval job running a network fetch | Persistence + C2/download |
| Cron/at job owned by a service account | Repurposed for attacker execution |
| Recently modified cron file or timer unit | Freshly planted schedule |
| `at` job queued (runs once, easy to miss) | Delayed / one-shot execution |
| User-level systemd timer in a home dir | Per-user persistence |
| Cron file with `+i` immutable bit | Armored persistence |
| Transient `systemd-run` timer with no unit file | Fileless scheduled execution |
| `anacrontab`/`incron.d` entry running a payload | Less-watched scheduler abused |

## Resources

- `crontab(5)`, `systemd.timer(5)`, `systemd-run(1)`, `at(1)`, `anacron(8)`, `incrontab(5)` man pages
- MITRE ATT&CK: T1053.003 (Cron), T1053.006 (Systemd Timers), T1053.002 (At)
