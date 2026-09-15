# Authentication and Login Records

Who logged in, when, from where, and what failed — this is the backbone of nearly every intrusion timeline, because almost all attacks pass through an authentication event you can pin down. Linux splits this evidence across two very different stores: the **binary login databases** (`wtmp`/`btmp`/`utmp`/`lastlog`), read with dedicated tools, and the **text auth logs** (`auth.log`/`secure`), which carry the SSH/sudo/PAM detail. The binary files tell you *that* a session happened; the text logs tell you *how* it authenticated and what it did next.

> 🔴 The single highest-value pattern here is **fail-then-success from the same source**: a wall of `Failed password` from one IP followed by an `Accepted` from that same IP is a successful brute force, and everything that session did is now suspect. Conversely, a suspiciously *short* `last` history or a zero-length `wtmp`/`btmp` means the login record was wiped.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Binary Login Databases](#binary-login-databases)
- [Text Auth Logs](#text-auth-logs)
- [SSH Activity](#ssh-activity)
- [Brute Force Detection](#brute-force-detection)
- [Public Key vs Password](#public-key-vs-password)
- [Active Sessions](#active-sessions)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Successful logins (most recent first)
last -Fa

# Failed logins (root required)
sudo lastb

# Last login per account
lastlog

# Successful SSH logins from the auth log
grep -Ei "Accepted" /var/log/auth.log /var/log/secure 2>/dev/null

# Failed SSH by IP (brute-force triage)
grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -nr | head

# Who's on now
w
```

## What to Check for What

| Investigative question | Command / filter |
|------------------------|------------------|
| Did a brute force **succeed**? | intersect failed-IPs with accepted-IPs (Deep Hunts #1) |
| Who logged in, when, from where? | `last -Fa`; `grep Accepted /var/log/auth.log` |
| What failed / was sprayed? | `lastb`; `grep "Failed password\|Invalid user"` |
| Was the login record wiped? | `utmpdump /var/log/wtmp`; `ls -l /var/log/wtmp /var/log/btmp` |
| Was it password or key auth? | `grep "Accepted password\|Accepted publickey"` |
| Which key was used? | pubkey fingerprint in the `Accepted publickey` line → `authorized_keys` |
| Root login when it should be off? | `grep "Accepted.*root" /var/log/auth.log` |
| Login records if text logs are gone? | `ausearch -m USER_LOGIN -i`; `grep USER_LOGIN /var/log/audit/audit.log*` |
| Who is on the box right now? | `w`; `who -a`; `ss -tnp \| grep sshd` |
| A dormant service account that woke up? | `lastlog \| grep -v 'Never logged in'` |

## Binary Login Databases

These four files are **binary** — you must use the dedicated tools, not `cat`. Each answers a different question, and `btmp` (failed attempts) requires root because it's a common target for credential-stuffing analysis.

| File | Content | Tool |
|------|---------|------|
| `/var/log/wtmp` | Login/logout history | `last` |
| `/var/log/btmp` | **Failed** login attempts (root-only) | `lastb` |
| `/run/utmp` | Currently logged-in users | `who`, `w` |
| `/var/log/lastlog` | Last login time per user | `lastlog` |

```bash
# Full history with year + IP/host column
last -Fa

last -F -f /var/log/wtmp

# Rotated wtmp archives
last -F -f /var/log/wtmp.1

# Raw dump (see the struct fields directly)
utmpdump /var/log/wtmp

# Failed attempts
lastb -f /var/log/btmp

# Per-user last login
lastlog

# History for one account / most recent with host column
last <username>

last -a | head -20

# Failed-login counters per user (from /var/log/faillog)
faillog -a

faillog -u <user>

# From a mounted image (wildcard picks up rotated wtmp/btmp too)
last -F -f /mnt/evidence/var/log/wtmp

utmpdump /var/log/wtmp*

lastb -f /mnt/evidence/var/log/btmp
```

🔴 **Tamper tells:** a `last` history that starts abruptly (no old entries), a zero-size `wtmp`/`btmp`, or a `reboot` line inserted to paper over a gap. `utmpdump` is the way to spot hand-edited records — it prints the raw struct fields, so malformed or zeroed entries that `last` would render cleanly become visible.

## Text Auth Logs

`auth.log` (Debian) / `secure` (RHEL) carry the SSH, sudo, su, and PAM detail. This is where you see *how* an authentication succeeded and, critically, the source IP and username.

```bash
# Successful / failed / sudo (Debian)
grep -i "accepted" /var/log/auth.log

grep -i "failed" /var/log/auth.log

grep -i "sudo" /var/log/auth.log

# RHEL equivalent
grep -i "accepted" /var/log/secure

# If auth.log is absent, syslog may carry it
grep -Ei "sshd|failed|accepted" /var/log/syslog* 2>/dev/null

# Search rotated + compressed
zgrep -i accepted /var/log/auth.log.*.gz 2>/dev/null
```

| Log line | Meaning |
|----------|---------|
| `Accepted password for user from IP` | Successful password login |
| `Accepted publickey for user from IP` | Successful key login |
| `Failed password for user from IP` | Failed attempt |
| `Failed password for invalid user X` | Login to a **non-existent** account (brute force / spray) |
| `session opened for user by (uid=0)` | PAM session start |
| `session opened for user root by (uid=1000)` | 🔴 `su`/`sudo` escalation to root by uid 1000 |
| `sudo: user : COMMAND=...` | 🔴 Privilege escalation with the exact command run |
| `Connection closed by authenticating user … [preauth]` | 🔴 Modern OpenSSH brute-force shape (no "Failed password") |
| `Disconnected from authenticating user` / `maximum authentication attempts` | Automated password/key spray |

The `Failed password for invalid user` lines are especially telling — they mean someone tried usernames that don't exist on the box, the signature of an automated spray rather than a fat-fingered admin.

## SSH Activity

SSH is the primary remote-access path, so its log lines carry most of the intrusion signal. Pin down a suspect user or IP and follow it.

```bash
# All sshd lines
grep "sshd" /var/log/auth.log

journalctl -u ssh -u sshd.service

# Today's SSH connections
grep sshd /var/log/auth.log | grep "$(date '+%b %e')"

# Logins by a specific user / from a specific IP
grep "Accepted.*for USER" /var/log/auth.log

grep "Accepted.*from 10.0.0.5" /var/log/auth.log

# Root logins (should usually be none if PermitRootLogin no)
grep "Accepted.*root" /var/log/auth.log

# Real-time SSH monitoring (live host)
tail -f /var/log/auth.log | grep sshd

# Journal-side SSH, bounded / followed
journalctl -u ssh --since "1 hour ago"

journalctl -u ssh --since "2026-04-23" --until "2026-04-24"

journalctl -u ssh -f
```

🔴 An `Accepted` for `root` on a host where `PermitRootLogin` should be `no` is either a misconfiguration the attacker exploited or evidence the config was changed — pivot to the SSH Artifacts note.

## Brute Force Detection

```bash
# Top source IPs for failed passwords
grep "Failed password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -nr | head -10

# Invalid-user attempts (usernames sprayed)
grep "Invalid user" /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -nr

# Failures in the last hour
grep "Failed password" /var/log/auth.log | grep "$(date '+%b %e %H')"

# Count logins per user across wtmp
last | awk '{print $1}' | sort | uniq -c | sort -nr

# Geo-locate the top failed-login sources (requires geoiplookup)
grep "Failed password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort -u | xargs -I{} geoiplookup {}
```

Alternate IP-extraction when the log format shifts the column (field-based):

```bash
# Top source IPs by failed sshd auth (positional awk variant)
grep "sshd" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
```

🔴 The pivot that matters: after ranking failed-login IPs, check whether any of them *also* produced an `Accepted`. That IP is where a brute force succeeded, and the corresponding session is your entry point — follow it into the shell history and process tree.

## Public Key vs Password

```bash
grep "Accepted publickey" /var/log/auth.log

grep "Accepted password" /var/log/auth.log
```

The auth method itself is a signal: a *password* login in an environment that's supposed to be key-only, or a *pubkey* login using a key that shouldn't exist, both send you to `~/.ssh/authorized_keys` to find out which key was used and whether an attacker planted it (see the SSH Artifacts note).

## Active Sessions

```bash
# Logged-in users + what they're running
w

who -a

users

# SSH sessions specifically
who | grep pts

ss -tnp | grep sshd

netstat -tnpa | grep 'ESTABLISHED.*sshd'

lsof -i :22

# Process tree of SSH sessions + a user's processes
ps auxf | grep sshd

ps -u <username> -f
```

On a live host, `w` shows not just who's connected but what each session is currently running — an attacker's active session may be visible right now. `ps auxf` under the session's `sshd` shows the exact shell/commands that login is running.

## Deep Threat Hunts

The entry-point sweep. *(seasoned-DFIR; do #1 first — it's the fastest path to the intrusion)*

```bash
# 1. THE money pivot: IPs that FAILED then got ACCEPTED = successful brute force
comm -12 \
  <(grep 'Failed password' /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort -u) \
  <(grep 'Accepted'        /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort -u)

# 2. Modern OpenSSH brute-force shapes (hidden in [preauth], not "Failed password")
grep -Ei "Connection closed by authenticating user|Disconnected from authenticating user|maximum authentication attempts|Received disconnect.*preauth" /var/log/auth.log 2>/dev/null

# 3. Every source IP that logged in successfully — baseline against known-good
grep 'Accepted' /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort -u
#   a first-seen IP that succeeds with NO prior failures = stolen valid creds, not brute force

# 4. su / sudo to root, with the exact command
grep -Ei "session opened for user root|COMMAND=|su(\[|:).*root" /var/log/auth.log 2>/dev/null

# 5. auditd login records — survive when the text logs are wiped
ausearch -m USER_LOGIN,USER_AUTH -i 2>/dev/null

grep USER_LOGIN /var/log/audit/audit.log* 2>/dev/null

# 6. Service accounts that ever logged in (should be "Never")
lastlog | grep -Ev 'Never logged in|^Username'

# 7. Distribution of successful-login hours (off-hours access stands out)
grep 'Accepted' /var/log/auth.log | awk '{print $3}' | cut -d: -f1 | sort | uniq -c

# 8. Pubkey fingerprint used (newer OpenSSH) -> match to authorized_keys to ID the key
grep -Eo 'Accepted publickey for .*(RSA|ED25519|ECDSA) SHA256:[A-Za-z0-9+/]+' /var/log/auth.log 2>/dev/null

# 9. Geo/ASN the top failed-login sources
grep "Failed password" /var/log/auth.log | grep -oP 'from \K[\d.]+' | sort -u | xargs -I{} geoiplookup {}
```

**Hunt ideas:**

- **The fail→accept intersection (#1) is the single fastest way to find the entry point** — run it before anything else.
- **A clean success from a never-before-seen IP with zero failures is scarier than a brute force** — it's valid stolen creds. Baseline your legitimate source IPs so the outlier pops.
- **Modern OpenSSH hides brute force in `[preauth]` closes**, not `Failed password` — grep both shapes.
- **`lastlog` is a free "which dormant account woke up" check** — a service account with a login time is repurposed.
- **Match the logged pubkey fingerprint to `~/.ssh/authorized_keys`** to identify exactly which key an attacker used, and whether they planted it.

## Getting Max Value

- **Preserve first:** copy `wtmp`/`btmp`/`utmp`/`lastlog`, `auth.log*`/`secure*` (incl. `.gz`), and the audit log before touching them; use `utmpdump` for byte-level integrity.
- **auditd `USER_LOGIN` records survive text-log wiping** — always check them when `wtmp`/`auth.log` look thin.
- **Build the session story:** accepted-login time → `wtmp` session → shell-history mtime → process tree. Those four line up a login with what it did.
- **Normalize to UTC** — syslog timestamps are *local* with no offset; a raw compare against filesystem UTC times will skew by hours.
- **If off-host syslog/SIEM exists** (Logging Architecture), the auth record may be intact there even if the local copy was wiped.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Which key was used / was it planted? | **SSH Artifacts**, **Persistence → SSH Keys** |
| What the session ran after login | **Shells** (history), **Auditd** (`USER_CMD`), **Process Trees** (10b) |
| Structured per-session replay | **Systemd Journal** (`_AUDIT_SESSION`) |
| `wtmp`/`btmp` byte-level tampering | **Logging Architecture**, **Anti-Forensics** (13b) |
| Lateral movement **out** to the next host | **SSH Artifacts** (`known_hosts`) |
| Was the account itself a backdoor? | **Users Groups and Authentication** (03) |
| Geo/ASN + C2 nature of the source IP | **Network and PCAP Forensics** (10c) |

## Scenarios

- **Successful brute force:** a wall of `Failed password` then an `Accepted` from the same IP — the session that follows is your entry point.
- **Valid-cred abuse:** a clean `Accepted` from a new IP with no failures — stolen credentials, not brute force; baseline source IPs to catch it.
- **Root login bypass:** `Accepted` for `root` where `PermitRootLogin` should be `no` — misconfig exploited or config changed.
- **Login-record wipe:** zero-size `wtmp`/`btmp`, a suspiciously short `last`; `utmpdump` reveals the hand-edits.
- **Planted-key access:** `Accepted publickey` with an unfamiliar fingerprint → find the key in `authorized_keys`.
- **Dormant activation:** a service account appearing in `lastlog`/`last` — repurposed for access.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Failures from an IP then `Accepted` from that IP | Successful brute force |
| `Accepted` for root when root login should be disabled | Policy bypass / misconfig |
| Successful login from an unexpected geo/IP or at an odd hour | Compromised credential |
| Zero-size or truncated `wtmp`/`btmp` | Login history wiped |
| `Accepted publickey` with an unfamiliar key fingerprint | Attacker-planted key |
| Login immediately followed by user/sudo changes | Foothold being consolidated |
| Many `Failed password for invalid user` | Automated username spray |
| `[preauth]` connection-closed bursts from one IP | Modern OpenSSH brute force |
| Clean `Accepted` from a first-seen IP, no failures | Valid stolen credentials |
| Service account present in `lastlog`/`last` | Dormant account repurposed |
| `session opened for user root by (uid=N)` off-hours | Escalation to root outside normal ops |

## Resources

- `last(1)`, `lastb(1)`, `lastlog(8)`, `faillog(8)`, `utmpdump(1)`, `wtmp(5)`, `sshd(8)` man pages
- MITRE ATT&CK: T1110 (Brute Force), T1021.004 (Remote Services: SSH), T1078 (Valid Accounts), T1070 (Indicator Removal — wtmp/btmp), T1548.003 (Sudo)
