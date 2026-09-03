# Unified Logs – Authentication and Security

How macOS records **interactive authentication** and **privilege escalation** in the Unified Logging System: GUI logins/logouts and screen unlock (`loginwindow`), and elevation via `sudo`/PAM (`su`, `login`). Same rolling-buffer rules apply — **collect early**.

> 🔴 These events drive **timeline reconstruction** (who was at the box, when) and **privilege-escalation / brute-force** detection. They age out of the buffer in days — redirect to a file or `log collect` before shutdown.

## Contents
- [Quick Triage](#quick-triage)
- [Subsystems](#subsystems)
- [loginwindow Login and Logout Events](#loginwindow-login-and-logout-events)
- [Successful vs Failed Logins](#successful-vs-failed-logins)
- [Screen Lock, Unlock, and Screensaver](#screen-lock-unlock-and-screensaver)
- [sudo and PAM Privilege Escalation](#sudo-and-pam-privilege-escalation)
- [su and login](#su-and-login)
- [Live Streaming](#live-streaming)
- [Preserving Authentication Logs](#preserving-authentication-logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
log show --predicate 'subsystem == "com.apple.loginwindow" AND eventMessage CONTAINS "fail"' --last 24h

log show --predicate '(process == "sudo") OR (eventMessage CONTAINS "PAM")' --last 1h

log show --predicate 'process == "su" OR process == "login"' --info --last 7d

who -a; last | head                                                 # who is / was on the box

log show --predicate 'subsystem == "com.apple.loginwindow" OR process == "sudo"' --last 1h > auth_events_last_hour.txt
```

---

## Subsystems

| Question | process / subsystem |
|---|---|
| Interactive login / logout / unlock | `subsystem == "com.apple.loginwindow"` (also `com.apple.loginwindow.logging`) |
| Privilege escalation | `process == "sudo"`; `eventMessage CONTAINS "PAM"` |
| Switch user / TTY console login | `process == "su"`, `process == "login"` |

> The actual password verification happens in **`opendirectoryd`**; remote/keychain/authorization auth in **`sshd`/`securityd`/`authd`** (Advanced Authentication note).

> 🔴 Many values are logged as `<private>` (usernames, etc.). Reveal on a live box only if needed (`sudo log config --mode "private_data:on"`) and document it; corroborate redacted entries with `last` or the DSLocal account store.

Live "who's on the box right now" (corroborates the log):
```bash
who -a        # current login sessions + idle/source

w             # who + what they're running

last | head   # recent login history (utmpx)
```

---

## loginwindow Login and Logout Events

`loginwindow` drives the GUI login screen, session start/stop, logout, and screen unlock.

```bash
# All loginwindow subsystem entries (last hour)
log show --predicate 'subsystem == "com.apple.loginwindow"' --last 1h
```
> Also query **`com.apple.loginwindow.logging`** for additional log entries:
```bash
log show --predicate 'subsystem == "com.apple.loginwindow.logging"' --last 1h
```

🔴 Extract: which **user** logged in/out, **session** start/stop times, console vs fast-user-switch, and auto-login (passwordless) sessions.

---

## Successful vs Failed Logins

Run each separately as needed:

```bash
# Successful login attempts
log show --predicate 'subsystem == "com.apple.loginwindow" AND eventMessage CONTAINS "success"' --last 1h

# Failed login attempts
log show --predicate 'subsystem == "com.apple.loginwindow" AND eventMessage CONTAINS "failed"' --last 1h

# Broader: "fail" matches both "failed" and "failure"
log show --predicate 'subsystem == "com.apple.loginwindow" AND eventMessage CONTAINS "fail"' --last 1h
```

🔴 Brute-force / password-guessing triage — count failures over a window:

```bash
# Failed GUI logins in last 24h (rough count)
log show --predicate 'subsystem == "com.apple.loginwindow" AND eventMessage CONTAINS[c] "fail"' --last 24h | grep -ci fail
```

> Many failures clustered in time, then a success = likely guessing. The deeper credential-failure source is `opendirectoryd` (see Advanced Authentication). Corroborate with `last` and the DSLocal account.

---

## Screen Lock, Unlock, and Screensaver

Unlock = a re-authentication event; places a user at the keyboard.

```bash
# Lock / unlock / screensaver auth via loginwindow
log show --predicate 'subsystem == "com.apple.loginwindow" AND (eventMessage CONTAINS[c] "lock" OR eventMessage CONTAINS[c] "unlock" OR eventMessage CONTAINS[c] "screensaver")' --info --last 24h
```

🔴 Unlock events outside expected hours, or right before/after suspicious activity, help place a human at the console (vs remote/automated action).

---

## sudo and PAM Privilege Escalation

```bash
# sudo usage OR any PAM-related event (privilege escalations)
log show --predicate '(process == "sudo") OR (eventMessage CONTAINS "PAM")' --last 1h
```

🔴 Deeper sudo/PAM hunting:

```bash
# sudo command lines, the user, and the target (TTY/CWD/COMMAND)
log show --predicate 'process == "sudo"' --info --last 7d

# PAM auth successes/failures (sudo, login, su, screensaver all use PAM)
log show --predicate 'eventMessage CONTAINS[c] "PAM" AND (eventMessage CONTAINS[c] "fail" OR eventMessage CONTAINS[c] "authentication")' --info --last 7d
```

| Signal | Meaning |
|---|---|
| 🔴 `sudo: <user> : command not allowed` / auth failures | Unauthorized escalation attempt |
| 🔴 sudo by an unexpected user or service account | Possible account compromise / backdoor |
| 🔴 `sudo … COMMAND=` running shells, `dscl`, `defaults`, downloaders | Hands-on-keyboard escalation |
| `PAM … authentication failure` bursts | Credential guessing against escalation paths |
| sudo `NOPASSWD` / sudoers edits referenced | Persistence via relaxed escalation (cross-ref Users and Groups) |

---

## su and login

`su` (switch user) and `login` (TTY/console session) are the classic PAM-driven interactive auth paths — high value for identity changes on the box.

```bash
# su / login activity (identity switch, console auth)
log show --predicate 'process == "su" OR process == "login"' --info --last 7d
```

🔴 Watch for: `su` to **root** or to **another user's** account, `su`/`login` against **hidden / newly created / UID<500** accounts (cross-ref Users and Groups), and repeated `su` failures (guessing another account's password).

---

## Live Streaming

```bash
# Stream auth events in real time (resource-intensive, live system only)
log stream --predicate 'subsystem == "com.apple.loginwindow" OR process == "sudo"' --info

# Wider live auth watch (interactive paths)
log stream --predicate 'subsystem == "com.apple.loginwindow" OR process == "sudo" OR process == "su" OR process == "login"' --info
```

> Use streaming during active IR to watch logins/escalations as they happen; pipe to a file to keep a record (`log stream … | tee /evidence/auth_stream.txt`).

---

## Preserving Authentication Logs

```bash
# Redirect auth-related logs to a file for correlation (last hour)
log show --predicate 'subsystem == "com.apple.loginwindow" OR process == "sudo"' --last 1h > auth_events_last_hour.txt

# Wider interactive-auth capture to file
log show --predicate 'subsystem == "com.apple.loginwindow" OR process == "sudo" OR process == "su" OR process == "login"' --info --last 7d > auth_events_7d.txt

# Full store for evidence (carries format strings)
sudo log collect --output /evidence/host.logarchive

log show --archive /evidence/host.logarchive --predicate 'process == "sudo"' --info
```

> Corroborate with **`last`** / **`last -t`** (login history from `utmpx`) and the account store (DSLocal) — these survive log rollover and back up redacted (`<private>`) entries.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Cluster of **failed** GUI logins then a success | Brute force / password guessing succeeded |
| Login or unlock to a **hidden / newly created / UID<500** account | Backdoor account in use (cross-ref Users and Groups) |
| `sudo` by an unexpected user or service account | Privilege escalation via compromised creds |
| `sudo … COMMAND=` launching shells / `dscl` / downloaders | Hands-on-keyboard activity |
| `PAM authentication failure` bursts | Guessing against escalation paths |
| `su` to root / another user at an odd time | Lateral identity change / account misuse |
| Unlock events **outside business hours** | Unauthorized physical/remote access |
| Auth events with surrounding **timeline gaps** | Possible log tampering / clock change |

---

## Resources

- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
- The Eclectic Light Company – Consolation / Ulbow / log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
