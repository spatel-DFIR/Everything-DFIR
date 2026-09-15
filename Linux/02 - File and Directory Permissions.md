# File and Directory Permissions

Linux permissions are both a privilege-escalation surface and a hiding place, so they matter twice in DFIR. An attacker who lands as an unprivileged user hunts for a SUID binary or a file capability that hands them root; an attacker who already has root leaves one behind as a re-entry primitive, flips an immutable bit to lock persistence against removal, and timestomps dropped files to sink them beneath a timeline's noise floor. This note covers the whole surface — POSIX bits, special bits, ACLs, file capabilities, extended attributes, immutability, and the timestamp analysis that exposes tampering — emphasizing *what an attacker does with each and how you catch it*.

> 🔴 Two things trip analysts here. First, **capabilities are not SUID** — a binary with `cap_setuid` grants root without ever setting the setuid bit, so a SUID-only sweep misses it; always run `getcap -r /` too. Second, **`ctime` cannot be forged with `touch`** — it updates on any metadata change — so when `mtime`/`atime` look old but `ctime` is recent, you're almost certainly looking at a timestomp.

> ⚠️ Before trusting `atime`, check the mount: `relatime`/`noatime` (the modern default) make access times unreliable. And **reading a file can bump its `atime`** — `stat` every suspect file and record all four times *before* you open it.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [POSIX Permissions and Octal](#posix-permissions-and-octal)
- [Special Bits SUID SGID Sticky](#special-bits-suid-sgid-sticky)
- [File Capabilities](#file-capabilities)
- [Access Control Lists](#access-control-lists)
- [Extended Attributes](#extended-attributes)
- [Immutable and Append-Only](#immutable-and-append-only)
- [Timestamps and Timestomping](#timestamps-and-timestomping)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
# All SUID/SGID binaries (privesc surface)
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# Files with capabilities (SUID-less privesc)
getcap -r / 2>/dev/null

# Immutable/append-only files (locked persistence)
lsattr -R /etc /root /home 2>/dev/null | grep -E '^....i|^.....a'

# World-writable files outside tmp
find / -xdev -type f -perm -0002 ! -path '/proc/*' -ls 2>/dev/null

# Recently changed files in /etc (last 3h)
find /etc -type f -mmin -180 -ls 2>/dev/null
```

## What to Check for What

| Investigative question | Command / filter |
|------------------------|------------------|
| What can escalate me to root here (SUID)? | `find / -perm -4000 -type f -ls` |
| SUID-less privesc (capabilities)? | `getcap -r / 2>/dev/null` |
| Is persistence armored (immutable)? | `lsattr -R /etc /root /home … \| grep i` |
| Hidden access grants (ACLs)? | `getfacl -R -s /etc` |
| Was a file timestomped? | compare `ctime` vs `mtime`; `find -newerct … ! -newermt …` |
| World-writable file in a system path? | `find / -xdev -type f -perm -0002 -ls` |
| Data hidden in extended attributes? | `getfattr -d -m - <file>` |
| What is the file's *real* birth time? | `stat --printf='%w\n' <file>`; `debugfs -R 'stat <inode>'` |
| Files owned by nobody (deleted user)? | `find / -xdev \( -nouser -o -nogroup \) -ls` |
| SUID/SGID planted in the incident window? | `find / -perm -4000 -newermt "<start>" ! -newermt "<end>"` |

## POSIX Permissions and Octal

Three permission triads (owner/group/other), each combining read, write, execute. Be fluent in the octal — you'll read it constantly in `find -perm` expressions and `chmod` traces in histories.

```
r (read) = 4    w (write) = 2    x (execute) = 1
```

On top of the base triads sit three *special* bits that change execution or deletion semantics — the security-relevant ones:

| Special bit | Octal | On file | On directory |
|-------------|-------|---------|--------------|
| SUID (`u+s`) | 4 | Run as file **owner** (→ root if owned by root) | (no effect) |
| SGID (`g+s`) | 2 | Run as file **group** | New files inherit dir group |
| Sticky (`o+t`) | 1 | (legacy) | Only the owner can delete their own files (`/tmp`) |

```bash
# Reading the mode column: -rwsr-xr-x = SUID; -rwxr-sr-x = SGID; drwxr-xr-t = sticky
chmod 4755 file   # SUID

chmod 2755 file   # SGID

chmod 1755 dir    # sticky
```

An `s` shown in **uppercase** (`S`) means the setuid/setgid bit is set but the execute bit is *not* — usually a misconfiguration, occasionally a deliberate quirk. Note it, but the dangerous case is the lowercase `s` on an executable.

## Special Bits SUID SGID Sticky

SUID/SGID is the classic Linux local-privesc surface: a program that runs as its owner (often root) but is invokable by any user. The legitimate set is small and stable per distro (`passwd`, `sudo`, `mount`, `ping`, etc.), which is exactly why *baselining* is so effective — anything beyond the known-good list is worth explaining.

```bash
# Full SUID/SGID sweep, cross-filesystem excluded for speed
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null

# SUID binaries in unusual locations (not standard system paths)
find / -type f -perm -4000 ! -path '/usr/*' ! -path '/bin/*' ! -path '/sbin/*' -ls 2>/dev/null

# SUID/SGID in user-writable or temp areas
find /home /tmp /var/tmp /dev/shm /opt -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
```

🔴 **How this is abused:** an attacker either finds an existing dangerous SUID binary or creates one. A SUID shell (`bash`, `dash`), a SUID interpreter (`python`, `perl`), or a SUID copy of `find`/`vim`/`nmap`/`cp`/`tar`/`cpulimit` is instant root — these are the GTFOBins privesc primitives, because each can be coerced into running an arbitrary command *as its owner*. A SUID-root binary sitting in `/home`, `/tmp`, or a custom `/opt` path is almost never legitimate. Diff the SUID set against a clean host of the same distro; the delta is your suspect list.

## File Capabilities

Capabilities slice root's omnipotence into ~40 discrete privileges that can be attached to a file, granting a specific power *without* the SUID bit. A favorite modern privesc and persistence vector precisely because a SUID-only sweep misses them.

```bash
# Enumerate all file capabilities
getcap -r / 2>/dev/null

# Capabilities of a running process
getpcaps <PID>

# Login-time capability grants (rarely used, worth a look)
cat /etc/security/capability.conf 2>/dev/null
```

| Capability | Why it's dangerous |
|------------|--------------------|
| `cap_setuid` / `cap_setgid` | Become any user → root |
| `cap_dac_override` / `cap_dac_read_search` | Bypass file permission checks (read/write any file, incl. `/etc/shadow`) |
| `cap_sys_admin` | Near-omnipotent; mount, namespaces, many escape primitives |
| `cap_sys_ptrace` | Attach to any process (inject code, read secrets from memory) |
| `cap_sys_module` | Load kernel modules (→ rootkit) |
| `cap_net_raw` | Raw sockets (sniffing, ARP spoofing) |

🔴 `cap_setuid+ep` on anything other than the small set of expected binaries is a privesc backdoor left for re-entry — an attacker adds it to an innocuous-looking binary and comes back to root later without tripping a SUID alarm.

## Access Control Lists

POSIX ACLs extend permissions beyond the single owner/group/other model, letting specific users or groups be granted access. A `+` at the end of the mode string (`-rw-rw-r--+`) is the visible flag that an ACL is present — easy to miss on a quick `ls`.

```bash
# Show ACLs on a file
getfacl /path/to/file

# Find files carrying ACLs
getfacl -R -s /etc 2>/dev/null

# Default ACLs on a directory (inherited by new files)
getfacl -d /path/to/dir
```

🔴 The abuse case is a stealthy grant: an ACL that lets an unexpected user or service account read a sensitive file (e.g. giving `www-data` read on `/etc/shadow`) achieves access without changing the file's visible owner/group/mode. Because it doesn't show in a normal `ls -l`, it's a quiet backdoor — enumerate ACLs on sensitive files explicitly.

## Extended Attributes

Extended attributes (xattrs) are name/value metadata attached to files, organized into namespaces. They carry SELinux labels and capability data, and the `user.*` namespace is arbitrary — occasionally abused to stash data out of sight.

```bash
# Dump all xattrs on a file
getfattr -d -m - /path/to/file

# SELinux label lives in security.selinux
getfattr -n security.selinux /path/to/file
```

Namespaces: `security.*` (SELinux/capabilities/IMA), `system.*` (ACLs), `trusted.*` (root-only), `user.*` (arbitrary). A `user.*` xattr holding base64, a URL, or a blob is worth extracting — it can be a data-hiding channel or an attacker marker. A missing or wrong `security.selinux` label on a system file can also indicate tampering.

## Immutable and Append-Only

The ext/xfs/btrfs immutable (`i`) and append-only (`a`) attributes sit *outside* the POSIX model — even root cannot modify or delete an immutable file until the attribute is cleared. Attackers use this to armor persistence.

```bash
# Show attributes (i = immutable, a = append-only)
lsattr /etc/passwd /etc/shadow /etc/crontab

# Recursively flag immutable/append-only files
lsattr -R /etc /root /home /var/spool/cron 2>/dev/null | grep -E '^....i|^.....a'

# An attacker sets +i so the file can't be edited/removed:
# chattr +i /path   (immutable)
# chattr +a /path   (append-only)
# You must clear it before removal: chattr -i /path
```

🔴 **The two abuse patterns:** (1) *armored persistence* — `+i` on a cron file, systemd unit, `authorized_keys`, `ld.so.preload`, or a dropped binary so responders' `rm` fails and the foothold survives naive cleanup (you must `chattr -i` first); and (2) *denial* — `+i` on `/etc/passwd` or `/etc/resolv.conf` to lock a legitimate admin out of fixing something. Always `lsattr` your suspect persistence paths; a "why won't this delete" moment is the tell.

## Timestamps and Timestomping

Every file carries four timestamps; three are visible with `stat`, and the fourth (birth) needs help. Understanding which the attacker *can* control is the whole game in anti-forensics.

| Time | Meaning | Attacker control |
|------|---------|------------------|
| `mtime` | Content last modified | Freely set with `touch -t/-d` or copied with `touch -r` |
| `atime` | Last accessed | Often unreliable (`relatime`/`noatime` mounts) |
| `ctime` | Inode last changed | **Cannot** be set by `touch`; changes on any metadata edit |
| `crtime` (birth) | File creation | ext4/XFS/Btrfs only; not shown by default `stat` |

```bash
# All visible timestamps + metadata
stat /path/to/file

# Birth time on ext4/XFS (statx, newer coreutils)
stat --printf='%w\n' /path/to/file

# ext4 birth time via debugfs (needs device + inode)
debugfs -R "stat <inode>" /dev/sda1 2>/dev/null

debugfs -R "stat /test/testfile" /dev/sda3 2>/dev/null

# View a specific time with ls
ls -l --time=atime file

ls -l --time=ctime file

ls -l --time=birth file
```

🔴 **Detecting timestomping** — attackers `touch` a dropped file back to an old date to bury it in the timeline, but they routinely forget `ctime` (which `touch` can't set):

- **`mtime`/`atime` older than `ctime`** — content claims to be old but the inode was changed recently. The single most reliable timestomp tell.
- **Whole-second timestamps with zeroed nanoseconds** (`stat` shows `.000000000`) while neighbouring legitimate files carry sub-second precision — a tell that times were set programmatically (`touch -t` has second granularity).
- **`mtime` far in the past on a file whose containing directory `mtime` is recent** — the directory remembers when the file was really added.
- **Check atime reliability first:** `mount | grep -E 'relatime|noatime'` — if set, atime tells you little regardless.

```bash
# Files whose ctime is newer than mtime (possible timestomp)
find /etc /usr/bin /tmp -type f -newerct '1 day ago' ! -newermt '1 day ago' -ls 2>/dev/null

# Everything changed in an exact window (broad activity/timestomp sweep)
find / -newermt "2026-04-27 00:00:00" ! -newermt "2026-04-27 03:00:00" -print 2>/dev/null

# Files modified on/after a date, with detail
find /path/to/dir -type f -newermt "2026-04-30" -exec ls -lh {} \; 2>/dev/null
```

## Deep Threat Hunts

Consolidated privesc + tamper sweep. *(seasoned-DFIR additions on top of the RTR set)*

```bash
# 1. SUID/SGID inventory to diff against a known-good peer of the same distro
find / -type f \( -perm -4000 -o -perm -2000 \) -printf '%p\n' 2>/dev/null | sort > /evidence/suid_now.txt
#   then: diff <(sort baseline_suid.txt) /evidence/suid_now.txt   # additions = suspects

# 2. SUID/SGID planted inside the incident window
find / -type f \( -perm -4000 -o -perm -2000 \) -newermt "2026-04-27 00:00:00" ! -newermt "2026-04-27 06:00:00" -ls 2>/dev/null

# 3. Only the DANGEROUS capabilities anywhere on disk
getcap -r / 2>/dev/null | grep -Ei 'setuid|setgid|dac_|sys_admin|sys_ptrace|sys_module|net_raw'

# 4. World-writable dirs that are MISSING the sticky bit (deletion/hijack risk)
find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null

# 5. Files with no valid owner or group (deleted-user or sloppy drop)
find / -xdev \( -nouser -o -nogroup \) -ls 2>/dev/null

# 6. Root-owned but group/other-writable (privesc: attacker edits root's file)
find / -xdev -user root -perm -0022 -type f ! -path '/proc/*' -ls 2>/dev/null

# 7. ctime newer than mtime across sensitive trees (timestomp)
find /etc /usr/bin /usr/sbin /tmp /home -type f -newerct '3 days ago' ! -newermt '3 days ago' -ls 2>/dev/null

# 8. Immutable/append-only across persistence-relevant trees
lsattr -R /etc /root /home /var/spool/cron /usr/lib/systemd 2>/dev/null | grep -E '^....i|^.....a'
```

**Hunt ideas:**

- **Baseline SUID/caps from a golden image** of the same distro/version; the delta *is* the finding — no guessing which SUID binaries are "normal."
- **Every immutable file is a question** — what is it protecting? Clear `+i` and inspect what it's armoring (a cron job? an `authorized_keys`?).
- **Stack the timestomp tells** — a file that is simultaneously `ctime > mtime`, zeroed-nanosecond, and newer than its parent dir's memory of it is a near-certain timestomp.
- **Orphaned (`-nouser`) files** frequently mark an account that was created then deleted (`userdel` cleanup) — pivot to auth logs for that account's lifetime.

## Getting Max Value

- **Preserve before you touch.** `stat` every suspect file and save all four timestamps first — opening/reading can update `atime` and destroy that evidence.
- **On a mounted image, use `debugfs` for the authoritative birth time** — ext4 hides `crtime` from a normal `stat`, but it's in the inode.
- **Keep the diff-vs-baseline and timestomp-window queries in your triage kit** — they turn a vague "check permissions" into a two-command answer.
- **Cross-check every hit against package ownership** (`dpkg -S`/`rpm -qf`): a SUID binary or capability on a file no package owns was placed by hand.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Was the SUID/capability actually *used* to escalate? | **Auditd** (`USER_CMD`, `uid≠0 euid=0`), **Process Trees** (10b) |
| Who owns the account behind the activity | **Users Groups and Authentication** (03) |
| What persistence an immutable file is protecting | **Persistence Mechanisms** (cron / systemd / ssh-keys / preload) |
| The file's real creation time / recover a deleted inode | **File Systems** (07), **Live Response** (10) |
| Build the tamper timeline | **Timelining** (13), **Anti-Forensics** (13b) |
| Verify a suspect binary against its package | **Package Managers and Integrity** (08) |
| A fileless `.so` mapped from `/dev/shm` | **Live Response** (10) |

## Scenarios

- **Post-exploit privesc:** unprivileged foothold → SUID/capability hunt reveals the root path taken.
- **Re-entry backdoor:** attacker leaves `cap_setuid+ep` on an odd binary to regain root later without a SUID alarm.
- **Armored persistence:** `rm` of a cron/systemd/`authorized_keys` file fails → `lsattr` shows `+i` → `chattr -i` then inspect.
- **Timestomp bust:** a dropped payload back-dated with `touch`; `ctime`/zeroed-nsec/parent-dir mtime betray the real time.
- **Stealth grant:** an ACL gives a service account read on `/etc/shadow` with no visible mode change.
- **Data hiding:** a `user.*` xattr holds a staged base64 blob or C2 URL.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| SUID shell/interpreter or extra SUID binary | Instant privilege escalation |
| `cap_setuid`/`cap_dac_*`/`cap_sys_admin`/`cap_sys_module` on odd binary | SUID-less privesc / rootkit-load backdoor |
| `+i` immutable on cron/systemd/authorized_keys/ld.so.preload | Armored persistence (won't `rm`) |
| `ctime` newer than `mtime`/`atime` | Timestomping |
| Zeroed-nanosecond timestamps among sub-second neighbours | Programmatic time-setting |
| ACL granting unexpected user access to `/etc/shadow` etc. | Hidden read/write grant |
| World-writable file in a system path, or world-writable dir w/o sticky | Tamper / hijack opportunity |
| `user.*` xattr holding base64/URL/blob | Data hiding |
| File owned by `nouser`/`nogroup` | Deleted-account artifact / sloppy drop |
| Root-owned file writable by group/other | Privesc via config/script edit |

## Resources

- GTFOBins — https://gtfobins.github.io (SUID / capability / sudo privesc reference)
- Red Hat — Linux file permissions explained: https://www.redhat.com/en/blog/linux-file-permissions-explained
- Red Hat — SUID, SGID, sticky bit: https://www.redhat.com/en/blog/suid-sgid-sticky-bit
- inversecos — Detecting Linux anti-forensics (timestomping): https://www.inversecos.com/2022/08/detecting-linux-anti-forensics.html
- Elastic — Timestomping detection rule (`touch`): https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/cross-platform/defense_evasion_timestomp_touch
- `stat(1)`, `lsattr(1)`, `chattr(1)`, `getcap(8)`, `getfacl(1)`, `getfattr(1)`, `capabilities(7)` man pages
- MITRE ATT&CK: T1548.001 (Setuid/Setgid), T1222.002 (Linux File Permission Modification), T1070.006 (Timestomp), T1564 (Hide Artifacts), T1027 (Obfuscated/hidden data)
