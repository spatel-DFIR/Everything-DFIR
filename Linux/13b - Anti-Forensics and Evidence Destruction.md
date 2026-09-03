# Anti-Forensics and Evidence Destruction

Competent attackers don't just break in — they work to make the intrusion invisible: clearing logs, disabling history, timestomping their files, wiping login records, hiding processes, and setting immutable bits so responders can't remove their persistence. This note consolidates the anti-forensic techniques scattered across the other notes into one hunting reference, organized by *what evidence they attack*, because recognizing the tampering is often how you find the intrusion — a gap, a zeroed file, or a disabled history is itself the lead.

> 🔴 Absence caused by tampering looks like innocence. A clean-looking host may be a well-cleaned one. The discipline is to treat every "nothing here" as a claim to verify: check whether the log *could* have recorded the event, whether history was disabled, whether timestamps were set programmatically, and whether the record was truncated — the tampering leaves its own fingerprints even when the original evidence is gone.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Log Clearing and Tampering](#log-clearing-and-tampering)
- [History Evasion](#history-evasion)
- [Timestomping](#timestomping)
- [Login Record Wiping](#login-record-wiping)
- [Immutable Persistence](#immutable-persistence)
- [Hiding Processes and Files](#hiding-processes-and-files)
- [Blinding Defenses](#blinding-defenses)
- [Secure Deletion](#secure-deletion)
- [Detection Strategy](#detection-strategy)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Zeroed / truncated logs and login records
find /var/log -type f \( -size 0 -o -size -10c \) -ls 2>/dev/null; ls -l /var/log/wtmp /var/log/btmp

# Journal integrity
journalctl --verify

# History disabled/redirected
grep -RIEn "HISTFILE=/dev/null|unset HISTFILE|HISTSIZE=0|set \+o history|ignorespace" /home /root /etc 2>/dev/null

# Immutable persistence (locked so it won't delete)
lsattr -R /etc /root /home 2>/dev/null | grep -E '^....i|^.....a'

# Timestomp tell: ctime newer than mtime
find /etc /usr/bin /tmp -type f -newerct '2 days ago' ! -newermt '2 days ago' -ls 2>/dev/null
```

## What to Check for What

| Tampering suspected | Fingerprint / command |
|---------------------|-----------------------|
| Logs cleared/edited? | zero-length; `journalctl --verify` fail; off-schedule mtime |
| History disabled? | `HISTFILE=/dev/null`/`ignorespace`; symlink to null; empty-but-active |
| File timestomped? | `ctime > mtime`; zeroed nanoseconds |
| Login records wiped? | zero `wtmp`/`btmp`; malformed `utmpdump` entries |
| Persistence armored? | `lsattr` `+i`/`+a` |
| Processes/files hidden? | `ld.so.preload`; kernel taint; `unhide`; static-tool diff |
| Defenses blinded? | `setenforce 0`; auditd `DAEMON_END`; rsyslog `discard` |
| Directory hidden by bind mount? | `/proc/mounts` bind entry not in `fstab` |
| Files securely wiped? | `shred`/`wipe`/`dd urandom` in history |

## Log Clearing and Tampering

Attackers clear or edit logs to remove the record of their activity. Each method leaves a different fingerprint (covered fully in the Logging Architecture note):

```bash
# Zero-length / truncated logs (: > file, truncate)
find /var/log -type f -size 0 -ls 2>/dev/null

# Log mtime off the rotation schedule (hand-edited with sed -i)
ls -l --time-style=full-iso /var/log/auth.log /var/log/syslog

# Sealed-journal tamper detection
journalctl --verify

# Logging service stopped during the incident (a deliberate gap)
journalctl -u rsyslog -u systemd-journald | grep -Ei "stopp|start"
```

🔴 A log that's zero-length, starts mid-history, has a mtime that doesn't match a rotation boundary, or fails `journalctl --verify` was tampered with. Check for a **remote syslog copy** (the Syslog note) — it often survives local clearing.

## History Evasion

Shell history is disabled or redirected to keep commands off the record (full treatment in the Shells note):

```bash
# The full set of history-evasion tricks
grep -RIEn "HISTFILE=/dev/null|unset HISTFILE|HISTSIZE=0|HISTFILESIZE=0|set \+o history|HISTCONTROL=ignorespace|HISTCONTROL=ignoreboth" /home /root /etc 2>/dev/null

# History symlinked to /dev/null
find /home /root -name ".bash_history" -type l -ls 2>/dev/null

# Empty history for an account that clearly logged in
find /home /root -name ".bash_history" -size 0 -ls 2>/dev/null
```

🔴 `HISTCONTROL=ignorespace` is the subtle one — the attacker space-prefixes commands and nothing records, while the file looks normal. If it's set, assume the visible history is incomplete and pivot to auditd, journald `_CMDLINE`, and `linux.bash` from memory.

## Timestomping

File times are set to old dates to sink dropped files below the timeline's noise floor (full treatment in the Permissions note):

```bash
# ctime newer than mtime/atime = touch-style timestomp (touch can't set ctime)
find /path -type f -newerct '2 days ago' ! -newermt '2 days ago' -ls 2>/dev/null

# Zeroed nanoseconds among sub-second neighbors (programmatic time-setting)
stat --printf='%n %y\n' /suspect/*

# Compare a file's time to its directory's mtime (dir remembers the real add)
stat -c '%n mtime=%y' /suspect/file; stat -c '%n dir_mtime=%y' /suspect/
```

🔴 `ctime` is the anchor: `touch` can forge `mtime`/`atime` but not `ctime`, so old content-times with a recent `ctime` is the classic timestomp. On ext4/XFS, `crtime` (birth) via `debugfs`/`statx` gives a second reference the attacker usually can't reach.

## Login Record Wiping

The binary login databases are wiped or edited to erase sessions (full treatment in the Auth and Login Records note):

```bash
# Zero-size or short wtmp/btmp
ls -l /var/log/wtmp /var/log/btmp; last -Fa | tail

# Malformed/edited records that 'last' renders cleanly
utmpdump /var/log/wtmp | tail -30

# A 'reboot' line inserted to explain a gap
last -Fx | grep -i reboot
```

Tools like `utmpdump` expose hand-edited records because they show the raw struct fields — zeroed or malformed entries that `last` would smooth over become visible.

## Immutable Persistence

Attackers set the immutable bit so responders' `rm` fails and their foothold survives naive cleanup (full treatment in the Permissions note):

```bash
# Find immutable/append-only files in persistence-heavy areas
lsattr -R /etc /root /home /var/spool/cron 2>/dev/null | grep -E '^....i|^.....a'

# Remove the bit before cleanup
chattr -i /path/to/locked/file
```

🔴 A "why won't this delete" moment on a cron file, systemd unit, or `authorized_keys` is the tell — `lsattr` it, and if `+i` is set, that's armored persistence you must `chattr -i` before removing.

## Hiding Processes and Files

Rootkits (userland `LD_PRELOAD` or kernel LKM) hide the attacker's processes, ports, and files from the standard tools. Detection is by cross-view inconsistency and memory — see the Rootkit Playbook and Rootkit Detection Tooling notes:

```bash
# Populated ld.so.preload / kernel taint (the two fast rootkit hints)
cat /etc/ld.so.preload 2>/dev/null; cat /proc/sys/kernel/tainted

# Hidden processes (automated)
unhide quick 2>/dev/null

# Hidden files: dot-prefixed and space/newline-named
find / -name ".*" -type f 2>/dev/null | grep -vE "/(\.bashrc|\.profile|\.ssh)"; find / -name "* *" 2>/dev/null | head
```

🔴 **Bind-mount hiding:** an attacker can mount an empty directory *over* a real one to conceal its contents from anyone browsing the path — the files still exist underneath. Diff live mounts against `fstab`:

```bash
# A bind/overlay mount present at runtime but not in fstab = a hiding trick
grep -E ' bind | overlay ' /proc/mounts

diff <(findmnt -rno TARGET 2>/dev/null | sort) <(awk '{print $2}' /etc/fstab 2>/dev/null | grep '^/' | sort)
```

## Blinding Defenses

Beyond destroying evidence, attackers **stop the recording** — disabling the security tooling so nothing is captured going forward. These leave their own bracketed gap.

```bash
# SELinux/AppArmor dropped to permissive (stops MAC logging + enforcement)
grep -i setenforce /var/log/audit/audit.log 2>/dev/null; ausearch -m MAC_STATUS -i 2>/dev/null

# auditd stopped / rules flushed (the execution log goes dark)
ausearch -m DAEMON_END,DAEMON_ABORT,CONFIG_CHANGE -i 2>/dev/null

# rsyslog discard/stop rules, or the shipper killed
grep -REn 'stop|discard|~' /etc/rsyslog.d/ 2>/dev/null; systemctl status rsyslog filebeat 2>/dev/null | grep -i active

# Kernel ring buffer cleared (dmesg -C wipes module-load / exploit traces)
grep -REn 'dmesg -C|dmesg --clear' /home/*/.*history /root/.*history 2>/dev/null

# EDR/monitoring agent stopped
systemctl list-units --state=inactive | grep -Ei 'falco|wazuh|auditd|osquery|splunk'
```

🔴 A `setenforce 0`, an auditd `DAEMON_END`, or a killed log-shipper followed by a stretch of silence is a **deliberate blind spot** — the bracket (when it stopped → when it resumed) is the window the attacker worked in. Treat that gap as *unknown*, and lean on any off-host copy.

## Secure Deletion

When attackers securely wipe files (rather than just `rm`), recovery is harder but the *act* still leaves traces.

```bash
# shred/wipe usage in history (the wiping itself is evidence of intent)
grep -REn "shred|wipe|srm|dd if=/dev/(zero|urandom)" /home/*/.*_history /root/.*_history 2>/dev/null

# BleachBit / cleanup tools installed or run
which bleachbit 2>/dev/null; grep -r bleachbit /var/log 2>/dev/null
```

🔴 `shred`, `wipe`, or `dd if=/dev/urandom of=<file>` in a shell history tells you the attacker deliberately destroyed a specific file — which both flags anti-forensic intent and tells you *what* they cared about erasing.

## Detection Strategy

Anti-forensics is a *meta*-signal: rather than finding the attacker's artifacts, you find the shape of their absence.

1. **Verify capability before concluding absence** — could this log/record even have captured the event? (auditd rules, journald storage, rotation window).
2. **Look for the fingerprints** — zeroed files, `--verify` failures, disabled history, `ctime`/`mtime` inversions, immutable bits, wiping tools in history.
3. **Fall back to sources the attacker missed** — remote syslog, auditd, memory (`linux.bash`), the filesystem journal, Btrfs snapshots, package integrity.
4. **Treat the tampering as a timeline event** — the moment a log was truncated or history disabled *is* an event you can often bound.

## Deep Threat Hunts

One-pass consolidated anti-forensics sweep. *(seasoned-DFIR; the tampering fingerprint IS the lead)*

```bash
# 1. Log clearing: zeroed/truncated + verify-fail + off-schedule mtime + service gap
find /var/log -type f \( -size 0 -o -size -10c \) -ls 2>/dev/null

journalctl --verify 2>&1 | grep -i fail; journalctl -u rsyslog -u systemd-journald | grep -Ei 'Stopp|Start'

# 2. History evasion (all tricks) + symlink-to-null + empty-for-active
grep -RIEn "HISTFILE=/dev/null|unset HISTFILE|HISTSIZE=0|ignorespace|set \+o history" /home /root /etc 2>/dev/null

find /home /root -name .bash_history \( -type l -o -size 0 \) -ls 2>/dev/null

# 3. Timestomp (ctime > mtime) across sensitive trees
find /etc /usr/bin /tmp /home -type f -newerct '3 days ago' ! -newermt '3 days ago' -ls 2>/dev/null

# 4. Login-record wiping (raw utmpdump exposes hand edits)
ls -l /var/log/wtmp /var/log/btmp; utmpdump /var/log/wtmp 2>/dev/null | tail

# 5. Immutable-armored persistence
lsattr -R /etc /root /home /var/spool/cron 2>/dev/null | grep -E '^....i|^.....a'

# 6. Rootkit hiding + bind-mount hiding
cat /etc/ld.so.preload 2>/dev/null; cat /proc/sys/kernel/tainted; unhide quick 2>/dev/null

grep -E ' bind | overlay ' /proc/mounts

# 7. Blinding: setenforce, auditd DAEMON_END, ring-buffer clear, agent killed
ausearch -m CONFIG_CHANGE,DAEMON_END,MAC_STATUS -i 2>/dev/null; grep -i setenforce /var/log/audit/audit.log 2>/dev/null

# 8. Deliberate wiping + intent in history
grep -REn 'shred|wipe|srm|dd if=/dev/(zero|urandom)|dmesg -C|history -c|journalctl --vacuum' /home/*/.*history /root/.*history 2>/dev/null
```

**Hunt ideas:**

- **The tampering fingerprint IS the lead** — a gap, a zeroed file, disabled history, or a `setenforce 0` points straight at when and where the attacker worked.
- **Every technique has a source it can't reach** — pivot to the ones the attacker missed (see Getting Max Value).
- **Time the tampering** — the moment a log was truncated / history disabled / `setenforce` ran is itself a bounded timeline event.
- **Bind-mount hiding conceals a directory's real contents** — diff `/proc/mounts` against `fstab`; the files exist under the mount.
- **Wiping tools in history tell you *what* they cared about erasing** — pivot to recover that specific artifact.

## Getting Max Value

- **Treat every "nothing here" as a claim to verify** — capability + retention + a tampering fingerprint before you write a non-finding.
- **Fall back to the sources the attacker missed:** remote syslog / SIEM, auditd, memory (`linux.bash`), the filesystem journal, **Btrfs/ZFS snapshots**, package integrity, `/proc`, and EDR telemetry.
- **Every tamper act is a timeline event** — bound it and fit it into the sequence.
- **Raw tools expose what smooth ones hide** — `utmpdump`, `journalctl --verify`, `lsattr`, a static `busybox`.
- **Cross-ref the dedicated note** for each technique's full treatment (they're linked per section).

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Log-clear detail + the off-host copy | **Logging Architecture** (06), **Syslog** (06) |
| History-evasion detail / memory recovery | **Shells** (04), **Memory Forensics** (11) |
| Timestomp detail | **Permissions** (02), **File Systems** (07) |
| Login-record wipe detail | **Authentication and Login Records** (06) |
| Immutable / armored persistence | **Permissions** (02) |
| Rootkit hiding confirmation | **Rootkit Detection** (11c), **Preload**, **LKM** |
| Recover wiped/deleted artifacts | **Trash and Deleted** (08), **File Systems** (07), **Memory** (11) |
| Fit tampering into the sequence | **Timelining** (13) |

## Scenarios

- **"Clean" host = well-cleaned one:** verify capability + hunt fingerprints before believing the absence.
- **Log wipe, SIEM save:** a remote-syslog/forwarder copy survives the local clearing.
- **History off, memory recovers it:** `linux.bash` pulls the commands from RAM.
- **Timestomp bust:** old `mtime`, recent `ctime` on a dropped file.
- **Armored persistence:** `+i` on a cron file so `rm` fails.
- **Blinding + gap:** a `setenforce 0`/`DAEMON_END` bracketing a silent stretch of activity.

## Red Flags

| Finding | Technique |
|---------|-----------|
| Zero-length/truncated logs, `journalctl --verify` fail | Log clearing/tampering |
| History disabled/redirected/empty for an active account | History evasion |
| `ctime` newer than `mtime`; zeroed nanoseconds | Timestomping |
| Zero-size `wtmp`/`btmp`; malformed `utmpdump` records | Login-record wiping |
| `+i` immutable on persistence files | Armored persistence |
| Populated `ld.so.preload` / kernel taint / hidden PIDs | Rootkit hiding |
| `shred`/`wipe`/`dd urandom` in history | Secure deletion (intent) |
| `setenforce 0` / auditd `DAEMON_END` / killed shipper + gap | Blinding defenses |
| Bind/overlay mount over a dir, not in `fstab` | Directory-hiding trick |
| `dmesg -C` / ring-buffer cleared | Kernel-trace wiping |

## Resources

- MITRE ATT&CK: T1070 (Indicator Removal) and sub-techniques, T1562 (Impair Defenses), T1564 (Hide Artifacts), T1222 (File Permissions Modification)
- `lsattr(1)`, `chattr(1)`, `utmpdump(1)`, `shred(1)` man pages
