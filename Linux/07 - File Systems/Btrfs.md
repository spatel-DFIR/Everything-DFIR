# Btrfs

Btrfs is the default on Fedora and openSUSE and increasingly common elsewhere. It's copy-on-write with first-class subvolumes and **snapshots**, and those snapshots are the headline for DFIR: many distros auto-snapshot before every package transaction (Snapper/`timeshift`), so a **pre-compromise copy of the system may already exist on disk**. That cuts both ways — a snapshot can hand you the attacker's exact change set, and a Btrfs-aware attacker may delete snapshots to destroy that evidence.

> 🔴 Check for snapshots first, before any recovery effort. `btrfs subvolume list -s /` and the Snapper/timeshift store (`/.snapshots/`) may contain a clean, mountable copy of the system from just before the incident — mount it read-only and diff it against the live subvolume to isolate exactly what changed.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Structure and Copy-on-Write](#structure-and-copy-on-write)
- [Subvolumes and Snapshots](#subvolumes-and-snapshots)
- [Metadata and Inode Analysis](#metadata-and-inode-analysis)
- [Timestamps](#timestamps)
- [Recovery](#recovery)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Filesystem + devices
sudo btrfs filesystem show

# All subvolumes (snapshots included)
sudo btrfs subvolume list /

# Snapshots may hold pre-attack copies of files - list and mount read-only
sudo btrfs subvolume list -s /

# Usage / device layout
sudo btrfs filesystem df /
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Is there a pre-incident copy of the system? | `btrfs subvolume list -s /`; `snapper list`; `ls /.snapshots/` |
| What exactly did the attacker change? | mount a pre-incident snapshot ro, `diff -rq` vs live |
| Precise per-file change set since a snapshot? | `snapper status <n>..0`; `snapper diff <n>..0` |
| Everything changed since a generation? | `btrfs subvolume find-new / 0` |
| Did the attacker delete snapshots? | sequential ID gaps in `snapper list`; `btrfs subvolume list -d` |
| Whole-subvolume exfil? | `btrfs send` in history/audit |
| Hidden data store? | rogue read-write subvolume (`btrfs subvolume list /`) |
| Recover overwritten data (CoW)? | `btrfs restore -l` (list roots) then restore a prior root |
| Is a file timestomped? | `stat`/inode `ctime` vs `mtime`; `otime` = birth |

## Structure and Copy-on-Write

Btrfs is copy-on-write: modifying a file writes *new* blocks rather than overwriting the old ones, until the old blocks are freed. Everything — data and metadata — lives in B-trees. This CoW design is why snapshots are cheap (they just share blocks) and why recently-overwritten data can linger longer than on an overwrite-in-place filesystem.

```bash
# Devices in the filesystem
sudo btrfs filesystem show

# Detailed tree/usage
sudo btrfs filesystem usage /

# Check for errors / scrub status (may reveal tampering or corruption)
sudo btrfs scrub status /
```

## Subvolumes and Snapshots

🔴 This is the single most valuable Btrfs feature for DFIR. A snapshot is a point-in-time (read-only or read-write) copy of a subvolume, and because distros snapshot automatically around updates, a system frequently carries copies of itself from before an incident.

```bash
# List every subvolume with IDs and paths
sudo btrfs subvolume list /

# List only snapshots
sudo btrfs subvolume list -s /

# Snapper-managed snapshots (openSUSE / Fedora)
snapper list

ls -la /.snapshots/

# Mount a specific subvolume/snapshot read-only for comparison
sudo mount -o ro,subvolid=<ID> /dev/sda2 /mnt/snap

# Diff a snapshot against current state to see what changed
sudo btrfs subvolume find-new <subvol> <generation>
```

**The workflow:** find a snapshot dated before the incident, mount it read-only, and diff it against the live subvolume — the delta *is* the attacker's change set (added binaries, modified configs, planted persistence), isolated cleanly without guesswork.

🔴 A Btrfs-aware attacker may **delete snapshots** to erase this evidence. Compare the `btrfs subvolume list -s` output against the Snapper/timeshift schedule — a gap where auto-snapshots should exist is itself a finding.

## Metadata and Inode Analysis

```bash
# Inspect internal metadata (advanced, read-only)
sudo btrfs inspect-internal dump-tree -t 5 /dev/sda2 | less   # FS tree

# Resolve inode -> path within a subvolume
sudo btrfs inspect-internal inode-resolve <inode> /mnt/point

# Logical-to-physical mapping
sudo btrfs inspect-internal logical-resolve <logical> /mnt/point
```

## Timestamps

Btrfs stores atime, mtime, ctime, and otime (creation), each with nanosecond precision. The `relatime`/`noatime` caveat and the `ctime`-can't-be-`touch`ed timestomp tell both apply exactly as on ext4/XFS.

```bash
stat --printf='%n born:%w mod:%y chg:%z\n' file
```

## Recovery

```bash
# Recover files from a damaged/target filesystem (offline)
sudo btrfs restore /dev/sda2 /recovery/output

# Roll back the FS tree to a previous root (recovery scenarios)
sudo btrfs restore -l /dev/sda2         # list roots first

# Given CoW, old data blocks may persist -> carving still applies
photorec disk.img
```

🔴 The strongest recovery lever on Btrfs is almost always a **snapshot**, not block carving — check for one first. Failing that, CoW means older versions of overwritten data may still be present, so `btrfs restore` against a prior root or signature carving can succeed where an overwrite-in-place filesystem would have lost the data.

## Deep Threat Hunts

Btrfs's snapshot machinery gives the cleanest change-set in Linux DFIR — and is itself an anti-forensics target. *(seasoned-DFIR)*

```bash
# 1. THE move: diff a pre-incident snapshot against live = the attacker's exact change set
btrfs subvolume list -s /

mount -o ro,subvolid=<ID> /dev/sda2 /mnt/snap

diff -rq /mnt/snap / 2>/dev/null

# 2. Precise per-file changes since a Snapper snapshot
snapper list

snapper status 40..0

snapper diff 40..0

# 3. Everything changed since a generation (full, bounded change list)
btrfs subvolume find-new / 0 2>/dev/null | awk '{print $NF}' | sort -u

# 4. Deleted-snapshot detection: sequential ID gaps = evidence removed
snapper list | awk 'NR>3{print $1}'

btrfs subvolume list -d /

# 5. Whole-subvolume exfil via btrfs send
grep -R "btrfs send" /root/.bash_history /home/*/.bash_history 2>/dev/null

ausearch -x /usr/bin/btrfs -i 2>/dev/null

# 6. Rogue read-write subvolume in an odd place (hidden store)
btrfs subvolume list / | grep -viE '@|@home|@snapshots|@var|@root'

# 7. CoW old-block recovery via a prior root
btrfs restore -l /dev/sda2

btrfs restore -r <root> /dev/sda2 /recovery/output

# 8. Integrity / tamper check
btrfs check --readonly /dev/sda2 2>/dev/null
```

**Hunt ideas:**

- **The snapshot diff is the cleanest change-set in Linux DFIR** — a pre-incident Snapper/timeshift snapshot vs live gives you *exactly* what the attacker added or modified, with no guessing.
- **Snapshot ID gaps = deleted snapshots.** Snapper numbers sequentially; a missing number where the schedule should have made one is anti-forensics.
- **`btrfs subvolume find-new <sv> 0`** yields a complete, generation-bounded "everything that changed" list — excellent for scoping.
- **`btrfs send` in history/audit** = whole-subvolume theft (a Btrfs-native exfil primitive).
- **CoW means overwritten data lingers** — `btrfs restore` against a prior root recovers it where an overwrite-in-place filesystem would have lost it.

## Getting Max Value

- **Check snapshots first** — a pre-incident copy beats any block recovery. Mount read-only, `diff`, done.
- **Preserve snapshots before they roll off** — Snapper auto-prunes; copy `/.snapshots` or `btrfs send` them to evidence storage.
- **Use `snapper diff`/`status` for precise per-file change sets**; `find-new` for a generation-bounded list.
- **Prefer native `btrfs restore` over raw carving** — it handles compressed (zstd/lzo) extents that signature carvers miss.
- **Watch for deleted-snapshot gaps and rogue rw subvolumes** — both are Btrfs-specific attacker moves.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| What the change-set means (persistence added) | **Persistence Mechanisms** |
| The package transaction that triggered an auto-snapshot | **Package Managers and Integrity** (08) |
| Timeline the changed files | **Timelining** (13) |
| Timestamp / timestomp interpretation | **File and Directory Permissions** (02) |
| Subvolume exfil via `btrfs send` over the network | **Network and PCAP Forensics** (10c) |
| Confirm it's Btrfs / device layout | **Filesystem Triage and Identification** |
| Deleted-snapshot anti-forensics context | **Anti-Forensics and Evidence Destruction** (13b) |

## Scenarios

- **Change-set goldmine:** a pre-incident snapshot diffed against live reveals exactly what the attacker changed.
- **Deleted-snapshot anti-forensics:** sequential ID gaps where auto-snapshots should exist.
- **Rogue subvolume:** a hidden read-write subvolume used as a data store.
- **Subvolume exfil:** `btrfs send` of a whole subvolume off the host.
- **CoW recovery:** a prior-root `btrfs restore` recovers overwritten data the FS "lost."

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Expected auto-snapshots missing | Attacker deleted evidence |
| Snapshot diff shows added/modified system files | Precise change set of the intrusion |
| `ctime` newer than `mtime` | Timestomping |
| New read-write subvolume in an odd location | Hidden data store |
| scrub errors after incident | Possible tampering/corruption |
| Sequential gap in Snapper snapshot IDs | Snapshots deleted (anti-forensics) |
| `btrfs send` in history / audit | Whole-subvolume exfil |

## Resources

- Btrfs documentation and `btrfs-*` man pages — https://btrfs.readthedocs.io
- Snapper — https://snapper.io
- MITRE ATT&CK: T1070 (Indicator Removal — snapshot deletion), T1070.006 (Timestomp), T1560 (Archive/Collect — `btrfs send`), T1485 (Data Destruction)
