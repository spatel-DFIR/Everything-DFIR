# Filesystem Triage and Identification

Before you analyze a filesystem you have to know what you're actually looking at, and on modern Linux that's rarely a single plain partition. Volumes are routinely layered — LVM on top of partitions, LUKS encryption under LVM, RAID under that, plus RAM-backed `tmpfs` and container `overlay` mounts that hold volatile-only evidence. Getting the layering wrong means imaging the wrong device or missing an encrypted volume entirely. This note is the orientation step: identify every filesystem and volume layer, understand the mount picture, and set expectations about which timestamps you can trust.

> 🔴 The `tmpfs` mounts (`/tmp`, `/dev/shm`, `/run/user/<uid>`) are RAM-backed — anything staged there is **live-only evidence** that vanishes on reboot, so collect it before imaging. And an unlocked LUKS volume is only readable while the host is live; once powered off, the passphrase/key requirement returns.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Identify Filesystems](#identify-filesystems)
- [Mounts and fstab](#mounts-and-fstab)
- [LVM](#lvm)
- [LUKS Encryption](#luks-encryption)
- [Software RAID](#software-raid)
- [tmpfs and overlayfs](#tmpfs-and-overlayfs)
- [Swap](#swap)
- [Timestamp Reality](#timestamp-reality)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Block devices with FS type, label, UUID, mountpoint
lsblk -f

# Filesystem type per mount
df -T

# What's mounted right now
mount | grep "^/dev"

# Identify a raw device's filesystem
file -sL /dev/sda1

blkid
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| What filesystem am I on (recovery strategy)? | `lsblk -f`; `blkid`; `file -sL /dev/sdX` |
| What's the full storage stack (image target)? | `lsblk`; `pvs/vgs/lvs`; `cat /proc/mdstat`; `cryptsetup isLuks` |
| Any hidden / attacker mount? | `cat /proc/mounts` vs `/etc/fstab`; `findmnt` |
| A file mounted as a filesystem (data hiding)? | `losetup -a` |
| Is `/tmp`/`/dev/shm` executable (noexec stripped)? | `mount \| grep -E ' /tmp \| /dev/shm ' \| grep -v noexec` |
| Encrypted volume I'll lose at shutdown? | `cryptsetup luksDump`; live `/dev/mapper/*` |
| Swap holding paged-out secrets? | `swapon --show`; `cat /proc/swaps` |
| Snapshots preserving pre-attack state? | `btrfs subvolume list /`; `zfs list -t snapshot` |
| Can I trust atime / find crtime? | `mount \| grep -E 'relatime\|noatime'`; `stat --printf='%w'` |

## Identify Filesystems

The filesystem type determines your entire analysis and recovery strategy — ext4 gives you deleted-file recovery, XFS essentially doesn't, Btrfs gives you snapshots. Identify it first.

```bash
# Type, label, UUID for every block device
blkid

lsblk -f

# Filesystem magic on a raw device (works even unmounted)
file -sL /dev/sda1

# Mounted filesystem types
df -T

cat /proc/filesystems
```

| Filesystem | Notes for DFIR |
|------------|----------------|
| ext4 | Default on Debian/Ubuntu; journal + crtime (via debugfs); best deleted-file recovery |
| XFS | Default on RHEL 7+; crtime present; **no practical undelete** — plan around it |
| Btrfs | Default on Fedora/openSUSE; CoW + snapshots (an evidence goldmine) |
| ZFS | Some appliances/servers; snapshots + `zpool history` |
| tmpfs | RAM-backed (`/tmp`, `/run`, `/dev/shm`) — volatile, lost on reboot |
| overlayfs | Container/live-image layering — the `upperdir` is the writable layer |

## Mounts and fstab

The mount picture is both practical (where the real data lives) and investigative (hiding tricks). `/proc/mounts` is live reality; `/etc/fstab` is intent; the difference between them is where the interesting anomalies hide.

```bash
# Live mounts (kernel truth)
cat /proc/mounts

# Configured mounts (intent)
cat /etc/fstab

# Bind mounts and unusual options
mount | grep -Ei "bind|nodev|noexec|nosuid"
```

🔴 A mount present at runtime but absent from `fstab` — a bind mount layered over a system directory to hide files, a `tmpfs` holding tools, an attacker-mounted external drive — is worth explaining. A bind mount over a directory can conceal whatever was originally there.

## LVM

The Logical Volume Manager sits between physical partitions and filesystems, so an image or a mount that ignores it will miss data. Enumerate the LVM stack and activate volumes from evidence disks explicitly.

```bash
# Physical volumes, volume groups, logical volumes
pvs

vgs

lvs

# Detailed map
lvdisplay

# Activate LVs from a mounted evidence disk
vgscan; vgchange -ay
```

## LUKS Encryption

Full-disk (or per-volume) encryption changes your acquisition plan entirely — a powered-off LUKS volume is unreadable without the key.

```bash
# Is a device LUKS-encrypted?
cryptsetup isLuks /dev/sda2 && echo LUKS

# Header info (cipher, key slots)
cryptsetup luksDump /dev/sda2

# Open (needs passphrase/key) -> maps to /dev/mapper/name
cryptsetup luksOpen /dev/sda2 evidence_crypt
```

🔴 On a live host, an unlocked LUKS volume is already mapped under `/dev/mapper/` and fully readable — capture it (or image the mapped device) *before* shutdown, or you lose access when the key requirement returns at next boot.

## Software RAID

```bash
# mdraid arrays
cat /proc/mdstat

mdadm --detail /dev/md0

# Assemble from evidence disks
mdadm --assemble --scan
```

If the data spans a RAID array, you must assemble it to read the logical volume — imaging a single member disk gives you only a fragment.

## tmpfs and overlayfs

```bash
# RAM-backed filesystems (volatile evidence)
mount | grep -E "tmpfs|ramfs"

df -T | grep tmpfs

# overlay mounts (containers / live systems) - shows lowerdir/upperdir
mount | grep overlay
```

🔴 `tmpfs` mounts hold live-only evidence — payloads staged in `/dev/shm` or `/tmp` (when tmpfs-backed) are gone after a reboot, so this is a "capture now" tier. `overlay` mounts bridge into the container world: the `upperdir` is a container's writable layer and records everything the container changed (see the Container section).

```bash
# overlay upperdir = the container's writable diff (everything it changed)
mount | grep overlay | grep -oE 'upperdir=[^,]+'
```

## Swap

🔴 Swap is the forgotten evidence tier: pages evicted from RAM — which can include **plaintext credentials, keys, and command fragments** — land in the swap device or file. It's acquirable like any block device, and worth grabbing on a live host before shutdown.

```bash
# Active swap (device or file, size, usage)
swapon --show

cat /proc/swaps

# A swap FILE (vs partition) is just a file you can copy for offline analysis
ls -l /swapfile /swap.img 2>/dev/null

# String-scrape a swap device for secrets (offline / with care)
strings -n 8 /dev/sdaN 2>/dev/null | grep -Ei 'password|BEGIN .*PRIVATE KEY|token'
```

## Timestamp Reality

This is the single biggest Linux timeline trap, so establish it before building any timeline. The two facts that bite people: atime is usually unreliable, and birth time isn't shown by default.

```bash
# Is atime reliable on this mount? relatime/noatime make it unreliable
mount | grep -Ei "relatime|noatime|atime"

# ext4 stores crtime but stat may not show it without statx/debugfs
stat --printf='birth: %w\n' /path/to/file
```

| Filesystem | mtime | atime | ctime | crtime (birth) |
|------------|-------|-------|-------|----------------|
| ext4 | yes | usually relatime | yes | yes (debugfs/statx) |
| XFS | yes | usually relatime | yes | yes |
| ext3 / older | yes | relatime | yes | **no** |
| Btrfs | yes | relatime | yes | yes |

🔴 Under `relatime` (the modern default) atime updates only occasionally, so "last accessed" tells you little; under `noatime` it's meaningless. And crtime, though present on ext4/XFS/Btrfs, needs `statx`/`debugfs`/TSK to read — plain `stat` and `ls` won't show it. Know both before you reason about "when was this file created/read."

## Deep Threat Hunts

Storage-layer hiding and acquisition-trap sweep. *(seasoned-DFIR)*

```bash
# 1. Loop devices — a FILE mounted as a filesystem (classic data hiding)
losetup -a

# 2. Device-mapper tree (LUKS/LVM live mappings you must image at the logical layer)
dmsetup ls --tree 2>/dev/null

# 3. Full partition tables + any extra/hidden partition
parted -l 2>/dev/null

fdisk -l 2>/dev/null

# 4. /tmp, /dev/shm, /var/tmp mounted WITHOUT noexec (payloads can execute there)
mount | grep -E ' /tmp | /dev/shm | /var/tmp ' | grep -v noexec

# 5. Container overlay upperdirs = where container changes live
mount | grep overlay | grep -oE 'upperdir=[^,]+'

# 6. ZFS pool history — a built-in audit log of every pool operation
zpool history 2>/dev/null

zfs list -t snapshot 2>/dev/null

# 7. Btrfs snapshots (pre-attack state goldmine, or an attacker cleanup target)
btrfs subvolume list / 2>/dev/null

# 8. Large files that could be a hidden filesystem image
find / -xdev -type f -size +100M 2>/dev/null | xargs -r file 2>/dev/null | grep -Ei 'filesystem|boot sector|LUKS|partition'

# 9. Clean mount tree + hidden-mount check
findmnt 2>/dev/null

diff <(findmnt -rno TARGET 2>/dev/null | sort) <(awk '{print $2}' /etc/fstab | grep '^/' | sort)
```

**Hunt ideas:**

- **A file mounted via loop (`losetup -a`) is a classic hide** — inspect the backing file; it can hold a whole hidden filesystem.
- **`/tmp` or `/dev/shm` mounted without `noexec`** means payloads run there; a remount stripping `noexec` is a real TTP — check the option, not just the path.
- **Swap is often skipped** — it can hold plaintext creds/keys paged out of memory; acquire the swap device/file.
- **Btrfs/ZFS snapshots cut both ways** — a goldmine of pre-attack state, or a target the attacker deleted. Enumerate and preserve them.
- **`zpool history` is a free audit log** — every `zpool`/`zfs` operation, timestamped.

## Getting Max Value

- **Establish the full stack before imaging:** partitions → RAID → LVM → LUKS → filesystem. Image the *logical* (assembled/opened) device, never a raw member or a still-encrypted volume.
- **Capture live-only tiers first:** `tmpfs` contents, the unlocked LUKS `/dev/mapper/` device, and **swap** — all vanish or re-lock at shutdown.
- **Grab the free timelines:** `zpool history` and Btrfs/ZFS snapshots are rollback points and operation logs you get for nothing.
- **Record the timestamp caveats up front** (atime `relatime`, crtime hidden) so the timeline note interprets them correctly.
- **Use `findmnt`/`lsblk -f` for a clean tree**, and always diff `/proc/mounts` against `/etc/fstab` for hidden mounts.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Deleted-file recovery (this is ext4) | **ext4** |
| Why XFS won't undelete / carve instead | **XFS** |
| Snapshot analysis for pre-attack state | **Btrfs** |
| Inode/block/timeline extraction from an image | **The Sleuth Kit** |
| Timestamp interpretation for the timeline | **Timelining** (13), **Permissions** (02) |
| overlay `upperdir` → container investigation | **Container** notes |
| What's staged live in `tmpfs` | **Live Response** (10), **Temp and Staging** (08) |

## Scenarios

- **Missed encrypted volume:** LUKS not opened before shutdown → the data is unreadable when the key requirement returns.
- **Wrong image target:** imaged a RAID member or PV instead of the assembled logical volume → only a fragment.
- **Hidden loopback filesystem:** an attacker's file mounted via `losetup` conceals a data store.
- **`/tmp` remounted exec:** `noexec` stripped so dropped payloads can run.
- **Snapshot goldmine/target:** a Btrfs/ZFS snapshot holds pre-attack state — or was deleted to destroy it.
- **Swap creds:** paged-out passwords/keys recovered by scraping the swap device.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Runtime mount not in `/etc/fstab` | Hidden data store / attacker mount |
| Bind mount over a system directory | Directory-hiding trick |
| Unexpected `tmpfs` holding executables | Volatile staging |
| `overlay` mounts on a "non-container" host | Containers you didn't expect |
| atime relied on while `relatime`/`noatime` is set | Timeline based on bad data |
| Unlocked LUKS volume on a host about to be powered off | Losing access to the evidence |
| `losetup -a` shows a file mounted as a filesystem | Hidden data store |
| `/tmp`/`/dev/shm` mounted without `noexec` | Payload execution enabled |
| Swap present but not acquired | Missed plaintext creds/keys |
| Btrfs/ZFS snapshots recently deleted | Anti-forensics against rollback state |

## Resources

- `lsblk(8)`, `blkid(8)`, `cryptsetup(8)`, `lvm(8)`, `mdadm(8)`, `losetup(8)`, `findmnt(8)`, `swapon(8)`, `dmsetup(8)` man pages
- MITRE ATT&CK: T1564 (Hide Artifacts), T1564.005 (Hidden File System), T1222.002 (Linux File Permission Modification), T1006 (Direct Volume Access)
