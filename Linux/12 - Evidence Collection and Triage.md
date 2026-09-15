# Evidence Collection and Triage

Good collection is what makes everything downstream possible — get the order wrong or contaminate the source and you can't undo it. The governing principle is *volatile before non-volatile*: RAM and `/proc` state evaporate on reboot, so they come first, then network/session state, then disk. This note covers the discipline (order of volatility, read-only on the source, hash everything), the tooling that automates it (UAC for triage), the manual core triage set, imaging, and how this scales from one host to a fleet — the bridge to enterprise-class IR.

> 🔴 Collect and scope *before* you eradicate, and capture the volatile tier *before* you image or reboot. The two most common irreversible mistakes are rebooting a host (destroying RAM, `/proc`, network state, and a volatile journal) and writing collected data to the subject's own disk (overwriting the unallocated space you might need to carve).

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Order and Principles](#order-and-principles)
- [Triage Collection with UAC](#triage-collection-with-uac)
- [The Core Triage Set](#the-core-triage-set)
- [Memory Acquisition](#memory-acquisition)
- [Disk Imaging](#disk-imaging)
- [Streaming an Image Off-Box](#streaming-an-image-off-box)
- [Cloud and VM Acquisition](#cloud-and-vm-acquisition)
- [Mounting Images Read-Only](#mounting-images-read-only)
- [Enterprise Scale](#enterprise-scale)
- [Chain of Custody](#chain-of-custody)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Automated artifact collection (broad, structured)
sudo ./uac -p ir_triage /evidence/

# Memory first if the host stays up (see Memory Forensics note)
sudo ./avml /evidence/mem.lime

# Hash everything you collect
find /evidence -type f -exec sha256sum {} \; > /evidence/hashes.txt
```

## What to Check for What

| Collection decision | Action |
|---------------------|--------|
| Host staying powered? | Acquire **RAM first** (AVML), then triage, then image |
| Cloud instance / VM? | Snapshot the disk (provider API) + guest RAM (hypervisor) |
| Can't write to the subject disk? | Stream the image off-box (`dd \| ssh`) |
| Full image impractical? | UAC `ir_triage` + targeted logical images |
| Many hosts? | Velociraptor / osquery fleet collection |
| Read an image safely? | `mount -o ro,loop,offset=…` |
| Prove nothing changed? | Hash at collection + re-verify on transfer |
| Anti-forensics present? | Capture log sizes / `lsattr` / timestamps *first* |

## Order and Principles

These principles aren't bureaucracy — each one prevents a specific, common, irreversible loss:

- **Volatile before non-volatile:** RAM → `/proc`/network/sessions → disk. Rebooting or imaging first destroys the volatile tier permanently.
- **Minimal footprint:** prefer statically-linked, trusted tools run from external media; avoid installing packages on the subject host (which writes to its disk and alters state).
- **Read-only on the source:** never write collected data back to the subject's disk; use mounted/external evidence storage.
- **Hash on collection** and record it; re-verify after transfer so you can prove nothing changed.
- **Note anti-forensics before touching:** capture the state (log sizes, immutable bits, timestamps) that a cleanup would alter — because your own actions can inadvertently change some of it.
- **Document commands + times:** this environment's live-response console runs as root/SYSTEM, so log every action for the record.

## Triage Collection with UAC

UAC (Unix-like Artifacts Collector) is the standard Linux/Unix triage tool — profile-driven, read-only, and it produces one structured, hashed archive that captures the whole triage set consistently. It's the fast path when you don't need to hand-pick artifacts.

```bash
# Full IR triage profile
sudo ./uac -p ir_triage /evidence/

# Everything (heavier)
sudo ./uac -p full /evidence/

# Against a mounted image instead of the live host
sudo ./uac -p ir_triage --mount-point /mnt/evidence /evidence/

# List available profiles/artifacts
./uac --list-profiles; ./uac --list-artifacts
```

UAC gathers logs, `/etc`, cron/systemd, shell histories, SSH artifacts, package DBs, `/proc` process state, and network state into one timestamped, hashed archive — the ideal input to the timelining stage.

## The Core Triage Set

If you're collecting manually (no UAC available), this is the minimum to preserve — all read-only. It's organized so nothing high-value is forgotten under pressure:

| Category | Paths / commands |
|----------|------------------|
| Logs | `/var/log/` (incl. rotated), journald (`journalctl -D`/copy `/var/log/journal`), `wtmp`/`btmp`/`lastlog`, `/var/log/audit/` |
| Config | `/etc/` (whole tree — cron, systemd, ssh, pam, sudoers, ld.so.preload) |
| Persistence | crontabs, systemd units/timers, `~/.ssh/`, autostart, udev rules |
| History | `/home/*/.*history`, `/root/.*history` |
| Live state | `ps auxww`, `ss -tunap`, `lsof`, `/proc/*/{cmdline,exe,maps,environ}`, `lsmod`, `mount` |
| Packages | `dpkg -l`/`rpm -qa`, `rpm -Va`/`debsums -c` output, `/var/log/apt` `/var/log/dnf.log` |
| Memory | full RAM image + `uname -r` |

```bash
# Example: snapshot volatile state to evidence files
ps auxww > /evidence/ps.txt

ss -tunap > /evidence/sockets.txt

lsmod > /evidence/lsmod.txt

for p in /proc/[0-9]*; do echo "== $p =="; cat "$p/cmdline" | tr '\0' ' '; echo; done > /evidence/proc_cmdlines.txt
```

## Memory Acquisition

Covered fully in the Memory Forensics note. In the collection flow: acquire RAM **first** if the host will stay powered, using AVML or LiME, write to external storage, hash, and record `uname -r`. This is the step you can never repeat once the host reboots.

## Disk Imaging

```bash
# Identify the target
lsblk -f; fdisk -l

# Raw image with progress (or dcfldd/dc3dd for built-in hashing)
sudo dd if=/dev/sda of=/evidence/sda.img bs=4M status=progress conv=noerror,sync

sudo dcfldd if=/dev/sda of=/evidence/sda.img hash=sha256 hashlog=/evidence/sda.hashes bs=4M

# EWF (E01) with metadata + compression
sudo ewfacquire /dev/sda

# Hash source and image, then compare
sudo sha256sum /dev/sda; sha256sum /evidence/sda.img
```

Use a **hardware write-blocker** (or a read-only mount) when imaging attached media. For a live system that can't be powered off, image the mounted logical volumes and lean on the memory capture plus the triage set — the volatile evidence often matters more than a perfect disk image anyway.

## Streaming an Image Off-Box

🔴 When you must image a live host but **can't write to its own disk** (no external storage attached, and writing locally would overwrite unallocated space), stream the image straight to a remote collector over the network — nothing lands on the subject disk.

```bash
# Pipe dd over SSH to a collector (compress in transit)
sudo dd if=/dev/sda bs=4M conv=noerror,sync | gzip -c | \
  ssh analyst@collector "cat > /evidence/$(hostname)-sda.img.gz"

# Or with netcat (collector: nc -l -p 9000 > sda.img)
sudo dd if=/dev/sda bs=4M conv=noerror,sync | nc collector 9000

# Hash the source and the received image, then compare
sudo sha256sum /dev/sda    # on the host; compare to the collector's hash of the file
```

Stream the UAC/triage archive the same way. Compute the hash on both ends and confirm they match.

## Cloud and VM Acquisition

🔴 In cloud and virtualized environments, the cleanest acquisition often isn't in-guest at all — snapshot from the platform, which is atomic and doesn't touch the guest's state.

| Platform | Disk | Memory |
|----------|------|--------|
| **AWS** | EBS snapshot (`aws ec2 create-snapshot`), then attach a copy to a forensics instance | SSM run-command → AVML, or memory-dump agent |
| **GCP** | `gcloud compute disks snapshot` | in-guest AVML via the ops agent |
| **Azure** | Managed-disk snapshot | in-guest AVML |
| **KVM/libvirt** | `virsh` disk snapshot / copy the qcow2 | `virsh dump --memory-only --live <dom>` |
| **VMware** | Copy the `.vmdk` | the `.vmem` file (guest RAM) from a snapshot |

```bash
# KVM guest RAM from the hypervisor (cleaner than in-guest AVML)
virsh dump <domain> /evidence/guest.mem --memory-only --live

# AWS: snapshot the volume, then work on a copy
aws ec2 create-snapshot --volume-id vol-0abc --description "IR $(date -u +%F)"
```

🔴 Snapshot from the **hypervisor/platform** for a consistent image without altering the guest; for RAM, a hypervisor `.vmem`/`virsh dump` beats in-guest AVML because it doesn't run code inside the compromised guest.

## Mounting Images Read-Only

```bash
# Find the partition offset (sectors * 512)
mmls /evidence/sda.img

# Read-only loop mount at the offset
sudo mount -o ro,loop,offset=$((512*227328)) /evidence/sda.img /mnt/evidence

# EWF image -> raw, then mount
ewfmount /evidence/sda.E01 /mnt/ewf

sudo mount -o ro,loop,offset=$((512*227328)) /mnt/ewf/ewf1 /mnt/evidence
```

Every artifact note's commands then run against `/mnt/evidence/...`. The `ro` flag is not optional — mounting evidence read-write can trigger a journal replay that alters the image.

## Enterprise Scale

One-host-at-a-time doesn't scale to a fleet, and this is where FOR608-class enterprise IR lives — fan the same triage set out across many endpoints and pull it back centrally:

- **Velociraptor** — hunt across the fleet with VQL artifacts; collect the identical triage set from hundreds of endpoints into one place.
- **osquery** — SQL-style live queries fleet-wide, with scheduled packs for persistence, processes, and sockets.
- **Config-management fan-out** (Ansible/Salt) — push a read-only collection script and gather results when no EDR is present.
- **EDR live-response console** — the model these notes assume: run read-only triage as root/SYSTEM on the endpoint remotely.

The workflow: scope IOCs (hashes, paths, IPs, keys, usernames) from the first host, then hunt those IOCs across the fleet to find every affected system before you close the case.

## Chain of Custody

- Record who collected what, when (UTC), from which host, with which tool/version.
- Hash at collection; store hashes separately; re-verify on transfer and before analysis.
- Keep originals immutable; work on copies.
- Preserve the acquisition log (commands + timestamps) — it's part of the evidence.

## Getting Max Value

- **Volatile-first, always** — RAM and `/proc` before any reboot or image; that step can't be repeated.
- **Never write to the subject disk** — stream off-box or use external evidence storage.
- **In cloud/VM, snapshot from the platform** (disk) + hypervisor (RAM) — cleaner and less invasive than in-guest tools.
- **UAC `ir_triage` gives a consistent hashed archive fast** — hand-pick artifacts only when you need something it misses.
- **Hash at collection, re-verify on transfer, keep originals immutable** — and preserve the acquisition log; it's evidence too.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Volatile-capture specifics | **Live Response** (10), **Memory Forensics** (11) |
| What to interpret from the collection | **Timelining** (13) + every artifact note |
| Fleet-scale IOC hunt | **IOC and YARA Scanning** (11d), **Enterprise** (16) |
| Container evidence collection | **Container → Container Evidence Collection** (C07) |
| Anti-forensics to note before touching | **Anti-Forensics and Evidence Destruction** (13b) |
| Reading images offline | **The Sleuth Kit**, **Filesystem Triage** (07) |

## Scenarios

- **Live host stays up:** RAM first (AVML), then UAC `ir_triage`, then image the logical volumes.
- **Cloud instance:** EBS/managed-disk snapshot + guest RAM via the hypervisor/agent — no reboot.
- **Can't power off / can't write locally:** stream `dd` off-box over SSH to a collector.
- **Fleet:** Velociraptor pushes the identical triage set to hundreds of endpoints and pulls it back centrally.
- **Spoliation risk:** hash at collection, keep originals immutable, preserve the acquisition log.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Host rebooted before RAM/volatile capture | Volatile evidence lost |
| Collected data written to the subject's own disk | Overwrites unallocated space / spoliation |
| Immutable (`+i`) evidence files | Cleanup lock — note before removing |
| Hash mismatch after transfer | Integrity failure — re-collect |
| Missing rotated logs / journal for the window | Retention or tampering gap |
| Imaged the guest in-place instead of snapshotting the VM | Altered guest state; less clean than a platform snapshot |

## Resources

- UAC (Unix-like Artifacts Collector) — https://github.com/tclahr/uac
- Velociraptor — https://docs.velociraptor.app ; osquery — https://osquery.io
- The Sleuth Kit (`mmls`, `ewfmount`) — https://sleuthkit.org
- `dd`/`dcfldd`/`dc3dd`, `ewfacquire`, `virsh(1)` man pages
- MITRE ATT&CK (defensive): data collection supports scoping across all techniques

