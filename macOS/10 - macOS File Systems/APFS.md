# APFS (Apple File System)

**APFS** is Apple's modern file system, introduced in **High Sierra (10.13, 2017)** and now the default on all SSD/flash Macs (and iOS/iPadOS/watchOS). It's built for flash: **Copy-on-Write (COW)**, a **container/volume** model with shared space, **native encryption**, **snapshots**, and **clones**. These features change forensics significantly — and are why **traditional acquisition workflows often fail** on APFS.

> 🔴 Two things to internalize: (1) **nanosecond UTC timestamps** make sloppy timestomping easy to spot; (2) APFS is usually **encrypted by default** (T2/Apple Silicon) and **TSK support is limited** — so cold/physical imaging frequently yields ciphertext or nothing. Plan a **live, logical, decrypted** acquisition. Snapshots are point-in-time gold.

## Contents
- [Quick Triage](#quick-triage)
- [History and Adoption](#history-and-adoption)
- [Container and Volume Layout](#container-and-volume-layout)
- [Copy-on-Write](#copy-on-write)
- [Snapshots](#snapshots)
- [Clones](#clones)
- [Native Encryption](#native-encryption)
- [Timestamps](#timestamps)
- [Why Traditional Acquisition Fails](#why-traditional-acquisition-fails)
- [Analysis Commands and Tools](#analysis-commands-and-tools)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
diskutil apfs list                                  # containers, volumes, roles, encryption state

diskutil apfs listSnapshots /                        # APFS snapshots (point-in-time copies)

tmutil listlocalsnapshots /                          # local Time Machine snapshots

diskutil apfs listCryptoUsers /                       # who can unlock (FileVault crypto users)

stat -f 'B=%SB m=%Sm c=%Sc a=%Sa %N' /path/file      # nanosecond MACB on a live volume
```

---

## History and Adoption

| Release | Milestone |
|---|---|
| High Sierra 10.13 (2017) | APFS default on **SSDs** |
| Mojave 10.14 | APFS default on **all** Macs (incl. Fusion) |
| Catalina 10.15 | **Read-only System volume** split (System + Data, firmlinks) |
| Big Sur 11 | **Signed System Volume (SSV)** — cryptographically sealed System volume; Time Machine moves to APFS |

🔴 If a Mac is from 2017+ and wasn't deliberately reformatted, assume **APFS** (often FileVault-encrypted).

---

## Container and Volume Layout

APFS inverts the old "one partition = one file system" model.

| Layer | What it is |
|---|---|
| **Partition (GPT)** | Holds one APFS **container** |
| 🔴 **Container** | Manages a pool of storage; the `synthesized` `diskXsY` |
| **Volumes** | Multiple volumes **share the container's free space** (no fixed sizes) |

Standard volume **roles** in the boot container:

| Volume | Role |
|---|---|
| `Macintosh HD` | **System** (read-only, sealed = SSV) |
| `Macintosh HD - Data` | 🔴 **Data** — user data, apps, most evidence |
| `Preboot` | Boot/FileVault unlock environment |
| `Recovery` | recoveryOS |
| `VM` | Swap / sleepimage |

> The System+Data split is joined by **firmlinks** so it looks like one tree at `/`. User evidence lives on the **Data** volume (`/System/Volumes/Data`). Cross-ref the Root Directory Structure note.

---

## Copy-on-Write

APFS **never overwrites a block in place** — a change writes a **new** block and updates pointers.

🔴 Forensic implications:
- **Old versions of data persist** in now-unreferenced blocks until reused → unallocated-space carving can recover prior content.
- But on **SSDs, TRIM** aggressively zeroes freed blocks → recovery window is short; **don't assume deleted = recoverable**.
- Metadata is also COW, so the file system is crash-consistent without a traditional journal.

---

## Snapshots

A snapshot is a **read-only, point-in-time** image of a volume, sharing blocks via COW (cheap). **Forensic gold** — a snapshot can hold files/states that were since changed or deleted.

```bash
# List snapshots on the boot volume
diskutil apfs listSnapshots /

tmutil listlocalsnapshots /                          # Time Machine local snapshots (com.apple.TimeMachine.*)

# Mount a snapshot read-only to browse it
mkdir /tmp/snap

mount_apfs -s com.apple.TimeMachine.2026-06-01-000000 /dev/diskXsY /tmp/snap
```

🔴 Local Time Machine snapshots are taken **hourly by default** and kept ~24h — they can resurrect deleted files, prior versions, and pre-tampering states. Always enumerate and preserve them.

---

## Clones

`cp -c` makes a **clone** — a COW copy that shares blocks until one side changes (instant, no extra space).

```bash
cp -c original copy            # clone (shares data blocks)
```

🔴 Two files can share the same underlying data with **separate metadata/timestamps** — don't assume identical content means a normal copy, and clone relationships can confuse "when was this created" reasoning.

---

## Native Encryption

APFS encryption is built in (per-volume, multi-key). **FileVault** is APFS encryption keyed to a Secure-Token user; on **T2/Apple Silicon** the media is hardware-encrypted regardless.

```bash
diskutil apfs list | grep -Ei 'encrypt|filevault|locked'

diskutil apfs listCryptoUsers /                      # Secure-Token unlock holders
```

🔴 An **unlocked** running Mac exposes plaintext; a **cold** image of an encrypted volume is ciphertext. Full key hierarchy, recovery keys, and the cold-vs-live decision are in the **FileVault** note — capture **live + unlocked**.

---

## Timestamps

APFS timestamps are **64-bit nanoseconds since 1970-01-01 (UTC)** — far more precise than HFS+'s 1-second.

| Timestamp | stat field |
|---|---|
| **Birth / Create** | `%SB` (crtime) |
| **Modified** | `%Sm` (mtime) |
| **Changed** (metadata/inode) | `%Sc` (ctime) |
| **Accessed** | `%Sa` (atime) — updated lazily; treat as approximate |

```bash
stat -f 'Birth: %SB%nModify: %Sm%nChange: %Sc%nAccess: %Sa%n' /path/file
```

🔴 Because resolution is **nanosecond**, real activity has noisy sub-second values. Timestamps that are **whole seconds (`.000000000`)**, identical across MACB, or where **create > modify** scream timestomping. A file with HFS+-style 1-second times on an APFS volume likely **came from another file system**.

---

## Why Traditional Acquisition Fails

🔴 The big one for this topic — classic "image the disk" workflows break on APFS:

| Obstacle | Effect |
|---|---|
| **Encryption by default** (FileVault / T2 / Apple Silicon) | A physical/cold image is **ciphertext** without the key |
| **Secure Enclave–bound keys** (T2 / Apple Silicon) | Keys **can't leave** the Mac → no chip-off; must acquire **on the original hardware** |
| **No Target Disk Mode chip pull** on Apple Silicon | Use **Mac Sharing Mode / DFU + Configurator**, with credentials |
| **Signed System Volume (SSV)** | System volume is sealed/read-only — image the **Data** volume for evidence |
| **Container/snapshot complexity** | One partition → many volumes + snapshots; pick the right volume & enumerate snapshots |
| **Limited TSK support** | Older TSK can't parse APFS; need APFS-aware tooling |

✅ Practical approach: **live, logical, decrypted** acquisition (or RAM + live triage) on the original machine while unlocked; enumerate and grab **snapshots**; document keys used. (See FileVault note for the decision tree.)

---

## Analysis Commands and Tools

```bash
# Live enumeration
diskutil apfs list

diskutil apfs listSnapshots /

diskutil list                                        # partition/container map

# Mount a decrypted image read-only (with the passphrase/recovery key)
diskutil apfs unlockVolume <diskXsY> -passphrase <pw>

# Mount a snapshot read-only
mount_apfs -s <snapshot_name> /dev/diskXsY /tmp/snap
```

| Tool | Use |
|---|---|
| `diskutil apfs` / `mount_apfs` | Native enumeration, unlock, snapshot mount |
| **apfs-fuse** (open source) | Mount/read APFS images on Linux/macOS for analysis |
| **TSK (newer builds)** | Some APFS pool support (`pstat`, APFS-aware `fls`) — verify version |
| Commercial (Cellebrite Inspector/BlackLight, Magnet AXIOM, Recon ITR, Elcomsoft) | Full APFS + FileVault decryption + snapshot parsing |

> 🔴 Verify your TSK actually supports APFS before relying on it; many older installs silently don't.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| MACB times in whole seconds (`.000000000`) on APFS | Timestomping (real APFS times are nanosecond) |
| `create` newer than `modify` | Faked timestamps |
| HFS+-style 1-second times on an APFS volume | File copied in from another file system |
| Unexpected/unknown **snapshots** | Could hold hidden or pre-tampering data (good) — or attacker staging |
| Snapshots **deleted** right before acquisition | Anti-forensics destroying point-in-time evidence |
| FileVault **disabled** recently | Pre-exfil decryption (cross-ref FileVault) |
| Clone (`cp -c`) relationships on suspicious files | Space-shared copies; rethink create/copy timeline |
| Encrypted volume + no available key at acquisition | Plan live/credentialed capture or it's ciphertext |

---

## Resources

- Apple File System Reference (Apple): https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
- apfs-fuse: https://github.com/sgan81/apfs-fuse
- The Sleuth Kit: https://www.sleuthkit.org/
