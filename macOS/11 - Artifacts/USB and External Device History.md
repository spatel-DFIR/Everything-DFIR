# USB and External Device History

Reconstructing which **USB / external devices** were attached to a Mac — and when — supports **data-exfiltration** cases and device attribution (serial numbers, vendor/product). Unlike Windows (with its rich `USBSTOR`/registry history), macOS has **no single device-history registry**, so you reconstruct it from **Unified Logs**, **live IORegistry**, and the **artifacts each volume leaves behind** when a Mac mounts it.

> 🔴 Be realistic: macOS USB history is **fragmented and partly volatile**. `system_profiler`/`ioreg` show only **currently** attached devices; Unified Logs (`IOUSB`) capture attaches but **roll** in days; the durable record is the **on-media artifacts** (`.fseventsd`, `.DS_Store`, `.Trashes`, `._*`) the Mac wrote to the device. Combine all three.

## Contents
- [Quick Triage](#quick-triage)
- [Live Device State](#live-device-state)
- [Attach Events in Unified Logs](#attach-events-in-unified-logs)
- [Mount History](#mount-history)
- [On-Media Artifacts](#on-media-artifacts)
- [What You Can and Cannot Get](#what-you-can-and-cannot-get)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Currently attached USB devices (vendor/product/serial)
system_profiler SPUSBDataType

# USB attach/detach events in the log (rolls — collect early)
log show --predicate 'eventMessage CONTAINS[c] "USBMSC" OR eventMessage CONTAINS[c] "IOUSB" OR eventMessage CONTAINS[c] "USB"' --last 7d

# Storage / Thunderbolt too
system_profiler SPStorageDataType SPThunderboltDataType
```

---

## Live Device State

```bash
# Full USB tree with serial numbers (live only — currently connected)
system_profiler SPUSBDataType

# IORegistry view (vendor/product IDs, serials, location)
ioreg -p IOUSB -l -w 0

ioreg -c IOUSBHostDevice -l -w 0 | grep -iE 'USB Product Name|USB Vendor Name|USB Serial Number|idVendor|idProduct'
```

🔴 Captures **serial number**, **vendor/product names + IDs**, and speed — gold for **attributing a specific device**. Limitation: only **currently attached** devices appear; capture this **before** unplugging.

---

## Attach Events in Unified Logs

```bash
# USB mass-storage attach/detach
log show --predicate 'eventMessage CONTAINS[c] "USBMSC" OR eventMessage CONTAINS[c] "AppleUSB"' --info --last 7d

# Disk Arbitration: volume mount/unmount (any external)
log show --predicate 'process == "diskarbitrationd" OR eventMessage CONTAINS[c] "mounted"' --info --last 7d

# Stream live while plugging a device (to learn its signatures)
log stream --predicate 'eventMessage CONTAINS[c] "USB"' --info
```

🔴 Log entries give **attach times** + device descriptors — but the buffer holds only **days–weeks**, so collect early (cross-ref Unified Logs Collection). Times here pair with on-media `.fseventsd` to bound when files moved.

---

## Mount History

```bash
# Currently mounted volumes
mount

diskutil list

# Disk Arbitration prefs / fstab (persisted mount config, not full history)
cat /etc/fstab 2>/dev/null

# Per-volume identity helps tie an external drive across mounts
diskutil info /Volumes/USB | grep -iE 'UUID|Name|Type'
```

> macOS doesn't keep a complete historical mount table — reconstruct mounts from **logs** (above) + the **volume UUID** seen in `.fseventsd/fseventsd-uuid` on the media itself.

---

## On-Media Artifacts

🔴 The most **durable** evidence a device was used on a Mac lives **on the device**:

| Artifact (on the external volume) | Proves |
|---|---|
| `/.fseventsd/` | File create/delete/copy **history on the device** (cross-ref FSEvents) |
| `.DS_Store` | Folders browsed in Finder + item names (cross-ref .DS_Store) |
| `.Trashes/<UID>/` | What a user **deleted** on the device + UID (cross-ref Trash) |
| `._*` (AppleDouble) | Mac xattrs/quarantine on copied files (cross-ref exFAT) |
| `.Spotlight-V100/` | Indexing attempt |

```bash
ls -laO /Volumes/USB

find /Volumes/USB -maxdepth 2 \( -name '.fseventsd' -o -name '.DS_Store' -o -name '.Trashes' -o -name '._*' \) 2>/dev/null
```

> These survive after the device is removed from the Mac — and reveal **what files moved** even when the Unified Log has rolled.

---

## What You Can and Cannot Get

| Want | macOS reality |
|---|---|
| Currently-attached device + serial | ✅ `system_profiler`/`ioreg` (live only) |
| Historical attach times | ⚠️ Unified Logs (rolling) / sysdiagnose |
| Full historical device list (USBSTOR-style) | ❌ No single registry — reconstruct |
| What files moved to/from a device | ✅ On-media `.fseventsd`/`.DS_Store`/`.Trashes` |
| Device used on *this* Mac vs elsewhere | ⚠️ Correlate volume UUID + Mac logs + on-media artifacts |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| External volume `.fseventsd` full of recent writes | **Data exfil** to removable media (T1052.001) |
| `.Trashes/<UID>/` with user content on a USB | Files deleted on the device — recover + attribute |
| USB attach in logs around an incident time | Device present during the activity |
| Unknown device serial in `ioreg` | Unauthorized device |
| `.DS_Store`/`._*` on a drive that "was never used on a Mac" | A Mac browsed/wrote it |
| Large files written to external near data-staging events | Staged exfil |

---

## Resources

- `man system_profiler` · `man ioreg` · `man diskutil`
- Cross-ref: FSEvents, .DS_Store, Trash, exFAT, Unified Logs (USB/IOUSB)
