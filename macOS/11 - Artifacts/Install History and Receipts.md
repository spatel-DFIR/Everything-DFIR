# Install History and Receipts

macOS records **what software was installed, when, and which files it dropped** in a few durable places: package **receipts** (`.bom` + `.plist`), the **InstallHistory.plist**, and `install.log`. These reconstruct the software timeline — when a (possibly malicious) package landed, what it wrote to disk, and whether an app's files match what its installer claims.

> 🔴 The **`.bom`** (Bill of Materials) in each receipt lists **every file an installer placed** — so you can confirm what a package dropped (and spot files that *don't* belong to any receipt = manually planted). InstallHistory + install.log give the **timeline**.

## Contents
- [Quick Triage](#quick-triage)
- [Where Install Evidence Lives](#where-install-evidence-lives)
- [Package Receipts and BOM](#package-receipts-and-bom)
- [Install History Timeline](#install-history-timeline)
- [pkgutil](#pkgutil)
- [DFIR Uses](#dfir-uses)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Installed package receipts
ls -la /var/db/receipts/

# Install + update timeline (dates, names, sources)
system_profiler SPInstallHistoryDataType

# Recent install.log activity
tail -n 100 /var/log/install.log
```

---

## Where Install Evidence Lives

| Path | Holds |
|---|---|
| 🔴 `/var/db/receipts/<pkg-id>.bom` | **Bill of Materials** — every file the package installed |
| 🔴 `/var/db/receipts/<pkg-id>.plist` | Receipt metadata: install date, version, volume, pkg id |
| `/Library/Receipts/InstallHistory.plist` | 🔴 Chronological **install/update history** |
| `/Library/Receipts/` (legacy) | Older `.pkg` receipts (pre-modern) |
| `/var/log/install.log` | Detailed install/update **log** (long retention) |
| `/System/Library/Receipts/` | OS component receipts |

---

## Package Receipts and BOM

```bash
# List receipts
ls /var/db/receipts/

# Read the BOM — files an installer placed (-p f = file paths)
lsbom -p f /var/db/receipts/com.vendor.product.bom

# Full BOM (paths, modes, UID/GID, sizes)
lsbom /var/db/receipts/com.vendor.product.bom

# Receipt metadata (install date, version)
plutil -p /var/db/receipts/com.vendor.product.plist
```

🔴 Compare the **BOM file list** against what's actually on disk:
- Files **in the BOM but missing** → removed (anti-forensics?).
- App/binary files **not in any BOM** → installed by something other than a package (drag-install, script, manual drop — often malware).

---

## Install History Timeline

```bash
# Human-readable install/update timeline
system_profiler SPInstallHistoryDataType

# The raw plist (process/display name, date, package identifiers, source)
plutil -p /Library/Receipts/InstallHistory.plist
```

🔴 Each entry shows **name, date, version, and process/source** (e.g. "Installer", "softwareupdated", an MDM, or a 3rd-party updater). An install by an **unexpected process** or at an odd time is a lead.

---

## pkgutil

```bash
# All installed package IDs
pkgutil --pkgs

# Filter for a vendor / suspicious id
pkgutil --pkgs | grep -i vendor

# Info about a package (version, install time, location)
pkgutil --pkg-info com.vendor.product

# Files a package installed (from its receipt)
pkgutil --files com.vendor.product

# Verify / forget (forget only removes the receipt, not files)
pkgutil --files com.vendor.product --only-files
```

---

## DFIR Uses

| Goal | How |
|---|---|
| 🔴 When did software X arrive? | InstallHistory.plist / install.log timestamp |
| What files did a package drop? | `lsbom` / `pkgutil --files` |
| Was a payload package-installed or hand-dropped? | File present but **not in any BOM** = hand-dropped |
| Unexpected installer/source | InstallHistory "process" field (MDM, 3rd-party updater) |
| Tie a dropped LaunchDaemon to its installer | Match the plist path to a BOM (cross-ref Persistence) |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| App/binary **not in any receipt BOM** | Hand-dropped (no installer) — common for malware |
| Install at an **odd time** / by an unexpected process | Unauthorized software |
| InstallHistory entry from an unknown 3rd-party updater | Supply-chain / unwanted software |
| Receipt for a package whose files are **gone** | Installed then cleaned up |
| `install.log` showing a profile/MDM-pushed install | Managed deployment (or rogue MDM — cross-ref App-specific Logs) |
| Receipt id mimicking a known vendor (typo-squat) | Masquerade |

---

## Resources

- `man lsbom` · `man pkgutil` · `man installer`
- Cross-ref: Persistence (what was dropped), Unified Logs – Additional Topics (install.log)
