# Fuji

**Fuji** (Forensic Unattended Juicy Imaging) is a **free, open-source** tool for **live, logical acquisition** on macOS — it captures the existing files and produces a **compressed DMG** disk image. It's a practical answer to the "can't physically image an encrypted/Apple-Silicon Mac" problem: run it on the **live, unlocked** system and collect a logical image you can analyze later.

> 🔴 Two operational facts: (1) Fuji is **not code-signed or notarized**, so Gatekeeper blocks it — strip quarantine with `xattr` (after verifying the hash); (2) it outputs a **compressed** DMG, which some tools (e.g. mac_apt release) can't read — convert to **uncompressed DMG** or **sparseimage** with `hdiutil`.

## Contents
- [Quick Triage](#quick-triage)
- [What Fuji Does](#what-fuji-does)
- [Running Fuji Past Gatekeeper](#running-fuji-past-gatekeeper)
- [Acquisition Methods](#acquisition-methods)
- [Live Acquisition Workflow](#live-acquisition-workflow)
- [Converting the Output Image](#converting-the-output-image)
- [Pitfalls and Chain of Custody](#pitfalls-and-chain-of-custody)
- [Resources](#resources)

---

## Quick Triage

```bash
# 1) Verify the download hash, THEN remove Gatekeeper quarantine
shasum -a 256 /path/to/Fuji.dmg

xattr -d com.apple.quarantine /path/to/Fuji.dmg

# 2) Run Fuji (GUI app) from your acquisition volume, image to external evidence media

# 3) If a tool needs uncompressed/sparse, convert the compressed DMG
hdiutil convert /path/to/image.dmg -format UDRO -o /path/to/image_uncompressed.dmg
```

---

## What Fuji Does

- **Live, logical** acquisition — copies the **existing files** from a running, unlocked Mac (it does **not** do a physical/bit-for-bit image).
- Produces a **compressed DMG** of the collected data.
- Free and open-source (by Lazza) — the go-to when full-disk physical imaging isn't possible (FileVault, T2/Apple Silicon, Secure Enclave-bound keys).
- Advanced: the **Fuji Cartridge** supports **recovery-mode** acquisitions (boot to recoveryOS and acquire from there).

---

## Running Fuji Past Gatekeeper

Fuji is **neither code-signed nor notarized** (two different things — signing proves developer identity; notarization means Apple scanned it for malware). Gatekeeper blocks it by default. Two options:

```bash
# Recommended: strip the quarantine xattr that macOS put on the download
xattr -d com.apple.quarantine /path/to/Fuji.dmg
```

- **System Settings method:** after the block prompt, go to **System Settings → Privacy & Security → "Open Anyway."**
- **xattr method (recommended):** remove `com.apple.quarantine` *before* copying Fuji to the acquisition volume.

> 🔴 Common with open-source forensic tools. Fuji is well-known and trusted — but **always verify the download hash** before removing quarantine and running any tool.

---

## Acquisition Methods

| Method | Use |
|---|---|
| 🔴 Live logical (default) | Capture files from the running, unlocked system → compressed DMG |
| Custom path selection | Acquire specific directories/volumes |
| **Fuji Cartridge** (recovery mode) | Acquire from **recoveryOS** for a cleaner, less-running-system capture |

> Live + unlocked is the realistic path on modern encrypted Macs — once the volume is decrypted in memory, Fuji can read the files (FileVault only protects data at rest).

---

## Live Acquisition Workflow

1. **Verify** Fuji's download hash; document it.
2. **Remove quarantine**: `xattr -d com.apple.quarantine /path/to/Fuji.dmg`.
3. Copy Fuji to your **acquisition volume** (external), not the subject disk.
4. Attach a **destination** evidence volume with enough space.
5. Launch Fuji on the **live, unlocked** Mac; choose method/scope and destination.
6. Run the acquisition → **compressed DMG** on the evidence volume.
7. **Hash** the output; record collector/time/host (chain of custody).
8. Convert the image if your analysis tool needs uncompressed/sparse (below).

---

## Converting the Output Image

Fuji produces **compressed** DMGs; convert with the built-in `hdiutil`:

```bash
# Compressed DMG -> uncompressed (UDRO, read-only)
hdiutil convert /path/to/image.dmg -format UDRO -o /path/to/image_uncompressed.dmg

# Compressed DMG -> sparseimage (UDSP)
hdiutil convert /path/to/image.dmg -format UDSP -o /path/to/image.sparseimage
```

> Conversion can take several minutes depending on image size. Use **uncompressed** or **sparseimage** when a tool (e.g. the **mac_apt** release build) can't read compressed DMGs (`-x DMG` vs `-x SPARSE`).

---

## Pitfalls and Chain of Custody

| 🔴 Pitfall | Avoid by |
|---|---|
| Running an **unverified** tool after stripping quarantine | Verify the SHA-256 first |
| Imaging to the **subject** disk | Always write to external evidence media |
| Expecting a physical image | Fuji is **logical** — unallocated/deleted data not captured |
| Subject is **locked/encrypted** | Acquire **live + unlocked** (decrypted in memory) |
| Compressed DMG rejected by a tool | Convert with `hdiutil` (UDRO / UDSP) |
| No integrity record | Hash output + document collector/time/host/macOS version |

---

## Resources

- Fuji: Forensic Unattended Juicy Imaging (releases): https://github.com/Lazza/Fuji/releases/latest
- Fuji Documentation: https://fujiapp.top/docs/overview/
- `man hdiutil`
