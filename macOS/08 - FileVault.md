# FileVault

FileVault 2 (FV2) is macOS **Full Disk Encryption (FDE)** — **data-at-rest** protection introduced in **Lion (10.7)**. The entire startup volume is encrypted; the key is released only after a Secure-Token user authenticates at the pre-boot login screen. The forensic crux is simple and brutal:

> 🔴 **A cold/dead image of a FileVault-enabled Mac is ciphertext.** Without the user password, a recovery key, or a live-captured key, the bytes are useless. **Decide acquisition strategy *before* you power it down.**

## Contents
- [Quick Triage](#quick-triage)
- [Check FileVault Status (do this first, live)](#check-filevault-status-do-this-first-live)
- [What It Is & Its Evolution](#what-it-is--its-evolution)
- [Key Hierarchy & Unlock Methods](#key-hierarchy--unlock-methods)
- [Hardware Matters: Pre-T2 vs T2 vs Apple Silicon](#hardware-matters-pre-t2-vs-t2-vs-apple-silicon)
- [Status & Management Commands](#status--management-commands)
- [Recovery Keys](#recovery-keys)
- [Forensic Impact & Acquisition Strategy](#forensic-impact--acquisition-strategy)
- [Decrypting an Image (when you have a key)](#decrypting-an-image-when-you-have-a-key)
- [Where Status/Config Lives](#where-statusconfig-lives)
- [Best Practices](#best-practices)
- [Red Flags](#red-flags)

---

## Quick Triage

```bash
# --- Posture (run live, before shutdown) ---
fdesetup status

fdesetup isactive

fdesetup list                              # FileVault-enabled users

fdesetup haspersonalrecoverykey

fdesetup hasinstitutionalrecoverykey

# --- Encryption state + who can unlock ---
diskutil apfs list | grep -Ei 'filevault|encrypt|locked'

diskutil apfs listCryptoUsers /            # Secure-Token unlock holders

# --- Institutional master key present? ---
ls -l /Library/Keychains/FileVaultMaster.keychain 2>/dev/null

# --- Hardware (dictates acquisition method) ---
system_profiler SPHardwareDataType | grep -Ei 'chip|model|processor'

system_profiler SPiBridgeDataType 2>/dev/null      # T2 presence

# --- FileVault events in the log (enable/disable/unlock + timing) ---
log show --predicate 'process == "fdesetup" OR process == "corestoraged" OR eventMessage CONTAINS[c] "FileVault"' --info --last 30d
```

---

## Check FileVault Status (do this first, live)

```bash
fdesetup status
```
Possible output:
```
FileVault is On.
FileVault is Off.
FileVault is On. Decryption in progress: Percent completed = 42.
Deferred enablement appears to be active for user 'jdoe'.
```
> 🔴 If it's **On** and the machine is currently **unlocked/logged in**, the volume is decrypted *right now* — capture it **before shutdown** (§6). A reboot re-locks everything.

---

## What It Is & Its Evolution

| Era | Mechanism | Scope |
|---|---|---|
| **Legacy FileVault (FV1)** — Panther 10.3 | Encrypted **home directory** into a `.sparsebundle`/`.sparseimage` disk image | One user's home only |
| **FileVault 2 (FV2)** — Lion 10.7 | **Full-volume** encryption via **CoreStorage** (HFS+) | Whole startup disk |
| **APFS FileVault** — Catalina 10.15+ | Native **APFS encryption** of the Data (and System) volume | Whole APFS container |

**Cipher:** AES-XTS with a 256-bit key; hardware-accelerated on T2/Apple Silicon.

---

## Key Hierarchy & Unlock Methods

| Layer | Role |
|---|---|
| **VEK** (Volume Encryption Key) | Encrypts the actual volume data |
| **KEK** (Key Encryption Key) | Wraps the VEK; this is what gets unlocked |
| **Unlock secrets** | Any one releases the KEK → VEK → data |

The KEK can be unlocked by:
- 🔴 A **Secure-Token** user's **password** (see *Users and Groups*: only Secure-Token holders can unlock FileVault)
- The **Personal Recovery Key (PRK)** — 24-char string shown at enablement
- An **Institutional Recovery Key (IRK)** — org master (`FileVaultMaster.keychain`)
- **iCloud escrow** (personal) or **MDM/Bootstrap Token** escrow (managed)

> Pre-boot authentication: the EFI/iBoot login screen unlocks the volume **before** macOS boots. Only FileVault-enabled (Secure-Token) users appear there.

---

## Hardware Matters: Pre-T2 vs T2 vs Apple Silicon

This determines how (and whether) you can acquire the disk.

| Platform | At-rest encryption | FileVault adds | Acquisition implication |
|---|---|---|---|
| **Intel, no T2** (≤2017) | None unless FV2 on (software CoreStorage/APFS) | The whole encryption | FV off = plaintext disk (image freely). FV on = need a key |
| **Intel + T2** (2018–2020) | **Always** HW-encrypted by the T2 (keys in Secure Enclave) | Requires **user password** to release keys | Disk **can't** be read on other hardware; FV off still needs the T2 to decrypt |
| **Apple Silicon** (M1+) | **Always** HW-encrypted (Secure Enclave) | User password protects the keys | Must acquire **on the original machine** (Mac Sharing Mode / DFU + Configurator); chip can't be pulled |

> On T2/Apple Silicon the SSD is encrypted **even with FileVault "Off"** — but the key is then available automatically at boot. FileVault **On** is what ties decryption to the user's password. Either way, you **cannot** desolder/chip-off — keys live in the Secure Enclave, bound to that Mac.

---

## Status & Management Commands

| Command | Does |
|---|---|
| `fdesetup status` | On/Off + encryption/decryption progress |
| `fdesetup isactive` | `true`/`false` (script-friendly) |
| `fdesetup list` | FileVault-**enabled users** |
| `fdesetup haspersonalrecoverykey` | Is a PRK set? |
| `fdesetup hasinstitutionalrecoverykey` | Is an IRK set? |
| `diskutil apfs list` | Per-volume `FileVault: Yes (Locked/Unlocked)`, `Encrypted: Yes` |
| `diskutil apfs listCryptoUsers /` | Who can unlock (Secure-Token crypto users) |
| `diskutil cs list` | Legacy **CoreStorage** (HFS+ era) encryption state |
| `sudo fdesetup enable` / `disable` | Turn FV on/off (prints PRK on enable) |
| `sudo fdesetup add -usertoadd <u>` | Grant a user FileVault unlock |

---

## Recovery Keys

| Type | What | Where it lives |
|---|---|---|
| **Personal (PRK)** | 24-char key shown once at enablement | User-kept; optionally **escrowed to iCloud** |
| **Institutional (IRK)** | Org-wide master key | 🔴 `/Library/Keychains/FileVaultMaster.keychain` |
| **iCloud escrow** | PRK stored with Apple | Retrievable via Apple legal process / the Apple ID |
| **MDM / Bootstrap Token** | Managed escrow | Retrievable from the MDM console |

> 🔴 An **IRK present** (`FileVaultMaster.keychain`) means there's an org master key that unlocks this disk — a legitimate acquisition path if you control the org.

---

## Forensic Impact & Acquisition Strategy

The single most important triage decision for a FileVault Mac:

| Machine state | What you can get | Action |
|---|---|---|
| **On + unlocked** (user logged in) | Volume is **decrypted in memory** — full logical access | 🔴 **Live/logical image now** + **RAM capture** (keys may be in RAM). **Do NOT shut down first.** |
| **On but at lock screen** | Encrypted; key in Secure Enclave/RAM but gated | Try known creds; consider RAM capture; avoid reboot |
| **Off / cold** | **Ciphertext only** | Need user password, PRK, IRK, or escrow to decrypt |

- **Cold imaging** a FileVault disk yields encrypted blocks — *valid* to collect, but undecryptable without a key.
- **Live acquisition** of a mounted, unlocked volume is the goal — once decrypted in memory, artifacts are accessible normally (FileVault only protects **at rest**).
- **RAM capture** can recover the VEK/FileVault key via memory forensics.
- Apple Silicon/T2: acquisition must run **on the original hardware** with credentials (the keys can't leave the Secure Enclave).

---

## Decrypting an Image (when you have a key)

```bash
# Attach the encrypted image/disk, then unlock the APFS volume:
diskutil apfs unlockVolume <diskXsY> -passphrase <userPwOrRecoveryKey>

diskutil apfs list                       # confirm 'Unlocked'

# Tooling for offline decryption:
#   APFS FileVault : apfs-fuse, Elcomsoft/Passware (password or recovery key)
#   HFS+ CoreStorage (legacy): libfvde / fvdemount
```
> Recovery-key and password both unlock; document which you used and the chain of custody.

---

## Where Status/Config Lives

| Path | Holds |
|---|---|
| `/Library/Keychains/FileVaultMaster.keychain` | Institutional Recovery Key (if set) |
| `/var/db/ConfigurationProfiles/` | MDM-enforced FileVault policy + escrow config |
| Crypto state | Read live via `fdesetup` / `diskutil apfs` (not a simple plist) |
| Unified log (`corestoraged`, `fdesetup`, `FileVault`) | Enable/disable/unlock events + timing |

---

## Best Practices

1. **Run `fdesetup status` first** — know whether FDE is on before touching power.
2. If **On + unlocked**, prioritize **live/logical acquisition** and **RAM capture**; shutting down re-locks the disk.
3. Secure the **unlock secret** early: user password, **PRK**, **IRK**, or **iCloud/MDM escrow**.
4. For **Apple Silicon/T2**, plan hardware-bound acquisition (Mac Sharing Mode / DFU); the disk can't be read elsewhere.
5. Document any recovery key obtained/used and every state change (chain of custody).
6. Remember: on an **unlocked** running Mac, FileVault has **no** further effect on artifact access — normal live triage applies.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| FileVault **Off** on a sensitive/managed endpoint | Posture gap or someone disabled it to ease exfil |
| FileVault recently **disabled** (log event) | Pre-exfil decryption / tampering |
| Unexpected **FileVault-enabled user** (`fdesetup list`) | Backdoor account that can unlock the disk |
| Backdoor account holding a **Secure Token** | Can decrypt FileVault (cross-ref Users and Groups) |
| **IRK** present where org doesn't expect one | Rogue master-key access path |
| PRK escrow pointed at an attacker-controlled Apple ID/MDM | Recovery-key exfiltration |
