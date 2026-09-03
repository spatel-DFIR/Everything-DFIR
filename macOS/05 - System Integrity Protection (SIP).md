# System Integrity Protection (SIP)

SIP (a.k.a. **"rootless"**, introduced in **El Capitan 10.11**) is a **kernel-enforced** mandatory access control that restricts what even **root** can do — protecting system files, system processes, NVRAM, and kext loading. For DFIR it's both a **trust anchor** (protected files can be relied on) and a **posture indicator** (SIP off = something/someone weakened the box). Its state lives in **NVRAM**, not on disk — so **capture it live**.

## Contents
- [Quick Triage](#quick-triage)
- [Check SIP Status (do this first, live)](#check-sip-status-do-this-first-live)
- [What SIP Protects (the pillars)](#what-sip-protects-the-pillars)
- [Protected Paths & the `restricted` Flag](#protected-paths--the-restricted-flag)
- [`csr-active-config` — The NVRAM Bitmask](#csr-active-config--the-nvram-bitmask)
- [Interpreting `csrutil status`](#interpreting-csrutil-status)
- [Disabling / Enabling SIP (the proper way)](#disabling--enabling-sip-the-proper-way)
- [Kexts & System Extensions (SIP enforcement)](#kexts--system-extensions-sip-enforcement)
- [Forensic Impact](#forensic-impact)
- [Documenting Changes (best practice)](#documenting-changes-best-practice)
- [Red Flags](#red-flags)

---

## Quick Triage

```bash
# --- POSTURE: full SIP picture (run live) ---
csrutil status

csrutil authenticated-root status

nvram csr-active-config

nvram -p | grep -Ei 'csr|boot-args'        # boot-args can also weaken security

# --- non-zero csr-active-config = some protection OFF ---

# --- KEXTS / SYSTEM EXTENSIONS: unsigned or non-Apple ---
kmutil showloaded 2>/dev/null | grep -vi com.apple

systemextensionsctl list

# --- PROTECTED-PATH TAMPER: restricted items that were modified ---
ls -lO /System/Library/CoreServices/SystemVersion.plist     # should show 'restricted'

find /System /usr /bin /sbin -flags +restricted -mtime -30 2>/dev/null   # recent change to a protected file

# --- PERSISTENCE in the writable exceptions SIP forces attackers into ---
ls -la /Library/LaunchDaemons /Library/LaunchAgents \
       /Users/*/Library/LaunchAgents /usr/local/bin 2>/dev/null

# --- BOOT-ARGS / NVRAM tampering ---
nvram boot-args 2>/dev/null                 # e.g. 'amfi_get_out_of_my_way=1' = AMFI bypass
```

---

## Check SIP Status (do this first, live)

```bash
csrutil status                     # human-readable: enabled / disabled / custom

nvram csr-active-config            # raw NVRAM bitmask (the ground truth)

csrutil authenticated-root status  # is the sealed System volume still enforced? (Big Sur+)
```

Typical output:
```
System Integrity Protection status: enabled.
```
> 🔴 `csrutil` reports what the **running** OS sees. The authoritative value is the NVRAM `csr-active-config` bitmask (§3). SIP **cannot** be reliably read from a dead disk image — it's a hardware/NVRAM artifact. Record it during live triage.

---

## What SIP Protects (the pillars)

| Pillar | Restricts | Even root? |
|---|---|---|
| 🔴 **Filesystem** | Writing to protected system paths (§2) | ✅ blocked |
| 🔴 **Runtime / process** | `task_for_pid()` — attaching a debugger or code-injecting into Apple/protected processes | ✅ blocked |
| 🔴 **Kext loading** | Loading unsigned/unapproved kernel extensions | ✅ blocked |
| **NVRAM** | Writing protected NVRAM variables (`csr-active-config`, boot args) | ✅ blocked |
| **DTrace** | Tracing protected processes | ✅ blocked |
| **Boot args** | `nvram boot-args` (e.g. disabling protections via kernel flags) | ✅ blocked |

> Net effect: malware running as **root cannot** modify `/System`, replace system binaries, inject into Apple daemons, or load a rootkit kext — **while SIP is on**.

---

## Protected Paths & the `restricted` Flag

SIP-protected items are marked at the filesystem level — independent of POSIX perms.

| Protected (read-only even to root) | Writable exceptions |
|---|---|
| `/System` (except `/System/Volumes/Data`) | `/usr/local` |
| `/usr` (most of it) | `/Applications` (third-party apps) |
| `/bin`, `/sbin` | `/Library` (most) |
| Apple's preinstalled apps in `/Applications` | `~/Library` (most) |

**How an item is marked protected:**
- The **`restricted`** BSD flag (`ls -lO` shows `restricted`) and/or the **`com.apple.rootless`** extended attribute.
- The master policy list: **`/System/Library/Sandbox/rootless.conf`** (protected paths + named exceptions).

```bash
ls -lO /System/Library/CoreServices/SystemVersion.plist   # → 'restricted'

xattr -l /usr/bin/sudo | grep rootless

grep -v '^#' /System/Library/Sandbox/rootless.conf | sort
```

> 🔴 **Where this pushes persistence:** because attackers **can't** write to protected paths, SIP-era persistence lands in the **writable exceptions** — `/Library/LaunchDaemons`, `~/Library/LaunchAgents`, `/usr/local/bin`, third-party `/Applications`. Hunt there first.

### DFIR artifacts: what SIP does (and doesn't) protect

> **Key takeaway: SIP protects the *OS*, not your *evidence*.** Almost every forensic artifact lives on the **Data volume in non-protected paths** — so even with SIP **on**, a root-level attacker can tamper with or delete them. What SIP *does* guarantee is that the OS and the system binaries you run during triage are trustworthy.

| DFIR artifact | Path | SIP-protected? | Forensic implication |
|---|---|---|---|
| Unified logs | `/var/db/diagnostics` | ❌ No (Data vol) | Root can delete/rotate — corroborate, don't assume complete |
| Plain-text logs | `/private/var/log` | ❌ No | Tamperable / deletable |
| FSEvents | `/.fseventsd` | ❌ No | Tamperable / deletable |
| Spotlight index | `/.Spotlight-V100` | ❌ No | Tamperable / deletable |
| Local accounts | `/var/db/dslocal/...` | ❌ No | Root can add/modify/hide accounts |
| `sudoers`, `hosts` | `/private/etc` | ❌ No | Modifiable |
| ⚠️ Shell **config** files | `/etc/zprofile`, `/etc/zshrc` (`=/private/etc`), all `~/.zsh*`, `~/.bash_profile` | ❌ No | **Common misconception** — these are **NOT** protected; that's exactly why they're persistence vectors |
| Third-party persistence | `/Library/Launch*`, `~/Library/LaunchAgents` | ❌ No | Writable — where implants live |
| Third-party apps | `/Applications/<thirdparty>.app` | ❌ No | Binary can be modified/trojanized |
| 🟢 Apple LaunchDaemons/Agents | `/System/Library/Launch*` | ✅ Yes | Apple autostart **baseline trustworthy** |
| 🟢 System binaries (your tools) | `/usr/bin`, `/bin`, `/sbin` (`log`, `plutil`, `sqlite3`) | ✅ Yes | Triage tools on the box are **trustworthy** |
| 🟢 Shell **binaries** + function libs | `/bin/zsh`, `/bin/bash`, `/usr/share/zsh` | ✅ Yes | The interpreter itself is trustworthy — but **not** the config it reads |
| 🟢 Apple apps | `/Applications/Safari.app`, etc. | ✅ Yes | Not trojanizable while SIP on |
| 🟢 Apple kexts | `/System/Library/Extensions` | ✅ Yes | Kernel baseline trustworthy |
| 🟢 OS version / build | `/System/Library/CoreServices/SystemVersion.plist` | ✅ Yes | Reliable OS identification |

> So: SIP **enabled** lets you *trust the OS and your on-box tools* and *rule out `/System` tampering* — but it does **not** vouch for logs, accounts, or persistence files. Those still need integrity corroboration.

---

## `csr-active-config` — The NVRAM Bitmask

SIP state is a bitmask in NVRAM. **Each bit set = one protection turned OFF.** `0x00` = fully enabled.

| Bit | Hex | Flag | Disables |
|---|---|---|---|
| 0 | `0x001` | `ALLOW_UNTRUSTED_KEXTS` | Kext signing |
| 1 | `0x002` | `ALLOW_UNRESTRICTED_FS` | Filesystem protection |
| 2 | `0x004` | `ALLOW_TASK_FOR_PID` | Process/debug protection |
| 3 | `0x008` | `ALLOW_KERNEL_DEBUGGER` | Kernel debugging |
| 4 | `0x010` | `ALLOW_APPLE_INTERNAL` | (Apple-internal builds) |
| 5 | `0x020` | `ALLOW_UNRESTRICTED_DTRACE` | DTrace restriction |
| 6 | `0x040` | `ALLOW_UNRESTRICTED_NVRAM` | NVRAM protection |
| 7 | `0x080` | `ALLOW_DEVICE_CONFIGURATION` | (device config) |
| 8 | `0x100` | `ALLOW_ANY_RECOVERY_OS` | RecoveryOS verification |
| 9 | `0x200` | `ALLOW_UNAPPROVED_KEXTS` | User-approved kext requirement |
| 10 | `0x400` | `ALLOW_EXECUTABLE_POLICY_OVERRIDE` | Executable policy |
| 11 | `0x800` | `ALLOW_UNAUTHENTICATED_ROOT` | Sealed System Volume (SSV) |

**Common values:**

| Value | Meaning |
|---|---|
| `0x00` | 🟢 SIP fully **enabled** |
| `0x77` | 🔴 Typical **`csrutil disable`** (kexts+fs+task_for_pid+apple-internal+dtrace+nvram) |
| `0x10` | Apple-internal only |
| `0x2` / `0x3` | Filesystem (± kext) protection off — enough to tamper system files |
| any non-zero | 🔴 **Some protection is off** — investigate which bit |

```bash
nvram csr-active-config

# csr-active-config	w%00%00%00     ← 'w' = 0x77  → SIP disabled
# (low byte is the value; decode it against the table above)
```

---

## Interpreting `csrutil status`

| Output | Meaning |
|---|---|
| `status: enabled.` | All protections on (`0x00`) |
| `status: disabled.` | 🔴 SIP off |
| `status: unknown` / **Custom Configuration** with per-feature lines | 🔴 Partial — read each line (`Kext Signing: disabled`, `Filesystem Protections: enabled`, `Debugging Restrictions`, `DTrace Restrictions`, `NVRAM Protections`) |

> A "Custom Configuration" / partial state is a **strong tamper signal** — normal Macs are either fully enabled or (rarely, devs) fully disabled.

---

## Disabling / Enabling SIP (the proper way)

**SIP can only be changed from RecoveryOS — not the running OS.** Running `csrutil disable` in the full OS errors out.

| Step | Intel | Apple Silicon |
|---|---|---|
| Enter Recovery | Reboot + hold **⌘-R** | Power off, **hold power** until "Loading startup options" → Options |
| Open Terminal | Utilities → Terminal | Utilities → Terminal |
| Change SIP | `csrutil disable` / `csrutil enable` | `csrutil disable` (then authenticate as admin) |
| Reboot | `reboot` | `reboot` |

```bash
# In RecoveryOS Terminal:
csrutil disable                    # turn SIP off (writes csr-active-config in NVRAM)

csrutil enable                     # turn it back on

csrutil authenticated-root disable # ALSO needed to modify the sealed System volume (Big Sur+)
```

**Apple Silicon security levels** (Startup Security Utility / `bputil`): disabling SIP drops the Mac from **Full Security** → **Reduced/Permissive Security**. Modifying the **sealed System volume** additionally requires `csrutil authenticated-root disable` + remounting and blessing a new snapshot.

> 🔴 Changing SIP requires **physical access + reboot to Recovery** → implies a hands-on actor (insider, or attacker with console access), not a remote-only compromise.

---

## Kexts & System Extensions (SIP enforcement)

SIP enforces code-signing on anything entering the kernel.

| Type | Loaded via | Check |
|---|---|---|
| Legacy **kext** (`.kext`, kernel space) | `kmutil load` / `kextload` | `kmutil showloaded` (modern), `kextstat` (legacy) |
| **System Extension** (`.systemextension`, user space — modern) | `systemextensionsctl` / app-provided | `systemextensionsctl list` |

```bash
kmutil showloaded                              # loaded kexts (flag non-Apple)

kmutil showloaded --collection-kind aux        # auxiliary (third-party) kext collection

systemextensionsctl list                       # installed system extensions
```
> 🔴 A loaded **unsigned/non-Apple kext** implies kext protection was weakened (SIP bit 0/9) or the user approved it. Unexpected kexts = potential rootkit.

---

## Forensic Impact

| SIP state | Implication for the investigation |
|---|---|
| **Enabled** | `/System`, `/bin`, `/usr`, Apple binaries are **trustworthy**; rule out tampering there. Persistence must be in writable areas (§2) |
| **Disabled / partial** | 🔴 System files, kexts, and Apple-process memory are **no longer trustworthy**; rootkits/system-binary trojans become possible — widen scope |
| **NVRAM-resident** | State survives OS reinstall and is tied to the machine; **not in the disk image** — must be captured live |

---

## Documenting Changes (best practice)

If you must disable SIP on an evidence machine (e.g., to run a tool or mount a volume):

1. **Before:** capture `csrutil status`, `nvram csr-active-config`, and `csrutil authenticated-root status` (screenshot + text), with **date/time, examiner, reason**.
2. Make the change **only in Recovery**, noting it alters **NVRAM** (chain-of-custody event).
3. **Re-enable** (`csrutil enable`) afterward and re-capture the values.
4. Prefer **not** to touch the live system — do analysis on a forensic **image** where possible; document why a live change was unavoidable.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `csrutil status: disabled` (or custom/partial) | SIP deliberately weakened |
| `csr-active-config` ≠ `0x00` | One or more protections off — decode which |
| `csrutil authenticated-root: disabled` | Sealed System volume modifiable → system-binary tampering possible |
| Non-Apple / unsigned **kext** loaded | Kext protection bypassed; possible rootkit |
| `boot-args` containing `amfi_get_out_of_my_way`, `-no_compat_check`, `cs_enforcement_disable` | Code-signing / AMFI bypass |
| Modified file under `/System`, `/usr`, `/bin` (broken `restricted`/seal) | System tamper (requires SIP off) |
| SIP disabled on a non-developer endpoint | Hands-on actor (Recovery access) — escalate |
