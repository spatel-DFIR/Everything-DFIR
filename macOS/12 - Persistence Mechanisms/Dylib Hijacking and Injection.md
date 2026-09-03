# Dylib Hijacking and Injection

macOS dynamic-library attacks let an adversary get **their** code running inside a **trusted** process — for persistence, privilege, and stealth (the malicious code inherits the host app's identity, TCC grants, and trust). The main families: **dylib hijacking** (plant a library where an app will load it), **dynamic-linker hijacking** (`DYLD_*` environment injection), and **process injection** (force code into a running process).

> 🔴 Why it matters: injected code runs **as the victim app**, so it inherits the app's **TCC permissions** (camera/mic/FDA), code-signing trust, and network reputation. Hardened-runtime + SIP block much of this on Apple binaries — but third-party apps without hardened runtime remain hijackable. Verify signatures and inspect Mach-O load commands.

## Contents
- [Quick Triage](#quick-triage)
- [Dylib Hijacking](#dylib-hijacking)
- [Dynamic Linker Hijacking](#dynamic-linker-hijacking)
- [Dylib Proxying](#dylib-proxying)
- [Process Injection](#process-injection)
- [What Stops It](#what-stops-it)
- [Detection](#detection)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Load commands of a binary — look for weak/rpath dylibs (hijackable)
otool -l /Applications/Some.app/Contents/MacOS/Some | grep -A3 -E 'LC_LOAD_WEAK_DYLIB|LC_RPATH|LC_LOAD_DYLIB'

# Verify the app/binary is intact + hardened-runtime
codesign --verify --strict --verbose=4 /Applications/Some.app 2>&1

codesign -d --entitlements - /Applications/Some.app 2>&1 | grep -i 'runtime\|disable-library'

# DYLD_* injection planted in launchd plists
grep -rl 'DYLD_INSERT_LIBRARIES\|DYLD_' /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents 2>/dev/null

# Dylibs actually loaded by a running process
vmmap <pid> 2>/dev/null | grep -i '\.dylib'
```

---

## Dylib Hijacking

An app references a dylib via a path that is **missing**, **weak** (`LC_LOAD_WEAK_DYLIB`), or **@rpath**-resolved — and a writable directory earlier in the search order lets an attacker **drop a malicious dylib** there. On next launch the app loads the attacker's library.

```bash
# Find weak/rpath load commands (the hijack surface)
otool -l /path/app/Contents/MacOS/binary | grep -A2 -E 'LC_LOAD_WEAK_DYLIB|LC_RPATH'

# What @rpath resolves to
otool -l /path/app/Contents/MacOS/binary | grep -A2 LC_RPATH
```

🔴 Look for a non-Apple **`.dylib`** sitting in an app's `Contents/Frameworks`/`Loader` path that **isn't part of the signed bundle** (breaks `codesign --verify`).

**ATT&CK:** Hijack Execution Flow: Dylib Hijacking — **T1574.004**

---

## Dynamic Linker Hijacking

The dynamic linker (`dyld`) honors **`DYLD_INSERT_LIBRARIES`** — set it, and your dylib is force-loaded into the target at launch. Often planted via a **LaunchAgent/Daemon** `EnvironmentVariables` or a wrapper script.

```bash
# Hunt DYLD_* in persistence plists and shell configs
grep -rl 'DYLD_INSERT_LIBRARIES' /Library/Launch* ~/Library/LaunchAgents /Users/*/.zshenv /Users/*/.zshrc /etc/launchd.conf 2>/dev/null
```

🔴 `DYLD_INSERT_LIBRARIES` is **ignored** for binaries with **hardened runtime** or SIP protection — so seeing it used means the target is an unhardened third-party app (or the attacker chose a weak target).

**ATT&CK:** Hijack Execution Flow: Dynamic Linker Hijacking — **T1574.006**

---

## Dylib Proxying

A malicious dylib that **re-exports** all symbols of the legitimate one (`LC_REEXPORT_DYLIB`) so the app keeps working while the attacker's code also runs — stealthier than a plain hijack (no broken functionality).

```bash
otool -l /path/malicious.dylib | grep -A2 LC_REEXPORT_DYLIB
```

**ATT&CK:** Hijack Execution Flow — **T1574.004**

---

## Process Injection

Forcing code into an **already-running** process:

| Technique | Notes |
|---|---|
| `task_for_pid` + thread injection | Needs root **and** an entitlement; SIP/hardened-runtime block it for protected procs |
| Electron app injection | Modify the app's `app.asar` / JS (no native signing on JS) — common for Slack/Discord/VS Code-style apps |
| Function hooking / `DYLD` | Via the linker techniques above |

🔴 Electron/JS app tampering is a soft target — the JavaScript isn't covered by code signing the way native Mach-O is.

**ATT&CK:** Process Injection — **T1055**

---

## What Stops It

| Control | Effect |
|---|---|
| **Hardened Runtime** | Ignores `DYLD_*`, requires library validation (only same-Team-ID/Apple dylibs) |
| **Library Validation** | Blocks loading dylibs signed by a different Team ID |
| **SIP** | Protects Apple binaries from injection/tampering |
| **Notarization/codesign** | Tampered bundles fail verification |

> 🔴 So the at-risk population is **third-party apps without hardened runtime / library validation**. Apple binaries are largely protected — an AMFI/library-validation denial in the logs (cross-ref System & Kernel) is the system *blocking* an attempt.

---

## Detection

```bash
# 1) Signature integrity of suspect apps (hijack/injection breaks the seal)
codesign --verify --strict --verbose=4 /Applications/Suspect.app 2>&1

# 2) Hardened runtime + library-validation status
codesign -d -vvv /Applications/Suspect.app 2>&1 | grep -iE 'flags|runtime'

# 3) Unexpected dylibs loaded by a process
vmmap <pid> | grep -i dylib

lsof -p <pid> | grep -i '\.dylib'

# 4) AMFI / library-validation denials (system blocked an attempt)
log show --predicate 'eventMessage CONTAINS[c] "Library Validation" OR eventMessage CONTAINS[c] "AMFI"' --info --last 7d

# 5) Non-bundled dylibs inside app folders
find /Applications -name '*.dylib' 2>/dev/null | head
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Non-bundled `.dylib` in an app's load path | Dylib hijack planted |
| `codesign --verify` **fails** on a normally-signed app | Bundle tampered (hijack/injection) |
| `DYLD_INSERT_LIBRARIES` in a LaunchAgent/Daemon or shell config | Dynamic-linker injection persistence |
| `LC_REEXPORT_DYLIB` malicious dylib | Dylib proxying (stealth) |
| Modified `app.asar` / JS in an Electron app | Injected JS payload |
| Loaded dylib signed by a **different Team ID** than the app | Untrusted injection |
| AMFI/Library-Validation **denials** for an app | System blocked an injection attempt |

---

## Resources

- `man dyld` · `man otool` · `man codesign`
- Patrick Wardle, "The Art of Mac Malware" (dylib hijacking research): https://taomm.org/
