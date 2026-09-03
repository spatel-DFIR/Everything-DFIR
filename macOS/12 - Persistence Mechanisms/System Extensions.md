# System Extensions

Apple replaced loadable **kernel extensions (kexts)** with **System Extensions** — user-space modules that deliver driver, networking, and security functionality **without** running in the kernel. They're more constrained (notarized, user-approved, sandboxed), but attackers still abuse them: a malicious **content filter**, **DNS proxy**, or **Endpoint Security** extension grants both **persistence** and a powerful **capability** (intercepting traffic or monitoring the system).

> 🔴 System Extensions must be **notarized and user-approved**, so they're a higher bar than a dropped plist — but a tricked approval (or a legit-looking signed extension) yields a persistent, privileged, traffic-intercepting foothold. Enumerate with `systemextensionsctl list` and verify every non-security-vendor network/ES extension.

## Contents
- [Quick Triage](#quick-triage)
- [Kexts to System Extensions](#kexts-to-system-extensions)
- [Types of System Extension](#types-of-system-extension)
- [Where They Live](#where-they-live)
- [Enumerating and Verifying](#enumerating-and-verifying)
- [Developer Mode](#developer-mode)
- [Legacy Kexts](#legacy-kexts)
- [Logs](#logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# List all installed system extensions + state (enabled/active, team ID)
systemextensionsctl list

# On-disk extension store
ls -la /Library/SystemExtensions/

# Is unsigned-extension developer mode on? (should be off in production)
systemextensionsctl developer 2>/dev/null

# Legacy: third-party kexts still loaded
kextstat | grep -v com.apple
```

---

## Kexts to System Extensions

| | Kexts (legacy) | System Extensions (modern) |
|---|---|---|
| Runs in | **Kernel** | **User space** |
| Risk | Full kernel access | Sandboxed, constrained |
| Trust | Signed kext + SIP/approval | **Notarized + user-approved** |
| Status | Deprecated (blocked on Apple Silicon by default) | The supported path (Catalina 10.15+) |
| Manage | `kextstat`, `kmutil` | `systemextensionsctl` |

---

## Types of System Extension

| Type | Capability — and why attackers want it |
|---|---|
| 🔴 **Network Extension** — content filter | See/block **all network traffic** (interception) |
| 🔴 **Network Extension** — DNS proxy | Redirect/inspect **DNS** (hijack) |
| **Network Extension** — VPN / app-proxy | Tunnel/route traffic |
| 🔴 **Endpoint Security** extension | Monitor process/file/auth events (powerful telemetry — or evasion) |
| **DriverKit** (dext) | User-space device drivers |

---

## Where They Live

| Path | Holds |
|---|---|
| 🔴 `/Library/SystemExtensions/` | Activated extensions (per-UUID folders) + `db.plist` |
| `/Library/SystemExtensions/db.plist` | The registry of installed extensions/state |
| Inside the app bundle `Contents/Library/SystemExtensions/` | The extension as shipped |
| `/Library/Preferences/com.apple.networkextension*.plist` | NE configs (VPN/filter/DNS) — cross-ref Wi-Fi/Network |

---

## Enumerating and Verifying

```bash
# Full list with team IDs and state
systemextensionsctl list

# The registry
plutil -p /Library/SystemExtensions/db.plist 2>/dev/null

# Find the extension binary + verify signature / notarization
find /Library/SystemExtensions -name '*.systemextension' 2>/dev/null

codesign -dvvv /Library/SystemExtensions/<uuid>/com.vendor.ext.systemextension 2>&1

spctl -a -vv -t exec /Library/SystemExtensions/<uuid>/com.vendor.ext.systemextension 2>&1

# Network filters / DNS proxies currently configured
plutil -p /Library/Preferences/com.apple.networkextension.plist 2>/dev/null
```

🔴 For each extension: does the **Team ID / vendor** make sense for what it does? A **content filter or ES extension from a non-security vendor** (or an unknown one) is a major red flag.

---

## Developer Mode

```bash
# Check (and beware) developer mode — allows UNSIGNED extensions to load
systemextensionsctl developer
```

🔴 If **developer mode is ON**, unsigned/un-notarized system extensions can run — a deliberate weakening an attacker (or a careless user) may have enabled. It should be **off** on production machines.

---

## Legacy Kexts

```bash
# Third-party kexts (non com.apple.*) still loaded
kextstat | grep -v com.apple

kmutil showloaded --no-kernel-components 2>/dev/null

# Where third-party kexts live
ls -la /Library/Extensions/ 2>/dev/null
```

> On modern Apple Silicon, loading a third-party kext requires lowering security (Reduced Security + user approval) — itself a red flag. Cross-ref the SIP and System & Kernel Events notes.

---

## Logs

```bash
# System Extension activation / approval activity
log show --predicate 'process == "sysextd" OR subsystem == "com.apple.sysextd" OR eventMessage CONTAINS[c] "system extension"' --info --last 30d

# Network Extension provider start (filters/VPN/DNS)
log show --predicate 'subsystem == "com.apple.networkextension" OR process == "nehelper"' --info --last 7d
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Unknown **content filter / DNS proxy** extension | Traffic interception / hijack |
| **Endpoint Security** extension from a non-security vendor | Surveillance or EDR-evasion abuse |
| Extension **Team ID** not matching any known app | Fake / hijacked |
| `systemextensionsctl developer` = **on** | Unsigned extensions allowed (weakened) |
| Extension activated **recently** / unexpected | Freshly planted |
| Third-party **kext** on modern macOS | Requires lowered security — investigate |
| NE config (`com.apple.networkextension*.plist`) with unknown provider | Rogue filter/VPN |

---

## Resources

- `man systemextensionsctl`
- Apple System Extensions / EndpointSecurity / NetworkExtension docs: https://developer.apple.com/documentation/systemextensions
