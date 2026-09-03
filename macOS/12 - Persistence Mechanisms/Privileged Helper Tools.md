# Privileged Helper Tools

**Privileged Helper Tools** let a normal app perform **root-level actions without prompting for credentials every time**. The app installs a small helper into `/Library/PrivilegedHelperTools/` (via the `SMJobBless` / ServiceManagement API, authorized once by an admin), plus a **LaunchDaemon** that runs it as **root**. Legitimate (updaters, VPNs, virtualization) — but a **persistence + privilege foothold** attackers install or **hijack**.

> 🔴 The helper runs as **root at boot** via its LaunchDaemon. Two attacks: (1) install a **malicious** helper for stealthy root persistence; (2) **tamper** a legitimate one (swap the binary or edit its plist). Defense = verify the helper's **code signature** and that the app↔helper authorization (`SMPrivilegedExecutables` / `SMAuthorizedClients`) still matches.

## Contents
- [Quick Triage](#quick-triage)
- [How They Work](#how-they-work)
- [Locations](#locations)
- [How Attackers Abuse Them](#how-attackers-abuse-them)
- [Verifying a Helper](#verifying-a-helper)
- [The App to Helper Trust Link](#the-app-to-helper-trust-link)
- [Logs](#logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# List installed privileged helpers
ls -la@ /Library/PrivilegedHelperTools/

# Verify each helper's signature is intact + see who signed it
for h in /Library/PrivilegedHelperTools/*; do echo "== $h =="; codesign -dvvv "$h" 2>&1 | grep -iE 'Authority|TeamIdentifier|Identifier'; codesign -v "$h" 2>&1; done

# The LaunchDaemon that runs each helper
ls -la /Library/LaunchDaemons/ | grep -iE "$(ls /Library/PrivilegedHelperTools/ 2>/dev/null | tr '\n' '|')xxx"
```

---

## How They Work

1. An app calls **`SMJobBless`** to install a helper; the admin authorizes it **once**.
2. The helper binary lands in **`/Library/PrivilegedHelperTools/<bundle-id>`** (root-owned).
3. A **LaunchDaemon** `/Library/LaunchDaemons/<bundle-id>.plist` registers it with `launchd` to run as **root**.
4. The app talks to the helper over **XPC** to request privileged actions — no repeated password prompts.

🔴 Result: a root daemon that **starts at boot** and persists independently of the app being open.

---

## Locations

| Path | Holds |
|---|---|
| 🔴 `/Library/PrivilegedHelperTools/<bundle-id>` | The helper **binary** (root) |
| 🔴 `/Library/LaunchDaemons/<bundle-id>.plist` | The daemon that runs it as root |
| App bundle `Contents/Library/LaunchServices/` | The helper as shipped inside the parent app |
| App `Info.plist` → `SMPrivilegedExecutables` | App declares which helper(s) it trusts |
| Helper `Info.plist` → `SMAuthorizedClients` | Helper declares which app(s) may call it |

---

## How Attackers Abuse Them

| Technique | What it looks like |
|---|---|
| 🔴 Install a **malicious** helper | Unknown helper + LaunchDaemon, runs root at boot |
| 🔴 **Replace** a legit helper's binary | Same name/path, **signature now broken** or re-signed with a different Team ID |
| **Tamper the plist** | `Program`/`ProgramArguments` points somewhere new |
| **Orphaned** helper | Parent app uninstalled but helper + daemon remain |
| Exploit a **vulnerable** helper | A legit helper that does privileged ops insecurely (XPC client validation flaw) |

---

## Verifying a Helper

```bash
# Full signing info (identifier, authority chain, Team ID)
codesign -dvvv /Library/PrivilegedHelperTools/com.vendor.helper 2>&1

# Verify the on-disk binary hasn't been modified since signing
codesign --verify --strict --verbose=4 /Library/PrivilegedHelperTools/com.vendor.helper 2>&1

# Notarization / Gatekeeper assessment
spctl -a -vv -t install /Library/PrivilegedHelperTools/com.vendor.helper 2>&1

# Timestamps — recently changed helper is suspicious
stat -f 'Birth=%SB Mod=%Sm Change=%Sc %N' /Library/PrivilegedHelperTools/*
```

🔴 A `codesign --verify` failure ("**a sealed resource is missing or invalid**" / "**code object is not signed at all**") on a helper = **tampering or a fake**.

---

## The App to Helper Trust Link

`SMJobBless` ties an app and its helper together by **code-signing requirement**:

- App `Info.plist` **`SMPrivilegedExecutables`** = the helper's signing requirement (must match the helper).
- Helper `Info.plist` **`SMAuthorizedClients`** = the app's signing requirement (must match the app).

```bash
# Read the helper's authorized clients
plutil -p /Library/PrivilegedHelperTools/com.vendor.helper 2>/dev/null  # if it's a bundle

# Read the parent app's declared helper requirement
plutil -extract SMPrivilegedExecutables xml1 -o - /Applications/Vendor.app/Contents/Info.plist 2>/dev/null
```

🔴 If the **Team ID** in those requirements doesn't match the actual signatures — or the named parent app **doesn't exist** — the trust link is broken: tampering or a standalone malicious helper.

---

## Logs

```bash
# ServiceManagement / SMJobBless installs + helper launches
log show --predicate 'process == "smd" OR subsystem == "com.apple.xpc.smd" OR eventMessage CONTAINS[c] "SMJobBless"' --info --last 30d

# launchd running the helper daemon
log show --predicate 'subsystem == "com.apple.launchd" AND eventMessage CONTAINS[c] "helper"' --info --last 30d
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Helper with a **broken `codesign --verify`** | Binary replaced/tampered |
| Helper signed by a **different Team ID** than its app | Hijack / fake |
| Helper present but **no parent app** installed | Orphan or standalone malware |
| Suspicious/odd helper **name** (typo-squat of a vendor) | Masquerade |
| Helper binary **recently modified** | Tampering event |
| `SMAuthorizedClients` / `SMPrivilegedExecutables` mismatch | Broken trust link |
| LaunchDaemon `Program` pointing outside `PrivilegedHelperTools` | Redirected to attacker payload |

---

## Resources

- Apple ServiceManagement / `SMJobBless` documentation: https://developer.apple.com/documentation/servicemanagement
- `man codesign` · `man spctl`
