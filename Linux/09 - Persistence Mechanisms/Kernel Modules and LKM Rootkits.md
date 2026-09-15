# Kernel Modules and LKM Rootkits

A Loadable Kernel Module runs in kernel space with full control of the system, which makes it the stealthiest persistence tier on Linux: an LKM rootkit can hook syscalls to hide its own module, the attacker's processes, files, and network connections from every userland tool — including the ones you'd use to find it. Because the compromised kernel can lie to `lsmod`/`ps`/`ss`, detection relies on comparing independent views (userland vs the kernel's raw structures) and on memory analysis, and confirmation almost always means **rebuild, not clean**.

> 🔴 The two cheapest kernel-rootkit hints are **kernel taint** (`/proc/sys/kernel/tainted` nonzero → an out-of-tree or unsigned module loaded) and **view mismatches** (a module in `/proc/modules` but not `lsmod`, a process in `/proc` but not `ps`). A confirmed kernel rootkit means the host cannot be trusted to clean itself — image it, prove it in memory, and rebuild.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [How the Persistence Works](#how-the-persistence-works)
- [Enumerating Modules](#enumerating-modules)
- [Auto-Load Locations](#auto-load-locations)
- [modprobe install and alias Abuse](#modprobe-install-and-alias-abuse)
- [Detecting a Hidden Module](#detecting-a-hidden-module)
- [Kernel Taint and Signing](#kernel-taint-and-signing)
- [Confirming in Memory](#confirming-in-memory)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Taint (out-of-tree/unsigned module = LKM hint)
cat /proc/sys/kernel/tainted

# Loaded modules - userland view (can be lied to) vs kernel views
lsmod; cat /proc/modules; ls /sys/module/

# Auto-load config (persistence across reboots)
cat /etc/modules 2>/dev/null; ls -l /etc/modules-load.d/ /etc/modprobe.d/

# Recent module load events
dmesg | grep -Ei "module|taint" | tail
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Cheapest kernel-rootkit hint? | `cat /proc/sys/kernel/tainted` (nonzero) |
| Module hiding itself? | `diff` `lsmod` vs `/proc/modules` vs `/sys/module` |
| Auto-load persistence? | `/etc/modules`, `/etc/modules-load.d/*`; unowned `.ko` |
| No-`.ko` persistence (runs a command)? | `install`/`alias` lines in `/etc/modprobe.d/` |
| Modern (ftrace) hook? | `/sys/kernel/debug/tracing/enabled_functions`; memory |
| Hidden processes/ports? | `unhide` (→ Rootkit Detection Tooling) |
| Conclusive proof? | memory: `linux.check_syscall`, `linux.hidden_modules` |
| Unsigned/out-of-tree module loaded? | `dmesg \| grep 'module verification\|out-of-tree'` |

## How the Persistence Works

The attacker loads a malicious module (`insmod`/`modprobe`) and configures it to auto-load at boot. Once in the kernel, a rootkit module typically hooks the syscall table (or specific kernel functions) to filter what userland sees — removing itself from `lsmod`, hiding PIDs from `/proc` enumeration, hiding files by name prefix, and hiding sockets from `ss`. Many also add a magic mechanism to grant root on demand (a signal, a magic file, a crafted packet).

```bash
# Load a module now
insmod ./evil.ko    # or: modprobe evil

# Persist across reboots - one of:
echo "evil" >> /etc/modules
echo "evil" > /etc/modules-load.d/evil.conf
```

🔴 Well-known LKM rootkits (Diamorphine, Reptile) hide themselves the instant they load, so `lsmod` won't show them — which is exactly why you can't rely on `lsmod` and must compare views and use memory.

## Enumerating Modules

```bash
# Userland view
lsmod

# Kernel's own list (harder for a rootkit to filter, but not immune)
cat /proc/modules

# Per-module directory (another independent view)
ls /sys/module/

# Details of a specific module - signature, path, description
modinfo <module>

# Modules whose file isn't from the distro / is unsigned
modinfo <module> 2>/dev/null | grep -iE "filename|sig_id|signer|vermagic"
```

Cross-check `lsmod` against `/proc/modules` and `ls /sys/module/` — legitimately these agree; a discrepancy is a module hiding from one of them.

## Auto-Load Locations

For a module to survive reboot it must be configured to load, so these files are where you find the persistence even when the running module hides:

| Path | Purpose |
|------|---------|
| `/etc/modules` | Modules to load at boot (Debian) |
| `/etc/modules-load.d/*.conf` | Modules to load at boot (systemd) |
| `/etc/modprobe.d/*.conf` | Module options + aliases (can force-load or alias a name) |
| `/lib/modules/$(uname -r)/` | Where module `.ko` files live |
| initramfs | An early-boot module can hide before userland exists |

```bash
cat /etc/modules 2>/dev/null; cat /etc/modules-load.d/*.conf 2>/dev/null; cat /etc/modprobe.d/*.conf 2>/dev/null

# .ko files under the modules tree not owned by a package
find /lib/modules/$(uname -r) -name "*.ko*" 2>/dev/null | while read k; do dpkg -S "$k" >/dev/null 2>&1 || rpm -qf "$k" >/dev/null 2>&1 || echo "UNOWNED: $k"; done
```

🔴 An entry in `/etc/modules`/`modules-load.d` naming a module you can't attribute, or an unowned `.ko` in the modules tree, is the persistence — even if the loaded module is currently hiding itself.

## modprobe install and alias Abuse

🔴 An overlooked no-`.ko` variant: `/etc/modprobe.d/*.conf` supports **`install`** and **`alias`** directives that run an arbitrary shell command whenever a module is requested. An attacker doesn't need their own kernel module — `install <common-module> /bin/sh -c 'payload; modprobe --ignore-install <common-module>'` runs the payload (as root) every time that module loads, e.g. at boot.

```bash
# install/alias directives that execute a command (kmod persistence without a .ko)
grep -rEn '^\s*(install|alias)\s' /etc/modprobe.d/ /lib/modprobe.d/ /run/modprobe.d/ 2>/dev/null

# Blacklisted security modules (attacker disabling a defense module)
grep -rEn '^\s*blacklist' /etc/modprobe.d/ 2>/dev/null
```

🔴 An `install` line for a routinely-loaded module (or one aliased to `/bin/sh`) is code execution as root at load time — read every non-standard line in `modprobe.d`.

## Detecting a Hidden Module

```bash
# Modules in /proc/modules but not lsmod (or vice-versa)
diff <(lsmod | awk 'NR>1{print $1}' | sort) <(awk '{print $1}' /proc/modules | sort)

# Modules in /sys/module but not lsmod
diff <(lsmod | awk 'NR>1{print $1}' | sort) <(ls /sys/module | sort)

# Gaps in kernel memory where a hidden module lives (advanced)
cat /proc/kallsyms | grep -iE "hook|hide|rootkit" 2>/dev/null

# Hidden processes/ports the module may be concealing (unhide - see Rootkit Detection Tooling)
unhide quick 2>/dev/null; unhide-tcp 2>/dev/null
```

🔴 A module present in one enumeration but absent from another is being hidden. Pair this with `unhide` (which finds the hidden *processes/ports* the module conceals) to build the case before you confirm in memory.

## Kernel Taint and Signing

```bash
# Taint value - nonzero means something non-standard loaded
cat /proc/sys/kernel/tainted

# Decode which taint bits are set (bit 12 = out-of-tree, bit 13 = unsigned)
for i in $(seq 0 18); do echo "bit $i: $(( ($(cat /proc/sys/kernel/tainted) >> i) & 1 ))"; done

# Is module signature enforcement on?
cat /sys/module/module/parameters/sig_enforce 2>/dev/null

dmesg | grep -iE "module verification failed|loading out-of-tree|taint"
```

🔴 On a host that should run only distro-signed modules, a taint bit for "out-of-tree" or "unsigned module," or a `dmesg` "module verification failed," means an unexpected module loaded — a strong LKM-rootkit indicator even when the module itself is hidden.

## Confirming in Memory

Memory analysis reads kernel structures directly rather than asking the (compromised) kernel — the trusted-context confirmation (see the Memory Forensics and Rootkit Detection Tooling notes).

```bash
# Acquire RAM first (see Memory Forensics note), then:
vol -f mem.lime linux.lsmod.Lsmod            # modules in memory vs live lsmod

vol -f mem.lime linux.check_syscall.Check_syscall   # hooked syscall table = kernel rootkit

vol -f mem.lime linux.check_afinfo.Check_afinfo     # hooked network functions

vol -f mem.lime linux.hidden_modules.Hidden_modules 2>/dev/null
```

🔴 A hooked syscall table (`check_syscall`) or a module visible in memory but not on the live host is **conclusive** kernel-rootkit evidence — it comes from the raw image, not the kernel's cooperation. That's the trigger to rebuild the host (see Remediation).

## Deep Threat Hunts

Cheapest-hint-first; memory is the only trusted view. *(seasoned-DFIR)*

```bash
# 1. Taint + the three-way view mismatch (fastest hints)
cat /proc/sys/kernel/tainted

diff <(lsmod | awk 'NR>1{print $1}' | sort) <(awk '{print $1}' /proc/modules | sort)

diff <(lsmod | awk 'NR>1{print $1}' | sort) <(ls /sys/module | sort)

# 2. modprobe.d install/alias directives (no-.ko root code execution at load)
grep -rEn '^\s*(install|alias)\s' /etc/modprobe.d/ /lib/modprobe.d/ /run/modprobe.d/ 2>/dev/null

# 3. Auto-load config + unowned .ko in the modules tree
cat /etc/modules /etc/modules-load.d/*.conf 2>/dev/null

find /lib/modules/$(uname -r) -name '*.ko*' 2>/dev/null | while read k; do
  dpkg -S "$k" >/dev/null 2>&1 || rpm -qf "$k" >/dev/null 2>&1 || echo "UNOWNED: $k"; done

# 4. ftrace-based hooks (modern rootkits hook via ftrace, not the syscall table)
cat /sys/kernel/debug/tracing/enabled_functions 2>/dev/null | head

# 5. Known-rootkit + unsigned-load tells in the ring buffer
dmesg | grep -iE 'diamorphine|reptile|module verification failed|loading out-of-tree|taint'

# 6. Recently created char device (a control node the module exposes)
find /dev -newermt '-30 days' -type c -ls 2>/dev/null

# 7. Is module loading locked post-boot? Inspect initramfs for an early module
cat /proc/sys/kernel/modules_disabled 2>/dev/null

lsinitramfs /boot/initrd.img-$(uname -r) 2>/dev/null | grep -i '\.ko'

# 8. TRUSTED confirmation from a memory image
#   vol -f mem.lime linux.check_syscall.Check_syscall
#   vol -f mem.lime linux.hidden_modules.Hidden_modules
```

**Hunt ideas:**

- **`modprobe.d install`/`alias` is no-`.ko` persistence** — `install <module> /bin/sh -c '…'` runs a root command whenever that module is requested; grep every non-standard line.
- **Modern rootkits hook via ftrace, not the syscall table** — check `enabled_functions` and lean on memory (`check_syscall`/`hidden_modules`).
- **Auto-load config + an unowned `.ko` is the persistence** even when the running module hides itself from `lsmod`.
- **Magic-signal rootkits (Diamorphine)** grant root via `kill -64` and hide on `kill -63` — behavior + `dmesg` strings betray them.
- **A confirmed kernel rootkit means the host lies to itself** — image RAM, prove it in memory, and **rebuild** (don't clean).

## Getting Max Value

- **Order the checks cheapest-first** — taint + three-way view diff, then auto-load config + unowned `.ko` + `modprobe.d install`, then memory confirmation.
- **`modprobe.d install/alias` is an overlooked no-module persistence** — always grep it.
- **Memory (`linux.check_syscall`/`hidden_modules`) is the only trusted view** — a compromised kernel lies to `lsmod`/`ps`/`ss`.
- **Confirmed kernel rootkit → rebuild** — you cannot trust the host to clean itself.
- **Preserve `initramfs` + `/lib/modules`** so you retain the `.ko` for analysis even after a rebuild.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Trusted-context confirmation | **Memory Forensics** (11), **Rootkit Detection Tooling** (11c) |
| Userland (preload) vs kernel rootkit | **Preload Hijacking** |
| The hidden processes/ports the module conceals | **Live Response** (10), **Rootkit Detection Tooling** (11c) |
| Reverse the `.ko` | **ELF and Malware Triage** (11b) |
| Taint / signing / lockdown state | **SELinux AppArmor and Kernel Hardening** (05) |
| Rebuild decision + eradication | **Remediation and Containment** (14) |

## Scenarios

- **Self-hiding LKM:** Diamorphine/Reptile removes itself from `lsmod` — caught by the three-way view diff and memory.
- **No-`.ko` persistence:** a `modprobe.d install` directive runs the attacker's command at module load.
- **Auto-load:** `/etc/modules` names the rootkit module so it reloads every boot.
- **ftrace hook:** a modern rootkit hooks functions via ftrace, visible in `enabled_functions`/memory.
- **Magic root:** `kill -64` grants root and `kill -63` toggles hiding — a behavioral signature.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| Kernel `tainted` nonzero (out-of-tree/unsigned) | Unexpected module loaded |
| `lsmod` ≠ `/proc/modules` ≠ `/sys/module` | Module hiding itself |
| Unowned `.ko` in the modules tree / unknown entry in `/etc/modules` | Auto-load persistence |
| Hidden processes/ports (`unhide`) with no visible module | Rootkit concealment |
| `check_syscall`/`check_afinfo` hooked (memory) | Confirmed kernel rootkit → rebuild |
| `dmesg` "module verification failed" | Unsigned module force-loaded |
| `install`/`alias` command line in `/etc/modprobe.d/` | No-`.ko` root code execution at load |
| ftrace `enabled_functions` hooking core syscalls | Modern (ftrace) rootkit |

## Resources

- `lsmod(8)`, `modinfo(8)`, `modprobe(8)`, `modprobe.d(5)`, kernel taint reference — https://docs.kernel.org/admin-guide/tainted-kernels.html
- MITRE ATT&CK: T1547.006 (Kernel Modules and Extensions), T1014 (Rootkit), T1601.001 (Patch System Image)
