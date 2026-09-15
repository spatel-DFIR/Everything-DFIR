# Memory Forensics

Memory holds what disk and even `/proc` can't retain: processes a rootkit hides from the task list, injected and unpacked code, decrypted payloads, kernel structures a rootkit has hooked, and network state that's already torn down. On Linux, memory forensics is also the definitive way to *confirm* a rootkit — you compare what the kernel's raw structures say against what the userland tools report, and the discrepancy is the rootkit. Because RAM is the most volatile evidence tier, capture it first, before any invasive action, and record the exact kernel version so you can actually parse the image later.

> 🔴 Two acquisition rules make or break the case. **Write the memory image to external/mounted evidence storage, never the host's own disk** (you'd overwrite the unallocated space you might need). And **record `uname -r` at capture time** — Linux memory analysis needs a symbol table matching the *exact* running kernel, and without it Volatility can't parse the image at all.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Live proc First](#live-proc-first)
- [Acquiring Memory](#acquiring-memory)
- [Record the Kernel Version](#record-the-kernel-version)
- [Building the Symbol Table](#building-the-symbol-table)
- [Volatility 3 Linux](#volatility-3-linux)
- [Swap and Deleted Content](#swap-and-deleted-content)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Capture RAM with AVML (statically linked, no build needed) - do this early
sudo ./avml /evidence/mem.lime

# Record the exact kernel for symbol tables
uname -r > /evidence/kernel_version.txt

# Meanwhile, harvest volatile /proc state (see Live Response note)
ls -l /proc/*/exe 2>/dev/null | grep -E "deleted|memfd"
```

## What to Check for What

| Investigative question | Volatility 3 plugin / action |
|------------------------|------------------------------|
| Hidden process (rootkit)? | `linux.psscan` vs `linux.pslist` |
| Kernel rootkit (hooks)? | `linux.check_syscall`, `linux.check_afinfo`, `linux.hidden_modules` |
| Process illegitimately root? | `linux.check_creds` |
| Injected/unpacked code? | `linux.malfind` (`--dump` to extract) |
| Typed commands (history-proof)? | `linux.bash` |
| Network state (torn-down too)? | `linux.sockstat` |
| No prebuilt symbols for this kernel? | build an ISF with `dwarf2json` |
| Secrets paged to disk? | string/YARA the swap image |
| Just one process's binary/env? | `/proc/PID/exe`, `/proc/PID/environ` (no image needed) |

## Live proc First

Before (or alongside) a full RAM image, `/proc` gives you immediate memory-derived evidence with no tooling and no symbol table — see the Live Response note for the full workup. The essentials worth grabbing straight away, because they come from the process's live memory:

```bash
# Recover a running (possibly deleted) binary from memory
cp /proc/<PID>/exe /evidence/pid_<PID>.bin

# Dump a process's readable memory regions
cat /proc/<PID>/maps        # region map

# Environment + cmdline straight from process memory
tr '\0' '\n' < /proc/<PID>/environ

tr '\0' ' ' < /proc/<PID>/cmdline
```

Think of `/proc` as targeted, no-setup memory forensics: if you only need one process's binary or environment, you don't need a full image or a symbol table. The full RAM capture is for the questions `/proc` can't answer — hidden processes, kernel hooks, torn-down connections.

## Acquiring Memory

Modern kernels block `/dev/mem` and `/dev/kmem` for full RAM access, so use a purpose-built acquirer. AVML is the easiest (a single static binary, no kernel module to build); LiME is the classic module-based approach.

| Tool | Notes |
|------|-------|
| **AVML** | Statically linked userland tool; no kernel module to compile; outputs LiME format. Easiest for most hosts. |
| **LiME** | Loadable kernel module; must be built/matched to the running kernel; reliable and widely used. |
| **`/proc/kcore`** | Live kernel-memory view (ELF); partial, but works with no extra tooling in a pinch. |

```bash
# AVML - single static binary, writes a LiME-format image
sudo ./avml /evidence/$(hostname)-$(date -u +%Y%m%dT%H%M%SZ).lime

# LiME - load the module, dump to a file (format=lime)
sudo insmod ./lime.ko "path=/evidence/mem.lime format=lime"

# Last resort: kcore (no module) - large/partial
sudo cp /proc/kcore /evidence/kcore.img     # or analyze in place
```

🔴 Hash the image immediately (`sha256sum`) and store the hash separately — memory images are large and a truncated or corrupted capture is worse than none because it can mislead. And again: write to external storage, not the subject disk.

## Record the Kernel Version

Volatility 3 parses a Linux image using an **Intermediate Symbol File (ISF)** that must match the exact running kernel. Capture everything you'll need to obtain or build one, or the acquisition is unusable.

```bash
# Exact kernel release + build
uname -r

uname -a > /evidence/uname.txt

# Kernel banner (Volatility reads this from the image too)
cat /proc/version > /evidence/proc_version.txt

# If available, grab the matching debug symbols / System.map for ISF generation
ls -l /boot/System.map-$(uname -r) /usr/lib/debug/boot/ 2>/dev/null
```

This step is what turns a raw memory dump into analyzable evidence — the banner in `/proc/version` is how Volatility confirms it has the right symbols, and `System.map`/debug packages are what you use to build the ISF if a prebuilt one doesn't exist for that kernel.

## Building the Symbol Table

🔴 The usual blocker in Linux memory forensics: Volatility has **no prebuilt ISF** for the target kernel (Linux kernels are legion; unlike Windows there's no symbol server). Build one yourself with **`dwarf2json`** from the kernel's DWARF debug info + `System.map`.

```bash
# 1. Get the debug kernel (vmlinux WITH symbols) — install the distro's dbgsym/debuginfo
#    Debian/Ubuntu: linux-image-$(uname -r)-dbgsym   RHEL: kernel-debuginfo
apt-get install linux-image-$(uname -r)-dbgsym 2>/dev/null   # or dnf debuginfo-install kernel

# 2. Build the ISF JSON from the debug kernel + System.map
dwarf2json linux \
  --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
  --system-map /boot/System.map-$(uname -r) > "$(uname -r).json"

# 3. Drop it where Volatility looks for symbols
cp "$(uname -r).json" ~/.local/lib/python*/site-packages/volatility3/symbols/linux/
```

> ℹ️ Grab `System.map` and the debug kernel *from the subject host or its exact package version* at capture time — a mismatched symbol table parses garbage. This is why recording `uname -r` and `/proc/version` up front is non-negotiable.

## Volatility 3 Linux

The high-value plugins are the ones that expose what userland can't see — hidden processes, hooked syscalls, injected code, and recovered command history.

```bash
# Confirm the image + pull the kernel banner (verify symbol match)
vol -f mem.lime banners.Banners

# Process listing (from kernel task list)
vol -f mem.lime linux.pslist.PsList

# Hidden processes (task list vs scan discrepancy = rootkit)
vol -f mem.lime linux.psscan.PsScan

vol -f mem.lime linux.pstree.PsTree

# Injected / anomalous memory regions
vol -f mem.lime linux.malfind.Malfind

# Loaded kernel modules (compare to lsmod from the live host)
vol -f mem.lime linux.lsmod.Lsmod

# Rootkit checks - syscall table and network hooks
vol -f mem.lime linux.check_syscall.Check_syscall

vol -f mem.lime linux.check_afinfo.Check_afinfo

# Network connections from memory
vol -f mem.lime linux.sockstat.Sockstat

# Recovered bash history from memory
vol -f mem.lime linux.bash.Bash

# Per-process environment variables
vol -f mem.lime linux.envars.Envars

# Open files
vol -f mem.lime linux.lsof.Lsof

# Process with tampered credentials (rootkit silently gave it uid 0)
vol -f mem.lime linux.check_creds.Check_creds

# Hidden kernel modules (not in the module list)
vol -f mem.lime linux.hidden_modules.Hidden_modules

# Dump a suspect process's memory / injected regions for reversing
vol -f mem.lime linux.malfind.Malfind --dump

vol -f mem.lime linux.pslist.PsList --pid <PID> --dump
```

🔴 The moves that catch what everything else misses: **`psscan` vs `pslist`** (a process present in the memory scan but absent from the kernel task list is hidden by a rootkit); **`check_syscall`/`check_afinfo`** (a hooked syscall table or network function *is* a kernel rootkit); **`malfind`** (injected or unpacked executable code in a process); and **`bash`** (recovers typed commands from memory even when the on-disk history was disabled or cleared — often the only record of what an attacker did).

## Swap and Deleted Content

```bash
# Swap devices/files (may hold paged-out process memory, incl. secrets)
swapon --show; cat /proc/swaps

# Search swap for strings (offline, on the image copy)
strings -a /evidence/swap.img | grep -Ei "password|BEGIN .*PRIVATE KEY|token="
```

Swap can preserve credentials and payload fragments that were paged out of RAM — image the swap device/file alongside memory when the case warrants, and string-search it for secrets that left main memory but persisted on disk.

## Deep Threat Hunts

The confirm-the-rootkit + recover-the-hidden workflow. *(seasoned-DFIR; work on the image copy)*

```bash
# 1. Hidden process: memory scan vs kernel task list
vol -f mem.lime linux.psscan.PsScan; vol -f mem.lime linux.pslist.PsList
#   a PID in psscan but not pslist = hidden by a rootkit

# 2. Kernel rootkit: hooks + hidden modules + tampered creds
vol -f mem.lime linux.check_syscall.Check_syscall

vol -f mem.lime linux.check_afinfo.Check_afinfo

vol -f mem.lime linux.hidden_modules.Hidden_modules

vol -f mem.lime linux.check_creds.Check_creds

# 3. Injected/unpacked code — and dump it for reversing
vol -f mem.lime linux.malfind.Malfind --dump

# 4. Recovered typed commands (history-proof)
vol -f mem.lime linux.bash.Bash

# 5. Dump a suspect process's binary/memory from the image
vol -f mem.lime linux.pslist.PsList --pid <PID> --dump

# 6. YARA + strings over the raw image (IOCs, keys, C2)
yara -r rules.yar /evidence/mem.lime 2>/dev/null

strings -a /evidence/mem.lime | grep -Ei 'BEGIN .*PRIVATE KEY|password=|/dev/tcp/|http://'

# 7. For a VM: snapshot guest RAM from the HYPERVISOR (cleaner than in-guest AVML)
virsh dump <domain> /evidence/guest.mem --memory-only --live   # KVM/libvirt; VMware = .vmem
```

**Hunt ideas:**

- **Building the ISF is the usual blocker** — `dwarf2json` against `System.map` + a debug kernel unblocks parsing when no prebuilt symbols exist.
- **`psscan` vs `pslist` and `check_creds`** catch what the live host hides — a hidden process, or a process a rootkit silently promoted to uid 0.
- **`linux.bash` recovers typed commands from RAM** even when on-disk history was disabled — often the *only* record of what the attacker did.
- **`malfind --dump` extracts injected/unpacked code** for reversing (→ ELF triage).
- **For a VM, snapshot guest RAM from the hypervisor** (`virsh dump` / `.vmem`) — cleaner and less invasive than in-guest AVML.

## Getting Max Value

- **Capture FIRST, to external storage, and record `uname -r` + `/proc/version`** — no matching symbols = an unparseable image.
- **Hash the image immediately** — a truncated capture misleads worse than none.
- **Build the ISF with `dwarf2json`** if no prebuilt exists — the key unblock for Linux.
- **`/proc` is targeted, no-symbol memory forensics** for a single process; the full image is for hidden processes, kernel hooks, and torn-down connections.
- **Image swap too**, and string/YARA the raw image for secrets and IOCs.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Live `/proc` equivalent (no image) | **Live Response and Volatile Data** (10) |
| Confirm an LKM / preload rootkit | **Kernel Modules and LKM**, **Preload Hijacking**, **Rootkit Detection** (11c) |
| Reverse a dumped payload | **ELF and Malware Triage** (11b) |
| YARA-scan the image / carved files | **IOC and YARA Scanning** (11d) |
| Acquire properly + chain of custody | **Evidence Collection and Triage** (12) |
| VM/container guest memory | **Container** section, **Enterprise** (VM snapshot) |

## Scenarios

- **Rootkit confirmation:** `psscan`/`check_syscall` prove a hidden process or a hooked kernel — the trigger to rebuild.
- **History recovery:** `linux.bash` pulls the attacker's commands that were wiped from disk.
- **Code injection:** `malfind` finds unpacked/injected code; `--dump` extracts it to reverse.
- **Credential tampering:** `check_creds` shows a process illegitimately running as uid 0.
- **Swap secrets:** keys/passwords paged out of RAM recovered from the swap image.
- **No-symbols blocker:** build the ISF with `dwarf2json` to make the image parseable.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `psscan` shows a process `pslist` doesn't | Hidden process (rootkit) |
| `check_syscall`/`check_afinfo` hooks | Kernel-level rootkit |
| `malfind` injected/executable anon regions | Code injection / unpacked payload |
| `lsmod` (memory) ≠ `lsmod` (live host) | Module hiding |
| Recovered bash history absent from disk | On-disk history was disabled/cleared |
| Credentials/keys found in swap | Secrets paged out to disk |
| `check_creds` shows a process illegitimately uid 0 | Rootkit credential tampering |
| `hidden_modules` finds a module not in the list | Concealed LKM |

## Resources

- Volatility 3 (Linux) — https://volatilityfoundation.org
- AVML — https://github.com/microsoft/avml
- LiME — https://github.com/504ensicsLabs/LiME
- dwarf2json (build ISF symbols) — https://github.com/volatilityfoundation/dwarf2json
- MITRE ATT&CK: T1014 (Rootkit), T1055 (Process Injection), T1620 (Reflective Loading), T1003 (Credential Dumping), T1070.003 (Clear History)
