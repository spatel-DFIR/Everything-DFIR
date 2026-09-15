# Preload Hijacking

The dynamic linker will load a shared library *before* all others if you tell it to — via the `LD_PRELOAD` environment variable or the `/etc/ld.so.preload` file — and the preloaded library can override any libc function. Attackers use this for two things at once: **persistence** (the library loads into processes automatically) and a **userland rootkit** (by hooking `readdir`/`open`/`accept` etc. it hides files, processes, and connections without touching the kernel). It's a favorite because it's powerful, portable, and needs no kernel module.

> 🔴 A populated `/etc/ld.so.preload` is almost always malicious on a normal host — it injects a library into **every dynamically-linked process on the system**. That's the single fastest userland-rootkit check on Linux. `LD_PRELOAD` set in the environment, a systemd unit, or a profile script is the per-process/per-service variant.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [How the Persistence Works](#how-the-persistence-works)
- [The Two Preload Vectors](#the-two-preload-vectors)
- [Hunting ld.so.preload](#hunting-ldsopreload)
- [Hunting LD_PRELOAD in the Environment](#hunting-ld_preload-in-the-environment)
- [Per-Process Detection](#per-process-detection)
- [Bypassing the Hooks with Static Tools](#bypassing-the-hooks-with-static-tools)
- [Analyzing the Preloaded Library](#analyzing-the-preloaded-library)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# The system-wide preload file (loads a .so into EVERY dynamically-linked process)
cat /etc/ld.so.preload 2>/dev/null

# Env-based preload across common config locations
grep -rIE "LD_PRELOAD|LD_LIBRARY_PATH" /etc/environment /etc/profile* /home/*/.*rc /home/*/.profile \
  /etc/systemd/system/*.service /usr/lib/systemd/system/*.service 2>/dev/null

# Any process running right now with LD_PRELOAD set
for p in /proc/[0-9]*; do tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -q LD_PRELOAD && echo "$p: $(tr '\0' '\n' < "$p/environ" | grep LD_PRELOAD)"; done
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| System-wide userland rootkit? | `cat /etc/ld.so.preload` (should not exist) |
| Per-service/user injection? | `grep -rI LD_PRELOAD /etc/systemd /etc/profile* /home/*/.*rc` |
| Live process carrying a preload? | `/proc/*/environ` + `/proc/*/maps` |
| Preload lib deleted but in memory? | `grep '(deleted)' /proc/*/maps \| grep .so` |
| Is the rootkit hiding files/PIDs? | `busybox ls`/`ps` vs `ls`/`ps` (bypass the hook) |
| What does the library hook? | `readelf --dyn-syms preload.so \| grep readdir\|open\|accept` |
| What does it hide (prefix/port)? | `strings preload.so` |
| Armored against removal? | `lsattr /etc/ld.so.preload` (`+i`) |

## How the Persistence Works

The attacker points the loader at a malicious `.so`. Because the loader honors it for (nearly) every dynamically-linked binary, the library ends up inside processes automatically — both a persistence mechanism (it keeps loading) and a hooking point (it can intercept any libc call).

```bash
# System-wide (persistence + rootkit for all processes):
echo "/usr/lib/libc_ext.so" > /etc/ld.so.preload    # 🔴 loads into everything

# Per-service (persistence for one daemon), e.g. in its systemd unit:
#   Environment=LD_PRELOAD=/dev/shm/.h.so
```

🔴 A rootkit library commonly hooks `readdir`/`readdir64` (to hide files/PIDs from `ls` and `/proc` walks), `open`/`fopen` (to hide file contents), and `accept`/`recvmsg` (to hide C2 connections) — so the *same* preload that persists the attacker also blinds your standard tools. Statically-linked tools (busybox) bypass the hooks and reveal the truth.

## The Two Preload Vectors

| Vector | Scope | Where it lives |
|--------|-------|----------------|
| 🔴 `/etc/ld.so.preload` | **Every** dynamically-linked process | A file listing `.so` paths |
| `LD_PRELOAD` env var | The processes that inherit it | `/etc/environment`, profile scripts, systemd `Environment=`, a launcher's env |

`ld.so.preload` is the system-wide rootkit vector; `LD_PRELOAD` in the environment is narrower (only affects processes that inherit that env) but stealthier because there's no single file to check — you have to look in every place an env var can be set.

## Hunting ld.so.preload

```bash
# Is it present + what does it reference?
cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/ld.so.preload 2>/dev/null

# Inspect each referenced library
for so in $(cat /etc/ld.so.preload 2>/dev/null); do echo "== $so =="; ls -la "$so"; file "$so"; done

# Is /etc/ld.so.preload immutable (armored)?
lsattr /etc/ld.so.preload 2>/dev/null
```

🔴 On a normal host `/etc/ld.so.preload` should not exist or be empty. Any entry — especially a `.so` in `/tmp`, `/dev/shm`, `/usr/lib` with a recent mtime, or a name mimicking a real library (`libc_ext.so`, `libselinux.so.9`) — is the userland rootkit's library. It's often set `+i` immutable so `rm` fails.

## Hunting LD_PRELOAD in the Environment

```bash
# System-wide env
grep -RIE "LD_PRELOAD|LD_LIBRARY_PATH" /etc/environment /etc/profile /etc/profile.d/* /etc/bash.bashrc 2>/dev/null

# Per-user env
grep -RIE "LD_PRELOAD|LD_LIBRARY_PATH" /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /root/.bashrc 2>/dev/null

# systemd units (per-service injection)
grep -rIE "LD_PRELOAD" /etc/systemd/system /usr/lib/systemd/system /run/systemd/system 2>/dev/null

# EnvironmentFile references that might set it
grep -rIE "EnvironmentFile" /etc/systemd/system 2>/dev/null
```

## Per-Process Detection

The definitive live check: which running processes actually have a preload set.

```bash
# Every process with LD_PRELOAD in its environment
for p in /proc/[0-9]*; do
  v=$(tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E "LD_PRELOAD|LD_LIBRARY_PATH")
  [ -n "$v" ] && echo "PID $(basename "$p") ($(cat "$p/comm" 2>/dev/null)): $v"
done

# The preloaded library shows in the process's maps
grep -l "\.so" /proc/*/maps 2>/dev/null | head    # then inspect a suspect PID's maps
cat /proc/<PID>/maps | grep -iE "/tmp|/dev/shm|preload"
```

🔴 A running process whose `environ` sets `LD_PRELOAD` to a `.so` in `/tmp`/`/dev/shm`, or whose `maps` shows a preloaded library from an odd path, is carrying the injected code — recover the `.so` for analysis (see the ELF and Malware Triage note).

> ℹ️ `environ` shows `LD_PRELOAD` only as of `exec`; a process that unset it after loading won't show it there. The library's presence in `/proc/PID/maps` is the more reliable live proof — and a preload `.so` **deleted from disk** still lives in `maps`.

## Bypassing the Hooks with Static Tools

🔴 The preload rootkit hooks libc functions (`readdir`, `open`, `accept`), so *dynamically-linked* tools (`ls`, `ps`, `ss`) are lied to. A **statically-linked** tool doesn't call the hooked libc — so comparing its output against the dynamic tool's output reveals exactly what's hidden.

```bash
# Files hidden from `ls` (readdir hook) — busybox is static and bypasses it
busybox ls -la /suspect/dir; echo "---"; ls -la /suspect/dir

# Processes hidden from `ps` — count mismatch = hidden PIDs
busybox ps -ef | wc -l; ps -ef | wc -l

# Confirm a hidden file exists by inode even though ls won't show it
busybox find / -inum <inode> 2>/dev/null
```

A discrepancy between the static and dynamic tool is proof of active hooking, and the delta *is* the hidden artifact set. (The kernel-module analog — `/proc` walk vs `ps` — is in the LKM note.)

## Analyzing the Preloaded Library

```bash
# What functions does it hook? (hooked libc symbols in the dynamic symbol table)
readelf --dyn-syms /path/preload.so | grep -iE "readdir|open|fopen|accept|access|unlink|execve|pam"

# Readable indicators (hidden-file prefixes, C2, magic strings)
strings /path/preload.so | grep -iE "/tmp|/dev/shm|magic|hide|\.so|http"
```

🔴 A preload library exporting `readdir`/`open`/`accept` (the functions it's overriding to hide artifacts) confirms it's a rootkit, and its strings often reveal *what* it hides (a filename prefix, a port, a magic value) — which tells you what else to look for.

## Deep Threat Hunts

Fastest-check-first, then confirm by hook-bypass. *(seasoned-DFIR)*

```bash
# 1. The single fastest userland-rootkit check
cat /etc/ld.so.preload 2>/dev/null; lsattr /etc/ld.so.preload 2>/dev/null

# 2. Every live process carrying a preload (environ) + odd libs in maps
for p in /proc/[0-9]*; do
  v=$(tr '\0' '\n' < "$p/environ" 2>/dev/null | grep LD_PRELOAD); [ -n "$v" ] && echo "$(cat $p/comm 2>/dev/null) $p: $v"
done

# 3. Preload lib DELETED from disk but still mapped (in-memory only)
grep -h '(deleted)' /proc/*/maps 2>/dev/null | grep -Ei '\.so'

# 4. Bypass the hooks: static vs dynamic tool (the delta = hidden artifacts)
busybox ls -la /tmp /dev/shm; echo ---; ls -la /tmp /dev/shm

# 5. LD_PRELOAD across every env-set location
grep -RIE 'LD_PRELOAD' /etc/environment /etc/profile* /etc/ld.so.preload \
  /etc/systemd/system /usr/lib/systemd/system /home/*/.*rc /root/.*rc 2>/dev/null

# 6. What the library hooks + what it hides
readelf --dyn-syms /path/preload.so 2>/dev/null | grep -iE 'readdir|open|fopen|accept|pam|execve|unlink'

strings /path/preload.so 2>/dev/null | grep -iE '/tmp|/dev/shm|magic|hide|http|:[0-9]{2,5}'

# 7. Recover a deleted/mapped preload lib for analysis
cp /proc/<PID>/map_files/<addr-range> /evidence/preload.so
```

**Hunt ideas:**

- **`/etc/ld.so.preload` is the fastest userland-rootkit check** — on a normal host it shouldn't exist; any entry is suspect.
- **Beat the hooks with a static tool** — `busybox ls`/`ps` can't be lied to by a libc hook, so a diff against `ls`/`ps` reveals the hidden files/PIDs directly.
- **`environ` shows the preload only as-of-exec** — the reliable live proof is the library in `/proc/PID/maps` (and its deleted-mapping).
- **A preload `.so` is often deleted after loading** — recover it from `/proc/PID/map_files` for analysis.
- **`readelf --dyn-syms` names the hooked functions**, and `strings` often leaks the hidden-file prefix/port — use it to find everything else the rootkit conceals.

## Getting Max Value

- **Order the checks** — `ld.so.preload` first (fastest), then env-based, then live `maps`; then confirm hiding with static tools.
- **Recover the `.so` even if deleted** from `/proc/…/map_files`; `readelf`/`strings` reveal the hooks + IOCs.
- **The library's strings usually leak the hidden prefix/magic** — pivot on it to enumerate everything else the rootkit hides.
- **Removal order matters** — clear `ld.so.preload` (`chattr -i` first), but killing a process reloads it if the persistence remains; coordinate with Remediation.
- **A userland preload is *not* a kernel rootkit** — if `busybox` *also* can't see the hidden artifacts, escalate to the LKM note.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Kernel-level rootkit (if userland tools still lie) | **Kernel Modules and LKM Rootkits** |
| Reverse the preload `.so` | **ELF and Malware Triage** (11b) |
| Recover a deleted/mapped `.so` | **Live Response** (10), **Trash and Deleted** (08) |
| Automated rootkit detection | **Rootkit Detection Tooling** (11c) |
| `LD_PRELOAD` set via shell/env | **Shell Startup and Profile Scripts**, **Shells** (04) |
| Confirm what's hidden / conclusive proof | **Live Response** (view mismatches), **Memory Forensics** (11) |
| Remove it safely | **Remediation and Containment** (14) |

## Scenarios

- **System-wide rootkit:** `/etc/ld.so.preload` points at a `.so` that hooks `readdir`/`open`/`accept` — hides files, PIDs, and C2 for every process.
- **Per-service injection:** `LD_PRELOAD` in a systemd unit injects the library into one daemon.
- **In-memory only:** the preload `.so` is deleted from disk and survives only in `/proc/PID/maps`.
- **Hook bypass:** `busybox ls` reveals files that `ls` hides — proving active `readdir` hooking.
- **Credential harvest:** the preload hooks `pam`/read functions to capture plaintext passwords.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| `/etc/ld.so.preload` present/populated | Userland rootkit loaded system-wide |
| Preloaded `.so` in `/tmp`/`/dev/shm` or with a recent mtime | Injected rootkit library |
| `/etc/ld.so.preload` set `+i` immutable | Armored persistence |
| `LD_PRELOAD` in a systemd unit / profile / env | Per-service or per-user injection |
| Running process with `LD_PRELOAD` in `environ` | Live injected code |
| Preload library exporting `readdir`/`open`/`accept` | Confirmed hooking rootkit |
| `ps`/`ss`/`ls` disagree with `/proc` | The rootkit is hiding artifacts |
| `busybox ls`/`ps` shows files/PIDs the dynamic tool hides | Active libc hooking (proof) |
| Preload `.so` deleted from disk but present in `/proc/*/maps` | In-memory-only rootkit lib |

## Resources

- `ld.so(8)` man page (LD_PRELOAD, /etc/ld.so.preload)
- MITRE ATT&CK: T1574.006 (Dynamic Linker Hijacking), T1014 (Rootkit), T1564 (Hide Artifacts)
