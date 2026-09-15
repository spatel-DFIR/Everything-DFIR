# Rootkit Detection Tooling

The Rootkit Playbook covers the manual detection-by-inconsistency method; this note is the tooling companion — the purpose-built scanners (`rkhunter`, `chkrootkit`, `unhide`) and the deeper Volatility checks that automate finding what a rootkit hides. The framing that matters: on a host you *suspect* is rootkitted, you cannot fully trust the tools running on it (a kernel rootkit can lie to any of them), so these scanners are a first pass, and memory analysis from a trusted context is the confirmation. Use the tools to raise suspicion fast, then prove it in RAM.

> 🔴 A userland scanner running on a compromised host is querying the very kernel that may be lying to it — so a *clean* result from `rkhunter`/`chkrootkit` does **not** clear the host. Their *positive* findings are valuable; their negative ones aren't conclusive. Confirm anything serious with memory forensics (`psscan` vs `pslist`, `check_syscall`), which sees past the kernel's lies.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [unhide Hidden Processes and Ports](#unhide-hidden-processes-and-ports)
- [rkhunter](#rkhunter)
- [chkrootkit](#chkrootkit)
- [Integrity and FIM as Detection](#integrity-and-fim-as-detection)
- [Manual Cross-View Checks](#manual-cross-view-checks)
- [Volatility Rootkit Plugins](#volatility-rootkit-plugins)
- [Interpreting Results](#interpreting-results)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Hidden processes: brute-force PID space vs /proc and ps
unhide brute; unhide proc; unhide sys

# Hidden TCP/UDP ports
unhide-tcp

# Signature + heuristic rootkit scan
rkhunter --check --sk

# Classic rootkit signature scan
chkrootkit

# Kernel taint (out-of-tree/unsigned module = LKM rootkit hint)
cat /proc/sys/kernel/tainted
```

## What to Check for What

| Investigative question | Tool |
|------------------------|------|
| Hidden process (novel or known)? | `unhide brute/proc/sys`; `/proc` walk vs `ps` |
| Hidden listening port? | `unhide-tcp` |
| Known rootkit signature? | `chkrootkit`, `rkhunter --check` |
| Trojaned `ps`/`ls`/`netstat`/`sshd`? | `rpm -Va`/`debsums`; AIDE/Tripwire |
| Active libc hooking? | trusted static tool (`busybox`) vs dynamic |
| Kernel rootkit (conclusive)? | memory: `psscan` vs `pslist`, `check_syscall`, `hidden_modules` |
| Is a clean scan trustworthy? | **No** on a suspected host — only memory clears it |
| Rebuild or clean? | kernel-confirmed = rebuild; userland preload = clean in place |

## unhide Hidden Processes and Ports

`unhide` is the most directly useful tool because it finds *hidden* things by comparing independent enumeration methods — exactly the inconsistency a rootkit creates. It doesn't rely on signatures, so it catches novel rootkits.

```bash
# Find hidden processes by three independent techniques
unhide brute      # brute-force the entire PID space, compare to /proc + ps

unhide proc       # compare /proc entries vs ps output

unhide sys        # compare system-call results vs /proc

# Find hidden listening ports (a socket ps/ss won't show)
unhide-tcp
```

🔴 A process reported by `unhide` that `ps` doesn't list, or a port from `unhide-tcp` that `ss` doesn't show, is a hidden artifact — a rootkit is concealing it. This is the automated version of the cross-view method, and it's the single highest-value rootkit-detection tool on a live host.

## rkhunter

Rootkit Hunter checks for known rootkit signatures, suspicious file properties, modified system binaries, and common backdoor indicators.

```bash
# Full check, skip the "press enter" prompts
rkhunter --check --sk

# Update signature databases first (if you have connectivity)
rkhunter --update

# Review the detailed log
cat /var/log/rkhunter.log | grep -iE "warning|found|suspect"

# Establish/verify a known-good file-property baseline
rkhunter --propupd    # baseline (do on a KNOWN-CLEAN host, not the victim)
```

`rkhunter` flags modified system binaries, hidden files, suspicious ports, and known rootkit artifacts. Treat its `Warning` lines as leads to verify — it produces false positives, so confirm each rather than acting on it blindly.

## chkrootkit

`chkrootkit` runs a battery of signature and behavioral checks for well-known rootkits and trojaned binaries.

```bash
# Run all checks
chkrootkit

# Focus on the meaningful verdicts
chkrootkit 2>/dev/null | grep -iE "INFECTED|suspicious|vulnerable"
```

🔴 An `INFECTED` verdict naming a specific rootkit, or "suspicious" findings on core binaries (`ps`, `netstat`, `ls`, `login`), warrants immediate escalation to memory analysis — but note `chkrootkit` also has known false positives (e.g. on some `INFECTED` PHP/`bindshell` checks), so verify.

## Integrity and FIM as Detection

🔴 A userland rootkit's tell is *modified system binaries* (`ps`/`ls`/`netstat`/`sshd` patched to hide the attacker) — so package integrity and file-integrity monitoring are direct rootkit detectors, and they don't rely on rootkit signatures.

```bash
# Package integrity: a hash mismatch on a core binary = trojaned
rpm -Va 2>/dev/null | grep -E '^..5' | grep -E '/bin|/sbin'

debsums -c 2>/dev/null

# AIDE / Tripwire: compare against a pre-seeded baseline DB (the reliable catch)
aide --check 2>/dev/null | grep -iE 'changed|added'

# Wazuh/OSSEC rootcheck + Linux Malware Detect are additional layers
maldet -a / 2>/dev/null
```

🔴 If an **AIDE/Tripwire baseline** was captured before the incident, its diff is the most reliable "what changed" for system binaries and configs — far less false-positive-prone than signature scanners. (Cross-ref Package Managers for the `rpm --rebuilddb` caveat: verify hashes against a clean package if a DB rebuild is suspected.)

## Manual Cross-View Checks

The tools automate these, but knowing the manual checks lets you verify a finding and works when a tool isn't installed (see the Rootkit Playbook for the full set):

```bash
# Processes: /proc walk vs ps
comm -23 <(ls -d /proc/[0-9]* | xargs -n1 basename | sort) <(ps -eo pid --no-headers | tr -d ' ' | sort)

# Modules: lsmod vs /proc/modules vs /sys/module
diff <(lsmod | awk 'NR>1{print $1}' | sort) <(ls /sys/module | sort)

# ld.so.preload (userland rootkit)
cat /etc/ld.so.preload 2>/dev/null

# Fake kernel-thread names with a real exe
for p in /proc/[0-9]*; do c=$(cat "$p/comm" 2>/dev/null); case "$c" in \[*\]) [ -s "$p/cmdline" ] && echo "FAKE: $p $c";; esac; done

# Bypass preload/libc hooks with a TRUSTED static tool, then compare
busybox ps -ef | wc -l; ps -ef | wc -l          # count mismatch = hidden PIDs
busybox ls -la /suspect/dir; ls -la /suspect/dir # file mismatch = readdir hook
```

## Volatility Rootkit Plugins

Memory analysis is the trusted-context confirmation — it reads kernel structures directly rather than asking the (possibly compromised) kernel. See the Memory Forensics note for acquisition.

```bash
# Hidden processes: scan vs list
vol -f mem.lime linux.psscan.PsScan     # compare to linux.pslist.PsList

# Hooked syscall table (kernel rootkit)
vol -f mem.lime linux.check_syscall.Check_syscall

# Hooked network functions
vol -f mem.lime linux.check_afinfo.Check_afinfo

# Modules in memory vs lsmod on the host
vol -f mem.lime linux.lsmod.Lsmod

# Injected code in processes
vol -f mem.lime linux.malfind.Malfind
```

🔴 `psscan` finding a process `pslist` doesn't, or `check_syscall` showing a hooked entry, is *conclusive* rootkit evidence — it comes from the raw memory image, not from the compromised kernel's cooperation. This is what turns a scanner's suspicion into proof.

## Interpreting Results

- **A positive finding** from any tool is a lead — verify it (false positives are common) and, if confirmed, escalate.
- **A clean result** clears nothing on a suspected host — the tool may have been lied to. Only a trusted-context check (memory) can clear it.
- **Kernel taint set** + a scanner hit + a memory-confirmed hidden process = a kernel rootkit → rebuild, don't clean (see Remediation).
- **`ld.so.preload` populated** with no scanner kernel findings = a userland rootkit, removable in place (but still rotate credentials).

## Deep Threat Hunts

Layered detection — scanners raise suspicion, memory confirms. *(seasoned-DFIR)*

```bash
# 1. unhide: all hidden-process techniques + hidden ports (catches NOVEL rootkits)
unhide brute; unhide proc; unhide sys; unhide-tcp

# 2. Signature scanners (positive = lead; clean != clear)
rkhunter --check --sk 2>/dev/null | grep -iE 'warning|found'

chkrootkit 2>/dev/null | grep -iE 'INFECTED|suspicious'

# 3. Integrity/FIM as detection (trojaned ps/ls/netstat/sshd)
rpm -Va 2>/dev/null | grep -E '^..5' | grep -E '/bin|/sbin'; debsums -c 2>/dev/null; aide --check 2>/dev/null

# 4. Bypass hooks with a trusted static tool, compare
busybox ps -ef | wc -l; ps -ef | wc -l

# 5. Manual cross-view (works with no tools installed)
comm -23 <(ls -d /proc/[0-9]* | xargs -n1 basename | sort -n) <(ps -eo pid= | tr -d ' ' | sort -n)

# 6. TRUSTED confirmation in memory (the proof + rebuild trigger)
vol -f mem.lime linux.psscan.PsScan; vol -f mem.lime linux.check_syscall.Check_syscall

vol -f mem.lime linux.hidden_modules.Hidden_modules; vol -f mem.lime linux.check_creds.Check_creds

# 7. eBPF-based live detection (Tracee/Falco rule matches)
tracee --output json 2>/dev/null | head
```

**Hunt ideas:**

- **A CLEAN scan clears nothing on a suspected host** — the kernel may be lying to the scanner; only memory (trusted context) can clear it. Positive findings, though, are always leads.
- **Integrity (`rpm -Va`/`debsums`/AIDE) *is* rootkit detection** — a modified `ps`/`ls`/`netstat`/`sshd` is a userland rootkit component.
- **`unhide brute` catches novel rootkits** by brute-forcing the entire PID space — no signature needed.
- **Bypass hooks with a trusted static `busybox`** and compare — a discrepancy is active libc hooking.
- **Confirm anything serious in memory** (`psscan`/`check_syscall`/`hidden_modules`) — that's what turns a scanner's guess into proof and the rebuild decision.

## Getting Max Value

- **Layer the detection:** scanners (fast, false-positive-prone) → integrity/FIM → trusted-static-tool cross-view → **memory confirmation**.
- **Never trust a clean scan** on a suspected host.
- **Positive + kernel taint + memory-confirmed hidden process = kernel rootkit → rebuild** (don't clean).
- **`ld.so.preload` populated + no kernel findings = userland rootkit** — removable in place, but rotate credentials.
- **Baseline (`rkhunter --propupd`, AIDE) on a KNOWN-CLEAN host**, never on the victim.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| The manual detection-by-inconsistency method | **Linux Rootkit Playbook** (15) |
| Kernel-rootkit confirmation | **Kernel Modules and LKM**, **Memory Forensics** (11) |
| Userland (preload) rootkit | **Preload Hijacking** |
| Trojaned-binary confirmation | **Package Managers and Integrity** (08), **ELF and Malware Triage** (11b) |
| Live cross-view / static-tool bypass | **Live Response and Volatile Data** (10) |
| Rebuild decision + eradication | **Remediation and Containment** (14) |

## Scenarios

- **Novel LKM:** `unhide brute` finds a hidden PID no signature knows; memory confirms; rebuild.
- **Trojaned binaries:** `rpm -Va` + `chkrootkit` flag a modified `ps`/`netstat`.
- **Userland rootkit:** `/etc/ld.so.preload` populated, no kernel findings — clean in place.
- **Clean-scan trap:** `rkhunter` reports clean but memory `psscan` shows a hidden process.
- **FIM catch:** an AIDE baseline flags a modified `/usr/sbin/sshd`.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `unhide`/`unhide-tcp` reports a hidden process or port | Rootkit concealment (novel or known) |
| `chkrootkit` `INFECTED` on a core binary | Trojaned system binary |
| `rkhunter` warns on modified binaries / hidden files | Tampering — verify each |
| `psscan` ≠ `pslist` / `check_syscall` hooked (memory) | Confirmed kernel rootkit → rebuild |
| Populated `/etc/ld.so.preload` | Userland rootkit |
| Kernel `tainted` nonzero | LKM rootkit hint |
| `rpm -Va`/AIDE flags a modified core binary | Trojaned system binary (userland rootkit) |
| `busybox ps`/`ls` disagrees with dynamic tool | Active libc hooking |

## Resources

- `rkhunter`, `chkrootkit`, `unhide` project docs; AIDE — https://aide.github.io ; Wazuh rootcheck
- Volatility 3 (Linux) — https://volatilityfoundation.org
- MITRE ATT&CK: T1014 (Rootkit), T1562.001 (Impair Defenses), T1027 (Obfuscation)
