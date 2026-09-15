# Linux Rootkit Playbook

The host is behaving oddly — a port nothing owns, CPU that doesn't add up, a process you can see in `/proc` but not in `ps` — but standard tools show nothing, because a rootkit is lying to them. This is the detection-by-inconsistency and rebuild-decision playbook.

> 🔴 You catch a rootkit by *comparing views*, not by trusting any single tool — a process or port visible through the kernel's raw interface (`/proc`, `/sys`, memory) but absent from the userland tool (`ps`, `ss`, `lsmod`) is the rootkit hiding it. And the disposition decision is stark: a confirmed **kernel** rootkit means rebuild, not clean, because the compromised kernel can lie to every command you'd use to verify a cleanup.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Detect by Inconsistency](#detect-by-inconsistency)
- [Userland vs Kernel Rootkits](#userland-vs-kernel-rootkits)
- [Confirm with Memory](#confirm-with-memory)
- [Scope](#scope)
- [Eradication and Rebuild Decision](#eradication-and-rebuild-decision)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)

## Attack Chain

Root access obtained → rootkit installed to hide the attacker's processes, files, ports, and logins: either **userland** (`LD_PRELOAD`/`ld.so.preload` hooking libc functions) or **kernel** (LKM hooking syscalls). The rootkit then conceals the persistence, C2, and any miner/backdoor running underneath it.

## Quick Triage

```bash
# The two fastest kernel-rootkit hints
cat /proc/sys/kernel/tainted            # nonzero = out-of-tree/unsigned module

cat /etc/ld.so.preload 2>/dev/null      # populated = userland hooking (almost always bad)

# Loaded modules the userland can see (may be lied to)
lsmod

# Integrity of core tools (a trojaned ps/ss hides things)
rpm -Va 2>/dev/null | grep -E '^..5' | grep -E "/bin/|/sbin/"; debsums -c 2>/dev/null
```

## Detect by Inconsistency

Rootkits hide from one view but not another — compare views to expose the lie.

```bash
# Processes: /proc walk vs ps (a PID in /proc but not ps = hidden)
comm -23 <(ls -d /proc/[0-9]* | xargs -n1 basename | sort) <(ps -eo pid --no-headers | tr -d ' ' | sort)

# Ports: /proc/net vs ss (a socket in /proc/net/tcp but not ss = hidden)
# compare hex-decoded /proc/net/tcp entries to `ss -tan`

# Files/dirs: readdir hooks hide names; stat by direct path still works
ls /some/dir; stat /some/dir/.hidden_guess     # if stat works but ls omits it -> hooked

# Modules: lsmod vs /proc/modules vs /sys/module
diff <(lsmod | awk 'NR>1{print $1}' | sort) <(ls /sys/module | sort)

# Link count vs visible entries in a dir (readdir hiding)
ls -la /etc | wc -l; stat -c %h /etc
```

🔴 Any mismatch — a process, port, file, or module visible through the kernel's raw interface (`/proc`, `/sys`) but absent from the userland tool (`ps`, `ss`, `ls`, `lsmod`) — is a rootkit hiding that artifact.

## Userland vs Kernel Rootkits

| | Userland (LD_PRELOAD) | Kernel (LKM) |
|-|-----------------------|--------------|
| Mechanism | Hooks libc calls (`readdir`, `access`) | Hooks syscalls / kernel functions |
| Tell | `/etc/ld.so.preload` set; `LD_PRELOAD` in env/units; a `.so` (often in `/tmp`/`/lib`) | `tainted` set; module in `lsmod`/`/proc/modules`; syscall-table hooks |
| Scope | Only dynamically-linked processes that inherit the preload | Whole system, including static binaries |
| Detect | Read `ld.so.preload`; static-linked tools bypass the hooks | Memory analysis; view mismatches |

```bash
# Userland: the injected library
cat /etc/ld.so.preload; ls -l $(cat /etc/ld.so.preload 2>/dev/null)

# Bypass userland hooks with a statically-linked / busybox tool to see the truth
busybox ps; busybox ls /proc | grep '^[0-9]'

# Kernel: module details
cat /proc/modules; for m in $(lsmod | awk 'NR>1{print $1}'); do modinfo "$m" 2>/dev/null | grep -E "filename|signature|vermagic"; done
```

## Confirm with Memory

Memory analysis sees past the lies (see Memory Forensics note).

```bash
# Acquire RAM first
sudo ./avml /evidence/mem.lime; uname -r > /evidence/kernel.txt

# Hidden processes: scan vs list
vol -f /evidence/mem.lime linux.psscan.PsScan       # compare to linux.pslist

# Syscall / network hooks (kernel rootkit proof)
vol -f /evidence/mem.lime linux.check_syscall.Check_syscall

vol -f /evidence/mem.lime linux.check_afinfo.Check_afinfo

# Modules in memory vs lsmod
vol -f /evidence/mem.lime linux.lsmod.Lsmod
```

## Scope

Once you can see the hidden artifacts, scope what they protect:

```bash
# The hidden process's identity + network
cp /proc/<hidden_pid>/exe /evidence/; cat /proc/<hidden_pid>/cmdline | tr '\0' ' '

# Persistence keeping the rootkit + payload alive (Persistence note)
# What the rootkit was hiding: miner? backdoor? exfil?
```

## Eradication and Rebuild Decision

🔴 **A confirmed kernel rootkit means rebuild, not clean.** You cannot trust a kernel that has been hooking its own syscalls — anything you run to "verify clean" runs through the compromised kernel.

- **Userland-only** (`ld.so.preload` + a `.so`, no kernel taint): removable in place — delete `/etc/ld.so.preload`, remove the `.so`, clear `LD_PRELOAD` from env/units, verify with static tools and a reboot. Still rotate credentials.
- **Kernel rootkit** (taint set, syscall hooks, hidden modules): image + capture evidence, then **rebuild from known-good media**, restore data from a verified-clean backup/snapshot, and rotate every credential the host touched.

```bash
# Userland removal (only if no kernel component)
sudo rm /etc/ld.so.preload; sudo rm <injected.so>
sudo unset LD_PRELOAD    # and scrub it from /etc/environment, units, rc files
```

## Fleet Hunt

IOCs: injected `.so` hash/name, kernel module name, `ld.so.preload` content, the hidden C2 IP.

```bash
# ld.so.preload present anywhere
for h in <hosts>; do ssh "$h" 'cat /etc/ld.so.preload 2>/dev/null; cat /proc/sys/kernel/tainted'; done

# Same module loaded elsewhere
# via osquery/Velociraptor: kernel_modules table / lsmod collection
```

## Correlate With

| Stage / to go deeper on… | Pivot to |
|--------------------------|----------|
| Kernel-rootkit mechanism + `modprobe.d`/ftrace detail | **Kernel Modules and LKM Rootkits** |
| Userland preload rootkit + hook bypass | **Preload Hijacking** |
| Automated scanners + integrity/FIM | **Rootkit Detection Tooling** (11c) |
| Trusted-context confirmation in memory | **Memory Forensics** (11) |
| Live cross-view / static-tool bypass | **Live Response** (10) |
| Trojaned-binary confirmation | **Package Managers** (08), **ELF and Malware Triage** (11b) |
| Rebuild decision + eradication | **Remediation and Containment** (14) |

## Red Flags

| Finding | Meaning |
|---------|---------|
| Process in `/proc` but not `ps` | Hidden process |
| Port in `/proc/net` but not `ss` | Hidden socket |
| `lsmod` ≠ `/proc/modules` ≠ `/sys/module` | Module hiding |
| Kernel `tainted` nonzero / syscall hooks in memory | Kernel rootkit → rebuild |
| Populated `/etc/ld.so.preload` | Userland rootkit |
| Trojaned `ps`/`ss`/`ls` (integrity fail) | Tool-level hiding |
