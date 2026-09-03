# SELinux AppArmor and Kernel Hardening

Mandatory Access Control (MAC) is the Linux analog to macOS's SIP/TCC layer, and it matters to DFIR in three ways at once: it *constrains* what a compromised process can do, it *logs* the attacker when they hit its boundaries, and *disabling it* is itself a recognizable attacker technique. The denials it records are frequently the clearest evidence of the intrusion — a webshell trying to bind a socket, `httpd` trying to exec a shell — so learning to read them turns a hardening feature into a detection source.

> 🔴 Don't skim past the denials. An `avc: denied` (SELinux) or `apparmor="DENIED"` (AppArmor) is the policy catching the attacker's payload doing something the legitimate service never does. A **burst of denials that suddenly stops** is worse news, not better — it usually means the attacker relabeled a file or flipped a boolean to *allow* their action, so the silence is the success.

> ⚠️ **Many hosts run no MAC at all.** SELinux is RHEL/Fedora's default and AppArmor is Debian/Ubuntu/SUSE's, but **Alpine and Arch ship with neither** (and minimal containers rarely add one). Confirm with `cat /sys/kernel/security/lsm` — if it lists only `capability`/`yama`/`lockdown`, there's no MAC layer here, so skip to the kernel-hardening checks below and rely on other telemetry.

## Contents

- [Quick Triage](#quick-triage)
- [Where the MAC and Hardening State Lives](#where-the-mac-and-hardening-state-lives)
- [What to Check for What](#what-to-check-for-what)
- [SELinux](#selinux)
- [AppArmor](#apparmor)
- [Kernel Hardening State](#kernel-hardening-state)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Live vs Image](#live-vs-image)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Which MAC is active?
getenforce 2>/dev/null; aa-status 2>/dev/null | head -1

# SELinux denials (these are frequently the attack itself)
ausearch -m avc -ts recent 2>/dev/null

# AppArmor denials
dmesg | grep -i 'apparmor="DENIED"'

# Kernel taint (out-of-tree / unsigned module loaded)
cat /proc/sys/kernel/tainted

# ptrace hardening (0 = any process can attach)
cat /proc/sys/kernel/yama/ptrace_scope
```

## Where the MAC and Hardening State Lives

Enforcement is a **live** property; config and logged denials survive on an image.

| Path | Holds |
|------|-------|
| `/etc/selinux/config` | 🔴 SELinux mode at boot (`SELINUX=`, `SELINUXTYPE=`) |
| `/etc/selinux/<policy>/modules/` | Loaded policy modules — a custom one is suspect |
| `/sys/fs/selinux/enforce` | Live enforce flag (`1`/`0`) |
| `/etc/apparmor.d/` + `/etc/apparmor.d/disable/` | AppArmor profiles / explicitly disabled ones |
| `/sys/kernel/security/apparmor/profiles` | Live loaded AppArmor profiles + modes |
| `/sys/kernel/security/lsm` | 🔴 The active LSM stack (which MACs are even on) |
| `/sys/kernel/security/lockdown` | Kernel lockdown mode (`none`/`integrity`/`confidentiality`) |
| `/var/log/audit/audit.log` | 🔴 AVC denials + `setenforce` events |
| `dmesg` / `journalctl -k` | AppArmor `DENIED`, module-load, taint messages |
| `/proc/sys/kernel/tainted` | 🔴 Taint flags (rootkit / out-of-tree hint) |
| `/proc/sys/kernel/{yama/ptrace_scope,modules_disabled,kexec_load_disabled}` | Hardening sysctls |

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Which MAC is active (or is any)? | `getenforce`; `aa-status`; `cat /sys/kernel/security/lsm` |
| Was protection downgraded near the incident? | `grep -i setenforce /var/log/audit/audit.log`; `aa-status` modes |
| What did the policy catch the attacker doing? | `ausearch -m avc -i`; `dmesg \| grep 'apparmor="DENIED"'` |
| Was policy loosened (boolean/module/permissive domain)? | `semanage boolean -l -C`; `semodule -l`; `semanage permissive -l` |
| Is a file mislabeled to run (webshell)? | `ls -Z /var/www/html /tmp /dev/shm` |
| Rogue kernel module loaded? | `cat /proc/sys/kernel/tainted`; `dmesg \| grep -i 'module verification'` |
| Is module loading / kexec locked down? | `cat /proc/sys/kernel/modules_disabled /proc/sys/kernel/kexec_load_disabled` |
| Escape/injection surface open? | `sysctl kernel.unprivileged_userns_clone kernel.yama.ptrace_scope` |

## SELinux

SELinux (RHEL/Fedora/CentOS default) is label-based: every process and file carries a security context, and policy governs which contexts may interact. Its value to you is that when an exploited service steps outside its normal behavior, policy denies and *logs* it.

```bash
# Current mode + policy
getenforce

sestatus

# Config (survives reboot)
cat /etc/selinux/config

# Contexts on processes and files
ps -eZ | head

ls -Z /path

# AVC denials in the audit log
ausearch -m avc -ts today 2>/dev/null

grep -i avc /var/log/audit/audit.log 2>/dev/null

# Booleans (toggles that loosen policy)
getsebool -a
```

| State | Meaning |
|-------|---------|
| `Enforcing` | Policy blocks + logs violations |
| `Permissive` | Policy logs but does **not** block 🔴 (common attacker downgrade) |
| `Disabled` | No SELinux at all 🔴 |

🔴 **Reading the AVC denials is the whole point.** When an attacker's payload tries something the policy forbids — a webshell in `httpd_sys_content_t` trying to `execute` a shell, or `open` a socket — SELinux logs an `avc: denied` naming the source context, target, and permission. Those lines often *are* the intrusion. Two follow-on checks: whether the mode was downgraded (`setenforce 0` in the audit log), and whether a boolean was flipped to permit the attacker's action.

```bash
# Context-change / relabel activity
ausearch -m avc,user_avc,selinux_err -i 2>/dev/null

# Was SELinux flipped? Check audit for setenforce
grep -i setenforce /var/log/audit/audit.log 2>/dev/null
```

**Policy-tampering checks** — subtler than flipping the whole mode:

```bash
# Booleans changed from their policy default (attacker loosened one)
semanage boolean -l -C 2>/dev/null

# Loaded policy modules — a non-standard one is likely audit2allow-generated
semodule -l 2>/dev/null

# Permissive DOMAINS — a service exempted from enforcement even while "Enforcing"
semanage permissive -l 2>/dev/null

# Explain exactly what a denial blocked (do NOT auto-apply the suggested allow)
ausearch -m avc -ts today 2>/dev/null | audit2why 2>/dev/null

# Boot-time relabel trigger (can erase attacker chcon, or hide a relabel)
ls -l /.autorelabel 2>/dev/null
```

🔴 A custom module in `semodule -l` that isn't distro-standard is a strong tell of **`audit2allow` abuse** — the attacker took their own denial, generated a policy module that permits it, and loaded it. Extract and read it. A **permissive domain** is stealthier still: the box reports `Enforcing`, but the attacker's target service runs unconstrained.

## AppArmor

AppArmor (Debian/Ubuntu/SUSE default) is path-based rather than label-based: profiles constrain named programs to a declared set of file paths and capabilities. Same DFIR value — a confined program stepping out of bounds produces a `DENIED` line.

```bash
# Profiles and their modes
aa-status

# Profile definitions
ls -l /etc/apparmor.d/

# Denials (logged to dmesg / journald / syslog)
dmesg | grep -i 'apparmor="DENIED"'

journalctl -k | grep -i apparmor

grep -i 'apparmor="DENIED"' /var/log/syslog /var/log/kern.log 2>/dev/null

# Profiles explicitly disabled by the attacker (symlinked into disable/)
ls -l /etc/apparmor.d/disable/ 2>/dev/null

# Live loaded profiles + their current mode
cat /sys/kernel/security/apparmor/profiles 2>/dev/null
```

| Profile mode | Meaning |
|--------------|---------|
| `enforce` | Blocks + logs |
| `complain` | Logs only 🔴 (downgrade tell) |
| *(unconfined)* | No profile applied to that program |

🔴 A profile moved from `enforce` to `complain`, a profile removed entirely, or a critical service (`mysqld`, a web app) showing `unconfined` when it should be confined all point to tampering or the misconfiguration the attacker exploited. The `DENIED` lines name the profile and the operation it blocked — read them the way you'd read SELinux AVCs.

## Kernel Hardening State

These sysctls are both hardening controls and useful anomaly signals — the taint flag in particular is the cheapest kernel-rootkit hint you have.

```bash
# Taint flags - nonzero means something out-of-tree loaded
cat /proc/sys/kernel/tainted

# Decode taint bits (module signing, out-of-tree, etc.)
for i in $(seq 0 18); do echo "bit $i: $(( ($(cat /proc/sys/kernel/tainted) >> i) & 1 ))"; done

# ptrace scope (0 lets any process attach to any other -> injection/cred theft easier)
cat /proc/sys/kernel/yama/ptrace_scope

# kernel pointer exposure
cat /proc/sys/kernel/kptr_restrict

# dmesg restriction
cat /proc/sys/kernel/dmesg_restrict

# Active LSM stack — tells you which MACs are even loaded
cat /sys/kernel/security/lsm

# Kernel lockdown mode (none / integrity / confidentiality)
cat /sys/kernel/security/lockdown 2>/dev/null

# Secure Boot state (signed-kernel enforcement)
mokutil --sb-state 2>/dev/null

# Is further module loading locked? kexec disabled?
cat /proc/sys/kernel/modules_disabled /proc/sys/kernel/kexec_load_disabled 2>/dev/null

# Escape/privesc surface: unprivileged user namespaces + unprivileged BPF
sysctl kernel.unprivileged_userns_clone kernel.unprivileged_bpf_disabled 2>/dev/null

# Module signature-verification failures in the ring buffer
dmesg | grep -iE 'module verification failed|loading out-of-tree|taint'

# Full sysctl snapshot for diffing against a known-good host
sysctl -a 2>/dev/null
```

🔴 **Kernel taint** is a near-free rootkit signal: a set taint bit for "out-of-tree module" or "unsigned module" on a host that should only run distro-signed modules means an unexpected module loaded. That's your cue to pivot to the kernel-module section of the Persistence note and to memory analysis. `ptrace_scope=0` on a host that should be hardened makes process injection and in-memory credential theft easier — worth noting if it was changed.

## Deep Threat Hunts

Consolidated MAC/hardening tamper sweep. *(seasoned-DFIR; MAC state is both a control and a detection source)*

```bash
# 1. Which LSMs are actually active (SELinux? AppArmor? lockdown? yama?)
cat /sys/kernel/security/lsm

# 2. SELinux loosened: locally-changed booleans, custom modules, permissive domains
semanage boolean -l -C 2>/dev/null

semodule -l 2>/dev/null

semanage permissive -l 2>/dev/null

# 3. Mislabeled files where they'd let a payload run (webshell relabel)
ls -Z /var/www/html /tmp /dev/shm 2>/dev/null

# 4. AppArmor disabled/complain profiles
ls -l /etc/apparmor.d/disable/ 2>/dev/null

aa-status 2>/dev/null

# 5. Enforcement flipped in the audit log (the downgrade event + its time)
grep -iE 'setenforce|enforcing=0|SELINUX=permissive' /var/log/audit/audit.log 2>/dev/null

# 6. Kernel hardening dropped: taint, module verify, lockdown, module-load lock
cat /proc/sys/kernel/tainted /proc/sys/kernel/modules_disabled 2>/dev/null

dmesg | grep -iE 'module verification failed|out-of-tree|taint'

# 7. Escape surface: unprivileged user namespaces (container/user-ns privesc)
sysctl kernel.unprivileged_userns_clone kernel.yama.ptrace_scope 2>/dev/null
```

**Hunt ideas:**

- **Diff against a golden host.** `getsebool -a` / `semanage boolean -l -C` / `sysctl -a` / `aa-status` all diff cleanly against a known-good peer — any loosened control is a lead.
- **Custom SELinux module = audit2allow backdoor.** A non-standard entry in `semodule -l` was almost certainly generated to permit the attacker's own denial. Extract and read it.
- **"Burst of denials then silence" is success, not safety.** Correlate the last AVC/DENIED timestamp with a `setenforce 0`, a boolean flip, a `chcon`/relabel, or an `aa-complain` right after.
- **Permissive domains hide in plain sight** — the box says `Enforcing` while one target service runs unconstrained.
- **Taint bit + "module verification failed" in dmesg** = an unsigned/out-of-tree module loaded; pivot straight to kernel-module rootkit analysis.

## Getting Max Value

- **Capture the live enforcement mode + LSM list + taint flags *before* imaging** — a dead disk can't answer "was it enforcing at the time of the attack." That answer only exists on the running kernel.
- **Treat AVC/DENIED lines as a detection source.** Each denial names *source context → target → permission*; that triad is frequently the intrusion itself (a webshell trying to exec a shell, bind a socket, read a secret).
- **Run denials through `audit2why`/`audit2allow -w`** to understand exactly what was blocked — but never apply the suggested allow to the evidence host.
- **On a mounted image you still get config + logged denials** (`/etc/selinux/config`, `/etc/apparmor.d/`, `audit.log`, syslog, journal) — parse those even without live state.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Full AVC/denial detail + timeline of the block | **Auditd** (`ausearch -m avc`), **Systemd Journal** |
| The out-of-tree module the taint flag implies | **Persistence → Kernel Modules and LKM Rootkits**, **Rootkit Detection Tooling** (11c) |
| Confirm a kernel-level rootkit | **Memory Forensics** (11) |
| The webshell the AVC caught | **Application and Database Logs**, **Web Exploitation playbook** |
| ptrace/userns abused for injection or escape | **Live Response** (10), **Container** escapes |
| The command that ran `setenforce`/`aa-complain` | **Auditd** (`USER_CMD`), **Shells** (history) |

## Scenarios

- **Denials *are* the intrusion:** `httpd_sys_content_t` attempting to exec a shell or open a socket = webshell RCE, caught and logged by policy.
- **Downgrade TTP:** `setenforce 0` or `aa-complain` executed right before the malicious action — the timestamp brackets the attack.
- **audit2allow backdoor:** attacker generates and loads a policy module that permits their payload, leaving the mode at `Enforcing`.
- **Permissive-domain stealth:** the box reports `Enforcing` but the target service is exempt from enforcement.
- **Kernel-rootkit hint:** taint bit set + "module verification failed" in `dmesg` on a host that should run only signed modules.
- **Escape surface:** `unprivileged_userns_clone=1` enables user-namespace privesc / container-escape primitives.

## Live vs Image

MAC enforcement state (`getenforce`, `aa-status`, kernel taint) is a **live-host** property — it reflects the running kernel and can't be read from a dead disk. On a mounted image you can only recover the *config* (`/etc/selinux/config`, `/etc/apparmor.d/`) and the *logged denials* (`/var/log/audit/audit.log`, `syslog`, the journal). Capture the live mode before imaging, or you lose the answer to "was it enforcing at the time."

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| SELinux `Permissive`/`Disabled` (or flipped near incident) | Protection turned off |
| AppArmor profile in `complain` / removed / service `unconfined` | Protection downgraded |
| Burst of AVC/DENIED events then silence | Attacker relabeled or allowed their action |
| `setenforce 0` in audit log | Deliberate SELinux downgrade |
| Kernel `tainted` nonzero (out-of-tree/unsigned) | Possible LKM rootkit / unexpected driver |
| `ptrace_scope=0` on a hardened host | Eases injection / credential theft |
| Non-standard module in `semodule -l` | Likely audit2allow-generated backdoor policy |
| Permissive domain (`semanage permissive -l`) | Service exempt from enforcement while "Enforcing" |
| Locally-changed SELinux boolean (`semanage boolean -l -C`) | Policy loosened to permit attacker action |
| Mislabeled file (`ls -Z`) in web/exec path | Relabel so a payload is allowed to run |
| `modules_disabled=0` + taint on a hardened host, or `lockdown=none` | Module-load path left open |
| `unprivileged_userns_clone=1` | User-namespace escape/privesc surface |

## Resources

- SELinux project wiki — https://selinuxproject.org
- AppArmor documentation — https://apparmor.net
- Linux kernel taint flags reference — https://docs.kernel.org/admin-guide/tainted-kernels.html
- Kernel lockdown / LSM — https://www.kernel.org/doc/html/latest/admin-guide/LSM/
- MITRE ATT&CK: T1562.001 (Impair Defenses: Disable/Modify Tools), T1547.006 (Kernel Modules), T1601 (Modify System Image), T1611 (Escape to Host — userns)
