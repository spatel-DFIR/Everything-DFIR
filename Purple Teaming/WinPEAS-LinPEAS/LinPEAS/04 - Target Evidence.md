# LinPEAS — Target Evidence

LinPEAS execution on the target leaves multiple forensic artifacts across the filesystem, process list, shell history, and system audit logs. The evidence signature differs from exploitation tools — LinPEAS doesn't modify system state, doesn't install persistence, and doesn't escalate privileges on its own; it only *reads* configuration, filesystem, and process state. This read-only nature means artifacts are primarily **execution evidence** (command-line arguments, bash history, audit logs of file access) and **output files** (enumeration results) rather than system modifications.

## Contents

- [Process-Level Artifacts](#process-level-artifacts)
- [Shell History and REPL Evidence](#shell-history-and-repl-evidence)
- [LinPEAS Output Files](#linpeas-output-files)
- [Temporary Staging Artifacts](#temporary-staging-artifacts)
- [Filesystem Access and Audit Events](#filesystem-access-and-audit-events)
- [Bash Audit Logs and Process Accounting](#bash-audit-logs-and-process-accounting)
- [Exported Analysis Files](#exported-analysis-files)
- [Cross-Linked Evidence with Linux Module Notes](#cross-linked-evidence-with-linux-module-notes)
- [Timeline Reconstruction](#timeline-reconstruction)

---

## Process-Level Artifacts

**Artifact type:** Process memory (volatile), process listing (if captured during execution)

When LinPEAS runs as a bash subprocess, the process tree reveals:

```
user@target:~$ ps auxwf | grep -E "bash|linpeas"
user  12345  0.1  2.3  12456  8392  pts/0  S+  14:45  0:00 bash /tmp/linpeas.sh
user  12346  0.0  0.1   5432  2154  pts/0  S+  14:45  0:00  \_ /bin/ls -la /
user  12347  0.0  0.1   4321  1998  pts/0  S+  14:45  0:00  \_ /usr/bin/find / -name "*.sh"
```

**Evidentiary value:**
- **Process ID (PID)** — if the forensic acquisition captured a process listing during LinPEAS execution, the PID chain reveals which account ran LinPEAS and which subprocess binaries were invoked (grep, awk, sed, find, ls, etc.)
- **Command-line arguments** — the full `bash /tmp/linpeas.sh -q -j` line is visible in `/proc/[PID]/cmdline` (and in `ps auxwf` output if captured at the right moment)
- **Runtime duration** — the time LinPEAS was active is visible in the process listing's elapsed time and in kernel process-accounting logs (if enabled)

**Volatility:** Once LinPEAS exits, the process is gone from live memory. However, if a forensic tool (e.g., `volatility` memory-forensics framework) captured the target's RAM during or shortly after LinPEAS execution, the process struct and command-line arguments remain in memory and can be recovered post-analysis.

**Flag combinations in cmdline:** The command-line reconstructed from `/proc/[PID]/cmdline` or `ps` output reveals:
- `-q` (quiet) — attacker was suppressing output, suggesting operational security awareness
- `-j` (JSON) — attacker wanted structured output, suggesting downstream parsing/scripting
- `-h` (HTML) — attacker was preparing a report, suggesting formal engagement (not an interactive pentest)
- `-o /path/to/file` (offline mode) — attacker was re-analyzing a previous run, suggesting deeper dive into findings

## Shell History and REPL Evidence

**Artifact type:** Filesystem (`~/.bash_history`, `~/.zsh_history`)

Target-side command history often contains the LinPEAS invocation itself and surrounding recon commands:

```bash
# Example ~/.bash_history on target
...
ssh attacker@192.168.1.50 "chmod +x linpeas.sh"
bash /tmp/linpeas.sh > /tmp/enum.txt 2>&1
grep "kernel" /tmp/enum.txt
grep -E "CVE-|vulnerable" /tmp/enum.txt
cat /tmp/enum.txt | grep "NOPASSWD"
...
```

**Evidentiary value:**
- **Bash history entry** — confirms that LinPEAS ran on this host under which user account
- **Surrounding commands** — grep/awk/sed on LinPEAS output reveals what the attacker focused on (kernel vulnerabilities, sudo rules, writable files, etc.)
- **Output file paths** — where the attacker staged the output (`/tmp/`, `/home/user/`, `/dev/shm/`, etc.) and whether it was later exfiltrated or deleted
- **Timing** — if bash history preserves timestamps (HISTTIMEFORMAT environment variable set), the exact time LinPEAS ran is recorded

**Reliability caveats:**
- Bash history is only written to disk *after* the shell exits (or when `history -w` is forced)
- An attacker aware of this can run bash commands with `HISTFILE=/dev/null` to bypass history logging entirely
- If the attacker's shell session was backgrounded or run via SSH with a non-interactive session (e.g., `ssh target "bash linpeas.sh"`), that single command may not appear in the interactive history
- If the target system is configured to use `zsh` instead of bash, look in `~/.zsh_history` (different format: `EXTENDED_HISTORY` by default)

## LinPEAS Output Files

**Artifact type:** Filesystem text, JSON, HTML files

By default, LinPEAS writes output to two locations simultaneously:

| Output Destination | Default | Flags |
|---|---|---|
| Stdout (terminal) | Always (if not redirected) | `-q` suppresses banners but not findings |
| Timestamped logfile | `linpeas-TIMESTAMP.log` in working directory | Can be disabled or redirected via shell redirection |
| JSON file (optional) | Specified with `-j` flag | `-j > findings.json` |
| HTML report (optional) | Specified with `-h` flag | `-h > report.html` |

**Likely filesystem locations on target:**

| Location | Context | Artifacts |
|---|---|---|
| `/tmp/linpeas*.log` | Default staging; temporary files | Likely deleted post-engagement; if present, proves execution on that host |
| `/tmp/linpeas_output.txt`, `/tmp/enum.txt`, `/tmp/findings.json` | Attacker-named outputs | Named for exfiltration staging; often `chmod 600` by attacker to hide from other users |
| `/home/user/linpeas*.txt` or `.json` | Home-directory staging | Less common; suggests longer-lived access or interactive attacker sessions |
| `/dev/shm/linpeas*` | Ramdisk staging (volatile, disappears on reboot) | Attacker avoiding disk write (favors OpSec); only recoverable if system is still powered on or memory captured |
| `/var/tmp/` | Persistent temp (not wiped on reboot) | Less common; only used if `/tmp` is mounted with `noexec` flag preventing script execution |

**File metadata:**
- **Access time (atime)** — when the attacker read/processed the output file
- **Modification time (mtime)** — when LinPEAS wrote the file (approximately = when LinPEAS ran)
- **Change time (ctime)** — when file permissions were modified (if attacker `chmod`'d it after creation)
- **File size** — rough proxy for target complexity; a 500 KB output file suggests many packages/services; a 50 KB file suggests minimal system or aggressive filtering

**Content analysis:**
- **JSON structure** — severity rankings, CVE references, recommendation links, category tags
- **Text output encoding** — Unicode control characters for colored output (ANSI color codes like `\x1b[31m` for red) visible if file wasn't stripped before transfer
- **Partial output** — if LinPEAS was interrupted (process killed, network disconnect), output file may be truncated, suggesting an incomplete enumeration run

## Temporary Staging Artifacts

**Artifact type:** Filesystem

Beyond named output files, LinPEAS and the attacker's surrounding activity leave trace files:

| Artifact | Location | Evidence |
|---|---|---|
| LinPEAS script itself | `/tmp/linpeas.sh`, `/opt/linpeas.sh`, `/home/user/linpeas.sh` | Script file used to run the enumeration; can be hashed to identify version |
| Script with execution bit set | `ls -la /tmp/linpeas.sh` shows `-rwxr-xr-x` or `-rwx------` | Explicit execution permission set; reveals if attacker chmod'd it or if inherited from transfer |
| Symlinks | `ls -la /tmp/linpeas.sh` → `/home/user/tools/linpeas.sh` | Suggests attacker linked from a central tools repo or persistent staging area |
| Backup copies | `linpeas.sh.bak`, `linpeas.sh.orig` | Attacker keeping versioned copies for comparison or rollback |
| PID files | `linpeas.pid`, `/tmp/linpeas-12345.pid` | Some versions may write PID files to prevent concurrent execution; rare |

**Attacker cleanup patterns:**
- **Aggressive cleanup:** `rm -rf /tmp/linpeas* /tmp/enum* /tmp/findings*` — attacker deletes everything post-exfiltration
- **Partial cleanup:** `rm /tmp/linpeas.sh` but leaves `linpeas_output.json` — attacker keeps results but not the script
- **No cleanup:** Files left behind — suggests low-OpSec awareness or rapid engagement progression without cleanup windows

Deleted files can often be recovered via filesystem carving techniques (if the filesystem hasn't been heavily used after deletion).

## Filesystem Access and Audit Events

**Artifact type:** System audit logs (`auditd`)

If the target has `auditd` enabled, LinPEAS's file access patterns generate audit events:

```
# Typical auditd events during LinPEAS execution
type=EXECVE msg=audit(...): argc=2 a0="bash" a1="/tmp/linpeas.sh"
type=OPEN msg=audit(...): name="/etc/passwd" flags=O_RDONLY mode=0644
type=OPEN msg=audit(...): name="/etc/shadow" flags=O_RDONLY mode=0640
type=EXECVE msg=audit(...): argc=3 a0="/bin/grep" a1="-r" a2="NOPASSWD"
```

**Evidentiary value:**
- **Precise execution timeline** — auditd timestamps (with microsecond precision) show exactly when LinPEAS started and each subprocess launched
- **File access patterns** — every file LinPEAS read generates an `OPEN`/`OPENAT` audit event with the exact filename and open flags
- **Process lineage** — `type=EXECVE` events show parent → child process chains
- **User attribution** — audit events include UID/GID, confirming which account ran LinPEAS

**Audit rules that capture LinPEAS:** If the system has minimal auditd rules, most of LinPEAS's file access may not be logged. However, system-wide rules like the following catch it:

```bash
# Audit all file reads under /etc
-w /etc/ -p r -k config_read

# Audit all executions
-a exit,always -F arch=b64 -S execve -F key=exec

# Audit /tmp access
-w /tmp/ -p wa -k tmp_writes
```

**Cleanup:** Unlike bash history, auditd logs are typically in `/var/log/audit/audit.log` (privileged read-only), which the attacker cannot directly modify without root access. However, if the attacker *does* have root, they can:
- Use `auditctl -D` to delete the audit daemon configuration (effective after reboot)
- Directly edit or truncate `/var/log/audit/audit.log` (forensically suspicious — a gap in timestamps)
- Uninstall `auditd` entirely (removes future audit events, but past logs remain unless explicitly deleted)

## Bash Audit Logs and Process Accounting

**Artifact type:** System-level process and command logging

Beyond shell history, several mechanisms can log LinPEAS invocation:

| Mechanism | Source | Evidence |
|---|---|---|
| **Process accounting (pacct)** | `/var/log/account/pacct` (if `process-accounting` daemon is running) | Every process launch recorded: `bash`, `/bin/grep`, `/bin/sed`, etc., with PID, UID, execution time |
| **Syslog** | `/var/log/syslog`, `/var/log/messages` | If LinPEAS or a subprocess writes to syslog (rare for LinPEAS itself) |
| **Bash `DEBUG` trap** | Set via `trap 'echo "DEBUG: $BASH_COMMAND"' DEBUG` | If enabled system-wide, logs every command; less common outside highly-secured environments |
| **Kernel audit daemon (auditd)** | `/var/log/audit/audit.log` | Covered above; most comprehensive |

**Recovery method:** If `/var/log/account/pacct` is present and binary process accounting is enabled:

```bash
# On forensic workstation (with pacct utilities installed)
# Convert binary pacct to human-readable format
lastcomm -f /path/to/pacct | grep -E "bash|linpeas|grep"
```

## Exported Analysis Files

**Artifact type:** Filesystem, structured data

If the attacker used LinPEAS's export flags or post-processed the output locally on the target, additional files appear:

| File Type | Creation Method | Location |
|---|---|---|
| JSON export | `bash linpeas.sh -j > findings.json` | `/tmp/findings.json`, attacker-named locations |
| HTML report | `bash linpeas.sh -h > report.html` | `/tmp/report.html` |
| CSV/TSV excerpts | `grep "kernel" linpeas.txt \| cut -d: -f1,2 > kernel_findings.csv` | Attacker-generated, varies by command |
| Grep-filtered output | `grep -E "NOPASSWD\|kernel.*vulnerable" linpeas.txt > high_priority.txt` | Staging for exfiltration, shows attacker's priority areas |

**Content clues:** Examining these files reveals what the attacker was hunting for:
- A `high_priority.txt` file containing only kernel vulnerabilities suggests the attacker was planning a kernel-exploit attack path
- A `sudo_findings.txt` file suggests the attacker was looking for sudo-based escalation
- HTML reports suggest the attacker was preparing deliverables for a client or team

## Cross-Linked Evidence with Linux Module Notes

**Cross-links to existing Linux module documentation** (rather than re-deriving evidence tables):

| Target Evidence Category | Cross-Link |
|---|---|
| Kernel version enumeration | `Linux/01 - Root Directory Structure and Filesystem Layout.md` (kernel version detection section) |
| Sudo configuration discovery | `Linux/03 - Users Groups and Authentication.md` (sudo and privilege delegation section) |
| Cron jobs and scheduled tasks | `Linux/09 - Persistence Mechanisms/` (cron-job forensics) |
| Service enumeration and systemd analysis | `Linux/01 - Root Directory Structure.md` (systemd and service management) |
| SSH key discovery | `Linux/03 - Users Groups and Authentication.md` (SSH and key-based auth section) |
| Package and software enumeration | `Linux/12 - Evidence Collection and Triage.md` (package managers and software inventory) |
| Capability and SUID/SGID binary enumeration | `Linux/05 - SELinux AppArmor and Kernel Hardening.md` (SUID/SGID and capabilities) |
| Bash/shell history forensics | `Linux/04 - Shells and Command History.md` (command history preservation and tampering detection) |
| Process accounting and auditd logs | `Linux/10 - Live Response and Volatile Data.md` (process accounting section) |
| File permissions and access rights | `Linux/02 - File and Directory Permissions.md` |

LinPEAS's enumeration output can be directly cross-referenced against these forensic notes to understand *what LinPEAS found* (e.g., kernel version 4.15.0) and *where the evidence of that finding is stored* on the target (e.g., `/proc/version`, `uname -r` syscall results, kernel logs in `dmesg`).

## Timeline Reconstruction

**Building a full attack timeline from LinPEAS artifacts:**

```
Target Evidence Timeline
─────────────────────────────────────────

2026-08-11 14:43:00 (auditd timestamp)
  OPEN audit event: /tmp/linpeas.sh
  → Attacker transferred the script to /tmp

2026-08-11 14:43:15 (auditd timestamp)
  EXECVE audit event: bash /tmp/linpeas.sh -q -j
  → LinPEAS execution started

2026-08-11 14:44:00 (auditd events, multiple)
  OPEN /etc/passwd
  OPEN /etc/shadow (permission denied, error logged)
  OPEN /etc/crontab
  OPEN /usr/bin/find
  → LinPEAS enumerating configuration and binaries

2026-08-11 14:45:30 (auditd timestamp, file write)
  WRITE /tmp/linpeas_output.json (size: 1.2 MB)
  → LinPEAS completed and flushed output to disk

2026-08-11 14:45:35 (bash history, mtime on file)
  ~/.bash_history entry written:
    "bash /tmp/linpeas.sh -q -j > /tmp/linpeas_output.json"
  → Bash shell exited, flushing history

2026-08-11 14:46:00 (attacker session, not captured)
  cat /tmp/linpeas_output.json | grep -E "CVE-|NOPASSWD"
  rm /tmp/linpeas.sh
  → Attacker reviewing output and cleaning up script

2026-08-11 14:47:00 (scp/ssh logs, if available)
  Outbound connection to 192.168.1.50
  File transfer: /tmp/linpeas_output.json
  → Output exfiltrated to attacker workstation
```

**Gaps and evasion:**
- If the attacker ran LinPEAS over SSH without writing to disk on target (via piped stdin), no `/tmp/linpeas.sh` file artifact exists
- If bash history is disabled (`HISTFILE=/dev/null`), the interactive bash history entry vanishes
- If auditd is not enabled, the precise timestamps and file-access details are lost
- If `/tmp` is mounted with `noexec`, the attacker would need to stage LinPEAS elsewhere (home directory, `/var/tmp/`, etc.), changing the evidence signature

The combination of **multiple independent sources** (auditd + bash history + output files + filesystem metadata) is the strongest timeline. Even if one source is tampered with or unavailable, the others can corroborate and fill gaps.
