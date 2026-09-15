# LinPEAS — Detection and Hunting

LinPEAS detection differs from exploitation tools because LinPEAS doesn't *change* system state — it only *reads* it. This means hunting strategies focus on **execution evidence** (how the attacker ran the script, which account, what flags), **output artifacts** (where results were staged and exfiltrated), and **access patterns** (which files were read, how many, in what sequence) rather than system modifications, registry changes, or network protocol signatures.

LinPEAS execution is *relatively easy to detect* because the script itself is verbose and noisy — it spawns many subprocesses (grep, find, ls, sed, awk, etc.), reads hundreds of files, and generates substantial output. The challenge is distinguishing **legitimate sysadmin activity** (a sysadmin running their own tools for baselines or troubleshooting) from **attacker activity** (an unauthorized user enumerating privilege-escalation paths).

## Contents

- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Not all LinPEAS signals survive attacker evasion efforts. This table ranks hunting signals by which evasion techniques defeat them:

| Signal Strength | Artifact | Evasion Technique That Breaks It | Confidence | Notes |
|---|---|---|---|---|
| **CRITICAL** | Unmodified LinPEAS script hash matches public repo | Attacker uses modified/customized LinPEAS fork | Very High | Script files are rarely modified; hash mismatch is strong indicator of intentional obfuscation |
| **CRITICAL** | `/tmp/linpeas*.sh` or `/tmp/linpeas*.log` file present, undeleted | Attacker deletes files post-exfiltration | Very High | Default staging location; presence proves execution; absence does not prove non-execution (file deletion is common cleanup) |
| **HIGH** | Bash history entry: `bash /tmp/linpeas.sh` or `bash ./linpeas.sh` | Attacker disables bash history (HISTFILE=/dev/null) or uses non-interactive SSH | High | Most attackers don't disable history; presence is strong evidence |
| **HIGH** | Auditd events: EXECVE `bash linpeas.sh` + OPEN events for `/etc/passwd`, `/etc/shadow`, `/etc/crontab`, `/etc/sudoers` | Attacker disables auditd, clears logs, or uses in-memory execution | High | Auditd is kernel-level and harder to evade than user-level logging; however, root access allows disabling |
| **HIGH** | JSON/HTML output files (`linpeas_output.json`, `report.html`) in common staging locations | Attacker uses offline mode only or deletes outputs | Medium | Output files are substantial (~1-5 MB); harder to hide than small scripts; but can be deleted or staged elsewhere |
| **MEDIUM** | Process listing shows multiple rapid subprocesses (grep, find, sed, awk) spawned by bash in short time window | Attacker runs LinPEAS via in-memory execution or heavily modifies script to reduce subprocess spawning | Medium | Live process inspection only works during execution; post-execution, only audit logs preserve this |
| **MEDIUM** | Network connection to attacker IP immediately after LinPEAS output file generation (scp, wget, curl, rsync) | Attacker uses DNS tunneling, SSH port forwarding, or delayed exfiltration | Medium | Timing correlation is suspicious but not definitive; could be unrelated admin activity |
| **MEDIUM** | File access patterns in auditd: sequential reads of `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/sudoers` in rapid succession | Attacker uses offline mode or does not read these files (unlikely; LinPEAS always reads these) | Medium | Pattern is characteristic of enumeration tools; legitimate tools do this too |
| **LOW** | Large temporary files in `/tmp/` with generic names (unnamed, rotated) | Attacker cleans up or uses `/dev/shm/` | Low | Too many false positives; sysadmin tools, system services, user applications all generate temp files |
| **LOW** | Disk space exhaustion or rapid growth in `/tmp/` | Attacker deletes output or uses ramdisk | Low | Many tools cause this; without corroborating evidence, not actionable |

**How to use this table:**
- **For forensic response:** Start with CRITICAL/HIGH signals. If any of these are present and uncontested, escalate to incident response.
- **For threat hunting:** Search for CRITICAL signals first (script hash, undeleted files); if found, broaden to HIGH signals (bash history, auditd events).
- **For blue-team tuning:** Detection rules ranked by evasion resistance help you prioritize which signals to alert on (CRITICAL signals have fewer evasion bypasses).

---

## Hunting on Source

**Objective:** Identify LinPEAS binary, command history, and exfiltrated output on the attacker's workstation.

### Command: Search for LinPEAS Script

```bash
# On forensic workstation or attacker-controlled machine
find ~ -name "*linpeas*" -type f 2>/dev/null
find ~ -name "*PEASS*" -type f 2>/dev/null
find ~ -name "*linpe*" -type f 2>/dev/null
find /opt -name "*linpeas*" -type f 2>/dev/null
find /tmp -name "*linpeas*" -type f 2>/dev/null
```

**Interpretation:**
- Any matches confirm LinPEAS presence on the source machine
- Multiple matches suggest versioning or repeated downloads/updates
- Matches in `/tmp` suggest transient staging (engaged but cleaned)
- Matches in `/opt` or `~/.local/bin` suggest persistent tools infrastructure

### Command: Hash and Verify LinPEAS Script

```bash
# Get SHA256 of found script
sha256sum ~/tools/linpeas.sh

# Compare against known good hash from official GitHub
# Fetch official repo's latest hash:
curl -s https://api.github.com/repos/peass-ng/PEASS-ng/contents/linpeas/linpeas.sh \
  | grep '"download_url"' | cut -d'"' -f4 | xargs curl -s | sha256sum

# Mismatch indicates modification
```

**Interpretation:**
- **Hash matches official:** Attacker used unmodified public LinPEAS (legitimate tool, used as-is)
- **Hash does not match:** Attacker modified script (added evasion, disabled checks, hardcoded flags) — high-confidence indicator of intentional obfuscation

### Command: Search Shell History for LinPEAS Invocations

```bash
# Bash history
grep -E "linpeas|PEASS" ~/.bash_history

# Zsh history (different format)
grep -E "linpeas|PEASS" ~/.zsh_history

# Fish history (also different format)
grep -E "linpeas|PEASS" ~/.local/share/fish/fish_history

# All users
for user in $(cut -d: -f1 /etc/passwd); do
  hist_file=$(eval echo "~$user/.bash_history")
  [ -f "$hist_file" ] && echo "=== $user ===" && grep -E "linpeas|PEASS" "$hist_file"
done
```

**Interpretation:**
- Command present → attacker ran LinPEAS, when (timestamp if HISTTIMEFORMAT is set), and with which flags
- Command absent → attacker may have disabled history (HISTFILE=/dev/null) or used non-interactive SSH

### Command: Search for LinPEAS Output Files

```bash
# Common output locations
find ~ -name "*enum*.txt" -o -name "*linpeas*.txt" -o -name "*linpeas*.json" \
  -o -name "*linpeas*.html" -o -name "*findings*" 2>/dev/null

# By file size (LinPEAS outputs are typically 1-5 MB)
find ~ -type f -size +100k -size -10M -mtime -7 2>/dev/null | \
  file - | grep -E "text|JSON|HTML"

# In Downloads
ls -la ~/Downloads/linpeas* ~/Downloads/*findings* ~/Downloads/*enum* 2>/dev/null
```

**Interpretation:**
- Presence of JSON/HTML/large text files proves LinPEAS was run and output captured
- File modification timestamps narrow the engagement window
- File names (auto-generated vs. attacker-named) suggest attacker familiarity and operational sophistication

### Command: Timeline Correlation — Source Tool Usage vs. Target Access

```bash
# Extract timestamp from bash history for LinPEAS invocation
grep -E "linpeas|PEASS" ~/.bash_history | head -1

# Extract timestamp from exfiltration command (scp, curl, etc.)
grep -E "scp.*linpeas|curl.*linpeas|wget.*linpeas|rsync.*linpeas" ~/.bash_history

# Correlate with target system access (SSH logs)
grep "user@target" ~/.bash_history | head -1 && tail -5 ~/.bash_history

# If SSH keys are present, check age against LinPEAS date
stat ~/.ssh/id_rsa | grep Modify
stat ~/tools/linpeas.sh | grep Modify
```

**Interpretation:**
- Tight timing (LinPEAS invocation followed quickly by exfiltration) suggests active, coordinated attack
- Loose timing (LinPEAS downloaded weeks ago; only recently used) suggests pre-positioned tools or opportunistic use
- SSH key age older than LinPEAS invocation suggests established access; key age newer suggests rapid pivot/lateral move

---

## Hunting on Target

**Objective:** Identify LinPEAS execution, output staging, and exfiltration on the compromised Linux host.

### Command: Search for LinPEAS Script and Output Files

```bash
# Find script (most common location: /tmp)
find /tmp /var/tmp /dev/shm /home -name "*linpeas*" -type f 2>/dev/null

# Find output files
find /tmp /var/tmp /home -name "*enum*.txt" -name "*findings*" -name "*linpeas*.log" \
  -o -name "*linpeas*.json" -o -name "*linpeas*.html" 2>/dev/null

# By recent modification time (assume engagement is recent)
find /tmp /var/tmp /home -type f -mtime -7 -size +50k 2>/dev/null | \
  xargs file | grep -E "text|JSON|HTML"

# Check /dev/shm for deleted-but-recoverable files
ls -la /dev/shm/ | grep -E "linpeas|enum|findings"
```

**Interpretation:**
- Undeleted files prove execution and output generation; examine content for severity rankings and findings
- Deleted files may be recoverable via `lsof` (if process still holds descriptor) or filesystem carving
- Ramdisk staging (`/dev/shm`) suggests high-OpSec awareness (files disappear on reboot)

### Command: Examine Bash History for LinPEAS and Related Commands

```bash
# Current user's history
cat ~/.bash_history | grep -E "linpeas|enum|findings"

# All users (if privilege escalation achieved)
for user in $(cut -d: -f1 /etc/passwd); do
  hist_file=$(eval echo "~$user/.bash_history")
  if [ -f "$hist_file" ] && [ -r "$hist_file" ]; then
    echo "=== $user ===="
    grep -E "linpeas|enum|findings|grep|export" "$hist_file" | tail -20
  fi
done

# Check for zsh history too (different location/format)
for user in $(cut -d: -f1 /etc/passwd); do
  zhist=$(eval echo "~$user/.zsh_history")
  if [ -f "$zhist" ]; then
    echo "=== $user (zsh) ===="
    grep -E "linpeas|enum|findings" "$zhist" | head -10
  fi
done
```

**Interpretation:**
- LinPEAS invocation entry confirms execution and user account
- Surrounding commands (grep, awk, head, tail on output) reveal attacker's investigation priorities
- Absence of expected history (when other commands are visible) suggests attacker disabled history (`HISTFILE=/dev/null`)

### Command: Check Auditd Logs for LinPEAS Execution

```bash
# If auditd is enabled and logging
grep -E "linpeas|bash.*linpeas" /var/log/audit/audit.log

# Broader: look for EXECVE events with bash spawning many subprocesses
ausearch -k exec | grep bash | head -20

# File access pattern: reads of /etc/passwd, /etc/shadow, /etc/sudoers in rapid sequence
ausearch -k config_read 2>/dev/null | grep -E "passwd|shadow|sudoers|crontab"

# Timeline: extract timestamps of LinPEAS execution
ausearch -k exec 2>/dev/null | grep bash | awk '{print $2, $3}' | sort | uniq
```

**Interpretation:**
- Presence of EXECVE events with `/tmp/linpeas.sh` confirms execution with precise timestamp
- File access patterns (hundreds of OPEN events for config files) are characteristic of enumeration tools
- Absence of audit logs suggests either auditd is disabled or logs were deleted (both suspicious)

### Command: Search for Network Connections Coinciding with LinPEAS Output Exfiltration

```bash
# If netflow/sflow data available (some organizations capture this):
# Search for outbound connections from target IP around the time of LinPEAS output generation
grep "target_ip" /path/to/netflow.log | grep -E "ESTABLISHED|TIME_WAIT" | sort -k2

# Check syslog for ssh/scp connections (if logging is configured)
grep -E "scp|sftp|ssh.*established" /var/log/auth.log

# Check bash history for explicit exfiltration commands
grep -E "scp|rsync|curl|wget|cat.*|" ~/.bash_history | grep -v "^#"

# Netstat/ss output captured at time of incident (if available in forensic snapshot)
# Look for established connections during LinPEAS time window
netstat -ntp 2>/dev/null | grep ESTABLISHED
```

**Interpretation:**
- SSH/SCP connection immediately after LinPEAS output file generation is highly suspicious
- Outbound connection to an attacker-controlled IP (if known) is direct evidence of exfiltration
- Absence of obvious exfiltration may indicate output staged for later pickup or attacker left to return

### Command: Check Sudo/Su History for Privilege Escalation Attempts Post-Enumeration

```bash
# Sudo log (may be in auth.log or syslog)
grep -E "sudo.*COMMAND" /var/log/auth.log | tail -20

# Attempt to access /root or other privileged areas after LinPEAS findings
grep -E "open.*denied" /var/log/audit/audit.log | tail -20

# Check if attacker escalated after LinPEAS findings
grep -E "uid=0|gid=0" /var/log/audit/audit.log | grep EXECVE
```

**Interpretation:**
- Escalation attempt immediately after LinPEAS output suggests attacker moved from reconnaissance to exploitation based on findings
- Escalation attempt that succeeds (UID changes to 0) is the next phase of attack; correlate with exploit tool usage

### Command: Check /tmp and Staging Areas for Exploitation Tools Post-LinPEAS

```bash
# After LinPEAS identifies privilege-escalation vectors, attacker often stages exploitation tools
find /tmp /var/tmp /home -type f -name "*exploit*" -o -name "*kernel*" -o -name "*.c" -o -name "*.py" 2>/dev/null

# Check for compilation artifacts (object files, executables) that don't match known packages
find /tmp -name "*.o" -o -name "*.so" -o -name "*.a" 2>/dev/null | xargs file | grep -v "^/.*: ELF"

# Check for git repos or source downloads post-LinPEAS
find /tmp -name ".git" -o -name "*.tar.gz" -o -name "*.zip" 2>/dev/null
```

**Interpretation:**
- Presence of exploit source or compiled binaries immediately after LinPEAS output suggests rapid exploitation attempt
- Matches indicate attacker used LinPEAS findings to guide exploitation tool selection

---

## Fleet-Wide Sweep

**Objective:** Identify all hosts in an environment where LinPEAS may have run.

### Distributed Search — Cross All Hosts

```bash
# For each host, check for LinPEAS artifacts (requires privileged access or EDR agent):
for host in $(cat ~/targets.txt); do
  echo "=== Checking $host ===" 
  ssh root@$host "find /tmp /var/tmp /home -name '*linpeas*' -o -name '*enum*.txt' 2>/dev/null"
  ssh root@$host "grep -r 'linpeas\|PEASS' /var/log/audit/audit.log 2>/dev/null | wc -l"
done

# Or using a centralized EDR platform (example: osquery):
osquery -json \
  'SELECT path, mtime, size FROM file WHERE path LIKE "%linpeas%" OR name LIKE "%findings%"'

# Or using YARA rules (if YARA is deployed):
yara -r ~/rules/linpeas_detection.yar /tmp /var/tmp /home
```

**YARA Rule for LinPEAS Script Detection:**

```yara
rule LinPEAS_Script {
  meta:
    description = "Detects LinPEAS enumeration script"
    author = "DFIR"
    date = "2026-08-11"
  strings:
    $header = "#!/bin/bash" nocase
    $peass1 = "peass-ng" nocase
    $peass2 = "linpeas" nocase
    $peass3 = "sudo -l" nocase
    $peass4 = "/etc/crontab" nocase
  condition:
    $header and ($peass1 or $peass2) and ($peass3 or $peass4)
}
```

**Interpretation:**
- Count of matching hosts reveals scope of privilege-escalation reconnaissance activity
- Timeline of matches (if multiple hosts hit) suggests coordinated campaign vs. isolated incidents

---

## Remediation

**Evidence preservation (do this first):**

```bash
# Capture LinPEAS files before deletion
mkdir -p /forensics/linpeas_evidence/$(date +%Y%m%d)
find /tmp -name "*linpeas*" -exec cp -pr {} /forensics/linpeas_evidence/$(date +%Y%m%d)/ \;
find /tmp -name "*enum*.txt" -exec cp -pr {} /forensics/linpeas_evidence/$(date +%Y%m%d)/ \;

# Capture auditd logs
cp /var/log/audit/audit.log /forensics/audit_$(date +%Y%m%d).log

# Capture bash history for all users
for user in $(cut -d: -f1 /etc/passwd); do
  hist_file=$(eval echo "~$user/.bash_history")
  [ -f "$hist_file" ] && cp "$hist_file" /forensics/history_${user}_$(date +%Y%m%d).txt
done
```

**Eradication (after preservation):**

```bash
# Remove LinPEAS script and output files
find /tmp /var/tmp /dev/shm -name "*linpeas*" -delete
find /tmp /var/tmp -name "*enum*.txt" -delete
find /tmp /var/tmp -name "*findings*" -delete

# Clear bash history if attacker left it intact (optional: preserve for analysis first)
# cat /dev/null > ~/.bash_history

# Restart auditd to reset audit log (if needed)
systemctl restart auditd

# Review and patch the privilege-escalation vulnerabilities LinPEAS identified
# (kernel exploit: update kernel; writable cron script: fix permissions; etc.)
```

**Detection rule deployment (going forward):**

```bash
# Auditd rule to alert on LinPEAS script execution
echo '-a always,exit -F dir=/tmp -F perm=x -F filetype=file -k linpeas_watch' >> /etc/audit/rules.d/custom.rules

# Sysmon rule (Windows-centric, but concept applies to osquery on Linux):
# Alert on bash spawning unusual subprocess sequences (grep, find, sed, awk in rapid succession)

# YARA rule deployment (scan /tmp periodically)
# Cron job: 0 * * * * yara -r ~/rules/linpeas.yar /tmp /var/tmp
```

**Hardening recommendations:**

1. **Monitor subprocess activity** — alert on bash spawning 50+ subprocesses in <5 seconds (characteristic of enumeration tools)
2. **Protect sensitive config files** — implement MAC (SELinux/AppArmor) rules to restrict read access to `/etc/shadow`, `/etc/sudoers` to authorized tools only
3. **Enable persistent auditd** — ensure auditd cannot be disabled without immediate alerting; log to remote syslog
4. **Baseline normal tool usage** — know which scripts/tools legitimately read `/etc/passwd`, `/etc/cron.d/`, etc., so unauthorized scanning stands out
5. **File integrity monitoring (FIM)** — alert on creation of new files in `/tmp/` matching patterns `*linpeas*`, `*enum*`, `*findings*`
6. **Enforce /tmp execution controls** — if feasible, mount `/tmp` with `noexec` flag (blocks direct script execution; attacker must copy to writable location with exec permission)

**Note on /tmp noexec:** Mounting `/tmp` with `noexec` makes running LinPEAS directly from `/tmp` impossible, but attacker can work around this by copying to a writable location with exec permissions (`/home/`, `/var/tmp/`, `/dev/shm/`). Not a silver bullet, but raises the bar.
