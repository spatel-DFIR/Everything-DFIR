# LinPEAS — Hands-On Use Cases

LinPEAS is an enumeration-only tool — every use case here assumes the attacker already has code execution (SSH login, web shell, container escape, etc.) and is running LinPEAS to *map the target's privilege-escalation surface*, not to exploit it directly. **MITRE ATT&CK T1082 (System Information Discovery)** and **T1518.1 (Software Discovery)** apply as the baseline techniques for all scenarios; privilege-discovery-specific techniques (T1007 System Service Discovery, T1526 Cloud Service Enumeration, T1134 Access Token Manipulation candidates) are layered per use case.

## Contents

- [Basic Enumeration with No Flags](#basic-enumeration-with-no-flags)
- [Quiet Output Suppression](#quiet-output-suppression)
- [Offline Mode Processing](#offline-mode-processing)
- [Kernel Vulnerability Scanning](#kernel-vulnerability-scanning)
- [System Services and Privilege Analysis](#system-services-and-privilege-analysis)
- [Network Configuration and Service Enumeration](#network-configuration-and-service-enumeration)
- [Cron Jobs and Scheduled Task Discovery](#cron-jobs-and-scheduled-task-discovery)
- [Installed Software and Third-Party Tools](#installed-software-and-third-party-tools)
- [Password File and Credential Harvesting](#password-file-and-credential-harvesting)
- [SSH Key Enumeration](#ssh-key-enumeration)
- [Container and Virtualization Detection](#container-and-virtualization-detection)
- [Sudo and Privilege Delegation Discovery](#sudo-and-privilege-delegation-discovery)
- [JSON Export for Downstream Analysis](#json-export-for-downstream-analysis)
- [HTML Report Generation](#html-report-generation)
- [Chained Workflow — Enumeration to Exploitation](#chained-workflow--enumeration-to-exploitation)

---

## Basic Enumeration with No Flags

**MITRE ATT&CK:** T1082, T1518.1

```bash
bash linpeas.sh
```

The minimal invocation — LinPEAS runs with default settings, enumerating system information, users, groups, sudo/SUID/SGID binaries, capabilities, installed packages, kernel version, and privilege-escalation vectors. Output streams to stdout (and a timestamped `.log` file by default). This is the reconnaissance pass: no filtering, all findings, intended to be piped into `tee` for simultaneous screen viewing and log capture. The raw output is human-readable but verbose — typically 500-2000 lines depending on system configuration, services running, and installed packages.

In a standard engagement, this one command gives the attacker a complete privilege-escalation surface map: what binaries are SUID/SGID, which cron jobs are world-writable, which services run as root with exploitable configurations, and whether the kernel itself is vulnerable to known local-privilege-escalation exploits.

## Quiet Output Suppression

**MITRE ATT&CK:** T1082, T1518.1 (operational variation)

```bash
bash linpeas.sh -q
```

`-q` (quiet mode) suppresses LinPEAS's colored banner output and status messages, printing only the actual findings — useful when output is being redirected to a file for later analysis or piped into another tool, or when terminal noise could trigger endpoint-security alerts on particularly aggressive EDR sensors that flag unusual bash output patterns. The findings themselves are identical; only the verbosity around them is reduced.

A variant for ultra-stealth operations: redirect stderr to `/dev/null` to suppress non-critical warnings about missing binaries:

```bash
bash linpeas.sh -q 2>/dev/null
```

## Offline Mode Processing

**MITRE ATT&CK:** T1082 (source-side analysis, post-exfiltration)

```bash
# On target: capture baseline system state
bash linpeas.sh > /tmp/linpeas_output.txt 2>&1

# Exfiltrate /tmp/linpeas_output.txt to attacker host
# (via scp, curl, base64 over DNS, or other channel)

# On attacker host: re-run linpeas in offline mode against captured output
bash linpeas.sh -o /path/to/linpeas_output.txt
```

`-o` (offline mode) processes a previously-captured LinPEAS output file without requiring access to the live target system again — useful when:
- The target access window is narrow (webshell that gets deleted, temporary SSH access, etc.)
- Output needs to be parsed/filtered on a more powerful attacker workstation than the target allows
- The operator wants to avoid running LinPEAS twice (once to capture, once to analyze) on the same target, minimizing process-tree/command-history footprint
- Multiple analysts need to review the same snapshot independently without touching the target again

Offline mode re-parses the captured output for colored highlighting, severity ranking, and filtering flags (see `Quiet Output Suppression` and subsequent use cases) without touching the filesystem or running commands on the target.

## Kernel Vulnerability Scanning

**MITRE ATT&CK:** T1082 (kernel enumeration), candidates for T1548.001 (Privilege Escalation: Abuse Elevation Control Mechanism: Setuid and Setgid) once exploitation begins

```bash
bash linpeas.sh | grep -A 5 "Kernel version"
bash linpeas.sh | grep -E "CVE-|kernel.*vulnerable|dirtycow|dirtypipe"
```

LinPEAS enumerates the kernel version and cross-references it against known local-privilege-escalation CVEs (Dirty Cow, Dirty Pipe, OverlayFS, etc.). The baseline enumeration doesn't require flags — kernel version is printed by default. However, detailed CVE matching within LinPEAS output can be isolated by grepping for `CVE-` markers, which LinPEAS highlights in color and ranks by severity when findings match known exploitable kernel versions.

Example: on a Ubuntu 18.04 system with kernel 4.15.0 (vulnerable to Dirty Cow / CVE-2016-5195), LinPEAS flags this immediately. An attacker who finds such a kernel can then pivot to a dedicated exploit (e.g., `exploit-db/linux/dos/40847.c` or similar) for actual elevation. LinPEAS's role is *identification*, not exploitation.

## System Services and Privilege Analysis

**MITRE ATT&CK:** T1007 (System Service Discovery), T1518.1 (Software Discovery)

```bash
bash linpeas.sh | grep -A 3 "systemd"
bash linpeas.sh | grep -E "service|daemon" | grep -i "root"
```

LinPEAS enumerates all running systemd services (or init.d services on older systems), listing the user under which each runs. Attacker value: services running as root with world-writable config files, writable startup scripts, or vulnerable binaries present a direct privilege-escalation chain. LinPEAS flags these as high-priority findings.

Example findings flagged by default:
- Writable `/etc/systemd/system/` directories or `.service` files
- Services run as root with shell script wrappers (rather than compiled binaries), making them rewritable
- Insecure systemd service configurations (e.g., `PrivateTmp=no` on a service that shouldn't need it, or `User=` directives that don't match the actual binary owner)

## Network Configuration and Service Enumeration

**MITRE ATT&CK:** T1018 (Remote System Discovery), T1049 (System Network Configuration Discovery)

```bash
bash linpeas.sh | grep -E "listening|ESTABLISHED|inet"
bash linpeas.sh | grep -A 2 "ports"
```

LinPEAS enumerates listening TCP/UDP ports and established connections (`netstat -tulpn` / `ss -tulpn`), showing which services are bound to which addresses and which remote hosts the system is connecting to. This surfacing of network configuration reveals:
- Internal-only services exposed on 127.0.0.1 that might be exploitable if the attacker gains shell access
- Database servers, message brokers, or management interfaces accessible locally but never exposed to the network (common misconfiguration: Redis/MongoDB on 0.0.0.0 with no auth)
- Outbound connections to remote management infrastructure (C2, monitoring agents, backup services) that the attacker can pivot through or disrupt

## Cron Jobs and Scheduled Task Discovery

**MITRE ATT&CK:** T1053.006 (Scheduled Task/Job: Cron), T1547.011 (Boot or Logon Initialization Scripts: Cron Job)

```bash
bash linpeas.sh | grep -E "crontab|cron"
bash linpeas.sh | grep -A 5 "/etc/cron"
```

LinPEAS enumerates cron jobs across:
- User crontabs (`/var/spool/cron/crontabs/*`)
- System crontab (`/etc/crontab`)
- Drop-in cron directories (`/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`)
- At jobs (`/var/spool/at/*` if `atd` is running)

Attacker value: if any cron job calls a script that the attacker can write to (world-writable, group-writable-and-attacker-in-group, or owned by an account the attacker has compromised), that script will execute at the scheduled time under the cron owner's privileges — often root. LinPEAS flags world-writable cron scripts and scripts in attacker-writable directories as high-priority findings.

## Installed Software and Third-Party Tools

**MITRE ATT&CK:** T1518.1 (Software Discovery)

```bash
bash linpeas.sh | grep -E "apt|dpkg|rpm|yum" -A 20
bash linpeas.sh | grep -E "installed.*vulnerable|version.*vulnerable"
```

LinPEAS enumerates installed packages via `apt list --installed` (Debian/Ubuntu), `rpm -qa` (Red Hat/CentOS), and package managers for other distros. It also cross-references installed software versions against known CVEs, surfacing outdated or vulnerable packages.

Attacker value: if a vulnerable version of a common tool is installed (outdated OpenSSH, curl with a credential-leakage bug, an old version of `sudo` with a bypass, etc.), that bug is often exploitable without privilege escalation — just a code execution or information-disclosure primitive that can be chained into full system compromise.

## Password File and Credential Harvesting

**MITRE ATT&CK:** T1087.001 (Account Discovery: Local Account), T1555 (Credentials from Password Managers), T1187 (Forced Authentication)

```bash
bash linpeas.sh | grep -E "password|passwd|shadow"
bash linpeas.sh | grep -E "readable.*shadow|/etc/shadow"
```

LinPEAS enumerates the contents of readable credential files:
- `/etc/passwd` (always readable, contains usernames, UIDs, GIDs, home directories, but not password hashes)
- `/etc/shadow` (readable only by root by default, contains actual password hashes; LinPEAS flags if world/group readable)
- `/etc/gshadow` (group password hashes, same readability rules)
- `.bash_history`, `.zsh_history`, `.ssh/id_*` files in user home directories (if the attacker has filesystem access to another user's home, or if permissions are misconfigured)

Attacker value: readable `/etc/shadow` is a direct privilege-escalation path (hashcat/John can crack offline). Readable `.ssh/id_rsa` files are direct lateral-movement credentials. LinPEAS's role is *identification*; the actual extraction and cracking happens in parallel with `Hashcat/` (this repo) or `John the Ripper` workflows.

## SSH Key Enumeration

**MITRE ATT&CK:** T1552.004 (Unsecured Credentials: Private Keys), T1021.006 (Remote Services: SSH)

```bash
bash linpeas.sh | grep -E "\.ssh|authorized_keys|id_rsa"
bash linpeas.sh | grep -E "SSH.*private|rsa.*found|id_.*readable"
```

LinPEAS specifically flags:
- Readable SSH private keys in user home directories (`.ssh/id_rsa`, `.ssh/id_ed25519`, etc.) — if readable by the attacker's current user (or world), they're direct lateral-movement credentials without password cracking
- World-writable or group-writable `.ssh/` directories (permission misconfiguration that lets an attacker inject a malicious key into an account's `authorized_keys`)
- `authorized_keys` files listing public keys that the attacker might recognize (e.g., a known C2 operator's key, if the target has already been compromised and a persistence key installed)

## Container and Virtualization Detection

**MITRE ATT&CK:** T1082 (System Information Discovery — detection of container/hypervisor presence)

```bash
bash linpeas.sh | grep -E "docker|container|VM|hypervisor"
bash linpeas.sh | grep -E "cgroup|/.dockerenv|/proc/vz"
```

LinPEAS detects whether the current process is running in a container or VM by checking for:
- `/.dockerenv` file (Docker)
- `cgroup` entries mentioning `docker`, `lxc`, `podman`, or container names
- `/proc/vz` (OpenVZ)
- `VMWARE`, `KVM`, `Xen` signatures in CPUID or `/proc/cpuinfo`

Attacker value: detecting container vs. bare-metal execution changes the privilege-escalation playbook entirely. In a container, kernel exploits often don't work (the kernel is shared with the host), but container-escape vectors (privileged container, volume mounts of the host root, etc.) are high-value. On a VM, guest-escape vectors (hypervisor vulnerabilities) are potential targets, but standard kernel exploits still work.

## Sudo and Privilege Delegation Discovery

**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid), T1550.001 (Use Alternate Authentication Material: Application Access Token)

```bash
bash linpeas.sh | grep -E "sudo"
bash linpeas.sh | grep -E "NOPASSWD|sudo.*all"
bash linpeas.sh | grep -E "sudo -l"
```

LinPEAS enumerates sudo configuration and privilege grants:
- Runs `sudo -l` to list commands the current user can run without a password or with escalated privileges
- Parses `/etc/sudoers` and `/etc/sudoers.d/*` (readable only by root, but LinPEAS attempts to read them for completeness)
- Flags dangerous patterns: `NOPASSWD:ALL` (current user can run any command as root without a password), wildcards in sudo rules, or commands that invoke scripts in user-writable directories

Attacker value: if the current user can run a specific binary as root (e.g., `sudo /usr/bin/vim`), that binary might be exploitable for privilege escalation (many common tools have ways to spawn a shell or run arbitrary commands — vim can open a shell with `:!bash`, Python with `import os; os.system('/bin/bash')`). LinPEAS flags the command; exploitation is downstream.

## JSON Export for Downstream Analysis

**MITRE ATT&CK:** T1082 (System Information Discovery — collection and export)

```bash
bash linpeas.sh -j > linpeas_output.json
```

`-j` flag exports findings to JSON format, one finding per object, with structured fields for severity, category, description, and remediation. Useful for:
- Piping into `jq` or a Python script for automated analysis/filtering
- Ingesting into a SIEM or vulnerability-management tool
- Generating structured reports for management that prefer machine-readable output over human-readable text
- Comparing LinPEAS runs across time (snapshot #1 vs. snapshot #2) to detect configuration drift or new vulnerabilities

JSON output preserves all findings that would appear in raw text output, but structured in a way that scripts can consume. Each finding object typically includes: `category` (kernel, services, cron, sudo, etc.), `severity` (high/medium/low), `finding` (the actual discovery), and `references` (CVE links, remediation guidance).

## HTML Report Generation

**MITRE ATT&CK:** T1082 (System Information Discovery — reporting)

```bash
bash linpeas.sh -h > linpeas_report.html
```

`-h` flag generates a standalone HTML report with findings organized into collapsible sections, color-coded by severity, and including inline remediation guidance and external references (links to exploit-db, Metasploit modules, etc.). The report is self-contained — one `.html` file, no external dependencies, viewable in any browser.

Attacker value: the HTML report is the presentation layer for a post-exploitation report to a client/team, or it can be used to identify which findings are highest-priority for the attacker to pursue first (critical findings highlighted in red, exploitable vectors listed first per section). The structural organization also helps when juggling multiple LinPEAS runs from different targets — each report's consistent formatting makes side-by-side review easier.

## Chained Workflow — Enumeration to Exploitation

**MITRE ATT&CK:** T1082 (discovery), T1548.001 (escalation), T1548.004 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)

```bash
# 1. Capture full enumeration on target
bash linpeas.sh > enum.txt 2>&1

# 2. Exfiltrate enum.txt to attacker host
scp user@target:enum.txt .

# 3. Parse locally for high-priority vectors
grep -E "kernel.*vulnerable|NOPASSWD|writable.*cron|readable.*shadow" enum.txt | tee priorities.txt

# 4. Re-run LinPEAS offline for deep-dive on specific section
bash linpeas.sh -o enum.txt | grep -E "cron" > cron_findings.txt

# 5. Check cron findings for writable scripts
while read line; do
  script=$(echo "$line" | grep -oP '/.*\.sh' | head -1)
  echo "File: $script" && ls -la "$script" 2>/dev/null || echo "Not accessible locally"
done < cron_findings.txt

# 6. If a writable cron script found: inject payload, wait for cron execution
# (downstream: actual privilege-escalation exploit, not LinPEAS's responsibility)
```

Real-world engagement flow:
1. **Enumeration pass** — run linpeas.sh with no flags to get the full surface map
2. **Offline analysis** — exfiltrate output, parse for highest-priority vectors
3. **Deep-dive** — for top findings (e.g., writable cron scripts, readable `/etc/shadow`), use OS tools to verify permissions and content
4. **Exploitation** — escalate privileges via the identified vector (cron injection, file overwrite, binary exploitation, etc.)
5. **Verification** — confirm escalation success (e.g., `id` shows new UID; attempt to read `/root/` files)

LinPEAS's output is the *reconnaissance layer* of this workflow — it tells the attacker *which* vectors are present, not *how* to exploit them. The escalation itself typically happens via dedicated exploit code (custom scripts, Metasploit modules, compiled exploit binaries) once LinPEAS has identified the target.
