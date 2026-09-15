# ATT&CK to Evidence Map

Reverse lookup: given a MITRE ATT&CK technique, where does the Linux evidence live and which note covers it. Verify IDs against the current Enterprise/Linux matrix — techniques evolve.

## Contents

- [Initial Access and Execution](#initial-access-and-execution)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Discovery and Lateral Movement](#discovery-and-lateral-movement)
- [Collection Exfil and Impact](#collection-exfil-and-impact)
- [Containers](#containers)

## Initial Access and Execution

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Exploit Public-Facing App | T1190 | Web/DB logs (access.log, error.log); Web Exploitation Playbook |
| Valid Accounts (SSH) | T1078 | Auth and Login Records; SSH Brute-Force Playbook |
| Brute Force | T1110 | `btmp`/auth.log fail→accept; Auth and Login Records |
| Command/Scripting: Unix Shell | T1059.004 | Shells (history), Auditd (EXECVE), Journal (`_CMDLINE`) |
| Command/Scripting: Python | T1059.006 | Shells (`.python_history`), Auditd |
| Ingress Tool Transfer | T1105 | History (`curl`/`wget`), Temp and Staging, Application logs |

## Persistence

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Cron | T1053.003 | Scheduled Tasks; Persistence (cron) |
| Systemd Timers | T1053.006 | Scheduled Tasks; Persistence (timers) |
| Systemd Service | T1543.002 | Persistence (systemd units) |
| Kernel Modules / LKM | T1547.006 | Persistence (kernel modules); Rootkit Playbook; Memory |
| SSH authorized_keys | T1098.004 | SSH Artifacts; Persistence (SSH) |
| Account Manipulation | T1098 | Users and Auth; Persistence |
| Create Account | T1136 | Users and Auth (`useradd` hunt) |
| PAM / pluggable auth | T1556.003 | Persistence (PAM backdoors) |
| Hijack Exec Flow: LD_PRELOAD | T1574.006 | Persistence (LD_PRELOAD); Rootkit Playbook |
| RC Scripts | T1037.004 | Persistence (init/rc, shell rc) |
| Trap / shell profile | T1546.004 | Shells; Persistence (profile.d, MOTD) |

## Privilege Escalation

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Setuid/Setgid | T1548.001 | Permissions (SUID/SGID) |
| Sudo/Sudo Caching | T1548.003 | Users and Auth (sudoers); Auditd (USER_CMD) |
| Exploitation for Priv Esc | T1068 | Journal/dmesg (crashes), Memory, package/kernel version |
| Abuse Linux Capabilities | T1548 | Permissions (`getcap`) |

## Defense Evasion

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Clear Command History | T1070.003 | Shells (history anti-forensics) |
| Clear Linux/Mac Logs | T1070.002 | Logging Architecture (tampering); wtmp/btmp |
| Timestomp | T1070.006 | Permissions (ctime vs mtime); File Systems |
| File Deletion | T1070.004 | Trash Artifacts; Live Response (`/proc/PID/exe` deleted) |
| Indicator Removal: immutable | T1070 | Permissions (`lsattr`/`chattr +i`) |
| Masquerading | T1036 | Live Response (fake process names, paths) |
| Rootkit | T1014 | Rootkit Playbook; Memory; SELinux/Kernel (taint) |
| Impair Defenses (SELinux/AppArmor/FW) | T1562 | SELinux and AppArmor; Live Response (firewall) |
| Hidden Files/Dirs | T1564.001 | Temp and Staging; File hunts (`find -name '.*'`) |

## Credential Access

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Credentials in Files | T1552.001 | Shells (history), Temp and Staging, app configs |
| Private Keys | T1552.004 | SSH Artifacts (private keys) |
| /etc/passwd and /etc/shadow | T1003.008 | Users and Auth; Auditd (`-f /etc/shadow`) |
| Unsecured Creds: cloud | T1552.005 | Enterprise Management (cloud-init, `.aws`) |

## Discovery and Lateral Movement

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| System/Account/Network Discovery | T1082/T1087/T1016 | Shells (history), Auditd |
| Remote Services: SSH | T1021.004 | SSH Artifacts (`known_hosts`); Auth Records |
| SSH Hijacking | T1563.001 | SSH Artifacts; Live Response (ssh-agent sockets) |

## Collection Exfil and Impact

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Archive Collected Data | T1560 | Temp and Staging (tar/gz/zip), Shells |
| Exfil Over C2 / Alt Protocol | T1041/T1048 | Live Response (network); Application logs |
| Data Encrypted for Impact | T1486 | ESXi and Linux Ransomware Playbook |
| Resource Hijacking | T1496 | Cryptojacking Playbook; Live Response |
| Service Stop | T1489 | Journal (service stops); Remediation |

## Containers

| Technique | ID | Evidence / Note |
|-----------|----|-----------------|
| Escape to Host | T1611 | Container: Escapes and Privilege Abuse |
| Deploy Container | T1610 | Container: Runtime Triage; Kubernetes |
| Container/Resource Discovery | T1613 | Container: Runtime Triage; Kubernetes |
| Build Image on Host | T1612 | Container: Malicious Images |
| Implant Internal Image | T1525 | Container: Malicious Images and Supply Chain |
