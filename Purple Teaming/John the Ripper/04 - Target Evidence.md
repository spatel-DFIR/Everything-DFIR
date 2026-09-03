# John the Ripper — Target Evidence

## Overview

**John the Ripper is an entirely offline password-cracking tool — it leaves ZERO evidence on the target host.** All activity is local to the attacking machine; the target system never sees network traffic, authentication attempts, or service probes of any kind.

This file is intentionally **thin** because there is no direct target-side evidence to hunt. Instead, this page redirects to the tools/techniques that *originally dumped* the hashes John now cracks.

---

## Direct Target Evidence: None

John the Ripper makes no changes to:
- **Filesystem** — no files created, modified, or deleted on the target
- **Event logs** — no authentication attempts, process creation, service modifications
- **Sysmon** — no process, network, file, or registry events
- **Network connections** — zero outbound or inbound traffic
- **Registry** — no modifications
- **Memory** — John never runs on the target
- **Credentials** — no exploitation of target credentials (only *copied* hashes are attacked)

The target is completely unaware that John is attacking its hashes.

---

## Hash Sources: Where Target Evidence Lives

Instead, **the evidence of password cracking on the target appears at the point where hashes were dumped**. This depends on how the operator obtained the hashes:

| How Hashes Were Obtained | Target Evidence | Cross-Link |
|---|---|---|
| `/etc/shadow` copied via `Impacket/secretsdump/` | DRSUAPI Event 4662 (privileged LDAP read), RPC to port 135/445 | `Impacket/secretsdump/` §04 |
| SAM registry dumped via `Impacket/secretsdump/` | Event 4633/4658 (SAM registry access), RemoteRegistry service activation | `Impacket/secretsdump/` §04, `Windows/08 - Registry Forensics/` |
| NTDS.dit copied via `Impacket/secretsdump/` | Volume Shadow Copy activity (VSS), Event 4662, Directory Service Changes logs | `Impacket/secretdsump/` §04, `Windows/23 - Active Directory/NTDS.dit` |
| Kerberos hashes from `Impacket/GetUserSPNs/` | Event 4769 (TGS-REQ), UDP traffic to port 88 | `Impacket/GetUserSPNs/` §04 |
| Hashes from web-app database breach | Web-app error logs, database access logs, or (if network-based) Zeek/NetFlow | Tool-specific (SQL injection, API abuse) |
| Hashes extracted from `/etc/passwd` (world-readable on some systems) | No event log (Unix typically doesn't log file reads); possible Auditd if enabled | `Linux/06 - Logs/Auditd/` |
| Hashes from application configuration file (e.g., `.htpasswd`) | File access logs (Auditd, Windows-equivalent) if enabled | Application-specific |

**Key insight:** The target's evidence is **in the tool chain that dumped the hashes, not in John itself**.

---

## No Authentication Attempts

Unlike network-based crackers (Hydra, Spray365), John never attempts to:
- Log in to any service
- Send authentication probes
- Query DNS or make HTTP/S requests
- Touch any network resource on the target

Therefore, no authentication-event logs appear:
- No Event 4625 (failed login)
- No Event 4624 (successful login)
- No Sysmon 3 (network connection)
- No firewall logs
- No IDS/IPS alerts

---

## No Process Footprint

John never runs a process on the target; it runs only on the **attacking machine**. No:
- Process creation logs (Event 4688, Sysmon 1)
- Child-process trees
- DLL loads or code injection (Sysmon 7, 8, 10)
- File access (Sysmon 11)
- Registry modifications (Sysmon 12, 13)

---

## No Data Exfiltration Evidence

Once John cracks passwords, the operator uses them in **separate tools** (e.g., `Impacket/psexec/`, RDP, SSH) to access the target. Those **separate accesses** leave evidence; John itself leaves none.

For example:
- Operator runs John, cracks `alice:password123`
- Operator later uses `ssh alice@target` or `psexec.py alice:password123@target`
- **The SSH/psexec tool creates the target-side evidence**, not John

---

## Indirect Target Evidence: Result of Using Cracked Passwords

Once the operator uses cracked passwords to access the target, **different tools** leave evidence:

| Cracked Password Used For | Evidence Location | Cross-Link |
|---|---|---|
| SSH login | `/var/log/auth.log` (successful login), Auditd (if enabled), bash history | `Linux/06 - Logs/Authentication/` |
| RDP login (Windows) | Event 4624 (successful logon), Sysmon login events | `Windows/04 - Logging/Event Logs/` |
| Domain account login | Event 4624, kerberos TGT request (Event 4768), subsequent logon events | `Windows/04 - Logging/Active Directory/` |
| `Impacket/psexec/` lateral movement | Service creation (Event 4697, 7045), named pipe, SMB traffic | `Impacket/psexec/` §04 |
| Application database login (e.g., MySQL) | Application logs (slow-query log, general query log if enabled) | Database-specific |

---

## Analysis Methodology: Reverse-Engineer the Attack

If you find evidence of hashes being dumped (e.g., DRSUAPI activity), suspect John:

1. **Identify the hash-dump event** — Event 4662 (LDAP read), RemoteRegistry access, VSS activity, etc.
2. **Timeline correlation** — check the attacking host's `john.pot` mtime
3. **Confirm via source-side artifacts** — if you acquire the attacking host, look for pot files, wordlists, session files
4. **Post-crack usage** — if cracked passwords were *used* to compromise targets, look for **subsequent authentication events** using those passwords (Event 4624, `/var/log/auth.log`, SSH connections, etc.)

---

## Cross-Links to Hash-Source Tools

- **Impacket/secretsdump/** — most common source of Windows SAM, NTDS.dit, LSA Secrets hashes
- **Impacket/GetUserSPNs/** — Kerberos TGS hashes (Kerberoasting)
- **Mimikatz/lsadump (DCSync)/** — DRSUAPI-based hash extraction (alternative to secretsdump for NTDS.dit)
- **Mimikatz/sekurlsa (Credential Dumping)/** — LSASS memory dump (can yield plaintext credentials or cached NTLM hashes)
- **ProcDump/** — LSASS memory dump (alternative to Mimikatz for obtaining hashes/credentials)
- **LaZagne/** — local credential harvesting from browser/app stores (pre-John, if passwords are stored hashed)

---

## Defensive Recommendations

Since John leaves no target-side evidence, defense focuses on **detecting the hash-dump technique**:

1. **Monitor DRSUAPI/RemoteRegistry access** — Event 4662, RemoteRegistry service activation
2. **Alert on volume shadow copy activity** — VSS creation for NTDS.dit extraction
3. **Detect ntdsutil/vssadmin abuse** — common DC-side techniques to dump NTDS
4. **Require SMB signing** — limits options for hash extraction over the network
5. **Enable audit logging** — both Directory Service Changes (5136) and Directory Service Access (4662)
6. **Restrict DCSync rights** — only allow DC computer accounts to perform DCSync
7. **Post-compromise detection** — monitor for use of cracked passwords in authentication logs (Event 4624, SSH logs)

Once hashes are on the attacking host, **John's execution is undetectable on the target** — the focus shifts to source-side detection (pot files, wordlists, shell history) and detecting the *use* of cracked passwords.

---

## Summary

| Artifact | Target Evidence? | Location |
|---|---|---|
| John process | ❌ No | Attacking host only |
| Pot file | ❌ No | Attacking host only |
| Network traffic | ❌ No | John is completely offline |
| Authentication attempt | ❌ No | John never probes target |
| Event logs | ❌ No | No target-side events |
| Filesystem changes | ❌ No | No target modifications |

**Bottom line:** Hunt the **source** (pot file, wordlists, shell history) and the **hash-dumping technique** (DRSUAPI events, RemoteRegistry, VSS), not the cracking tool itself.
