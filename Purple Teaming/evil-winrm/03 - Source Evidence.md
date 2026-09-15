# evil-winrm — Source Evidence

Evidence left on the **attacking/operator machine** — the attacker's own host, where evil-winrm was run. This is typically a pentester's or red-teamer's Linux box, but can also be a compromised Windows host running Ruby.

## Contents
- [Process & Runtime Artifacts](#process--runtime-artifacts)
- [Filesystem Artifacts](#filesystem-artifacts)
- [Network State](#network-state)
- [Shell History](#shell-history)
- [Log Files (if `-l` flag was used)](#log-files-if--l-flag-was-used)
- [Memory Forensics](#memory-forensics)
- [Credential Material Left Behind](#credential-material-left-behind)
- [Correlation with Target Timeline](#correlation-with-target-timeline)

---

## Process & Runtime Artifacts

| Artifact | Detail |
|---|---|
| **Ruby process** | A `ruby` process running the evil-winrm script — visible in `ps`, process dumps, and EDR telemetry if the attacker's machine is monitored. The command line typically shows: `ruby /path/to/evil-winrm` or `ruby -I/path/to/evil-winrm` if installed via `gem`. Stops immediately when the operator disconnects or closes the shell |
| **Child processes of Ruby** | None typically — evil-winrm is a single Ruby process, no spawned children (unlike `psexec.py` or other tools that spawn `cmd.exe`/`powershell.exe` locally for encoding/preprocessing). All command execution happens **remotely** inside the target's PowerShell runspace |
| **Network sockets** | One persistent TCP socket to the target on port 5985 (HTTP) or 5986 (HTTPS), established when `evil-winrm` connects and closed when the session ends. Visible in `netstat -ano` or `lsof -i` on the attacker's machine |
| **Environment variables** | If Kerberos is used (`-K` flag), the `KRB5CCNAME` environment variable may be set to point to the ccache file path — visible in `env` or in `/proc/self/environ` if the process is inspected |

## Filesystem Artifacts

| Path | Artifact | Detail |
|---|---|---|
| `~/.evil-winrm/` | RC file (rare) | Rarely present; evil-winrm does not have a default config file like other tools. If the operator created a shell alias or helper script, it would live here at operator discretion, not from evil-winrm itself |
| `/tmp/` or `$TMPDIR` | Session logs (if `-l` flag used) | If evil-winrm was run with `-l`, it writes a log file to the current working directory with a timestamp-based name, e.g., `evil-winrm_20260811_120000.log` — contains all commands and responses from the session. Persists after evil-winrm exits; must be manually deleted or will remain on disk indefinitely |
| Operator's home directory | Downloaded files via `download` command | If the operator used `download` during the session, the downloaded files are saved locally; by default, to the current working directory when evil-winrm was invoked. Forensic signatures depend on the file type (executable, document, database, etc.) |
| `/etc/krb5.keytab` (Linux/Unix only) | Kerberos keytab (if shared from Windows) | If using Kerberos auth and a keytab was copied to the attacker's machine, it persists after the session ends. Presence of a `.keytab` file on an attacker-controlled host is a strong signal of Kerberos abuse |
| Operator's `.config/` or `.ssh/` directories | Certificate files (if `-c/-k` used) | Private key files (`.pem`, `.key`) used for certificate-based auth. If copied to the attacker's machine, they persist as leverage for future attacks |

## Network State

| Observable | Detail |
|---|---|
| **Connection log (netstat/ss)** | At the moment of running, `netstat -ano \| grep 5985` or `ss -tuln` shows the connection state — typically `ESTABLISHED` from the attacker's IP to the target's 5985/5986. Disappears from the connection table after the session closes (but network-capture files may retain the closed connection's metadata) |
| **Firewall rules** | No **outbound** firewall rules are modified by evil-winrm itself — if the attacker's firewall allows outbound TCP 5985/5986, the connection succeeds; if not, evil-winrm hangs or fails with a connection timeout. A successful session implies the attacker's network egress permits TCP to the target on the WinRM port |
| **Packet capture (if network tapping is in place)** | The full HTTP/S stream from the attacker to target is captured in PCAP format if a network sniffer is running. HTTPS (5986) traffic is encrypted; HTTP (5985) traffic is not. PSRP protocol payloads are visible in plaintext for HTTP sessions — see `Windows/12 - Lateral Movement.md` for protocol decode examples |
| **DNS queries** | If the target was specified as an FQDN (e.g., `dc01.corp.local`), the attacker's machine performs a DNS query to resolve the hostname before connecting. The query is visible in local DNS logs (`/var/log/systemd/journal` for systemd-resolved, `/var/log/dnsmasq.log` for dnsmasq, or in the attacker's recursive resolver's logs if the query is forwarded) |

## Shell History

| Shell | History File | What It Captures |
|---|---|---|
| **bash** | `~/.bash_history` | Every `evil-winrm` command typed at the shell, including arguments, flags, and credentials: `evil-winrm -i 10.10.10.5 -u jsmith -p 'Summer2026!'` — **cleartext passwords are visible** in bash history if typed directly on the command line (not prompted) |
| **zsh** | `~/.zsh_history` | Same as bash history, plus timestamps |
| **fish** | `~/.local/share/fish/fish_history` | Same content, different JSON format |
| **tcsh/csh** | `~/.history` | Captured, though less common on modern systems |

**Critical for OPSEC:** Credentials passed via `-p` flag or `-H` hash value are **plaintext in shell history** if not explicitly suppressed. Operators typically:
1. Use environment variables and avoid shell history: `export PASS='Summer2026!'; evil-winrm -i 10.10.10.5 -u jsmith -p $PASS` (still lands in history but hides the credential slightly)
2. Run `history -c` or `history -w` to clear history after a session (deletes the current shell's history from disk)
3. Use `set +o history` before running evil-winrm to disable history for that one command, then `set -o history` to re-enable

Once inside the evil-winrm interactive shell (the `*Evil-WinRM*>` prompt), commands typed at that prompt are **not** captured in the attacker's local shell history — they are internal to evil-winrm's own session and only logged if the `-l` flag was passed (see below). This is a key distinction from other tools: entering an interactive evil-winrm shell "pauses" the local shell history.

## Log Files (if `-l` flag was used)

If the operator ran `evil-winrm ... -l`, a session log file is written to disk:

| Artifact | Detail |
|---|---|
| **Filename** | `evil-winrm_<YYYYMMDD>_<HHMMSS>.log` in the current working directory, e.g., `evil-winrm_20260811_120530.log` |
| **Content** | Every command typed at the `*Evil-WinRM*>` prompt, every output response, timestamps, and any upload/download activity — a complete operational transcript of the interactive session |
| **Lifecycle** | Created when evil-winrm starts with `-l` and written to continuously as commands are executed. **Persists on disk after evil-winrm exits** — not automatically deleted |
| **Forensic value** | If an attacker used `-l` (unusual on actual operations, more common in red team exercises for audit trails), the log file is a complete, verbatim record of every command executed in the session. This is one of the **strongest** artifacts an analyst can recover from an attacker's machine |

## Memory Forensics

| Observable | Detail |
|---|---|
| **Ruby process memory** | If the attacker's machine is captured live (memory dump, `core` dump, or EDR-based memory scanning), the `ruby` process's memory may contain: credentials passed via command-line flags, unencrypted responses from the target (if HTTP/5985 was used), and buffered PowerShell command output. Modern AMSI/EDR may scan this memory for suspicious content |
| **Kerberos tickets in memory** | If Kerberos auth was used, the system's Kerberos ticket cache (typically in-memory or in `~/.krb5cc_<UID>` if using MIT Kerberos) contains the TGT and any TGS tickets issued for the WinRM authentication. These are **live, usable tickets** and a powerful indicator of Kerberos abuse on the attacker's machine |
| **OpenSSL/TLS handshake state** | If HTTPS (5986) was used and the session is captured mid-connection, TLS session keys may be recoverable if an attacker's machine's SSLKEYLOGFILE environment variable was set (rarely on purpose, sometimes accidentally if tools like curl are configured this way) |
| **Bash/shell process memory** | If the attacker typed credentials on the command line (`evil-winrm ... -p 'Password123!'`), those credentials may still reside in bash/zsh process memory if the process hasn't exited. EDR tools often scan process memory for leaked credentials |

## Credential Material Left Behind

| Material | Risk | Mitigation |
|---|---|---|
| **Kerberos ccache file** (if `-K` was used) | High — the `.ccache` file is a **live, usable ticket cache**. If left on the attacker's machine, it can be stolen and replayed (T1558 Pass-the-Ticket abuse). Tickets expire (usually 24 hours for a TGT), but while valid, they're a high-value target | Use `kdestroy` or `rm` to delete the ccache file immediately after the session. Alternatively, use a temporary directory and clean it at shutdown |
| **Kerberos keytab file** (if service account keytab was copied to attacker) | Very High — a keytab is **equivalent to a password** for the service account. It never expires (unless the account's password is changed) and can be reused indefinitely for authentication | Keytabs should never be copied to an attacker-controlled machine. If obtained, delete immediately after use; document the presence as a credential compromise |
| **NT hash** (if `-H` was used) | Medium — the hash itself is not a password, but it can be used for pass-the-hash attacks. If the attacker's machine is compromised, the hash can be extracted from memory or shell history | Use environment variables to avoid plaintext in shell history: `export HASH='...'` instead of inlining it on the command line |
| **Cleartext password** (if `-p` was used with a plaintext password) | Very High — stored in shell history, process memory, and `/proc/<pid>/environ` for the `ruby` process | Avoid passing cleartext on the command line. Use `-p` with a prompt (omit the argument) to avoid shell history |
| **Certificate private key** (if `-k` was used) | Very High — a stolen private key is equivalent to the account/identity it represents and can be used indefinitely | Private keys should never be copied to an attacker-controlled machine long-term. If copied for a temporary session, delete immediately. If the private key is leaked/stolen, the certificate should be revoked immediately |
| **Session log file** (if `-l` was used) | Medium-High — the `.log` file contains a plaintext transcript of all commands and responses from the target, including command output that may contain credentials, secret data, or proprietary information | Delete the log file immediately after the session ends if running in an environment with threat of the attacker's machine being compromised |

## Correlation with Target Timeline

The tightest correlation between the attacker's machine and the target occurs at the **moment of connection**:

| Attacker-Side Event | Target-Side Event | Correlation Anchor |
|---|---|---|
| evil-winrm launches (`ruby` process appears in `ps`) | WinRM service logs the connection (Security 4624 Type 3, or WinRM Operational 15) | **Timestamp match (within seconds)** — the attacker's `ruby` process start time should correlate with the target's inbound WinRM session creation event |
| DNS query for target hostname (if FQDN used) | No direct equivalent on target | Visible in DNS logs on the attacker's network segment; may indicate reconnaissance phase before evil-winrm execution |
| TCP SYN to target:5985/5986 from attacker's IP | Target's WinRM service receives inbound connection | **Source IP + destination port + timestamp** — matches the attacker's outbound socket and the target's inbound event |
| evil-winrm receives the PSRP/WinRM response (HTTP 200) | WinRM service completes the initial handshake | **Timing**: typically within 1–2 seconds of the TCP handshake, often within 1 millisecond of the target's authentication log entry |
| First PowerShell command typed at the prompt (e.g., `whoami`) | Runspace receives the command and executes it, logs appear in Security/PowerShell event logs | **Timestamp + command content** — if the command is recovered from the target's event logs (e.g., via Sysmon 1 or 4688), it matches the exact command typed by the attacker |
| Session remains open (attacker typing commands) | Target's WinRM session remains active; multiple commands are executed in the same runspace | **Persistent connection** — the single WinRM session on the target corresponds to the single `ruby` process on the attacker's machine |
| evil-winrm exits (Ctrl+C or `exit` command) | Target's WinRM session terminates; runspace is destroyed | **Correlation endpoint** — the attacker's `ruby` process termination aligns with the target's WinRM session-close event (event ID 91 on modern Windows) |

This **connection-time correlation** is the strongest signal for linking an attacker machine to a target compromise: a `ruby` process start time on the attacker machine should be nearly identical (within 1–5 seconds, accounting for clock skew) to the WinRM session-open event on the target.

