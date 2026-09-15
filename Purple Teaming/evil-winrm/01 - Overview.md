# evil-winrm — Overview

> 🔴 **Red Flag Principle:** evil-winrm **maintains an interactive shell session** over a persistent WinRM connection, fundamentally different from `psexec.py` or `wmiexec.py` which execute discrete commands and disconnect. A single operator session means a single persistent WinRM session, multiple commands executed as one continuing runspace — making session artifacts (WinRM event IDs 6, 8, 15, 33, 91) and PowerShell session logs the strongest signals for this tool compared to one-off command execution.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Built-In Commands & Utilities](#built-in-commands--utilities)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

**evil-winrm** was created by **Hackplayers** (a collective of security researchers) as a Ruby-based command-line WinRM client, first released circa **2019** and verified against the canonical source repository [`Hackplayers/evil-winrm`](https://github.com/Hackplayers/evil-winrm).

- **Canonical source:** [`Hackplayers/evil-winrm`](https://github.com/Hackplayers/evil-winrm) on GitHub — actively maintained (latest commits 2024–2025), authored/maintained by the Hackplayers collective.
- **License:** MIT — the full project (Ruby source, bundled libraries, included codec/bypass utilities) is open source.
- **Current state:** Actively used in penetration tests and red-team exercises; maintained with semi-regular commits and responsive issue handling. Docker images available via Docker Hub (`oscarakaelvis/evil-winrm`).
- **Language & dependencies:** Ruby 2.3 or higher; gems: `winrm` (≥2.3.7), `winrm-fs` (≥1.3.2), `stringio`, `logger`, `fileutils`. Optional: `krb5-user` (Debian) or `krb5` (BlackArch) for Kerberos support; Donut (for position-independent code injection) for advanced payloads.
- **Distribution:** Installed via `gem install evil-winrm` (PyPI-equivalent for Ruby) or by cloning the repo and running `bundle install`.

## How It Works

evil-winrm is a **full, interactive WinRM client** that establishes a persistent connection to a target's WinRM service (default port **5985** for HTTP, **5986** for HTTPS) and spawns a **runspace session** — a long-lived PowerShell execution context where commands accumulate state and persist across multiple invocations, the opposite of discrete command execution.

### Architecture Diagram

```
Operator's machine                         Target (Windows)
─────────────────                          ─────────────────
evil-winrm CLI
  (Ruby process)
    │
    ├─ Authenticate                ──▶   WinRM Service (5985/5986)
    │  (NTLM/Kerberos/cert/hash)        (HTTP/HTTPS)
    │
    ├─ Create runspace             ──▶   PowerShell Remoting
    │  (PSRP over WinRM)                Protocol (PSRP)
    │                                    
    ├─ Execute `whoami`            ──▶   Runspace executes
    │  (in runspace context)             command #1, returns output
    │                              ◀──
    │
    ├─ Execute `dir C:\`           ──▶   Same runspace, command #2
    │  (in the SAME runspace)            state persists from cmd #1
    │                              ◀──
    │
    └─ Close session               ──▶   Runspace terminates
       (or Ctrl+C)                       (or timeout)

     Target sees: ONE WinRM session with TWO (or N) commands,
                  executed sequentially in the SAME runspace,
                  all attributed to the same authentication context.
```

### Session Lifecycle

1. **Authentication** — Operator supplies credentials (cleartext, hash, Kerberos ticket, or certificate) via CLI flags.
2. **WinRM connection** — evil-winrm opens an HTTP/S connection to the target's WinRM service and negotiates PSRP (PowerShell Remoting Protocol).
3. **Runspace creation** — A new PowerShell runspace is created on the target. This runspace **persists** across multiple commands as long as the operator's session remains open.
4. **Interactive shell** — Each command typed is executed in the same runspace context; variables, functions, and session state accumulate across commands.
5. **Session termination** — When the operator disconnects (or times out), the runspace is destroyed.

This is fundamentally different from `psexec.py` (which creates a service, drops a binary, spawns a process per command, then cleans up) and `wmiexec.py` (which calls `Win32_Process.Create()` once per command in isolation). evil-winrm maintains **one connection**, **one runspace**, **multiple commands**.

### Protocol Detail

- **Transport:** HTTP (5985) or HTTPS (5986) — standard WinRM service ports (not SMB 445, not RPC 135).
- **Protocol:** PSRP (**PowerShell Remoting Protocol**) — Microsoft's standardized protocol for interactive and session-based PowerShell execution over WinRM.
- **Authentication:** Handled at the HTTP layer via NTLM, Kerberos, certificate-based (Mutual TLS), or Negotiate (auto-select).
- **Encryption:** HTTPS (5986) enforces encryption in transit; HTTP (5985) is plaintext unless the WinRM service is configured with a custom policy.
- **Runspace model:** Persistent — the operator's session maintains a single runspace handle across multiple commands, with full state accumulation.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| **Transport** | HTTP/S (TCP 5985/5986) to the target's WinRM listener |
| **Protocol** | PSRP (PowerShell Remoting Protocol) — standardized Microsoft protocol for remote PowerShell sessions |
| **Authentication** | NTLM, Kerberos (requires ccache or kirbi file), certificate-based mutual TLS, or cleartext credentials |
| **Session model** | Persistent runspace — one connection, one execution context, multiple commands with state accumulation |
| **Command execution** | PowerShell `Invoke-Command` equivalent: commands run inside the target's PowerShell process context, not spawning a separate `cmd.exe` |
| **Built-in capabilities** | In-memory DLL/binary loading (Dll-Loader, Invoke-Binary, Donut-Loader), dynamic AMSI patching (Bypass-4MSI), file transfer with progress indicators, service enumeration (no admin required for `services` command), command history, interactive shell with tab completion |
| **Underlying WinRM** | Microsoft's Windows Remote Management (WinRM) service — built into all modern Windows Server and client OS, typically listening on 5985 (HTTP) by default, requires the WinRM service to be running and listening |

## Command-Line Switches — Quick Reference

Verified against the live `Hackplayers/evil-winrm` source (`evil-winrm` script and the `lib/winrm.rb` core client). All flags below are exact and current.

| Flag | Argument | Plain-English meaning |
|---|---|---|
| `-i` / `--ip` | `<hostname\|ip>` | **Required** — target host IP address or FQDN. For Kerberos auth, FQDN is **mandatory** (SPN resolution requires a resolvable hostname, not a bare IP) |
| `-u` / `--user` | `<username>` | **Required** (unless Kerberos is used) — username to authenticate as. For local accounts, use just the username; for domain accounts, use `DOMAIN\username` format or let `-r` specify the realm |
| `-p` / `--password` | `<password>` | Password (cleartext). If omitted, evil-winrm prompts interactively. If `-H` (hash) is provided, `-p` is ignored |
| `-H` / `--hash` | `<nthash>` | **Pass-the-hash:** NTLM hash (NT hash only, LM hash not used by WinRM). Format: the 32-hex-character NT hash. Overrides `-p` if both are provided |
| `-K` / `--ccache` | `<path>` | Path to a Kerberos ccache file (MIT/Linux format) or a `.kirbi` file (Mimikatz format — auto-converted). Enables **Pass-the-Ticket** (T1550.003) |
| `-r` / `--realm` | `<DOMAIN>` | **Required for Kerberos** — Active Directory domain/realm name (e.g., `CORP.LOCAL`). Used to resolve SPNs and construct the target's Kerberos principal |
| `--spn` | `<prefix>` | SPN prefix for Kerberos authentication — default is `HTTP` (resulting in `HTTP/hostname`). Rarely changed; set to `HOST` or `CIFS` only if the target's SPNs deviate from standard |
| `-c` / `--pub-key` | `<path>` | Path to a public key certificate (.pem, .cer, or .pfx format). Used for certificate-based (mutual TLS) authentication. Requires `-k` as well |
| `-k` / `--priv-key` | `<path>` | Path to a private key (.pem format). Used with `-c` for certificate-based authentication |
| `-P` / `--port` | `<port>` | Port number — default **5985** (HTTP) or **5986** (HTTPS). Change if WinRM is listening on a non-standard port (common in hardened environments) |
| `-S` / `--ssl` | (flag, no argument) | **Force HTTPS** — connect via SSL/TLS (port 5986 if `-P` not specified). Attempts unencrypted HTTP by default; this flag overrides to encrypted HTTPS |
| `-a` / `--user-agent` | `<string>` | Custom `User-Agent` header string sent in the HTTP request. Default: `Microsoft WinRM Client`. Changing this does **not** provide meaningful evasion (Windows Defender/EDR watches the WinRM protocol, not the header value) |
| `-U` / `--url` | `<path>` | **Rarely used** — custom WinRM endpoint URL path. Default: `/wsman`. Only change if the target has a non-standard WinRM listener path |
| `-n` / `--no-colors` | (flag, no argument) | Disable colored terminal output — useful for logging to files or non-ANSI-capable terminals |
| `-N` / `--no-rpath-completion` | (flag, no argument) | Disable remote path completion/tab-completion for remote file paths — speeds up startup on slow/laggy connections where the remote path-enumeration step delays the shell |
| `-l` / `--log` | (flag, no argument) | **Enable logging** — writes all commands and output to a `.log` file in the current directory with a timestamp-based filename (e.g., `evil-winrm_20260811_120000.log`). Useful for post-session review |
| `-h` / `--help` | (flag, no argument) | Display help message and exit |
| `-V` / `--version` | (flag, no argument) | Display installed `evil-winrm` version and exit |

## Built-In Commands & Utilities

Once an interactive session is established, these commands are available **inside the shell** (typed at the `*Evil-WinRM*>` prompt), distinct from command-line flags (which are passed before connecting):

| Command | Purpose | Notes |
|---|---|---|
| `upload <local_file> [remote_path]` | Transfer a file from operator's machine to the target | If `remote_path` is omitted, uploads to the current working directory on the target. Progress bar shown. Supports wildcard patterns |
| `download <remote_file> [local_path]` | Transfer a file from the target to operator's machine | Same progress-bar mechanics as `upload`. Supports wildcard patterns |
| `services` | Enumerate all services on the target and their permission state | Does **not** require admin privileges — shows which services the current user has `GenericWrite`/`GenericAll`/permission to modify (useful for local privesc scouting) |
| `menu` | Display list of loaded PowerShell functions/cmdlets from the bundled library | Shows what helper functions (`Invoke-Binary`, `Dll-Loader`, `Bypass-4MSI`, etc.) are available in this session |
| `clear` / `cls` | Clear the screen | ANSI-standard terminal clear |
| `exit` | Disconnect and close the session | Cleanly terminates the runspace and closes the WinRM connection |
| **PowerShell commands** (native) | Any standard PowerShell cmdlet or script block | `whoami`, `Get-Process`, `$env:USERNAME`, `Get-ChildItem C:\`, `[System.Environment]::UserName`, etc. — full PowerShell is available |

### Built-In Helper Functions (Loaded by Default)

These are PowerShell functions **shipped with evil-winrm** and automatically available in every session (verify with the `menu` command):

| Function | Purpose | MITRE ATT&CK relevance |
|---|---|---|
| **Bypass-4MSI** | Dynamically patch the AMSI (`amsi.dll`) in-memory to bypass Windows Defender/EDR AMSI engine (does not uninstall AMSI, patches it to a no-op) | T1562.001 (Impair Defenses: Disable or Modify Tools) |
| **Invoke-Binary** | Load and execute a .NET assembly (`.exe` or `.dll`) entirely in memory with comma-separated command-line arguments — avoids disk writes | T1202 (Indirect Command Execution) / T1548 (Abuse Elevation Control Mechanism) if combined with UAC bypass |
| **Dll-Loader** | Load a DLL from local filesystem, SMB share, or HTTP/HTTPS URL and execute its export functions in-memory | T1105 (Ingress Tool Transfer) / T1202 |
| **Donut-Loader** | Inject a position-independent x64 payload (generated via the `donut` code-generator) directly into memory via `RtlCreateUserThread` | T1104 (Multi-Stage Channels) / T1055 (Process Injection) if chained with reflective DLL injection |
| **Colorization/output helpers** | `Write-Host` replacements with color styling for output clarity in an interactive session | Formatting only, no MITRE equivalent |

## Quick Use-Case List

1. **Interactive SYSTEM shell via cleartext credentials** — baseline case, most common usage
2. **Interactive shell via pass-the-hash** — no cleartext password needed, use an NT hash instead
3. **Interactive shell via Kerberos (pass-the-ticket)** — highest stealth potential, Kerberos-based auth only (no NTLM fallback to capture)
4. **Interactive shell via certificate-based auth** — when the target requires mutual TLS (non-standard, rare)
5. **Direct command execution** (non-interactive) — execute a single command and exit, scripted across many hosts
6. **File upload/download workflows** — using `upload`/`download` commands for staged payloads or data exfiltration
7. **In-memory code execution** — `Invoke-Binary` and `Dll-Loader` for running custom tools without disk writes
8. **AMSI bypass + in-memory script execution** — `Bypass-4MSI` followed by loading obfuscated PowerShell scripts
9. **Service enumeration for local privilege escalation** — the `services` command to identify modifiable/exploitable services
10. **Staged C2 delivery** — using the WinRM shell to download and execute a Cobalt Strike/Sliver beacon or other agent
11. **Chained lateral movement** — leveraging harvested credentials (from `secretsdump.py`, Mimikatz, etc.) to pivot to the next host
12. **Kerberos-keytab or AES-key authentication** — service account abuse with long-lived key material instead of passwords
13. **WinRM on non-standard ports** — targeting hardened environments where WinRM has been moved to a custom port (e.g., 5987, 5988)
14. **Interactive multi-command sessions with state persistence** — where the operator maintains session state across 10+ commands in one connection (distinct from one-off execution)

## Prerequisites

| Requirement | Notes |
|---|---|
| **Target has WinRM enabled and listening** | Default on all Windows Server editions and most modern Windows client OS (Windows 10+). Can be verified via `netstat -ano \| find "5985"` on the target, or port-scanned from the network. If disabled, requires local admin + command-line to re-enable (`winrm qc -q` or PowerShell equivalent) |
| **Network access to WinRM port** | Outbound TCP 5985 (HTTP) or 5986 (HTTPS) from the operator's machine to the target. Firewalls, NAT, or segmentation may block this |
| **Valid credentials or credential material** | Cleartext password, NT hash (pass-the-hash), Kerberos ticket (pass-the-ticket), or certificate. At minimum: username + one of {password, hash, ticket, cert} |
| **Target hostname must be resolvable** | For Kerberos auth (`-K`, `-r` flags), the `-i` parameter must be a fully-qualified domain name (FQDN) that resolves to the correct IP. A bare IP fails Kerberos SPN resolution |
| **Ruby 2.3+** | Operator's machine must have Ruby installed. Verify: `ruby --version` |
| **evil-winrm gem installed** | `gem install evil-winrm` or cloned from GitHub with `bundle install` |
| **For Kerberos auth specifically** | `krb5-user` (Debian/Ubuntu) or `krb5` (BlackArch/Red Hat) package, and a valid `.ccache` or `.kirbi` file. Optional: `kinit` to manually manage Kerberos tickets |
| **Operator's clock must be synchronized with the target** | Kerberos requires clock skew < 5 minutes; NTLM is more forgiving but still sensitive to large skews. Use `ntpdate` / `timedatectl` to sync if needed |
| **For certificate-based auth** | A valid X.509 certificate chain + private key that the target's WinRM service trusts (rare in standard environments; more common in federalized/multi-org scenarios) |

