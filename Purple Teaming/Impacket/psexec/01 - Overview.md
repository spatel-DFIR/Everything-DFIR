# Impacket — psexec.py — Overview

> 🔴 **Red Flag Principle:** A new **service** appears on a host with a **short, random-looking name and a binary sitting directly in `C:\Windows\`** (not `System32`, not `Program Files`), installed moments after a **remote SMB logon**, started once, run as **SYSTEM**, and communicating over a named pipe called **`RemCom_communicaton`** — misspelled, preserved unchanged from ~20-year-old source code. That exact fingerprint is Impacket's `psexec.py`.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Impacket is a Python library for constructing and manipulating network protocols, originally released by **CORE Security** (Core Impact team) in the early 2000s. The library — and `psexec.py` specifically — is credited in its own source header to **beto (Alberto Solino, @agsolino)**. CORE Security was later acquired by HelpSystems, rebranded **Fortra**, which maintains the project today at [`github.com/fortra/impacket`](https://github.com/fortra/impacket) under a modified Apache license.

`psexec.py` lives in the project's `examples/` folder, and its own source header describes it plainly:

```
# Description:
#   PSEXEC like functionality example using RemComSvc
#
# Reference for:
#   DCE/RPC and SMB.
```

It is a **pure-Python reimplementation of Sysinternals PsExec's remote-execution behavior**, built entirely on SMB and DCE/RPC — no dependency on the real `PsExec.exe` binary. Critically, it doesn't reuse Microsoft's PsExec service internals at all: it repurposes the **open-source RemCom project's service binary** as the payload it drops and runs. This one fact drives most of this note's forensic value — **every default-configuration run of Impacket's `psexec.py` drops a functionally identical service binary**, generated from the same embedded template each time, which is why hash-based hunting works so well against it (see `04 - Target Evidence.md` and `05 - Detection and Hunting.md` for the important caveat: this only holds when the operator hasn't overridden the binary with `-file`).

## How It Works

```
Attacker (psexec.py)                                Target (10.10.10.5)
─────────────────────                                ────────────────────
1. SMB Session Setup (TCP 445, or 139) ────────────▶  Authenticate via NTLM or Kerberos
                                                        (password, hash, ticket, or key)

2. Locate a writable admin share ───────────────────▶  Tries ADMIN$ (→ C:\Windows\) first,
   (findWritableShare())                                falls back to other writable shares

3. Write service binary ────────────────────────────▶  \\10.10.10.5\ADMIN$\<8-random-letters>.exe
   (RemCom-derived, embedded in the script)

4. DCE/RPC bind to \PIPE\svcctl (MS-SCMR) ──────────▶  OpenSCManagerW()
     ├─ CreateServiceW(<4-random-letters>,               (service name ≠ binary name —
     │    ImagePath=C:\Windows\<8-random-letters>.exe,     two independent random strings)
     │    dwStartType=SERVICE_DEMAND_START)
     └─ StartServiceW()                               SCM launches the service ──▶ services.exe
                                                                                       └─▶ <8-random-letters>.exe (RemComSvc, SYSTEM)
                                                                                             └─▶ cmd.exe /Q /K ...
                                                                                                   └─▶ (operator's commands)

5. Open \PIPE\RemCom_communicaton ───────────────────▶  RemComSvc opens the control pipe plus
   + per-session \PIPE\RemCom_stdin/stdout/stderr        per-process stdin/stdout/stderr pipes,
   (interactive I/O relay)                                pipes cmd.exe's I/O back over SMB

6. On exit / Ctrl+C (installService.uninstall()):
     ├─ ControlService(SERVICE_CONTROL_STOP)  ────────▶  Service stopped
     ├─ DeleteService()                       ────────▶  Service registry key removed
     └─ deleteFile() the uploaded binary      ────────▶  Binary deleted from ADMIN$
```

Step-by-step:

1. **Authenticate** — negotiates an SMB session (TCP 445; legacy NetBIOS 139 also supported via `-port`) using a cleartext password, NTLM hash (pass-the-hash), a Kerberos ticket, an AES key, or a keytab.
2. **Find a writable share** — tries `ADMIN$` first (maps to `%SystemRoot%`, i.e. `C:\Windows\`); if that's not writable with the supplied credentials, `findWritableShare()` walks other shares looking for one it can write to.
3. **Drop the service binary** — uploads the embedded RemCom-derived executable under a **random 8-character mixed-case filename** (e.g. `aBcDeFgH.exe`) unless `-remote-binary-name` overrides it.
4. **Create & start the service via SVCCTL** — binds to `\PIPE\svcctl` (MS-SCMR protocol) and calls `OpenSCManagerW` → `CreateServiceW` → `StartServiceW`. The **service name is a separate random 4-character mixed-case string** (not the same value as the 8-character binary name — two independent random draws) unless `-service-name` overrides it. Start type is `SERVICE_DEMAND_START` — it only ever runs because `psexec.py` explicitly starts it, never on boot.
5. **Interactive I/O over named pipes** — the running service opens `\PIPE\RemCom_communicaton` (fixed name, hard-coded in the RemCom protocol, always spelled exactly this way including the typo) as a control channel, plus per-invocation `\PIPE\RemCom_stdin`/`stdout`/`stderr` pipes suffixed with a random 4-letter "machine" tag and the process ID, and relays a `cmd.exe` session's I/O back to the operator over SMB.
6. **Cleanup** — on a clean exit, the script calls `installService.uninstall()` (stop + delete the service) and deletes the uploaded binary — in **both** the success path and the exception handler, so even a crashed session usually attempts cleanup. It is still only *best-effort*: a killed network path, EDR blocking the delete RPC, or a hard process kill on the operator side skips this entirely, leaving the service key and/or binary behind (see `04 - Target Evidence.md`).

**Always runs as SYSTEM** — because execution happens via the Service Control Manager, not a logged-on user context. This is a key differentiator from WMI- or WinRM-based lateral movement, which typically execute as the authenticating user rather than SYSTEM.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport | SMB (TCP 445), legacy NetBIOS session service (TCP 139 via `-port`) |
| Authentication | NTLM (password or pass-the-hash) or Kerberos (ticket, AES key, or keytab) |
| File delivery | SMB write to an administrative share — `ADMIN$` preferred, falls back to any other writable share |
| Remote execution | MS-SCMR (Service Control Manager Remote Protocol) over `\PIPE\svcctl` |
| Interactive I/O | RemCom's proprietary named-pipe protocol — `\PIPE\RemCom_communicaton` (fixed) + per-invocation `\PIPE\RemCom_stdin/stdout/stderr<machine><pid>` |
| Execution context | SYSTEM (service context, not the authenticating user's token) |

## Command-Line Switches — Quick Reference

Full flag reference as of the current `examples/psexec.py` in the official [fortra/impacket](https://github.com/fortra/impacket) repository, written for a reader who has never run the tool.

**Positional**

| Argument | Meaning |
|---|---|
| `target` | `[[domain/]username[:password]@]<targetName or address>` — who to authenticate as and where |
| `command` | What to run remotely. **Default: `cmd.exe`** — omit it entirely to land in an interactive shell |

**General**

| Switch | Plain-English meaning |
|---|---|
| `-c pathname` | Upload a **local file** to the target and execute *that* instead of relying on the built-in relay — arguments for it go in the `command` positional. This is a **second, separate file drop** from the RemCom service binary — see `02 - Hands-On Use Cases.md` |
| `-path` | Working directory on the target to run the command from |
| `-file` | Supply your **own** RemCom-compatible service binary instead of Impacket's bundled default. **This defeats hash-based detection** of the dropped binary — see the caveat in `05 - Detection and Hunting.md` |
| `-ts` | Prefix every output line with a timestamp (operator convenience, doesn't touch the target) |
| `-debug` | Verbose debug output — troubleshooting the tool itself, doesn't touch the target |
| `-codec` | Character encoding used to decode the target's console output (fixes garbled output on non-English systems) |

**Authentication**

| Switch | Plain-English meaning |
|---|---|
| `-hashes LMHASH:NTHASH` | Authenticate with an NTLM hash instead of a password — pass-the-hash. LM hash is usually the placeholder `aad3b435b51404eeaad3b435b51404ee` |
| `-no-pass` | Don't prompt for a password — pairs with `-k` (Kerberos) or `-hashes` |
| `-k` | Use Kerberos authentication instead of NTLM (reads a ticket from the `KRB5CCNAME`-pointed ccache, or requests one if a password is supplied) |
| `-aesKey` | Authenticate with a Kerberos AES key (128- or 256-bit) instead of a password or RC4/NT hash — quieter, avoids the weaker NTLM-family crypto entirely |
| `-keytab` | Read Kerberos keys from a keytab file — common for service-account authentication |

**Connection**

| Switch | Plain-English meaning |
|---|---|
| `-dc-ip` | IP of a domain controller — needed for Kerberos auth if DNS won't resolve one |
| `-target-ip` | Force a specific IP for the connection even if `target` is a hostname (useful to route around DNS or segmented name resolution) |
| `-port {139,445}` | SMB port to use. **Default: 445** |
| `-service-name` | Override the default random 4-character service name |
| `-remote-binary-name` | Override the default random 8-character dropped binary filename |

## Quick Use-Case List

- Interactive SYSTEM shell via cleartext credentials
- Pass-the-hash execution (NTLM hash, no cleartext password)
- Pass-the-ticket / Kerberos execution, including AES-key and keytab variants
- One-off, non-interactive command execution
- Uploading and running a custom local tool (`-c`) rather than just relaying `cmd.exe`
- Swapping the service binary (`-file`) to evade hash-based detection
- Blending in with custom service/binary names (`-service-name` / `-remote-binary-name`)
- Fleet-wide / mass execution scripted across a target list
- Alternate-port or direct-IP targeting to route around DNS/firewall quirks
- Staging and launching a secondary C2 payload
- Chained use immediately after credential harvesting (e.g. `secretsdump.py` → `psexec.py`)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Credential material | One of: cleartext username+password, NTLM hash (`LMHASH:NTHASH`), a Kerberos ticket (`.ccache`), an AES key, or a keytab |
| Privilege on target | Authenticating account must be a **local administrator** on the target — needed for admin-share write access and `SC_MANAGER_CREATE_SERVICE` rights |
| Network reachability | TCP 445 (SMB) to the target by default; TCP 139 as a fallback via `-port` |
| Name resolution | Required for Kerberos auth (SPN resolution needs the hostname, not a bare IP) — use `-target-ip` to decouple hostname-for-Kerberos from routing |
| Domain context | A local account works against a standalone host; a domain account plus a reachable DC is needed for Kerberos auth |
