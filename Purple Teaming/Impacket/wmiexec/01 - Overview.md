# Impacket — wmiexec.py — Overview

> 🔴 **Red Flag Principle:** `WmiPrvSE.exe` (the WMI Provider Host) spawns an unexpected child process — `cmd.exe`, `powershell.exe`, or, if the operator used `-silentcommand`, the target binary/command **directly with no `cmd.exe` in between at all** — moments after an inbound DCOM/RPC authentication. No service is ever created. The only filesystem artifact in the default configuration is a tiny, extensionless, **transient** file named `__<unix-epoch-timestamp>` (e.g. `__1754176575.883421`) that briefly appears on an administrative share, gets read back over SMB, and is deleted within the same second — that file exists solely to shuttle command output back to the operator, not as a payload. That combination — `WmiPrvSE.exe` as the unexplained parent process plus a fleeting `__<timestamp>` file — is Impacket's `wmiexec.py`.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Interactive Shell Commands](#interactive-shell-commands)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`wmiexec.py` lives in the same `examples/` folder of [`fortra/impacket`](https://github.com/fortra/impacket) as `psexec.py`, maintained under the same modified Apache license, credited to the same original author in its source header — **beto (Alberto Solino, @agsolino)**. It carries the same "Reference for" convention psexec's header does, except here it reads simply:

```
# Description:
#   A similar approach to smbexec but executing commands through WMI.
#   Main advantage here is it runs under the user (has to be Admin)
#   account, not SYSTEM, plus, it doesn't generate noisy messages
#   in the event log that smbexec.py does when creating a service.
#   Drawback is it needs DCOM, hence, I have to be able to access
#   DCOM ports at the target machine.
#
# Reference for:
#   DCOM
```

That comment, taken directly from the current source, is the single most important piece of design context in this note: the tool's own author frames it as a **deliberate evolution away from service-based execution** (which both `psexec.py` and `smbexec.py` rely on) specifically to avoid the noisy Service Control Manager event trail (System 7045/7036) those tools generate. The tradeoff, also stated by the author, is that it needs a working DCOM path to the target rather than just SMB — see [Prerequisites](#prerequisites).

## How It Works

`wmiexec.py` does **not** create a service and does **not** drop an executable payload in the default configuration. It authenticates over DCOM/RPC, calls the `Create` method on the `Win32_Process` WMI class to spawn a process directly, and — only if the operator wants output — separately authenticates over SMB purely to shuttle the spawned process's console output back, using the target's **own loopback SMB connection to itself** as the relay mechanism. This is confirmed directly from `examples/wmiexec.py`'s `WMIEXEC.run()` and `RemoteShell` classes:

```
Attacker (wmiexec.py)                                Target (10.10.10.5)
─────────────────────                                ────────────────────
1. (optional) SMB Session Setup (TCP 445) ──────────▶  Authenticate via NTLM or Kerberos
   — only established if output capture is on           (used only later, to read output back —
   (skipped entirely with -nooutput / -silentcommand)     NOT used to execute anything)

2. DCOM/RPC connection (TCP 135 + dynamic port) ────▶  Authenticate via NTLM or Kerberos
   (DCOMConnection — independent auth event              (a SEPARATE logon from step 1's SMB auth,
    from step 1, always established)                       even though it's the same credentials)
     └─ CoCreateInstanceEx(CLSID_WbemLevel1Login)
          └─ IWbemLevel1Login.NTLMLogin('//./root/cimv2')
               └─ iWbemServices.GetObject('Win32_Process')

3. win32Process.Create(command, pwd, None) ─────────▶  svchost.exe (Winmgmt service)
   command defaults to:                                    └─▶ WmiPrvSE.exe (WMI Provider Host)
     'cmd.exe /Q /c <cmd> 1>                                     └─▶ cmd.exe /Q /c <cmd>
        \\127.0.0.1\ADMIN$\__<ts> 2>&1'                               └─▶ (operator's command, as
   -shell-type powershell instead sends:                                   the AUTHENTICATED USER —
     powershell.exe -NoP -NoL -sta -NonI                                   never SYSTEM)
        -W Hidden -Exec Bypass -Enc <base64>
   -silentcommand strips the 'cmd.exe /Q /c' wrapper
   entirely — the raw command becomes WmiPrvSE.exe's
   DIRECT child, no cmd.exe hop at all

4. Target's cmd.exe/powershell.exe writes its own      C:\Windows\__<unix-epoch-timestamp>
   output to its OWN admin share over LOOPBACK SMB       (transient, extensionless — created only
   (127.0.0.1) — only if output capture is on             if output capture is on)

5. getFile(share, output-filename) ──────────────────▶  Operator's SMB session (step 1) reads the
   deleteFile(share, output-filename)                      file back, then it is deleted

6. Steps 3-5 repeat for every command typed in the semi-interactive shell — the SAME output
   filename is reused for the entire session (it's a module-level constant computed once when
   wmiexec.py starts, not regenerated per command)
```

Step-by-step, verified against `examples/wmiexec.py`:

1. **Two independent authentications, not one.** Unless `-nooutput` or `-silentcommand` is used, `wmiexec.py` opens an `SMBConnection` (NTLM or Kerberos login) purely to later retrieve and delete the output file — this connection never executes anything. Separately, it always opens a `DCOMConnection` (also NTLM- or Kerberos-authenticated) that does the actual work. Both use the same supplied credentials, but they are two distinct protocol-level logons on the target — expect **two** Security 4624 events in the output-enabled case, not one.
2. **WMI login and object binding.** Over the DCOM connection, it calls `CoCreateInstanceEx` for `CLSID_WbemLevel1Login`, then `IWbemLevel1Login.NTLMLogin('//./root/cimv2', ...)` to get an `IWbemServices` handle scoped to the `root\cimv2` namespace, then `GetObject('Win32_Process')` to obtain a handle on the process-creation class.
3. **Command execution via `Win32_Process.Create()`.** The command is wrapped as `cmd.exe /Q /c <command>` by default (or the raw command with no wrapper at all if `-silentcommand` is set, or a base64-encoded PowerShell one-liner if `-shell-type powershell` is set), then passed to `win32Process.Create(command, currentDirectory, None)`. On the target, this is serviced by `WmiPrvSE.exe` (the WMI Provider Host, itself spawned by a shared `svchost.exe` hosting the `Winmgmt` service) — the created process **impersonates the authenticating user's security context**, not SYSTEM. This is the tool's own stated headline advantage over `psexec.py`/`smbexec.py`.
4. **Output relay over loopback SMB.** If output capture is enabled, the wrapped command redirects its stdout/stderr to `\\127.0.0.1\<share>\__<unix-epoch-timestamp>` (default share `ADMIN$`, i.e. `C:\Windows\__<timestamp>`) — the **target machine writes to its own admin share over SMB to itself**, not a direct pipe back to the operator. `OUTPUT_FILENAME` is computed once, `'__' + str(time.time())`, when the script starts — the same filename is reused for the life of the session, not regenerated per command.
5. **Read-back and cleanup.** The operator's original SMB connection calls `getFile()` against that same share/filename, retrying on `STATUS_SHARING_VIOLATION` (the target hasn't finished writing/closed the file handle yet) with a 1-second backoff, then `deleteFile()` once the read succeeds. There is no equivalent of psexec's service-uninstall step because there's no service to remove.
6. **`-silentcommand` is the tool's single most consequential OPSEC flag.** It does two things at once: it skips the SMB connection entirely (so no output file is ever written, and no `-share` access happens at all), **and** it strips the `cmd.exe /Q /c` wrapper, so `Win32_Process.Create()` launches the raw command as a **direct child of `WmiPrvSE.exe`** with no intermediate command interpreter. This is functionally analogous to psexec's `-file` flag as "the flag that breaks the obvious detection pattern" — except here it breaks the *process-tree* assumption (cmd.exe under WmiPrvSE.exe) rather than a file-hash assumption. See `05 - Detection and Hunting.md`.

**Always runs as the authenticating user, never SYSTEM** — the inverse of psexec's execution context, and the reason WMI-based lateral movement is frequently chosen when an operator specifically wants to avoid a SYSTEM-context artifact trail or wants command execution to blend in with that user's normal activity pattern.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport (execution) | DCOM/RPC — TCP 135 (RPC endpoint mapper) + a dynamically negotiated high port |
| Transport (output only) | SMB (TCP 445) — only established if output capture is enabled (`-nooutput`/`-silentcommand` skip it entirely) |
| Authentication | NTLM (password or pass-the-hash) or Kerberos (ticket, AES key, or keytab) — negotiated **independently** for the SMB connection and the DCOM connection |
| Remote execution | WMI `Win32_Process.Create()` method call, via `IWbemServices` bound to the `root\cimv2` namespace, reached through `IWbemLevel1Login.NTLMLogin()` |
| Output delivery | Target-side loopback SMB write (`\\127.0.0.1\<share>\__<timestamp>`) → operator-side `getFile()`/`deleteFile()` over the operator's own SMB session |
| Execution context | The authenticating user's token (impersonation), **not** SYSTEM |
| Process host | `WmiPrvSE.exe` (WMI Provider Host), spawned under a shared `svchost.exe` hosting the `Winmgmt` service |

## Command-Line Switches — Quick Reference

Full flag reference as of the current `examples/wmiexec.py` in the official [fortra/impacket](https://github.com/fortra/impacket) repository, written for a reader who has never run the tool.

**Positional**

| Argument | Meaning |
|---|---|
| `target` | `[[domain/]username[:password]@]<targetName or address>` — who to authenticate as and where |
| `command` | What to run remotely. **Default: empty** — omit it entirely to land in the semi-interactive shell instead of a one-shot execution |

**General**

| Switch | Plain-English meaning |
|---|---|
| `-share` | Which share to write/read the output-relay file through. **Default: `ADMIN$`** (maps to `C:\Windows\`). Changing this moves the transient `__<timestamp>` file to a different share/location |
| `-nooutput` | Don't capture or print command output at all — **no SMB connection is created for the entire session**, meaning no output file is ever written. Still wraps the command in `cmd.exe /Q /c` |
| `-silentcommand` | Execute the given command **without** wrapping it in `cmd.exe` — the raw command becomes `WmiPrvSE.exe`'s direct child. Implies no output capture (no SMB connection either). **Cannot be combined with an empty command** (no interactive shell support) |
| `-ts` | Prefix every logging output line with a timestamp (operator convenience, doesn't touch the target) |
| `-debug` | Verbose debug output — troubleshooting the tool itself, doesn't touch the target |
| `-codec` | Character encoding used to decode the target's console output (default: the local terminal's encoding, falling back to UTF-8). If output looks garbled, run `chcp.com` on the target, map the result against Python's [standard encodings list](https://docs.python.org/3/library/codecs.html#standard-encodings), and re-run with the matching `-codec` value |
| `-shell-type {cmd,powershell}` | Which command processor wraps the executed command. **Default: `cmd`**. `powershell` base64-encodes the command and launches it via `powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc <b64>` |
| `-com-version MAJOR:MINOR` | Force a specific DCOM protocol version (e.g. `5.7`) instead of letting OXID resolution auto-negotiate one — useful for compatibility with older/nonstandard DCOM configurations |

**Authentication**

| Switch | Plain-English meaning |
|---|---|
| `-hashes LMHASH:NTHASH` | Authenticate with an NTLM hash instead of a password — pass-the-hash |
| `-no-pass` | Don't prompt for a password — pairs with `-k` (Kerberos) |
| `-k` | Use Kerberos authentication instead of NTLM (reads a ticket from the `KRB5CCNAME`-pointed ccache, falling back to the command-line-supplied credentials if none is found) |
| `-aesKey` | Authenticate with a Kerberos AES key (128- or 256-bit) instead of a password or RC4/NT hash |
| `-dc-ip` | IP of a domain controller — needed for Kerberos auth if the domain part of `target` can't otherwise resolve one |
| `-target-ip` | Force a specific IP for the connection even if `target` is a NetBIOS name that won't resolve |
| `-A authfile` | Read credentials from a `smbclient`/`mount.cifs`-style authentication file, avoiding a plaintext password on the command line/shell history |
| `-keytab` | Read Kerberos keys from a keytab file — common for service-account authentication |

## Interactive Shell Commands

When run without a `command` argument, `wmiexec.py` drops into a semi-interactive shell (a Python `cmd.Cmd` subclass) that adds a handful of meta-commands on top of whatever the target's shell (`cmd.exe`/`powershell.exe`) understands natively — these are handled entirely client-side and never reach the target's command interpreter:

| Command | Meaning |
|---|---|
| `lcd {path}` | Change the **local** (operator-side) working directory |
| `lput {src_file} {dst_path}` | Upload a local file to the target over SMB — functionally the closest thing wmiexec has to psexec's `-c` secondary payload drop, except it's a session command, not a CLI flag |
| `lget {file}` | Download a file from the target's current remote directory to the operator's local working directory, over SMB |
| `! {cmd}` | Run a command locally on the operator's own machine (`os.system()`) |
| `exit` | End the session |

## Quick Use-Case List

- Semi-interactive shell via cleartext credentials
- Pass-the-hash execution (NTLM hash, no cleartext password)
- Pass-the-ticket / Kerberos execution, including AES-key and keytab variants
- Authentication via a `smbclient`-style auth file (`-A`) to keep credentials off the command line/shell history
- One-shot, non-interactive command execution (positional `command` argument)
- Fully blind, no-connection execution via `-silentcommand` — the strongest OPSEC variant, skips both the SMB output channel and the `cmd.exe` wrapper
- Output-suppressed (but still `cmd.exe`-wrapped) execution via `-nooutput`
- Switching to a PowerShell-based semi-interactive shell (`-shell-type powershell`)
- Moving the output-relay file off the default `ADMIN$` share (`-share`)
- Uploading/downloading files mid-session (`lput`/`lget`) rather than a CLI-level file drop
- Forcing a specific DCOM protocol version (`-com-version`) for compatibility or fingerprint-blending
- Fleet-wide / mass execution scripted across a target list
- Chained use immediately after credential harvesting (e.g. `secretsdump.py`/`GetUserSPNs.py` → `wmiexec.py`)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Credential material | One of: cleartext username+password, NTLM hash (`LMHASH:NTHASH`), a Kerberos ticket (`.ccache`), an AES key, or a keytab |
| Privilege on target | Authenticating account must be a **local administrator** on the target — WMI's `root\cimv2` namespace and `Win32_Process.Create()` require it by default |
| Network reachability (execution) | TCP 135 (RPC endpoint mapper) plus a dynamically negotiated high port for the DCOM/WMI connection — this is the tool's own stated drawback vs. psexec/smbexec's SMB-only requirement |
| Network reachability (output, optional) | TCP 445 (SMB) to the target, **only** if output capture is enabled (default) — entirely skippable with `-nooutput`/`-silentcommand` |
| Name resolution | Required for Kerberos auth (SPN resolution needs the hostname, not a bare IP) — use `-target-ip` to decouple hostname-for-Kerberos from routing |
| Domain context | A local account works against a standalone host; a domain account plus a reachable DC is needed for Kerberos auth |
