# Impacket — smbexec.py — Overview

> 🔴 **Red Flag Principle:** A **temporary service is created, started, and deleted on the target once for every single command typed** — not once per session like `psexec.py`, not zero times like `wmiexec.py`. Each cycle's `ImagePath` is the same recognizable template: `%COMSPEC% /Q /c echo <command> ^> \\<COMPUTERNAME>\<share>\__output_<8-random-letters> 2^>^&1 > %SYSTEMROOT%\<8-random-letters>.bat & %COMSPEC% /Q /c %SYSTEMROOT%\<8-random-letters>.bat & del %SYSTEMROOT%\<8-random-letters>.bat`. A **burst** of System 4697/7045 "service installed" events sharing one identical `ServiceName`, arriving seconds apart in a tight window, with `ImagePath` built from an `echo`/redirect/batch-file/`del` template — that's `smbexec.py`. If you see exactly *one* such event, you're more likely looking at `psexec.py`; if you see *none* at all but a `WmiPrvSE.exe` spawning children, that's `wmiexec.py` — see the three-way contrast in `04 - Target Evidence.md`.

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

`smbexec.py` lives in the same `examples/` folder of [`fortra/impacket`](https://github.com/fortra/impacket) as `psexec.py` and `wmiexec.py`, under the same modified Apache license, credited in its own source header to the **same original author — beto (Alberto Solino, @agsolino)**. There is no separate "original tool" credited (e.g. no reference to the unrelated open-source `csexec` project) — verified directly against the current source header, which reads:

```
# Description:
#   A similar approach to psexec w/o using RemComSvc. The technique is described here
#   https://web.archive.org/web/20190515131124/https://www.optiv.com/blog/owning-computers-without-shell-access
#   Our implementation goes one step further, instantiating a local smbserver to receive the
#   output of the commands. This is useful in the situation where the target machine does NOT
#   have a writeable share available.
#   Keep in mind that, although this technique might help avoiding AVs, there are a lot of
#   event logs generated and you can't expect executing tasks that will last long since Windows
#   will kill the process since it's not responding as a Windows service.
#   Certainly not a stealthy way.
#
#   This script works in two ways:
#       1) share mode: you specify a share, and everything is done through that share.
#       2) server mode: if for any reason there's no share available, this script will launch a
#          local SMB server, so the output of the commands executed are sent back by the target
#          machine into a locally shared folder.
```

That comment is the single most important piece of design context here, and it's worth reading literally rather than paraphrasing: the tool's own author states it is **"certainly not a stealthy way"** and warns that Windows will actively **kill the spawned process** if a command runs too long, because the process backing the "service" (`cmd.exe`) never calls `StartServiceCtrlDispatcher()` the way a real Windows service does — the Service Control Manager eventually decides it isn't responding and terminates it. This single design fact shapes almost everything else in this note: the technique trades a real dropped binary (psexec) or a DCOM call (wmiexec) for **repeated, disposable service-creation cycles**, one per command, each one individually noisy and individually bounded in how long it can run.

The referenced technique write-up (archived, original Optiv blog now offline) describes using `cmd.exe` itself as a service binary via the Service Control Manager, without needing any custom-compiled payload — `smbexec.py` is Impacket's implementation of that idea, extended with the option to stand up its own throwaway SMB server (`-mode SERVER`) for cases where the target has no share the operator can write to.

## How It Works

`smbexec.py` never drops an executable payload and never calls `psexec.py`'s RemCom binary at all — it repurposes the **Service Control Manager itself** as the execution primitive, using `cmd.exe` (via the `%COMSPEC%` environment variable) as the "service binary" for a single compound command line, then destroys the service immediately after. This is confirmed directly from `examples/smbexec.py`'s `RemoteShell.execute_remote()` method:

```
Attacker (smbexec.py)                                Target (10.10.10.5)
─────────────────────                                ────────────────────
1. SMB Session Setup (TCP 445, or 139) ─────────────▶  Authenticate via NTLM or Kerberos
   (established ONCE for the whole session)              (password, hash, ticket, or key)

2. DCE/RPC bind to \PIPE\svcctl (MS-SCMR) ──────────▶  OpenSCManagerW()   (also ONCE per session)

3. Shell starts — do_cd('') fires automatically to set the initial prompt,
   which is itself a full create/start/delete cycle (see step 4) before
   the operator has typed anything.

4. FOR EVERY COMMAND TYPED — a fresh cycle:
     CreateServiceW(<ServiceName>, <ServiceName>,        (ServiceName is the SAME random
       ImagePath = "%COMSPEC% /Q /c echo <cmd> ^>          8-character string — or the
         \\<COMPUTERNAME>\<share>\__output_<rand8>          operator's -service-name value —
         2^>^&1 > %SYSTEMROOT%\<rand8>.bat &                reused for EVERY cycle in the
         %COMSPEC% /Q /c %SYSTEMROOT%\<rand8>.bat &         session, not regenerated per command)
         [copy <output> \\<operatorIP>\TMP  — SERVER only]
         & del %SYSTEMROOT%\<rand8>.bat",
       dwStartType = SERVICE_DEMAND_START)          ──▶  SCM registers the service key
     StartServiceW()                                ──▶  services.exe launches the "service"
     DeleteService()   (marks for deletion,                 └─▶ cmd.exe /Q /c "echo ... & cmd.exe
       fired unconditionally, success or fail)                    /Q /c <batchfile> & del <batchfile>"
     CloseServiceHandle()                                          ├─ echo writes the operator's
                                                                     │    command text into a new
                                                                     │    .bat file (built-in, no
                                                                     │    child process)
                                                                     ├─▶ cmd.exe /Q /c <batchfile>
                                                                     │     (CHILD process — separate
                                                                     │      cmd.exe instance runs
                                                                     │      the batch file, which is
                                                                     │      the operator's actual
                                                                     │      command, redirected to
                                                                     │      the output file)
                                                                     └─ del <batchfile>  (built-in,
                                                                          cleans up the .bat itself)

5. getFile(share, output-filename) ──────────────────▶  Operator's SMB session (opened in step 1)
   deleteFile(share, output-filename)   [SHARE mode]      reads the output file back, then deletes
   (SERVER mode: reads the LOCAL copy the                 it — SERVER MODE DOES NOT DELETE THE
    target pushed via the `copy` clause instead;           ORIGINAL FILE ON THE TARGET. See
    the ORIGINAL file on the target is left behind)         04 - Target Evidence.md.

6. Steps 4-5 repeat for every command in the semi-interactive shell — same ServiceName,
   same output filename, reused for the life of the session.
```

Step-by-step, verified against `examples/smbexec.py`:

1. **One SMB session, one SCM binding, for the whole session.** The RPC binding to `\PIPE\svcctl` (`ncacn_np:<target>[\pipe\svcctl]` — connection-oriented RPC over an SMB named pipe, same transport family as `psexec.py`, **not** wmiexec's DCOM/TCP-135 path) and the `OpenSCManagerW()` call happen once, when the shell starts. Everything downstream reuses that single handle.
2. **The shell auto-primes itself.** `RemoteShell.__init__()` calls `do_cd('')` immediately after connecting — which itself triggers a full create/start/delete/read cycle to populate the prompt string — so a service-creation event fires the instant the operator connects, before any command is typed.
3. **Every typed command gets its own service.** `execute_remote()` builds a `batchFile` path (`%SYSTEMROOT%\<8-random-letters>.bat`) and a compound `command` string: `%COMSPEC% /Q /c echo <data> ^> <output> 2^>^&1 > <batchFile> & %COMSPEC% /Q /c <batchFile> & del <batchFile>` (with an inserted `copy` clause in `-mode SERVER`). That string is passed directly as `lpBinaryPathName` to `hRCreateServiceW()`, then `hRStartServiceW()` launches it, then `hRDeleteService()` marks the service for deletion **unconditionally** — even if `StartServiceW` raised an exception — and `hRCloseServiceHandle()` releases the handle. No account is specified on `CreateServiceW`, so the service defaults to running as **LocalSystem**, same as `psexec.py`.
4. **The command line is a nested `cmd.exe` invocation, not a flat one.** Because `%COMSPEC% /Q /c <batchFile>` appears as a clause *inside* the outer `%COMSPEC% /Q /c "..."` command, Windows spawns a genuine **child** `cmd.exe` process to run the batch file — `echo` and `del` are shell built-ins executed by the outer `cmd.exe` itself, but the batch-file invocation is not. The result is a three-hop process chain before the operator's actual command even runs: `services.exe → cmd.exe (outer, builds & cleans up the batch file) → cmd.exe (inner, executes the batch file, i.e. the operator's command)`.
5. **PowerShell mode changes what's echoed, not the wrapper.** `-shell-type powershell` prefixes the command with `$ProgressPreference="SilentlyContinue";`, base64-encodes it (UTF-16LE), and substitutes `powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc <b64>` in place of the raw command text — but that whole string is still `echo`'d into the same `.bat`-file-and-redirect wrapper. Unlike `wmiexec.py`, there is **no way to skip the batch-file wrapper** in `smbexec.py` — no `-silentcommand`/`-nooutput` equivalent exists.
6. **Output relay, and an asymmetric cleanup bug between modes.** In the default `-mode SHARE`, the operator's SMB session reads the output file back with `getFile()` and then explicitly deletes it with `deleteFile()` — the target is left clean. In `-mode SERVER`, the batch command's `copy` clause pushes the file to the operator's own ad hoc SMB listener, and `smbexec.py` only reads/deletes the **local copy** it just received — **it never issues a `deleteFile()` call against the original file on the target at all.** Since `OUTPUT_FILENAME` is a session-constant (`'__output_' + 8 random letters`, generated once at import time), every subsequent command in a `-mode SERVER` session simply overwrites that same file again — meaning a `-mode SERVER` session leaves **one persistent, repeatedly-overwritten file** sitting on the target's chosen share indefinitely after the operator disconnects. This is a genuine, source-verified forensic asymmetry between the two modes — see `04 - Target Evidence.md`.
7. **No positional `command` argument exists.** Unlike `psexec.py` and `wmiexec.py`, `smbexec.py`'s argument parser defines only `target` — there is no way to pass a one-shot command on the CLI. The tool **always** drops into the semi-interactive `cmd.Cmd`-based shell. Operators script non-interactive/one-shot use by piping a line into the process's stdin (standard Python `cmd.Cmd` behavior when stdin isn't a TTY) — see `02 - Hands-On Use Cases.md`.
8. **`cd` is explicitly disabled.** `do_cd()` refuses to track a working directory (`"You can't CD under SMBEXEC. Use full paths."`) — every command must use fully-qualified paths, a real, source-confirmed operational quirk of this tool specifically.
9. **Cleanup on exit is best-effort, layered on top of the per-command cleanup.** `finish()` attempts one more `deleteFile()` for the output filename and one more open/stop/delete pass against the shared service name, swallowing any exception — a safety net for whatever the last in-flight cycle might have left behind.

**Always runs as SYSTEM** — same execution context as `psexec.py`, because `CreateServiceW` doesn't specify a service account and defaults to LocalSystem. This is the opposite of `wmiexec.py`, which always runs as the authenticating user.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport | SMB (TCP 445), legacy NetBIOS session service (TCP 139 via `-port`) — a **single** SMB session serves both the SVCCTL RPC binding and the share file I/O for the entire operator session, no dynamic RPC port ever negotiated |
| Authentication | NTLM (password or pass-the-hash) or Kerberos (ticket, AES key, or keytab) |
| Remote execution | MS-SCMR (Service Control Manager Remote Protocol) over `\PIPE\svcctl` — `CreateServiceW`/`StartServiceW`/`DeleteService`/`CloseServiceHandle`, repeated once **per command**, not once per session |
| Command delivery | No file upload at all — the operator's command text is embedded directly in the service's `ImagePath` string, `echo`'d into a batch file by the target's own `cmd.exe`, then executed |
| Output delivery | Target-side write to `\\<COMPUTERNAME>\<share>\__output_<8-random-letters>` (via the service's own `echo`/redirect), read back over the operator's existing SMB session (`SHARE` mode) or copied out to an operator-hosted ad hoc SMB server (`SERVER` mode) |
| Execution context | SYSTEM (service context, not the authenticating user's token) |
| Process host | `services.exe → cmd.exe (outer) → cmd.exe (inner, runs the batch file)` — three hops before the operator's actual command |

## Command-Line Switches — Quick Reference

Full flag reference as of the current `examples/smbexec.py` in the official [fortra/impacket](https://github.com/fortra/impacket) repository, written for a reader who has never run the tool.

**Positional**

| Argument | Meaning |
|---|---|
| `target` | `[[domain/]username[:password]@]<targetName or address>` — who to authenticate as and where. **There is no `command` positional** — `smbexec.py` always lands in the semi-interactive shell |

**General**

| Switch | Plain-English meaning |
|---|---|
| `-share` | Which share to write/read the output-relay file through. **Default: `C$`** (not `ADMIN$` — a real difference from `psexec.py`/`wmiexec.py`) |
| `-mode {SHARE,SERVER}` | **Default: `SHARE`.** `SHARE` uses `-share` on the target for output retrieval. `SERVER` spins up Impacket's own throwaway SMB server locally to catch the output instead — for when the target has no share the operator can write to. **`SERVER` mode requires root/admin on the operator's own machine** to bind TCP 445 |
| `-ts` | Prefix every logging output line with a timestamp (operator convenience, doesn't touch the target) |
| `-debug` | Verbose debug output — troubleshooting the tool itself, doesn't touch the target |
| `-codec` | Character encoding used to decode the target's console output. Default: the local terminal's encoding, falling back to UTF-8 |
| `-shell-type {cmd,powershell}` | Which command processor the echoed text is built for. **Default: `cmd`**. `powershell` base64-encodes the command and launches it via `powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc <b64>` — but this string is still delivered through the same batch-file/`echo` wrapper, unlike wmiexec's PowerShell mode |

**Connection**

| Switch | Plain-English meaning |
|---|---|
| `-dc-ip` | IP of a domain controller — needed for Kerberos auth if DNS won't resolve one |
| `-target-ip` | Force a specific IP for the connection even if `target` is a hostname |
| `-port {139,445}` | SMB port to use. **Default: 445** |
| `-service-name` | Override the default random 8-character service name — the **same** name is reused for every command-cycle in the session either way |

**Authentication**

| Switch | Plain-English meaning |
|---|---|
| `-hashes LMHASH:NTHASH` | Authenticate with an NTLM hash instead of a password — pass-the-hash |
| `-no-pass` | Don't prompt for a password — pairs with `-k` (Kerberos) |
| `-k` | Use Kerberos authentication instead of NTLM (reads a ticket from the `KRB5CCNAME`-pointed ccache, falling back to the command-line-supplied credentials if none is found) |
| `-aesKey` | Authenticate with a Kerberos AES key (128- or 256-bit) instead of a password or RC4/NT hash |
| `-keytab` | Read Kerberos keys from a keytab file — common for service-account authentication |

**Not present in `smbexec.py`** (worth naming explicitly, since both siblings in this folder have them): no `-file`/`-c`/`-remote-binary-name` (nothing is ever dropped as a binary), no `-A` authentication-file option, no `-nooutput`/`-silentcommand` equivalent, no `lput`/`lget` file-transfer shell commands, no `-com-version`.

## Interactive Shell Commands

`smbexec.py` always drops into a semi-interactive shell (a Python `cmd.Cmd` subclass). A handful of meta-commands are handled entirely client-side and never reach the target's `\PIPE\svcctl` execution path:

| Command | Meaning |
|---|---|
| `shell {cmd}` | Run a command **locally** on the operator's own machine (`os.system()`) — does not touch the target at all |
| `cd` / `CD` | **Disabled for real navigation.** Always sends a bare `cd` to the target to refresh the prompt string, but logs an error (`"You can't CD under SMBEXEC. Use full paths."`) if the operator supplied an argument — the target-side working directory can never actually be changed through this tool |
| `exit` / `EOF` (Ctrl+D) | End the session, triggering `finish()`'s best-effort cleanup pass |

Anything else typed goes straight to `default()`, which sends it to the target via `execute_remote()` — i.e. every ordinary command is a remote execution.

## Quick Use-Case List

- Semi-interactive SYSTEM shell via cleartext credentials (default `SHARE` mode, `C$`)
- Pass-the-hash execution (NTLM hash, no cleartext password)
- Pass-the-ticket / Kerberos execution, including AES-key and keytab variants
- Switching to a PowerShell-wrapped shell (`-shell-type powershell`)
- `SERVER` mode when no writable share exists on the target
- Blending in with a custom service name (`-service-name`)
- Moving the output-relay share off the default `C$` (`-share`)
- Alternate-port targeting (`-port 139`) to route around a filtered 445
- Local command execution mid-session (`shell`) — operator-side convenience, doesn't touch the target
- Piping a single command via stdin for scripted, non-interactive one-shot use (no CLI `command` argument exists)
- Fleet-wide / mass execution scripted across a target list
- Staging and launching a secondary C2 payload via a one-liner downloader command
- Chained use immediately after credential harvesting (e.g. `secretsdump.py` → `smbexec.py`)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Credential material | One of: cleartext username+password, NTLM hash (`LMHASH:NTHASH`), a Kerberos ticket (`.ccache`), an AES key, or a keytab |
| Privilege on target | Authenticating account must be a **local administrator** — needed for `SC_MANAGER_CREATE_SERVICE` rights and (in `SHARE` mode) write access to `-share` |
| Network reachability | TCP 445 (SMB) to the target by default; TCP 139 as a fallback via `-port` — a single connection carries both the SVCCTL RPC traffic and the share file I/O |
| `SERVER` mode reachability | Additionally requires the **target** to reach back out to the **operator's** IP on TCP 445, and the **operator** to have root/admin rights to bind that port locally |
| Command duration budget | Any single command is bounded by Windows' service-start timeout — a long-running command gets killed by the SCM because `cmd.exe` never calls `StartServiceCtrlDispatcher()`; this is stated directly in the tool's own source comment |
| Name resolution | Required for Kerberos auth (SPN resolution needs the hostname, not a bare IP) — use `-target-ip` to decouple hostname-for-Kerberos from routing |
| Domain context | A local account works against a standalone host; a domain account plus a reachable DC is needed for Kerberos auth |
