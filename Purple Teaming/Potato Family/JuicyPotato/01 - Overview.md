# JuicyPotato — Overview

> 🔴 **Red Flag Principle:** JuicyPotato is a **legacy token-impersonation exploit** (2018) that abuses COM object instantiation to trick a SYSTEM-running service into impersonating and spawning a child process. Unlike PrintSpoofer's simple RPC coercion, JuicyPotato requires **identifying a usable CLSID per Windows version**—a hidden COM object that (a) runs as SYSTEM, (b) implements the IMarshal interface, and (c) can be instantiated by the attacker's account. The key indicator is **unexpected COM instantiation by a low-privilege account**, followed by a SYSTEM-context child process. However, this tool is **pre-2019 and effectively abandoned**; modern systems with Windows Server 2019+ and fully patched Windows 10+ may lack suitable CLSIDs, making JuicyPotato unreliable. RoguePotato (2019) and PrintSpoofer (2021) supersede it on modern systems.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

JuicyPotato is a standalone C# exploit tool, originally developed by `@ohpe` (the GitHub alias) and maintained under the **[ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)** repository.

Verified against the canonical upstream repository:

- **License:** GPL 3.0.
- **Author:** `@ohpe` (credited in the README, no real name publicly associated).
- **Purpose:** "Windows Local Privilege Escalation (enable all privileges)." Specifically abuses COM object instantiation to trick SYSTEM-running services into token impersonation.
- **Version:** v0.1 (final). The repository shows last activity in 2020, and is **not archived but inactive**.
- **Active maintenance:** No — last commit was in 2020; effectively abandoned.

**Lineage:** JuicyPotato is a direct successor to **RottenPotato** (2016, by Stephen Breen / @breenmachine), an earlier COM-based token impersonation exploit. JuicyPotato added support for multiple Windows versions (via CLSID enumeration per OS) and multiple token impersonation methods (`CreateProcessWithTokenW`, `CreateProcessAsUser`), making it more flexible but also more complex.

**Supersession:** RoguePotato (2019) and PrintSpoofer (2021) are newer alternatives that are more reliable on Windows Server 2019+ and Windows 10 2019H1+. JuicyPotato is mainly of historical interest or as a fallback on older systems (Windows 7, Server 2008 R2, Server 2012 R2).

## How It Works

### Exploit flow: COM instantiation → SYSTEM token capture → CreateProcessAsUser/CreateProcessWithToken

```
Attacker (low-privilege account with SeImpersonate)
──────────────────────────────────────────────────

1. JuicyPotato selects a CLSID from a hardcoded list
   (CLSID selection depends on Windows version and available
    service accounts; CLSID must satisfy three criteria:
    ├─ Instantiable by the attacker's account (not admin-only)
    ├─ Runs as SYSTEM (LS_SYSTEM_REQUIRED flag)
    └─ Implements IMarshal interface)

2. JuicyPotato sets up a COM server on -l <port>
   (default 127.0.0.1:<port>, e.g., 127.0.0.1:10000)
   and registers a marshalled object

3. A SYSTEM-running service (e.g., spoolsv.exe, wlms.exe,
   TokenBroker, or another COM service) attempts to instantiate
   the attacker-specified CLSID via CoCreateInstanceEx()

4. The COM service, running as SYSTEM, receives the
   attacker-controlled marshalled object and unmarshals it.
   During unmarshalling, it exposes its SYSTEM token context.

5. JuicyPotato captures this token via:
   ├─ ImpersonateAnonymousToken() (if available)
   ├─ CoGetCallContext() (COM call context)
   └─ Other token-stealing techniques specific to the CLSID

6. With the SYSTEM token impersonated, JuicyPotato calls:
   ├─ CreateProcessWithTokenW(system_token, ...) — if -t t
   └─ CreateProcessAsUser(system_token, ...) — if -t u
   (or auto-tries both if -t *)

7. The spawned process runs as SYSTEM, and the attacker
   has a SYSTEM-context shell or command execution.
```

**Key difference from PrintSpoofer:**
- PrintSpoofer: Fixed RPC target (Print Spooler), simple and reliable.
- JuicyPotato: Variable COM CLSID, requires OS/version-specific tuning, more flexible but less reliable.

### CLSID enumeration and version dependency

**CLSID hunt:** JuicyPotato ships with a hardcoded list of CLSIDs (verified against `clsid.txt` or source constant) that work on specific Windows versions. A sample:

| CLSID (truncated) | Service | OS Versions | LS_SYSTEM_REQUIRED |
|---|---|---|---|
| `{0FB0F995-...}` | OneSyncSvc (Windows 10) | Windows 10 1803+ | Yes |
| `{5E9DDC73-...}` | BITS (Windows 7+) | Windows 7, Server 2008+ | Yes |
| `{14B59933-...}` | NtmsSvc | Windows Server 2003+ | Yes |
| Others | Various services | Various | Yes |

**Critical detail:** Not all CLSIDs work on all Windows versions. JuicyPotato's CLSID list is **not exhaustive and not always up-to-date** for newer Windows builds. Operators often have to trial-and-error which CLSID works on their target, or use a scanning tool to enumerate available CLSIDs.

### Token impersonation methods

JuicyPotato supports two approaches (via `-t` flag):

| Method | Flag | Requirement | Fallback |
|---|---|---|---|
| **CreateProcessWithTokenW** | `-t t` | `SeImpersonate` privilege | Not available on all accounts. |
| **CreateProcessAsUser** | `-t u` | `SeAssignPrimaryToken` privilege (rarer). | Typically not available. |
| **Auto-try** | `-t *` | Tries both above, in order. | Safe for operators; will pick the first working method. |

**Default:** If not specified, JuicyPotato defaults to `-t *` (auto-try).

## Techniques / Protocols Used

| Technique / Protocol | Details |
|---|---|
| **COM / OLE (Component Object Model)** | JuicyPotato abuses the COM marshalling mechanism, specifically IMarshal, to trick a SYSTEM service into exposing its token. |
| **RPC (over DCOM)** | COM instantiation occurs over RPC/DCOM (Dynamic COM) to local endpoints or named pipes. |
| **Token Impersonation (SeImpersonate / SeAssignPrimaryToken)** | Captures and impersonates SYSTEM-context tokens via Win32 API. |
| **Process Creation (CreateProcessWithTokenW / CreateProcessAsUser)** | Spawns child process under the impersonated token. |
| **Named Pipes / Local Marshalling** | The attacker's COM server listens on a local port/pipe for SYSTEM to attempt instantiation. |

## Command-Line Switches — Quick Reference

| Flag | Argument | Purpose | Blue-Team Context |
|---|---|---|---|
| `-l` | `<port>` | **Mandatory.** Listening port for the attacker's COM server (e.g., `-l 10000`). Must be on the local machine (127.0.0.1). | The attacker sets up a fake COM service to trick SYSTEM into connecting. |
| `-p` | `<program>` | **Mandatory.** The program/command to execute as SYSTEM (e.g., `-p "cmd.exe"` or `-p "C:\Windows\Temp\payload.exe"`). | The attacker's goal — execute arbitrary code. |
| `-t` | `t\|u\|*` | **Token impersonation method.** `t` = CreateProcessWithTokenW (SeImpersonate), `u` = CreateProcessAsUser (SeAssignPrimaryToken), `*` = try both. Default is `*`. | Determines which privilege the attacker exploits; `*` is safest. |
| `-m` | `<address>` | COM server listen address (default `127.0.0.1`). Rarely changed. | The attacker's COM server IP; usually local. |
| `-a` | `<arguments>` | Arguments to pass to the spawned program (e.g., `-a "whoami"`). | Specifies the exact command the spawned process runs. |
| `-k` | `<ip>` | RPC server IP for the SYSTEM service to connect to (default `127.0.0.1`). Rarely used. | For RPC relay; typically not needed in basic exploitation. |
| `-n` | `<port>` | RPC server port (default 135, the Endpoint Mapper). Rarely changed. | Standard RPC port; usually not modified. |
| `-c` | `<clsid>` | Specific CLSID to instantiate (e.g., `-c {GUID}`). If omitted, JuicyPotato tries a default (usually BITS). | Specifies which COM object to target. Operator may need to trial-and-error. |
| `-z` | (no argument) | **Test mode.** Validates that the specified CLSID is usable on the current system, then exits. Does not execute the payload. | Useful for checking system compatibility before launching the full exploit. |

**Example command:**
```
JuicyPotato.exe -l 10000 -p "cmd.exe" -t * -a "whoami > C:\output.txt"
```

Listens on port 10000, tries both token methods, and executes `cmd whoami > output.txt` as SYSTEM.

## Quick Use-Case List

1. **Basic SYSTEM command execution** — One-liner escalation from SeImpersonate to SYSTEM shell.
2. **Reverse shell with default CLSID** — Automated escalation, no CLSID tuning needed (if a default CLSID works).
3. **CLSID enumeration and trial** — Operator identifies a working CLSID via `-z`, then exploits with `-c <clsid>`.
4. **Credential dumping as SYSTEM** — Execute `mimikatz` or `secretsdump` as SYSTEM (same pattern as PrintSpoofer).
5. **Windows 7 / Server 2008 R2 targeting** — JuicyPotato is more reliable on older OS versions (pre-2019) where newer tools may not work.
6. **Multi-method token impersonation** — Use `-t *` to auto-try both CreateProcessWithTokenW and CreateProcessAsUser, bypassing the need to know which privilege is available.
7. **Service account escalation from IIS** — Typical scenario: attacker has RCE as IIS app pool (has SeImpersonate), uses JuicyPotato to jump to SYSTEM.
8. **Database service escalation** — MSSQL or MySQL running as service account with SeImpersonate; exploit to SYSTEM.
9. **Chained exploitation via netcat/nc** — Upload `nc.exe`, use JuicyPotato to spawn `nc.exe -e cmd`, get SYSTEM reverse shell.
10. **Fileless payload delivery** — Use PowerShell `-c "IEX(...)"` as the program, download and execute a C2 payload in-memory as SYSTEM.
11. **Scheduled task creation** — Escalate to SYSTEM, create a persistence task (similar to PrintSpoofer use case).
12. **Registry modification for persistence** — With SYSTEM access, modify `HKLM` registry keys (e.g., Run keys, COM object registration) to install backdoors.

## Prerequisites

| Prerequisite | How to Verify | Impact if Missing |
|---|---|---|
| **SeImpersonate or SeAssignPrimaryToken** | Run `whoami /priv` and look for either privilege. | **Critical.** JuicyPotato cannot work without one. If using `-t t`, SeImpersonate is required; if `-t u`, SeAssignPrimaryToken; `-t *` requires at least one. |
| **Valid CLSID for target OS version** | Requires trial-and-error or enumeration. Default CLSIDs may or may not work. | **Critical.** Without a usable CLSID, the exploit fails silently or with an error. Operator must identify a working CLSID. |
| **Available port for COM server** | Ensure the port specified with `-l` is not in use. | **Medium.** If the port is in use, the COM server fails to bind, and the exploit fails. Try a different port. |
| **Network connectivity to localhost** | RPC communication is local; should always be available. | **Low.** Localhost is always reachable unless network stack is broken. |
| **Not required: Admin/SYSTEM before exploit** | JuicyPotato is specifically designed for low-privilege escalation. | N/A — the whole point is to escalate *from* low privilege. |

---

## Summary

JuicyPotato is a **flexible but complex token-impersonation exploit** designed for older Windows versions (Windows 7 through Server 2016, and early Windows 10). Its reliance on CLSID enumeration makes it less reliable on modern, patched systems compared to PrintSpoofer (2021) or RoguePotato (2019). However, on legacy systems, it may be the only available option. Its dual token-method support (`-t t` vs. `-t u`) gives it an edge in environments where the attacker is unsure which privilege is available. It is **archived/abandoned** and represents the state of token-impersonation exploits circa 2018.

For modern penetration testing, **PrintSpoofer is preferred** on Windows 10/Server 2019+. JuicyPotato is mainly used as a fallback on older systems or in labs.
