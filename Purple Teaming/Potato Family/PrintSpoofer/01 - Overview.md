# PrintSpoofer — Overview

> 🔴 **Red Flag Principle:** PrintSpoofer is a **one-shot, zero-persistence privilege escalation tool** that abuses the Print Spooler RPC service to convert a `SeImpersonate` token into a SYSTEM-context command execution. Unlike persistence techniques, there is **no installed malware, no registry changes, no new service**—just an executable that runs once, spawns a single SYSTEM process, and exits. The distinctive signal is **behavioral: a non-SYSTEM user context spawning a SYSTEM-context child process via an `SeImpersonate` token impersonation mechanism**, detected as an unexpected process elevation in event logs (4672 token privilege escalation, 4688 process creation with SYSTEM parent/child pair, or Sysmon process-create events showing the token transition).

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

PrintSpoofer is a standalone C/C++ exploit tool maintained by **[itm4n](https://github.com/itm4n)** (Clément Labro) on GitHub.

Verified against the canonical upstream repository, [`github.com/itm4n/PrintSpoofer`](https://github.com/itm4n/PrintSpoofer):

- **License:** MIT.
- **Author:** itm4n (`@itm4n_`).
- **Purpose:** "Abuses the Print Spooler service to impersonate SYSTEM and execute commands" — targets the Windows Print Spooler RPC interface, leveraging `SeImpersonate` privilege to obtain a SYSTEM-context token.
- **Version:** v0.1 (final, released 2021). The repository was **archived on September 21, 2024**, and is now read-only.
- **Active maintenance:** No — archived as of 2024, but the exploit mechanics remain valid on unpatched systems.
- **No prebuilt binaries distributed** — source code only; operators compile locally or via C2.

The exploit itself targets **CVE-2021-1732** (the "Printer Bug"), a Print Spooler RPC vulnerability that allows an unprivileged user to coerce the SYSTEM-running spoolsv.exe service into authenticating to an attacker-controlled RPC endpoint. PrintSpoofer intercepts this authentication attempt, performs an RPC relay to a separate COM interface, and impersonates the SYSTEM token.

## How It Works

### Exploit flow: Printer Bug RPC coercion → SeImpersonate impersonation → SYSTEM execution

```
Attacker machine (PrintSpoofer.exe running with SeImpersonate)
────────────────────────────────────────────────────────────

1. PrintSpoofer creates a malicious RPC server on the local machine
   (listening on a named pipe or local endpoint)
   
2. PrintSpoofer coerces the Print Spooler service (spoolsv.exe,
   running as SYSTEM) into connecting to this RPC endpoint
   via a crafted RPC call to the Print Spooler interface
   (MS-RPRN protocol, operation 0x65 / RpcAsyncGetPrinterData)
   
3. When spoolsv.exe connects to the attacker's RPC server, it
   authenticates as SYSTEM
   
4. PrintSpoofer captures this SYSTEM-context authentication and
   performs a token impersonation via:
   ├─ ImpersonateAnonymousToken() or
   ├─ DuplicateTokenEx() + SetThreadToken(), or
   └─ The spooler's own leaked token context
   
5. With the SYSTEM token impersonated on the attacker's thread,
   PrintSpoofer calls:
   └─ CreateProcessAsUser(system_token, "cmd.exe /c " + attacker_command)
   
6. The spawned process runs as SYSTEM, in the same session/desktop
   as the Print Spooler call
   
7. PrintSpoofer (parent process) exits; the spawned SYSTEM process
   continues independently (if backgrounded/redirected)
```

**Key mechanic:** The exploit does not create a new service, drop a DLL, write to disk (beyond the spawned process's own artifacts), or modify the registry. The Print Spooler service itself is not compromised or crashed—it simply receives a coerced RPC call and authenticates, unaware its token has been impersonated.

### Privilege requirement

- **Mandatory:** `SeImpersonate` privilege (or `SeAssignPrimaryToken` on older Windows versions).
- **Typical contexts:** IIS application pools, MSSQL service accounts, Windows service accounts, or any account run by WinRM/WinRS.
- **Not required:** Admin/SYSTEM-level account (the whole point of the exploit).
- **Print Spooler state:** Must be running (`spoolsv.exe`). Print Spooler is enabled by default on Windows 10, Server 2016, and Server 2019; can be disabled via Group Policy or `Set-Service -Name spooler -StartupType Disabled` but is commonly left on.

### Desktop/session sensitivity

PrintSpoofer respects the caller's current desktop session. With `-d <SessionID>`, the spawned process can be directed to a different session (e.g., Session 3 on an RDP connection), but the Print Spooler RPC call originates from the local machine—remote exploitation via PrintSpoofer alone is not possible (the Print Spooler service doesn't expose RPC over the network by design; only local RPC endpoints are reachable).

## Techniques / Protocols Used

| Technique / Protocol | Details |
|---|---|
| **MS-RPRN (Print Spooler RPC)** | PrintSpoofer abuses the Print Spooler RPC interface (MS-RPRN), specifically operations 0x65 and related, to coerce the spoolsv.exe service. |
| **RPC Coercion** | Forcing a SYSTEM-running service to authenticate to an attacker-controlled endpoint, a broader technique shared with other Potato-family tools. |
| **Token Impersonation (SeImpersonate)** | Converting a captured SYSTEM-context token into the calling thread's impersonation context, then spawning a process under that context. |
| **Process Creation (CreateProcessAsUser)** | Spawning a child process with the impersonated SYSTEM token, bypassing normal privilege checks. |
| **Named Pipes / Local RPC Endpoints** | PrintSpoofer uses local IPC mechanisms (named pipes or DCE/RPC endpoints) to receive the coerced connection from the Print Spooler. |

## Command-Line Switches — Quick Reference

| Flag | Argument | Purpose | Blue-Team Context |
|---|---|---|---|
| `-c` | `<command>` | **Mandatory.** The command to execute as SYSTEM. Wrap in quotes if it contains spaces. Example: `-c "cmd /c whoami > c:\temp\output.txt"`. | The attacker's goal—execute arbitrary code in SYSTEM context. |
| `-i` | (no argument) | **Interactive.** Runs the spawned process in the **current console**, showing output in real-time. Without `-i`, the process runs backgrounded and output is lost unless redirected. | If enabled, the attacker sees command output live; otherwise, output must be written to a file or named pipe for retrieval. |
| `-d` | `<SessionID>` | **Desktop/Session targeting.** Spawns the process in session `<SessionID>` (e.g., `-d 1` for RDP session 1). Default is the caller's current session (usually session 0 for services or Session 1 for interactive login). | Allows an attacker to direct code execution to a specific RDP session; useful for targeting an administrator's active RDP session from a service account. |
| `-h` | (no argument) | **Help.** Displays usage information and exits. | Informational only. |

## Quick Use-Case List

1. **Basic SYSTEM reverse shell** — Obtain a SYSTEM-context reverse shell from a service account (e.g., IIS, MSSQL).
2. **Reverse shell with custom staging** — Chain PrintSpoofer with a multi-stage payload (Stage 1: basic reverse shell, Stage 2: full C2 implant as SYSTEM).
3. **Credential dumping as SYSTEM** — Execute `secretsdump.py` or `mimikatz.exe` as SYSTEM to dump domain/local credentials at the highest privilege level.
4. **Fileless execution via Named Pipe redirection** — Combine PrintSpoofer with named-pipe output redirection to achieve fileless command execution (write output to a named pipe, read it from the attacker process).
5. **UAC bypass chain (pre-UAC-enabled context)** — If running in a context where UAC restrictions apply, use PrintSpoofer to jump to true SYSTEM, then disable UAC or modify admin policies.
6. **Scheduled task or service creation** — With SYSTEM execution, create a scheduled task or persistent service as SYSTEM (though persistence is typically separate from PrintSpoofer itself).
7. **NTDS.dit dump** — Copy `C:\Windows\System32\ntds.dit` and registry hives (`sam`, `system`, `security`) to a staged location as SYSTEM (requires SYSTEM to read).
8. **COM/IIS metabase manipulation** — Modify IIS configuration (web.config, MetaBase.xml) to inject malicious code or alter bindings.
9. **Lateral movement pivoting** — From an initial low-privilege foothold, use PrintSpoofer to escalate to SYSTEM, then use the SYSTEM context to access internal network resources (e.g., UNC paths, WMI, registry on other machines).
10. **Disable security software as SYSTEM** — Disable Windows Defender, disable the Windows Update service, or tamper with endpoint security agent processes (all require SYSTEM).
11. **WebShell SYSTEM read/write** — If running within an IIS application pool (typical privilege level for web shells), use PrintSpoofer to read/write files as SYSTEM (e.g., read sensitive application config files, write new ASP.NET web shells to `wwwroot`).
12. **Persistence mechanism bootstrapping** — Use SYSTEM execution to install a persistence mechanism (e.g., a scheduled task, a service binary in `System32`, or a registry-run key) that survives reboot and maintains attacker access.

## Prerequisites

| Prerequisite | How to Verify | Impact if Missing |
|---|---|---|
| **SeImpersonate privilege** | Run `whoami /priv` and look for `SeImpersonatePrivilege` in the list. | **Critical.** PrintSpoofer will not work without this. Typical in IIS app pools, MSSQL, Windows services. |
| **Print Spooler running** | `net start spooler` or `Get-Service spooler \| Select Status`. | **Critical.** If the Print Spooler service is stopped or disabled, the RPC coercion will fail. Default is Automatic start, so this is usually present. |
| **Local code execution** | Already have shell/command execution on the target as a service account. | **Critical.** PrintSpoofer requires local execution; it is not a remote exploit. |
| **Write access to output location** (if redirecting output) | Ensure the path passed to `-c "... > C:\output.txt"` is writable by the service account. | **Medium.** Without write access, command output is lost (unless using `-i` for interactive display, but interactive output is also lost if the process is backgrounded). |
| **.NET Framework** (if compiling) | Typically present on Windows servers. C# source compiles with Visual Studio or csc.exe. | **Low.** Most operators use precompiled binaries or obtain via C2 framework. |
| **Not required: Admin/SYSTEM before exploit** | PrintSpoofer is specifically designed for low-privilege escalation. | N/A — the whole point is to escalate *from* low privilege. |

---

## Summary

PrintSpoofer is the **simplest and most direct** of the Potato-family tools: single-flag RPC coercion, minimal prerequisites (just SeImpersonate + running Print Spooler), and a one-command execution model. It's favored in offensive operations for speed and reliability on default-configured Windows systems. Because it leaves no persistence or on-disk footprint (only temporary artifacts during execution), post-exploitation forensics must rely on behavioral signals (unexpected SYSTEM process spawns, event logs) rather than filesystem evidence.
