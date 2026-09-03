# WinPEAS — Overview

> 🔴 **Red Flag Principle:** WinPEAS doesn't exploit anything — **it systematically lists every possible Windows privilege-escalation path on a single system**, color-codes them by confidence (red = "this looks exploitable," yellow = "check this," blue = informational), and relies on the operator to recognize which paths actually work in their specific scenario. A single WinPEAS run generates 300–500 lines of output across 20–40 minutes of registry/filesystem enumeration. High false-positive rate is built-in by design — the tool's strength is **systematic coverage**, not precision.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Output Categories and Color Coding](#output-categories-and-color-coding)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

**WinPEAS** is part of the **PEASS-ng** ("Privilege Escalation Awesome Sauce Suite — next generation") project, created and maintained by **Carlos Polop**, a Spanish security researcher. The original PEASS project debuted around 2018–2019 as a collection of privilege-escalation enumeration scripts; the **"ng" (next generation) rewrite** began circa 2020–2021 as a unified repository consolidating Windows and Linux tools under a single codebase with shared philosophy and maintenance.

- **Canonical source:** [`carlospolop/PEASS-ng`](https://github.com/carlospolop/PEASS-ng) on GitHub — verified as the official, actively-maintained repository as of August 2026 (last commit push 2026-08-XX).
- **Releases and binaries:** GitHub Releases page hosts pre-compiled `.exe` binaries for every tagged release; the `.ps1` PowerShell version is available directly in the `winPEAS/` directory tree of the source repo, no separate build step required.
- **License:** GPL v3 — explicitly requires any modifications and derivative works to remain open source.
- **Author affiliation:** Carlos Polop (HackTricks author, infosec educator); not affiliated with any commercial AV/EDR vendor, reinforcing its reputation as a red-team/pentest community baseline tool rather than vendor-optimized scanning software.

## How It Works

WinPEAS operates in **two executable formats**, both maintained and equally functional:

### WinPEAS.exe (compiled C# binary)

```
Operator's machine (C2, reverse shell, or direct console)
│
├─ Download/stage WinPEAS.exe (via WebDAV, SMB, C2, wget, etc.)
│
├─ Execute: C:\Temp\WinPEAS.exe
│  (or renamed: C:\Temp\svchost.exe, conhost.exe, etc.)
│
└─ Local process:
   ├─ Open HKEY_LOCAL_MACHINE registry hives (SAM, Security,
   │  Software, System) — requires admin for Security, runs as-is
   │  for Software/System (gives different results at diff privs)
   │
   ├─ Enumerate:
   │  ├─ Users, groups, local admin membership
   │  ├─ Services (DisplayName, ImagePath, StartType, obj/pwd)
   │  ├─ Scheduled tasks (Task Scheduler XML, trigger/action)
   │  ├─ Network shares, listening ports, firewall rules
   │  ├─ Installed software (Programs & Features registry)
   │  ├─ DLLs in known hijack paths (System32, AppData, etc.)
   │  ├─ Unquoted service paths (analyzer checks for spaces
   │  │  in the path that aren't quoted)
   │  ├─ DCOM/COM object registration (AppID/LocalServer32)
   │  ├─ Token privileges (SeImpersonate, SeDebugPrivilege,
   │  │  SeLoadDriver, etc. — via TokenPrivileges API)
   │  ├─ UAC configuration (EnableUIAccess, FilterAdministratorToken,
   │  │  ConsentPromptBehavior from HKLM\Software\Microsoft\Windows\
   │  │  CurrentVersion\Policies\System)
   │  ├─ PowerShell execution policy
   │  ├─ Bitlocker/cipher status
   │  ├─ Antivirus/Windows Defender exclusion lists
   │  └─ Cached credentials in browsers (Chrome, Firefox,
   │     Edge registry/AppData reads — no live password decryption,
   │     just presence enumeration)
   │
   └─ Color-code results to stdout or (with flags) to file
      Output to: STDOUT (interactive), file (no-file-touch),
      or HTML export (requires `-html` flag)

Results: ~300-500 lines of categorized output, organized by
         attack vector, each line color-coded:
         🔴 RED = immediate escalation likelihood
         🟡 YELLOW = check this manually
         🔵 BLUE = informational context
```

### WinPEAS.ps1 (PowerShell script)

Functionally identical to the `.exe`, but:
- **Execution:** `powershell -ExecutionPolicy Bypass -File C:\Temp\winpeas.ps1` (or via `IEX` in-memory load).
- **Advantage:** No compiled binary footprint, can be obfuscated trivially (comments, string concatenation, variable renaming).
- **Disadvantage:** Requires PowerShell (unavailable on minimal systems) and exposes the script's source-code logic to AMSI if unobfuscated.
- **Canonical:** The `.ps1` version is the original; the `.exe` is maintained as a convenience for C2 frameworks and static-payload delivery.

Both versions enumerate the **same findings set** — the difference is delivery/execution context, not coverage.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Local access model | Filesystem reads + registry reads (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER) — no network calls of WinPEAS's own, no C2 callback, no external authentication |
| Privilege context | Runs as whatever user invoked it; discovers different findings based on privilege level (SYSTEM > Administrator > low-privileged user). A low-priv user still discovers many vectors but lacks registry/file-read permissions for the deepest checks. |
| Target APIs | Windows Registry API (RegOpenKey, RegEnumValue), filesystem enumeration (FindFirstFile, GetFileAttributes), WMI querying (for OS info), Token APIs (GetTokenInformation), and COM object enumeration (CoCreateInstance for DCOM registry lookup). All read-only, no exploitation APIs called. |
| Output | ANSI color codes to stdout by default; can redirect to file (.txt or `-html` for HTML report) or supress colors with `$NoColor` environment variable |

## Command-Line Switches — Quick Reference

Verified directly against the current `carlospolop/PEASS-ng/winPEAS/` repository structure. WinPEAS has minimal flags — most of its behavior is built-in enumeration, not opt-in subcommands like Metasploit or Nmap.

### WinPEAS.exe

| Flag | Plain-English meaning |
|---|---|
| `(no flags)` | Run full enumeration, output to stdout with ANSI colors. Default behavior. |
| `-h` or `-help` | Print help text (list of all flags) and exit. |
| `-html <filename>` | Generate an HTML report file (self-contained, includes CSS/JS for interactivity) in addition to or instead of stdout. Useful for exfiltration/offline analysis. |
| `-searcherPath <path>` | (Rare) Specify a path to load custom modules/plugins; defaults to local `Searchers/` directory. For advanced custom enumeration only. |
| `-runAll` | Force run all searchers, even those that would normally be skipped (e.g., disabled-by-default checks). |

### WinPEAS.ps1 (PowerShell version)

| Parameter | Plain-English meaning |
|---|---|
| `-verbose` | Include extra debugging output as the script runs (print each registry open, file read attempt). Slows down execution. |
| `-nocolor` | Disable ANSI color codes in output (useful when piping to file on systems that mangle escape sequences). |
| `-html` | Generate an HTML report (same as `.exe` version). |

**Key limitation:** WinPEAS has **no built-in evasion flags** (no `-randomize`, no `-quiet`, no `-obfuscate`). Evasion depends on deployment method (renamed binary, PowerShell obfuscation, in-memory execution) — the tool itself is a straightforward enumerate-and-report engine.

## Output Categories and Color Coding

WinPEAS output is organized hierarchically by attack vector. The top-level categories (verified against the source `Searchers/` directory in the repository) include:

| Category (Output Section) | Color Code | What It Enumerates | Typical Findings |
|---|---|---|---|
| **System Information** | 🔵 Blue | OS version, architecture, PowerShell version, registered hotfixes | Windows Server 2019 (no patch KB5035844), PowerShell 5.1 |
| **Network Configuration** | 🔵 Blue | IP addresses, DNS servers, listening ports, firewall rules | "Listening on 0.0.0.0:3389," "Firewall: OFF on one profile," SMB listening |
| **Users and Groups** | 🟡 Yellow | Local user accounts, group membership, user descriptions | Administrator, SYSTEM service accounts, "Backup Operator" members (can read file ACLs) |
| **Logged In Users** | 🟡 Yellow | Currently logged-in users, logon tokens | DOMAIN\Administrator token present (might be impersonatable) |
| **UAC Configuration** | 🔴 Red | UAC status (Enabled/Disabled), FilterAdministratorToken, ConsentPrompt settings | "UAC is Enabled but **FilterAdministratorToken = 0**" (can UAC-bypass without prompt) |
| **Privileges** | 🔴 Red | Token privileges: SeImpersonate, SeDebugPrivilege, SeLoadDriver, SeManageVolume, etc. | "SeImpersonate: Enabled" (ripe for Potato family), "SeDebugPrivilege: Enabled" |
| **Services** | 🔴 Red | Each installed service: name, ImagePath, StartType, service account | "UpdateTask.exe: Unquoted path C:\Program Files\Vendor\update task.exe" (space allows hijack), "Service runs as SYSTEM," "ImagePath to non-existent binary" |
| **Scheduled Tasks** | 🔴 Red | All scheduled tasks: trigger/action/principal, run-as account | "Task runs as SYSTEM every 5 min," "Task's binary is in writable location" |
| **Registry AutoRun Locations** | 🔴 Red | HKLM\Software\Microsoft\Windows\CurrentVersion\Run, RunOnce, services.exe startup items | "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run: C:\malware.exe" (implant found), or legitimate vendor entries flagged as "modifiable by non-admin" |
| **DLL Hijacking Opportunities** | 🟡 Yellow | Paths where WinPEAS found `.dll` files missing (could be hijacked), and writable locations | "C:\Program Files\Vendor\lib.dll missing (but C:\Program Files\Vendor is writable)" |
| **DCOM Privilege Escalation** | 🔴 Red | COM objects registered with `LocalServer32` (executables), their ACLs, and which can be instantiated at higher privilege | "ShellBrowserWindow DCOM object: AppID {C08ADE90...}, modifiable ACL" |
| **Installed Software** | 🔵 Blue | All installed software from Add/Remove Programs registry key | List of ~50 software names (context for attack surface) |
| **Running Processes** | 🔵 Blue | Process list, service account identities for each | "explorer.exe runs as user, svchost.exe runs as SYSTEM, potential targets for process injection" |
| **Browser Cached Credentials** | 🟡 Yellow | Chrome, Firefox, Edge credential store locations; no passwords decrypted, just presence flagged | "Chrome credential cache detected at C:\Users\admin\AppData\Local\..." |
| **BitLocker & Encryption** | 🔵 Blue | BitLocker status, cipher/mode, recovery key availability | "BitLocker Enabled, but recovery key stored in Active Directory" (less useful for local escalation) |
| **Windows Defender & Exclusions** | 🔵 Blue | Antivirus status, configured exclusion paths | "Exclusion: C:\Company\*" (implants could hide here) |
| **Credentials in Environment** | 🟡 Yellow | Environment variable scan for hardcoded passwords, API keys | "PSModulePath variable contains writable directory" (potential module hijack) |
| **Potential Kernel Exploits** | 🟡 Yellow | OS version + known kernel-exploit database (HotFixes/KB articles missing) | "Windows 10 build 19045, missing KB5035844 (DisallowCMD UAC bypass) — potentially vulnerable to CVE-2023-XXXXX" |

**Color interpretation for operators:**
- **Red = act on this immediately** — unquoted service path, SeImpersonate privilege, UAC misconfiguration.
- **Yellow = check this in your scenario** — may or may not be exploitable depending on your access level and the target's specific binary/path availability.
- **Blue = context** — helps you plan the overall exploitation chain, but not immediately exploitable on its own.

## Quick Use-Case List

1. **Post-exploit reconnaissance (direct shell)** — WinPEAS immediately after reverse shell, PowerShell session, or SSH access to enumerate escalation paths.
2. **C2-integrated automated enumeration** — Cobalt Strike `execute-assembly`, Sliver `execute` command, or Empire agent automatically stages WinPEAS on beacon callback.
3. **Offline triage (file exfil + analysis)** — WinPEAS output redirected to file, exfiltrated over C2, analyzed on operator's jump box.
4. **Staged deployment (initial access → enumeration → exploitation)** — Responder/phishing foothold → WinPEAS → LaZagne (creds) → Rubeus (Kerberos) → PsExec (lateral) or Potato (escalation).
5. **Privilege-level comparison** — Run WinPEAS twice (once as current user, once via `runas` with different creds) to compare discovery results at different privilege levels.
6. **Post-remediation verification** — Re-run WinPEAS to confirm that UAC bypass, unquoted paths, or service misconfigurations were actually fixed.
7. **Kernel-exploit targeting** — WinPEAS identifies OS build and installed patches; output fed into exploit frameworks (e.g., kernel.sh for Linux equivalents) to find applicable exploits.
8. **Firewall/EDR detection avoidance** — PowerShell version obfuscated and piped in-memory via `IEX`; no binary file on disk, no parent-process association with cmd.exe.
9. **CI/CD/container intrusion** — WinPEAS in a Windows container (unusual but possible in Hyper-V setups or Windows containers in mixed-OS clusters) to triage container escape paths.
10. **Domain privilege escalation** — WinPEAS identifies local admin groups and group memberships; output piped to BloodHound collection (SharpHound or manual import) for AD graph analysis and kerberoasting setup.
11. **Scheduled task persistence + escalation** — WinPEAS finds world-writable task files or service binaries; exploit identified path, create persistent scheduled task under SYSTEM.
12. **Multi-stage backdoor staging** — WinPEAS run, output parsed by operator's custom script to identify specific escalation path (e.g., "SeImpersonate available"); automatically stages second tool (Potato family exploit, DLL hijack payload, etc.) based on findings.

## Prerequisites

| Prerequisite | Detail |
|---|---|
| **Code execution on the target** | WinPEAS requires already being able to run a binary (`.exe`) or script (`.ps1`) on the target. It does not provide initial access — it assumes a reverse shell, web shell, C2 agent, or direct Windows access already exists. |
| **Operating system** | Windows XP through Windows 11, Windows Server 2003 through 2022 — verified against the source's compatibility list. |
| **Privileges to run WinPEAS itself** | Can run as any user (SYSTEM, admin, low-priv). Different privilege levels discover different findings — SYSTEM/admin uncovers deeper registry access, low-priv user still finds many leverageable paths but misses some ACL-guarded findings. |
| **Privileges to actually exploit findings** | Varies by finding. A low-priv user can discover "SeImpersonate available," but exploitation of that requires the Potato-family tools (which WinPEAS itself doesn't run). See WinPEAS's own output for "Exploitation Required" flags per finding. |
| **Powershell version (if using .ps1)** | PowerShell 3.0+ (2012 and later). PowerShell 2.0 (Windows 7 RTM, Windows Server 2008 R2) likely still works, but not explicitly tested against modern WinPEAS. |
| **Execution policy (if using .ps1)** | Can be bypassed via `-ExecutionPolicy Bypass` switch in the invocation, or via `IEX` in-memory load (common in C2 frameworks). WinPEAS.exe requires no PowerShell policy. |
| **No network requirement** | WinPEAS makes zero outbound network calls on its own — entirely local enumeration. Safe to run on a network with strict egress controls. |
| **Antivirus/EDR considerations** | WinPEAS.exe as an unmodified binary is well-known and likely flagged by modern EDR (Defender, CrowdStrike, etc.). Evasion via renaming binary, using `.ps1` version with obfuscation, or delivering via C2 execute-assembly (runs in memory) are standard mitigations. |

