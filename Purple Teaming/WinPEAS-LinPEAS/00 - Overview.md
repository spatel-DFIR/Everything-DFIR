# WinPEAS / LinPEAS — Overview

This folder bundles **two platform-specific privilege-escalation enumeration frameworks** — Carlos Polop's **WinPEAS** (Windows) and **LinPEAS** (Linux) — because they solve the identical first problem in post-compromise privilege escalation: *"what are all the ways this host could be escalated, given the code execution I already have?"* Together, they form a cross-platform enumeration baseline that feeds into exploitation (via the `Potato Family/` for Windows, or kernel-exploit chains for Linux) rather than executing the escalation itself.

## Contents
- [Why These Two Are Bundled](#why-these-two-are-bundled)
- [The Core Distinction — Platform-Specific Enumeration](#the-core-distinction--platform-specific-enumeration)
- [Design Shared Across Both](#design-shared-across-both)
- [Side-by-Side Comparison](#side-by-side-comparison)
- [When an Analyst Sees One vs. the Other](#when-an-analyst-sees-one-vs-the-other)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## Why These Two Are Bundled

Both tools execute locally (requiring code execution already on the target), run unattended with no interactive shell required, produce high-volume output categorized into privilege-escalation vectors, and generate enough false positives that their value lies in **systematic coverage** rather than surgical precision. They exist as a pair under the unified `PEASS-ng` ("Privilege Escalation Awesome Sauce Suite — next generation") GitHub repository maintained by **Carlos Polop** — verified against [`carlospolop/PEASS-ng`](https://github.com/carlospolop/PEASS-ng) as of August 2026. They share:

- A common philosophy: enumerate everything, color-code by urgency, let the operator triage which findings are exploitable in their specific scenario.
- A common limitation: no exploitation built-in — they identify the path to privilege escalation but don't execute it.
- A common evidentiary footprint: high local I/O (config file reads, registry queries, system information enumeration), minimal network traffic, run-time artifacts only — the tools delete themselves or run from memory.
- A common hunting challenge: both tools make no assumptions about payload delivery, binary names, or command-line flags — WinPEAS can be renamed, recompiled, or run as PowerShell; LinPEAS can be piped over SSH or executed from a web shell — so process-tree detection is fragile.

The reason they're in the same folder: an operator compromising a mixed Windows/Linux environment (hybrid cloud, AD-managed Linux servers, containerized infrastructure) will stage one or both as a detection-evasion envelope — knowing that once one shell is proven and triage is underway, both systems will feed into a unified lateral-movement/escalation strategy.

## The Core Distinction — Platform-Specific Enumeration

Read each sub-tool's own `01 - Overview.md` for full mechanics — this is the fast disambiguation an analyst needs before reading either page in depth:

```
WinPEAS                                     LinPEAS
────────────────────────────────────────    ──────────────────────────────────
PowerShell or compiled .exe (.NET)          Bash script, zero external
Enumerates Windows-specific vectors:        dependencies beyond Unix tools
  • Users, groups, permissions               Enumerates Linux-specific vectors:
  • Services, scheduled tasks                 • SUID binaries and their params
  • Registry UAC/LSA/token bypass paths      • Sudo rules and wildcards
  • DLL hijack opportunities                  • Kernel version vs. known exploits
  • Unquoted service paths                    • Writable /etc, .so injection
  • GPO misconfigurations                     • SSH/private-key accessibility
  • Credential material (browsers, etc.)      • Cron jobs & world-writable scripts
  • COM object abuse (Windows only)           • Capability abuse (CAP_DAC_OVERRIDE)
  • PrintSpooler/BITS/WinRM/WMI abuse        • Namespace abuse (Docker, LXC)
                  │                                           │
                  ▼                                           ▼
    Feeds Windows-specific exploitation      Feeds Linux-specific exploitation
    (PetitPotato, SweetPotato, DLL          (kernel exploits, sudo bypass,
     hijack, etc.) or lateral movement       SUID wrapper chains, capability
     via AD/Kerberos                         abuse, container escape)
```

WinPEAS is **PowerShell by default** (modern, execution-policy-aware, matches C2 assumptions) or **.exe** (no PowerShell needed, direct binary execution) — both versions are maintained. LinPEAS is **Bash only** — it requires shell access and a Unix environment, but no compilers or scripting-language interpreters beyond the shell itself.

## Design Shared Across Both

| Aspect | Detail |
|---|---|
| **Execution model** | Local, read-only enumeration — no exploitation. WinPEAS reads `HKEY_LOCAL_MACHINE` and filesystem; LinPEAS reads `/proc`, `/sys`, `/etc`, filesystem. No network calls of the tool's own. |
| **Output** | Categorized, color-coded findings by severity (red = likely exploitable, yellow = check manually, green/blue = informational). Both output hundreds of lines — designed for scanning the color-coded summary first, then drilling into specifics. |
| **Runtime** | WinPEAS: 20-40 minutes typical (comprehensive registry/ACL enumeration). LinPEAS: 5-15 minutes typical (faster file/process reads). Both scale with system size. |
| **Operational footprint** | Minimal: local process creation (temp files, child processes reading config), no C2 callbacks. Both are safe to run without expecting EDR callback — the only signal is the process itself. |
| **False-positive rate** | High, by design. Both find potential paths and flag them for operator analysis rather than filtering. An "exploitable" finding may require specific conditions (e.g., a SUID binary without its standard companion library, unquoted path requiring a specific spacing in the binary name) that don't apply to this system. |
| **Reusability** | Both tools are **read-only and idempotent** — safe to run multiple times on the same host, useful for logging outputs to compare across time or to verify that remediations actually closed paths. |

## Side-by-Side Comparison

| | WinPEAS | LinPEAS |
|---|---|---|
| **Source repository** | `carlospolop/PEASS-ng/winPEAS/` (unified repo) | `carlospolop/PEASS-ng/linPEAS/` (unified repo) |
| **Language(s)** | PowerShell (.ps1) + C# (.exe, both actively maintained) | Bash (.sh only) |
| **Delivery methods** | Direct .exe execution, PowerShell script invocation, embedded .exe in .NET app, execute-assembly from C2 | Bash script piped via SSH, wget/curl pull and execute, embedded in shell one-liner, docker/container shells |
| **Authentication context required** | Runs as whatever user invoked it — can be SYSTEM (post-SeImpersonate abuse), local admin, or low-privileged user (finds different vectors at each level) | Runs as shell owner — typically `www-data`/`apache` (web shell), unprivileged SSH user, or root (if already escalated) |
| **Binary footprint (if .exe)** | .exe file itself is signable, recompilable (see GhostPack precedent); renamed `.exe` still identifiable via PE metadata (FileDescription, ProductName, InternalName hardcoded if not rebuilt) | Script is plaintext — easily obfuscated by adding comments, renaming functions, reordering code with zero functional change |
| **No-file-touch execution** | PowerShell version can be loaded entirely into memory via `IEX` / `Invoke-WebRequest`, zero disk artifact | Bash piped via SSH (`ssh target 'bash < ./linpeas.sh'`) or heredoc over a pre-existing shell — zero disk artifact |
| **Color output** | Yes, ANSI color codes; respects `$NoColor` environment variable for EDR-aware operators | Yes, ANSI color codes; respects `NO_COLOR` environment variable (standard Unix convention) |
| **Output export formats** | HTML export option (`-html`), text redirect-to-file only by default | TXT file dump (`-oN`), JSON export (`-oJ`), simple text redirect |
| **Notable evasion in the wild** | WinPEAS renamed to common system binaries (`svchost.exe`, `conhost.exe`); PowerShell version obfuscated via encoding/string replacement | LinPEAS rarely renamed — Bash scripts are inherently less suspicious than binaries, and renaming adds no evasion value |
| **MITRE ATT&CK Software entry** | None (procedure example only under T1592.004 / T1087 / T1012) | None (procedure example only under T1592.004 / T1087 / T1012) |
| **License** | GPL v3 (verified at [`carlospolop/PEASS-ng`](https://github.com/carlospolop/PEASS-ng) root LICENSE) | GPL v3 (same repository, same license) |

## When an Analyst Sees One vs. the Other

- **WinPEAS (.exe) dropped to `%TEMP%` with a random name, executed, then deleted** → a C2 framework (Cobalt Strike, Sliver, Empire) staging automated recon, likely followed by credentialed access-enumeration tools (Rubeus, LaZagne, AdFind) within minutes.
- **WinPEAS output redirected to a file, exfilled over DNS/HTTPS** → the operator is conducting an offline-first reconnaissance phase, triage from a jump box, before touching any live exploitation.
- **LinPEAS piped into a running shell (Bash history shows `bash < linpeas.sh`; `/proc` entry shows recent script invocation)** → post-exploitation triage on a Linux/Unix system, typically immediately after `Impacket/` reverse shell or SSH access.
- **LinPEAS output file found in `/tmp` or `/var/tmp`** → dropped by a web shell or compromised CI/CD pipeline, operator paused to enumerate before escalating.
- **Both WinPEAS and LinPEAS present in an intrusion** → the adversary is operating in a hybrid environment or preparing for multiple vectors simultaneously; both will feed into the same playbook via the `Potato Family/` (Windows) or kernel-exploit chains (Linux), cross-referenced in their respective `02 - Hands-On Use Cases.md` files.

## Sub-Tool Table of Contents

| Sub-Tool | Covers |
|---|---|
| [`WinPEAS/`](WinPEAS/01%20-%20Overview.md) | Windows privilege-escalation enumeration (PowerShell + compiled .exe). Enumerates UAC bypass paths, unquoted services, registry-storable credentials, DLL hijacking, and COM object abuse — 200+ vectors in a single ~20-40 minute run. Designed for post-compromise triage and feeds directly into `Potato Family/` exploitation. |
| [`LinPEAS/`](LinPEAS/01%20-%20Overview.md) | Linux privilege-escalation enumeration (Bash script). Hunts SUID binaries, sudo misconfiguration, kernel exploits, writable system paths, and namespace abuse in a single ~5-15 minute run. Designed for post-compromise triage on web shells, reverse shells, or SSH access. |

Both sub-tool folders inherit this page's shared-design framing and the platform-specific enumeration model above — neither re-derives it. Each sub-tool's own pages dig into platform-specific artifact types, detection, and exploitation chains.
