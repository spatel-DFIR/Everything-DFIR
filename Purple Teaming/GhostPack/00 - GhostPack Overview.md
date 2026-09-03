# GhostPack — Overview

The root page for the `GhostPack/` tool folder. GhostPack is not a single tool but an author-family umbrella — a set of independent, purpose-built C# offensive-security tools sharing a common origin, licensing posture, and distribution model. This folder covers five members: **SharpUp** (local privesc enumeration), **SharpDump** (LSASS/process minidump), **SafetyKatz** (dump + in-process Mimikatz parse, combined), **SharpWMI** (WMI-based remote execution/persistence), and **Certify** (AD CS enumeration and abuse). `Rubeus/` and `Seatbelt/` — also GhostPack projects, also authored by Will Schroeder — were built earlier in this repo as their own top-level folders (Wave 1/Wave 2) rather than nested here; treat them as members of the same family even though they sit outside this directory.

## Contents
- [What GhostPack Is](#what-ghostpack-is)
- [Shared Mechanics Across the Family](#shared-mechanics-across-the-family)
- [Where the Five Tools Diverge](#where-the-five-tools-diverge)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## What GhostPack Is

[`GhostPack`](https://github.com/GhostPack) is a GitHub organization, not a single repository — each tool is its own independently versioned project. **Will Schroeder (`@harmj0y`)** is the primary or co-primary author on every tool in this folder (Certify is co-authored with **Lee Christensen**, `@tifkin_`); all five ship under the **BSD 3-Clause** license. The organizing idea across the family, stated or implied in every one of these tools' own READMEs, is the same: take a capability that already exists as a PowerShell function (frequently from `PowerSploit`, itself built earlier in this repo at `../PowerSploit/`) and re-implement it as compiled, standalone C# — removing the dependency on a live PowerShell host process and the logging surface (Script Block Logging, Module Logging, AMSI's PowerShell-specific hook) that comes with it. SharpUp is an explicit port of `PowerSploit/PowerUp`'s discovery checks; SharpDump is an explicit port of `PowerSploit`'s `Exfiltration/Out-Minidump.ps1`; SharpWMI is a C# reimplementation of PowerSploit-era WMI lateral-movement primitives. SafetyKatz and Certify don't port a PowerShell ancestor — they wrap and drive other compiled tools (a modified Mimikatz build; the CA-facing enrollment RPC surface) directly.

**Development posture is not uniform across the five, and that matters for how each page frames its History section.** SharpUp, SharpDump, SafetyKatz, and SharpWMI are all frozen or near-frozen — first commits clustered in **July 2018**, minimal-to-no activity since (SafetyKatz: 6 commits total, nothing since 2018-08-20; SharpDump: one substantive fix in 2019, nothing since; SharpUp: feature-frozen since 2022; SharpWMI: last commit 2021-01-15). **Certify is the outlier** — actively maintained, with a complete rewrite at v2.0.0 (2025-08-11) that replaced its entire command surface, and commits landing as recently as 2026-07-29. Do not assume "GhostPack tool" implies "abandoned tool" — verify each one's own repo state independently, as each sub-tool's `01 - Overview.md` does.

## Shared Mechanics Across the Family

- **No official binaries are ever released, for any of the five.** Every tool's README states this explicitly ("we are not planning on releasing binaries... you will have to compile yourself"), verified live against each repo's `/releases` and `/tags` API endpoints (all empty). This has one consistent evidentiary consequence repeated across every sub-tool's `04 - Target Evidence.md`: there is no canonical file hash or PE-signature to match a suspect binary against — every real-world deployment is a custom operator compile, so behavioral/API-level detection (documented in each `05 - Detection and Hunting.md`) carries more weight than static signature matching.
- **All five are reflectively loadable.** Each is a standalone .NET assembly (target framework ranges from 3.5 for the 2018-era tools up to 4.7.2 for Certify), and each sub-tool's Hands-On page documents the same C2-loader delivery pattern already established for `../Rubeus/` and `../Seatbelt/`: Cobalt Strike's `execute-assembly`, Covenant, or Sliver's `execute-assembly` hosting a CLR inside an existing beacon process and invoking the tool's `Main()` directly, with no `.exe` ever touching disk on the target.
- **Zero shared codebase or plugin architecture across tools** — despite the common authorship, SharpUp/Seatbelt share a reflection-driven `Checks`-namespace discovery pattern with each other, but SafetyKatz, SharpDump, SharpWMI, and Certify are each their own independent, single-purpose binary with no shared library dependency on one another. Cross-tool relationships in this folder are chained-workflow relationships (one tool's output feeding the next tool's input), not code-sharing ones.

## Where the Five Tools Diverge

| Axis | SharpUp | SharpDump | SafetyKatz | SharpWMI | Certify |
|---|---|---|---|---|---|
| Purpose | Local privesc enumeration (read-only) | Process/LSASS minidump | LSASS dump + in-process Mimikatz parse | WMI remote execution / event-subscription persistence | AD CS (ADCS) template/CA enumeration + certificate abuse |
| Network client of its own | No (local only, except SYSVOL SMB read) | No (local only) | No (local only) | **Yes** — DCOM/WMI to a remote host | **Yes** — LDAP + MS-WCCE/RPC to a CA/DC |
| Weaponizes what it finds | No — discovery only | No — dump only | **Yes** — dumps and parses in one run | **Yes** — executes commands / registers persistence | **Yes** — requests and can forge certificates |
| PowerShell ancestor | `PowerSploit/PowerUp.ps1` | `PowerSploit/Out-Minidump.ps1` | None (wraps Mimikatz + a PE loader) | PowerSploit-era WMI lateral-movement functions | None (wraps CA enrollment APIs directly) |
| Development state (verified) | Feature-frozen since 2022 | Frozen since 2019 | Frozen since 2018-08-20 | Frozen since 2021-01-15 | **Actively maintained**, v2.0.0 rewrite 2025-08-11 |

## Sub-Tool Table of Contents

| Sub-Tool | Covers |
|---|---|
| [`SharpUp/`](<SharpUp/01%20-%20Overview.md>) | Local privilege-escalation enumeration — 15 checks (service ACLs/binaries/registry keys, unquoted paths, `AlwaysInstallElevated`, GPP/autologon/unattended-install credential harvesting, hijackable `%PATH%`/DLLs, token privileges) run as concurrent threads, gated by the caller's own integrity level unless `audit` is passed |
| [`SharpDump/`](<SharpDump/01%20-%20Overview.md>) | Arbitrary-PID or LSASS minidump via `dbghelp.dll!MiniDumpWriteDump()`, with a fixed, PID-qualified `debug<PID>.out`/`.bin` output naming convention and automatic GZip compression — the deliverable is a portable dump file for later, possibly offline, parsing |
| [`SafetyKatz/`](<SafetyKatz/01%20-%20Overview.md>) | LSASS dump and credential parse **in one execution** — the same `MiniDumpWriteDump()` call as SharpDump, feeding a manually PE-loaded, modified Mimikatz build running `sekurlsa::minidump` in-process against the fresh dump before deleting it; takes no command-line arguments and always targets `lsass` by name |
| [`SharpWMI/`](<SharpWMI/01%20-%20Overview.md>) | Remote command execution and enumeration over WMI/DCOM, distinct from `../Impacket/wmiexec/` and `../LOLBins/wmic/` — includes an `executevbs` mode that registers a real `__EventFilter`/`ActiveScriptEventConsumer` persistence primitive rather than a one-shot `Win32_Process.Create()` call |
| [`Certify/`](<Certify/01%20-%20Overview.md>) | AD CS (ADCS) certificate-template and CA enumeration, ESC-class misconfiguration identification (ESC1/2/3/4/6/7/8/9/11/13/15/16), certificate request/renewal, and golden-certificate forging (`forge`, absorbing the formerly separate `ForgeCert` tool) — chains directly into `../Rubeus/`'s `asktgt /certificate:` for the authentication step |

Every sub-tool's own `01 - Overview.md` carries its individually-verified History, mechanics diagram, and full switches table — this page states the family-level findings once and does not repeat them.
