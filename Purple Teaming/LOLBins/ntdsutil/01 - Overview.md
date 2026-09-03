# LOLBins — ntdsutil.exe — Overview

> 🔴 **Red Flag Principle:** `ntdsutil.exe "ac i ntds" "ifm" "create full <path>" q q` gives an attacker the **entire domain's credential material** — every account's NT hash, including `krbtgt` — using a Volume Shadow Copy internally, **without ever stopping the NTDS service and without ever touching `lsass.exe`**. There's no network protocol to catch, no service to spot in the SCM, no LSASS-handle-open event to flag — the only reliable tell is **process-tree/context on the Domain Controller itself**: `ntdsutil.exe` (or `vssadmin.exe`, its raw-VSS equivalent) executing outside a documented backup window, especially under an interactive shell, with `ifm`/`create full` in the command line and a non-standard output path. This is the single most common ransomware-precursor, domain-dominance technique for offline, at-scale hash extraction — and unlike DCSync, it requires the attacker to already be **on the DC**, not just holding a replication-rights grant.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`ntdsutil.exe` is **not** an open-source, GitHub-hosted project — it's a native Windows Server binary shipped by Microsoft as part of the Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS) server roles (also installable standalone via the AD DS Tools component of the Remote Server Administration Tools, RSAT). Per that reasoning, "verify against the official source" for this note means Microsoft's own documentation and the LOLBAS Project catalog, not a GitHub repository — cited throughout below.

Microsoft's official reference ([Ntdsutil | Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343%28v=ws.11%29)) describes it plainly: *"Ntdsutil.exe is a command-line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). You can use the ntdsutil commands to perform database maintenance of AD DS, manage and control single master operations, and remove metadata left behind by domain controllers that were removed from the network without being properly uninstalled. This tool is intended for use by experienced administrators."* It has shipped since Windows Server 2003 and remains current on Server 2016/2019/2022/2025 — the specific documentation cited in this note is archived TechNet-era content (`v=ws.11`, covering Server 2008–2012 R2) because that is the last version where Microsoft published a full command-by-command reference table; no newer replacement table was found on Microsoft Learn during this build, and later `ntdsutil` versions have not been found to remove any of the commands documented there. Binary path: `%SystemRoot%\System32\ntdsutil.exe`.

**The LOLBAS Project** ([lolbas-project.github.io/lolbas/OtherMSBinaries/Ntdsutil](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Ntdsutil/), source YAML in [LOLBAS-Project/LOLBAS](https://github.com/LOLBAS-Project/LOLBAS/blob/main/yml/OtherMSBinaries/Ntdsutil.yml)) catalogs exactly one documented abuse entry for this binary, credited to **Tony Lambert** (added 2020-01-10), acknowledging **Sean Metcalf (@PyroTek3)** and his ADSecurity.org research as the origin of the technique:

```
ntdsutil.exe "ac i ntds" "ifm" "create full c:\" q q
```

LOLBAS categorizes this as `Dump`, use-case "Dumping of Active Directory NTDS.dit database," requiring Administrator privileges, mapped to **MITRE ATT&CK T1003.003**. Its listed detection indicator is intentionally narrow: *"ntdsutil.exe with command line including 'ifm'"* — a limitation this note's Detection & Hunting file addresses directly, since that single substring check misses every variant that avoids the literal word `ifm`.

## How It Works

**The most important structural fact about this tool, for a DFIR reader used to the rest of this module's remote-exploitation tools (Impacket, Sliver, Mimikatz): `ntdsutil` has no network client of its own.** It is a purely local, interactive command-line utility that operates on files already present on the box it runs on. There is no "connect to a target" step — the "target" is whatever host `ntdsutil.exe` is executed on. An attacker must **already have code execution on a Domain Controller** (via RDP, an interactive console session, WinRM, a service, a scheduled task, or a chained lateral-movement tool such as Impacket's `wmiexec.py`/`psexec.py`) before `ntdsutil` itself does anything — this is the opposite prerequisite from DCSync (`Mimikatz/lsadump (DCSync)/`), which needs only a network-reachable replication-rights grant and never touches the DC's disk at all.

```
Operator's chosen access vector (RDP / console / WinRM / PsExec / wmiexec / scheduled task)
                        │
                        ▼  (all of this executes ON the Domain Controller itself)
ntdsutil.exe "ac i ntds" "ifm" "create full <path>" q q
        │
        ├─ "ac i ntds"  (activate instance ntds)
        │       binds the ntdsutil session to the local NTDS instance — the directory
        │       service's registry-held pointers to the live ntds.dit/log/working-dir paths
        │
        ├─ "ifm" → "create full <path>"
        │       │
        │       ├─ 1. Internally invokes the Volume Shadow Copy Service (VSS) against the
        │       │      volume hosting %SystemRoot%\NTDS\ntds.dit — a point-in-time-consistent
        │       │      snapshot, taken WITHOUT stopping the NTDS service and WITHOUT ever
        │       │      opening a handle to lsass.exe
        │       ├─ 2. A temporary working database is built in %TMP% (Microsoft's own docs:
        │       │      "you need at least 110% of the size of the AD DS... database free on
        │       │      the drive where the %TMP% folder is") — the single most likely-to-be-
        │       │      overlooked disk artifact of this whole operation
        │       ├─ 3. (unless "nodefrag" is specified) an ESE offline-defragmentation pass
        │       │      runs against the snapshotted copy
        │       └─ 4. Output is written to two new subfolders under <path>:
        │              <path>\Active Directory\ntds.dit    — the full AD database
        │              <path>\registry\SYSTEM               — the SYSTEM hive (needed to
        │                                                      decrypt ntds.dit's secrets
        │                                                      offline)
        │              (multiple independent third-party analyses — ired.team, The Hacker
        │              Recipes, Cyberis — also report a SAM hive landing in the same
        │              registry\ folder; on a DC that hive holds only the local DSRM
        │              Administrator account, since domain accounts are never stored in a
        │              DC's own SAM)
        │
        └─ "q q"  exits the ifm submenu, then ntdsutil itself
```

Microsoft's own `ifm` reference page ([ifm | Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732530%28v=ws.11%29)) states directly: *"The full AD DS installation media includes the registry"* — confirming the SYSTEM hive is captured automatically, with no extra flag needed, which is exactly what makes `ntds.dit` + `registry\SYSTEM` together a complete, immediately offline-crackable credential set (hand this pair to `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`, cross-linked in Use Cases).

**Why this specific mechanism is the tool's defining detection problem:** `ifm` was designed for a completely legitimate purpose — generating install media so a new DC can be promoted without pulling a full initial replication over the network — and it accomplishes that using the same VSS machinery a backup product would use. The command is therefore **indistinguishable from routine DC administration at the API/protocol level**; the only thing that separates a legitimate IFM export from a credential-theft one is *context* (who ran it, when, from what parent process, and where the output went) — never the command itself. See `05 - Detection and Hunting.md`'s Hunting Priority table, and `Windows/23 - Special Services/Domain Controller — Role-Specific Forensics.md`'s Step 7 flowchart, which this note leans on rather than re-deriving.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Execution | Local, interactive console utility — no network client. Runs entirely on whatever host it's invoked on |
| Underlying mechanism | Volume Shadow Copy Service (VSS) — same subsystem `vssadmin.exe` exposes directly; `ntdsutil ifm` is a purpose-built wrapper around it for AD DS/AD LDS specifically |
| Database engine | ESE (Extensible Storage Engine) — the same engine used by Exchange, WINS, and AD CS; `ntdsutil`'s `files` submenu invokes `esentutl.exe` for several of its lower-level operations (compact, integrity, recover) |
| Credential material produced | `ntds.dit` (the AD database itself, containing every account's password-derived secrets in encrypted form) + the `SYSTEM` registry hive (holds the boot key needed to decrypt those secrets offline) — the same two-file pair `secretsdump.py`'s `-just-dc`-free, offline mode consumes |
| Delivery vector into this note's scope | None of its own — reaching the DC to run it at all requires a separate technique: interactive logon (RDP/console), WinRM, a remote-execution tool (`Impacket/psexec/`, `Impacket/wmiexec/`), or a scheduled task/service |

## Command-Line Switches — Quick Reference

`ntdsutil` is a **REPL (interactive menu) tool**, not a flag-based CLI — but every menu command can also be passed as a separate quoted string on the initial command line, executed in sequence, which is exactly how the LOLBAS abuse invocation and every use case in this note work (`ntdsutil.exe "<cmd1>" "<cmd2>" ... q q`). Per Microsoft's own docs, most commands accept a **short form** (first few characters) instead of the full phrase. Full reference: [Ntdsutil | Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343%28v=ws.11%29).

**Top-level menu (the commands relevant to this note's abuse scope; Microsoft's page lists several purely administrative ones — LDAP policies, SSL/LDAP port, change service account — omitted here as out of scope for a purple-team reference)**

| Command | Short form | Plain-English meaning |
|---|---|---|
| `activate instance ntds` | `ac i ntds` | Sets AD DS (as opposed to an AD LDS instance) as the active target for every subsequent command — the mandatory first step before `ifm`, `files`, or `metadata cleanup` will do anything |
| `ifm` | `i` | Enters the Install From Media submenu — see below. **This is the credential-theft-at-scale submenu** |
| `files` | `f` | Enters the database-file-maintenance submenu (info, move, compact, integrity, recover) — legitimate maintenance surface, occasionally useful to an attacker for reconnaissance (`info` reports `ntds.dit`'s current size/location without touching it) |
| `metadata cleanup` | `m c` | Enters the submenu for removing a decommissioned/failed DC's leftover directory metadata — legitimate cleanup surface, discussed as a possible anti-forensics use in `02 - Hands-On Use Cases.md` |
| `set DSRM password` | `set d p` | Enters the submenu for resetting a DC's local Directory Services Restore Mode administrator password — a separate abuse angle (persistence, not bulk credential theft) covered in Use Cases |
| `roles` | `r` | Transfers/seizes FSMO (operations master) operational roles — administrative surface, not covered further in this note (no LOLBAS-documented abuse found for it specifically) |
| `authoritative restore` | `au r` | Restores previously-deleted AD objects from backup — legitimate DR tooling, not itself a credential-theft vector |
| `quit` | `q` | Exits the current submenu, or the tool entirely if at the top level — the abuse invocation's trailing `q q` exits both the `ifm` submenu and `ntdsutil` itself |
| `Help` / `?` | — | Displays in-tool help for the current menu |

**`ifm` submenu — the credential-export commands themselves**

| Command | Plain-English meaning |
|---|---|
| `create full <path>` | The LOLBAS-documented command. Exports `ntds.dit` + the `SYSTEM` (and, per third-party corroboration, `SAM`) registry hive to `<path>\Active Directory\` and `<path>\registry\`, with ESE defragmentation |
| `create full nodefrag <path>` | Same export, skipping the defragmentation pass — faster, smaller time-on-target, at the cost of a slightly larger output file |
| `create sysvol full <path>` | Same as `create full`, plus SYSVOL content (GPO scripts, startup/logon scripts, Group Policy Preferences XML — potentially still holding legacy `cpassword` material on an unpatched/never-remediated environment) |
| `create sysvol full nodefrag <path>` | `create sysvol full` without defragmentation |
| `create rodc <path>` | Builds RODC (Read-Only Domain Controller) install media. **Microsoft's own docs state Ntdsutil strips cached secrets from RODC media** — an operator who runs this variant by mistake gets a materially defanged, credential-poor export |
| `create sysvol rodc <path>` | `create rodc` plus SYSVOL — same cached-secrets stripping applies |
| `quit` / `Help` / `?` | Return to the top-level menu / in-tool help |

**`set DSRM password` submenu**

| Command | Plain-English meaning |
|---|---|
| `reset password on server <name-or-NULL>` | Prompts for and sets a new DSRM local-administrator password on the named DC (or the local one, if `NULL`) — see the persistence use case in `02` |
| `sync from domain account <name>` | Syncs the DSRM password to match a specified domain user account's current password (requires Server 2008 R2+/SP3+ or a specific hotfix per Microsoft's docs) |

**`metadata cleanup` submenu**

| Command | Plain-English meaning |
|---|---|
| `remove selected server <name>` | Removes directory + FRS metadata for a named, already-decommissioned DC, and attempts to transfer/seize any FSMO roles it held |
| `remove selected server <name1> on <name2>` | Same, executed against a different specified server rather than localhost |

## Quick Use-Case List

- Baseline, on-host `ifm` extraction of `ntds.dit` + `SYSTEM` via an interactive session on a DC
- Remote invocation against a DC by chaining through another lateral-movement/remote-execution tool (WinRM, PsExec, `wmiexec.py`) — ntdsutil itself never leaves the DC
- Speed-optimized extraction for mass/ransomware-precursor use (`create full nodefrag`)
- Capturing SYSVOL alongside the database in the same pull (`create sysvol full`)
- Staging the IFM output to a non-standard, removable-media, or cloud-sync-folder path ahead of exfiltration
- Chained offline hash extraction — handing the exported `ntds.dit`/`SYSTEM` pair to `secretsdump.py`
- Bypassing the literal `"ifm"` substring the LOLBAS/Sigma detection indicators watch for, via raw `vssadmin create shadow` + manual file copy instead of `ntdsutil ifm`
- The defanged variant operators specifically avoid (`create rodc` / `create sysvol rodc`) — included for completeness of the command surface
- DSRM password reset + `DsrmAdminLogonBehavior` registry modification for a persistent backdoor local-admin logon on the DC
- Multi-DC / forest-wide domain-dominance sweep (repeating the extraction across every reachable DC)
- Post-attack `metadata cleanup` to erase a rogue or DCShadow-style replication partner's directory footprint

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target Domain Controller | Non-negotiable — `ntdsutil` has no remote client. Reaching this state is itself a separate technique (RDP/console logon, WinRM, `Impacket/psexec/`, `Impacket/wmiexec/`, a scheduled task, or an already-planted implant) |
| Elevated/Administrator privileges on that DC | LOLBAS lists this explicitly. In practice this means Domain Admin, Enterprise Admin, or an account specifically delegated full administrative control of that DC — no lesser built-in role has the access `ifm`'s live-database VSS path requires |
| Disk space | At least 110% of the current `ntds.dit` size free on the drive backing `%TMP%`, per Microsoft's own `ifm` documentation — undersized `%TMP%` volumes are a real, documented failure mode for this technique, not just a theoretical caveat |
| Output-path write access | Wherever `<path>` in `create full <path>` points — a local drive, a writable UNC share, or removable/cloud-sync storage the operator has already staged |
| No prerequisite network reachability of any kind | Distinct from every other tool covered so far in this module — no port, no protocol, no credential material beyond the local session already held |
