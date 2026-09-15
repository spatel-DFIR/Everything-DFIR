# LOLBins — ntdsutil.exe — Target Evidence

Because `ntdsutil` always runs on the Domain Controller it acts against (`01 - Overview.md`), this file carries almost the entire evidentiary weight of this note — there is no separate remote-target evidence class to split off the way there is for Impacket's tools. This module does not re-derive the DC-specific investigation workflow already built in `Windows/23 - Special Services/Domain Controller — Role-Specific Forensics.md` (Step 7's process-tree flowchart) or the domain-wide response sequencing in `Windows/Threat Landscape and Playbooks/Domain Credential Compromise (DCSync and NTDS.dit Theft) Playbook.md` — both are cross-linked at point of use below rather than repeated.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon-if-deployed)
- [Volume Shadow Copy Artifacts](#volume-shadow-copy-artifacts)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Contrast with DCSync](#contrast-with-dcsync)

---

## Filesystem

| Artifact | Detail |
|---|---|
| IFM output — database | `<path>\Active Directory\ntds.dit` — the exported AD database, created fresh at the operator-chosen path. Per Microsoft's own docs, `ntdsutil` stores it under a subfolder literally named **`Active Directory`** |
| IFM output — registry hives | `<path>\registry\SYSTEM` (and, per third-party corroboration in `01`, `SAM`) — the decryption-key material needed to make the database usable offline |
| Temp working database | A temporary ESE database built under `%TMP%` for the duration of the export — Microsoft's docs specifically flag the 110%-of-database-size free-space requirement here; a partially-completed or failed IFM run can leave an oversized temp artifact behind if space ran out mid-operation |
| Live `ntds.dit` metadata | `%SystemRoot%\NTDS\ntds.dit`'s own `LastAccessTime`/`LastWriteTime` — a VSS-based read (via `ifm` or raw `vssadmin`) does **not** normally alter the live file's own timestamps, since the operation reads from the shadow copy, not the live file directly; a file whose metadata *has* changed outside a documented maintenance window is a different, and separately concerning, finding |
| Prefetch | `NTDSUTIL.EXE-<HASH>.pf` — created on first execution (if Prefetch tracing is enabled; verify on server SKUs, which have varied by version/edition). See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record `ntdsutil.exe`'s execution and (for Amcache) compile timestamp — since it's a stock Microsoft binary present on every DC, its mere presence in these artifacts is expected; the **execution timestamp**, not the binary's presence, is the signal. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| DSRM registry-abuse variant (if used) | No new file artifact — this variant is entirely registry/authentication-behavior, covered under Registry below |

## Registry

| Key | Relevance |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` | Holds the directory service's own record of `ntds.dit`'s and the log files' current location — `files info` (a reconnaissance-only submenu command, see `01`) reads this without modifying it |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` | **The persistence-specific artifact.** Default value is `0` or absent; a value of `2` means the DSRM local-administrator account can log on normally at any time, without the DC being booted into DSRM first. This is the durable registry-level tell for the `02 - Hands-On Use Cases.md` DSRM backdoor variant — its mere presence at `2` on a DC that hasn't documented a legitimate reason for it is a strong finding on its own |
| Nothing new under `CurrentControlSet\Services` for the `ifm` extraction itself | Unlike `psexec.py`/`smbexec.py`'s service-creation footprint, a straightforward `ifm` export creates no new service, scheduled task, or persistent registry run-key — its footprint is entirely filesystem + event-log + (optionally) the DSRM key above |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| Security | 4688 (Process Creation) | **The primary target-side signal**, if command-line auditing is enabled — shows `ntdsutil.exe` launching with the full `"ac i ntds" "ifm" "create full <path>"` argument string, and its `ParentProcessName` (the field that separates a legitimate backup job from an interactive shell — see the flowchart cross-link below) |
| Security | 4689 (Process Termination) | End of the `ntdsutil.exe` run |
| Security | 4672 | Special privileges assigned to the logon that ran `ntdsutil` — corroborates the Administrator-equivalence prerequisite from `01` |
| Security | 4624 (Logon Type 3, 10, etc.) | Whatever logon actually got the operator onto the DC (RDP=Type 10, network=Type 3 if via WinRM/WMI) — correlate against the access-vector-specific evidence cross-linked in `03 - Source Evidence.md` |
| Security | 4657 | Registry value modification — **if** SACL auditing is configured on `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, fires when `DsrmAdminLogonBehavior` is set, independent of any process-creation logging gap |
| Security | 4661 | Handle requested for the DSRM/local-admin SAM object, if the `set DSRM password` submenu was used to reset the DSRM account's password |
| System | 8224 / 8226 (VSS) | VSS-related service events tied to shadow-copy creation — generic to any VSS consumer (backup software included), not exclusive to `ntdsutil`; useful only in combination with the process-tree context below |

**Accuracy note on WMI-Activity events:** unlike `Impacket/wmiexec/`, `ntdsutil` does not use WMI as its execution mechanism — no WMI-Activity Operational events (5857/5858/etc.) are generated by this tool itself. If an operator reached the DC *via* `wmiexec.py` to run `ntdsutil` (`02`'s chained-remote-invocation scenario), those WMI-Activity events belong to that access vector, not to `ntdsutil`'s own behavior — see `Impacket/wmiexec/04 - Target Evidence.md` for that event set.

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 1 (Process Create) | `ntdsutil.exe` launching with its full command line, `ParentImage` showing exactly what spawned it (`cmd.exe`/`powershell.exe` under an interactive session, `WmiPrvSE.exe` if chained through wmiexec, `wsmprovhost.exe` for WinRM) — the single richest artifact for both attribution and the backup-window context check |
| 11 (File Create) | `ntds.dit` being written under the operator-chosen `<path>\Active Directory\` — this is exactly the file-creation pattern **MITRE CAR analytic CAR-2019-08-002** is built around: `EventCode=11 TargetFilename="*ntds.dit" Image="*ntdsutil.exe"`. CAR rates this analytic's own coverage of T1003.003 as **"Low"** — it only catches the `ntdsutil.exe`-driven path (missing the raw-VSS bypass from `02`) and only at creation time (missing a subsequently renamed/moved copy) |
| 13 (Registry Value Set) | `DsrmAdminLogonBehavior` being written, if Sysmon's registry-monitoring config includes that key — a stronger, more granular alternative to Security 4657 for the DSRM-persistence variant |
| **Not generated** | No named-pipe (17/18) or DCOM/RPC (3, tied to WMI specifically) events attributable to `ntdsutil` itself — its own operation is entirely local file/VSS/registry activity, not network protocol traffic |

## Volume Shadow Copy Artifacts

`ifm`'s internal VSS use (and the raw `vssadmin create shadow` bypass from `02`) leaves the same general shadow-copy evidence class covered in `Windows/19 - Anti-Forensics and Evidence Destruction.md § Volume Shadow Copy Analysis` and `Windows/23 - Special Services/Domain Controller — Role-Specific Forensics.md` Step 2/7 — not re-derived here. The specific addition this note makes: an **unexpected VSC creation event on a DC outside a documented backup window is frequently the setup step immediately preceding an `ifm` pull or a raw shadow-copy `ntds.dit` copy**, per that note's own Step 7 corroboration list — check `vssadmin list shadows` timing against the `ntdsutil.exe`/`vssadmin.exe` process-creation timestamp as a pair, not independently.

## Network-Layer Evidence

`ntdsutil` itself generates none — it's a local tool with no network component (`01 - Overview.md`). Any network-layer evidence in an `ntdsutil`-involved incident belongs entirely to the **access vector** that got the operator onto the DC (RDP/TCP 3389, WinRM/TCP 5985-5986, or whatever Impacket tool's own protocol — see `03 - Source Evidence.md`'s cross-link table) or to the **exfiltration** of the resulting output if it was staged to a remote UNC share (SMB traffic to that share, covered generically in `Windows/12 - Lateral Movement.md`).

## Endpoint Security Product Signatures

Because `ntdsutil.exe` is a signed, first-party Microsoft binary performing an operation (VSS-backed database export) it's explicitly designed to perform, static/hash-based AV detection **does not apply at all** — this is a textbook Living-off-the-Land binary in the fullest sense. Detection depends entirely on behavioral/EDR heuristics: process-creation context (parent process, account, timing) and, where deployed, an EDR rule specifically modeled on the same process-tree logic as `Windows/23`'s Step 7 flowchart. A modern EDR product with an AD-specific detection package should flag `ntdsutil.exe`/`vssadmin.exe` execution outside a known backup context — the *absence* of such an alert on a host that otherwise shows the filesystem/event-log pattern above is itself worth investigating.

## Memory Forensics

`ntdsutil.exe` runs as an ordinary, non-hidden foreground process for the duration of the export — no injection or hiding technique is inherent to the tool itself. Its process memory can hold the exact command-line arguments (useful if 4688 command-line auditing wasn't enabled) for as long as the process is still running; once it exits, this recovery path closes and the durable evidence is entirely the filesystem/event-log/registry artifacts above. A live-response memory capture that catches `ntdsutil.exe` mid-`ifm`-run is also the only way to observe the transient `%TMP%` working-database file before it's cleaned up.

## Building a Timeline

The tightest, highest-confidence anchor chain is: **[access-vector logon event] → Security 4688/Sysmon 1 (`ntdsutil.exe` process creation, with `ParentImage`) → System VSS creation event / `vssadmin list shadows` entry → Sysmon 11 (`ntds.dit` file create under the chosen `<path>`) → [optional: DsrmAdminLogonBehavior registry write, Security 4657/Sysmon 13, if the persistence variant was also used] → Security 4689 (process termination) → [optional: SMB write to a remote UNC share, if the output was staged for exfil, per `03`'s Evidence at the Exfiltration Destination]**. All of these typically land within seconds to low minutes of each other on an uninterrupted run — full walkthrough of how to weigh and prioritize this chain against the tool's evasion variants lives in `05 - Detection and Hunting.md`.

## Contrast with DCSync

> 🔴 **Why this matters for triage.** If you're investigating a suspected domain-wide credential compromise and the evidence trail is entirely **network/replication-protocol-shaped** (an MS-DRSR request, Security 4662 with the `DS-Replication-Get-Changes`/`-All` rights GUIDs, sourced from a host that isn't a DC) — that's DCSync, not this tool; see `Mimikatz/lsadump (DCSync)/04 - Target Evidence.md` and `Windows/05b - Active Directory & Domain Forensic Artifacts.md § DCSync / Replication Abuse`. If instead the trail is **host-local** — a process on the DC itself, a new file under an operator-chosen path, VSS activity — you're looking at `ntdsutil`/`vssadmin`-driven NTDS.dit theft, this note's subject. `Windows/Threat Landscape and Playbooks/Domain Credential Compromise (DCSync and NTDS.dit Theft) Playbook.md` treats these as the two converging paths to the identical outcome (full domain credential exposure, `krbtgt` included) and gives the shared response sequencing (double krbtgt reset, domain-wide password rotation, DSRM password reset on every DC) once either is confirmed — not re-derived here.
