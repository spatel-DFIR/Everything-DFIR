# AdFind — Source Evidence

AdFind is a lightweight, standalone binary run directly by an operator (interactively at a console, via a batch file, or launched by a C2 implant's "run a command" capability) — there's no service, no session protocol, and no listener to characterize. That keeps this file narrower than a lateral-movement tool's, but the source-side footprint that does exist is consistently present across every real-world invocation and is often the most complete record available, since (per `04 - Target Evidence.md`) the domain controller itself logs almost nothing about a normal LDAP read.

## Contents
- [The Binary Itself](#the-binary-itself)
- [Shell / Console History](#shell--console-history)
- [Process Creation and Command-Line Logging](#process-creation-and-command-line-logging)
- [Local Network-Connection State](#local-network-connection-state)
- [Output Files Left Behind](#output-files-left-behind)
- [Cached Credential Material](#cached-credential-material)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## The Binary Itself

`AdFind.exe` is distributed only as a compiled binary from joeware.net — there is no per-build hash diversity mechanism the tool applies itself (unlike, say, Sliver's per-build implant compilation), so a given release's hash is stable and can be blocklisted, but operators routinely **rename the file** (`ad.exe`, `find.exe`, arbitrary names) specifically to defeat filename/hash-adjacent detections. The PE's internal `OriginalFileName` field still reads `AdFind.exe` regardless of the on-disk filename — verified as the basis for multiple published detection analytics (Elastic's `AdFind Command Activity` rule, Splunk's `Windows AdFind Exe` analytic) that explicitly check `process.pe.original_file_name == "AdFind.exe"` alongside the process image name, precisely because renaming defeats the latter but not the former.

## Shell / Console History

If launched interactively from `cmd.exe` or PowerShell rather than by a batch file or C2 task, the full invocation — including any `-u`/`-up` credentials and the complete filter/`-sc` string — lands in the interactive shell's own history:

| Shell | Artifact |
|---|---|
| PowerShell | `ConsoleHost_history.txt` under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\` — persists across sessions |
| `cmd.exe` | Only in-session command recall (`doskey`/F7 buffer) unless the invocation was itself logged elsewhere — no persistent on-disk history by default |
| Batch file (`.bat`/`.cmd`) | The script file itself, if recovered from disk before deletion, is the single richest artifact — the exact sequence and every filter string in one place (see `02 - Hands-On Use Cases.md`'s chained-workflow example, which is the real shape these scripts take) |

## Process Creation and Command-Line Logging

**This is the strongest and most consistently available source-side signal for AdFind, full stop.** Because there's no separate protocol-level artifact for a plain LDAP read the way there is for, e.g., a named-pipe-based lateral-movement tool, the process creation event carrying the full command line *is* the primary evidence:

| Log | Event ID | Signal |
|---|---|---|
| Sysmon | 1 (Process Create) | Full command line — the LDAP filter or `-sc` shortcut name, base DN, any `-u`/`-up` credential, output redirection target — plus `OriginalFileName` in the event's PE metadata, which survives renaming |
| Security | 4688 (Process Creation) | Same, **only if** "Include command line in process creation events" is enabled — not on by default, verify before relying on it |

Because AdFind's filter strings and `-sc` names are so distinctive (`objectcategory=`, `trustdmp`, `computers_pwdnotreqd`, and dozens more — see `01 - Overview.md`'s switch table), command-line-content matching on Sysmon 1 / Security 4688 is dramatically higher-signal here than for many other tools in this repo, where a generic binary name is the only anchor. See `05 - Detection and Hunting.md` for the exact match patterns published detection analytics use.

## Local Network-Connection State

```
netstat -ano | findstr :389
netstat -ano | findstr :636
netstat -ano | findstr :3268
```

A live or recently-closed outbound TCP connection from the AdFind process (or its parent, if it already exited) to 389/636 (LDAP/LDAPS) or 3268/3269 (GC/GC-SSL) on a domain controller — visible in `netstat` while the process is running, or via the source host's own EDR network telemetry after the fact. Because AdFind sessions are typically short-lived (a single bind, one search, results returned, process exits), catching this live requires either a very tight response window or an EDR product that retains historical connection telemetry.

## Output Files Left Behind

Every realistic AdFind invocation redirects output somewhere — to the console (captured only if the session itself is logged, e.g. by a C2 implant), or to a file:

| Artifact | Notes |
|---|---|
| Redirected `.txt`/`.csv` output files | Filenames are operator-chosen but follow a strong real-world convention (`ad_users.txt`, `ad_computers.txt`, `ad_group.txt`, `ad_trustdmp.txt` — see `02 - Hands-On Use Cases.md`'s chained-workflow example, sourced from published incident reports). Content is plain-text/CSV and trivially fingerprinted once the operator knows AdFind's own attribute-label vocabulary (`sAMAccountName`, `distinguishedName`, etc. as printed labels) |
| The batch script itself, if one was used | Often deleted post-run, but recoverable via the same techniques used for any other dropped/deleted script (`$MFT`/USN journal for filename and deletion timing, file-carving from unallocated space) |

## Cached Credential Material

If `-u`/`-up` was used with an explicit password (rather than the current logon token), that credential exists in the following places on the source host and is worth pulling forward into a broader credential-exposure assessment, not just an AdFind-specific one:

- **Command-line/shell history**, per above — cleartext or the `ENCPWD:` obfuscated form (reversible, not cryptographically strong — see `01 - Overview.md`)
- **Sysmon 1 / Security 4688**, if command-line logging captured the invocation
- No separate credential cache is created by AdFind itself — it doesn't write anything analogous to a `.kirbi` ticket file or a saved credential blob; the password exists only as long as the command line that carried it is retained somewhere

## Memory Forensics

`AdFind.exe` is typically a short-lived process — bind, one search, output, exit — so a live memory capture window is narrow. If captured while running (or from a crash dump / hibernation file that happened to catch it), the process's own command-line arguments (visible via `PEB.ProcessParameters.CommandLine` in a memory analysis tool) are the highest-value recoverable string, followed by any LDAP result data still resident in the process's heap before it exited and released it.

## Timeline Correlation Value

Because AdFind's on-host source footprint is concentrated almost entirely in **one process-creation event carrying a highly distinctive command line**, it correlates cleanly against the target-side evidence in `04 - Target Evidence.md`: a source-host process-creation timestamp for `AdFind.exe`/a renamed equivalent, matched against the network-layer LDAP/GC connection window to a specific domain controller in the same few seconds, is normally enough to pin down exactly which DC was queried and when — even though the DC's own logs (per `04`) rarely record the query content itself. This is the same evidentiary pattern `Seatbelt/03 - Source Evidence.md` and `Impacket/psexec/03 - Source Evidence.md` use — a thin target-side footprint pushed back onto a strong source-side process/command-line anchor — applied here to a tool whose entire operational value is a single fast query rather than a multi-step session.
