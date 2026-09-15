# ProcDump / comsvcs.dll MiniDump — Source Evidence

## Contents
- [Where "Source" Evidence Actually Lives For This Technique](#where-source-evidence-actually-lives-for-this-technique)
- [ProcDump — Operator-Host Artifacts](#procdump--operator-host-artifacts)
- [comsvcs.dll — Operator-Host Artifacts](#comsvcsdll--operator-host-artifacts)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Where "Source" Evidence Actually Lives For This Technique

Unlike a lateral-movement tool with a clean attacker-host/target-host split, both techniques here are most often run **directly on the host already being victimized** — an operator with local/domain admin has landed on the box and is dumping its own `lsass.exe` in place, not reaching out to a separate target over the network. When that's the case, "source" and "target" evidence collapse onto the same machine, and the source-side story is really: *how did the operator get here in the first place, and where did `procdump.exe` come from if it wasn't already installed?*

When either technique **is** fired remotely (per `02`'s fleet-wide use case), the actual source-side evidence — command history, authenticated session state, tool staging — belongs to whichever delivery vector did the work (`../PsExec/03 - Source Evidence.md`, `../Impacket/wmiexec/03 - Source Evidence.md`, `../LOLBins/wmic/03 - Source Evidence.md`) and is cross-linked rather than re-derived here. This file covers what's specific to ProcDump/`comsvcs.dll` themselves on whichever host actually issued the command.

## ProcDump — Operator-Host Artifacts

- **Download artifact, if staged from the internet directly:** `Procdump.zip` (or the extracted `procdump.exe`/`procdump64.exe`) carries a `Zone.Identifier` Alternate Data Stream (`ZoneId=3`) if pulled via a browser or `Invoke-WebRequest` without `-UseBasicParsing`/explicit stream suppression — the same MOTW pattern documented across this repo (`../LOLBins/certutil/`'s cache-write finding is the adjacent precedent for a tool leaving an unavoidable download-side trace).
- **`EulaAccepted` registry value**, written under `HKCU:\Software\Sysinternals\ProcDump` (or the shared `HKCU:\Software\Sysinternals` key some Sysinternals tools use) on first interactive run or with `-accepteula` — proves ProcDump ran under this profile on this host at least once. Same artifact family as `../PsExec/03 - Source Evidence.md`'s `EulaAccepted` finding.
- **Command-line history** — PowerShell `ConsoleHost_history.txt`, `cmd.exe`'s in-session buffer (not persisted by default), or a C2 framework's own task log, depending on how the operator is interacting with the host at all.
- **Process artifacts** — Prefetch (`PROCDUMP64.EXE-<hash>.pf` or the renamed binary's own equivalent), Amcache/`ShimCache` entries for the binary's first execution, Sysmon 1 if deployed locally.
- **Staged binary metadata** — file-system timestamps ($SI/$FN pairing) on the dropped `procdump.exe`/`procdump64.exe` itself are the same kind of evidence covered in depth in `Windows/` artifact-reference notes; not re-derived here.

## comsvcs.dll — Operator-Host Artifacts

**Structurally thin by design** — there is no tool to stage, download, or install. The only source-side artifacts are the invocation itself:

- **Command-line history** for the `rundll32.exe comsvcs.dll, MiniDump ...` (or ordinal-form) invocation, wherever that history is captured (PowerShell console history, C2 task log).
- **No EULA, no download cache, no Prefetch entry for a "new" binary** — `rundll32.exe` and `comsvcs.dll` are both pre-existing, frequently-executed Windows components; their mere presence in Prefetch/Amcache proves nothing on its own. This is the same evidentiary asymmetry `../LOLBins/00 - LOLBins Overview.md` describes generally for any true LOLBIN: the artifact strength has to come from *what* was invoked and *against what target*, not *that* the launcher ran at all.

## Memory-Forensics Angle

If the operator's own host is later imaged (e.g., a compromised internal pivot box, not just the ultimate victim), a live or hibernated memory capture may still hold the in-progress `.dmp` file buffer, the resolved LSASS PID lookup command's process memory, or — if a C2 agent staged the dump before exfil — the agent's own in-memory task/result buffer naming the file path and target host. This is a secondary, opportunistic lead, not a primary hunting signal — treat it as corroboration if a memory capture already exists for other reasons.

## Timeline Correlation Value

The strongest timeline anchor from source-side evidence is the **`EulaAccepted` registry write for ProcDump** (or, absent that, the earliest command-line/Prefetch evidence of `procdump.exe` execution) — it establishes a lower bound for when the operator's tooling first became capable of running this technique on a given host, which correlates against the target-side `.dmp` file creation timestamp (`04`) to confirm the dump happened on this same visit rather than being staged for later use. For `comsvcs.dll`, since there's no equivalent install-time marker, the command-line/task-log timestamp itself is the only timeline anchor available — correlate it directly against the `04` target-side `dbghelp.dll` image-load and `.dmp` file-creation timestamps instead.
