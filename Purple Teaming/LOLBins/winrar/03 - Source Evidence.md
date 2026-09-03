# LOLBins — WinRAR — Source Evidence

**Framing note, same caveat as this module's other native-binary entries (`../certutil/`, `../msbuild/`):** WinRAR always runs **on the compromised/target host itself** for the exfil-staging use case this note covers — there is no separate "WinRAR operator machine" the way there is for a network-attack tool like Impacket's `psexec.py`. The closest equivalents to source-side evidence are: (1) the **attacker-controlled destination** the finished archive is ultimately transferred to, (2) the **C2 tasking layer** that issued the archive command in the first place, (3) anything the operator did on their own machine *before* deployment — most relevantly, preparing or testing a portable copy of `Rar.exe`/`WinRAR.exe`, and (4) the delivery mechanism that got code execution on the target in the first place. All of WinRAR's own execution evidence is target-side and covered in `04 - Target Evidence.md`.

## Contents
- [Attacker-Controlled Destination Infrastructure](#attacker-controlled-destination-infrastructure)
- [C2 Tasking Layer](#c2-tasking-layer)
- [Pre-Staging on the Operator's Own Machine](#pre-staging-on-the-operators-own-machine)
- [Delivery-Mechanism Artifacts](#delivery-mechanism-artifacts)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Attacker-Controlled Destination Infrastructure

Whatever channel actually moves the finished `.rar`/`.part*.rar` volumes off the target (cloud storage account, FTP/SFTP server, a C2 server's file-transfer store, a webhook endpoint) is the genuine "source-equivalent" evidence base for this technique — if that infrastructure is ever recovered (legal process, hosting-provider cooperation, or attacker-infrastructure reuse a prior incident already attributed):

| Artifact | Notes |
|---|---|
| Uploaded archive volumes themselves | If recovered intact, confirms exactly what was taken — file listing (if `-p` only, not `-hp`, was used) is readable without the password; contents require the password regardless |
| Upload timestamps / access logs on the receiving infrastructure | Correlates directly against the target-side archive-creation and file-create timestamps in `04 - Target Evidence.md`, tightening the intrusion timeline |
| Filenames used for the uploaded volumes | Whether they match the exact output naming the target-side command line shows, or were renamed again before/during transfer — a rename between creation and receipt is itself worth noting |

## C2 Tasking Layer

Where `Rar.exe`/`WinRAR.exe` was invoked via a C2 framework's command-execution feature rather than typed by a human operator directly on the victim console, the **C2 framework's own task/session history is the real "source" artifact** for this technique — and it lives on the C2 server (or the operator's console talking to it), not on the compromised host:

- **Sliver / Empire / Cobalt Strike / Metasploit-style frameworks:** task history logs the exact command string tasked to the implant — including the archive password, if one was set inline in the command — and the timestamp it was issued. See this module's own `Sliver/03 - Source Evidence.md` and `PowerShell Empire/03 - Source Evidence.md` for how each framework's own logging captures this.
- If the operator has access to the C2 server itself (red-team retrospective, or a real intrusion where the C2 infrastructure was later recovered), this task history is often the **only** place a used `-p`/`-hp` password survives in plaintext outside the brief window the target-side process itself was running — a materially stronger source than trying to recover it from the target after the fact.

## Pre-Staging on the Operator's Own Machine

The one place a genuine "operator box" artifact class exists for this tool: if the operator tests the archive command locally before deploying it, or prepares a portable copy of `Rar.exe`/`WinRAR.exe` to drop onto a target that doesn't already have it installed, that leaves the same general categories of evidence any other locally-run command or staged tool does:

| Artifact | Notes |
|---|---|
| PowerShell/cmd history (`(Get-PSReadlineOption).HistorySavePath`, `doskey /history`) | If the operator ran a test invocation interactively on their own Windows staging box |
| Prefetch / Amcache / ShimCache for `Rar.exe`/`WinRAR.exe` on the staging box | Same low-uniqueness caveat as target-side execution evidence — WinRAR running is common, low-signal on its own; see `Windows/06 - Evidence of Program Execution/` |
| The portable `Rar.exe`/`WinRAR.exe` binary staged for delivery | Its own compile/link timestamp and RARLAB code-signature details are unaffected by being renamed/relocated before deployment — see `04`'s note on Authenticode persistence |
| A locally-created test archive, if not securely deleted | Recoverable via standard filesystem/deleted-file forensics on the staging box — see `Windows/08 - Deleted Items and File Existence.md` |

## Delivery-Mechanism Artifacts

The mechanism that got code execution on the target in the first place — a phishing document's macro, a dropped script, a prior LOLBIN stage, an exploited service — carries its own evidence trail entirely independent of WinRAR itself. That trail is out of scope for this note (it belongs to whatever delivered it) but is the natural next pivot point once the archive-creation command is identified; see [`Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md`](<../../../Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md>) for the broader LOLBIN-chaining picture.

## Timeline Correlation Value

Same asymmetry as this module's other native-binary entries: because there's no dedicated "WinRAR operator machine" to anchor a timeline against, **target-side evidence (04) is the primary anchor, and source-side evidence extends that timeline outward** — a target-side Sysmon 1 event showing the exact archive command (including any inline password) is what lets an investigator go pull the matching upload-log entry from recovered attacker infrastructure, or the matching task-history entry from a C2 server, rather than the usual pattern elsewhere in this module of an operator-side network connection anchoring the target-side burst. The password itself, specifically, is the artifact most likely to exist **only** in this direction — captured once, at the moment of target-side execution or C2 tasking, and nowhere else, since a `-hp`-protected archive gives up nothing to a purely target-side forensic pass after the fact.
