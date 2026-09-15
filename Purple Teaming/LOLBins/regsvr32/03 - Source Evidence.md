# LOLBins — regsvr32.exe — Source Evidence

**Framing note, since this differs from the rest of this module:** every other tool folder in `Purple Teaming/` (Impacket, Mimikatz, Sliver, etc.) is launched *from* a dedicated attacker/operator machine, so "Source Evidence" means what's left on that machine. `regsvr32.exe` is a **native Windows binary that always runs on the victim/target host itself** — there is no separate "regsvr32 operator box." The closest equivalents to source-side evidence are: (1) the **attacker-controlled infrastructure** hosting the scriptlet payload that the `/i:` switch pulls from, (2) the **delivery/tasking layer** that issued the regsvr32 command in the first place (a macro, a script, or a C2 framework's task queue), and (3) whatever the operator did on their own machine *before* crafting the scriptlet — most relevantly, creating/generating the `.sct` (scriptlet) file itself, which is human-readable XML. All of `regsvr32.exe`'s own execution evidence is target-side and covered in `04 - Target Evidence.md`.

## Contents
- [Attacker-Side Web/Payload-Hosting Infrastructure](#attacker-side-webpayload-hosting-infrastructure)
- [C2 Tasking Layer](#c2-tasking-layer)
- [Scriptlet Generation on the Operator's Own Machine](#scriptlet-generation-on-the-operators-own-machine)
- [Delivery-Mechanism Artifacts](#delivery-mechanism-artifacts)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Attacker-Side Web/Payload-Hosting Infrastructure

For every Squiblydoo use case in `02 - Hands-On Use Cases.md` where the scriptlet is hosted remotely via HTTP/HTTPS, the request lands on infrastructure the attacker controls (or has compromised for staging purposes). If that infrastructure is ever seized, imaged, or its logs otherwise obtained:

| Artifact | Where | Notes |
|---|---|---|
| Web server access log | `access.log` (Apache/nginx) or equivalent | A request for `payload.sct` (or whatever the scriptlet filename) will show in the server's access log with an `User-Agent` string from `regsvr32.exe` — typically `RegSvcs/2.0` (Windows 7/8/10) or a bare `Windows-Update-Agent/...` variant depending on OS. A burst of requests from the same source IP in a short time window may indicate multiple target hosts pulling the same stager. |
| Requested path/filename | Same log | The exact filename/URI path requested (e.g., `payload.sct`, `stage2.sct`, a random UUID path, etc.) — useful for correlating against what a target's Sysmon log or network IDS recorded independently. |
| TLS certificate / hosting provider metadata | Passive DNS, certificate transparency logs, WHOIS | Standard attacker-infrastructure attribution work, not specific to regsvr32 — relevant here only because regsvr32's request is what generated the log entry being pivoted from. |
| Scriptlet source code (if obtained) | Seized server storage, repository history | The `.sct` file itself is human-readable XML; if the operator hosted the scriptlet on the attacker's own server without obfuscation, a copy of the exact JScript/VBScript code can be recovered and analyzed for attacker-specific tools/C2 identifiers/payload details. |

## C2 Tasking Layer

Where `regsvr32.exe` was invoked via a C2 framework's command-execution feature rather than typed by a human operator directly on the victim console, the C2 framework's own **task/session history is the actual "source" artifact** for this technique — and it lives on the C2 server (or the operator's console talking to it), not on the compromised host:

- **Sliver / Empire / Cobalt Strike / Metasploit-style frameworks:** task history logs the exact command string tasked to the implant, including the full `regsvr32.exe /i:...` invocation and the timestamp it was issued — see this module's own `Sliver/03 - Source Evidence.md` and `PowerShell Empire/03 - Source Evidence.md` for what that logging looks like for each specific framework.
- If the operator has access to the C2 server itself (red-team retrospective, or a real intrusion where the C2 infrastructure was later recovered), this task history is a complete, timestamped record of every regsvr32 command issued across every compromised host — a stronger single source than reconstructing the same picture from scattered target-side event logs.

## Scriptlet Generation on the Operator's Own Machine

If the operator ran scriptlet-generation tools (e.g., msfvenom with a scriptlet format output, an Empire `regsvr32` launcher, or custom Python/PowerShell scripts to build a `.sct` file) on their own Windows staging box rather than pulling pre-built scriptlets from a shared repository, that process leaves several categories of evidence:

| Artifact | Notes |
|---|---|
| PowerShell/cmd history | If the operator used PowerShell or cmd.exe to run a scriptlet-generator tool interactively (e.g., `msfvenom -f vbscript -p windows/meterpreter/reverse_tcp LHOST=...`), the command lives in `(Get-PSReadlineOption).HistorySavePath` or `doskey /history` if available. |
| Prefetch / Amcache / ShimCache for scriptlet-generator tools | Evidence that `msfvenom.exe`, `python.exe`, or other generator tools ran on the staging box — same low-uniqueness caveat as target-side execution evidence; see `Windows/06 - Evidence of Program Execution/` |
| Generated `.sct` intermediate file | If not securely deleted, the scriptlet itself (a human-readable XML file, typically named `*.sct` but sometimes misnamed as `.txt`, `.vbs`, `.xml`, etc.) is recoverable via standard filesystem/deleted-file forensics on the staging box — a strong artifact if the operator didn't explicitly wipe it. |
| Repository clone / downloaded payload pack | If the operator downloaded a pre-built scriptlet pack from a public repository (GitHub, etc.), a local `.git` clone or ZIP extraction left artifacts in `%USERPROFILE%\Downloads\`, `%TEMP%`, or wherever the operator stashed it. |

## Delivery-Mechanism Artifacts

The mechanism that got the regsvr32 command onto the target in the first place — a phishing document's macro, a dropped script, a second LOLBIN stage, an interactive RDP/SSH session — carries its own evidence trail entirely independent of regsvr32 itself. That trail is out of scope for this note (it belongs to whatever delivered it) but is the natural next pivot point; see [`Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md`](<../../../Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md>) for the broader LOLBIN-chaining picture and its own attack-chain framing.

## Timeline Correlation Value

Because there's no dedicated "regsvr32 operator machine" to anchor a timeline against, the correlation value here runs the opposite direction from the rest of this module: **target-side evidence (04) is the primary timeline anchor, and source-side evidence is what extends that timeline outward** — a target-side Sysmon 1 event showing the exact scriptlet URL and timestamp is what lets an investigator go pull the matching access-log entry from attacker infrastructure (if ever recovered) or the matching task-history entry from a C2 server, rather than the usual pattern in this module of an operator-side network connection anchoring the target-side burst. For the rare case where the operator's own staging box is compromised/recovered, scriptlet-generation evidence (a `.sct` file in `%TEMP%`, a recent `msfvenom` invocation in PowerShell history) can confirm that this operator used regsvr32 as a delivery mechanism and narrows down the operator's toolkit and development time window.
