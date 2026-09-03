# LOLBins — certutil.exe — Source Evidence

**Framing note, since this differs from the rest of this module:** every other tool folder in `Purple Teaming/` (Impacket, Mimikatz, Sliver, etc.) is launched *from* a dedicated attacker/operator machine, so "Source Evidence" means what's left on that machine. `certutil.exe` is a **native Windows binary that always runs on the victim/target host itself** — there is no separate "certutil operator box." The closest equivalents to source-side evidence are: (1) the **attacker-controlled infrastructure** hosting the payload the download verbs pull from, (2) the **delivery/tasking layer** that issued the certutil command in the first place (a macro, a script, or a C2 framework's task queue), and (3) whatever the operator did on their own machine *before* delivery — most relevantly, running `-encode` locally to prepare a smuggled payload. All of `certutil.exe`'s own execution evidence is target-side and covered in `04 - Target Evidence.md`.

## Contents
- [Attacker-Side Web/Payload-Hosting Infrastructure](#attacker-side-webpayload-hosting-infrastructure)
- [C2 Tasking Layer](#c2-tasking-layer)
- [Pre-Staging on the Operator's Own Machine](#pre-staging-on-the-operators-own-machine)
- [Delivery-Mechanism Artifacts](#delivery-mechanism-artifacts)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Attacker-Side Web/Payload-Hosting Infrastructure

For every download-verb use case in `02 - Hands-On Use Cases.md`, the request lands on infrastructure the attacker controls (or has compromised for staging purposes). If that infrastructure is ever seized, imaged, or its logs otherwise obtained (e.g. via legal process, a hosting provider's cooperation, or the attacker reusing infrastructure a prior incident already attributed):

| Artifact | Where | Notes |
|---|---|---|
| Web server access log | `access.log` (Apache/nginx) or equivalent | Look specifically for the certutil-characteristic `User-Agent` strings documented in `04 - Target Evidence.md` (`Microsoft-CryptoAPI/10.0`, `CertUtil URL Agent`) — a listing of source IPs making requests with those UAs is effectively a list of every victim host that ran the download verb against this URL |
| Requested path/filename | Same log | The exact filename requested (`beacon.exe`, `update.b64`, etc.) — useful for correlating against the filename an EDR alert or a target-side file-creation event captured independently |
| TLS certificate / hosting provider metadata | Passive DNS, certificate transparency logs, WHOIS | Standard C2/staging-infrastructure attribution work, not specific to certutil — relevant here only because certutil's request is what generated the log entry being pivoted from |

## C2 Tasking Layer

Where `certutil.exe` was invoked via a C2 framework's command-execution feature rather than typed by a human operator directly on the victim console, the C2 framework's own **task/session history is the actual "source" artifact** for this technique — and it lives on the C2 server (or the operator's console talking to it), not on the compromised host:

- **Sliver / Empire / Cobalt Strike / Metasploit-style frameworks:** task history logs the exact command string tasked to the implant, including the full `certutil -urlcache -f ...` invocation and the timestamp it was issued — see this module's own `Sliver/03 - Source Evidence.md` and `PowerShell Empire/03 - Source Evidence.md` for what that logging looks like for each specific framework.
- If the operator has access to the C2 server itself (red-team retrospective, or a real intrusion where the C2 infrastructure was later recovered), this task history is a complete, timestamped record of every certutil command issued across every compromised host — a stronger single source than reconstructing the same picture from scattered target-side event logs.

## Pre-Staging on the Operator's Own Machine

The one place a genuine "operator box" artifact class exists for this tool: if the operator runs `certutil -encode` locally (on Windows) to prepare a smuggled payload before delivery, that invocation leaves the same general categories of evidence any other locally-run command does:

| Artifact | Notes |
|---|---|
| PowerShell/cmd history (`(Get-PSReadlineOption).HistorySavePath`, `doskey /history`) | If the operator ran the encode step interactively on a Windows staging box rather than scripting it |
| Prefetch / Amcache / ShimCache for `certutil.exe` on the staging box | Same low-uniqueness caveat as target-side execution evidence — `certutil.exe` running is common, low-signal on its own; see `Windows/06 - Evidence of Program Execution/` |
| The `.b64`/`.hex` intermediate file itself | If not securely deleted, recoverable via standard filesystem/deleted-file forensics on the staging box — see `Windows/08 - Deleted Items and File Existence.md` |

## Delivery-Mechanism Artifacts

The mechanism that got the certutil command onto the target in the first place — a phishing document's macro, a dropped script, a second LOLBIN stage — carries its own evidence trail entirely independent of certutil itself. That trail is out of scope for this note (it belongs to whatever delivered it) but is the natural next pivot point; see [`Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md`](<../../../Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md>) for the broader LOLBIN-chaining picture and its own attack-chain framing.

## Timeline Correlation Value

Because there's no dedicated "certutil operator machine" to anchor a timeline against, the correlation value here runs the opposite direction from the rest of this module: **target-side evidence (04) is the primary timeline anchor, and source-side evidence is what extends that timeline outward** — a target-side Sysmon 1 event showing the exact download URL and timestamp is what lets an investigator go pull the matching access-log entry from attacker infrastructure (if ever recovered) or the matching task-history entry from a C2 server, rather than the usual pattern in this module of an operator-side network connection anchoring the target-side burst.
