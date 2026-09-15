# LOLBins — msbuild.exe — Source Evidence

**Framing note, matching `../certutil/` and `../ntdsutil/`:** every other tool folder in `Purple Teaming/` (Impacket, Mimikatz, Sliver, etc.) is launched *from* a dedicated attacker/operator machine, so "Source Evidence" means what's left on that machine. `msbuild.exe` is a **native Windows/.NET Framework binary that always runs on the victim/target host itself** — there is no separate "MSBuild operator box" the way there is a Sliver C2 console. The closest equivalents to source-side evidence are: (1) the **project-file authoring/testing environment**, if the operator built and test-ran the malicious `.csproj`/`.xml` on their own machine before delivery, (2) the **C2/tasking layer** that issued the `msbuild.exe` command in the first place, and (3) **attacker-controlled infrastructure**, only relevant if the project file was staged via a network-fetching LOLBIN like `certutil.exe` first. All of `msbuild.exe`'s own execution evidence is target-side and covered in `04 - Target Evidence.md`.

## Contents
- [Project-File Authoring and Local Testing](#project-file-authoring-and-local-testing)
- [C2 Tasking Layer](#c2-tasking-layer)
- [Attacker-Side Staging Infrastructure](#attacker-side-staging-infrastructure)
- [Delivery-Mechanism Artifacts](#delivery-mechanism-artifacts)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Project-File Authoring and Local Testing

Unlike `certutil.exe`'s abuse (which requires no local preparation beyond having a payload file ready), a working MSBuild inline-task project file benefits from local test-compilation before deployment — inline C#/VB that fails to compile on the target simply fails the build silently-ish rather than executing. If the operator authored and test-ran the project file on their own Windows machine first:

| Artifact | Notes |
|---|---|
| The `.csproj`/`.xml`/`.proj`/`.rsp` file itself | If not securely deleted from the authoring machine, recoverable via standard filesystem/deleted-file forensics — see `Windows/08 - Deleted Items and File Existence.md` |
| `%LOCALAPPDATA%\Temp\MSBuildTemp\<GUID>` on the authoring machine | The same transient compile-temp-file mechanism documented in `04 - Target Evidence.md` applies equally here during local test runs — normally deleted, recoverable only if `MSBUILDLOGCODETASKFACTORYOUTPUT=1` was set during testing or via deleted-file recovery before the temp file was overwritten |
| Prefetch / Amcache / ShimCache for `msbuild.exe` on the authoring machine | Same low-uniqueness caveat as target-side execution evidence — `msbuild.exe` running is extremely common on any developer machine, low-signal on its own; see `Windows/06 - Evidence of Program Execution/` |
| PowerShell/cmd history | If the operator invoked `msbuild.exe` interactively while iterating on the payload rather than scripting it end-to-end |
| Source-control history | If the operator drafted the malicious project file inside a git repo (a real, observed pattern — a plausible-looking `.csproj` committed to a repo, later exfiltrated or reused directly against a target), commit history/reflog on the authoring machine or a compromised repository is a recoverable trail |

## C2 Tasking Layer

Where `msbuild.exe` was invoked via a C2 framework's command-execution feature rather than typed by a human operator directly on the victim console — the realistic path for the fleet-wide use case in `02 - Hands-On Use Cases.md` — the C2 framework's own **task/session history is the actual "source" artifact**, and it lives on the C2 server (or the operator's console talking to it), not on the compromised host:

- **Empire** specifically ships built-in modules for MSBuild-based execution, per MITRE ATT&CK's own T1127.001 procedure-example list — see `../../PowerShell Empire/03 - Source Evidence.md` for what that framework's task-history logging captures.
- **Sliver / Cobalt Strike / Metasploit-style frameworks** tasking a raw `msbuild.exe <project>` shell command log the full command string and issue timestamp the same way they would for any other shell-out — see this module's `../../Sliver/03 - Source Evidence.md` for the general pattern.
- If the operator has access to the C2 server itself (red-team retrospective, or a real intrusion where the C2 infrastructure was later recovered), this task history is a complete, timestamped record of every MSBuild invocation issued across every compromised host.

## Attacker-Side Staging Infrastructure

Only relevant where the project file was fetched from attacker-controlled infrastructure rather than delivered by some other vector (phishing attachment, dropped by another implant already on-host) — see `02`'s "Staged Delivery via certutil" scenario. In that case, the source-side evidence is identical in kind to what `../certutil/03 - Source Evidence.md`'s "Attacker-Side Web/Payload-Hosting Infrastructure" section already documents (web server access logs, the certutil-characteristic User-Agent strings, TLS/hosting-provider attribution) — not re-derived here since it belongs entirely to the delivery LOLBIN, not to MSBuild itself.

## Delivery-Mechanism Artifacts

The mechanism that got the project file and the `msbuild.exe` invocation onto the target in the first place — a phishing macro, a dropped script, another LOLBIN stage — carries its own evidence trail independent of MSBuild itself. That trail is out of scope for this note (it belongs to whatever delivered it) but is the natural next pivot point; see [`Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md`](<../../../Windows/Threat Landscape and Playbooks/LOLBIN Abuse Hunting Playbook.md>) for the broader LOLBIN-chaining picture.

## Timeline Correlation Value

As with `../certutil/` and `../ntdsutil/`, there's no dedicated "MSBuild operator machine" to anchor a timeline against by default, so target-side evidence (`04`) is the primary anchor and source-side evidence extends that timeline outward — a target-side Sysmon 1 event showing the exact project-file path and timestamp is what lets an investigator pivot to the matching C2 task-history entry (if the C2 server is ever recovered) or the matching delivery-mechanism artifact. The one exception to this module's usual pattern: if the operator's own authoring/testing machine is ever recovered or imaged, the project file's **compile-tested, working form** on that machine — potentially including comments, variable names, or an earlier draft with a different callback address — can be a materially richer artifact than anything recoverable from the target alone, since the target-side project file is typically deleted or never logged in full by default (see `04`'s discussion of why the project file's own content is the technique's richest, and most perishable, evidence).
