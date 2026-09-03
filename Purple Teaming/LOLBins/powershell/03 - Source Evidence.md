# LOLBins — powershell.exe / pwsh.exe — Source Evidence

**Framing note, shared with `certutil/` and `ntdsutil/`:** `powershell.exe`/`pwsh.exe` is a native Windows/cross-platform binary that runs **on the target itself** — there is no dedicated "PowerShell operator box" the way there's an Impacket or Sliver attacking host. What follows are the closest equivalents: (1) the **operator's own machine**, if they crafted or tested an encoded command/script locally before delivery; (2) **attacker-controlled infrastructure** hosting a download-cradle payload; (3) the **C2 tasking layer**, where PowerShell was launched by a framework's task queue rather than typed directly; and (4) — a genuine point of difference from `certutil` — the **chained tool's own source evidence**, when PowerShell was invoked as a byproduct of another already-documented lateral-movement or C2 tool in this module rather than run standalone. All of PowerShell's own execution evidence is target-side and covered in full in `04 - Target Evidence.md`.

## Contents
- [Pre-Staging on the Operator's Own Machine](#pre-staging-on-the-operators-own-machine)
- [Attacker-Side Web/Payload-Hosting Infrastructure](#attacker-side-webpayload-hosting-infrastructure)
- [C2 Tasking Layer](#c2-tasking-layer)
- [Chained-Tool Source Evidence](#chained-tool-source-evidence)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Pre-Staging on the Operator's Own Machine

If the operator builds an `-EncodedCommand` payload, tests an obfuscated one-liner, or drafts a download-cradle script on their own Windows workstation before delivery, that activity leaves the **exact same evidence classes documented in `04 - Target Evidence.md`** — because there's no operator-vs-target distinction in the engine's own instrumentation. Concretely:

| Artifact | Notes |
|---|---|
| PSReadLine history (`ConsoleHost_history.txt`) | If the operator interactively built/tested the encoding steps rather than scripting them end-to-end, the plaintext `[Convert]::ToBase64String(...)` construction commands land here, on the **operator's own machine** — arguably higher-value than the target-side artifact, since it can show the *un-encoded* source command the target-side logs only capture post-decode (if logging was even enabled there at all) |
| Event ID 4104 (if the operator's own machine has Script Block Logging enabled — common on red-team/pentest workstations for the operator's own QA purposes) | Same schema as the target-side event documented in `04` |
| Non-Windows operator tooling | If the operator used a non-PowerShell environment (Python, a C2 framework's own encoder, an online Base64 tool) to build the encoded blob rather than PowerShell itself, none of the above applies — the construction step leaves no PowerShell-specific trace at all, only whatever generic shell-history/tool-usage evidence that environment produces |

## Attacker-Side Web/Payload-Hosting Infrastructure

For every download-cradle scenario in `02 - Hands-On Use Cases.md`, the HTTP(S) request lands on infrastructure the operator controls. If that infrastructure is ever recovered (seizure, hosting-provider cooperation, infrastructure reuse tying back to a prior attributed incident):

| Artifact | Where | Notes |
|---|---|---|
| Web server access log | `access.log` (Apache/nginx) or equivalent | The requesting `User-Agent` for `Net.WebClient`/`Invoke-WebRequest` typically reads as a generic .NET/PowerShell UA string (version-dependent — e.g. patterns like `Mozilla/5.0 (Windows NT...) WindowsPowerShell/5.1...` for `Invoke-WebRequest`, or no distinctive UA at all for a raw `WebClient` call unless one is explicitly set) — treat this as a corroborating, not primary, signal since it's easily overridden with a single extra line in the operator's script (`$wc.Headers.Add('User-Agent', ...)`) |
| Requested path/filename | Same log | Correlates against the filename a target-side Sysmon 11/3 event captured independently — see `04` |
| Served payload content | If preserved on recovered infrastructure | The exact script/payload bytes an operator would otherwise only see reconstructed from a target-side 4104 event |

## C2 Tasking Layer

Where `powershell.exe`/`pwsh.exe` was launched via a C2 framework's tasking feature rather than typed by a human directly on the target, the framework's own task/session history **is** the real source-side artifact — and it lives on the C2 server, not on the compromised host:

- **PowerShell Empire specifically** — since PowerShell is one of Empire's own agent languages, the framework's task history captures both the original module/shell-command tasked to the agent *and* the server-rendered stager/module PowerShell source that gets executed target-side. See `Purple Teaming/PowerShell Empire/03 - Source Evidence.md` for what that logging looks like.
- **Sliver / Cobalt Strike / Metasploit-style frameworks tasking a raw PowerShell one-liner** — same principle; see each framework's own `03 - Source Evidence.md` in this module rather than re-deriving generic C2-tasking-log mechanics here.
- If the operator's own C2 server is later recovered (red-team retrospective, or a real intrusion where the infrastructure was seized), this task history is a complete, timestamped record of every PowerShell invocation issued across every compromised host — generally a stronger single source than reconstructing the same picture purely from scattered target-side event logs, especially on estates where 4103/4104 were never enabled.

## Chained-Tool Source Evidence

This is genuinely different from `certutil.exe`'s treatment: PowerShell is disproportionately likely to appear as a **feature of another already-documented tool** rather than run standalone by an operator's own hands. In those cases, the chaining tool's own `03 - Source Evidence.md` is the primary source-side record, not this note:

- **Impacket `wmiexec.py -shell-type powershell`** — the operator's own shell/command history on their attacking Linux/macOS box (bash/zsh history, `/proc/<pid>/cmdline` exposure) is documented in `Purple Teaming/Impacket/wmiexec/03 - Source Evidence.md`; this note's job is only to explain what that tool does to the target once it decides to launch PowerShell.
- **PowerShell Empire agents, Sliver PowerShell-loader modules, Metasploit's `psh_reflection`/`web_delivery`** — same principle; each framework's own folder in this module owns its source-side story.

Rather than re-deriving generic "what does an operator's own shell history look like" content that already exists per-tool elsewhere in `Purple Teaming/`, this note defers to those pages and focuses its own depth on the one thing genuinely unique to PowerShell: the target-side engine instrumentation covered in `04`.

## Timeline Correlation Value

Because there is rarely a dedicated "PowerShell operator machine" to anchor a timeline against (the exception being the pre-staging case above), the correlation direction mirrors `certutil.exe`'s: **target-side evidence (04) is the primary timeline anchor**, and source-side evidence — recovered C2 task history, recovered attacker web-infrastructure logs, or a chained tool's own operator-side record — is what extends that timeline outward once a target-side event (a 4104 script-block entry, a Sysmon 1 process-create with a suspicious command line) establishes the "what happened and when" first.
