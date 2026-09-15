# AnyDesk — Source Evidence

## A necessary reframe before the artifact list

Every other Source Evidence file in this repo assumes a meaningful split: an attacker-controlled host running the offensive tool (a Cobalt Strike Team Server, an Impacket script, a Metasploit console) versus a victim host receiving the effect. **That split doesn't hold cleanly for AnyDesk**, and forcing it would misrepresent how this tool is actually used and investigated:

- AnyDesk has **no operator-controlled server component** (`01 - Overview.md`) — there is no Team Server to seize, no Beacon-log directory unique to the attacker's side. Every party in a session, operator and victim alike, is running the identical off-the-shelf client talking to the same vendor-operated relay.
- In the dominant real-world pattern (per `01 - Overview.md`'s CISA-sourced use cases), the tool is **installed and run on the target/victim host** — the "source" of the intrusion, in the sense every other page in this module means it, barely exists as a distinct artifact-bearing machine. The operator's own device is typically their personal workstation or an unrelated prior victim used as a jump box — almost never something a DFIR engagement gets to image, unlike a seized C2 server in a law-enforcement takedown.
- **A specific, verified artifact asymmetry makes this concrete rather than hand-wavy:** `connection_trace.txt` entries are explicitly written and labeled as **`Incoming <date>, <time> [<Username>]`** — confirmed independently across two forensic write-ups (Hats Off Security's analysis and inversecos's log-format breakdown). This file is **inbound-only by design**. An operator's own machine, initiating outbound session after outbound session against different victim IDs, would show **little or nothing in its own `connection_trace.txt`** for any of that activity — the file only populates on whichever side received the connection request. The richest lead about "who connected in" therefore lives on the target, not the source.

**What this file actually does, given that:** it names what "source evidence" means for this specific tool, points at the one place a target-side analyst can pull source-attributable information without ever touching an attacker-controlled host, and covers the artifact set for the rarer case where an operator-side machine (a jump box, a seized device) genuinely is recovered — which turns out to be functionally the **same catalog as `04 - Target Evidence.md`**, not a distinct one.

## Contents
- [What "Source" Means Here](#what-source-means-here)
- [The Best Available Source-Attribution Lead: the Target's Own Trace Files](#the-best-available-source-attribution-lead-the-targets-own-trace-files)
- [If an Operator-Side Host Is Recovered](#if-an-operator-side-host-is-recovered)
- [The Address Book — a Genuinely Source-Side-Only Artifact](#the-address-book--a-genuinely-source-side-only-artifact)
- [Shell/Command History](#shellcommand-history)
- [Network State](#network-state)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## What "Source" Means Here

Three distinct things could be "the source" depending on the scenario, and they carry very different evidentiary value:

1. **The operator's personal/attack workstation** — almost never recoverable in a normal DFIR engagement scoped to the victim organization's own environment.
2. **A prior-compromised host used as an operator jump box** — recoverable if it's inside scope (e.g. a fleet-wide incident where one already-owned host is also the one from which AnyDesk sessions to *other* internal hosts originated). This is the realistic "source" case for this tool.
3. **The target's own AnyDesk client, in the rarer reverse-direction scam pattern** — where the *victim* initiates the outbound connection to the operator's ID (the tech-support-scam flow in `02 - Hands-On Use Cases.md`). Here the victim machine is simultaneously the only "source" artifact host that will ever be in scope, and its own evidence is already fully covered in `04 - Target Evidence.md` since it's the host under investigation either way.

## The Best Available Source-Attribution Lead: the Target's Own Trace Files

Given the above, the single most productive "source evidence" move for this tool is usually **not** hunting for a source host at all — it's extracting everything the *target's own* `connection_trace.txt` and `ad.trace` already recorded about the inbound connection:

- `connection_trace.txt`'s `Incoming` entries record the connecting party's identity as presented (username field) and the authentication method used (`User`/`Passwd`/`Token` — `04 - Target Evidence.md`).
- `ad.trace` is materially richer and, per independent forensic analysis (inversecos), includes an `External address` field carrying an actual **source IP** for the connecting session — the closest thing to attacker-infrastructure attribution this tool structurally offers without ever touching a second host.
- Neither file is unique to "source evidence" as a section — both are catalogued in full in `04 - Target Evidence.md` — the point here is that this is where source-side context actually comes from in the overwhelming majority of real investigations of this tool.

## If an Operator-Side Host Is Recovered

Where a jump-box or seized operator device genuinely is in scope, it carries **the identical artifact catalog as `04 - Target Evidence.md`** — `ad.trace`, `connection_trace.txt` (now populated only for sessions where *this* machine was the receiving end, per the asymmetry above), `file_transfer_trace.txt`, thumbnails, registry/service artifacts if installed rather than portable — cross-reference that file rather than re-deriving the same table twice. The one thing worth flagging distinctly: on this machine, the outbound connections it initiated to *other* IDs will **not** appear in its own `connection_trace.txt` at all (inbound-only), so an analyst working purely from that file alone would undercount this host's actual role — `ad.trace`'s broader session logging and the operator's own on-screen session history are the correctives.

## The Address Book — a Genuinely Source-Side-Only Artifact

The one artifact type that's meaningfully **source-side by nature**, not a relabeled copy of target evidence: AnyDesk's **Address Book** feature (an operator's saved list of frequently-used contacts/IDs, syncable across the operator's own devices via `my.anydesk`). If recovered from a genuine operator device, an Address Book is potentially the single highest-value artifact in this whole note — it's a list of **every ID the operator has saved across every engagement**, not just the one under investigation. There's no locally-documented file path for this from AnyDesk's own docs (it's primarily account-synced, not purely local-file-based) — flagged here as an open question rather than asserted with a specific path.

## Shell/Command History

Where an operator scripted their own connection via the CLI (`02 - Hands-On Use Cases.md`) rather than clicking through the GUI, PowerShell/cmd history on a recovered operator-side host captures the exact invocation — including, per `01 - Overview.md`'s caveat, the Unattended Access password passed to `--with-password`/`--set-password` in full, since it's piped via `echo` rather than masked:

```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath | Select-String 'AnyDesk|--with-password|--set-password'
```

## Network State

An operator-side host's own outbound connection state to `*.net.anydesk.com` on TCP 80/443/6568 looks structurally identical to the same connection state on a target host (`04 - Target Evidence.md`'s Network-Layer Evidence section) — there is no source-specific network signature distinguishing "the connecting party" from "the connected-to party" at this layer; direction has to come from the trace-file content itself (above), not the connection metadata.

## Memory Forensics

No unique server-side memory model exists for this tool the way it does for a C2 framework's Team Server (`Cobalt Strike/03 - Source Evidence.md`) — an operator-side AnyDesk client's live memory holds the same category of session-state data (current session token, screen-buffer content, any file actively mid-transfer) that a target-side client's memory would, covered in `04 - Target Evidence.md`'s Memory Forensics section rather than duplicated here.

## Timeline Correlation Value

Because the richest source-attributable data usually comes from the **target's own** trace files (above) rather than a recovered source host, timeline-building for this tool is effectively **already centered on `04 - Target Evidence.md`** — build the timeline there, and treat any genuinely recovered operator-side artifact as a confirming cross-reference (matching session-start timestamps, matching the connecting IP in `ad.trace`'s `External address` field) rather than the primary spine of the timeline the way a Team Server's `events.log` is for Cobalt Strike.
