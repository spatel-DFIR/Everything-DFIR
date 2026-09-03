# LOLBins — bitsadmin.exe — Source Evidence

**Framing note, matching this module's `certutil/` entry:** most tool folders in `Purple Teaming/` (Impacket, Mimikatz, Sliver, etc.) are launched *from* a dedicated attacker/operator machine, so "Source Evidence" means what's left on that box. `bitsadmin.exe` is a **native Windows binary that runs on the victim/target host itself** — there is no separate "bitsadmin operator box." The closest equivalents to source-side evidence are: (1) the **attacker-controlled infrastructure** the download/SMB-source techniques pull from, (2) the **delivery/tasking layer** that issued the `bitsadmin` command in the first place (a macro, a script, or a C2 framework's task queue), and (3) whatever the operator did on their own machine *before* delivery to prepare the payload. All of `bitsadmin.exe`'s own execution evidence — including the persistence mechanic that makes this tool distinctive — is target-side and covered in `04 - Target Evidence.md`.

## Contents
- [Attacker-Side Payload-Hosting Infrastructure](#attacker-side-payload-hosting-infrastructure)
- [Internal SMB Staging Infrastructure](#internal-smb-staging-infrastructure)
- [C2 Tasking Layer](#c2-tasking-layer)
- [Pre-Staging on the Operator's Own Machine](#pre-staging-on-the-operators-own-machine)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Attacker-Side Payload-Hosting Infrastructure

For every HTTP/HTTPS-sourced use case in `02 - Hands-On Use Cases.md`, the request lands on infrastructure the attacker controls or has compromised for staging. If that infrastructure is ever recovered (legal process, hosting-provider cooperation, or reused infrastructure a prior incident already attributed):

| Artifact | Where | Notes |
|---|---|---|
| Web server access log | `access.log` (Apache/nginx) or equivalent | BITS's HTTP client doesn't carry a `bitsadmin`-specific User-Agent the way `certutil`'s CryptoAPI fetch does — expect a generic Windows/BITS-stack UA rather than a uniquely fingerprintable one; correlate on request timing and the requested filename instead |
| Requested path/filename | Same log | The exact filename requested (`beacon.exe`, `stage2.exe`, etc.) — useful for correlating against a filename an EDR alert or target-side BITS-Client event captured independently |
| TLS certificate / hosting metadata | Passive DNS, certificate transparency logs, WHOIS | Standard C2/staging-infrastructure attribution work, not specific to `bitsadmin` |

## Internal SMB Staging Infrastructure

Unique to this tool relative to most of this module's download-primitive entries: the SMB-sourced transfer use case pulls from an **internal file share**, not Internet infrastructure. If that share is a compromised host or a deliberately staged share on already-owned infrastructure:

| Artifact | Where | Notes |
|---|---|---|
| SMB server access/audit logging | Security event log (object access auditing) on the share's host, if enabled | File-open events for the staged payload, correlated by source IP/host and timestamp against the target's own BITS-Client log entry |
| File-share ACLs / share enumeration history | The staging host itself | Reveals which accounts/hosts had reachability to pull the payload in the first place — relevant scoping information for an incident that used this variant |

## C2 Tasking Layer

Where `bitsadmin.exe` was invoked via a C2 framework's command-execution feature rather than typed by a human operator directly on the victim console, the C2 framework's own **task/session history is the actual "source" artifact** — and it lives on the C2 server (or the operator's console talking to it), not on the compromised host:

- **Sliver / Empire / Cobalt Strike / Metasploit-style frameworks:** task history logs the exact command string tasked to the implant, including the full `bitsadmin /create`/`/addfile`/`/SetNotifyCmdLine`/`/resume` sequence (or the one-shot `/transfer` form) and the timestamp it was issued — see this module's own `Sliver/03 - Source Evidence.md` and `PowerShell Empire/03 - Source Evidence.md` for what that logging looks like per framework.
- If the operator has access to the C2 server itself, this task history is a complete, timestamped record of every `bitsadmin` command issued across every compromised host — a stronger single source than reconstructing the same picture from scattered target-side event logs, and the only reliable way to recover the **original creation intent** of a persistence job that may not fire its notify command until long after the initial tasking.

## Pre-Staging on the Operator's Own Machine

The one place a genuine "operator box" artifact class exists for this tool: preparing the payload that will eventually be fetched (compiling it, staging it on attacker-controlled web/file infrastructure) happens on the operator's own machine before any `bitsadmin` command is ever issued on the target:

| Artifact | Notes |
|---|---|
| Build/compile artifacts for the staged payload | Out of scope for this note specifically — belongs to whichever payload-generation tool produced it (see that tool's own folder in this module) |
| Upload history to the hosting infrastructure | Web server upload logs, S3/object-storage access logs, or SMB-share write events on the operator's own staging infrastructure, if ever recovered |

## Timeline Correlation Value

Because there's no dedicated "bitsadmin operator machine" to anchor a timeline against, the correlation value runs the same direction as `certutil/03 - Source Evidence.md`: **target-side evidence (04) is the primary timeline anchor, and source-side evidence extends that timeline outward.** This matters more for `bitsadmin` than for most of this module's download-primitive tools, because the persistence use case means the *creation* timestamp (recoverable from a target-side BITS-Client event or the QMGR queue database) can be substantially earlier than the *execution* timestamp (when the notify command actually fires) — a target-side timeline built from `04`'s artifacts is what lets an investigator work backward to the matching C2 task-history entry or attacker-infrastructure log for the job's original creation, potentially days or weeks before the payload actually ran.
