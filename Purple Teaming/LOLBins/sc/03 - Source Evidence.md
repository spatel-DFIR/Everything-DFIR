# LOLBins — sc.exe — Source Evidence

What the operation leaves on the **attacking/source** host — most relevant to the remote-creation/lateral-movement and fleet-wide use cases in `02 - Hands-On Use Cases.md`, where a genuine source↔target pair exists. Because `sc.exe` carries no credential material of its own (see `01 - Overview.md`'s red-flag callout), the most valuable source-side evidence usually belongs to the **session-establishment step that precedes it** (`net use`, an existing token, `runas`), not to `sc.exe`'s own command line.

## Contents
- [Command-Line and Shell History](#command-line-and-shell-history)
- [Process Artifacts](#process-artifacts)
- [Local Network-Connection State](#local-network-connection-state)
- [Cached Credential and Session Material](#cached-credential-and-session-material)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Command-Line and Shell History

- **PowerShell `PSReadLine` history** (`$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`) — captures the full `sc.exe`/`sc \\target` command line if the operator worked from a PowerShell prompt, including the `binpath=`/`sdset` SDDL argument in full. Also captures any preceding `net use \\target\IPC$ /user:...` line — the piece that carries the actual credential.
- **cmd.exe** has no persistent cross-session history of its own — only the current session's `doskey`-buffered history, gone once the window closes. An operator running from a raw `cmd.exe` (as most `sc.exe` scripting favors, since `sc.exe` predates PowerShell) leaves nothing here after the session ends.
- **Batch/script files** left on disk — `sc.exe`'s awkward `option= value` syntax (mandatory trailing space) makes it a common candidate for wrapping in a `.bat`/`.cmd`/`.ps1` script rather than typing interactively, especially for the fleet-wide use case. Any such script is itself a durable, recoverable artifact with its own MACB timestamps.
- **Command history embedded in a C2 framework's operator log** (Cobalt Strike, Sliver, Metasploit, Empire) if `sc.exe` was invoked through a beacon/agent rather than an interactive shell — the framework's own operator-side logging (already covered per-framework elsewhere in this module) is the authoritative record in that case, not anything native to Windows.

## Process Artifacts

- **Sysmon Event ID 1 (Process Creation)** for `sc.exe` itself, if Sysmon is deployed on the source host — captures the full command line (including `binpath=`, `obj=`, the `sdset` SDDL string), parent process, and hashes of the `sc.exe` binary. This is the single strongest source-side artifact when present, since it survives the RPC call itself leaving no local trace of what happened on the far end.
- **Security 4688 (Process Creation)** — the native equivalent, requires "Audit Process Creation" enabled and, for full command-line visibility, the separate "Include command line in process creation events" policy (both non-default).
- **Prefetch/ShimCache/Amcache for `sc.exe`** — confirms `sc.exe` executed on the source host and roughly when, but (being the built-in, constantly-legitimately-used system utility) has essentially zero standalone investigative value without a correlating command line from Sysmon/4688. A `sc.exe` Prefetch entry alone proves nothing suspicious on its own.
- **Renamed-binary artifacts** (see `02 - Hands-On Use Cases.md`'s Renamed or Relocated Binary use case) — a copy of `sc.exe` under a different filename retains its Authenticode signature and internal `OriginalFileName` (`sc.exe`) metadata; a source-side sweep for processes whose signed identity doesn't match their on-disk filename catches this the same way `LOLBins/wmic/05 - Detection and Hunting.md` and `LOLBins/schtasks/05 - Detection and Hunting.md` do for their own binaries.

## Local Network-Connection State

- **`Get-NetTCPConnection`/`netstat`** captured during or immediately after a remote `sc \\target` operation shows an established TCP 445 (SMB/`\PIPE\svcctl`) or TCP 135 + dynamic-high-port (RPC/TCP) connection to the target — live-response value only, this state is gone once the connection tears down and isn't retained anywhere by default.
- **DNS cache** (`ipconfig /displaydns`) may retain a recent resolution for the target hostname if `sc.exe` was invoked with a name rather than a bare IP.
- **SMB client-side session cache** (`net use` with no arguments, or `Get-SmbConnection`) shows any still-open `\\target\IPC$`/`\\target\ADMIN$`/`\\target\C$` session the operator established to authenticate before running `sc \\target` — this is the artifact that actually proves *how* the operator authenticated, since `sc.exe`'s own command line never will (per `01 - Overview.md`'s red-flag callout).

## Cached Credential and Session Material

- **Credential Manager** (`cmdkey /list`) — if the operator used `net use \\target\IPC$ /user:... /savecred` or `runas /savecred`, the credential persists in Windows Credential Manager on the source host until explicitly deleted, recoverable by anyone with access to that user profile.
- **LSASS-resident tokens/session keys** for the authenticated session — standard memory-forensics territory (see below), not something `sc.exe` itself adds anything unique to.
- **No `sc.exe`-specific credential cache exists** — unlike, say, `bitsadmin`'s QMGR queue database or `certutil`'s `CryptnetUrlCache` side-effect (both covered in their own `LOLBins/` notes), `sc.exe` writes no local artifact of its own beyond the process-execution evidence above. Its evidentiary footprint on the source host is entirely the surrounding session/process context, not anything the tool itself persists.

## OS-Level Audit Trail

- **Security 4648 (Explicit Credential Logon)** — fires on the source host when `net use \\target\IPC$ /user:...` (or `runas /user:...`) is used with explicit alternate credentials rather than the current token; captures the target server name and the account name used. This is the closest source-side equivalent to a "credential submitted for this operation" event, and it belongs to the session-establishment step, not to `sc.exe` itself.
- **Security 4624/4625** on the source host are target-side-oriented for an inbound connection, but a source host can also show 4624 Logon Type 3 entries for its **own** prior authentication to file shares if `sc.exe`'s operator used a domain-cached session.
- **PowerShell Script Block Logging (4104)** — if `sc.exe` was invoked from within a PowerShell script or one-liner rather than a raw `.exe` call, and 4104 is enabled (off by default — see [`LOLBins/powershell/01 - Overview.md`](<../powershell/01 - Overview.md>) for the full logging-subsystem posture), the full invoking script text is captured here on the source host.

## Memory-Forensics Angle

- **RPC/DCE client state in `sc.exe`'s own process memory** is transient — the process typically exits immediately after the command completes, and by the time a memory image is captured `sc.exe` itself is almost never still resident.
- **LSASS** on the source host holds whatever token/credential material backed the session `sc.exe` rode on (current-user token, or the explicit credentials from `net use`) — the same LSASS memory-forensics angle documented in depth in [`Mimikatz/sekurlsa (Credential Dumping)/`](<../../Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md>), not anything specific to `sc.exe`.
- **Network connection state captured in a memory image** (via Volatility's `netscan`) can recover the TCP 445/135 connection to the target even after the live connection has since closed, if the image was captured close enough in time.

## Timeline Correlation Value

Source-side evidence for `sc.exe` is thin by design — the tool does one thing (issue an SCM RPC call) and holds almost no state of its own. Its real timeline value comes from **anchoring the moment of intent** against richer target-side evidence: a Sysmon 1 / 4688 process-creation timestamp for `sc.exe` on the source host, paired with a 4648 explicit-credential-logon a moment earlier (proving *how* the operator authenticated) and the target's own 7045/4697/4624 chain (see `04 - Target Evidence.md`), reconstructs the full attacker-intent-to-target-effect sequence even though no single host holds every piece. This thin-source/rich-target evidentiary shape is the mirror image of, say, `bitsadmin`'s SetNotifyCmdLine persistence (documented in [`LOLBins/bitsadmin/`](<../bitsadmin/01 - Overview.md>)), where the source-side QMGR queue database is the strongest artifact — for `sc.exe`, the target almost always carries the weight.
