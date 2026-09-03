# LOLBins — setspn.exe — Source Evidence

What the operation leaves on the host `setspn.exe` actually ran from. Because `setspn.exe` speaks LDAP directly to a Domain Controller/Global Catalog rather than to a peer "target" host in the SMB/RPC sense every other tool in this folder uses, there is no separate attacker-host/target-host split the way there is for `sc.exe` or `wmic.exe` — the operating host **is** the source, and everything else lands on the DC side, covered in `04 - Target Evidence.md`.

## Contents
- [Binary Presence Itself Is an Artifact](#binary-presence-itself-is-an-artifact)
- [Command-Line and Shell History](#command-line-and-shell-history)
- [Process Artifacts](#process-artifacts)
- [Local Network-Connection State](#local-network-connection-state)
- [Cached Credential and Session Material](#cached-credential-and-session-material)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Binary Presence Itself Is an Artifact

Unlike most of this folder's tools, `setspn.exe` is **not present by default** outside a Domain Controller — see `01 - Overview.md`'s Prerequisites. On any other host, its presence proves one of two things happened: the RSAT **AD DS and AD LDS Tools** Feature-on-Demand (`Rsat.ActiveDirectory.DS-LDS.Tools`) was deliberately installed, or the binary was manually copied in from elsewhere (see `02 - Hands-On Use Cases.md`'s Renamed or Relocated Binary use case). Both are themselves durable artifacts:

- **Capability install state** — `Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory*'` on the live host, or the FoD installation record in `%SystemRoot%\servicing\`/DISM logs, shows whether and when the RSAT AD tooling was added. On a workstation that has no legitimate administrative reason to carry AD DS tooling, this install event alone is worth flagging independent of anything `setspn.exe` was subsequently used for.
- **A copied/relocated binary** retains its Authenticode signature and internal `OriginalFileName` (`setspn.exe`) metadata regardless of what it's renamed to — the same masquerading-detection angle documented for `sc.exe` and `wmic.exe` elsewhere in this folder.

## Command-Line and Shell History

- **PowerShell `PSReadLine` history** (`$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`) — captures the full command line if run from a PowerShell prompt, including the exact SPN string and target account name for `-S`/`-D` writes. This is the single most valuable command-line artifact for reconstructing a Targeted-Kerberoasting injection after the fact, since `04`'s DC-side evidence records *that* the attribute changed but not always the human-readable command that caused it.
- **cmd.exe** has no persistent cross-session history — only the current session's `doskey` buffer, gone once the window closes. `setspn.exe` predates PowerShell and its `option value` syntax (no `=` requirement, unlike `sc.exe`) reads naturally from a raw `cmd.exe` prompt, so operators favoring a minimal footprint often use one.
- **Batch/script files** left on disk — a fleet-wide or forest-wide sweep (`02`'s enumeration use cases) is a natural candidate for a wrapping `.bat`/`.ps1` script rather than repeated interactive typing, especially if the operator is iterating the injection/roast/cleanup triplet against several candidate accounts.
- **C2 framework operator logs** (Cobalt Strike, Sliver, Metasploit, Empire) if `setspn.exe` was invoked through a beacon/agent's `shell`/`execute-assembly`-style command rather than an interactive console — the framework's own operator-side logging (covered per-framework elsewhere in this module) is authoritative in that case.

## Process Artifacts

- **Sysmon Event ID 1 (Process Creation)** for `setspn.exe`, if deployed — the single strongest source-side artifact, capturing the full command line (`-S`/`-D` SPN string and target account name, `-Q` pattern, `-T`/`-F` scope flags), parent process, and hashes of the binary. Survives the fact that the LDAP operation itself leaves comparatively thin evidence on the source host beyond this.
- **Security 4688 (Process Creation)** — the native equivalent, requires "Audit Process Creation" enabled and, separately, "Include command line in process creation events" for full command-line visibility (both non-default).
- **Prefetch/ShimCache/Amcache for `setspn.exe`** — confirms execution and roughly when, but (being a legitimate, if uncommon, administrative utility) has limited standalone investigative value without a correlating command line from Sysmon/4688 — the same caveat already documented for `sc.exe` in [`LOLBins/sc/03 - Source Evidence.md`](<../sc/03 - Source Evidence.md>). On a **non-DC host**, however, even a bare Prefetch/Amcache entry for `setspn.exe` — with no accompanying command line — is itself notably more suspicious than the identical finding on a Domain Controller, precisely because the binary's presence there already required a deliberate RSAT install (see above).

## Local Network-Connection State

- **`Get-NetTCPConnection`/`netstat`** captured during or immediately after a `setspn.exe` run shows an established connection to a Domain Controller on TCP 389/636 (domain-scoped `-L`/`-Q`/`-S`/`-D`/`-X`) or to a Global Catalog on TCP 3268/3269 (`-F` forest-scoped operations) — live-response value only, gone once the connection tears down.
- **DNS cache** (`ipconfig /displaydns`) may retain a recent resolution for the specific DC or GC `setspn.exe` connected to, if a hostname rather than a cached/well-known DC was used.
- No SMB session state is created by `setspn.exe` itself — unlike `sc.exe`'s `net use \\target\IPC$` pattern, `setspn.exe` never touches SMB/RPC; its entire network footprint is LDAP/LDAPS/GC traffic to whatever DC serviced the request.

## Cached Credential and Session Material

- **No `setspn.exe`-specific credential cache exists.** Like `sc.exe` (see [`LOLBins/sc/03 - Source Evidence.md`](<../sc/03 - Source Evidence.md>)), `setspn.exe` writes no local artifact of its own beyond the process-execution evidence above — it rides whatever Kerberos/NTLM session the operator's current logon already holds, and persists nothing new on disk related to that session.
- **LSASS-resident tokens/session keys** for the authenticated session are standard memory-forensics territory — see [`Mimikatz/sekurlsa (Credential Dumping)/`](<../../Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md>), not anything specific to this tool.

## OS-Level Audit Trail

- **Security 4624/4634** on the source host for the operator's own domain logon backing the session `setspn.exe` used — routine logon evidence, not `setspn.exe`-specific, but establishes the identity window the tool's activity falls inside.
- **Security 4648 (Explicit Credential Logon)** — only relevant if the operator explicitly supplied alternate credentials (e.g. via `runas /netonly`) rather than using their own current session, which is the more common case for `setspn.exe` given it has no credential switches of its own to prompt for alternates.
- **PowerShell Script Block Logging (4104)** — if `setspn.exe` was invoked from within a PowerShell script/one-liner and 4104 is enabled (off by default — see [`LOLBins/powershell/01 - Overview.md`](<../powershell/01 - Overview.md>) for the full logging-subsystem posture), the full invoking script text, including any looped injection/roast/cleanup sequence, is captured here.

## Memory-Forensics Angle

- **`setspn.exe`'s own process memory** is transient — the process exits as soon as the LDAP operation completes, and is almost never still resident by the time a memory image is captured.
- **LSASS** on the source host holds whatever token/credential material backed the session — the same LSASS memory-forensics angle documented in [`Mimikatz/sekurlsa (Credential Dumping)/`](<../../Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md>), not unique to this tool.
- **Network connection state captured in a memory image** (Volatility's `netscan`) can recover the TCP 389/636/3268 connection to the DC/GC even after the live connection has since closed, if the image was captured close enough in time.

## Timeline Correlation Value

Source-side evidence for `setspn.exe` is thin for the same structural reason it is for `sc.exe` — the tool issues one or a handful of LDAP calls and holds almost no state of its own. Its real value is **anchoring intent and identity**: a Sysmon 1 / 4688 command line for `setspn.exe` on the source host, correlated against the requesting account in the LDAP-modify evidence on the DC (`04 - Target Evidence.md`), and — for the Targeted-Kerberoasting use case specifically — against a Security 4769 Kerberos ticket request that follows within seconds to minutes, reconstructs the full inject→roast→cleanup sequence even though no single host holds every piece. The tighter the time gap between a source-side `-S` command and the DC-side 4769 that follows it, the stronger the correlation — a wide gap suggests either a coincidental legitimate SPN change or two unrelated events rather than one deliberate attack sequence.
