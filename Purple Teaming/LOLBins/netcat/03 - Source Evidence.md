# LOLBins — Netcat / Ncat / Socat — Source Evidence

**Framing note — this note's evidence split differs from most of this module's other entries.** WinRAR, bitsadmin, and most other `LOLBins/` tools run *only* on the compromised/target host — there's no genuine "operator machine" artifact class beyond C2 tasking history. Netcat/ncat/socat are the opposite: **every use case in `02` genuinely runs a process on the attacker-controlled host too** — a listener has to exist somewhere, whether that's the attacker's own box, a pivot host, or rented infrastructure. This file covers whichever host is playing the attacker/listener role in a given scenario, and cross-references `04 - Target Evidence.md` for the victim-host side of the same connection.

## Contents
- [Shell / Command History](#shell--command-history)
- [Local Network-Connection State](#local-network-connection-state)
- [Process Artifacts](#process-artifacts)
- [Package / Binary Installation Artifacts](#package--binary-installation-artifacts)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell / Command History

On the operator's own box (Linux/macOS attacker workstation, or a pivot host reached via a prior stage), the listener/connect command is a normal shell invocation and lands in standard shell history unless explicitly suppressed:

| Artifact | Notes |
|---|---|
| `~/.bash_history` / `~/.zsh_history` | Captures the full `nc`/`ncat`/`socat` command line verbatim, including the destination IP/port and any `-e`/`--sh-exec`/`EXEC:` payload string, **unless** `HISTCONTROL=ignorespace` is set and the operator prefixed the command with a space, `history -c` was run, or the shell's history file was piped to `/dev/null`/unset entirely (`unset HISTFILE`) — all common OPSEC habits worth checking for evidence of, not just the history itself |
| PowerShell `(Get-PSReadlineOption).HistorySavePath` | If the listener side is a Windows box running `nc.exe`/`ncat.exe` from a PowerShell session |
| Terminal scrollback / `script`-recorded sessions | If the operator was running an interactive terminal-recording tool during the engagement (common in red-team engagements for their own audit trail) |

## Local Network-Connection State

The listener/connect process leaves an active or recently-closed socket in local network state for as long as the OS keeps the entry:

```sh
# Linux — currently listening/established sockets, with owning process
ss -tulpn | grep -E 'nc|ncat|socat'
netstat -tulpn | grep -E 'nc|ncat|socat'   # if ss isn't available

# macOS
lsof -i -P | grep -E 'nc|ncat|socat'
```

```powershell
# Windows — same idea for a Windows-based operator/pivot box
Get-NetTCPConnection | Where-Object { (Get-Process -Id $_.OwningProcess).ProcessName -match 'nc|ncat|socat' }
```

This state is volatile — it disappears once the process exits and any OS-level connection-tracking entry ages out, so it's only useful if captured live or via a memory acquisition close to the time of use (see Memory Forensics below).

## Process Artifacts

| Artifact | Notes |
|---|---|
| Process listing (`ps aux` / `Get-Process`) | Shows the live `nc`/`ncat`/`socat` process and its full command line while running — same volatility caveat as network state |
| Prefetch / Amcache / ShimCache (Windows operator box) | If the operator ran a Windows build of any of these three tools locally, standard execution-evidence artifacts apply the same way they would on any Windows host — see `Windows/06 - Evidence of Program Execution/` |
| The binary itself, if a portable/compiled-from-source copy was staged | Its presence, compile timestamp, and (for a Windows PE) any embedded version info are recoverable via standard filesystem forensics on the operator's own staging box |

## Package / Binary Installation Artifacts

Where the operator installed one of these tools from a package manager on their own Linux-based attack platform (rather than compiling from source or using a portable copy), the install itself leaves a standard package-manager trail:

```sh
# Debian/Ubuntu-family
grep -E 'netcat|ncat|socat' /var/log/dpkg.log /var/log/apt/history.log

# RHEL/Fedora-family
grep -E 'netcat|ncat|socat' /var/log/dnf.log /var/log/yum.log
```

Low forensic value against an *attacker's own* box in most engagement models (the operator's tooling choices are usually already known), but directly relevant if the "source" host in a given scenario is itself a previously-compromised pivot host — confirming whether `socat`/`ncat` was already present (living off pre-existing tooling) versus freshly installed/dropped by the intrusion is a meaningful distinction for scoping.

## OS-Level Audit Trail

```sh
# Linux auditd — if process-execution auditing is configured, captures the exec
# event independent of shell history tampering
ausearch -x nc -x ncat -x socat -i

# Alternatively, a generic execve rule already in place:
ausearch -k exec_watch -i | grep -E 'nc|ncat|socat'
```

`auditd`'s exec logging is the operator-side equivalent of the target-side Sysmon/4688 process-creation evidence covered in `04` — and carries the same caveat that it must already be configured/enabled to have captured anything; it isn't on by default on most distributions.

## Memory Forensics

A live or recently-acquired memory image of the operator/pivot host can recover:
- The full command line of a still-running `nc`/`ncat`/`socat` process, independent of whether shell history was cleared
- Session data actively buffered in the process's memory — potentially including plaintext of whatever was relayed through it, if the connection used no encryption (plain `nc`) or if the analysis has access to the TLS session keys (Ncat/socat with `--ssl`/`OPENSSL`)
- Standard process-listing/network-socket-table artifacts recoverable the same way as any other live process — see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md` for the Windows-side equivalent if the operator/pivot box in question is Windows-based

## Timeline Correlation Value

Unlike this module's target-only entries (WinRAR, bitsadmin), **source-side evidence here is a genuine independent timeline anchor, not just an extension of target-side evidence** — a listener's bind/accept timestamp on the attacker side and the corresponding connect-out timestamp on the target side (Sysmon 1/3, covered in `04`) should line up almost exactly, and any meaningful gap between them is itself worth investigating (queued/retried connection, an intermediate pivot hop not yet identified, or clock skew between the two hosts worth correcting for before trusting either timeline). Where a relay/pivot chain (see `02`'s Relay/Pivot Chaining use case) is involved, each hop in the chain has its own source-side process/connection evidence — reconstructing the full path requires walking each hop's local evidence in sequence rather than assuming a single attacker-to-target hop.
