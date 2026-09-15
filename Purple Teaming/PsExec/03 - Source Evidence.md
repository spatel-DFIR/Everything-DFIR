# PsExec (Sysinternals) — Source Evidence

Evidence left on the **operator's own host** — the machine `psexec.exe` was actually run from. Because this tool has no local database, no config file, and no persistent credential cache of its own, the source-side footprint is thinner than a C2 framework's but genuinely distinctive, and one artifact here (`EulaAccepted`) has no equivalent anywhere else in this module.

## Contents
- [The EulaAccepted Registry Value](#the-eulaaccepted-registry-value)
- [The Binary Itself and Its PE Metadata](#the-binary-itself-and-its-pe-metadata)
- [Shell / Console History](#shell--console-history)
- [Process Creation and Command-Line Logging](#process-creation-and-command-line-logging)
- [Local Network-Connection State](#local-network-connection-state)
- [Prefetch, ShimCache, and Amcache on the Source Host](#prefetch-shimcache-and-amcache-on-the-source-host)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## The EulaAccepted Registry Value

**The single most distinctive source-side artifact this tool leaves, and one with no equivalent in Impacket's `psexec.py`** (a pure network client with no local EULA concept at all):

| Key | Value | What it proves |
|---|---|---|
| `HKCU\Software\Sysinternals\PsExec\EulaAccepted` | `1` (DWORD) | PsExec ran **interactively** on **this specific host**, under **this specific user profile**, at least once |
| `HKCU\Software\Sysinternals\EulaAccepted` | `1` (DWORD) | A newer, tool-agnostic global-acceptance key covering the whole Sysinternals suite — check both, since which one gets written depends on how the EULA was accepted |

The EULA prompt only appears on a genuinely first-ever interactive run of `psexec.exe` under that profile, or is written silently when `-accepteula` is passed from a script — **either path writes the key**. Per `01`/`02`, `-accepteula` suppresses the *dialog*, not the registry artifact — it exists specifically to avoid a scripted/unattended run hanging on a click, not to avoid leaving a trace. This is a genuinely strong artifact for one specific question: "did PsExec ever execute on this host, under this profile?" — but two honest caveats apply, the same ones this repo's other pages give similar single-key artifacts: (1) an informed operator can pre-seed or delete the key manually, defeating the timing inference (though not the fact of its presence if they forget), and (2) it says nothing about *which target(s)* were touched or *when* on its own — it needs correlating with the artifacts below.

## The Binary Itself and Its PE Metadata

`psexec.exe` is distributed as an **Authenticode-signed Microsoft binary** inside `PSTools.zip` — a real, checkable provenance signal that has no analog for a from-scratch reimplementation:

| Check | Expected value | Why it matters |
|---|---|---|
| Digital signature | Valid, signed by Microsoft | A `psexec.exe` (or a claimed one) with an invalid, missing, or non-Microsoft signature is not the genuine tool — either a stale/tampered copy or something else entirely masquerading under the name |
| PE `OriginalFileName` (VERSIONINFO) | `psexec.c` — an unusual but source-verified value (Splunk's own published detection query keys on this exact string), reflecting an internal Sysinternals build convention rather than a `.exe` name | Survives an operator renaming their own local copy of `psexec.exe` to evade an image-name allowlist/blocklist on the operator's own host |
| `CompanyName` / `ProductName` | `Sysinternals` / consistent with the PsTools suite | Corroborating metadata alongside the signature check |

`Get-AuthenticodeSignature` (native PowerShell, no extra tooling required) is the fastest live check — see `05 - Detection and Hunting.md`.

## Shell / Console History

| Shell | Artifact |
|---|---|
| PowerShell | `ConsoleHost_history.txt` under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\` — captures the full invocation, including any `-u`/`-p` cleartext password passed inline |
| `cmd.exe` | Only in-session recall (`doskey`/F7 buffer) unless the invocation was itself logged elsewhere (a wrapper batch script, a C2 implant's task-output log) |
| Wrapper batch/PowerShell script, if recovered before deletion | The richest single artifact — the exact target list, credentials, and command in one place (see `02`'s scripted/fleet-wide examples) |

**A real, avoidable exposure worth flagging:** passing `-p` inline puts the password in plaintext on the command line and, if PowerShell was the invoking shell, in `ConsoleHost_history.txt` permanently. Omitting `-p` (prompting instead) avoids both — an operator who does this is making a deliberate OPSEC choice, and its absence from recovered history is itself informative when reconstructing operator tradecraft maturity.

## Process Creation and Command-Line Logging

| Log | Event ID | Signal |
|---|---|---|
| Sysmon | 1 (Process Create) | Full `psexec.exe` command line — target(s), `-u`/`-p` (if inline), `-r`/`-s`/`-c`/`-accepteula` flags — plus the binary's own PE metadata fields, which survive a renamed local copy |
| Security | 4688 (Process Creation) | Same, **only if** "Include command line in process creation events" is enabled (not on by default) |
| Security | 4648 | Explicit-credential logon on the **source** host, if `-u` triggered a distinct local logon context for the outbound connection |

Unlike a bulk-exfil or C2 tool, a single PsExec invocation is typically short-lived on the source side — the process exits (or detaches, with `-d`) once the remote command starts, so the command-line-capture window on the operator's own host is narrow. This makes Sysmon 1 / 4688 retention depth genuinely important here — a delayed investigation may find the target-side evidence in `04 - Target Evidence.md` long after the source-side process-creation record has rolled off.

## Local Network-Connection State

```powershell
Get-NetTCPConnection -RemotePort 445 -State Established
netstat -ano | findstr :445
```

A live or very recent outbound SMB session (TCP 445) to the target host(s), visible while `psexec.exe` is actively running or its named-pipe session is still open. Because a single PsExec session is typically short (authenticate → drop → run → relay → cleanup, often seconds to low minutes for a non-interactive command), this window is narrower than what `Rclone/03 - Source Evidence.md` documents for a bulk transfer — live capture is much more time-sensitive here.

## Prefetch, ShimCache, and Amcache on the Source Host

`psexec.exe` itself executed on the operator's own host, so it leaves the same standard execution-evidence trio any executed binary does — see `Windows/06 - Evidence of Program Execution/Prefetch.md`, `.../ShimCache (AppCompatCache).md`, and `.../Amcache.md` for the general mechanics, cross-linked rather than re-derived. The tool-specific value here: an entry for `PSEXEC.EXE` (or a renamed local copy — check PE metadata per above) on a host with no legitimate reason to run remote-administration tooling is the anomaly signal, mirroring the same logic `Windows/10 - Persistence Mechanisms/Services.md`'s own PsExec subsection already documents for this exact artifact class.

## Memory Forensics

A running `psexec.exe` process holds its full command-line arguments — including any inline `-p` password — in `PEB.ProcessParameters.CommandLine`, recoverable via standard memory-forensics tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`). Because the tool embeds the `PSEXESVC` payload as a resource inside its own PE image (per `01`'s `FindResource(NULL,"PSEXESVC","BINRES")` mechanic), a live memory capture of the `psexec.exe` process itself can, in principle, recover the embedded service-binary resource blob directly from the process's own image section — useful where the target-side dropped copy has already been deleted by cleanup and the source host is still reachable.

## Timeline Correlation Value

Source-side evidence for this tool chains cleanly: `[EulaAccepted registry-write timestamp, if this is a genuinely first run under this profile]` → `[Sysmon 1 / 4688 process creation for psexec.exe, full command line]` → `[outbound TCP 445 connection, held open for the session's duration]` → `[process exit or detach, per -d]`. Because the source-side process lifetime is typically short, this chain is most useful as a **narrow time anchor** to pivot into the far richer target-side record in `04 - Target Evidence.md` — correlate the Sysmon 1 timestamp here against Security 4624 (Type 3 logon) on the target to establish which source host initiated a given PSEXESVC service-install event, exactly the pairing `Windows/12 - Lateral Movement.md`'s own source/destination framing calls for.
