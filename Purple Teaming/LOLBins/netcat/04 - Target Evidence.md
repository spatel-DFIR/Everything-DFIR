# LOLBins — Netcat / Ncat / Socat — Target Evidence

Evidence left on the **target/victim** host — wherever code execution occurred and one of these three tools ran, whether as a reverse-shell payload, a bind-shell listener, a relay hop, or a file-transfer client. Because none of the three has any built-in persistence mechanism (see `01 - Overview.md` — no registry Run key, no scheduled task, nothing beyond the running process itself), **the process itself and what it spawns is the entire evidentiary picture** — there is no `bitsadmin`-style delayed-execution trail or `certutil`-style disk-cache side effect to fall back on.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon (if deployed)](#sysmon-if-deployed)
- [Linux Audit Trail](#linux-audit-trail)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing Abuse from Legitimate Use](#distinguishing-abuse-from-legitimate-use)

---

## Filesystem

| Artifact | Detail |
|---|---|
| The `nc`/`ncat`/`socat` binary itself | No fixed OS-enforced install path for any of the three (unlike Windows-native LOLBins). On Windows, a dropped `nc.exe`/`ncat.exe` can sit anywhere the operator has write access. On Linux, it may already be present via package manager (`socat` and `netcat-openbsd`/`netcat-traditional` are common pre-installed or easily-`apt install`-able packages on many distros) — confirming whether the binary was *already there* versus freshly dropped is a real, meaningful distinction |
| `/tmp/f` (or any operator-chosen path) — the named pipe from the `mkfifo` workaround | A real, recoverable disk artifact: `ls -la /tmp/f` shows a `p` (FIFO) file type. Survives until deleted — an operator who forgets the `rm -f` cleanup at the end of a session leaves this sitting on disk indefinitely |
| Prefetch (Windows) | `NC.EXE-<HASH>.pf` / `NCAT.EXE-<HASH>.pf` / `SOCAT.EXE-<HASH>.pf` updates on every run — see `Windows/06 - Evidence of Program Execution/Prefetch.md`. Low-uniqueness on any host where the binary is legitimately used for troubleshooting, but its mere **presence at all** is itself informative on most enterprise endpoints, where these tools have no legitimate business reason to be installed |
| Amcache / ShimCache (Windows) | Records execution including the full on-disk path — useful for recovering the actual staged location of a renamed/relocated binary even after deletion. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Bash history / shell artifacts (Linux) | Covered from the target's own perspective here rather than the operator's — if the target itself is where an interactive `nc`/`socat` session was typed rather than delivered via a script/C2 task, the same `~/.bash_history` caveats from `03 - Source Evidence.md` apply |
| `-o`/`--output`/`-x`/`--hex-dump` session logs (Ncat) | If the operator used Ncat's own session-logging flags, a plaintext or hex-dumped copy of everything relayed through the session may exist on whichever end specified the flag — genuinely valuable if recovered, since it can capture command output regardless of TLS |

## Registry

**Not applicable in the way it is for `../schtasks/` or `../bitsadmin/`.** None of the three tools write any registry key of their own — no MRU list, no configuration hive, nothing. The only registry-relevant angle is entirely generic and not specific to this tool: if the operator separately established persistence (a Run key, a scheduled task, a service) that *launches* one of these tools on a schedule or at logon, that persistence mechanism's own registry footprint belongs to whichever technique/tool created it — see the relevant sibling folder in this module (`../schtasks/`, `../bitsadmin/`) or `Windows/10 - Persistence Mechanisms/` rather than looking for it here.

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **Security** | **4688** (Process Creation) | Captures the `nc.exe`/`ncat.exe`/`socat.exe` invocation, including the full command line **if command-line auditing is enabled** — without it, 4688 only confirms the binary ran, not with what arguments |
| Security | 4689 | Process termination — limited independent value; confirms the session ended but not what happened during it |
| Security | 5156 (if the Windows Filtering Platform audit policy is enabled) | Logs the actual permitted network connection at the OS-firewall layer — independent of process-creation auditing, and survives even if the process was already terminated by the time an analyst looks |

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| **1 (Process Create)** | Captures the full command line for the `nc.exe`/`ncat.exe`/`socat.exe` invocation itself, **and separately** for whatever shell/program it spawns via `-e`/`--sh-exec`/`EXEC:` — the second event's `ParentImage` field pointing back to the network tool is the core forensic signature this note's hunting guidance is built around |
| **3 (Network Connect)** | **The most direct evidence of the connection itself** — source/destination IP, port, and protocol. **Critically, this event type is disabled by default** in Sysmon (per Microsoft's own current Sysmon documentation: *"The network connection event logs TCP/UDP connections on the machine. It is disabled by default"*) — it must be explicitly enabled in the deployed Sysmon configuration, or this evidence class simply doesn't exist regardless of what happened |
| 10 (ProcessAccess) | Not typically generated by these tools' normal operation — would only appear if a follow-on payload delivered *through* the shell performed credential-access-style process memory reads (e.g., an LSASS dump chained after gaining shell access), which is a separate technique this note doesn't otherwise cover |
| 11 (FileCreate) | Fires for the `mkfifo`-created named pipe if the workaround was used, and for any file written by the download/upload use cases in `02` |
| 17 / 18 (PipeEvent) | **Named pipes on Windows are a different OS object than the POSIX `mkfifo` FIFO used in the Linux workaround** — these events are not expected to fire for the standard netcat/socat use cases in this note; flagged here only to head off a common confusion between the two unrelated "named pipe" concepts |

## Linux Audit Trail

```sh
# auditd, if execve-auditing is configured — the direct equivalent of Sysmon 1
# for this platform
ausearch -x nc -x ncat -x socat -i

# The critical second half of the picture: what the tool itself then spawned
ausearch -k exec_watch -i | grep -B2 -A2 'sh\|bash'
```

Same caveat as the Windows Security 4688 command-line-auditing dependency: `auditd` exec logging is not enabled by default on most distributions and must be explicitly configured (a rule such as `-a always,exit -F arch=b64 -S execve -k exec_watch`) before it captures anything.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `conn.log` | Every TCP/UDP connection regardless of endpoint logging — source/destination IP:port, duration, byte counts. **This is the evidence class that survives even when the host has no process-level auditing or Sysmon deployed at all** — see the Hunting Priority table in `05 - Detection and Hunting.md` |
| Zeek `ssl.log` / JA3-JA3S fingerprinting | Relevant specifically to Ncat's `--ssl` and socat's `OPENSSL` address type — the TLS handshake's client/server fingerprint (JA3/JA3S) can distinguish these tools' TLS stack behavior from a genuine browser or standard web-server TLS stack, though this requires a baseline of known-good JA3/JA3S values for the environment to compare against |
| Firewall/proxy logs | Outbound connections to unfamiliar or newly-seen destinations, especially on non-standard ports (T1571) |
| NetFlow | Volume/duration pattern of the connection — an interactive shell session has a distinctive small-packets, long-duration, bidirectional flow shape quite different from a bulk file transfer or a brief `-zv` scan probe |

## Endpoint Security Product Signatures

Unlike WinRAR (a mainstream, broadly-legitimate utility with essentially no static signature coverage), **`nc.exe`/`ncat.exe`/`socat` binaries are commonly flagged outright by mainstream AV/EDR products as "hacktool," "PUA" (Potentially Unwanted Application), or similarly generic dual-use-tool categories on static file signature alone** — a materially different detection posture from most of this module's other entries, where the binary itself is legitimate/signed and detection has to rely on behavior. This makes simple presence-on-disk a meaningfully stronger signal for these three tools than it is for, say, WinRAR or certutil — but it also means an operator has every incentive to rename the binary, compile it from source under a different name, or avoid touching disk at all (piping a statically-linked binary directly into memory execution, out of scope for this note's disk-based use cases). Static signature detection should be treated as a useful but easily-defeated first layer, not the primary control — see `05`'s Hunting Priority table.

## Memory Forensics

A running `nc`/`ncat`/`socat` process and any shell it spawned are ordinary, non-hidden OS processes — standard process-listing and injection-detection tooling shows nothing structurally unusual about the process itself (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`). The genuinely valuable memory-forensics angle here: **for plaintext sessions (plain `nc`, or `ncat`/`socat` without `--ssl`/`OPENSSL`), the process's own memory space may still contain a legible transcript of commands sent and output received**, recoverable via string-search against a memory image — often the only way to recover the actual content of a session after the fact if network capture wasn't running and no `-o`/`--output` log was written.

## Building a Timeline

The tightest anchor sequence, per session: **Sysmon 1 (network-tool process create, full command line including the `-e`/`--sh-exec`/`EXEC:` payload) → Sysmon 3 (network connect, if enabled) → Sysmon 1 again (the spawned shell/program, `ParentImage` pointing back to the network tool) → [ongoing session activity, no further discrete events unless file creates/registry writes occur through the shell] → Sysmon 5 (process terminate) on session end.** Where Sysmon 3 was **not** enabled (the common default-configuration case), Zeek `conn.log` or firewall/NetFlow data is the only surviving anchor for exactly when the network connection itself existed — cross-reference against the process-creation timestamps rather than relying on either source alone.

## Distinguishing Abuse from Legitimate Use

> 🔴 Given that these binaries are frequently signature-flagged outright (see Endpoint Security Product Signatures above), the presence of `nc`/`ncat`/`socat` on an enterprise endpoint is already a meaningfully stronger starting signal than for a mainstream utility like WinRAR — but a genuine sysadmin troubleshooting session still looks materially different from a shell/relay use case.

| Dimension | Legitimate use | Abuse (this note) |
|---|---|---|
| Duration/pattern | Brief, `-zv`-style connectivity check (connect-and-immediately-close), or a short, planned file transfer with a known start/end | Long-lived, open-ended interactive session; or a listener left running indefinitely awaiting a future connect-back |
| Spawned child process | None — a banner grab or file transfer never invokes `-e`/`--sh-exec`/`EXEC:` | `cmd.exe`, `powershell.exe`, `/bin/sh`, or `/bin/bash` as a **direct child** of the network tool — the core signature this note's hunting priority is built around |
| Destination | A known internal host/service, often the same handful of destinations repeated across routine troubleshooting | A previously-unseen external IP, especially on a non-standard/high port |
| Encryption use | Rare — troubleshooting rarely needs `--ssl`/`OPENSSL` | Common specifically because it defeats plaintext detection — the presence of `--ssl`/`OPENSSL` on an otherwise-unexplained connection is itself worth extra scrutiny |
| Binary provenance | Installed via the OS package manager, present at a standard package-manager-owned path | Dropped to a non-standard path (`C:\Windows\Temp`, `C:\Users\Public`, `/tmp`, `/dev/shm`), possibly renamed |
