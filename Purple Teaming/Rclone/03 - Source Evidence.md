# Rclone — Source Evidence

Rclone runs **from** the compromised host **to** an external cloud endpoint — there's no service, no session protocol on the victim's own network, and (per `04 - Target Evidence.md`) the "target" in the usual sense of this repo's template barely exists for this tool. That makes the **source host** where almost all of the durable, tool-specific evidence lives: the binary itself, its config file, and the process/network activity it generates while running.

## Contents
- [The Binary Itself](#the-binary-itself)
- [The Config File Artifact](#the-config-file-artifact)
- [Shell / Console History](#shell--console-history)
- [Process Creation and Command-Line Logging](#process-creation-and-command-line-logging)
- [Local Network-Connection State](#local-network-connection-state)
- [Log Files Left Behind](#log-files-left-behind)
- [Cached Credential Material](#cached-credential-material)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## The Binary Itself

`rclone.exe` (or `rclone` on Linux/macOS) is distributed as a compiled Go binary from the project's own [GitHub Releases](https://github.com/rclone/rclone/releases) — a stable hash for a given release, but **renaming is the documented norm in real intrusions, not the exception**: `svchost.exe` (The DFIR Report's 2021 Sodinokibi/REvil case), `sihosts.exe` (Red Canary), and `TrendFileSecurityCheck.exe` are all separately, independently documented examples. What doesn't change with the filename is the **PE metadata the Go build embeds** — `OriginalFileName: rclone.exe`, a product description of "Rsync for cloud storage," and a company/URL field referencing rclone.org. This is precisely the field Elastic's and Splunk's own published detection rules (see `05 - Detection and Hunting.md`) check specifically because renaming defeats the image-name match but not this one. A mismatch between the on-disk filename and the PE's own `OriginalFileName`/description fields is, by itself, close to a smoking gun for this tool.

## The Config File Artifact

If the operator used a saved remote (the common case — the connection-string/no-config-file evasion in `02 - Hands-On Use Cases.md` is real but adds command-line exposure in exchange), an `rclone.conf` file exists at a predictable, OS-specific default path unless `--config` overrode it:

| OS | Default path |
|---|---|
| Windows | `%APPDATA%\rclone\rclone.conf` |
| Linux / macOS | `$XDG_CONFIG_HOME/rclone/rclone.conf`, or `~/.config/rclone/rclone.conf` if unset (legacy: `~/.rclone.conf`) |

Its content is directly readable in almost every real case: `[remote-name]` sections, a `type =` line naming the backend, and per-backend credential fields. Per `01 - Overview.md`'s finding, any password stored via `--obscure` is **reversible by any copy of rclone** (fixed hardcoded AES-256-CTR key) — treat a recovered obscured password as equivalent to plaintext, not as a mitigated exposure. The one real protection is full-file encryption via `RCLONE_CONFIG_PASS`/`rclone config`'s password feature — if present, the raw file is unreadable without that password, which itself may be recoverable from the artifacts below.

**Naming pattern to watch for:** in the documented Sodinokibi/REvil case, the config file was named to match the renamed binary (`svchost.conf` alongside `svchost.exe`) — a real, source-verified example of an operator keeping the binary/config pair visually consistent, though this repo found no verified case of the **remote name itself** (the `[section]` label) being deliberately chosen to impersonate a specific legitimate brand/service — that's a logical, available option (remote names are entirely operator-chosen free text) but not something this note can cite a confirmed named incident for. Flagging honestly rather than asserting it as documented.

## Shell / Console History

| Shell | Artifact |
|---|---|
| PowerShell | `ConsoleHost_history.txt` under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\` — captures the full invocation including any inline credentials or an `RCLONE_CONFIG_PASS` assignment on the same line |
| `cmd.exe` | Only in-session recall (`doskey`/F7 buffer) unless the invocation was itself logged elsewhere |
| Batch/PowerShell wrapper script | If recovered from disk before deletion, the richest single artifact — the exact source path, destination remote, and every flag in one place (see `02`'s scheduled-exfiltration example) |

## Process Creation and Command-Line Logging

**The strongest and most consistently available source-side signal, matching the pattern this repo's `AdFind/` page documents for a similarly thin-target tool.**

| Log | Event ID | Signal |
|---|---|---|
| Sysmon | 1 (Process Create) | Full command line — source path, `remote:path` destination string, any inline credential (connection-string evasion), `--bwlimit`/`--include`/`--exclude` scoping — plus `OriginalFileName`/`Description` in the event's PE metadata fields, which survive renaming |
| Security | 4688 (Process Creation) | Same, **only if** "Include command line in process creation events" is enabled (not on by default) |

Rclone's own `remote:path` syntax and verb set (`copy`/`sync`/`move`/`config`) are distinctive enough that command-line-content matching carries real weight here, the same way AdFind's filter/`-sc` vocabulary does — see `05 - Detection and Hunting.md` for the exact match patterns published rules use.

## Local Network-Connection State

```
netstat -ano | findstr :443
Get-NetTCPConnection -RemotePort 443,22,21 -State Established
```

An rclone transfer of any real size holds a live, often long-duration outbound connection to the destination provider's API endpoint — visible in `netstat`/`Get-NetTCPConnection` while running, or via EDR network telemetry after the fact if the tool has exited. Unlike AdFind's brief single-query sessions, an rclone `copy`/`sync` of a large tree can hold the connection open for minutes to hours, widening the window a live-response capture can catch it in.

## Log Files Left Behind

If `--log-file` was used (common in the scripted/scheduled scenarios in `02`), a plain-text log recording every file transferred, skipped, or errored — including the source path and destination remote for each — persists on disk until deleted. Even without an explicit `--log-file`, `-v`/`-vv` console output is captured wherever the invoking shell/session itself is logged (a C2 implant's task-output logging, a PowerShell transcript, etc.).

## Cached Credential Material

- **`rclone.conf`** itself, per above — obscured passwords are trivially reversible; encrypted configs require the `RCLONE_CONFIG_PASS` value
- **Command-line/shell history**, if credentials were supplied inline via the connection-string evasion or an `RCLONE_CONFIG_PASS` environment-variable assignment on the same line
- **Process environment block** — `RCLONE_CONFIG_PASS` (or any backend credential supplied as an environment variable rather than a config/CLI value) is readable from a live process's environment via standard live-response tooling (`Get-Process`/`.StartInfo.EnvironmentVariables` equivalents, or a memory-forensics environment-block parse) for as long as the process runs
- No separate ticket/blob-style credential cache is created — unlike Mimikatz's `.kirbi` files or a saved token cache, rclone's only persistent credential artifact is the config file itself

## Memory Forensics

A running `rclone.exe`/`rclone` process holds its full command-line arguments in `PEB.ProcessParameters.CommandLine` (recoverable via standard memory-forensics tooling), along with — for the connection-string evasion specifically — any credential values that never touched disk at all. For a longer-running transfer (large `copy`/`sync`, or a standing `mount`/`serve` session), the capture window is materially wider than AdFind's typical bind-query-exit lifecycle, improving the odds a live memory acquisition catches it mid-operation.

## Timeline Correlation Value

Rclone's source-side footprint stacks cleanly: `[process creation for rclone/a renamed equivalent, full command line via Sysmon 1]` → `[rclone.conf read/write timestamp, or its explicit absence if the connection-string evasion was used]` → `[outbound connection to the destination provider's IP/port, held open for the duration of the transfer]` → `[--log-file contents, if present, itemizing exactly what was transferred]`. Because the destination is nearly always outside the victim's own logging visibility (per `04 - Target Evidence.md`), this source-side chain is normally the *entire* recoverable record of what left the network and when — treat it with the same evidentiary weight `AdFind/03 - Source Evidence.md` gives its own source-heavy footprint, for the same underlying reason: the "target" here logs almost nothing.
