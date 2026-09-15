# Spray365 — Source Evidence

What the operation leaves on the **attacking/source** host running `spray365.py`.

## Contents
- [The `.s365` Execution Plan File — the Single Richest Artifact](#the-s365-execution-plan-file--the-single-richest-artifact)
- [The Results JSON File](#the-results-json-file)
- [Shell/Command History](#shellcommand-history)
- [Process Artifacts](#process-artifacts)
- [Network Connection State](#network-connection-state)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline-Correlation Value](#timeline-correlation-value)

---

## The `.s365` Execution Plan File — the Single Richest Artifact

Unlike `../TrevorSpray/`, which writes accumulated state to a fixed, hidden `~/.trevorspray/` directory, Spray365's entire operational plan lives in **one operator-named JSON file** (extension `.s365` by convention, but the tool doesn't enforce it — `-ep` accepts any writable path). This file is generated *before* any spray traffic is sent and contains, in cleartext, the complete `Credential` list: every `domain`, `username`, `password`, the specific `client_id`/`endpoint`/`user_agent` pair assigned to that credential, and the computed `delay`/`initial_delay`. Recovering this single file from a source host — whether still present post-engagement, in a temp directory, in shell history via its path, or in a backup/snapshot — reconstructs the **entire planned attack surface**, including every password that was going to be tried, independent of whether the `spray` step ever actually ran or how far it got.

This is a materially different exposure profile than `../TrevorSpray/`'s design: TrevorSpray's credential material only exists in files *after* a hit is confirmed (`valid_logins.txt`); Spray365's plan file exposes the **full candidate password list up front**, whether or not any of them worked.

## The Results JSON File

`modules/spray/helpers.export_auth_results()` writes `spray365_results_<YYYY-MM-DD_HH-MM-SS>.json` to the **current working directory** at the end of every `spray` run (no fixed/hidden location, no cumulative history file across runs — each invocation gets its own uniquely timestamped file). Contents mirror the `.s365` input plus each attempt's `AuthResult` (success/partial-success/failure, the parsed AADSTS error message, and — for successes — the raw token response). A directory listing showing multiple `spray365_results_*.json` files is itself a durable indicator of exactly how many separate spray sessions were run and when, readable straight from the filenames without opening any of them.

## Shell/Command History

`~/.bash_history`/`~/.zsh_history` (or PowerShell's `ConsoleHost_history.txt` on Windows, since Spray365 runs cross-platform under any Python 3.9+) captures the full `generate`/`spray`/`review` invocations, including `-p`/`--password` if a single password was passed inline rather than via `-pf`. Because the tool is a Click-based CLI with subcommands, history entries are distinctively shaped (`python3 spray365.py generate normal -ep ... -d ... -u ...`) and easy to `grep spray365` for across a broad shell-history sweep.

## Process Artifacts

- Process name/command line: `python3 spray365.py <subcommand> ...` — full argv (including the `.s365`/results file paths and any inline password) visible to anything with process-listing access during the run.
- `generate audit` runs are computationally and temporally distinct in process behavior: because they materialize the full cross-product plan (potentially hundreds of credentials for even a single-user, single-password input) before writing it out, expect a visible burst of CPU/memory activity and a longer-than-`normal`-mode runtime for the `generate` step itself, before any network traffic is even sent — a process-behavior tell independent of any file content.
- No child-process spawning is intrinsic to the tool itself (unlike `../TrevorSpray/`'s SSH-proxy children or `iptables` shell-outs) — MSAL's HTTP calls happen in-process via `requests`. The one exception is `-x/--proxy`, which doesn't spawn anything but does mean all traffic routes through whatever separate proxy process the operator configured out-of-band (e.g. Burp).

## Network Connection State

Every spray attempt is a direct outbound HTTPS connection from the operator's own box to `login.microsoftonline.com` (MSAL's fixed `/organizations` multi-tenant authority) — **there is no built-in mechanism to route this through anything but a single, static egress point** (the box itself, or whatever one `-x/--proxy` target is configured). `netstat`/`ss` during a run shows a steady stream of connections to Microsoft's login infrastructure from one source IP, for the plan's entire duration — a materially simpler, less-varied network footprint than `../TrevorSpray/`'s SSH-proxy/subnet-spoofing options produce, since Spray365 has no equivalent capability of its own.

## Memory-Forensics Angle

- MSAL's `PublicClientApplication` and its in-memory token cache hold every credential and any successfully-issued token for the process's lifetime — a memory acquisition of a live `spray365.py spray` process can recover in-progress plaintext usernames/passwords and any tokens already obtained, same as any Python process handling credential material directly.
- Because results are only written to disk in one batch at the very end of a `spray` run (`export_auth_results()` runs once, after the full loop completes, not incrementally per-attempt), an **abrupt process termination during a run produces no `spray365_results_*.json` file at all** — all in-progress result data exists only in memory until the run finishes normally. This is the inverse of `../TrevorSpray/`'s incremental-log-file design, and means memory acquisition (or a forced `-R` resume from a known position with a fresh run) is the only way to recover results from an interrupted Spray365 session.

## Timeline-Correlation Value

Because Spray365 has no built-in IP-diversity mechanism, source-side network-connection timestamps correlate 1:1 with target-side Entra ID Sign-in Log timestamps for a **single, consistent source IP** across the entire run — simpler to reconcile than a multi-egress `../TrevorSpray/` session, but also meaning a single acquired source host (or its `--proxy` target, if one was configured) accounts for the full observed spray traffic with no additional egress points to hunt down.
