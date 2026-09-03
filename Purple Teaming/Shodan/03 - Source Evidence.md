# Shodan — Source Evidence

This file matters differently for Shodan than for most tools in this repo. Per `04 - Target Evidence.md`, a plain Shodan query leaves **no evidence on the target at all** — the target never sees the operator's traffic, only Shodan's own independent crawling. That means "source evidence" here isn't a supporting artifact alongside a richer target-side trail — for the overwhelming majority of Shodan use cases, **the operator's own machine is the only place this activity is recorded anywhere.** Practically, that also reframes who's reading this file: it's written for a **SOC monitoring its own analysts or its own red team**, not for an incident responder investigating a victim network, since a victim network has nothing of its own to investigate for this specific tool.

## Contents
- [Configuration and API Key Storage](#configuration-and-api-key-storage)
- [Shell / Console History](#shell--console-history)
- [Process Creation and Command-Line Logging](#process-creation-and-command-line-logging)
- [Local Network-Connection State](#local-network-connection-state)
- [DNS Resolution Artifacts](#dns-resolution-artifacts)
- [Downloaded/Cached Result Files](#downloadedcached-result-files)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Configuration and API Key Storage

`shodan init <api key>` (per `01 - Overview.md`'s verified source read of `shodan/cli/settings.py` and `shodan/cli/helpers.py`) writes the key to a predictable, single-purpose location:

| Artifact | Path | Notes |
|---|---|---|
| API key file | `~/.shodan/api_key` if `~/.shodan/` already exists, otherwise `~/.config/shodan/api_key` | Plaintext, `chmod 600` on creation — recoverable in full by anyone with read access to the operator's home directory or a filesystem-level acquisition of the host |
| No environment-variable fallback | — | Verified directly against the CLI source: `get_api_key()` only ever reads the on-disk file, there is no `SHODAN_API_KEY`-style environment variable the CLI itself checks. If a key appears in an environment variable, it got there via a custom wrapper script, not the tool itself |

The presence of `~/.shodan/` or `~/.config/shodan/` on a host is, by itself, a durable indicator that the `shodan` CLI has been initialized on that machine at some point — persists independent of whether the tool has been run recently.

## Shell / Console History

The `shodan init <api key>` invocation is the single highest-value command-history artifact this tool produces, because **the full API key is a literal command-line argument**:

| Shell | Artifact |
|---|---|
| Bash | `~/.bash_history` — the raw `shodan init <key>` line, in full, unless `HISTCONTROL=ignorespace` was used and the operator deliberately prefixed the command with a space |
| Zsh | `~/.zsh_history` — same exposure |
| PowerShell (if run from a Windows box with the CLI installed via `pip`) | `ConsoleHost_history.txt` under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\` |

Every subsequent `shodan search`/`download`/`stats`/etc. invocation also lands in shell history in full, including the complete query string — which, unlike the API key itself, is often useful evidence of *intent* (what the operator was looking for) rather than credential exposure.

## Process Creation and Command-Line Logging

```
Sysmon Event ID 1 (Windows) / auditd execve (Linux) / Endpoint Security process-exec events (macOS)
```

Because `shodan` is a plain Python `click`-based CLI (no service, no persistent listener, no injected payload), a process-creation event carrying the full command line is the primary host-based artifact — the same evidentiary pattern this repo already documents for `AdFind/03 - Source Evidence.md`: a short-lived process, invoked directly, whose command line *is* the evidence. Look for:

- `python` / `python3` (or a `shodan.exe`-named console-script entry point on Windows, depending on install method) as the parent/image
- Command-line arguments containing `shodan search`, `shodan download`, `shodan stream`, `shodan scan submit`, etc., plus the literal query string
- On a system with EDR command-line visibility, this is typically the *only* durable execution record — there's no dropped payload, no created service, no scheduled task for a normal query workflow

## Local Network-Connection State

```
netstat -an | grep :443       # Linux/macOS
Get-NetTCPConnection -RemotePort 443    # Windows
```

Every `shodan` CLI call is an outbound HTTPS/443 connection to one of a small, fixed set of Shodan-operated hostnames — `api.shodan.io` (nearly everything), `stream.shodan.io` (`shodan stream`), `trends.shodan.io` (`shodan trends`), `exploits.shodan.io` (library-only, no CLI command uses it), and the unauthenticated `internetdb.shodan.io`. A SOC with full-packet or proxy-log visibility into its own egress can recover:

- **The API key itself, in cleartext, inside the request URL.** Per direct inspection of `shodan/client.py`'s `_request()` method, the key is appended as a `key=<value>` URL **query-string parameter** on every single API call — not a header, not a POST body field for GET requests. Any full-URL-capturing web proxy, TLS-inspecting middlebox, or DNS-over-HTTPS-defeating SSL-bump appliance on the operator's own network egress path will have the operator's Shodan API key sitting in plaintext in its own logs. This is a real, easily-overlooked credential-exposure angle distinct from anything Shodan itself does wrong — it's simply how the CLI's HTTP client is built
- **A default, unmodified `python-requests/<version>` User-Agent string.** The client source sets no custom `User-Agent` header anywhere in `_request()` — every request identifies itself as a stock `requests` library call. This is a real, if soft, distinguishing signal on an egress proxy: a browser session against `shodan.io`'s website looks nothing like this, so `python-requests` traffic specifically to `api.shodan.io`/`stream.shodan.io` is a reasonably clean marker for CLI/scripted usage vs. a human browsing the web UI
- **The query string itself**, for any proxy that logs full request URLs — since `search`/`count`/`download`/`host`/`stream` all pass the query as a URL parameter, the same proxy visibility that recovers the API key also recovers exactly what was searched for

## DNS Resolution Artifacts

Any DNS query log, resolver cache, or Zeek/network-sensor DNS record on the operator's own network will show resolution of `api.shodan.io` and whichever of the secondary Shodan hostnames a given session's commands touched. This is often the **cheapest and most durable** source-side signal available — DNS logs are commonly retained far longer than full connection/proxy logs, and a query for `stream.shodan.io` or `internetdb.shodan.io` specifically (rather than the generic `api.shodan.io`) narrows down *which* CLI capability was in use without needing full-URL visibility at all.

## Downloaded/Cached Result Files

`shodan download`, `alert download`, `alert export`, `domain --save`, `host --save`, and `trends --save`/`--filename` all write `.json.gz` files to the current working directory at invocation time — named after the query, IP, domain, or a default like `<query>-trends.json.gz`. These are:

- Recoverable via standard filesystem timeline analysis ($MFT, USN journal on Windows; `stat`/journal metadata on Linux) even if later deleted, the same way any other dropped file is
- Directly informative of *scope* once recovered — a downloaded file's content is the literal reconnaissance output, telling an investigator exactly what target space and criteria the operator was working from, without needing to reconstruct it from the query string alone
- Plaintext JSON internally (gzip-compressed, not encrypted) — trivially decompressed and read by anyone who recovers the file

## Memory Forensics

`shodan` CLI invocations are short-lived, foreground, synchronous processes (with the partial exception of `shodan stream`, which stays resident for the duration of the subscription). A live memory capture catching the process mid-run can recover:

- The full command line via the process's own `PEB.ProcessParameters.CommandLine` (Windows) or `/proc/<pid>/cmdline` (Linux) — including the query, and if `init` was captured mid-execution, the raw API key argument
- In-flight HTTP request/response data still resident in the Python process's heap, including the API key on the outgoing request line and any not-yet-flushed-to-disk result data
- For `shodan stream`, a longer capture window than any other subcommand, since the process is designed to run indefinitely rather than exit immediately

## Timeline Correlation Value

Because there is normally no target-side event to correlate against (per `04 - Target Evidence.md`), the source-side artifacts above are usually the **entire** evidentiary record of a Shodan-based reconnaissance activity — not a supporting layer on top of something richer elsewhere, which is the inverse of how most tools in this module are documented. Reconstructing "what did the operator learn, and when" is a matter of correlating, in order: DNS resolution timestamps for Shodan hostnames → the outbound HTTPS connection window → the shell-history/process-creation command line for that window → any `.json.gz` file written to disk in the same window. The one exception where the target genuinely does gain a correlatable event is `shodan scan submit`/`scan internet` (on-demand scanning) — see `04 - Target Evidence.md` for how that specific case's timing lines up against Shodan's own crawler-sourced traffic reaching the target shortly after the source-side `scan submit` command runs.
