# ngrok — Source Evidence

## A necessary reframe before the artifact list

Every other Source Evidence file in this repo assumes a clean split: an attacker-controlled host running the offensive tool versus a victim host receiving the effect. **ngrok doesn't hold to that split cleanly**, for a reason distinct from AnyDesk's (`AnyDesk/03 - Source Evidence.md`) but with the same practical consequence — figure out *which* host is actually running the agent before applying this file:

- **When ngrok exposes a service that already lives on the compromised host** — the RDP-tunnel, SMB-tunnel, or reverse-shell-listener use cases in `02 - Hands-On Use Cases.md` — the agent process runs **on the victim/target machine itself**. That single host is simultaneously the "source" of the tunnel (running the tool) and the "target" of the intrusion (the host under investigation). In this case, everything in this file applies directly to the target host, and `04 - Target Evidence.md`'s network/service-layer content applies to that same host too — there is no second machine to separately image.
- **When ngrok fronts attacker-owned infrastructure** — the phishing-kit-hosting or C2-listener-fronting use cases — the agent runs on the **operator's own machine** (their laptop, a rented VPS, a Team Server host). This is the classic "source" case every other page in this module means, and it's recoverable only in the rarer scenario where that infrastructure itself gets seized (a law-enforcement takedown, a misconfigured host an analyst pivots to from other evidence).

**What this file covers:** the artifact catalog for whichever host is actually running the `ngrok` agent process, regardless of which of the two roles above it's playing — the artifacts themselves (config file, process state, network state, local inspection UI) are identical either way; only the interpretation of "why is this process here" differs.

## Contents
- [Configuration File and Authtoken](#configuration-file-and-authtoken)
- [Environment-Variable Authtoken — the Disk-Evading Variant](#environment-variable-authtoken--the-disk-evading-variant)
- [Process Artifacts and Command Line](#process-artifacts-and-command-line)
- [Local Inspection UI State](#local-inspection-ui-state)
- [Shell/Command History](#shellcommand-history)
- [Network State](#network-state)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Configuration File and Authtoken

Verified against ngrok's own [config file docs](https://ngrok.com/docs/agent/config/v3/) and corroborating community-documented default paths:

| OS | Default `ngrok.yml` location |
|---|---|
| Windows | `%LocalAppData%\ngrok\ngrok.yml` |
| macOS | `~/Library/Application Support/ngrok/ngrok.yml` |
| Linux | `~/.config/ngrok/ngrok.yml` |

`ngrok config add-authtoken <token>` (`01 - Overview.md`) writes the account's authtoken into this file in plain YAML under the `agent:` block — **not obfuscated or encrypted**, unlike, for example, Rclone's `--obscure`-flagged passwords (`Rclone/01 - Overview.md`, itself only trivially reversible). Recovering this file from a source host directly identifies the ngrok **account** the operator used, which — if it's ever surfaced in an ngrok API/dashboard investigation via legal process — can tie multiple engagements/intrusions to the same account across unrelated victim organizations. A `--config <path>` invocation pointing somewhere other than the OS default (`01 - Overview.md`) is itself a minor OPSEC choice worth noting when found.

## Environment-Variable Authtoken — the Disk-Evading Variant

Per ngrok's own documentation, the `NGROK_AUTHTOKEN` environment variable is honored by the agent and **"take[s] precedence over"** the config-file value — meaning an operator can run `ngrok http ...` with the token set only in the shell/process environment for that single session, never touching `ngrok.yml` at all. This is the direct ngrok analogue of AnyDesk's `echo <password> | AnyDesk.exe --set-password` command-line-visibility caveat (`AnyDesk/01 - Overview.md`): it avoids one artifact (the config file) at the cost of a different one (the environment block of the running/recently-run process, and potentially shell history if it was exported via `export NGROK_AUTHTOKEN=...`/`$env:NGROK_AUTHTOKEN='...'` rather than piped inline). Check both the config file **and** the process/shell environment before concluding no authtoken evidence exists.

## Process Artifacts and Command Line

The invoked command line directly states operator intent — `ngrok http 8080` vs. `ngrok tcp 3389` vs. `ngrok tcp 445` immediately tells an analyst which service was being exposed and to what protocol, without needing to correlate against anything else:

```powershell
# Windows — live or recently-terminated process command line
Get-CimInstance Win32_Process -Filter "Name='ngrok.exe'" | Select-Object ProcessId, CommandLine, ParentProcessId
```

```bash
# Linux/macOS — live process
ps aux | grep -i ngrok
```

A `ngrok service install`-registered instance (`01 - Overview.md`) additionally leaves a standing service/daemon registration (Windows service, systemd unit, launchd job) independent of any single terminal session — covered in OS-Level Audit Trail below.

## Local Inspection UI State

`03`'s most ngrok-specific artifact: the local web inspection interface at `127.0.0.1:4040` (`01 - Overview.md`) holds every HTTP request/response that transited an HTTP tunnel while the agent process was running, including any credentials submitted to a phishing page fronted by the tunnel (`02 - Hands-On Use Cases.md`'s inspection-UI use case). ngrok's own documentation does not state whether this history is persisted to disk between agent restarts or held purely in the running process's memory — **flagged as an open question rather than asserted either way**; treat a live, still-running agent process as a live-response opportunity to pull this data via the local API (`GET http://127.0.0.1:4040/api/requests/http`) before the process is terminated, since a restart may lose it entirely.

## Shell/Command History

```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue |
  Select-String 'ngrok|NGROK_AUTHTOKEN|config add-authtoken'
```

```bash
grep -i 'ngrok\|NGROK_AUTHTOKEN' ~/.bash_history ~/.zsh_history 2>/dev/null
```

Captures the exact invocation, including an authtoken passed via `--authtoken` on the command line (`01 - Overview.md`) or exported inline before an `NGROK_AUTHTOKEN`-reliant invocation.

## Network State

The running (or recently-run) agent maintains a **persistent, long-lived outbound TCP 443 connection** to its control-channel domain (`connect.<region>.ngrok-agent.com`, or the legacy `tunnel.<region>.ngrok.com` on pre-3.3.0 agents — `01 - Overview.md`'s architecture diagram):

```powershell
Get-NetTCPConnection -State Established -OwningProcess (Get-Process ngrok -ErrorAction SilentlyContinue).Id -ErrorAction SilentlyContinue
```

```bash
lsof -i -a -c ngrok
```

Unlike a one-off connection, this session persists for as long as the tunnel is active — a single sustained flow record spanning the entire operational window is itself useful for duration-based timeline bracketing (When Did the Tunnel Start / End), distinct from the request-level granularity the inspection UI provides for HTTP tunnels specifically.

## OS-Level Audit Trail

Where `ngrok service install` was used (`01 - Overview.md`, `02 - Hands-On Use Cases.md`'s persistence use case), the same native OS service-registration artifacts any other Windows-service-backed tool leaves apply here with no ngrok-specific behavior — cross-link rather than re-derive: System Event ID 7045 (service install) and the service's own registry key under `HKLM\SYSTEM\CurrentControlSet\Services\` on Windows; the corresponding systemd-unit-file/journal entries on Linux. See `AnyDesk/04 - Target Evidence.md`'s Windows Event Logs section for the exact 7045-based hunt pattern, directly reusable here.

## Memory Forensics

A live `ngrok.exe`/`ngrok` process holds the account authtoken (or session token derived from it) in memory regardless of whether it came from the config file, `--authtoken`, or `NGROK_AUTHTOKEN` — meaning a memory-resident credential is recoverable even in the disk-evading `NGROK_AUTHTOKEN`-only deployment case above. It also holds the current tunnel's assigned public URL/address and, for HTTP tunnels, whatever request/response data the inspection UI hasn't yet aged out. No public config-extraction tooling comparable to Cobalt Strike's `1768.py`/`CobaltStrikeParser` (`Cobalt Strike/03 - Source Evidence.md`) exists for ngrok, since there's no embedded Malleable-style configuration block to parse out — a live process capture (`ProcDump`, already built in this repo, or an equivalent) followed by string/strings extraction for the authtoken and public URL is the practical approach.

## Timeline Correlation Value

The control-channel connection's start time (Network State, above) brackets the entire tunnel's active window precisely — it opens when the agent starts and closes when the process terminates or loses connectivity, giving a hard start/end pair to anchor everything else against: process creation (Process Artifacts), first inbound request through the tunnel (inspection UI, if HTTP), and any service-registration event (OS-Level Audit Trail) if persistence was configured. Where the agent ran on the same host being investigated as the intrusion's target (this file's opening reframe), this timeline merges directly with `04 - Target Evidence.md`'s rather than standing as a separate source-side spine.
