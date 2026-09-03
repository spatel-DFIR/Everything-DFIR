# PowerShell Empire — Detection and Hunting

Scope note: this file hunts for exactly what `03 - Source Evidence.md` and `04 - Target Evidence.md` already document — the server-side data directory/database, the stage-0/1/2 staging handshake, PowerShell logging of the decoded launcher, listener-type-specific network signatures, and module-tasking artifacts. It does not introduce detection content for capability this note hasn't otherwise covered.

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

Empire exposes more independently-changeable defaults than most tools in this repo: the `StagingKey`, `DefaultProfile` (URIs + User-Agent), `Cookie` name, spoofed `Headers`, the `Launcher` command string itself, `Bypasses` (AMSI/ETW patches), `Obfuscate`/`ObfuscateCommand`, `JA3_Evasion`, agent `Language` choice, and — for `http_malleable` — an entire custom traffic-shaping profile. Rank hunts by what survives realistic combinations of these, not by treating every signal as equally durable:

| Rank | Signal | Survives StagingKey/DefaultProfile/Cookie/Headers randomization? | Survives `Bypasses`? | Survives `Obfuscate`? | Survives non-PowerShell agent language? | Survives `JA3_Evasion`? |
|---|---|---|---|---|---|---|
| 1 (strongest) | PowerShell **Script Block Logging (4104)** capturing the *decoded* stager text | ✅ Yes — captures the rendered script regardless of what values were plugged in | ✅ Yes — ScriptBlock logging and AMSI are separate engines; an AMSI bypass patch is itself logged by 4104 before it takes effect | ⚠️ Partial — the entry still exists, but obfuscated variable/token names make signature-based triage harder; manual/behavioral review still works | ❌ **No** — Python/IronPython/C#/Go agents never touch the PowerShell ScriptBlock logging pipeline at all | ✅ Yes — logging happens client-side, independent of TLS |
| 2 | Beacon/check-in periodicity — `DefaultDelay`±`DefaultJitter` request cadence to the listener, Sysmon 3 / Zeek `http.log` | ✅ Yes — cadence persists regardless of URI/cookie/header values | ✅ Yes | ✅ Yes | ✅ Yes — every agent language follows the same delay/jitter tasking-poll model | ✅ Yes |
| 3 | Default launcher **command-line pattern**: `-noP -sta -w 1 -enc` + `New-Object System.Net.WebClient` / `.DownloadData()` chain, Sysmon 1 / Security 4688 | ✅ Yes for `StagingKey`/profile/cookie — those don't touch the launcher's flags or WebClient usage | ✅ Yes — bypass snippets are prepended, they don't remove the WebClient/flag pattern | ❌ **No** — `Obfuscate` rewrites the entire stager body including the WebClient call chain into unrecognizable form | ❌ **No** — this is the PowerShell-specific launcher; other languages have their own distinct process signature (interpreter invocation or standalone compiled binary) | ✅ Yes |
| 4 | Default listener values: `StagingKey` `2c103f2c4ed1e59c0b4e2e01821770fa`, `DefaultProfile` (`/admin/get.php,/news.php,/login/process.php`), `Cookie` name `session`, `Headers` (`Server:Microsoft-IIS/7.5`) | ❌ **No** — the entire point of this rank is that it's the *unmodified default*; any operator who changes these values defeats the check trivially | N/A | N/A | ⚠️ Partial — `StagingKey` is shared across agent languages on the same listener, so it's still checkable regardless of which language a given agent uses | N/A |
| 5 | JA3/JA3S TLS handshake fingerprint (HTTPS listeners only) | ✅ Yes — TLS cipher order is independent of application-layer options | ✅ Yes | ✅ Yes | ✅ Yes | ❌ **No** — `JA3_Evasion=True` exists specifically to randomize the cipher list and defeat this |
| 6 | `smb` listener named-pipe artifact (`\\.\pipe\<PipeName>`, default `empire_pipe`), Sysmon 17/18 | ❌ **No** for the *default name* — trivially overridden via `PipeName` | ✅ Yes (pipe creation itself) | N/A | Only relevant for IronPython agents (currently the only supported language for `smb`) | N/A |
| 7 (weakest) | Static file/binary indicators (dropped stager files, fixed strings) | ❌ **No** — `multi_launcher` drops nothing to disk by default; where a file stager *is* used, obfuscation/naming are fully operator-controlled | ❌ **No** | ❌ **No** | N/A | N/A |

**Build primary detections on rank 1-2: enabling PowerShell Script Block Logging is the single highest-leverage native control against this tool specifically, because it reverses the one obfuscation layer (`-enc`) every PowerShell-language deployment relies on for wire transfer — and unlike AMSI, it is not defeated by any of Empire's own bypass options. Where the target environment can't guarantee PowerShell logging (non-Windows targets, non-PowerShell agents, logging disabled), fall back to rank 2's cadence-based network hunt, which is agent-language-agnostic. Rank 4's default-value checks cost nothing and are worth running first on any suspected host — they catch the large fraction of real-world deployments that never rotate the shipped defaults — but their absence proves nothing.**

## Hunting on Source

Commands assume access to the Empire server host (or its data directory backup) or its API with valid credentials.

```powershell
# 1. Identify the Empire data directory and its contents
#    (03 - Source Evidence.md: "The Server Data Directory")
Get-ChildItem -Path "$HOME/.local/share/empire" -Recurse -ErrorAction SilentlyContinue

# 2. Pull the SQLite DB directly (if SQLite; MySQL requires DB creds instead)
#    sqlite3 must be available on the analysis host
& sqlite3 "$HOME/.local/share/empire/empire.db" ".tables"
& sqlite3 "$HOME/.local/share/empire/empire.db" "SELECT id, name, options FROM listeners;"

# 3. Check whether default credentials were ever used — a strong signal of a
#    rushed/careless deployment (03's "Server Configuration")
Get-Content "$HOME/.local/share/empire/../../../empire/server/config.yaml" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'empireadmin|password123|empire_user|empire_password'

# 4. Server + per-listener logs
Get-Content "$HOME/.local/share/empire/logs/empire_server.log" -ErrorAction SilentlyContinue -Tail 200
Get-ChildItem "$HOME/.local/share/empire/logs/listener_*.log" -ErrorAction SilentlyContinue

# 5. Live process + bound ports — don't assume defaults, cross-reference
#    against the Listener table above
Get-Process -Name 'python*' -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -match 'empire' }
& ss -tlnp 2>$null | Select-String -Pattern ':1337|:80|:443'
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -in 1337,80,443 }

# 6. Shell history for install/server invocation and any cleartext-credential
#    login calls typed directly rather than piped from a file
Get-Content "$HOME/.bash_history","$HOME/.zsh_history" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'ps-empire|username=.*password=|Authorization: Bearer'

# 7. Via the API itself, if only credentials (not host access) are available —
#    pull the full agent/task history for attribution and timeline building
$hdr = @{ Authorization = "Bearer $TOKEN" }
Invoke-RestMethod -Uri "$SERVER/api/v2/agents/" -Headers $hdr
Invoke-RestMethod -Uri "$SERVER/api/v2/agents/tasks" -Headers $hdr
```

## Hunting on Target

```powershell
# 1. Rank 1 — Script Block Logging capturing a decoded Empire stager.
#    Look for the WebClient/DownloadData/IEX chain and the plaintext
#    StagingKey assignment that survives EVERY listener-config change.
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'New-Object System\.Net\.WebClient' -and $_.Message -match 'DownloadData' }

# Pull the StagingKey directly out of a matched entry if present
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match "GetBytes\('([a-f0-9]{32})'\)" } |
  ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; StagingKey = $Matches[1] } }

# 2. Rank 1 continued — the mattifestation AMSI-bypass string specifically,
#    logged by 4104 BEFORE it blinds AMSI for the rest of the session
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'amsiInitFailed' }

# 3. Rank 3 — default launcher command-line pattern (Security 4688, requires
#    command-line auditing enabled; defeated by a custom Launcher/Obfuscate)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '-noP\s+-sta\s+-w\s+1\s+-enc' }

# Sysmon 1 equivalent
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'powershell\.exe' -and $_.Message -match '-enc' }

# 4. Rank 2 — beaconing cadence to a suspected listener (works regardless of
#    agent language). Requires a candidate destination; pair with rank 4/5
#    below to first FIND a candidate, then confirm cadence here.
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Where-Object { $_.RemotePort -in 80,443,8080,8443 } |
  Group-Object RemoteAddress | Where-Object Count -gt 3

# 5. Rank 4 — DEFAULT-CONFIG check only: unmodified DefaultProfile URIs,
#    cookie name, and spoofed IIS header. Zero-cost, catches lazy deployments,
#    proves nothing on its own if absent.
# (Best run at the network layer — see Zeek note below)

# 6. Rank 6 — SMB listener pivot: default pipe name, if unmodified
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\\\\.\\pipe\\empire_pipe' }
# Custom pipe names require enumerating ALL pipe create/connect events and
# triaging by behavior (unexpected process, no legitimate application tie),
# not by name match

# 7. Module-tasking artifacts — service/scheduled-task creation from
#    lateral-movement or persistence modules (04's Windows Event Logs table)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697,4698} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message
```

### Network-layer hunt (Zeek/proxy logs) — default-config signature

```
# Zeek http.log — the zero-cost, rank-4 default-config check
zeek-cut uri user_agent host method request_body_len < http.log |
  awk -F'\t' '$1 ~ /^\/admin\/get\.php|^\/news\.php|^\/login\/process\.php/'

# Cookie header carrying the default cookie name "session" with a
# base64-looking value on an otherwise-unremarkable request
zeek-cut host uri < http.log | grep -E 'Cookie: session='
```

Pair this with the `Server: Microsoft-IIS/7.5` response-header check on any HTTP(S) service that otherwise fingerprints (via active probing or passive TLS/HTTP-stack behavior) as **not actually IIS** — the mismatch between claimed and actual server software is a durable, near-zero-false-positive signal for an unmodified `http`/`https` listener specifically.

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ErrorAction SilentlyContinue -ScriptBlock {
  $hits = [System.Collections.Generic.List[object]]::new()

  # Rank 1: decoded Empire stager pattern in ScriptBlock logs
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'New-Object System\.Net\.WebClient' -and $_.Message -match 'DownloadData' } |
    ForEach-Object { $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'scriptblock-webclient-download'; Time = $_.TimeCreated }) }

  # Rank 3: default launcher command line (Security 4688)
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '-noP\s+-sta\s+-w\s+1\s+-enc' } |
    ForEach-Object { $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'default-launcher-cmdline'; Time = $_.TimeCreated }) }

  # Rank 1: mattifestation AMSI bypass
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'amsiInitFailed' } |
    ForEach-Object { $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'amsi-bypass-mattifestation'; Time = $_.TimeCreated }) }

  # Rank 6: default SMB pipe name
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'empire_pipe' } |
    ForEach-Object { $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'default-smb-pipe'; Time = $_.TimeCreated }) }

  $hits
}

# A host hitting multiple independent signal classes in a tight window is a
# far stronger candidate than any single signal alone
$results | Group-Object Host, Signal | Sort-Object Count -Descending | Select-Object -First 30 Count, Name

$results | Export-Csv -Path .\empire_sweep_results.csv -NoTypeInformation
```

## Remediation

**Capture evidence before acting.** Killing the agent process or isolating the host destroys the decoded stager/StagingKey sitting only in the PowerShell process's own memory and any pending unlogged tasking. Pull ScriptBlock/Module logs, Sysmon 1/3/17/18, Security 4688/4697/4698, and — if server-side access is separately available — the Empire database's task history (`03 - Source Evidence.md`) before remediating.

Empire itself rides legitimate OS mechanisms (PowerShell, `.NET`, HTTP, SMB IPC) — the actual hardening targets are the access paths and logging gaps this note has documented:

```powershell
# PowerShell Script Block Logging + Module Logging — the single highest-
# leverage native control against this tool, per the Hunting Priority table:
# survives every listener-config change, every Bypasses option, and captures
# the plaintext StagingKey directly
# Computer Configuration > Administrative Templates > Windows Components >
# Windows PowerShell > "Turn on PowerShell Script Block Logging" = Enabled
# ... > "Turn on Module Logging" = Enabled (Module Names = *)

# Command-line auditing for process creation — needed to catch the default
# launcher pattern via Security 4688 (defeated by a custom Launcher string,
# so treat as a secondary control, not primary)
# Computer Configuration > Administrative Templates > System > Audit Process
# Creation > "Include command line in process creation events" = Enabled

# Constrained Language Mode / AppLocker — raises the cost of the PowerShell
# agent specifically (blocks reflective .NET method invocation many bypasses
# rely on); does not affect Python/C#/Go agents at all, so pair with process/
# network monitoring rather than relying on this alone

# AMSI hardening — Defender/AMSI signature updates for the public
# mattifestation/rastamouse/liberman bypass strings; monitor for AMSI
# provider errors/failures as a secondary signal even where the specific
# string is missed

# Egress filtering — a default-deny egress policy with an explicit allowlist
# forces http/https/http_malleable listener traffic onto a proxied,
# inspectable path where the network-layer signals in this note (default
# URIs, cookie name, JA3 where JA3_Evasion is off) have visibility

# Restrict SMB/IPC reachability between workstations where not operationally
# required — closes the smb listener's peer-to-peer pivot path
```

Enabling PowerShell Script Block Logging fleet-wide is the single highest-leverage compensating control from this note's perspective — it is the one signal class in the priority table that survives every evasion option Empire's own `Bypasses`/`Obfuscate`/listener-randomization features expose, short of abandoning the PowerShell agent language entirely.
