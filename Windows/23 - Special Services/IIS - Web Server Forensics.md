# IIS - Web Server Forensics

Microsoft Internet Information Services (IIS) turns a Windows Server into an internet-facing application host, and that exposure makes it a favorite initial-access target: a vulnerable application, a weak upload restriction, or a stolen set of credentials gets an attacker a foothold that looks — to casual inspection — like nothing more than a request in a log file. Unlike most of this module's artifacts, IIS forensics is not primarily about the registry, NTFS metadata, or event logs (though all three matter here too) — it is primarily about **reading web server logs at scale and recognizing the request patterns that don't belong**, then following the trail from a suspicious request to a dropped file, a config change, or a process that should never have existed.

This note is written to be opened mid-incident on a box someone has flagged as "the web server got popped" and worked top-to-bottom: confirm what's actually running, find the logs, read them correctly, hunt them hard, check for a dropped web shell, check for a config-based backdoor that never dropped a file at all, then correlate everything against process/network/event evidence already covered elsewhere in this module.

> 🔴 **The single highest-value tell in this entire note: `w3wp.exe` (the IIS worker process) spawning `cmd.exe` or `powershell.exe`.** In normal operation the worker process serves requests through its own managed/native code pipeline and does not shell out. A `cmd.exe` or `powershell.exe` child of `w3wp.exe` is a web shell executing operating-system commands until proven otherwise — see Step 6.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Investigation Workflow](#investigation-workflow)
  - [Step 1 — Confirm IIS Presence, Version, and Topology](#step-1--confirm-iis-presence-version-and-topology)
  - [Step 2 — Enumerate Sites, App Pools, Bindings, and Identities](#step-2--enumerate-sites-app-pools-bindings-and-identities)
  - [Step 3 — Locate the Log Files](#step-3--locate-the-log-files)
  - [Step 4 — Read the Logs: Format and Field Reference](#step-4--read-the-logs-format-and-field-reference)
  - [Step 5 — Hunt the Logs](#step-5--hunt-the-logs)
  - [Step 6 — Web Shell Detection](#step-6--web-shell-detection)
  - [Step 7 — Config-Based Persistence and Backdoors](#step-7--config-based-persistence-and-backdoors)
  - [Step 8 — Correlate with Process, Network, and Event Evidence](#step-8--correlate-with-process-network-and-event-evidence)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Pitfalls](#pitfalls)
- [Red Flags](#red-flags)
- [MITRE ATT&CK Techniques Covered](#mitre-attck-techniques-covered)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, no-third-party-tool triage across the workflow below. Run these first; the step-by-step sections give the full reasoning and the deeper pivots each one hints at.

```powershell
# Is IIS even installed, and what version - the starting fact for everything else
Get-Service W3SVC -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue | Select-Object VersionString, MajorVersion, MinorVersion

# Every site, its ID (needed to find its logs), physical path, and app pool - the topology map (Step 1/2)
& "$env:windir\system32\inetsrv\appcmd.exe" list sites

# Currently running worker processes mapped to app pool - the PID you'll need when correlating process/network evidence back to a site (Step 8)
& "$env:windir\system32\inetsrv\appcmd.exe" list wp

# w3wp.exe spawning a shell - the single highest-value red flag in this note (Step 6)
$w3wpPids = (Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'").ProcessId
Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -in $w3wpPids -and $_.Name -in @('cmd.exe','powershell.exe','powershell_ise.exe','cscript.exe','wscript.exe') } |
    Select-Object ProcessId, Name, ParentProcessId, CommandLine

# Files under wwwroot modified/created most recently - the fastest lead on a dropped web shell (Step 6)
Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 30 FullName, CreationTime, LastWriteTime, Length

# Suspicious script extensions with unusually small size or a double extension - classic web-shell disguise pattern (Step 6)
Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -File -Include *.asp,*.aspx,*.ashx,*.asmx,*.cer,*.asa,*.jsp,*.php -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -lt 5KB -or $_.Name -match '\.\w+\.\w+$' } | Select-Object FullName, Length, LastWriteTime

# Quick webshell-pattern string sweep across all IIS logs on the box - cast a wide net before scoping (Step 5)
Get-ChildItem 'C:\inetpub\logs\LogFiles' -Recurse -Filter *.log -ErrorAction SilentlyContinue |
    Select-String -Pattern 'cmd=|cmd\.exe|powershell|eval\(|base64|\.\./\.\./|whoami|certutil' -CaseSensitive:$false |
    Select-Object Path, LineNumber, Line -First 100
```

## Investigation Workflow

### Step 1 — Confirm IIS Presence, Version, and Topology

Before anything else, establish that IIS is actually running, which version, and whether this is a single default site or a multi-tenant box hosting dozens of applications under different identities. This shapes every step that follows — log location, the number of app pools to check, and how much blast radius a single compromised handler mapping could have.

| Check | Command | What it tells you |
|---|---|---|
| Service presence/state | `Get-Service W3SVC` or `sc.exe query w3svc` | Is the World Wide Web Publishing Service installed and running |
| IIS version | `HKLM:\SOFTWARE\Microsoft\InetStp` → `VersionString`, `MajorVersion`, `MinorVersion` | Determines which management surface applies (see version table below) |
| GUI management console | `inetmgr.exe` (`%windir%\system32\inetsrv\`) | Interactive inspection if a GUI session is available; not always practical mid-incident |
| Command-line management | `appcmd.exe` (`%windir%\system32\inetsrv\appcmd.exe`) | The scriptable equivalent of IIS Manager — works over a remote shell, no GUI required |
| PowerShell module | `Import-Module WebAdministration` (or the newer `IISAdministration` module on Server 2012+) | Exposes `Get-Website`, `Get-WebAppPoolState`, `Get-WebBinding`, and the `IIS:` PSDrive |

| IIS Version | Typical OS | Notes |
|---|---|---|
| IIS 6.0 | Windows Server 2003 | Legacy; metabase-based config (not `applicationHost.config`), no built-in `appcmd`; largely EOL but still found on legacy estates |
| IIS 7.0 / 7.5 | Windows Server 2008 / 2008 R2 | First version with XML-based `applicationHost.config` and the integrated request pipeline |
| IIS 8.0 / 8.5 | Windows Server 2012 / 2012 R2 | Adds Centralized Certificate Store, CPU throttling; config model unchanged |
| IIS 10.0 | Windows Server 2016 / 2019 / 2022, Windows 10/11 | Current; HTTP/2 support, further hardening options |

#### PowerShell

Confirm presence, state, and version in one pass:

```powershell
Get-Service W3SVC | Select-Object Name, Status, StartType
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue |
    Select-Object VersionString, MajorVersion, MinorVersion, InstallPath
```

Load the management module and confirm it can actually enumerate the `IIS:` provider (fails silently on a box where IIS is installed but the management tools role feature is not):

```powershell
Import-Module WebAdministration -ErrorAction Stop
Get-PSDrive IIS -ErrorAction SilentlyContinue
```

### Step 2 — Enumerate Sites, App Pools, Bindings, and Identities

Once IIS is confirmed, map the full topology: every site, the application pool it runs under, its bindings (host header/IP/port), its physical content path, and — critically — the identity the worker process runs as. A site compromised through one vulnerable application can pivot to every other site sharing its app pool identity, so this map is what scopes blast radius before you go deeper.

All of this is defined in one central XML file: `%windir%\System32\inetsrv\config\applicationHost.config`. It holds `<sites>`, `<applicationPools>`, `<sites>/<bindings>`, and (relevant again in Step 7) `<globalModules>` — every site and pool on the box is a `<site>`/`<add>` element in this one file. Two sibling files worth knowing about: `redirection.config` (points at where configuration is delegated/stored if shared config is in use) and `administration.config` (IIS Manager's own feature-delegation settings) — rarely load-bearing for an intrusion, but worth knowing they exist so an unfamiliar reference doesn't cause confusion.

| Command | Purpose |
|---|---|
| `appcmd list sites` | Every site, its ID, state, and bindings |
| `appcmd list apppools` | Every app pool, its state, and .NET/pipeline mode |
| `appcmd list vdirs` | Every virtual directory and its physical path |
| `appcmd list apps` | Every application and the app pool it's assigned to |
| `appcmd list wp` | **Currently running** worker processes with PID and app pool name — the map from a process/network artifact back to a site |
| `Get-Website` | PowerShell equivalent of `appcmd list sites`, adds `.Net` object output for scripting |
| `Get-WebAppPoolState -Name <pool>` | Live state of a specific app pool |
| `Get-ItemProperty IIS:\AppPools\<pool> -Name processModel.identityType` | The app pool identity type (see below) |

App pool identity matters because it's the effective security context every request into that pool runs as:

| Identity type | Meaning | Forensic relevance |
|---|---|---|
| `ApplicationPoolIdentity` (default since IIS 7.5) | A per-pool virtual account (`IIS AppPool\<PoolName>`), least-privilege by default | Baseline/expected — a web shell running under this context still only has this pool's rights, which bounds (but doesn't eliminate) impact |
| `NetworkService` | Shared, lower-privileged built-in account | Legacy default; multiple pools running under the same shared identity blur attribution between sites |
| `LocalSystem` | Full SYSTEM privilege | 🔴 A web application running its worker process as `LocalSystem` is a severe over-privilege finding independent of any compromise — flag on sight |
| Custom account (domain or local) | Credentials stored in `applicationHost.config` (`processModel/@userName`, `@password`), encrypted at rest via `aspnet_regiis -pe`/protected configuration | If the box is compromised with sufficient privilege, these credentials can be decrypted in place (`aspnet_regiis -px`) — see Step 7; a custom identity with domain rights turns a web app compromise into a credential-theft/lateral-movement pivot |

#### PowerShell

Obtain a full site/pool/binding inventory:

```powershell
Import-Module WebAdministration
Get-Website | Select-Object Name, ID, State, PhysicalPath, ApplicationPool
Get-ChildItem IIS:\AppPools | Select-Object Name, State
Get-WebBinding | Select-Object protocol, bindingInformation, ItemXPath
```

Join sites to their app pool's identity type, so a shared/over-privileged identity surfaces without manually cross-referencing two lists:

```powershell
Get-Website | ForEach-Object {
    $pool = $_.ApplicationPool
    $identity = Get-ItemProperty "IIS:\AppPools\$pool" -Name processModel.identityType -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Site         = $_.Name
        SiteID       = $_.ID
        AppPool      = $pool
        IdentityType = $identity.Value
        PhysicalPath = $_.PhysicalPath
    }
}
```

Map every currently running `w3wp.exe` PID to its app pool, the artifact you'll need constantly in Step 8:

```powershell
& "$env:windir\system32\inetsrv\appcmd.exe" list wp
# Or, staying in native PowerShell:
Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" | Select-Object ProcessId, CommandLine
```

### Step 3 — Locate the Log Files

Default location, current IIS: `%SystemDrive%\inetpub\logs\LogFiles\W3SVC<SiteID>\`. Legacy/IIS 6 default: `%WinDir%\System32\LogFiles\W3SVC<SiteID>\`. Both are configurable per site — always confirm the actual configured path rather than assuming the default, especially on a box that's been re-platformed or hardened.

**Site ID → friendly name** is the mapping most analysts trip over: the log folder is named by numeric site ID (`W3SVC1`, `W3SVC2`, …), not by the site's display name. Get the mapping from `appcmd list sites` or `Get-Website | Select Name, ID` (Step 2) before assuming which folder belongs to which application.

| Log format | Description | Forensic note |
|---|---|---|
| **W3C Extended** (default) | Space-delimited, ASCII, customizable field set defined by the `#Fields:` directive at the top of each file | The format this note is built around — flexible, but the flexibility is exactly the gotcha in Step 4 |
| **IIS (Microsoft) log format** | Fixed comma-delimited field set, legacy | Deprecated but still seen on old boxes; field order is fixed, no `#Fields:` directive to check |
| **NCSA Common Log Format** | Fixed, Apache-style, legacy | Minimal fields (no user agent, no referer) — least useful format for hunting, but sometimes the only option on very old configs |
| **Centralized Binary Logging (CBL)** | One binary `.ibl` file for *all* sites on the box, rather than one text log per site | 🔴 Breaks the "one folder per site" assumption entirely and is not human-readable or `Import-Csv`-parseable — requires Log Parser (or an equivalent binary-log-aware tool) to read. Check `appcmd list config` / the `<centralW3CLogFile>` section of `applicationHost.config` before assuming a per-site log layout |
| **ODBC logging** | Logs written directly to a database instead of flat files | Rare in modern deployments; if configured, the "log files" for this note are rows in a DB table — check the connection string in `applicationHost.config` |

**Rotation policy** — configured per site (`Period`: Hourly / Daily / Weekly / Monthly, or `TruncateSize` for size-based rollover) — directly determines whether the log covering your incident window still exists. An hourly-rotating site with aggressive log-cleanup or limited disk space can lose the exact hour you need before you ever get to the box. Check the earliest available log timestamp in the target folder **immediately**, before doing anything else, and check whether logs are shipped off-box to a SIEM/central collector as a backup source if the local copy is gone.

**A log source most analysts forget:** `%SystemDrive%\Windows\System32\LogFiles\HTTPERR\` — the kernel-mode HTTP.sys error log. This captures requests that were rejected or failed *before* they ever reached IIS/W3SVC (malformed requests, some scanning/DoS-shaped traffic, certain connection-level failures), so it will contain activity that never appears in the W3C site logs at all. It uses its own fixed space-delimited format (not W3C, no `#Fields:` directive) and its own status vocabulary (e.g. `Connection_Dropped`, `Timer_ConnectionIdle`) — worth a pass alongside the W3C logs, not a replacement for them.

#### PowerShell

Resolve every site's log directory and earliest/latest available log, so you know your actual evidentiary window before hunting anything:

```powershell
Get-Website | ForEach-Object {
    $logDir = Join-Path (Get-ItemProperty "IIS:\Sites\$($_.Name)" -Name logFile.directory).Value "W3SVC$($_.ID)"
    $logDir = [System.Environment]::ExpandEnvironmentVariables($logDir)
    $files = Get-ChildItem $logDir -Filter *.log -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Site        = $_.Name
        SiteID      = $_.ID
        LogDir      = $logDir
        EarliestLog = ($files | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
        LatestLog   = ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
    }
}
```

Confirm whether Centralized Binary Logging is in play before assuming the per-site folder layout:

```powershell
& "$env:windir\system32\inetsrv\appcmd.exe" list config -section:system.applicationHost/log
```

### Step 4 — Read the Logs: Format and Field Reference

| Field | Meaning | Forensic relevance |
|---|---|---|
| `date` / `time` | UTC timestamp of the request (server local time only if explicitly configured otherwise) | Confirm which clock this is against your incident timeline — W3C logs are UTC by default regardless of server locale |
| `s-ip` | Server IP that received the request | Distinguishes which binding/interface was hit on a multi-homed box |
| `cs-method` | HTTP method (`GET`, `POST`, `PUT`, …) | See Step 5 — unusual methods are a direct hunt signal |
| `cs-uri-stem` | Requested path, no query string | The "which file/handler" half of the request |
| `cs-uri-query` | Query string | Where injection attempts, encoded commands, and web-shell parameters (`cmd=`, `p=`) usually live |
| `s-port` | Port the request hit | Confirms HTTP vs HTTPS binding, or a non-standard port |
| `cs-username` | Authenticated username, if any | `-` for anonymous access — do not read a populated value as automatic attribution without checking the site's auth type |
| `c-ip` | **Client** IP — the requester | The primary pivot field for Step 5's IP-frequency hunts |
| `cs(User-Agent)` | Client-supplied User-Agent string | Trivially spoofed, but still a useful clustering/outlier field — see Step 5 |
| `cs(Referer)` | Client-supplied referring URL | Also spoofable; useful for spotting direct/no-referer access to a page that should only ever be reached via in-app navigation |
| `sc-status` | HTTP status code returned | 200/404/500 distribution — see Step 5 |
| `sc-substatus` | IIS sub-status | 🔴 High-value and often overlooked — e.g. `404.7` means Request Filtering blocked the request by file extension. A blocked attempt is still an attempt worth investigating, even though the site log's `sc-status` alone reads as an ordinary 404 |
| `sc-win32-status` | Underlying Win32 error code | Distinct from `sc-status` — an OS-level result code, useful for distinguishing "app returned an error" from "OS-level failure" |
| `time-taken` | Request processing time in milliseconds | Outlier-hunting field — see Step 5 |

🔴 **The field set above is the common default, not a guarantee.** IIS logging is fully customizable per site, and the actual fields present — and their order — are declared in the `#Fields:` directive at the top of every log file:

```
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2026-07-15 00:00:00
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```

**Always parse this line before assuming a schema.** A site with a trimmed-down field set (no `cs(Referer)`, no `cs-username`), or one where a field was added mid-deployment, will silently break any script that hardcodes column positions or names — and different sites on the same box can have different `#Fields:` lines. Step 5's `Import-IISLog` helper reads this line dynamically for exactly this reason.

### Step 5 — Hunt the Logs

This is the core analytical work of an IIS investigation — no third-party tool required, though Log Parser Studio (see Tooling) is worth reaching for once native pipelines get slow across a very large log set.

#### PowerShell

Create a reusable log-ingestion helper that reads the `#Fields:` directive dynamically (per the Step 4 gotcha) instead of assuming a fixed schema, and skips comment lines:

```powershell
function Import-IISLog {
    param([Parameter(Mandatory)][string]$Path)
    $fieldsLine = Get-Content $Path -TotalCount 10 | Where-Object { $_ -match '^#Fields:\s*(.+)$' }
    if (-not $fieldsLine) { throw "No #Fields: directive found in $Path - confirm this is a W3C Extended log, not IIS/NCSA/CBL format" }
    $headers = ($Matches[1]) -split '\s+'
    Import-Csv -Path $Path -Delimiter ' ' -Header $headers | Where-Object { $_.($headers[0]) -notmatch '^#' }
}

# Load every log for one site into memory for the pipelines below
$logs = Get-ChildItem 'C:\inetpub\logs\LogFiles\W3SVC1' -Filter *.log |
    ForEach-Object { Import-IISLog $_.FullName }
```

Run the core hunt pipelines against `$logs` from above. Each query pairs with what the result means:

```powershell
# Top user agents - establishes the "normal" baseline (browsers, known crawlers/monitors) to hunt against
$logs | Group-Object 'cs(User-Agent)' | Sort-Object Count -Descending | Select-Object -First 20 Count, Name

# Rare/unique user agents - hand-crafted tooling (curl, python-requests, custom scanners, empty/blank UA) clusters here, not in the top-N noise
$logs | Group-Object 'cs(User-Agent)' | Sort-Object Count | Select-Object -First 20 Count, Name

# Most-requesting client IPs - legitimate high-volume clients (load balancers, monitors, real users) vs. a scanner/brute-forcer
$logs | Group-Object c-ip | Sort-Object Count -Descending | Select-Object -First 20 Count, Name

# Rarest/single-hit client IPs - a one-off request from an otherwise-unseen IP to a sensitive path is a classic exploit-attempt shape
$logs | Group-Object c-ip | Where-Object Count -eq 1 | Select-Object Name, @{N='Sample';E={$_.Group[0].'cs-uri-stem'}}

# Filter to a specific incident time window - bound everything else below to this once you have a suspected window
$start = Get-Date '2026-07-15 00:00:00'; $end = Get-Date '2026-07-16 23:59:59'
$window = $logs | Where-Object { $ts = [datetime]"$($_.date) $($_.time)"; $ts -ge $start -and $ts -le $end }

# Status-code distribution - 404 floods = recon/path brute-forcing; unexpected 200s = something answered that shouldn't have; 5xx spikes = exploit attempts crashing the app
$logs | Group-Object sc-status | Sort-Object Count -Descending | Select-Object Count, Name

# Sub-status detail on 404s specifically - separates "genuinely missing" (404.0) from "blocked by Request Filtering" (404.7) attempts worth investigating anyway
$logs | Where-Object sc-status -eq 404 | Group-Object sc-substatus | Select-Object Count, Name

# Longest time-taken requests - slow server-side processing can mean a webshell running a command, or a timing-based injection attempt
$logs | Sort-Object { [int]$_.'time-taken' } -Descending | Select-Object -First 20 date, time, c-ip, cs-uri-stem, cs-uri-query, 'time-taken'

# Unusual HTTP methods - PROPFIND/PUT/MOVE/COPY/SEARCH indicate WebDAV enumeration or abuse; DEBUG/TRACE are rarely legitimate
$logs | Group-Object cs-method | Sort-Object Count
$logs | Where-Object cs-method -in @('PROPFIND','PUT','DEBUG','TRACE','MOVE','COPY','SEARCH')

# POST requests to unexpected/static-looking extensions - a common webshell-disguise pattern (e.g. image.jpg.aspx, config.txt with embedded code)
$logs | Where-Object { $_.'cs-method' -eq 'POST' -and $_.'cs-uri-stem' -match '\.(jpg|jpeg|png|gif|txt|css|ico|bmp)$' }

# Requests to script extensions the site shouldn't be serving at all (e.g. .php landing on an ASP.NET-only site) - a strong outlier
$logs | Where-Object { $_.'cs-uri-stem' -match '\.(php|jsp|cgi)$' } | Group-Object cs-uri-stem | Sort-Object Count
```

Perform a cross-log, time-bounded, multi-site webshell-pattern sweep, and use the string-search primitive when you need raw `Select-String` across files that don't need the field-aware parsing above:

```powershell
# Regex sweep for webshell request shapes across every log on the box, not just one site
Get-ChildItem 'C:\inetpub\logs\LogFiles' -Recurse -Filter *.log |
    Select-String -Pattern 'cmd=|eval\(|assert\(|base64_decode|FromBase64|\.\./\.\./|whoami|net\suser|certutil\s.*-decode|powershell\s.*-e' -CaseSensitive:$false |
    Select-Object Path, LineNumber, Line

# Combine multiple sites' logs, bounded to the incident window, deduped by IP + URI stem to spot repeated probing
$allLogs = Get-ChildItem 'C:\inetpub\logs\LogFiles' -Recurse -Filter *.log |
    ForEach-Object { Import-IISLog $_.FullName }
$allLogs | Where-Object { $ts = [datetime]"$($_.date) $($_.time)"; $ts -ge $start -and $ts -le $end } |
    Group-Object c-ip, cs-uri-stem | Sort-Object Count -Descending | Select-Object -First 30 Count, Name
```

🔴 If the box uses **Centralized Binary Logging** (Step 3), none of the `Import-Csv`-based pipelines above work against the raw `.ibl` file — fall back to Log Parser (see Tooling) or export to W3C format first if the tooling supports it.

### Step 6 — Web Shell Detection

**Filesystem sweep.** Freshly dropped or modified files under the web root are the fastest lead — sort by `LastWriteTime` (or `CreationTime`, since a web shell's *creation* time is often more meaningful than a last-write, unlike a config an admin might routinely re-save) and look for anything that doesn't belong:

```powershell
Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -File |
    Sort-Object CreationTime -Descending | Select-Object -First 50 FullName, CreationTime, LastWriteTime, Length
```

Signals worth weighting heavily:

- **Extension mismatch with the site's actual stack** — a `.php` or `.jsp` file appearing on a pure ASP.NET site, or vice versa.
- **Double extensions** — `image.jpg.aspx`, `report.pdf.asp`. IIS resolves the *rightmost* extension for handler mapping, so the file executes as script despite looking like a static asset in a directory listing.
- **Very small file size for a "functional" script** — the well-known China Chopper web shell is a notorious example: its ASPX/PHP payload is on the order of tens of bytes (a single `eval(Request[...])`-style line), tiny enough to be trivially missed by anyone eyeballing file sizes for something "substantial."
- **Filenames that don't match the deployment's naming convention** — random alphanumeric strings, generic names (`temp.aspx`, `x.aspx`, `1.asp`) dropped alongside a normal, consistently-named application's files.
- **Baseline diff against known-good** — compare a file hash set against the last known-good deployment package (source control checkout, WDeploy/MSDeploy package, or a prior backup) rather than relying on eyeballing alone:

```powershell
$current = Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -File | Get-FileHash
$baseline = Import-Csv 'C:\hunt\known_good_hashes.csv'   # pre-built from a trusted deployment artifact
Compare-Object $baseline.Hash $current.Hash | Where-Object SideIndicator -eq '=>' |
    ForEach-Object { $current | Where-Object Hash -eq $_.InputObject }
```

**The process-tree tell.** This is the single highest-confidence indicator in the whole note. `w3wp.exe` serves requests through its own request pipeline (ISAPI/managed modules, ASP.NET, etc.) — it has essentially no legitimate reason to spawn a shell or scripting-host process as a child:

```
services.exe
 └─ svchost.exe  (WAS - Windows Process Activation Service)
      └─ w3wp.exe            IIS worker process, running as the app pool identity
           └─ cmd.exe                         🔴 ALMOST NEVER LEGITIMATE
                └─ powershell.exe -enc ...     🔴 webshell executing an attacker-supplied command
                     └─ whoami.exe / net.exe / certutil.exe   🔴 recon, staging, or download-and-execute
```

Any `cmd.exe`, `powershell.exe`, `cscript.exe`, or `wscript.exe` child of `w3wp.exe` deserves immediate investigation — pull the full command line via 4688 (Step 8, cross-link note 11) to see exactly what was executed.

#### PowerShell

Use the Hunt Evil query, expanded to include the command line for context:

```powershell
$w3wpPids = (Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'").ProcessId
Get-CimInstance Win32_Process |
    Where-Object { $_.ParentProcessId -in $w3wpPids -and $_.Name -in @('cmd.exe','powershell.exe','powershell_ise.exe','cscript.exe','wscript.exe','mshta.exe') } |
    Select-Object ProcessId, Name, ParentProcessId, CommandLine, CreationDate
```

Follow an evidence-first approach: preserve the suspect file and process state before touching anything, then contain:

```powershell
# Preserve the suspect file (copy, don't move, and hash it) before any remediation touches it
Copy-Item 'C:\inetpub\wwwroot\app\images\image.jpg.aspx' 'C:\hunt\evidence\' -Force
Get-FileHash 'C:\inetpub\wwwroot\app\images\image.jpg.aspx' | Format-List

# Stop the affected app pool to halt further execution without deleting evidence
Stop-WebAppPool -Name '<AffectedPool>'

# Quarantine (rename/move out of the served path) rather than delete outright, until analysis is complete
Move-Item 'C:\inetpub\wwwroot\app\images\image.jpg.aspx' 'C:\hunt\quarantine\image.jpg.aspx.bak'
```

### Step 7 — Config-Based Persistence and Backdoors

Not every IIS compromise drops a file with a shell extension sitting in a web-browsable folder. Several config-based techniques let an attacker execute code through IIS without ever creating something that looks like "a web shell" to a filesystem sweep:

| Mechanism | Location | How it's abused |
|---|---|---|
| **Handler mappings** | `web.config` → `<system.webServer><handlers>` | Maps a file extension to a handler/module that executes it. An attacker can map an otherwise-static extension (e.g. `.jpg`, `.txt`) to an executable handler, turning an innocuous-looking uploaded file into executable code — no separate "shell file" with a suspicious extension ever needs to exist |
| **HTTP modules** | `web.config` or `applicationHost.config` → `<system.webServer><modules>` | Registers a managed module DLL that runs on every request to the site (via `Application_BeginRequest`-equivalent pipeline hooks). A malicious module intercepts and executes attacker input on **every** request, with no distinguishable "shell URL" to find at all |
| **Global modules** | `applicationHost.config` → `<system.webServer><globalModules>` | Server-wide native-code module registration, affecting **every site and pool on the box**, not just one application. Compare registered `<add name= image=/>` entries against a known-good baseline and check the DLL's signature |
| **ISAPI filters/extensions** | `applicationHost.config` → `<isapiFilters>`, `<system.webServer><isapiCgiRestriction>` | Legacy native-code mechanism, still abused where present — a rogue ISAPI filter runs against every request before it reaches managed code |
| **`Global.asax`** | Site root, `Application_Start` / `Application_BeginRequest` | 🔴 Especially stealthy: code placed here runs at application startup or on every request, without needing a URL an attacker (or an analyst) would ever navigate to directly. Check its modification time against the deployment baseline and review its content for `Eval`, `Process.Start`, or base64-decoded blocks |
| **App pool identity credentials** | `applicationHost.config` → `<processModel userName= password=/>`, encrypted via `aspnet_regiis -pe`/protected configuration | An attacker with sufficient local privilege can decrypt these in place (`aspnet_regiis -px`) — if the identity is a domain account, this converts a web-app compromise directly into stolen domain credentials for lateral movement |

#### PowerShell

Pull every registered global module and flag ones whose image path isn't under the expected system directories, and check `Global.asax` last-write time against site deployment:

```powershell
& "$env:windir\system32\inetsrv\appcmd.exe" list config -section:system.webServer/globalModules

Get-ChildItem 'C:\inetpub\wwwroot' -Recurse -Filter Global.asax |
    Select-Object FullName, CreationTime, LastWriteTime
```

Diff a site's `web.config` handler mappings against a known-good copy:

```powershell
[xml]$current  = Get-Content 'C:\inetpub\wwwroot\app\web.config'
[xml]$baseline = Get-Content 'C:\hunt\known_good\web.config'
Compare-Object ($baseline.configuration.'system.webServer'.handlers.add.name) ($current.configuration.'system.webServer'.handlers.add.name)
```

Revert config changes from a known-good copy and rotate any custom app pool identity credentials that may have been exposed:

```powershell
# Evidence-first: preserve the current (possibly backdoored) config before overwriting
Copy-Item 'C:\Windows\System32\inetsrv\config\applicationHost.config' 'C:\hunt\evidence\applicationHost.config.bak'

# Restore from known-good, then recycle the pool to pick up the change
Copy-Item 'C:\hunt\known_good\web.config' 'C:\inetpub\wwwroot\app\web.config' -Force
Restart-WebAppPool -Name '<AffectedPool>'
```

### Step 8 — Correlate with Process, Network, and Event Evidence

The log-and-filesystem work above establishes *what request* likely delivered or triggered a compromise. This step ties it to host-level execution and network evidence, and to any other log sources on the box the earlier steps don't cover.

| Evidence source | What it adds | Where covered |
|---|---|---|
| Security log 4688 (process creation), filtered to `w3wp.exe`-spawned children | Full command line of whatever `cmd.exe`/`powershell.exe` a web shell executed — requires command-line auditing GPO to be enabled (see Step 6's process-tree finding) | [`11 - Event Log Analysis` § Process Creation — 4688](<../11 - Event Log Analysis.md#process-creation--4688>) |
| Outbound network connections owned by a `w3wp.exe` PID | C2 beaconing or data exfiltration from a web shell — a worker process making outbound connections to anything other than expected backend services (database, internal APIs) is a strong signal | `Get-NetTCPConnection -OwningProcess <w3wp PID>`; full live-response methodology in [`16 - Live Response and Volatile Data`](<../16 - Live Response and Volatile Data.md>) |
| FTP logs (if the FTP Server role/service is installed) | A **separate** log location from HTTP: `%SystemDrive%\inetpub\logs\LogFiles\FTPSVC<SiteID>\` — FTP brute-force or anonymous-upload abuse is a common delivery path for a web shell that then gets served over HTTP from the same content root | Same W3C-style field/format reasoning as Step 4 applies to FTP logs, distinct log folder |
| `HTTPERR` logs | Requests HTTP.sys rejected before reaching W3SVC — see Step 3 | Step 3 above |
| Execution evidence for whatever the shell launched (Prefetch, ShimCache, Amcache) | Confirms an executable named in a 4688 event or process listing actually ran, with first/last-seen timing | [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>) |
| Memory-resident/fileless web shell variants | Some web shells inject into or run entirely within the `w3wp.exe` process without ever writing a persistent file — the filesystem sweep in Step 6 will not find these | [`17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`](<../17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md>) |
| Database backend activity, if the web app has a SQL Server backend | A web shell or SQL-injection chain frequently pivots into the database tier — separate investigation with its own log sources | `SQL Server Forensics.md` (this folder) |

#### PowerShell

```powershell
# 4688 events whose parent process was w3wp.exe - requires command-line auditing GPO enabled (note 11)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
    Where-Object { $_.Properties[13].Value -match 'w3wp\.exe' } |
    Select-Object TimeCreated, @{N='NewProcess';E={$_.Properties[5].Value}}, @{N='CommandLine';E={$_.Properties[8].Value}}, @{N='ParentProcess';E={$_.Properties[13].Value}}

# Outbound connections owned by any w3wp.exe PID right now
$w3wpPids = (Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'").ProcessId
Get-NetTCPConnection | Where-Object { $_.OwningProcess -in $w3wpPids -and $_.State -eq 'Established' } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
```

## Investigative Sequence Summary

```
1. Confirm IIS presence & version
   W3SVC service + InetStp registry key + appcmd.exe/WebAdministration module
                    │
2. Enumerate topology
   appcmd list sites/apppools/vdirs · applicationHost.config · app pool identity type
                    │
3. Locate the logs
   %SystemDrive%\inetpub\logs\LogFiles\W3SVC<SiteID>\ · site ID → friendly name
   · format (W3C/IIS/NCSA/CBL) · rotation policy vs. incident window · HTTPERR
                    │
4. Read the logs
   Parse the #Fields: directive - never assume the schema · W3C field reference
                    │
5. Hunt the logs
   Top & rare UA/IP · time-window filter · webshell string/regex sweep
   · status/sub-status distribution · time-taken outliers · unusual methods
   · POST-to-static-extension
                    │
6. Web shell detection
   wwwroot sweep by Creation/LastWriteTime · suspicious/double extensions
   · baseline hash diff
   🔴 w3wp.exe spawning cmd.exe/powershell.exe
                    │
7. Config-based persistence
   web.config handlers/modules · applicationHost.config global modules · ISAPI
   · Global.asax · app pool identity credential exposure
                    │
8. Correlate with process/network/event evidence
   4688 for w3wp.exe children (note 11) · outbound connections from w3wp.exe
   · FTPSVC logs · HTTPERR · execution evidence (note 06) · memory-resident
   variants (note 17) · SQL Server backend (this folder)
                    │
9. Hand off
   Config/credential remediation (note 21) · lateral movement if dropped
   tools or stolen app pool credentials reached other hosts (note 12)
```

## Pitfalls

| 🔴 Pitfall | Why it matters |
|---|---|
| Trusting `cs-username` as attacker attribution | Anonymous access logs `-`; even when populated, it's the *authenticated web-app* user, not necessarily the true requester — verify the site's auth type before drawing conclusions |
| Assuming log rotation preserved the incident window | Hourly/size-based rotation plus limited retention can mean the exact hour you need is already gone — check the earliest available log timestamp first, and look for a SIEM/central log-shipping pipeline as a backup source |
| Hardcoding a field schema instead of reading `#Fields:` | Different sites — or the same site after a config change — can have different field sets and orders; a hardcoded column assumption silently misattributes data |
| Assuming a per-site log folder layout | Centralized Binary Logging consolidates every site into one binary `.ibl` file; confirm the logging configuration before assuming `W3SVC<ID>\` folders exist per site |
| Ignoring HTTP.sys-level rejections | Malformed or blocked requests that never reach W3SVC don't appear in the W3C site logs at all — check `HTTPERR` for that layer |
| Reading `sc-status` 200 as automatically benign | A successful web-shell request returns 200 like any legitimate request — status code alone never substitutes for path/method/UA context |
| Assuming one `w3wp.exe` PID persists for a site across the whole window | App pools recycle (scheduled, on-demand, or after a crash), producing a new PID; enumerate all `w3wp.exe` instances and their app pool mapping (`appcmd list wp`) across the full incident window, not just the currently-running one |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `w3wp.exe` spawning `cmd.exe`, `powershell.exe`, `cscript.exe`, or `wscript.exe` | Almost never legitimate — the single highest-confidence web-shell indicator covered in this note |
| Recently created file under `wwwroot` with a double extension or a size in the tens-of-bytes range | Classic web-shell disguise and minimal-footprint pattern (e.g. China Chopper–style payloads) |
| Script extension present that doesn't match the site's actual technology stack | `.php`/`.jsp` on an ASP.NET-only site (or the reverse) has no legitimate explanation |
| POST requests to static-looking extensions (`.jpg`, `.txt`, `.css`) | Handler-mapping abuse or a disguised shell file — static extensions have no business receiving POST bodies |
| Unusual HTTP methods (`PROPFIND`, `PUT`, `MOVE`, `COPY`, `DEBUG`, `TRACE`) | WebDAV enumeration/upload abuse or legacy protocol-level attacks |
| `sc-substatus` `404.7` (Request Filtering blocked by extension) | A blocked attempt is still an attempt — investigate what was being probed for |
| Global module, ISAPI filter, or `web.config` handler mapping not present in the known-good baseline | Config-based persistence that leaves no suspicious file in `wwwroot` at all |
| `Global.asax` modified outside the normal deployment cadence | Executes on every application start or request — one of the stealthiest backdoor placements available |
| App pool identity is `LocalSystem`, or a custom domain account with excess privilege | Over-privileged by default, and a high-value credential-theft target if the box is compromised |
| Outbound connection from a `w3wp.exe` PID to an unexpected destination | Web-shell C2 beaconing or exfiltration riding the worker process's own network context |

## MITRE ATT&CK Techniques Covered

| Technique | ID | Where in this note |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Initial compromise vector this whole note investigates the aftermath of |
| Server Software Component: Web Shell | T1505.003 | Step 6 — filesystem detection and the `w3wp.exe` process-tree tell |
| Application Layer Protocol: Web Protocols | T1071.001 | Step 8 — outbound connections from `w3wp.exe`, web-shell C2/exfil blending into normal HTTP(S) traffic |
| Ingress Tool Transfer | T1105 | Step 6/8 — web shell or follow-on tooling dropped/pulled onto the box via the compromised application |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Step 6/8 — `w3wp.exe` → `cmd.exe` |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Step 6/8 — `w3wp.exe` → `powershell.exe` |
| Valid Accounts | T1078 | Step 7 — app pool identity credential theft feeding reuse elsewhere on the estate |

Verify sub-technique numbering against the current ATT&CK Enterprise matrix — IDs evolve.

## Tooling

| Tool | Use |
|---|---|
| **`appcmd.exe`** (`%windir%\system32\inetsrv\`) | The scriptable command-line surface for every piece of IIS topology covered in Steps 1–2 — works over a remote shell with no GUI required |
| **`WebAdministration`** / **`IISAdministration`** PowerShell modules | Native cmdlet access to sites, app pools, bindings, and the `IIS:` PSDrive |
| **IIS Manager (`inetmgr.exe`)** | GUI inspection when an interactive session is available; not always practical mid-incident |
| **Log Parser / Log Parser Studio** (Microsoft, unsupported but still widely used) | SQL-like querying across large or Centralized-Binary-Logging log sets faster than native pipelines at scale; also the standard way to read `.ibl` binary logs |
| **`aspnet_regiis.exe`** | Encrypts/decrypts protected configuration sections (app pool identity credentials) — know it exists so you recognize what an attacker with local access could do with it |
| **Sysmon** | If deployed, Event ID 1 (process creation) and Event ID 3 (network connection) give richer, more reliable `w3wp.exe` child-process and outbound-connection visibility than 4688 alone, without depending on the command-line-auditing GPO |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full 4688 process-creation field mechanics and the command-line-auditing GPO dependency | [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md#process-creation--4688>) |
| Execution evidence (Prefetch/ShimCache/Amcache) for whatever a web shell launched | [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>) |
| Lateral movement if stolen app pool credentials or dropped tools reached other hosts | [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) |
| Live-response network/process enumeration on a possibly-still-active compromise | [`16 - Live Response and Volatile Data`](<../16 - Live Response and Volatile Data.md>) |
| Memory-resident/fileless web shell variants that never wrote a file for Step 6's sweep to find | [`17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`](<../17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md>) |
| The common IIS-plus-database backend pairing, once a web shell or SQLi chain pivots into the data tier | `SQL Server Forensics.md` (this folder) |
| Account/credential remediation once an app pool identity or admin credential is confirmed exposed | [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md>) |
| Reverse technique-to-evidence lookup across this whole module | [`00b - ATT&CK Windows to Evidence Map`](<../00b - ATT&CK Windows to Evidence Map.md>) |

## Resources

- MITRE ATT&CK **T1505.003** (Server Software Component: Web Shell) — https://attack.mitre.org/techniques/T1505/003/
- MITRE ATT&CK **T1190** (Exploit Public-Facing Application) — https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK **T1071.001** (Application Layer Protocol: Web Protocols) — https://attack.mitre.org/techniques/T1071/001/
- Microsoft Learn — IIS Logging Overview and W3C Extended Log File Format field reference
- Microsoft Learn — `applicationHost.config` reference and the IIS configuration hierarchy
- Microsoft Sysinternals / Log Parser Studio — https://learn.microsoft.com/sysinternals/ and Microsoft's Log Parser Studio download
- Publicly documented web shell families (e.g. China Chopper) — referenced conceptually in Step 6 for their known minimal-footprint pattern; no third-party payload content reproduced
