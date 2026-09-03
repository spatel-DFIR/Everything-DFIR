# Sliver — Detection and Hunting

Scope note: this file hunts for exactly what `03 - Source Evidence.md` and `04 - Target Evidence.md` already document — server/operator artifacts, the six C2 transports, `execute-assembly`/`sideload`/`spawn-dll`/`migrate`/`execute-shellcode`, named-pipe/TCP pivoting, `psexec` staging, and `procdump`-based LSASS access. It does not introduce hunting content for Sliver capabilities this note hasn't otherwise covered (e.g. `shell`/`getsystem`), even where third-party research below documents them — flagged inline where that research goes beyond this note's scope.

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

Sliver exposes more independently-toggleable evasion/customization axes than most tools in this repo (see `01 - Overview.md`'s Armor/evasion section): userland-hook patching (`--evasion`), PE-metadata spoofing (`--spoof-metadata`), in-process execution with AMSI/ETW patching (`--in-process` + `--amsi-bypass`/`--etw-bypass`), pluggable wire-format traffic encoders, and the structural choice to route through a named-pipe/TCP pivot with no direct target egress. Rank hunts by what survives the combination of these, not by treating every signal as equally durable:

| Rank | Signal | Survives `--evasion`/`--spoof-metadata`? | Survives `--in-process`+`--amsi-bypass`/`--etw-bypass`? | Survives traffic encoders / JARM randomization? | Survives named-pipe/TCP pivot (no direct egress)? |
|---|---|---|---|---|---|
| 1 (strongest) | Beacon/session check-in periodicity + per-transport protocol handshake shape (mTLS client-cert exchange, HTTP(S) request shape, DNS query cadence, WireGuard handshake) — Sysmon 3 / Zeek | ✅ Yes — neither flag touches the network layer | ✅ Yes | ⚠️ Partial — traffic encoders and JARM-randomization (an optional Sliver dev feature per the port9.org/Hunt & Hackett research below) defeat *content*-based fingerprints, but the underlying interval+jitter cadence and TLS/DNS/WG protocol shape itself persists | ❌ **No** — the pivoted host produces zero external network signal by design; redirect to the pivot host itself (rank 6) |
| 2 | JA4X TLS certificate-generation fingerprint on mTLS/HTTPS listeners | ✅ Yes | ✅ Yes | ✅ Yes by design — JA4X fingerprints the *code path* that generates the cert, not the randomized field values themselves, so it survives Sliver's own per-binary cert randomization (verified against [FoxIO's JA4+ writeup](https://blog.foxio.io/ja4+-network-fingerprinting), which used a driftnet.io JA4X feed to enumerate default Sliver C2s on the internet) | ⚠️ N/A for the pivoted host's internal traffic; unaffected on the still-externally-reachable pivot host |
| 3 | Sysmon 1 (Process Create) + parent-child lineage: `execute-assembly`/`sideload`/`spawn-dll`'s default sandboxed child (`notepad.exe`), `migrate` target, `psexec` service host process | ✅ Yes | ❌ **No** — `--in-process` on `execute-assembly` runs inside the implant's own already-existing process, no new process is ever created | ✅ Yes — encoders operate on the C2 wire format, not process creation | ✅ Yes — fires on the executing host regardless of pivot topology |
| 4 | Sysmon 8 (CreateRemoteThread) / Sysmon 10 (ProcessAccess) for `execute-shellcode`, `migrate`, `msf-inject` injecting into a separate PID | ✅ Yes | ✅ Yes — injecting into a *different* target PID still requires the same handle-open/write/thread-create sequence regardless of whether the source implant itself is running in-process | ✅ Yes | ✅ Yes |
| 5 | `psexec` service artifacts: Security 4697 / System 7045 (Service Installed) matching operator-chosen or default `--service-name`, plus the created service's binary running from `--binpath` (default `C:\Windows\Temp`) | ✅ Yes | N/A — `psexec` doesn't use the in-process/AMSI/ETW flag set | ✅ Yes | ✅ Yes — SMB/SCM reachability to the target is independent of the *operator's* C2 pivot topology |
| 6 | Named-pipe/TCP pivot artifacts themselves: Sysmon 17/18 (`\\.\pipe\<name>` create/connect) on the pivot host, Sysmon 3 to an *internal* (not external) IP for TCP pivot | ✅ Yes | N/A | ✅ Yes — pivot transport isn't wrapped in the same C2 application-layer encoding the rank-1/2 signals target | This **is** the rank-1 substitute when pivoting is in play — always relevant, not defeated by the thing it exists to compensate for |
| 7 (weakest) | Static binary indicators: package-path strings (`sliverpb`, `/sliver/`, `github.com/bishopfox/sliver/`), non-randomized JARM hash, PE version-info metadata | ❌ **No** — Go symbol-table obfuscation is **on by default** (per `01 - Overview.md`; `--skip-symbols` is the rare flag that would leave these strings intact, not the default state) and `--spoof-metadata` directly defeats PE-field matching | N/A | ❌ **No** — JARM randomization (where enabled) and any wire-format encoder both directly target this signal class | N/A |

**Build hunts on rank 1-2 where you have network visibility (Zeek/full-packet-capture chokepoints, egress proxies) — JA4X in particular is the one signal in this table explicitly designed by Sliver's own cert-randomization code to *not* be defeated by that same randomization, per the FoxIO research above. Where a candidate host shows implant-consistent process/injection behavior (ranks 3-5) but no matching external connection, pivot to rank 6 before concluding there's no C2 traffic — `04 - Target Evidence.md`'s "no direct egress" callout is exactly this scenario.**

## Hunting on Source

Commands below assume **PowerShell 7+ (`pwsh`)**, which runs natively on the Linux hosts most `sliver-server` deployments use (the framework itself is a single Go binary with no OS-specific server build requirement) — this lets one hunt syntax cover a Linux-hosted server, a Windows-hosted server, or an operator's own Windows/macOS client. Where `pwsh` has no first-class cmdlet for a Linux-only primitive (e.g. `lsof`, `ss`), the block shells out to the native tool directly.

```powershell
# 1. Identify a running sliver-server process and the SQLite DB it has open
#    (03 - Source Evidence.md: "The Server Database") — cross-platform via pwsh
Get-Process -Name 'sliver-server' -ErrorAction SilentlyContinue

# Linux/macOS server host:
& lsof -p (Get-Process -Name 'sliver-server' -ErrorAction SilentlyContinue).Id 2>$null |
  Select-String -Pattern '\.db$|sqlite'

# 2. Server config, CA/cert material, and HTTP C2 profile store — location is
#    configuration-dependent (03's "Server Configuration and Certificates"),
#    so search broadly by filename/path rather than assuming a fixed location
Get-ChildItem -Path / -Recurse -Force -ErrorAction SilentlyContinue -Include 'server.json' |
  Where-Object { $_.FullName -match 'sliver' }

# 3. Console logs and asciicast session recordings (v1.6.0+)
Get-ChildItem -Path / -Recurse -Force -ErrorAction SilentlyContinue -Include '*.log','*.cast' |
  Where-Object { $_.FullName -match 'sliver' }

# 4. Built-in audit log — most structured "who did what, when" record
Get-ChildItem -Path / -Recurse -Force -ErrorAction SilentlyContinue -Filter '*audit*' |
  Where-Object { $_.FullName -match 'sliver' }

# 5. Live listener jobs bound to server-configured ports — don't assume
#    defaults, cross-reference against a live `jobs` console capture if available
& ss -tlnp 2>$null | Select-String -Pattern ':8888|:80|:443|:53|:1337|:9898'
# Windows-hosted server or operator workstation equivalent:
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $_.LocalPort -in 8888,80,443,53,1337,9898 }

# 6. Operator client artifacts — imported .cfg (mTLS operator cert) and the
#    sliver-client local cache, on any machine that might be an operator client
Get-ChildItem -Path $HOME -Recurse -ErrorAction SilentlyContinue -Include '*.cfg' |
  Select-String -Pattern '"operator"|"ca_certificate"|"private_key"' -List
Get-ChildItem -Path "$HOME/.sliver-client" -Recurse -ErrorAction SilentlyContinue

# 7. Shell history for the operator-provisioning command (bash/zsh on the
#    server or a Linux operator box; PSReadLine on a Windows operator box)
Get-Content "$HOME/.bash_history","$HOME/.zsh_history" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'sliver-server|sliver-client|operator --name|--permissions|import.*\.cfg'
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'sliver-client|import.*\.cfg'
```

For live/recently-terminated `sliver-server` process memory (CA private key, active implant key material, in-flight beacon tasks not yet in the DB — per `03 - Source Evidence.md`'s Memory Forensics section), use a platform-appropriate acquisition tool (e.g. AVML/LiME on Linux) rather than a one-line hunt query — this is an acquisition step, not a search.

## Hunting on Target

```powershell
# 1. execute-assembly/sideload/spawn-dll default sandboxed-child pattern —
#    rank 3 in the priority table, defeated only by --in-process
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'notepad\.exe' -and $_.Message -notmatch 'explorer\.exe' }

# 2. CreateRemoteThread / ProcessAccess for execute-shellcode, migrate,
#    msf-inject — rank 4, survives --in-process because it targets injection
#    into a SEPARATE pid regardless of the source process's own execution mode
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=8,10} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'GrantedAccess' }
# GrantedAccess mask interpretation for LSASS specifically (procdump target)
# follows the same evidentiary logic as
# Purple Teaming/Mimikatz/sekurlsa (Credential Dumping)/04 - Target Evidence.md

# 3. migrate's defining signature — implant network behavior suddenly
#    originating from a process with no independent reason to make it
#    (04 - Target Evidence.md: "explorer.exe suddenly beaconing")
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'explorer\.exe|svchost\.exe|winlogon\.exe' }

# 4. psexec-staged service — rank 5. Verified default service metadata
#    (Microsoft Defender Experts, "Looking for the 'Sliver' lining", 2022-08-24):
#    DisplayName "Sliver", Description "Sliver implant", ImagePath matching
#    [a-zA-Z]:\windows\temp\[a-zA-Z0-9]{10}\.exe when the operator leaves
#    --service-name/--binpath at their defaults (both are operator-overridable
#    per 01 - Overview.md, so treat this as the DEFAULT-config pattern, not universal)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Sliver|windows\\temp\\[a-zA-Z0-9]{10}\.exe' }
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Sliver' }
# The underlying 3-step sequence (binary copy over SMB -> CreateServiceW ->
# StartServiceW) is the durable part per VMware/Broadcom's 2023-01 lateral-
# movement writeup — build detections on the SEQUENCE across Security 4688/
# 4697/System 7045 in a tight window, not on the service name/path alone,
# since both are operator-configurable strings

# 5. Named-pipe pivot — rank 6, the compensating signal when rank 1 shows
#    nothing (pivoted host has no direct egress)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\\\\.\\pipe\\' }

# 6. TCP pivot — a second, internal-only listening port (default 9898) with
#    inbound connections from the pivoted host, not an external one
Get-NetTCPConnection -LocalPort 9898 -ErrorAction SilentlyContinue

# 7. mTLS C2 callback — TCP 8888 is the source-verified generate/listener
#    default (01 - Overview.md); an outbound TLS handshake to it from a
#    process with no legitimate reason to make one is rank-1 territory
Get-NetTCPConnection -RemotePort 8888 -State Established -ErrorAction SilentlyContinue

# 8. DNS C2 — repeated queries to a single non-corporate parent domain,
#    encoded-looking subdomain labels (task/response data as DNS labels)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'QueryName: [a-z0-9]{20,}\.' }

# 9. WMI-based lateral movement via an Armory-installed extension (e.g.
#    SharpWMI, per VMware/Broadcom's alternative-lateral-movement note) —
#    only relevant if the engagement used an armory-installed WMI extension
#    rather than the built-in psexec command
Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' -MaxEvents 500 -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Win32_Process|Create' }

# 10. Static-artifact check — low-confidence UNLESS --skip-symbols was passed
#     (symbol obfuscation is on by DEFAULT, per 01 - Overview.md), so this is
#     a bonus check, not a primary hunt (rank 7 in the priority table).
#     Strings verified against Wazuh's published YARA indicators.
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include '*.exe','*.dll' |
  Select-String -Pattern 'sliverpb|github\.com/bishopfox/sliver' -List
```

### Network-layer fingerprints worth knowing (and where they conflict across sources)

| Fingerprint | Value/behavior | Source | Caveat |
|---|---|---|---|
| JA4X (mTLS/HTTPS cert) | Consistent across instances because it fingerprints the cert-generation code path, not field values | [FoxIO JA4+](https://blog.foxio.io/ja4+-network-fingerprinting) | Survives Sliver's own per-binary cert randomization by design — the strongest network signal in this table |
| JA4H (HTTP C2) | Default HTTP C2 config sets exactly 5 headers (`Host`, `User-Agent`, `Content-Length`, `Upgrade-Insecure-Requests`, `Accept-Encoding`); observed fingerprint prefix `po11cn050000_...` | [Webscout, "Dissecting JA4H for improved Sliver C2 detections"](https://blog.webscout.io/dissecting-ja4h-for-improved-sliver-c2-detections/) | A custom `--c2profile` (per `01 - Overview.md`) directly changes header shaping — treat this as a **default-config** fingerprint only |
| JARM (mTLS/HTTPS) | Example hashes documented for default configs; drifts by Go compiler version (two different hashes observed across Go 1.16.7 vs 1.17 builds) | [tofile.dev "Hunting Sliver"](https://blog.tofile.dev/2021/09/04/sliver.html), [port9.org](https://blog.port9.org/posts/fingerprinting-tls-servers/) | Sliver added an **optional JARM-randomization** feature per both sources — treat any single JARM hash as a fragile, config- and build-dependent IOC, not a fixed signature |
| HTTP response headers | `Cache-Control: no-store, no-cache, must-revalidate`, `Content-Type: application/octet-stream`, default 404 response | Microsoft, tofile.dev, port9.org (independently corroborated across 3 sources) | Consistent enough across sources to treat as a real default-config pattern |
| mTLS listener port | TCP **8888** | Source-verified (`01 - Overview.md`, `client/command/jobs/commands.go`) | Some third-party infra-scanning writeups ([Hunt & Hackett](https://www.huntandhackett.com/blog/hunting-for-a-sliver), Webscout) instead report `CN=operators`/`CN=multiplayer` certificates on **TCP 31337** — that port matches Sliver's separate multiplayer/operator-console channel, not the implant-facing `mtls` listener; don't conflate the two when building a network detection |
| WireGuard listener port | UDP **53** (per source-verified `01 - Overview.md`) | Source-verified | Wazuh's Sliver writeup instead lists UDP **51820** (the *standard* WireGuard protocol default) — this conflicts with the source-verified value; verify against the actual `wg` listener job configuration observed rather than assuming either number |

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ErrorAction SilentlyContinue -ScriptBlock {
  $hits = [System.Collections.Generic.List[object]]::new()

  # Rank 3: unexpected notepad.exe children (execute-assembly/sideload/spawn-dll default)
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'notepad\.exe' } | ForEach-Object {
      $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'notepad-child'; Time = $_.TimeCreated })
    }

  # Rank 5: service installs matching default Sliver psexec metadata
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Sliver|windows\\temp\\[a-zA-Z0-9]{10}\.exe' } | ForEach-Object {
      $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'psexec-service'; Time = $_.TimeCreated })
    }

  # Rank 1: established connections to the source-verified mTLS default port
  Get-NetTCPConnection -RemotePort 8888 -State Established -ErrorAction SilentlyContinue | ForEach-Object {
    $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'mtls-8888'; Time = (Get-Date) })
  }

  # Rank 6: named-pipe pivot creation/connection
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=17,18} -ErrorAction SilentlyContinue | ForEach-Object {
    $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'named-pipe-pivot'; Time = $_.TimeCreated })
  }

  $hits
}

# Group by host and signal — a host hitting MULTIPLE independent signal
# classes (e.g. notepad-child AND mtls-8888) in a tight window is a far
# stronger candidate than any single signal alone
$results | Group-Object Host, Signal | Sort-Object Count -Descending | Select-Object -First 30 Count, Name

$results | Export-Csv -Path .\sliver_sweep_results.csv -NoTypeInformation
```

## Remediation

**Capture evidence before acting.** Killing the implant process or isolating the host destroys exactly the volatile artifacts this note has emphasized as most valuable: the decrypted C2 config (transport endpoint, encryption keys) sitting in the implant's own memory (`04 - Target Evidence.md`'s Memory Forensics section), any `--in-process` `execute-assembly`/`sideload` output that never touched disk, and — on the server side, if reachable — the live task queue for any beacon whose results haven't checked in yet (`03 - Source Evidence.md`). Pull a memory image, Sysmon 1/3/8/10/17/18 events, and Security 4697/System 7045 events for the affected host(s) first.

Sliver itself isn't the thing to "fix" — it's a legitimate red-team framework riding legitimate OS mechanisms (TLS, DNS, SMB service creation, process injection APIs, Windows' own named-pipe IPC). The actual hardening targets are the access paths it rides, mapped to what this note has documented:

```powershell
# Command-line auditing for process creation — the single highest-value
# native control for this tool class; without it, Security 4688 can't
# corroborate the psexec service-name/binpath pattern or any injection
# command line at all:
# Computer Configuration > Administrative Templates > System > Audit
# Process Creation > "Include command line in process creation events" = Enabled

# Restrict SMB admin-share/service-creation access where it isn't
# operationally required — closes the psexec lateral-movement path this
# note documents (Security 4697/System 7045, and any SharpWMI-based
# armory-extension alternative):
# Computer Configuration > Windows Firewall > "File and Printer Sharing"
# inbound rule group — scope to management hosts only; restrict local
# Administrators-group membership to reduce viable psexec targets

# Egress filtering on non-proxy-aware transports — mTLS (default TCP 8888)
# and TCP-pivot (default 9898) both rely on direct outbound TCP to an
# operator-controlled host; a default-deny egress policy with an explicit
# allowlist for required business traffic forces both onto a proxied path
# where JA4X/JA4H fingerprinting (see table above) has visibility

# DNS security controls — since DNS C2 depends on delegated-domain
# resolution reaching an attacker-controlled authoritative server, a DNS
# security service (RPZ blocklists, DNS-over-HTTPS interception policy,
# or a resolver that logs/blocks encoded-looking subdomain query volume)
# closes the fallback transport documented for restrictive-egress environments

# LSASS protection (Credential Guard / RunAsPPL) — blunts the built-in
# procdump-based LSASS access path this note documents; see
# Purple Teaming/Mimikatz/sekurlsa (Credential Dumping)/05 - Detection and
# Hunting.md for the full LSASS-hardening treatment, which applies
# identically regardless of which tool is doing the dumping

# Ensure Sysmon is deployed with process (1), network (3), CreateRemoteThread
# (8), ProcessAccess (10), and pipe (17/18) events enabled — per the priority
# table above, this is the one native-logging source that reliably survives
# BOTH --in-process execution (via ranks 2/4/5/6) and default-config network
# fingerprinting (via rank 1/2), even where command-line auditing is off
```

Enabling Sysmon with the specific event-ID set above is the single highest-leverage compensating control from this note's perspective — no single evasion flag Sliver exposes (`--evasion`, `--in-process`, traffic encoders, JARM randomization) defeats all six of those event classes simultaneously, per the Hunting Priority table.
