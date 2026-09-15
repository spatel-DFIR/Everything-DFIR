# ngrok — Detection and Hunting

Scope note: this file hunts for exactly what `03 - Source Evidence.md` and `04 - Target Evidence.md` already document. ngrok's real operator-facing evasion surface is narrower than a fully customizable C2 framework's — there's no Malleable-style profile rewriting request content — but it does expose three genuine choices that change what survives: **domain tier** (ephemeral-random vs. free-static vs. paid-reserved/custom), **`NGROK_AUTHTOKEN` vs. config-file** authentication, and **binary rename**. Rank every signal by which of those it survives, not by treating every artifact as equally durable.

## Contents
- [Hunting Priority — What Survives Which Evasion Choice](#hunting-priority--what-survives-which-evasion-choice)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — What Survives Which Evasion Choice

| Rank | Signal | Survives a custom (paid) domain? | Survives binary rename? | Survives `NGROK_AUTHTOKEN`-only auth? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | DNS/TLS-SNI to the **control-channel** domain (`connect.<region>.ngrok-agent.com` / legacy `tunnel.<region>.ngrok.com`) | ✅ Yes — this connection is mandatory regardless of what public domain the operator pays for | ✅ Yes — network destination, independent of filename | ✅ Yes — unrelated to how the token is supplied | The one connection every ngrok agent makes no matter what, per `01 - Overview.md`'s architecture diagram — the single hardest signal to evade |
| 2 | DNS/TLS-SNI to an ngrok-owned public endpoint domain (`*.ngrok.io`, `*.ngrok.app`, `*.ngrok-free.app`, `*.ngrok-free.dev`) | ❌ **No** — a paid bring-your-own custom domain replaces this with the operator's own hostname entirely | ✅ Yes | ✅ Yes | Strong and simple, but the one signal an operator can fully defeat with a paid-plan feature — don't treat this as sufficient on its own for a mature threat actor |
| 3 | Sustained, long-lived outbound TCP 443 flow duration anomaly | ✅ Yes — flow-duration behavior is unrelated to which domain is used | ✅ Yes | ✅ Yes | Works even where TLS SNI itself isn't loggable (ECH, DoH bypassing local resolvers) — weaker precision (more false positives) but the hardest signal to remove entirely |
| 4 | Process command line (`ngrok http/tcp/tls ...`) | N/A | ❌ No — a renamed binary's command line no longer contains the literal string `ngrok` | ✅ Yes | Directly states operator intent (which port/service is exposed) when available, but trivially defeated by a rename + no `OriginalFileName`-equivalent confirmed for this binary (`04 - Target Evidence.md`) |
| 5 | `ngrok.yml` presence/content at the default OS path | N/A | N/A | ❌ **No** — an `NGROK_AUTHTOKEN`-only invocation never writes this file at all | Rich when present (authtoken, endpoint definitions) but the first thing a disk-evading operator skips |
| 6 (weakest standalone) | RDP (3389) or SMB (445) reachable via any TCP tunnel address at all | N/A | N/A | N/A | Near-zero legitimate justification in most enterprise environments (`04 - Target Evidence.md`'s Distinguishing section) — high-confidence **only** when paired with rank 1/2/3 confirming an ngrok tunnel is actually the delivery mechanism, not a standalone signal |

**Build primary hunts on ranks 1 and 3 wherever you have DNS/proxy/NetFlow visibility — they're the two signals a paid custom domain, a binary rename, and a disk-evading auth method all fail to remove simultaneously.** Rank 2 is usually the easiest and most precise hunt to stand up first, but flag it explicitly as defeatable by a paid feature rather than presenting it as durable. Ranks 4-5 are strong corroborating detail once a network-layer hit already exists, not a starting point on their own.

## Hunting on Source

Applies to whichever host is actually running the `ngrok` agent process — per `03 - Source Evidence.md`'s reframe, this may be the same host under investigation as the target of the intrusion (self-tunneled RDP/SMB) or a genuinely separate attacker-controlled machine.

```powershell
# 1. Process presence and command line — rank 4, defeated by rename
Get-CimInstance Win32_Process -Filter "Name='ngrok.exe'" |
  Select-Object ProcessId, CommandLine, CreationDate, ParentProcessId

# 2. Config file presence — rank 5, absent under NGROK_AUTHTOKEN-only deployments
Get-ChildItem "$env:LocalAppData\ngrok\ngrok.yml" -ErrorAction SilentlyContinue |
  ForEach-Object { Get-Content $_.FullName }

# 3. NGROK_AUTHTOKEN in the environment of a live process (disk-evading variant)
Get-CimInstance Win32_Process -Filter "Name='ngrok.exe'" | ForEach-Object {
  # Requires an EDR/live-response tool capable of reading a target process's
  # environment block, e.g. Get-ProcessEnvironmentVariable equivalents, or a
  # memory-acquisition + strings pass (03 - Source Evidence.md's Memory Forensics)
}

# 4. Persistent control-channel connection — rank 1, the hardest signal to evade
Get-DnsClientCache -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'ngrok-agent\.com$|\.ngrok\.com$' }
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Where-Object { $_.OwningProcess -eq (Get-Process ngrok -ErrorAction SilentlyContinue).Id }

# 5. Local inspection UI — live-response only, may not survive a restart
#    (03 - Source Evidence.md flags persistence-to-disk as an open question)
Invoke-RestMethod -Uri 'http://127.0.0.1:4040/api/requests/http' -ErrorAction SilentlyContinue

# 6. Shell history
Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue |
  Select-String 'ngrok|NGROK_AUTHTOKEN|config add-authtoken'

# 7. Service-registration artifact, if persistence was configured (01/02)
Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\ngrok' -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'ngrok' }
```

## Hunting on Target

Applies to the network-perimeter and (where the self-tunnel case applies) the exposed-service host's own logs — per `04 - Target Evidence.md`'s reframe, this is frequently the **only** available evidence when the host itself isn't recovered.

```powershell
# 1. Rank 1 — control-channel DNS, the hardest signal to remove
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'ngrok-agent\.com|tunnel\.\w+\.ngrok\.com' }

# 2. Rank 2 — public endpoint domain (defeated by a paid custom domain)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\.ngrok\.io|\.ngrok\.app|\.ngrok-free\.app|\.ngrok-free\.dev' }

# 3. Rank 3 — sustained-flow-duration anomaly (works even without a usable SNI/DNS log)
#    Query your NetFlow/Zeek conn.log for long-duration (multi-hour+) outbound TCP 443
#    flows to unfamiliar destinations — no ngrok-specific string match required

# 4. Rank 6, corroborating only — RDP/SMB tunneled through a non-standard learned
#    remote endpoint rather than the org's own known infrastructure
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Logon Type:\s*10' } |
  Select-String 'Source Network Address' # cross-reference against known-good RDP source ranges
```

Also query proxy/firewall logs directly for the same domain patterns as the Sysmon queries above — in most environments those logs cover far more hosts than Sysmon deployment reaches, and they're the primary source when the tunneled host itself was never recovered for endpoint forensics at all (`04 - Target Evidence.md`'s opening reframe).

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ErrorAction SilentlyContinue -ScriptBlock {
  $hits = [System.Collections.Generic.List[object]]::new()

  # Rank 4: process presence by name (defeated by rename — pair with network hits)
  Get-CimInstance Win32_Process -Filter "Name='ngrok.exe'" -ErrorAction SilentlyContinue |
    ForEach-Object {
      $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'ngrok-process'; CommandLine = $_.CommandLine })
    }

  # Rank 5: config file presence
  if (Test-Path "$env:LocalAppData\ngrok\ngrok.yml") {
    $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'ngrok-config-file'; Path = "$env:LocalAppData\ngrok\ngrok.yml" })
  }

  # Rank 1/2: DNS cache entries for either domain family
  Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'ngrok-agent\.com$|\.ngrok\.com$|\.ngrok\.io$|\.ngrok\.app$|\.ngrok-free\.(app|dev)$' } |
    ForEach-Object {
      $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'ngrok-dns-cache'; Name = $_.Name })
    }

  # Service-registration persistence check
  if (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\ngrok' -ErrorAction SilentlyContinue) {
    $hits.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; Signal = 'ngrok-installed-service' })
  }

  $hits
}

# A host hitting on both a network-layer signal (rank 1/2/3) AND a local
# artifact (rank 4/5) is far higher-confidence than either alone — a bare
# DNS-cache hit alone could reflect legitimate developer use per
# 04 - Target Evidence.md's Distinguishing section
$results | Group-Object Host | Sort-Object Count -Descending
$results | Export-Csv -Path .\ngrok_sweep_results.csv -NoTypeInformation
```

Cross-reference every hit against the organization's own approved developer-tooling baseline (which teams are permitted to use ngrok, for what purpose) before triage — presence alone means little in an environment where engineering teams use ngrok legitimately, the same caveat this module makes for every dual-use tool.

## Remediation

**Capture evidence before killing the process or isolating the host.** Terminating a live `ngrok` process loses the local inspection-UI request history (`03 - Source Evidence.md` flags this as possibly memory-only) and the live process environment (relevant to the `NGROK_AUTHTOKEN`-only deployment case) — pull both, plus `ngrok.yml` if present and the current `Get-NetTCPConnection` state, **before** terminating.

```powershell
# Immediately break the tunnel rather than waiting for a full host-isolation cycle
Stop-Process -Name ngrok -Force -ErrorAction SilentlyContinue

# If persistence was configured, remove the service registration too —
# killing the process alone leaves ngrok service install's auto-restart in place
ngrok.exe service stop
ngrok.exe service uninstall

# If the tunneled service itself (RDP/SMB) has no legitimate reason to be
# reachable at all, address that exposure directly rather than only the tunnel:
#  - Confirm RDP/SMB firewall scoping matches policy independent of this incident
#  - Rotate credentials for any account observed authenticating through the
#    tunneled RDP/SMB session (04 - Target Evidence.md's Windows Event Logs)

# Block egress to ngrok's control-channel and endpoint domains outright if
# ngrok is not part of the environment's approved developer-tooling baseline:
#   *.ngrok-agent.com, *.ngrok.com, *.ngrok.io, *.ngrok.app, *.ngrok-free.app, *.ngrok-free.dev
# (proxy/firewall category block or explicit domain blocklist — per
# 04 - Target Evidence.md's Distinguishing section, this is a policy decision,
# not a purely technical one, since legitimate developer use is common)
```

If ngrok **is** legitimately approved for developer use in the environment, tighten scope rather than banning the tool outright: restrict which hosts/user groups may reach the control-channel domain at all (the one connection no ngrok deployment can avoid, per the Hunting Priority table's rank-1 signal), and treat any tunnel touching RDP, SMB, or another sensitive internal service as requiring explicit change-management approval — the deployment target, not the tool's mere presence, is what should drive the alert.
