# Hydra — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide / At-Scale Hunt](#fleet-wide--at-scale-hunt)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

Hydra exposes three real, distinct evasion levers: **timing** (`-c`/`-W`/`-t`, slow the rate of attempts), **spray shape** (`-e`/`-C` plus `-u`, spread attempts thin across many accounts instead of hammering one), and **transport** (`HYDRA_PROXY`/`HYDRA_PROXY_HTTP`, hide the true source IP). No single flag defeats every kind of detection — a defender's detection portfolio has to cover more than one axis, because an operator tuning for one (say, avoiding lockout via spray) doesn't automatically also defeat another (velocity-based alerting still fires on the fan-out pattern unless timing is *also* slowed).

| Rank | Signal | Survives `-c`/timing throttle? | Survives `-e`/`-C` spray (`-u`)? | Survives `HYDRA_PROXY`? | Notes |
|---|---|---|---|---|---|
| 1 | Native target-service authentication failure logs, correlated by **destination account/service** rather than source IP (e.g. many distinct accounts each failing once against the same service in a rolling window) | ✅ Yes — the *pattern*, not the speed, is what this looks for | ⚠️ **This is the exact pattern spray mode produces** — detects it directly, doesn't need to survive it | ✅ Yes — target-side, proxy doesn't change what the target logs about itself | The correct baseline signal for catching spray specifically; requires baselining "normal" per-account failure noise first so a genuine spray doesn't get lost in routine mistyped-password volume |
| 2 | Volume/velocity — attempt count against one account or one service per unit time, from one apparent source | ❌ **No** — `-c` (forcing `-t 1`, one attempt at a time across all threads) is built specifically to defeat this | ✅ Yes (partially) — still fires on any single account that does get repeated attempts, e.g. `-e s` against a small user list | ❌ No, per-proxy-hop — if attempts fan out across a proxy list, no single "source" accumulates a high count | The classic, most commonly deployed detection — also the easiest for an informed operator to route around with two of Hydra's three evasion levers |
| 3 | Source-IP reputation / geolocation / ASN anomaly | ✅ Yes | ✅ Yes | ❌ **No** — this is precisely what a proxy or proxy-list is for | Cheap, high-value as a first-pass filter, but trivially defeated by anyone who bothers to set `HYDRA_PROXY` |
| 4 | Account-lockout threshold (Event 4740 / equivalent) | ✅ Yes (irrelevant to timing) | ❌ **No** — spray mode's entire purpose is staying under this threshold per account | ✅ Yes (irrelevant to source IP) | Defeated by design whenever the operator chooses spray over single-account brute force; treat 4740 as a lagging indicator that catches only unsophisticated runs, not a primary control |
| 5 | Invalid-username / non-existent-account authentication attempts | ✅ Yes | ✅ Yes — spray mode inherently touches many accounts, increasing the odds of hitting a stale/non-existent one from a slightly outdated user list | ✅ Yes | Strong when it fires (no legitimate explanation exists), but depends on the operator's user list containing errors — a well-sourced list (e.g. built from `AdFind`/`BloodHound` output) may contain zero invalid accounts, producing no signal at all |
| — (weakest) | Hydra-specific file hash / static signature (the compiled `hydra` binary itself) | N/A | N/A | N/A | Hydra is widely available, open-source, and trivially recompiled from source with a different build fingerprint — treat this as effectively no signal at all, the same conclusion this repo has reached for every source-available/no-official-binary tool it covers |

**Build hunts on rank 1 first, specifically because it's the one signal that spray mode doesn't defeat — it's what spray mode looks like.** Rank 2 remains useful as a fast first-pass filter for unsophisticated/default-settings runs, but should never be the only detection in place given how directly `-c`/`-u` are built to route around it.

## Hunting on Source

These commands target the attacking host directly — most useful when responding to an incident where the attacking box itself (a compromised pivot host, or a red-team-owned system under a purple-team exercise) is in scope.

**Locate a `hydra.restore` file anywhere on the filesystem (per `03`, path is relative to wherever it was launched, not fixed):**

```powershell
# Windows-hosted Hydra build (Cygwin/WSL/compiled port)
Get-ChildItem -Path C:\ -Recurse -Filter "hydra.restore" -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime, @{N='Owner';E={(Get-Acl $_.FullName).Owner}}
```

```bash
# Linux/macOS attacking host
find / -name "hydra.restore" -exec stat -c '%Y %U %n' {} \; 2>/dev/null
```

**Shell-history sweep for Hydra invocations and proxy environment variables:**

```bash
grep -HiE 'hydra .*(-l|-L|-p|-P|-C|-x|-e )' ~/.bash_history ~/.zsh_history 2>/dev/null
grep -HiE 'HYDRA_PROXY' ~/.bash_history ~/.zsh_history ~/.bashrc ~/.zshrc 2>/dev/null
```

**Process/connection burst check (live-response, while a run may still be active):**

```bash
# Linux: a hydra process holding an unusually large number of concurrent
# outbound sockets to one destination
ss -tnp | grep hydra | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

```powershell
# Windows-hosted equivalent, any process with an anomalous fan-out of
# connections to a single destination port/service
Get-NetTCPConnection | Group-Object RemoteAddress, RemotePort |
    Where-Object Count -gt 15 |
    ForEach-Object { $_.Group | Select-Object -First 1 -Property OwningProcess, RemoteAddress, RemotePort, @{N='Count';E={$_.Count}} }
```

## Hunting on Target

**SMB/RDP (rank 1 pattern — account fan-out, per-service):**

```powershell
# Domain-controller/member-server sweep: many DISTINCT accounts each failing
# a small number of times against the same service, in a rolling window --
# the direct signature of -e/-C spray mode with -u
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)} |
    ForEach-Object { [PSCustomObject]@{ Account = $_.Properties[5].Value; SourceIP = $_.Properties[19].Value } } |
    Group-Object SourceIP |
    Where-Object { ($_.Group.Account | Sort-Object -Unique).Count -gt 10 } |
    Select-Object Name, @{N='UniqueAccounts';E={($_.Group.Account | Sort-Object -Unique).Count}}, Count
```

Cross-reference a positive hit against `Windows/Threat Landscape and Playbooks/RDP Brute-Force and Foothold Playbook.md`'s own 🎯 Hunt Evil block for the RDP-specific fail-then-success pivot check (Logon Type 10 4624 immediately following this pattern).

**SMB/RDP (rank 2 pattern — volume against one account/service):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)} |
    ForEach-Object { [PSCustomObject]@{ Account = $_.Properties[5].Value; SourceIP = $_.Properties[19].Value } } |
    Group-Object Account, SourceIP |
    Where-Object Count -gt 10 |
    Sort-Object Count -Descending
```

**SSH (adapted from `Linux/06 - Logs/Authentication and Login Records.md`'s Brute Force Detection section — apply that page's query directly, then split by account count for the spray-vs-brute-force distinction):**

```bash
# Rank 2 shape -- one account, many failures, one source
grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oP 'for \K\S+(?= from)' | sort | uniq -c | sort -rn | head

# Rank 1 shape -- one source, many DISTINCT accounts (the spray signature)
grep "Failed password" /var/log/auth.log 2>/dev/null | \
    awk '{ split($0,a,"from "); split(a[2],b," "); print b[1] }' | sort | uniq -c | sort -rn |
    awk '$1 > 10 {print $2}' | while read ip; do
        echo "$ip: $(grep "Failed password" /var/log/auth.log | grep "$ip" | grep -oP 'for \K\S+(?= from)' | sort -u | wc -l) distinct accounts"
    done
```

**HTTP(S) form/Basic auth (IIS target — adapted from `Windows/23 - Special Services/IIS - Web Server Forensics.md`'s log-hunting workflow):**

```powershell
# 401 bursts (Basic/Digest) grouped by client IP, or repeated identical
# response sizes to a login POST URI (form-based -- application-dependent)
Import-Csv -Delimiter ' ' -Path C:\inetpub\logs\LogFiles\W3SVC1\*.log |
    Where-Object { $_.'sc-status' -eq 401 } |
    Group-Object 'c-ip' | Where-Object Count -gt 20 | Sort-Object Count -Descending
```

**Invalid-username sweep (rank 5, works across SSH/SMB/RDP alike where the target's own logging distinguishes it):**

```powershell
# Windows: 4625 with a Sub Status indicating the account name itself doesn't exist (0xC0000064)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
    Where-Object { $_.Message -match '0xC0000064' } |
    Group-Object { $_.Properties[19].Value } | Where-Object Count -gt 3
```

## Fleet-Wide / At-Scale Hunt

Password spraying is inherently a multi-target activity in the realistic case (either many accounts on one service, or the same credential tried across many hosts/services) — a single-host hunt understates the picture. Sweep across the environment rather than one system at a time:

```powershell
# Domain-wide: one source IP authenticating (successfully or not) against an
# unusually large number of DISTINCT domain accounts within a short window,
# across every reachable DC's Security log -- the fleet-scale version of the
# rank-1 pattern above
$DCs = (Get-ADDomainController -Filter *).HostName
Invoke-Command -ComputerName $DCs -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddHours(-6)}
} -ErrorAction SilentlyContinue |
    ForEach-Object { [PSCustomObject]@{ Account = $_.Properties[5].Value; SourceIP = $_.Properties[19].Value; Success = ($_.Id -eq 4624) } } |
    Group-Object SourceIP |
    Where-Object { ($_.Group.Account | Sort-Object -Unique).Count -gt 20 } |
    Select-Object Name, @{N='UniqueAccounts';E={($_.Group.Account | Sort-Object -Unique).Count}}, @{N='AnySuccess';E={$_.Group.Success -contains $true}}

# Endpoint-side: the same one-source-many-accounts pattern against local
# SAM auth (non-domain accounts) across every workstation/server
Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-6)} |
        Where-Object { $_.Message -notmatch 'Logon Type:\s+2' }  # exclude interactive/console noise
} -ErrorAction SilentlyContinue
```

For internet-facing services (RDP, SSH, HTTP), also pull perimeter firewall/reverse-proxy/WAF logs for the same source-IP-vs-unique-account-count pattern — a spray against internet-exposed infrastructure frequently shows up there before (or instead of) generating enough individual host-level Windows/Linux events to stand out on any single system.

## Remediation

**Capture the full failure/success event window, the source IP(s), and (if the attacking host is in scope) the `hydra.restore` file and any `-o` output before taking any of the following actions** — resetting the compromised account's password or blocking the source IP outright can end an active session and destroy the evidence needed to scope what a successful pivot actually did.

- **Reset the password on any account confirmed to have authenticated successfully** during the identified attack window — do this after, not instead of, capturing the evidence above.
- **Do not rely on account lockout as a primary control** — per the Hunting Priority table, a spray run is specifically designed to never trip it; lockout stops the naive single-account case but provides no protection against the mode a competent operator will actually choose.
- **Enforce MFA on every externally-reachable authentication surface Hydra can target** — password-only auth on SSH, RDP, or a web login form is fully in-scope for every use case in `02`; MFA doesn't stop the guessing attempts themselves but removes their value even when a correct password is found.
- **Rate-limit and connection-cap at the service level** (`sshd`'s `MaxStartups`/`fail2ban`-style tools, web-server/WAF rate limiting, RDP's own connection-limiting where supported) — this directly targets the one axis (`-t`/`-c`) an operator can't fully route around without also slowing the attack to a crawl, unlike lockout thresholds which spray mode sidesteps entirely.
- **If a proxy/`HYDRA_PROXY` chain was identified**, treat the proxy endpoint itself as an indicator worth tracking (block/monitor), understanding it may be shared innocent infrastructure (a public VPN/Tor exit, a compromised third-party host) rather than attacker-owned.
- **Review whether the targeted account list itself leaked** — a spray run against a well-formed, low-invalid-username list (rank 5 in the Hunting Priority table produces little/no signal) is a strong indicator the operator already had accurate reconnaissance (an AD dump, a breached directory export, output from `AdFind`/`BloodHound`/`NetExec` enumeration) — worth investigating as its own, separate finding rather than treating the spray as the whole incident.
