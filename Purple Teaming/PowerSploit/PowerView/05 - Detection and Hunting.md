# PowerView — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked by which of PowerView's own evasion/customization options survive each signal — **PowerShell-native logging first**, since that's this tool's dominant evidence class, then network/process signals that persist regardless of scripting-engine configuration.

| Rank | Signal | Survives disabled logging? | Survives AMSI bypass? | Survives in-memory-only load? | Survives fork obfuscation helpers? |
|---|---|---|---|---|---|
| 1 | DC-side LDAP connection **volume/fan-out** from a single source host (network-flow-level, not content) | Yes — network layer, not application logging | Yes | Yes | **Yes** — obfuscation only rewrites the filter string, not the connection count or timing |
| 2 | Event 400 (classic PowerShell channel) — session start + full `HostApplication` command line | **Yes** — on by default, no configuration required | Yes (command line is captured pre-execution) | Yes, if `powershell.exe` itself was launched (not if driven through an already-running C2 agent's PowerShell host) | Yes — obfuscation applies to the LDAP filter, not the invoking command line |
| 3 | SAMR fan-out pattern — one source host querying many computers' session/local-group state in a short window | Yes | Yes | Yes | Yes |
| 4 | Script Block Logging (4104) full content | **No** — off by default; defeated entirely if never enabled | **Partially** — the narrow Warning-level heuristic for hardcoded suspicious strings still fires even with full logging off, but is a documented, source-verified bypassable heuristic (see `LOLBins/powershell/02 - Hands-On Use Cases.md`) | No — never touches disk, but does pass through the engine that would log it if configured | Content-level filter obfuscation is irrelevant here since 4104 captures the *script*, not the filter it sends |
| 5 | LDAP filter string literal matching (e.g. Kerberoasting's classic filter signature) | N/A — a network/content-inspection signal, not a logging one | N/A | N/A | **No** — this is exactly what `Get-ObfuscatedFilterString`/`Get-RandomizedCasing` are built to defeat; do not rely on this as a primary signal against the fork |
| 6 | Event 4661 / SACL-based SAMR object-access auditing | No — requires a non-default SACL configuration | N/A | N/A | N/A |
| 7 | Event 5136 (Directory Service Changes) for the fork-only ACL/RBCD write functions | No — requires both non-default "Audit Directory Service Changes" policy and a SACL on the specific object | N/A | N/A | N/A |
| 8 | Event 1644 (DC-side expensive-query diagnostics) | No — off by default, and most PowerView queries are fast enough to never cross the threshold even when enabled | N/A | N/A | N/A |

## Hunting on Source

```powershell
# Event 400 sessions with a download-cradle or PowerView-suggestive command line
Get-WinEvent -LogName "Windows PowerShell" |
    Where-Object { $_.Id -eq 400 -and $_.Message -match 'DownloadString|EncodedCommand|Get-Domain|Find-Domain|Invoke-Kerberoast' } |
    Select-Object TimeCreated, Message

# 4104 content, where Script Block Logging is enabled — direct hit on PowerView function names
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 -and $_.Message -match 'Get-Domain(User|Computer|Group|Trust)|Find-Interesting|Invoke-Kerberoast|Find-LocalAdminAccess|Find-DomainUserLocation' } |
    Select-Object TimeCreated, Message

# Sysmon 1 — powershell.exe/pwsh.exe launching with a suspicious parent (Office app, script host, C2 implant)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 -and $_.Message -match 'Image.*(powershell|pwsh)\.exe' -and $_.Message -notmatch 'ParentImage.*explorer\.exe' }

# Outbound LDAP/Kerberos/SAMR volume from a single host in a short window (source-side EDR/network log export)
Get-NetTCPConnection -RemotePort 389,636,3268,3269,88,445 -State Established |
    Group-Object RemoteAddress | Where-Object Count -gt 20

# ConsoleHost_history.txt — interactive sessions only
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
    -Pattern 'Get-Domain|Find-Domain|Invoke-Kerberoast|Find-LocalAdminAccess'
```

## Hunting on Target

```powershell
# DC-side: volume of unique client IPs issuing high query counts in a short window
# (requires a network-flow/firewall export correlated to 389/636/3268/3269 — not a native
# DC event-log query, since content/volume auditing isn't a built-in Security-log feature)

# DC-side: Event 1644, only useful if diagnostics were already enabled
Get-WinEvent -LogName "Directory Service" | Where-Object { $_.Id -eq 1644 }

# DC-side: Event 5136 for the fork-only ACL/RBCD write functions, only if
# Audit Directory Service Changes + a SACL are already configured on the relevant objects
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 5136 -and $_.Message -match 'nTSecurityDescriptor|msDS-AllowedToActOnBehalfOfOtherIdentity' }

# Member-computer side: SAMR object-access auditing, only if a SACL is configured (non-default)
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4661 }
```

## Fleet-Wide Sweep

Because PowerView's realistic operational use is nearly always domain-wide (that's the tool's entire value proposition — enumerate at scale, not one object at a time), a fleet sweep is really a **network-flow aggregation exercise** rather than a per-host log pull:

```powershell
# Correlate firewall/NetFlow: which source hosts issued LDAP/SAMR/Kerberos connections to
# an unusually large number of distinct domain computers/DCs in a short window
# (run against SIEM-ingested flow data, not natively queryable from any single host)
```

Combine with a domain-wide Event 400 pull (SIEM-aggregated, not single-host) filtered for the same download-cradle/function-name patterns used in the Hunting on Source section above — the classic-channel Event 400 being on-by-default makes it the one PowerShell-engine signal reliably present across every unconfigured host in the fleet.

## Remediation

- **Enable Script Block Logging (4104) and Module Logging (4103) fleet-wide** via GPO — the single highest-leverage change, since both are off by default and PowerView's real content only shows up here.
- **Enable "Audit Directory Service Changes" with SACLs on high-value objects** (Domain Admins and other privileged group DACLs, `AdminSDHolder`, Tier-0 computer objects' `msDS-AllowedToActOnBehalfOfOtherIdentity`) — this is what makes Event 5136 fire for the fork-only ACL/RBCD write functions; without it, a directory write from `Add-DomainObjectAcl`/`Set-DomainRBCD` is functionally invisible.
- **Enable Directory Service Diagnostics (Field Engineering, Event 1644)** where DC performance overhead is acceptable — narrows PowerView's near-total DC-side logging blind spot, though only for queries expensive enough to cross the threshold.
- **Constrain SAMR remote access** (`RestrictRemoteSAM`, already default-on since Server 2016 but confirm it hasn't been loosened) — directly weakens `Find-LocalAdminAccess`/`Find-DomainUserLocation` for non-admin callers.
- **Deploy Honeytoken/decoy AD objects** (a fake "Domain Admin" user with an SPN, a fake highly-privileged-looking group) — since PowerView's enumeration is comprehensive by design, a decoy that shows up in every full sweep and is queried/Kerberoasted is a high-confidence tripwire independent of any logging configuration.
- **Preserve evidence before remediating a confirmed ACL/RBCD write** — reverting `Add-DomainObjectAcl`/`Set-DomainRBCD` changes without first capturing the modified object's security descriptor and the 5136 event (if present) destroys the clearest evidence of what the operator actually changed.
