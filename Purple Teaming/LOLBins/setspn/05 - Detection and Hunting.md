# LOLBins — setspn.exe — Detection and Hunting

`setspn.exe` splits into a recon track (thin, mostly-invisible-by-default DC evidence, identical to `GetUserSPNs.py`'s own LDAP leg) and a write track (a much stronger native signal, Event 5136, but only where the SACL/audit-subcategory prerequisite is actually configured). This file ranks signals accordingly, **before** giving hunt commands, per this module's Writing Style Guide. Hunting on Source targets `03 - Source Evidence.md`'s artifacts; Hunting on Target targets `04 - Target Evidence.md`'s.

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked strongest (most invariant, hardest for an operator to avoid) to weakest.

| Rank | Signal | Survives | Defeated by |
|---|---|---|---|
| 1 (strongest) | **Security 4769 correlated against a preceding Security 5136 `servicePrincipalName` Value-Added event for the same account** — the full Targeted-Kerberoasting fingerprint from `01`'s red-flag callout | Any choice of SPN string, any tool used for the subsequent TGS-REQ (`GetUserSPNs.py`, Rubeus, PowerView), and a prompt `-D` cleanup (the cleanup itself becomes a **third** correlating event, not a way to erase the first two) | **The non-default SACL/Audit Directory Service Changes prerequisite for 5136 not being configured** — without it, this correlation is unavailable and the hunt degrades to rank 3/4 below. Also defeated by an operator targeting an account that legitimately already had an SPN (standard, non-targeted Kerberoasting) — this signal is specific to the *injection* variant only |
| 2 | **RSAT AD DS/LDS Tools capability present on a non-Domain-Controller host with no legitimate administrative reason to carry it** | Any use case, any switch — this is a presence check, not a behavior check, so it can't be evaded by choice of command | Does not itself prove misuse — only narrows which hosts are worth scrutinizing further; a host with a genuine reason to run RSAT (a Tier-0 admin workstation) produces the same signal legitimately |
| 3 | **Security 5136 for `servicePrincipalName`, in isolation (no correlated 4769)** | Survives regardless of whether a roast ever followed — catches `-S`/`-D` activity even for an operator who abandoned the attack before requesting a ticket, or who is only doing recon-adjacent SPN hygiene testing | The same non-default SACL/audit-subcategory prerequisite as rank 1 |
| 4 | **Sysmon 1 / Security 4688 command line for `setspn.exe`'s own invocation** | Captures the exact SPN string, target account, and switches used — the only signal that shows *what the operator actually typed* | No Sysmon/command-line-auditing deployment; defeated for `Image`-keyed rules specifically by a renamed binary (though `OriginalFileName`/hash-based rules still catch it) |
| 5 | **A single 4769 in isolation, or a single `setspn -Q`/`-L` in isolation** | Provides essentially no signal on its own — routine AD administration produces both regularly | Never alert on either alone; use only as raw material for ranks 1 and 3's correlation, or feed into the burst-based Kerberoasting hunt already documented in [`Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md>) |
| 6 (weakest) | **LDAP Event 1644 / SACL-backed 4662 for the `-Q`/`-X` recon leg** | Same weak-alone caveat as `GetUserSPNs.py`'s own recon-track evidence | Entirely dependent on non-default logging; also produces no signal at all for the write-track use case, which is this tool's more distinctive contribution |

## Hunting on Source

```powershell
# setspn.exe command lines — Sysmon 1, if present. Captures -S/-D SPN strings and target accounts in full
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)\bsetspn(\.exe)?\b' } |
  Select-Object TimeCreated, @{N='CommandLine';E={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# Same via Security 4688 (requires command-line auditing enabled)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match '(?i)\\setspn\.exe' }

# Flag the write-track switches specifically (-S/-A/-D/-R) versus pure recon (-L/-Q/-X) —
# the write track is the higher-priority half of this tool's evidentiary story
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)\bsetspn(\.exe)?\b' -and $_.Message -match '(?i)(\s-s\s|\s-a\s|\s-d\s|\s-r\s)' }

# RSAT AD DS/LDS Tools capability check — presence on a non-DC host is itself a hunting signal
# (Hunting Priority rank 2)
Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory*' |
  Where-Object { $_.State -eq 'Installed' }

# PSReadLine console history — captures the exact SPN/account argument text for interactive use
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Pattern 'setspn\s+(-s|-a|-d|-l|-q|-x|-r)' -SimpleMatch:$false

# Renamed-binary check — walk running/recent processes for setspn.exe's Authenticode identity under a different name
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.ExecutablePath -ErrorAction SilentlyContinue
    if ($sig.SignerCertificate.Subject -match 'Microsoft Windows' -and $_.Name -ne 'setspn.exe' -and $_.ExecutablePath -match '(?i)setspn(\.exe)?$') {
        [PSCustomObject]@{ PID = $_.ProcessId; Path = $_.ExecutablePath; Name = $_.Name; Signer = $sig.SignerCertificate.Subject }
    }
}
```

## Hunting on Target

**Leads with the 5136-to-4769 correlation from Hunting Priority rank 1 — the strongest and most distinctive signal this tool contributes that `GetUserSPNs.py`'s own detection guidance doesn't already cover.**

```powershell
# Row 1: the centerpiece hunt — Security 5136 servicePrincipalName Value-Added events,
# each cross-referenced against a Security 4769 for the same account shortly afterward.
# Requires "Audit Directory Service Changes" + a SACL on servicePrincipalName to be configured —
# confirm this before assuming an empty result means nothing happened.
$spnWrites = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=(Get-Date).AddHours(-24)} |
  Where-Object { $_.Message -match 'servicePrincipalName' -and $_.Message -match 'Value Added' }

foreach ($w in $spnWrites) {
    $account = ($w.Message -split "`r`n" | Where-Object {$_ -match 'Object:'})[1]  # adjust index to the DN line in the local event schema
    $window  = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=$w.TimeCreated; EndTime=$w.TimeCreated.AddMinutes(15)} -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        WriteTime      = $w.TimeCreated
        ObjectChanged  = $account
        FollowedBy4769 = [bool]($window | Where-Object { $_.Message -match [regex]::Escape($account) })
    }
}

# Row 3: 5136 in isolation — every servicePrincipalName write in the window, correlated 4769 or not
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=(Get-Date).AddDays(-7)} |
  Where-Object { $_.Message -match 'servicePrincipalName' } |
  Select-Object TimeCreated, Message

# Row 4: Sysmon 1 / Security 4688 for setspn.exe's own invocation, target-side (if setspn ran
# directly on the DC rather than a remote workstation)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '(?i)\bsetspn(\.exe)?\b' }

# Row 6: Directory Service Event 1644, if Field Engineering=5 is enabled — the recon-track filter string
Get-WinEvent -LogName 'Directory Service' -FilterXPath "*[System[EventID=1644]]" -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'servicePrincipalName' }

# Baseline diff — export current SPN inventory and compare against a prior export to catch any
# write that occurred entirely outside the 5136 window (e.g. before auditing was enabled, or if
# retention already rolled the event off)
Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, whenChanged |
  Select-Object DistinguishedName, servicePrincipalName, whenChanged |
  Export-Csv "C:\hunt\spn_inventory_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
# Compare-Object against a prior day's export to surface any account that newly appears with an SPN
```

The centerpiece hunt above is deliberately **not** a replacement for [`Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md>)'s own burst-based 4769 hunt (one requester, many distinct SPNs) — run both. The GetUserSPNs hunt catches standard, broad Kerberoasting sweeps against *existing* SPN-bearing accounts; this file's 5136-to-4769 correlation catches the narrower, more targeted injection variant that broad-sweep hunting structurally cannot see, since a freshly-injected SPN on one single account never produces the "many distinct SPNs from one requester" burst shape at all.

## Fleet-Wide Sweep

Both `setspn -S` writes and the RSAT-capability check benefit from a domain-wide pass, since a write can land on whichever DC serviced the request and a capability install can happen on any workstation:

```powershell
$domainControllers = (Get-ADDomainController -Filter *).HostName

# Pull 5136 servicePrincipalName writes from every DC — a write can land on any DC servicing the request
$fleetWrites = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'servicePrincipalName' } |
        Select-Object @{N='DC';E={$env:COMPUTERNAME}}, TimeCreated, Message
} -ErrorAction SilentlyContinue
$fleetWrites | Export-Csv C:\hunt\setspn_5136_fleet_sweep.csv -NoTypeInformation

# Sweep workstations/member servers for the RSAT AD DS/LDS Tools capability — flags hosts that
# shouldn't have setspn.exe available at all
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    $cap = Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory*' -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Installed' }
    if ($cap) { [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; Capability = $cap.Name } }
} -ErrorAction SilentlyContinue | Export-Csv C:\hunt\rsat_ad_tools_fleet.csv -NoTypeInformation
```

## Remediation

🔴 **Capture evidence before deleting an injected SPN or resetting the target account.** A `-D` cleanup performed by the *investigator* rather than the attacker still permanently erases the `servicePrincipalName` value from the live object — export first.

```powershell
# Export the current SPN state and the relevant 5136/4769 event windows before touching anything
Get-ADObject -Identity 'targetuser' -Properties servicePrincipalName | Export-Clixml 'C:\hunt\targetuser_spn_before.xml'
wevtutil epl Security 'C:\hunt\security_relevant.evtx'

# If an injected SPN is confirmed and the investigation is otherwise complete, remove it —
# this is the same command an attacker's own cleanup step would use, now run defensively
setspn.exe -D "http/fakesvc.corp.local" targetuser

# Rotate the target service account's password regardless of whether a cracked hash is confirmed —
# a Targeted-Kerberoasting injection implies the account's password was exposed to offline
# cracking during the window the SPN existed
Set-ADAccountPassword -Identity targetuser -Reset
```

**Structural fixes, not just detect-and-respond** — largely the same set already documented in depth in [`Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md>) (AES-only enforcement via `msDS-SupportedEncryptionTypes`, gMSA/dMSA adoption, canary SPN accounts), plus one addition specific to the write-track vulnerability this tool exposes:

- **Audit and minimize `GenericWrite`/`GenericAll`/`WriteProperty(servicePrincipalName)`/Validated-SPN delegations across the domain.** This is the actual root cause Targeted Kerberoasting exploits — an over-permissive ACE, usually left over from a delegation grant that was broader than intended. BloodHound's `GenericWrite`/`GenericAll` shortest-path queries (see [`BloodHound/BloodHound/02 - Hands-On Use Cases.md`](<../../BloodHound/BloodHound/02 - Hands-On Use Cases.md>)) are the practical way to find these ACEs from a defender's chair, exactly as an attacker would use them offensively — auditing from the same graph an attacker would query is the direct fix.
- **Enable "Audit Directory Service Changes" with a SACL on `servicePrincipalName` for at least all Tier-0/service-account OUs**, deliberately — per `04 - Target Evidence.md`, this is non-default and its absence is the single biggest reason the write-track evidence in this file goes dark. This is a narrower, cheaper audit scope than SACL'ing every attribute read domain-wide, and it directly enables Hunting Priority rank 1.
- **Canary/honeypot SPN accounts extend to the injection variant too** — a decoy account with `GenericWrite` deliberately granted to a low-privilege group, monitored for any `servicePrincipalName` write at all, catches an operator probing for exactly this kind of misconfiguration even before a real high-value account is targeted.
