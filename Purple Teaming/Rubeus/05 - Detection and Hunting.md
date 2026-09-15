# Rubeus — Detection and Hunting

## Hunting Priority

Rubeus exposes real evasion/customization options (`/opsec`, `/rc4opsec`, `/tgtdeleg`, `/nopreauth`, `/proxyurl`, `/delay`/`/jitter`, and the inherent fact that no stable compiled binary exists). Ranked by which signals survive the most of them:

| Rank | Signal | Survives custom compile/rename? | Survives `/opsec`/`/rc4opsec`/`/tgtdeleg`? | Survives `/proxyurl` (KDC proxy)? | Notes |
|---|---|---|---|---|---|
| 1 | `winlogon.exe` process-access from a non-LSA process, immediately followed by all-users ticket-cache API calls | ✅ Yes | ✅ Yes | ✅ Yes | Only fires for **elevated** operations (`triage`/`dump`/`monitor`/`harvest`/`purge`/`ptt` targeting another `/luid`) — no evasion flag touches this path at all, since it's the elevation mechanism itself, not the Kerberos traffic |
| 2 | Non-`lsass.exe` process holding a live TCP/UDP socket to port 88 or 464 | ✅ Yes | ✅ Yes | ❌ **No** — `/proxyurl` routes over HTTPS instead | The tool author's own stated hardest-to-avoid tell; defeated only by the one flag built specifically to reroute the transport |
| 3 | Kerberoasting burst — one principal requesting TGS for many distinct SPNs in a tight window | ✅ Yes | ⚠️ Partial — `/delay`/`/jitter` widen the window, `/ticket:X` skips the LDAP-driven enumeration step that produces the pattern | ✅ Yes | Already documented in depth in `Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md` — apply that page's query directly, Rubeus produces the identical shape |
| 4 | Diamond ticket's base 4768 tied to the **template** account, not the final claimed PAC identity | ✅ Yes | N/A (no dedicated evasion flag) | ✅ Yes | Requires deliberately correlating "which account authenticated" against "which identity later shows up using tickets" — not caught by a simple 4769-only hunt |
| 5 | Command-line switch/credential-material matching (`/rc4:`, `/aes256:`, `asktgt`, `/rc4opsec`, etc.) | ⚠️ Partial | ⚠️ Partial | N/A | **Fully defeated** if Rubeus is invoked programmatically (`[Rubeus.Program]::Main("...".Split())` from a PowerShell reflection wrapper) rather than as a literal process command line — only the wrapper script's own (much less distinctive) command line is visible then |
| 6 | Encryption-type field (`0x17` RC4 vs `0x11`/`0x12` AES) in 4768/4769 | N/A | ⚠️ **Actively misleading for default `kerberoast`** | ✅ Yes | Rubeus's plain default requests each account's *highest* supported enctype — an RC4-only detection rule will **miss** a default-mode Rubeus Kerberoast run against AES-capable accounts entirely; see `01`'s opsec-flag table |
| 7 | PE metadata / static filename / binary hash | ❌ **No** | ❌ No | N/A | No official binary is ever released — there is no canonical signature to match against in the first place, weakest signal in this table by construction |

## Hunting on Source

**The `winlogon.exe` handle-access pattern (rank 1):**

```powershell
# Requires Sysmon with ProcessAccess (Event ID 10) enabled and configured to log
# accesses to winlogon.exe -- the concrete telemetry behind the GetSystem()
# token-duplication pattern documented in 03 - Source Evidence.md
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 10 -and $_.Message -match "TargetImage:.*winlogon\.exe" } |
    Select-Object TimeCreated, @{N='SourceImage';E={($_.Message -split "`n" | Select-String "SourceImage:").ToString()}}, Message
```

**Non-`lsass.exe` port 88/464 connections (rank 2):**

```powershell
Get-NetTCPConnection -RemotePort 88,464 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -ne 'lsass') {
            [PSCustomObject]@{ Process = $proc.ProcessName; PID = $proc.Id; Path = $proc.Path; RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort }
        }
    }
```

**Command-line/credential-material matching (rank 5 — cheap first pass, know its blind spot):**

```powershell
# Sysmon Event ID 1 / Security 4688, filtered for Rubeus command patterns
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
    Where-Object { $_.Message -match '(asktgt|asktgs|kerberoast|asreproast|/rc4opsec|/tgtdeleg|/krbkey:|/ptt\b)' }
```

**Local persistence of harvested output (`monitor`/`harvest /registry`):**

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\' | Where-Object { $_.PSChildName -notin (Get-ChildItem 'HKLM:\SOFTWARE\' -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty PSChildName) } # baseline against a known-clean SOFTWARE hive; anomalous keys warrant manual review
```

## Hunting on Target

**Kerberoasting burst — adapted from `Impacket/GetUserSPNs (Kerberoasting)/05 - Detection and Hunting.md`, apply that page's full query; Rubeus produces the identical event shape:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
    Where-Object { $_.Message -match 'Ticket Encryption Type:\s+0x17' } |
    Group-Object { ($_.Message -split "`n" | Select-String 'Account Name:').ToString() } |
    Where-Object { $_.Count -gt 3 }   # one principal, many distinct SPNs, tight window
```

Remember rank 6 above: this query alone **misses default-mode Rubeus Kerberoast runs** against AES-capable accounts entirely, since no `0x17` ever appears — run a parallel sweep on `0x11`/`0x12` grouped the same way to catch that path.

**AS-REP Roasting sweep (4768 burst, pre-auth-disabled accounts):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} |
    Group-Object { ($_.Message -split "`n" | Select-String 'Account Name:').ToString() } |
    Sort-Object Count -Descending | Select-Object -First 20
```

A single source identity generating many distinct-target 4768 events in a short window (rather than the usual one-account-per-logon pattern) is the AS-REP-roasting-sweep signature — cross-reference against known `DONT_REQ_PREAUTH` accounts to confirm.

**S4U2Proxy / constrained-delegation abuse:**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
    Where-Object { $_.Message -match 'Transited Services:\s+\S' }
```

A populated `Transited Services` field on a 4769 confirms an S4U2Proxy exchange occurred — cross-reference the requesting account against BloodHound's `AllowedToDelegate` edge list (`Purple Teaming/BloodHound/`) to separate legitimate delegation usage from abuse of an account that shouldn't be delegation-trusted at all.

**Silent Golden/Silver forgery — use-time detection only:** creation generates no target-side event (see `04`). Apply `Mimikatz/kerberos (Golden-Silver Ticket)/05 - Detection and Hunting.md`'s MDI-alert-based hunting directly (alert IDs 2027/2032/2040/2022/2009/2013) — not re-derived here, since Rubeus's `golden`/`silver` and Mimikatz's `kerberos::golden` produce structurally identical forged-ticket-in-use artifacts.

**SYSVOL mount from `/ldap`-assisted forging (requires non-default Object Access auditing on the `SYSVOL` share):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140,5145} |
    Where-Object { $_.Message -match 'SYSVOL' }
```

## Fleet-Wide Sweep

```powershell
# Domain-wide: sweep every DC's Security log for the Kerberoasting/AS-REP-roasting
# burst patterns above in one pass (requires an account with log-read rights on
# every DC, or centralize via a SIEM instead of live WinRM fan-out)
$DCs = (Get-ADDomainController -Filter *).HostName
Invoke-Command -ComputerName $DCs -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=(Get-Date).AddHours(-24)} |
        Where-Object { $_.Message -match 'Ticket Encryption Type:\s+0x(17|11|12)' }
} -ErrorAction SilentlyContinue

# Endpoint-side: sweep the fleet for non-lsass processes holding port 88/464,
# and for the winlogon.exe ProcessAccess pattern, across every reachable host
Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock {
    Get-NetTCPConnection -RemotePort 88,464 -ErrorAction SilentlyContinue |
        Where-Object { (Get-Process -Id $_.OwningProcess).ProcessName -ne 'lsass' }
} -ErrorAction SilentlyContinue
```

## Remediation

**Capture forged/harvested ticket blobs, affected account identities, and the full event-log window before taking any of the following actions** — resetting keys or disabling accounts invalidates the very tickets an investigation may still need to characterize scope.

- **Reset the `krbtgt` password twice** (each reset invalidates one generation of Golden Tickets and Diamond Tickets forged/re-signed with the prior key; a single reset leaves the *previous* key's tickets valid until the second reset per AD's two-generation key history) — same remediation this repo's `Mimikatz/kerberos (Golden-Silver Ticket)/` already covers for the Golden Ticket case, applies identically here.
- **Reset the specific service/computer account password** for any account a Silver Ticket was forged against, or any account recovered via Kerberoasting/AS-REP roasting and confirmed cracked.
- **Purge and re-issue tickets domain-wide is impractical** — instead, force logoff/disconnect sessions on hosts where a forged or abused ticket was confirmed applied (`Rubeus.exe purge` is the attacker's own cleanup tool; defenders use `klist purge`/session termination or a full reboot to clear the LSA ticket cache on an affected endpoint).
- **Review and tighten Kerberos delegation configuration**: audit every account with `TrustedToAuthForDelegation` set or a non-empty `msDS-AllowedToDelegateTo`, remove it where not operationally required, and prefer Resource-Based Constrained Delegation (which the *resource* owns and controls) over classic constrained delegation (which the *delegate* account controls) where delegation is genuinely needed.
- **Disable unconstrained delegation** wherever it's not explicitly required — it's the precondition for the `monitor`/`harvest` TGT-harvesting play, and removing it removes that entire attack surface rather than just detecting its use.
- **Enforce AES-only Kerberos encryption** (`msDS-SupportedEncryptionTypes`) domain-wide where legacy RC4-dependent systems allow it — this doesn't stop Kerberoasting/AS-REP roasting outright, but removes Rubeus's `/tgtdeleg`/`/rc4opsec` RC4-downgrade value and forces every recovered hash into the much more expensive-to-crack AES modes.
- **Enable the auditing this page's hunts depend on**: Directory Service Access auditing (for 5136-based delegation-attribute-change detection, mirroring `LOLBins/setspn/`'s own finding), Object Access auditing on `SYSVOL` (for the `/ldap`-mount signal), and Sysmon with ProcessAccess (Event ID 10) enabled and scoped to include `winlogon.exe` as a monitored target image — none of these are default-on, and every one of them is a real detection gap until explicitly configured.
