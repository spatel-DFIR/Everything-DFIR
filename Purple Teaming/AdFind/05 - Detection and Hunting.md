# AdFind — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

AdFind exposes a small but meaningful evasion surface: **renaming the binary** (defeats image-name matching, not PE metadata), **switching to LDAPS** (`-ssl`/`-starttls`, defeats plaintext network content inspection, not connection-metadata visibility), and simply **relying on the ambient logon token instead of `-u`/`-up`** (removes the credential-exposure angle but doesn't touch the command-line-content signal at all, since the filter/`-sc` string is present either way). Given `04 - Target Evidence.md`'s finding that the domain controller itself logs almost nothing about a normal query by default, **rank hunts by what's visible on the source host first** — that's where the durable signal actually lives for this tool, a reversal of the usual "target evidence is primary" framing this repo otherwise leans on.

| Rank | Signal | Survives binary rename? | Survives LDAPS (`-ssl`/`-starttls`)? | Survives using the ambient logon token (no `-u`/`-up`)? |
|---|---|---|---|---|
| 1 (strongest) | Command-line content match on the LDAP filter / `-sc` shortcut string (Sysmon 1 / Security 4688) — `objectcategory=`, `trustdmp`, `computers_pwdnotreqd`, etc. | ✅ Yes — the filter string doesn't change | ✅ Yes — command-line logging is process-level, unrelated to the LDAP transport's encryption | ✅ Yes — the filter is present in the command line regardless of how the bind is authenticated |
| 2 | PE metadata match — `OriginalFileName == AdFind.exe` (Sysmon 1's PE fields, or an EDR product surfacing the same field) | ✅ Yes — this is specifically the field renaming doesn't touch | ✅ Yes | ✅ Yes |
| 3 | Network-layer connection metadata to 389/636/3268/3269 on a DC from a source with no established administrative relationship to it | ✅ Yes — port/destination behavior is unaffected by the binary's filename | ⚠️ **Partial** — connection metadata (port, destination, duration, volume) still visible; LDAPS defeats only *content* inspection, which this rank doesn't rely on | ✅ Yes |
| 4 | Image-name/process-name match on `AdFind.exe` (no PE-metadata check) | ❌ **No** — trivially defeated by a simple rename, and renaming is common enough in real intrusions that this alone is unreliable | ✅ Yes | ✅ Yes |
| 5 (weakest) | Directory Service Event 1644 (expensive/inefficient LDAP query, DC-side) | ✅ Yes (not filename-dependent) | ✅ Yes (fires regardless of transport encryption — the DC evaluates the query in cleartext internally either way) | ✅ Yes | — but **not enabled by default**, and only fires for queries expensive enough to cross the configured threshold; most AdFind queries target well-indexed attributes and simply won't trigger it |

**Build hunts on ranks 1–2 first** — they're the only signals unaffected by every evasion option AdFind actually exposes, and they don't require the non-default DC-side diagnostics logging rank 5 depends on. Command-line-content matching is doing essentially all of the real work for this tool.

## Hunting on Source

```powershell
# 1. Sysmon Process Create — match on AdFind's distinctive filter/shortcut
#    vocabulary in the full command line, independent of the image name
#    used (catches renamed binaries)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'objectcategory=|trustdmp|computers_pwdnotreqd|dclist|dcmodes|domainlist|gpodmp|adobjcnt|admincountdmp|sdfilter|getacl' }

# 2. Same, but anchored on the PE OriginalFileName field specifically —
#    the strongest single check against a renamed binary
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'OriginalFileName:\s*AdFind\.exe' }

# 3. Security 4688, if command-line auditing is enabled — same pattern,
#    weaker PE-metadata visibility than Sysmon 1
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'objectcategory=|trustdmp|computers_pwdnotreqd|-sc ' }

# 4. PowerShell/console history for the invocation and any embedded
#    -u/-up credential — HIGH VALUE if explicit alternate credentials
#    were used instead of the ambient logon token
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'adfind|-sc |-f "|trustdmp|-up '

# 5. Outbound connections to LDAP/LDAPS/GC ports from the source host
Get-NetTCPConnection -RemotePort 389,636,3268,3269 -ErrorAction SilentlyContinue
```

## Hunting on Target

Given `04 - Target Evidence.md`'s finding that the domain controller logs almost nothing natively, target-side hunting here is narrower than in most other pages in this repo — network-layer visibility and (if already enabled) the 1644 diagnostic log are what's available:

```powershell
# 1. Directory Service Event 1644 — ONLY useful if Field Engineering
#    diagnostics were already enabled (not a hunt-time control to turn
#    on reactively; it's a standing configuration decision, see
#    Remediation below) and the specific query was expensive enough to
#    trigger it
Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Id=1644} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'objectCategory|servicePrincipalName|userAccountControl' }

# 2. Firewall/connection logging on the DC itself, if enabled — inbound
#    389/636/3268/3269 from a source with no established administrative
#    pattern to this DC
Get-NetTCPConnection -LocalPort 389,636,3268,3269 -State Established -ErrorAction SilentlyContinue |
  Select-Object RemoteAddress, RemotePort, CreationTime
```

For anything beyond this, correlate back to `03 - Source Evidence.md`'s much stronger source-side signals — a DC-side network connection alone tells you *that* a query happened and from where, not *what* it asked for.

## Fleet-Wide Sweep

```powershell
# Sweep across the estate for Sysmon 1 events carrying AdFind's
# distinctive command-line vocabulary, catching renamed binaries via the
# same filter/shortcut-string match used on a single host above
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'objectcategory=|trustdmp|computers_pwdnotreqd|dclist|dcmodes|domainlist|OriginalFileName:\s*AdFind\.exe' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='CommandLine';e={($_.Message | Select-String -Pattern 'CommandLine:\s*(.+)').Matches.Groups[1].Value}}
} -ErrorAction SilentlyContinue

$results | Sort-Object TimeCreated | Export-Csv -Path .\adfind_sweep_results.csv -NoTypeInformation

# Cross-reference: hosts running AdFind-shaped queries followed within a
# short window by BloodHound/SharpHound collection activity is a strong
# composite signal for a domain-mapping phase in progress — see
# ../BloodHound/BloodHound/05 - Detection and Hunting.md and
# ../BloodHound/SharpHound/05 - Detection and Hunting.md for that
# suite's own hunt queries to run alongside this one
```

## Remediation

**Capture evidence first** — pull the Sysmon 1 events (including the full command line and any recoverable output-file targets) and any recoverable batch script before killing the process or isolating the host; AdFind's own footprint is thin enough (per `03`/`04`) that acting first risks losing the only recoverable record of exactly what was queried.

AdFind itself isn't the thing to fix — it's a legitimate administrative tool exploiting the fact that AD grants broad default read access to any authenticated domain account. The durable hardening targets are the access paths and visibility gaps it rides, not the binary:

```powershell
# Enable command-line auditing for process creation — the single
# highest-value native control for this tool specifically, since it's
# currently NOT enabled by default and rank 1/4 in the priority table
# above depend on it for Security 4688 visibility (Sysmon 1 captures
# command lines regardless, making Sysmon deployment the higher-leverage
# move if it isn't already present):
# Computer Configuration > Administrative Templates > System > Audit
# Process Creation > "Include command line in process creation events" = Enabled

# Reduce the value of a successful sweep rather than trying to block
# read access outright (broad LDAP read is normal/required AD behavior
# and cannot be meaningfully restricted without breaking legitimate
# tooling) — specifically close the PASSWD_NOTREQD and stale-adminCount
# findings this tool exists to surface:
# - Audit and clear PASSWD_NOTREQD on any account it isn't operationally
#   required for (adfind -sc computers_pwdnotreqd IS itself a legitimate
#   defensive audit command — run it yourself before an attacker does)
# - Periodically reconcile adminCount=1 accounts against actual current
#   privileged-group membership and clear the flag on stale entries

# Where diagnostic-level DC logging is already a standing requirement
# for other reasons, Directory Service 1644 (Field Engineering = 5) adds
# marginal target-side query-content visibility for expensive/broad
# queries specifically — not a primary control on its own (see the
# Hunting Priority table's rank 5), and carries real DC performance-
# logging overhead, so weigh it against that cost rather than enabling
# it purely for this tool
```

Enabling Sysmon with command-line capture (if not already deployed) is the single highest-leverage move from this note's perspective — per the priority table above, it's the one signal that survives every evasion option AdFind actually exposes, and it requires no DC-side configuration change or performance trade-off to get.
