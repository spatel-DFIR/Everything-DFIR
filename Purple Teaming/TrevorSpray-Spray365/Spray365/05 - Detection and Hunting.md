# Spray365 — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide / Tenant-Wide Sweep](#fleet-wide--tenant-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked by which of Spray365's own evasion options (`-cID`/`-eID` randomization, `-rUA`, `-S`/`-mD` shuffle, `-x` external proxy) each signal survives:

| Rank | Signal | Survives client/endpoint randomization (default)? | Survives `-rUA`? | Survives `-S`/shuffle? | Survives an external `-x` proxy? | Notes |
|---|---|---|---|---|---|---|
| 1 | Fixed `/organizations` multi-tenant MSAL authority + ROPC grant type, high volume, many `UserPrincipalName`s, few source IPs | Yes — structural to every request regardless of client/endpoint | Yes | Yes | No — a rotating external proxy defeats the "few source IPs" half of this signal | Strongest available signal; only defeated by capability Spray365 doesn't provide natively |
| 2 | `UserPrincipalName` + `IPAddress` pair with high `ResultType`-diversity across many distinct `AppId`s in a short window | Yes — this is what the randomization itself produces as a side effect | Yes | Partially — shuffle changes ordering, not the underlying app-identity diversity | No | Effectively turns the tool's own evasion mechanic into the detection signal |
| 3 | Audit-mode shape: one user, ~1 password, 30+ distinct `AppId`s in a tight window | Yes (this *is* the audit-mode default) | Yes | N/A (`-S` not typically meaningful for single-user audit runs) | No | High-confidence, high-severity — implies an already-valid credential plus active CA-gap mapping |
| 4 | Single/near-single source IP sustaining the entire session | N/A | N/A | N/A | **No — the one option this tool lacks natively actually defeats this row** | Weakest signal; only reliable because Spray365 ships with no IP-rotation of its own — don't assume this holds against every deployment |
| 5 | Any single fixed `AppId` presence | **No — actively defeated by default random selection** | N/A | N/A | N/A | Do not build a detection around this — see `04 - Target Evidence.md` |

## Hunting on Source

Applies to an acquired copy of the operator's own box:

```bash
# The execution plan file is the single richest artifact — cleartext
# credentials and the full planned attack surface, whether or not
# spraying ever completed
find / -iname "*.s365" 2>/dev/null
cat found_plan.s365 | python3 -m json.tool | head -50

# Results files, one per completed run, in whatever CWD each was launched from
find / -iname "spray365_results_*.json" 2>/dev/null

# Package footprint (repo is archived — likely a manual git clone, not pip)
find / -iname "spray365.py" 2>/dev/null
find / -type d -iname "Spray365" 2>/dev/null

# Shell history sweep
grep -E "spray365\.py (generate|spray|review)" ~/.bash_history ~/.zsh_history 2>/dev/null
```

On Windows (the tool is cross-platform Python):

```powershell
Get-ChildItem -Recurse -Filter "*.s365" -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Filter "spray365_results_*.json" -ErrorAction SilentlyContinue
Select-String -Path (Get-ChildItem $env:APPDATA\..\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue) -Pattern "spray365"
```

## Hunting on Target

PowerShell/KQL against Entra ID Sign-in Logs, extending `Cloud/Microsoft/Entra ID/Playbooks/Password Spray.md`'s existing queries:

```kql
// Rank 1: the structural MSAL/organizations-authority signature —
// many distinct AppIds, few source IPs, high ResultType volume,
// scoped to the multi-tenant authority pattern MSAL always uses
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType in (50126, 50053, 50055, 50057, 50158, 50076, 53003, 50034, 0)
| summarize Users = dcount(UserPrincipalName),
            DistinctApps = dcount(AppId),
            Attempts = count()
          by IPAddress, bin(TimeGenerated, 1h)
| where Users > 10 and DistinctApps > 5
| order by Attempts desc
```

```kql
// Rank 3: audit-mode CA-gap-mapping shape — one user, tight window,
// very high AppId diversity — treat any hit as a confirmed-credential
// incident, not a routine spray alert
SigninLogs
| where TimeGenerated > ago(7d)
| summarize DistinctApps = dcount(AppId), Attempts = count() by UserPrincipalName, bin(TimeGenerated, 15m)
| where DistinctApps > 30
| order by DistinctApps desc
```

```kql
// Rank 2/5 combined check: for any user showing signal 1 or 2 above,
// confirm whether a SINGLE AppId dominates (operator pinned -cID/-eID,
// a narrower and more deliberate probe) vs. broad AppId spread
// (default randomized behavior)
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<flagged-user>"
| summarize Attempts = count() by AppId, AppDisplayName
| order by Attempts desc
```

## Fleet-Wide / Tenant-Wide Sweep

```kql
// Tenant-wide: correlate any account showing the audit-mode CA-gap
// pattern (rank 3) against whether it ALSO shows an earlier bulk-spray
// pattern (rank 1) for the same user in the preceding 30 days — this
// is the "population spray found a hit, then someone came back and
// mapped the CA gaps for it" combined narrative
let SprayHits = SigninLogs
    | where TimeGenerated > ago(30d)
    | where ResultType == 50126
    | summarize SprayAttempts = count() by UserPrincipalName, bin(TimeGenerated, 1d);
let AuditHits = SigninLogs
    | where TimeGenerated > ago(30d)
    | summarize DistinctApps = dcount(AppId) by UserPrincipalName, bin(TimeGenerated, 15m)
    | where DistinctApps > 30;
SprayHits
| join kind=inner AuditHits on UserPrincipalName
| project UserPrincipalName, SprayAttempts, DistinctApps
```

## Remediation

**Capture evidence before acting** — export the full Sign-in Log window (every distinct `AppId`/`ResultType` combination for the flagged user/IP) and, if source-host access exists, the `.s365`/`spray365_results_*.json` files, before remediating.

- Reset the password and **revoke all refresh tokens/sessions** for every account confirmed valid, per the existing Password Spray playbook's "Did Any Account Fall?" step.
- If an `audit`-mode pattern (rank 3) was observed, treat it as higher-severity than a routine spray hit — it implies the credential is **already confirmed valid** and the operator is actively hunting for a Conditional Access bypass; prioritize this account's investigation and containment ahead of any still-in-progress population-wide spray traffic.
- Review and **tighten Conditional Access policies to explicit app/resource allow-lists** rather than broad "any client app" grants — Spray365's entire audit-mode value proposition depends on some application/resource combination being under-covered by policy; a tenant with tightly scoped CA (specific approved client apps only) has far less surface for this technique regardless of which random `client_id` gets tried.
- Enable/verify **Smart Lockout**; note per `04 - Target Evidence.md` that Spray365's lack of native IP rotation means Smart Lockout is comparatively *more* effective against this tool by default than against a rotation-capable tool like `../TrevorSpray/`, unless the operator has chained an external rotating proxy via `-x`.
- Because Spray365 pulls its client_id/endpoint catalog directly from `AADInternals`, review that tool's own `05 - Detection and Hunting.md` (`../../AADInternals/05 - Detection and Hunting.md`) for any overlapping first-party-client-ID hunting guidance already documented there.
