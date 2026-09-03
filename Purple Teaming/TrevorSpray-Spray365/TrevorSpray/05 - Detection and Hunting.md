# TrevorSpray — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide / Tenant-Wide Sweep](#fleet-wide--tenant-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked by which of TrevorSpray's own evasion options (`--ssh`, `--subnet`, `--random-useragent`, `-d`/`-j` delay tuning) each signal survives:

| Rank | Signal | Survives IP rotation (`-s`/`--subnet`)? | Survives `--random-useragent`? | Survives delay/jitter tuning? | Notes |
|---|---|---|---|---|---|
| 1 | Loot-phase burst (many distinct `ClientAppUsed`/`ResourceDisplayName`, same user, same source IP, sub-minute window) | N/A — evaluated per-source-IP, works even with rotation | Yes | Yes | The single strongest signal in this file — it's a behavioral pattern intrinsic to the tool's default post-success logic, not a static fingerprint. Only defeated by `-nl/--no-loot`, which an operator must deliberately choose |
| 2 | Static hardcoded User-Agent (iPhone/Mobile Safari string) across many distinct sign-ins | Yes — UA travels with the request regardless of source IP | **No** — this is exactly what `--random-useragent` defeats | Yes | Strong until the operator adds one flag; still useful as a baseline "did they bother to evade" indicator |
| 3 | Many `50126` (invalid credential) sign-ins across many distinct users from few source IPs/ASNs | **No** — `--ssh`/`--subnet` is built specifically to defeat this | Yes | Partially — high delay reduces volume-per-window but doesn't change the pattern shape | The classic spray signature from the existing Playbook; degrades fastest against a well-resourced operator |
| 4 | `AppId 38aa3b87-a06d-4817-b275-7a316988d93b` ("Microsoft Azure PowerShell") + `resource=graph.windows.net` (legacy AAD Graph) combination, high volume | Yes | Yes (only affects `client_id` for `msol` when `--random-useragent` is set) | Yes | Legitimate baseline traffic exists for this `AppId` in most tenants — use as a volume/rate anomaly, not a bare presence signal |
| 5 | Single-source-IP volume threshold | **No** | N/A | Partially | Weakest signal here — trivially defeated by `-s`/`--subnet`; include only as a tripwire for unsophisticated/default-configuration runs |

## Hunting on Source

Applies to an acquired copy of the operator's own box (red-team infra review, or a compromised-attacker-infrastructure scenario in an IR engagement):

```bash
# Presence of the tool's own state directory — near-definitive
ls -la ~/.trevorspray/

# Full historical target/username/credential scope in one place
cat ~/.trevorspray/valid_logins.txt      # every credential ever confirmed valid
cat ~/.trevorspray/existent_users.txt    # every username ever confirmed to exist
cat ~/.trevorspray/tried_logins.txt      # cumulative attempt log, keyed "<module>|<url>|<user>|<password>"

# Full run-by-run timeline, independent of console verbosity at the time
grep -E "INFO|SUCCESS|ERROR" ~/.trevorspray/trevorspray.log | less

# Confirm SSH round-robin proxying was in use (child ssh processes / listening SOCKS5 ports)
ss -tlnp | grep -E ':334[89][0-9]|:33[5-9][0-9]{2}'   # base port 33482 + N
ps -ef | grep -E '\bssh\b.*-D'

# Confirm subnet-spoofing was configured
sudo iptables -t nat -L -n -v | grep -i spoof   # rule naming is operator/tool-version dependent; inspect all NAT/mangle rules if this misses
ip -6 addr show

# Loot artifacts
ls -la ~/.trevorspray/loot/
```

Package/pip installation footprint (if the tool was `pip install git+...`'d rather than run from a git checkout):

```bash
pip show trevorspray trevorproxy 2>/dev/null
python3 -c "import trevorspray" 2>&1   # confirms library presence even with no CLI history
```

## Hunting on Target

PowerShell/KQL against Entra ID Sign-in Logs, extending the existing `Cloud/Microsoft/Entra ID/Playbooks/Password Spray.md` queries with TrevorSpray-specific detail:

```kql
// Rank 1: the loot-phase burst — same user, same source IP, 3+ distinct
// ClientAppUsed values within a 60-second window
SigninLogs
| where TimeGenerated > ago(7d)
| summarize DistinctClientApps = dcount(ClientAppUsed),
            Apps = make_set(ClientAppUsed),
            Resources = make_set(ResourceDisplayName)
          by UserPrincipalName, IPAddress, bin(TimeGenerated, 1m)
| where DistinctClientApps >= 3
| order by DistinctClientApps desc
```

```kql
// Rank 2: the static iPhone/Mobile Safari UA appearing across many distinct
// UserPrincipalName sign-ins from the same small set of source IPs — a
// fixed UA across a wide user population is itself the anomaly
SigninLogs
| where TimeGenerated > ago(7d)
| where UserAgent has "iPhone; CPU iPhone OS 13_2_3"
| summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress
| where Users > 5
| order by Users desc
```

```kql
// Rank 4: "Microsoft Azure PowerShell" AppId against the legacy AAD Graph
// resource, high volume, many distinct users — baseline exists, so this
// is a rate/volume hunt, not a bare-presence hunt
SigninLogs
| where TimeGenerated > ago(7d)
| where AppId == "38aa3b87-a06d-4817-b275-7a316988d93b"
| where ResourceDisplayName has "graph.windows.net" or ResourceDisplayName has "Windows Azure Active Directory"
| summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, 1h)
| where Users > 10
```

For non-`msol` modules, hunt on the relevant non-Entra source directly — ADFS Security Event Log 411/510, Exchange/IIS protocol logs for `owa`, or the fronting IdP's own audit log for `okta`/`auth0`/`jumpcloud`/`anyconnect` — per `04 - Target Evidence.md`'s breakdown.

## Fleet-Wide / Tenant-Wide Sweep

TrevorSpray is inherently a tenant-wide tool by design (it sprays the whole user list in one run), so the sweep is a single query scoped to the whole tenant rather than a per-host loop:

```kql
// Tenant-wide: any account with BOTH a bulk-spray-pattern hit AND a
// subsequent loot-burst pattern in the same session window — the
// highest-confidence "this was TrevorSpray, and it worked" combined signal
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 50126
| summarize SprayHits = count(), SprayIPs = make_set(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where SprayHits > 3
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(30d)
    | summarize DistinctApps = dcount(ClientAppUsed) by UserPrincipalName, bin(TimeGenerated, 1m)
    | where DistinctApps >= 3
  ) on UserPrincipalName
```

Also sweep for the sibling-domain/tenant-enumeration side effect: if the environment runs its own DNS resolver logging, a burst of DKIM-selector CNAME lookups (`selector1._domainkey.<domain>`, `selector2._domainkey.<domain>`) or MX/TXT lookups from a single external resolver in a short window is consistent with the `--recon` phase running against the organization's public DNS, ahead of any spray traffic actually reaching Microsoft.

## Remediation

**Capture evidence before acting** — pull the full Sign-in Log window (including every loot-burst `ClientAppUsed`/`ResourceDisplayName` entry) and export `~/.trevorspray/` from any recovered attacker infrastructure before remediating, since containment actions (password reset, session revocation, legacy-auth block) will end the activity and may end the observation window along with it.

- Reset the password and **revoke all refresh tokens/sessions** for every account confirmed in the "Did Any Account Fall?" table of the existing Password Spray playbook.
- **Block legacy authentication tenant-wide** — this single control defeats the entire IMAP/SMTP/POP3/EWS/EAS/UM loot-phase burst at once, since all of them are legacy-auth protocols. This is the highest-leverage remediation specific to this tool's actual behavior.
- Enable/verify **Smart Lockout** and, where licensing allows, Conditional Access policies requiring compliant/hybrid-joined devices — reduces the value of any credential the spray does recover, independent of source-IP rotation.
- For confirmed `adfs`/`owa` hits, coordinate with the on-prem/Exchange team — Entra-side remediation alone doesn't touch a compromised on-prem or hybrid identity if the credential was also validated against ADFS or an on-prem Exchange front-end directly.
- If the Azure Service Management API loot probe succeeded for any account, treat it as a **management-plane incident**, not a mailbox-access incident — review Azure resource-level activity logs for that identity, not just Entra/Exchange logs.
