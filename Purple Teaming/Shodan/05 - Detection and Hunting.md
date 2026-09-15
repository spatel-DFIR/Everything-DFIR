# Shodan — Detection and Hunting

## Contents
- [Hunting Priority — What's Actually Findable](#hunting-priority--whats-actually-findable)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Turning Shodan Around on Yourself](#turning-shodan-around-on-yourself)
- [Fleet-Wide / Estate-Wide Sweep](#fleet-wide--estate-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — What's Actually Findable

Shodan doesn't expose operator-facing evasion flags the way most tools in this module do (no `-file`-style rename trick, no encoder chain, no proxy-routing switch built into the CLI itself) — the thing that varies here isn't evasion sophistication, it's **which side of the interaction you're even able to observe**, per `03`/`04`. Rank hunts by that reality rather than by evasion resistance:

| Rank | Signal | Where it lives | Caveat |
|---|---|---|---|
| 1 (strongest, source-side) | `shodan init <key>` / any `shodan <command>` in process-creation logs (Sysmon 1 / auditd) on a machine you control | Operator's own host | Only works if you're the SOC watching your own analysts/red team — has no equivalent on a victim's network |
| 2 (strongest, target-side) | Recurring, single-banner-grab connections from unfamiliar source IPs with no further interaction, on a roughly weekly (or daily, if Monitor-tracked) cadence | Target's own perimeter/firewall/Zeek logs | This is Shodan's **own routine crawling** — it tells you the target is indexed, not that any specific operator queried it |
| 3 | API key in cleartext inside the `key=` URL parameter of outbound HTTPS requests to `api.shodan.io`, visible only to full-URL-capturing proxy/TLS-inspection logs | Operator's own egress network | Requires TLS interception/full-URL proxy logging already in place — not available on most networks by default |
| 4 | An unusual, tightly-clustered pair of Shodan-crawler-pattern visits **less than 24 hours apart** to the same host | Target's own perimeter logs | Weak/circumstantial indicator of an on-demand scan (`shodan scan submit`) rather than routine crawling — not conclusive, and Enterprise `--force` defeats even this |
| 5 (structurally absent) | Any evidence of a *plain query* (`search`/`host`/`count`/`download`/`stats`) reaching the target at all | — | Doesn't exist. Per `04 - Target Evidence.md`, this event never touches the target's infrastructure. Don't build a hunt around finding it |

**The practical takeaway:** hunting "Shodan usage against my organization" is really two separate, differently-actionable questions — "is my org indexed and how current is that index" (rank 2, answerable, and answerable *by the target itself* using Shodan's own tools — see below), and "did a specific operator query us" (structurally rank-5 unanswerable from the target side, full stop).

## Hunting on Source

For a SOC monitoring its own pentest team, red team, or SOC analysts who have legitimate Shodan accounts:

```powershell
# Windows: process-creation events for shodan CLI usage
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'shodan(\.exe)?\s+(init|search|host|download|scan|alert|stream|trends|domain)' }
```

```bash
# Linux/macOS: shell history and process accounting
grep -E 'shodan (init|search|host|download|scan|alert|stream)' ~/.bash_history ~/.zsh_history 2>/dev/null

# auditd, if execve auditing is configured
ausearch -x shodan -ts recent
```

```bash
# DNS/proxy logs — cheapest, most durable signal (per 03's note that DNS
# logs commonly outlive full connection logs): resolution of Shodan's
# operated hostnames from hosts that shouldn't normally have a reason to
dig +short api.shodan.io stream.shodan.io trends.shodan.io internetdb.shodan.io
# then correlate resolver/DNS logs for those FQDNs against your own asset inventory
```

```bash
# Filesystem check for CLI initialization on a specific host under investigation
ls -la ~/.shodan/api_key ~/.config/shodan/api_key 2>/dev/null
```

For an organization with an approved, budgeted Shodan subscription (increasingly common for the defensive use case below), the presence of this activity is expected and the hunt is really an **authorization check** — confirming the account/host pair matches an approved user, not that Shodan usage happened at all.

## Hunting on Target

This is the meatier half, and it's about characterizing Shodan's own crawler traffic correctly rather than reconstructing any specific operator's actions (per `04`):

```
# Zeek/NetFlow-style hunt logic (pseudocode — adapt to your stack):
# 1. Group inbound connections by source IP
# 2. Flag sources where: exactly 1 connection (or a tight burst) per port
#    touched, a real application-layer banner exchange occurred (not just
#    SYN/RST), and NO further interaction followed within the observation
#    window
# 3. Cross-reference flagged sources against recurrence: does the same
#    behavioral pattern repeat roughly weekly (or daily) from a DIFFERENT
#    source IP each time?
# -> matches this shape are consistent with Shodan-style internet-wide
#    crawler traffic (also matches Censys, other similar internet-scanning
#    services — this behavioral pattern is not exclusive to Shodan)
```

```bash
# If your organization maintains (or subscribes to) a threat-intel feed of
# known internet-scanner ranges, correlate against it — but treat it as
# supplementary, not authoritative, per 04's note that Shodan publishes no
# official range list:
grep -F -f known_scanner_ranges.txt firewall_inbound.log
```

**Do not invest heavily in blocking specific Shodan IP ranges as a detection or prevention strategy.** Per `04 - Target Evidence.md`'s citation of the NDSS 2025 measurement study, Shodan's ~91 observed scan-source IPs are spread across a mix of directly-owned and (mostly) cloud-provider address space specifically because that infrastructure churns — blocking today's observed range only shifts which of Shodan's scanners next indexes you, it doesn't stop indexing, and any effort spent maintaining a Shodan-specific IP blocklist is better spent on the exposure-reduction items in Remediation below.

## Turning Shodan Around on Yourself

The single most effective "hunting on target" technique for this specific tool isn't log analysis at all — it's using Shodan's **own** query surface, defensively, against your own organization, which sidesteps the entire "can't see the operator's query" problem by making the target and the querier the same party:

```bash
# Free, key-less check — what does Shodan currently know about a specific
# asset, with zero setup?
curl -s https://internetdb.shodan.io/<your-own-ip> | python3 -m json.tool

# With an account: full current banner detail + history for your own IPs
shodan host <your-own-ip> --history

# Continuous version — see it the moment Shodan's next crawl finds
# something new/risky about YOUR OWN infrastructure (see 02's "Monitoring
# Your Own Organization Continuously" use case for the full setup)
shodan alert domain your-org.example --triggers new_service,vulnerable,malware,open_database,ssl_expired
shodan alert stats country,port,vuln
```

This directly answers the question a target-side log hunt structurally cannot: not "is someone querying us" (unanswerable, per the priority table above), but **"what would that query return right now, and is it something we'd rather it didn't"** — which is the actionable version of the same concern.

## Fleet-Wide / Estate-Wide Sweep

```bash
# Sweep every currently-monitored netblock/domain across the org's own
# Shodan account for anything a trigger has flagged since the last check
shodan alert list
shodan alert stats country,port,vuln,product --limit 25

# Broader one-off sweep: every external netblock the org owns, faceted
shodan stats --facets port,product,vuln 'net:198.20.69.0/24,203.0.113.0/24'
```

```powershell
# Fleet-wide source-side sweep for unauthorized shodan CLI usage across an
# analyst/red-team estate
$targets = Get-Content .\hosts.txt

Invoke-Command -ComputerName $targets -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'shodan(\.exe)?\s+(init|search|host|download|scan|alert|stream)' } |
    Select-Object @{n='Host';e={$env:COMPUTERNAME}}, TimeCreated,
      @{n='CommandLine';e={($_.Message | Select-String -Pattern 'CommandLine:\s*(.+)').Matches.Groups[1].Value}}
} -ErrorAction SilentlyContinue | Export-Csv -Path .\shodan_usage_sweep.csv -NoTypeInformation
```

## Remediation

**There is nothing to "act on" against the operator in the target-facing sense** — per `04`, a target has no operator-specific event to isolate or respond to. Remediation here is about **reducing exposure**, not incident response against a specific actor:

```
# Reduce what Shodan (or anyone else scanning the internet) finds in the
# first place — the durable fix, since blocking scanner IPs doesn't work
# (per "Hunting on Target" above):

1. Inventory your own external footprint the same way Shodan sees it —
   run the "Turning Shodan Around on Yourself" queries above FIRST, before
   assuming you know what's exposed
2. Close/firewall services that don't need to be internet-facing at all
   (databases, RDP/VNC, management interfaces) rather than relying on
   security-through-obscurity of a non-standard port — Shodan's banner
   grabbing identifies services by response content, not just port number
   (per 01's protocol-auto-detection behavior), so port-hopping alone is
   not a real control
3. Patch CVEs your own vuln:/has_vuln:true monitoring surfaces — treat a
   Shodan Monitor "vulnerable" trigger firing on your own infrastructure
   as equivalent in urgency to an internal vulnerability scanner finding
   the same issue, since an external attacker has access to the identical
   query
4. Place genuinely-needed remote-access/management interfaces behind a
   VPN or bastion rather than directly internet-facing, removing them
   from Shodan's (and any scanner's) reachable surface entirely
5. Rotate TLS certificates and don't reuse distinctive default
   certs/banners across environments — ssl.cert.subject.cn: and similar
   filters (01's Search Filters table) let an operator pivot from one
   discovered asset to sibling infrastructure sharing the same cert
6. If a Shodan Monitor subscription is budgeted, enable it proactively
   (per 02's "Monitoring Your Own Organization Continuously") rather than
   treating Shodan purely as something to defend against — daily rescans
   of your own netblocks with trigger-based alerting is a genuinely
   useful, low-effort addition to an existing external-attack-surface-
   management program
```

For the source-side half (an unauthorized/unapproved `shodan` CLI usage found via `Hunting on Source`), standard credential-hygiene response applies to the exposed API key specifically: rotate it via the Shodan account dashboard, since per `03 - Source Evidence.md` it travels in cleartext in every request URL and is fully recoverable from shell history, process command lines, or proxy logs once an operator's host is compromised or under investigation.
