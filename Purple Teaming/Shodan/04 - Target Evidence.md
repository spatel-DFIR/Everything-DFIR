# Shodan — Target Evidence

**Be precise about what this file actually covers, because it's the opposite of nearly every other `04 - Target Evidence.md` in this module.** A plain Shodan query — `search`, `host`, `count`, `download`, `stats`, `trends`, `domain` — reads Shodan's own **pre-existing** index. It does not send any packet, connection, or request of any kind to the target. **There is zero target-side evidence for a plain Shodan query, full stop** — not "weak" evidence, not "hard to find" evidence, actually none, because the event that would generate it never happens. What this file documents instead is the two things that *do* touch the target: **(1) Shodan's own recurring, independent crawling**, which happens on Shodan's own schedule regardless of any specific operator, and **(2) on-demand scanning**, the one Shodan feature that genuinely triggers fresh, request-driven probing.

## Contents
- [Why a Plain Query Leaves Nothing](#why-a-plain-query-leaves-nothing)
- [What Does Leave Evidence: Shodan's Own Crawling](#what-does-leave-evidence-shodans-own-crawling)
- [Identifying Shodan Crawler Traffic in Your Own Logs](#identifying-shodan-crawler-traffic-in-your-own-logs)
- [On-Demand Scanning: The One Case With Fresh, Request-Driven Traffic](#on-demand-scanning-the-one-case-with-fresh-request-driven-traffic)
- [Follow-On Active Recon After Target Selection](#follow-on-active-recon-after-target-selection)
- [Building a Timeline](#building-a-timeline)

---

## Why a Plain Query Leaves Nothing

Restating the mechanism from `01 - Overview.md`'s "Phase 2" diagram: `shodan search "org:acme"` is an HTTPS request from the **operator's machine to `api.shodan.io`**. The target organization is named only as a string inside that request's query parameters — it is not a network endpoint of the request in any sense. No DNS query the target's resolvers would see, no TCP handshake the target's firewall would log, no HTTP request the target's web server would receive. An IR investigation on the target side, no matter how thorough, has no artifact to find for this specific action, because it isn't an action that happens against the target's infrastructure at all. This is worth stating explicitly to a stakeholder rather than implying detection is merely "hard" — it's structurally absent, and any report claiming to have "detected the Shodan query" against a specific target is describing something else (most likely Shodan's own independent crawling, below, coincidentally observed around the same time).

## What Does Leave Evidence: Shodan's Own Crawling

Per `01 - Overview.md`'s crawler mechanics (sourced from `book.shodan.io`'s own documentation), Shodan's crawlers connect to essentially every IPv4 address on a rotating basis:

- **Baseline cadence:** the full address space gets randomly re-crawled roughly **once a week**. Any given target's most recent Shodan-visible banner data can be anywhere from hours to just under a week stale relative to a live scan.
- **Faster cadence for Shodan-Monitor-tracked assets:** if a *different* party (the target organization itself, a security researcher, anyone with a Shodan Monitor subscription) has added the target's IPs to their own `shodan alert`, those specific IPs get rescanned **at least daily** — meaning the crawl frequency the target experiences can vary by IP for reasons entirely outside its own control or knowledge.
- **Random, not sequential, arrival pattern.** Because the crawler picks random IP/port combinations rather than working through ranges in order, a target cannot infer "we were scanned in sequence with our neighbor's /24" — Shodan's own design goal is explicitly to prevent that kind of predictability.
- **Multiple simultaneous crawlers, geographically distributed**, each tagging its own results with a `_shodan.region` value (visible only in the resulting Shodan banner data, not to the target) — meaning repeated "Shodan scans" of the same target over time may originate from entirely different source IPs and even different regions/ASNs.
- **Protocol-appropriate banner grabs, not just a TCP connect-and-close.** A crawler probing an open HTTP port will issue a real (if minimal) HTTP request to retrieve headers/title/body content for the banner; a crawler probing SSH will complete enough of the SSH handshake to capture the version banner; and so on per-protocol — this is meaningfully more than a bare port-scan touch, and shows up accordingly in application-layer logs, not just connection logs.

## Identifying Shodan Crawler Traffic in Your Own Logs

Shodan **does not publish an official, maintained list of its scanner IP ranges or a documented, self-service opt-out mechanism** — this was checked directly against Shodan's own help center (`help.shodan.io`) and on-demand-scanning documentation, neither of which offers a removal/allowlist-exemption process. What exists instead:

- **Independent academic measurement has fingerprinted specific Shodan infrastructure.** A peer-reviewed NDSS 2025 measurement study ("Revealing the Black Box of Device Search Engine: Scanning Assets, Strategies, and Ethical Consideration") identified **91 distinct Shodan scan-source IPs** over its measurement window, found that only **11 of those 91** carry WHOIS registration information directly attributable to Shodan (the remaining ~82% register through the WHOIS details of whichever cloud provider hosts that particular scanner), that reverse-DNS PTR records, where present, resolve to **`scanf.shodan.io`** or **`census.shodan.io`**-style hostnames, that **23 of the 91 scan-source IPs carry no PTR record at all**, and that roughly 47% of observed scanner IPs geolocate to the US, spread across a mix of enterprise and cloud ISPs. **Treat any specific IP or range as a moving target, not a static list** — Shodan's own reliance on cloud-provider address space for a large share of its scanners means the concrete IPs behind `scanf.shodan.io`/`census.shodan.io` churn as cloud allocations change, and Shodan publishes no official, maintained range list of its own to correlate against.
- **Community-maintained blocklists exist** (several public GitHub gists/repos aggregating observed Shodan/Censys/similar scanner ranges) and are usable as a *supplementary* signal, but should be treated the same way any threat-intel feed of unknown freshness/provenance is treated — a hint to correlate against, not a ground-truth allowlist.
- **The more durable behavioral signals** (survive Shodan rotating its infrastructure, unlike any specific IP list):
  - A single connection (or a handful, clustered tightly in time) grabbing a banner on one or a small number of ports, from a source IP with **no prior relationship** to the target, followed by **no further interaction** — one probe, one banner grab, done. Contrast with an actual attacker's follow-up, which typically shows repeated/varied interaction after initial discovery.
  - **HTTP requests with no `Referer`, no session/cookie behavior, and a generic/library-style `User-Agent`** rather than a real browser's — consistent with an automated banner-grabbing crawler rather than a human or a browser-based tool.
  - **Recurrence at roughly weekly intervals** (or daily, if the target happens to be monitored by someone's Shodan alert) from **varying source IPs/ASNs/regions** over successive visits — a pattern no single-operator active-scanning tool in this module (`Masscan/`, `Nmap/`) produces, since those originate from one fixed operator IP for the duration of an engagement.

## On-Demand Scanning: The One Case With Fresh, Request-Driven Traffic

`shodan scan submit <target>` and `shodan scan internet <port> <protocol>` (per `02 - Hands-On Use Cases.md`) are genuinely different from every other use case in this note: they cause Shodan's own crawler infrastructure to perform a **fresh probe against the requested target shortly after the request is submitted** — real, current-moment traffic, not a read of old data. Critically for a target-side investigator:

- The traffic that arrives is still **sourced from Shodan's own scanner infrastructure**, not from the requesting operator's IP — an on-demand scan is functionally indistinguishable, on the wire, from Shodan's own routine background crawling of the same host, **except for its timing**: it arrives promptly after a specific external request rather than on Shodan's own independent weekly/daily schedule.
- There is **no reliable way for a target to determine, from the traffic alone, that a scan was operator-requested rather than routine** — Shodan's on-demand scan API does not add any distinguishing marker to the resulting probe traffic that a target could observe. The only external corroboration available is the default **24-hour no-rescan restriction** noted in `01 - Overview.md`: if a target sees two distinct Shodan-crawler-pattern visits to the same host less than 24 hours apart, that is inconsistent with the routine weekly/daily baseline and is a reasonable (though not certain — Enterprise accounts can bypass the restriction with `--force`) indicator that an on-demand request occurred.

## Follow-On Active Recon After Target Selection

Everything genuinely attributable to a specific operator, on a specific target, at a specific time, happens **after** the Shodan phase, when the operator's own tools take over per `02 - Hands-On Use Cases.md`'s chained-workflow example:

- A `Masscan`/`Nmap` follow-up scan against the narrowed target list is a fully ordinary active-scanning event with its own, complete evidence trail — see `../Masscan/04 - Target Evidence.md` and `../Nmap/04 - Target Evidence.md`, not re-derived here
- Any direct connection attempt against a specific service Shodan surfaced (an RDP logon attempt, a database connection attempt, etc.) is likewise an ordinary target-side event for that specific protocol/service, documented in the relevant tool's own note or in the corresponding `Windows/`/`Linux/` artifact-reference material
- **None of this later activity carries any Shodan-specific signature.** By the time an operator connects to a target based on Shodan-sourced intelligence, that connection looks identical to one based on intelligence gathered any other way — Shodan's role in the reconnaissance chain is, by design, invisible from this point forward

## Building a Timeline

Given the above, a target-side timeline for "was this org subject to Shodan-based reconnaissance" realistically has only two kinds of entries to work with:

1. **Shodan's own routine/on-demand crawler visits**, reconstructed from perimeter logs using the behavioral signals above (single banner-grab connection, generic library-style client behavior, recurring roughly weekly/daily, varying source infrastructure) — this establishes *that the target is indexed and being kept current*, not that any particular operator looked at the result
2. **Any subsequent active-recon or connection activity** from an operator who evidently used Shodan-sourced intelligence to pick this specific target/service/port combination — inferred circumstantially (an unusually well-targeted first-touch scan hitting exactly the services/ports Shodan would have surfaced, with no preceding broad discovery phase of the operator's own) rather than proven directly, since nothing in that later traffic names Shodan as the source of the targeting decision

This is a genuinely different investigative posture than most tools in this repo: the target-side story is almost entirely about characterizing *ambient* internet-scanner noise correctly (so it isn't mistaken for something else, and so a genuine on-demand-scan anomaly can be told apart from routine crawling) rather than reconstructing a specific operator's actions step by step.
