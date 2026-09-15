# AdFind — Target Evidence

Set expectations correctly before anything else: AdFind's "target" is a **domain controller answering a normal, authenticated LDAP read** — not a host AdFind executes on or drops anything to. There's no filesystem drop, no registry write, no service, no scheduled task, nothing analogous to the persistence/execution artifacts most other tools in this repo leave on their target. What a domain controller sees is **query traffic and, by default, almost nothing else** — Windows does not log LDAP search content on a DC out of the box. This makes AdFind's Target Evidence page deliberately thin, consistent with `PLANNING.md`'s note that not every tool has heavy content in every section — the real evidence for an AdFind operation lives on the *source* side (`03 - Source Evidence.md`), not here.

## Contents
- [Why There's No Filesystem/Registry Story](#why-theres-no-filesystemregistry-story)
- [LDAP Query Telemetry on the Domain Controller](#ldap-query-telemetry-on-the-domain-controller)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Behavior on the DC](#endpoint-security-product-behavior-on-the-dc)
- [Building a Timeline](#building-a-timeline)

---

## Why There's No Filesystem/Registry Story

AdFind performs exactly one kind of operation against its target — an LDAP bind followed by a search request — and both are inherently read-only from the DC's perspective. There is no equivalent here to a dropped service binary, a scheduled task, a registry Run key, or any of the artifact classes that anchor most other tool pages in this repo. If an operator also uses their AdFind session's access to make a *write* (adding an SPN, modifying a group), that's a distinct, separately-logged AD write operation outside AdFind's own capability — AdFind itself has no write mode. Where enumeration purposes overlap with a tool that *can* write (e.g. `setspn -S` adding an SPN to a writable account), see `../LOLBins/setspn/04 - Target Evidence.md` for that artifact story instead of expecting it here.

## LDAP Query Telemetry on the Domain Controller

Standard Windows domain controllers **do not log LDAP search content by default.** The one native mechanism that can capture a filter string is not designed as a security control at all:

| Log | Event ID | What it captures | Caveat |
|---|---|---|---|
| Directory Service (on the DC) | **1644** | The LDAP filter text, base DN, client IP, and performance metrics (objects visited, objects returned, execution time) for a search that crosses configured "expensive" or "inefficient" thresholds | **Not enabled by default.** Requires the `Field Engineering` diagnostics registry value under `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics` to be raised to `5`, and by design only fires for searches that are slow/expensive (default threshold 30,000 ms execution time, or high visited/returned-object counts) — a fast, well-indexed AdFind query (most of them, since AdFind's default filters target well-indexed attributes like `objectCategory`) may never trigger it at all. This is a performance-troubleshooting feature Microsoft built for DC administrators, not a security-logging feature, and most environments never turn it on |
| Directory Service | 1136/1137/etc. (LDAP interface events) | Bind/connection-level statistics, not filter content | Present in some configurations but does not carry query text |

Practically: **assume the DC-side event log carries no record of a typical AdFind query unless 1644 diagnostics were already enabled for unrelated performance-troubleshooting reasons**, and even then, only for the subset of queries expensive enough to cross the threshold. This is the core reason this note leans so heavily on source-side command-line evidence (`03 - Source Evidence.md`) rather than target-side logging — for this specific tool, the source-side story is genuinely the stronger one.

## Network-Layer Evidence

The one target-side evidence class that's reliably present regardless of DC logging configuration — because it's produced by the network layer, not application-level auditing:

| Source | What it shows |
|---|---|
| Firewall / network flow logs on or in front of the DC | Inbound connection to TCP 389 (LDAP) / 636 (LDAPS) for a standard domain query, or 3268/3269 for a Global Catalog query — source IP, timestamp, connection duration |
| Zeek `ldap.log` (if network segment is monitored) | Captures the LDAP protocol exchange at a structured level — bind DN/method, and depending on Zeek version and TLS status, potentially search-request details for unencrypted LDAP. LDAPS traffic (636/3269) is opaque to a passive network sensor without a TLS-inspection capability |
| NetFlow / switch logs | A source host connecting to a DC's 389/636/3268/3269 with no prior legitimate administrative relationship to that DC is a coarse but genuinely useful anomaly signal, especially at fleet scale (see `05 - Detection and Hunting.md`'s fleet-wide sweep) |

Encrypted LDAPS traffic (`-ssl`/`-starttls` in AdFind, or an environment that enforces LDAP signing/channel binding) defeats content inspection at the network layer entirely — connection metadata (source, destination, port, duration, volume) is all that survives, which is why the network-layer signal here is corroborating rather than primary.

## Endpoint Security Product Behavior on the DC

There is effectively no "target-side" endpoint-security angle distinct from what's already covered on the source host in `03 - Source Evidence.md` — the DC isn't running the AdFind binary, it's answering a query from it. Where a DC *does* run local endpoint security tooling, that product's own network/behavioral telemetry (unusually broad or high-volume LDAP query patterns from a given source, if the product has that visibility) is the relevant angle, not a file- or process-based detection, since no AdFind-related file or process exists on the DC itself.

## Building a Timeline

Given how little the DC itself contributes natively, timeline-building for an AdFind operation is really a **source-side exercise correlated against sparse target-side network telemetry**: `[Sysmon 1 / Security 4688 process creation for AdFind.exe on the source host, full command line]` → `[outbound connection to the DC's 389/636/3268/3269 in the same window, source-side netstat/EDR or target-side firewall/NetFlow log]` → `[Directory Service 1644, only if diagnostics were already enabled and the specific query was expensive enough to trigger it]`. In the overwhelming majority of real investigations, the first two are all that's recoverable — treat any additional DC-side query-content evidence as a bonus, not something to plan a detection strategy around. See `05 - Detection and Hunting.md`'s Hunting Priority table for how this thin evidence shape drives which signal to actually hunt on first.
