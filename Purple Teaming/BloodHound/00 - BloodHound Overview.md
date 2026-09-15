# BloodHound — Overview

The root page for the `BloodHound/` tool folder. "BloodHound" is really **two tools working as a pair**: a **collector** that walks a live Active Directory (or Entra ID) environment and a **graph-analysis application** that turns what the collector found into attacker-relevant path queries. This page covers what the suite is as a whole, how the two halves fit together, and a table of contents into the 2 sub-tool folders that carry the actual operational depth. This page intentionally stays shallow — go to a sub-tool's own `01 - Overview.md` for its Red Flag Principle, verified command/query reference, and full evidence chain.

## Contents
- [What BloodHound Is](#what-bloodhound-is)
- [Install & Setup](#install--setup)
- [The Two Halves — Collector vs. Analysis Engine](#the-two-halves--collector-vs-analysis-engine)
- [Shared Mechanics Across Sub-Tools](#shared-mechanics-across-sub-tools)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## What BloodHound Is

BloodHound was created by **Andy Robbins (`@_wald0`)**, **Rohan Vazarkar (`@CptJesus`)**, and **Will Schroeder (`@harmj0y`)**, first presented at **DEF CON 24 (2016)** in the talk *"Six Degrees of Domain Admin"* — a title the project's GitHub description still carries. The founding insight: AD privilege escalation is a **graph reachability problem**, not a checklist. Model users, groups, computers, sessions, and ACLs as nodes and edges, and "can I get from this foothold to Domain Admin" becomes a shortest-path query instead of hours of manual enumeration correlation.

Two architecturally distinct generations share the name, and both sub-tool pages in this folder flag the distinction where it matters:

| Generation | Status |
|---|---|
| **BloodHound Legacy** (v1–v4) | Electron desktop GUI + a standalone Neo4j the operator ran separately. Original repo `BloodHoundAD/BloodHound` now redirects to `SpecterOps/BloodHound-Legacy` — not formally archived, but superseded and no longer the recommended deployment path. |
| **BloodHound Community Edition (CE)** — current | A SpecterOps-maintained, containerized rewrite (Go API, React web UI, Neo4j or all-Postgres graph backend, Docker Compose deployment). Actively released under `SpecterOps/BloodHound`, Apache-2.0. **This folder documents CE**, the current tool. |

The project (both the collector and the analysis app) is now maintained by **SpecterOps**, the company its three creators went on to found — everything referenced in this folder lives under the **[`SpecterOps`](https://github.com/SpecterOps)** GitHub org.

## Install & Setup

| Component | Install path |
|---|---|
| **SharpHound** (collector) | Compiled C#/.NET binary from [`SpecterOps/SharpHound`](https://github.com/SpecterOps/SharpHound) — runs on a Windows host (workstation, jump box, or domain-joined attacker VM), either dropped to disk as `SharpHound.exe` or reflectively loaded via the `Invoke-BloodHound` PowerShell wrapper. See `SharpHound/01 - Overview.md` → Prerequisites. |
| **AzureHound** (cloud collector) | Separate Go binary, also [`SpecterOps`](https://github.com/SpecterOps/AzureHound)-maintained — walks Entra ID/Azure via Microsoft Graph and ARM REST APIs. Companion to SharpHound, not a mode of it. |
| **BloodHound CE** (analysis app) | `bloodhound-cli install` (Docker Compose stack — Neo4j or Postgres graph backend, Postgres app-state database, Go API, React web UI). See `BloodHound/01 - Overview.md` → Command-Line Switches for the full `bloodhound-cli` command set. |

There is no single "install BloodHound" step — an operator stands up the CE web application once, then runs SharpHound/AzureHound repeatedly against whatever environment they're assessing and uploads the results in.

## The Two Halves — Collector vs. Analysis Engine

```
Target AD / Entra ID              Operator's analysis host
──────────────────────            ─────────────────────────
   SharpHound.exe                  BloodHound CE (Docker stack)
   (LDAP + SAMR + SMB)   ──JSON/──▶  Upload Files → Neo4j/Postgres
        │                  zip       graph ingest → Cypher queries
   AzureHound                            │
   (MS Graph + ARM REST) ──JSON/─────────┘
                            zip
```

**SharpHound** (and its cloud sibling AzureHound) is the only half of this pair that ever touches the target environment — every LDAP query, SAMR call, and SMB session-enumeration hit lands on a real Domain Controller or member host, and that's where nearly all of this suite's target-side detectable footprint lives. **BloodHound CE** never talks to the target domain at all: it ingests the JSON/zip SharpHound or AzureHound already produced and runs entirely offline from that point on, which is why its own `04 - Target Evidence.md` is deliberately thin on "target" in the traditional sense — the real target-side evidence for the whole BloodHound workflow is documented in `SharpHound/04 - Target Evidence.md`, and what a compromised BloodHound CE deployment itself looks like as a target (its own Neo4j/Postgres backend, exposed with the project's own documented default credentials) is what `BloodHound/04 - Target Evidence.md` actually covers.

Put differently: **SharpHound asks the questions; BloodHound answers them.** An analyst who finds SharpHound traffic on a DC should assume a BloodHound CE instance somewhere has (or will soon have) a full attack-path map of that environment — and an analyst investigating a suspected AD compromise with no obvious SharpHound traffic should still check whether an older graph dump or a compromised BloodHound instance gave the same map away.

## Shared Mechanics Across Sub-Tools

- **Graph vocabulary.** Every finding either sub-tool page discusses ultimately resolves to BloodHound's node/edge model (`User`/`Computer`/`Group`/`Domain`/`CertTemplate`/`AZUser`/etc. nodes; `AdminTo`/`HasSession`/`MemberOf`/`GenericAll`/`WriteDacl`/`ForceChangePassword`/`DCSync`/`AllowedToAct`/`AddKeyCredentialLink`/Azure `AZ*` edges, etc.) — defined once in `BloodHound/01 - Overview.md` → How It Works, not re-derived per collection method.
- **Collection-method ↔ edge mapping.** Nearly every SharpHound `CollectionMethod` flag (`ACL`, `Session`, `LocalAdmin`, `Trusts`, `CertServices`, …) exists specifically to populate one or more BloodHound edge types — reading `SharpHound/01 - Overview.md`'s Collection Methods table alongside `BloodHound/01 - Overview.md`'s edge-type list makes the full input→output chain explicit.
- **Downstream tool chaining.** Both sub-tool pages point the same direction once a path is found — a Kerberoastable-user edge chains into `Impacket/GetUserSPNs (Kerberoasting)/`, a DCSync-rights edge into `Mimikatz/lsadump (DCSync)/` and `Impacket/secretsdump/`, and ticket-abuse findings into Rubeus (Wave 2, not yet built in this repo) — cross-linked inline in each page's Quick Use-Case List rather than restated here.
- **MITRE ATT&CK.** Both sub-tools map primarily to **T1069/T1069.002/T1069.003** (Permission Groups Discovery), **T1087/T1087.002/T1087.004** (Account Discovery), and **T1482** (Domain Trust Discovery) — the *discovery* tactic. Neither tool by itself executes a privilege-escalation or lateral-movement technique; that happens only once an operator acts on a path BloodHound surfaced, using one of the already-built tools cross-linked above.

## Sub-Tool Table of Contents

| Sub-Tool | Covers |
|---|---|
| [`SharpHound/`](SharpHound/01%20-%20Overview.md) | The C#/.NET collector — two-phase LDAP (directory-wide) + SMB/RPC (per-computer) enumeration, `CollectionMethod` flags, `--Stealth`, throttling/jitter, and the DC-side `SDFlags=0x5` LDAP-query signature that's the single strongest detection hook in the whole suite. |
| [`BloodHound/`](BloodHound/01%20-%20Overview.md) | The CE analysis application — ingestion pipeline, graph model, Cypher/prebuilt queries (Shortest Path, Kerberoasting, DCSync, ACL abuse, ADCS, Azure), and why an exposed, default-credentialed BloodHound backend is itself a legitimate target. |

Every sub-tool page shares this page's graph vocabulary and collection-to-edge mapping above — neither re-derives it.
