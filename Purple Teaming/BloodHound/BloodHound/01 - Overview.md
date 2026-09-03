# BloodHound — BloodHound CE — Overview

> 🔴 **Red Flag Principle:** BloodHound itself never touches the target domain — it is a local graph-query engine chewing on data SharpHound/AzureHound already stole (see the sibling `SharpHound/` folder for that collection phase). There is no "BloodHound traffic" to hunt for on a Domain Controller; the real signal is whatever tool the operator runs *next* once a path is found — DCSync via `Mimikatz/lsadump (DCSync)/` or `Impacket/secretsdump/`, Kerberoasting via `Impacket/GetUserSPNs (Kerberoasting)/`, ticket abuse via Rubeus. The one place BloodHound *does* generate its own, first-party footprint a blue team can actually find is the **operator's own analysis host and, if network-exposed, the Neo4j/PostgreSQL backend itself** — the project's official `docker-compose.yml` ships literal, publicly documented default credentials (`neo4j`/`bloodhoundcommunityedition`, `bloodhound`/`bloodhoundcommunityedition`) and binds them to `127.0.0.1` only by explicit design choice. An exposed bolt port `7687` or a `0.0.0.0`-bound Postgres carrying those unrotated defaults isn't collateral — it's a target in its own right, and increasingly a real one, since a compromised BloodHound instance hands an attacker the same domain-dominance map a legitimate operator built.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

BloodHound was created by **Andy Robbins (`@_wald0`)**, **Rohan Vazarkar (`@CptJesus`)**, and **Will Schroeder (`@harmj0y`)**, first presented at **DEF CON 24 (2016)** in the talk *"Six Degrees of Domain Admin"* — a title the project's GitHub description still carries verbatim today. The original insight, drawn from years of red-team engagements, was that Active Directory privilege escalation is fundamentally a **graph reachability problem**: the question "can I get from a low-privilege foothold to Domain Admin" is answerable by modeling users, groups, computers, sessions, and ACLs as nodes and edges and running a shortest-path query, rather than manually chaining enumeration output by hand. Vazarkar built the original data collector into what became **SharpHound**.

Two distinct, architecturally different codebases now share the BloodHound name, and an analyst needs to tell them apart on sight:

| Generation | Stack | Repo status (verified live) |
|---|---|---|
| **"BloodHound Legacy"** (v1–v4) | Electron desktop GUI + a standalone Neo4j 3.5 install the operator ran separately | Original repo `BloodHoundAD/BloodHound` now **redirects to `SpecterOps/BloodHound-Legacy`** (verified via the GitHub API — `full_name` resolves there); not formally archived, but community guidance and the project's own docs treat it as superseded and no longer the recommended deployment path |
| **BloodHound Community Edition (CE)** — **current, primary subject of this note** | Rewritten by SpecterOps as a multi-container stack: Go API backend, React web UI, Neo4j (or, as of newer releases, an all-PostgreSQL graph backend) for the graph, PostgreSQL for application state, orchestrated via Docker Compose | `SpecterOps/BloodHound`, Apache-2.0 license, actively released — latest tag at time of writing is **v9.5.1** (2026-07-29). Maintained by the SpecterOps team |

The practical difference an analyst needs to internalize: Legacy shipped as a single Electron `.exe`/`.app` an operator ran directly against a Neo4j they'd installed themselves (no bundled auth model, no multi-user support, no built-in ingestion API). CE is a **web application with its own accounts, sessions, and REST/HMAC API**, deployed as containers — the entire operating model, including where credentials and session tokens live, is different. This note covers **CE**, flagging Legacy differences only where an analyst is likely to encounter one in the wild (older engagement notes, older malware/tooling assuming the desktop app, dated blog posts).

## How It Works

### The two-phase split this note deliberately does not re-derive

BloodHound CE has no data-collection mechanics of its own. Everything it analyzes was gathered by a **separate collector** run against the live target environment:

- **SharpHound** — walks on-prem Active Directory over LDAP, SAMR, and SMB (sessions, local group membership, ACLs). Full mechanics: sibling folder `BloodHound/SharpHound/`.
- **AzureHound** — walks Entra ID/Azure over the Microsoft Graph and Azure Resource Manager REST APIs.

Both emit a JSON payload (SharpHound zips multiple JSON files together by default). **Everything from that point forward — ingestion and analysis — is what this folder covers**, and it happens **entirely offline** with respect to the target domain: once the collection files exist, an operator can disconnect from the target network entirely and still run every query in this note.

### Pipeline

```
Target AD / Entra ID                  Operator's analysis host                  Operator's next move
──────────────────────                ─────────────────────────                 ────────────────────
SharpHound / AzureHound
(out of scope here —
see SharpHound/ folder)
        │
        ▼
 zip / JSON collection
 file(s) on disk ─────────────▶ Upload via web UI ("Upload Files")
                                 OR the file-upload REST API
                                 (POST /api/v2/file-upload/start
                                  → POST .../{id}  [chunks]
                                  → POST .../{id}/end)
                                        │
                                        ▼
                                 BloodHound Go API parses JSON,
                                 resolves SIDs/GUIDs, writes
                                 nodes + edges into the graph
                                 backend (Neo4j bolt://7687 by
                                 default, or an all-Postgres
                                 graph backend — selectable via
                                 `bloodhound-cli graphDriver`)
                                        │
                                        ▼
                                 Post-ingest analysis pass computes
                                 transitive/composite edges (nested-
                                 group AdminTo, transitive MemberOf,
                                 etc.) — "initial graph analysis,"
                                 ~1 minute per the official docs
                                        │
                                        ▼
                                 Operator queries via the web UI:
                                 Explore search / Pathfinding tab /
                                 Cypher tab / prebuilt query library
                                                │
                                                ▼
                                                        Path found (e.g. Kerberoastable
                                                        user → AdminTo → Domain Admins)
                                                        ──▶ hand off to Impacket/
                                                        GetUserSPNs, Rubeus, Mimikatz,
                                                        Certipy, etc. against the target
```

Application state (user accounts, sessions/JWTs, saved queries, asset-group tags like Owned/Tier Zero, audit log) lives in **PostgreSQL** regardless of which graph backend is selected — the graph database and the app's own operational database are always two separate stores, even in the Neo4j-default configuration. Verified directly in the project's `examples/docker-compose/docker-compose.yml`: the `bloodhound` container's `bhe_database_connection` env var points at the Postgres `app-db` service, entirely separate from `bhe_neo4j_connection`.

### The graph model — what an analyst is actually looking at

Every object BloodHound knows about is a **node** with a type label (`User`, `Computer`, `Group`, `Domain`, `OU`, `GPO`, `CertTemplate`, `EnterpriseCA`, Azure equivalents like `AZUser`/`AZApp`/`AZServicePrincipal`, etc.) and a set of properties (`hasspn`, `dontreqpreauth`, `unconstraineddelegation`, `admincount`, and dozens more, all populated straight from what SharpHound/AzureHound collected). Every **relationship** between two nodes is an **edge**, and each edge kind maps to a specific, real-world AD/Azure primitive an attacker can abuse to move from one node's control to the other's — `AdminTo`, `HasSession`, `MemberOf`, `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDACL`, `ForceChangePassword`, `AddMember`, `Owns`, `DCSync`, `AllowedToDelegate`/`AllowedToAct` (RBCD), `AddKeyCredentialLink` (Shadow Credentials), and Azure-side equivalents prefixed `AZ*` (`AZGlobalAdmin`, `AZContributor`, `AZAddSecret`, `AZOwns`, etc.) — all verified directly against the live `packages/go/graphschema/` source in `SpecterOps/BloodHound`, not assumed from memory or older write-ups (several older edge names circulating in blog posts and cheat sheets have since been renamed).

**BloodHound doesn't find a "vulnerability."** It finds a **graph traversal** — a chain of edges an operator (or an already-compromised principal) can walk from a **start node** to a **high-value end node**. That's the entire value proposition: turning "which of these 40,000 ACL entries actually matters" into "here is the one 4-hop path from the user you just phished to Domain Admins."

### Tags: Owned and Tier Zero (formerly "High Value")

Two special markers drive most pathfinding: **`owned`** (a principal/asset the operator has confirmed control of) and **`admin_tier_0`** (BloodHound's own designation for maximally privileged objects — Domain Admins, DCs, `krbtgt`, etc., seeded by default and operator-extendable). Both are verified constants in the BloodHound source (`packages/go/graphschema/ad/const.go`: `Owned = "owned"`, `AdminTierZero = "admin_tier_0"`). In Cypher queries these surface as dynamic node labels `Tag_Owned` and `Tag_Tier_Zero` rather than the raw tag string — a detail that matters if an analyst is reading a custom Cypher query out of an operator's history and needs to recognize what it's matching against. The UI's older "High Value" terminology is being phased in favor of "Tier Zero" across the current release line; both names refer to the same underlying tag and may appear side-by-side depending on exact version.

### Query safety limits — and why they exist

Full graph shortest-path (many-to-many, e.g. "every Owned node to every Tier Zero node") is deliberately **not** offered as a one-click prebuilt query — the shipped query for it is present in the UI's own source **commented out**, with the comment reading verbatim: *"MANY TO MANY SHORTEST PATH QUERIES USE EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE."* Two environment variables gate custom Cypher: `bhe_disable_cypher_complexity_limit` (default `false`) caps expensive query patterns, and `bhe_graph_query_memory_limit` (default `2`, in GB) bounds per-query memory — both are real, source-verified settings in `docker-compose.yml`, not assumptions.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Graph backend protocol | Neo4j **Bolt** (binary graph protocol, port 7687 by default) — or, on newer releases, an all-PostgreSQL graph driver selectable via `bloodhound-cli graphDriver pg` / the `GRAPH_DRIVER` env var |
| Application database | PostgreSQL (app-state: accounts, sessions, saved queries, asset-group tags, audit log) — always separate from the graph store |
| Web/API transport | HTTP(S) REST API + React SPA, default port **8080** |
| Ingestion transport | Multi-step REST upload (`/api/v2/file-upload/start` → `/api/v2/file-upload/{id}` → `/api/v2/file-upload/{id}/end}`), authenticated by either a browser session JWT or an HMAC-signed API key (`Authorization: bhesignature <TOKEN_ID>`, `RequestDate`, `Signature` headers) |
| Analysis/query language | **Cypher** (Neo4j's graph query language), exposed directly to the operator via the UI's Cypher tab and used internally by every prebuilt query |
| Deployment orchestration | Docker Compose v2 (or Podman with Docker-compatibility mode), wrapped by the official `bloodhound-cli` Go binary |
| Upstream collection protocols (out of scope, cross-linked) | LDAP/LDAPS, SAMR, SMB, MS-DRSR (SharpHound — see `SharpHound/`); Microsoft Graph + Azure Resource Manager REST (AzureHound) |

## Command-Line Switches — Quick Reference

BloodHound CE is primarily GUI/query-driven, not flag-driven — this table adapts the "switches" concept to the tool's actual operator-facing surfaces: the **`bloodhound-cli`** setup/management binary (verified directly against its `cmd/*.go` source in `SpecterOps/bloodhound-cli`), and the **key UI actions** an operator treats as their day-to-day "commands."

**`bloodhound-cli` subcommands**

| Command | Plain-English meaning |
|---|---|
| `bloodhound-cli install` | First-time setup: writes default config, pulls/builds the Docker containers, creates the default `admin` account with a randomly generated password. Only meant to run once |
| `bloodhound-cli up` / `bloodhound-cli down` | Shortcuts for `containers up` / `containers down` |
| `bloodhound-cli containers up` | Build, (re)create, and start all BloodHound containers |
| `bloodhound-cli containers down` | Bring down all services and remove the containers |
| `bloodhound-cli containers start` / `stop` | Start stopped services / stop running services without removing containers |
| `bloodhound-cli containers restart` | Restart all stopped and running services |
| `bloodhound-cli containers build` | Rebuild containers — only needed for updates |
| `bloodhound-cli config` | Display the full current configuration |
| `bloodhound-cli config get <key> [<key>...]` | Print specific configuration values (e.g. `ADMIN_PASSWORD`, `POSTGRES_PASSWORD`) |
| `bloodhound-cli config set <key> <value>` | Change a configuration value; requires bringing containers down and back up to take effect |
| `bloodhound-cli logs <bloodhound\|neo4j\|postgres> [-l <lines>]` | Fetch container logs by service name (default 500 lines) |
| `bloodhound-cli resetpwd` | Wipes and recreates the default `admin` account with a new random password — requires BloodHound ≥ v7.1.0, destroys existing admin user data |
| `bloodhound-cli check` | Evaluate the Docker environment and download the needed Compose YAML files if missing |
| `bloodhound-cli running` | List currently running BloodHound services |
| `bloodhound-cli graphDriver neo4j` / `bloodhound-cli graphDriver pg` | Switch the graph storage backend between Neo4j and the all-PostgreSQL driver |
| `bloodhound-cli update` | Pull newer container images if available |
| `bloodhound-cli uninstall` | Remove all BloodHound containers, images, and volume data |
| `bloodhound-cli version` | Print the CLI's own version |

**Key UI actions ("commands" for a GUI-driven tool)**

| Action | Plain-English meaning |
|---|---|
| **Upload Files** | Ingest a SharpHound/AzureHound zip or JSON collection — drives the file-upload REST API under the hood |
| **Explore → search bar** | Free-text node lookup by name/ObjectID — the starting point for manual investigation |
| **Explore → Pathfinding tab** | Pick a start node and an end node; BloodHound computes the shortest attack-path traversal between them using only edges flagged as pathfinding-eligible (a curated subset — e.g. plain `GenericWrite` counts, but not every collected edge does) |
| **Explore → Cypher tab** | Raw Cypher query execution against the graph — the escape hatch for anything the prebuilt library doesn't cover |
| **Prebuilt/common queries list** | A curated library of ready-made Cypher queries grouped by category (Domain Information, Dangerous Privileges, Kerberos Interaction, Shortest Paths, AD CS, Azure, etc.) — see `02` for the verified query text behind the most operationally relevant ones |
| **Node context menu → "Mark as Owned"** | Tags a node with the `owned` asset-group tag, seeding it as a start point for "Shortest Paths from Owned" queries |
| **Node context menu → "Add to Tier Zero"** (formerly "Add to High Value") | Tags a node with `admin_tier_0`, marking it as an end point for "Shortest Paths to Tier Zero" queries |
| **Administration → Data Collection** | View ingest job history/status, accepted file types, and completed-tasks detail for a given upload job |

## Quick Use-Case List

- Baseline deployment via `bloodhound-cli install` (Docker Compose stack: Neo4j/Postgres graph+app databases, API, web UI)
- Ingesting a SharpHound collection zip/JSON through the web UI's Upload Files workflow
- Automating/scripting ingestion via the HMAC-signed file-upload REST API instead of the UI
- Ingesting AzureHound output to bring Entra ID/Azure objects and edges into the same graph
- Finding the shortest path from any principal to Domain Admins / Tier Zero
- Finding the shortest path from an already-**Owned** principal to a Tier Zero target
- Enumerating Kerberoastable users (`hasspn=true`) — cross-links into `Impacket/GetUserSPNs (Kerberoasting)/`
- Enumerating AS-REP roastable users (`dontreqpreauth=true`)
- Discovering ACL-abuse paths — `GenericAll`/`GenericWrite`/`WriteOwner`/`WriteDACL`/`ForceChangePassword`/`AddMember`/`Owns` edges
- Finding principals with **DCSync** rights on the domain object — cross-links into `Mimikatz/lsadump (DCSync)/` and `Impacket/secretsdump/`
- Discovering RBCD (`AllowedToAct`) and Shadow Credentials (`AddKeyCredentialLink`) abuse paths
- Discovering AD CS attack paths (ESC1/ESC2/ESC3/ESC4/ESC6/ESC8/ESC9/ESC10/ESC13-style template/CA misconfigurations) — cross-links into a future `Certipy/` folder
- Mapping cross-domain/forest trust-abuse paths (`SameForestTrust`/`CrossForestTrust`, foreign group membership)
- Writing custom Cypher queries beyond the prebuilt library for engagement-specific questions
- Marking nodes **Owned** and **Tier Zero** to seed and scope further pathfinding as an engagement progresses
- Ingesting non-AD/Azure custom data sources via **OpenGraph** (identity providers, dev platforms, device management — a newer, more peripheral capability)
- Chained workflow: a BloodHound-identified path feeding directly into Rubeus (ticket abuse), Mimikatz (credential/ticket ops), Impacket (remote exec/secrets), or Certipy (ADCS abuse) against the real target

Full walkthroughs with commands, verified Cypher, and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine + Compose v2 (or Podman with Docker-compatibility mode) | The entire CE stack runs as containers; no bare-metal install path is documented as primary |
| Already-collected SharpHound and/or AzureHound output | BloodHound has no collection capability of its own — see `SharpHound/` for that phase |
| Sufficient local RAM/CPU headroom | Neo4j graph analysis over a large domain (tens of thousands of objects) is memory-intensive; `bhe_graph_query_memory_limit` caps *query*-time memory but ingestion/analysis itself needs real headroom |
| Network reachability to the **target domain** | **Not required** for BloodHound CE itself once collection files exist — this is the whole point of the offline analysis phase. Reachability is only a SharpHound/AzureHound-phase requirement |
| Ingestion permission (`GraphDBIngestManage`) on the BloodHound user/API key used | Verified in the API route registration — uploading requires this specific permission, not just any authenticated session |
| A browser (for UI use) or an HMAC-capable HTTP client (for API automation) | The API auth model (`bhesignature` HMAC headers) is a real, documented mechanism for non-interactive uploads/queries, not a UI-only tool |

Full command syntax, every use case's MITRE ATT&CK mapping, and verified Cypher for the prebuilt queries referenced above are in `02 - Hands-On Use Cases.md`.
