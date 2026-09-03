# BloodHound — BloodHound CE — Target Evidence

## Contents
- [Scoping Note — Two Very Different "Targets"](#scoping-note--two-very-different-targets)
- [The Real Target-Side Footprint Lives in the Collection Phase](#the-real-target-side-footprint-lives-in-the-collection-phase)
- [When BloodHound CE Itself Is the Target](#when-bloodhound-ce-itself-is-the-target)
- [Filesystem Evidence on a Compromised BloodHound Host](#filesystem-evidence-on-a-compromised-bloodhound-host)
- [Network-Layer Evidence of Access to a BloodHound Instance](#network-layer-evidence-of-access-to-a-bloodhound-instance)
- [Application-Layer Evidence Inside a Compromised Instance](#application-layer-evidence-inside-a-compromised-instance)
- [What an Attacker Gains from a Compromised BloodHound Instance](#what-an-attacker-gains-from-a-compromised-bloodhound-instance)
- [Building a Timeline](#building-a-timeline)

---

## Scoping Note — Two Very Different "Targets"

This file has to cover two entirely different meanings of "target," and conflating them is the single easiest mistake an analyst can make with this tool:

1. **The AD/Azure domain BloodHound's *data* describes.** BloodHound CE generates **zero** direct network traffic or host artifacts on the real target domain. It analyzes data that already exists. Whatever target-side footprint an engagement leaves came from **SharpHound/AzureHound's collection phase** — a completely separate tool with its own LDAP/SAMR/SMB/Graph-API traffic, its own event-log signature, and its own detection story, covered in full in `SharpHound/04 - Target Evidence.md`. **This file does not re-derive that content.**
2. **The BloodHound CE deployment itself**, if an attacker pivots onto the operator's own analysis infrastructure — the Docker host, the exposed Neo4j/Postgres backend, or the web UI. This is a real, growing scenario (red-team infrastructure gets targeted like anything else, and misconfigured/internet-facing BloodHound instances have been found in the wild) and is where this file's actual original content lives.

## The Real Target-Side Footprint Lives in the Collection Phase

To be explicit about what an analyst should go read instead of expecting it here: LDAP query volume/pattern, SAMR session enumeration, DCOM/WMI calls for computer-session collection, the resulting Security/LDAP-interface event-log signature, and SharpHound's own binary/PowerShell execution artifacts on collection hosts are **all SharpHound's evidence, not BloodHound's** — see `SharpHound/04 - Target Evidence.md`. Where a discovered graph edge maps onto a technique this repo covers elsewhere with its own full target-evidence treatment (DCSync, Kerberoasting, RBCD, Golden/Silver Tickets, ADCS abuse), that tool's own `04 - Target Evidence.md` is the authoritative source — cross-linked throughout `02` above — not duplicated here.

## When BloodHound CE Itself Is the Target

A BloodHound CE deployment is an attractive target in its own right for a very specific reason: **it is, by design, a pre-computed map of the exact same domain-dominance paths an attacker wants to find.** Compromising the analysis instance can skip the entire collection-and-analysis effort a from-scratch attacker would otherwise need — including the loud, detectable LDAP/SAMR enumeration traffic SharpHound generates. This makes the BloodHound host itself a legitimate incident-response target, whether it belongs to a red team, a purple-team exercise, or (increasingly, per public reporting on exposed instances) a real organization's own internal security tooling.

## Filesystem Evidence on a Compromised BloodHound Host

If an attacker gains filesystem access to the Docker/Podman host running the stack (via any of this repo's own lateral-movement tools, or simply because the box was internet-facing and weakly secured):

| Artifact | What it reveals |
|---|---|
| `~/.config/bloodhound/bloodhound.config.json` (or platform-equivalent XDG path) | Initial admin password in cleartext (see `03`), even if since rotated in the UI |
| `docker-compose.yml` / `docker-compose.dev.yml` in the deployment working directory | Literal default DB credentials (`neo4j`/`bloodhoundcommunityedition`, `bloodhound`/`bloodhoundcommunityedition`) if never overridden — readable without any cracking |
| `.env` file alongside the compose YAML, if present | Rotated credentials, if the operator did change them — still plaintext |
| `neo4j-data` / `postgres-data` Docker volumes | The entire ingested attack-path graph and application state, mountable and readable directly from the host filesystem without ever authenticating to the running containers |

## Network-Layer Evidence of Access to a BloodHound Instance

```bash
# On the BloodHound host itself, or from network capture/NetFlow if the box is monitored
ss -tn state established '( dport = :8080 or dport = :7687 or dport = :7474 or dport = :5432 )'
```

- **Port 8080 (web UI/API)** — any inbound connection from a source IP that isn't the expected operator range is the primary anomaly signal. If the deployment binds `0.0.0.0` instead of the documented `127.0.0.1` default, this port is reachable from anywhere with network access — internet-wide if unfortunate placement/firewalling allows it
- **Port 7687 (Neo4j bolt)** — a direct bolt connection bypassing the BloodHound API entirely (e.g. via `cypher-shell` or a Neo4j driver library) is a strong signal of an attacker who has recovered Neo4j credentials and is querying the graph **directly**, skipping the application layer's own audit logging entirely — this is a materially quieter path into the same data than using the web UI, and worth flagging as the higher-severity access pattern
- **Port 7474 (Neo4j browser)** — same significance as bolt access, but via Neo4j's own web console; also directly exposes a **query editor with no BloodHound-side audit trail**
- **Port 5432 (Postgres)** — commented out/disabled in the shipped compose file by default (verified: `# ports:` is literally commented in `examples/docker-compose/docker-compose.yml`'s `app-db` service); any listener here at all means an operator explicitly uncommented it, itself worth flagging regardless of who's connecting

## Application-Layer Evidence Inside a Compromised Instance

Once inside (via the web UI with recovered admin credentials, or directly against Neo4j/Postgres):

- **New/unexpected user accounts** in the BloodHound Postgres `users` table, or new API keys under Administration — an attacker who wants durable access will often create their own account/key rather than continuing to use recovered admin credentials that might get rotated
- **Unusual Cypher query patterns** in Postgres's saved-query history or (if enabled) audit log — a legitimate operator's query pattern tends to follow the prebuilt-query library closely; an attacker unfamiliar with the specific engagement's naming/structure often runs broader, more exploratory custom Cypher first
- **Bulk data export activity** — BloodHound's UI/API supports exporting query results/graph data; a sudden bulk export shortly after first access is consistent with an attacker exfiltrating the entire attack-path map rather than interactively exploring it
- **New file-upload ingest jobs the legitimate operator didn't initiate** — an attacker with write access might feed the instance their own freshly collected SharpHound data to enrich or refresh a stale graph, visible in the ingest-job history

## What an Attacker Gains from a Compromised BloodHound Instance

This is the honest "so what" for defenders triaging a compromised instance: everything the legitimate operator already found. Every Shortest-Path-to-Domain-Admins result, every DCSync-eligible principal, every Kerberoastable account, every ADCS ESC misconfiguration, every Owned/Tier-Zero marking — all of it sitting pre-computed in the graph. An attacker who reaches this data skips weeks of legitimate reconnaissance effort and inherits the exact roadmap a red team or the organization's own security team built. This is also why marking a node **Owned** is operationally sensitive data in its own right on a real engagement — it's a literal list of every credential/foothold the operator has confirmed, not just a UI convenience.

## Building a Timeline

For a compromised-BloodHound-instance incident specifically, the useful chain is: initial access to the analysis host or exposed backend (correlate with whatever lateral-movement/initial-access tool got the attacker there — this repo's other tool folders cover that evidence) → filesystem/credential access to `bloodhound.config.json`/compose files or direct Neo4j/Postgres connection (this file, above) → application-layer access establishing which data was viewed/exported (this file, above) → subsequent real-world exploitation of whichever specific paths the compromised graph revealed, which is where the timeline hands off to that specific technique's own tool folder (`Mimikatz/`, `Impacket/`, etc.) for target-side evidence on the underlying AD/Azure environment itself. The critical correlation point for an examiner: **a compromised BloodHound instance can make an attacker's subsequent moves look suspiciously well-informed and efficient** — an attacker who goes straight for a specific DCSync-eligible account or a specific ADCS template with no visible prior enumeration traffic on the domain itself is a strong indicator they had access to a pre-built graph rather than having enumerated the environment themselves.
