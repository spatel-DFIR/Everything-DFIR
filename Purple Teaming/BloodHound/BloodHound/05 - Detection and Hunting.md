# BloodHound — BloodHound CE — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source (the Operator's Analysis Host)](#hunting-on-source-the-operators-analysis-host)
- [Hunting on Target (BloodHound as a Target Itself)](#hunting-on-target-bloodhound-as-a-target-itself)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

BloodHound CE has no traditional "evasion flags" the way most tools in this repo do — it isn't run against a target's endpoint at all, so there's no AV/EDR bypass surface to rank against. The ranking that matters here is instead about **which signal survives an operator's own basic OPSEC discipline** (rotating default credentials, binding to localhost, clearing history) versus which signals are structurally unavoidable:

| Rank | Signal | Why it ranks here |
|---|---|---|
| **1 (strongest)** | Default `neo4j`/`bloodhoundcommunityedition` or `bloodhound`/`bloodhoundcommunityedition` credentials still working against a discovered instance | Structural — these are published, static strings baked into the public `docker-compose.yml`. Survives unless the operator explicitly rotated them; a huge fraction of real deployments never do |
| **2** | Direct bolt (7687) or Neo4j-browser (7474) access bypassing the BloodHound API entirely | Survives even if the operator locked down the web UI's own auth, since these are separate listeners with their own (often-default) credentials |
| **3** | `bloodhound.config.json` / compose YAML on disk with the initial admin password | Survives password rotation in the UI — the file isn't auto-updated on change, so a stale-but-often-still-informative credential persists |
| **4** | Postgres app-database ingest-job history and asset-group tag timestamps | Survives casual query-history clearing in the UI (if the operator only clears the UI's visible recent-queries list, the underlying Postgres records may remain) |
| **5** | Shell history / bash-history-style artifacts (`bloodhound-cli` invocations, raw `curl` to the file-upload API) | Trivially cleared by the operator — treat as corroborating, not primary |
| **6 (weakest)** | Browser history/session-JWT artifacts | Depends entirely on browser configuration (private browsing, auto-clearing extensions) and is the easiest for even a careless operator to lose |

## Hunting on Source (the Operator's Analysis Host)

Applies when the analysis host itself is available for examination (an incident on red-team infrastructure, or a retro against a purple-team exercise box).

```bash
# Config file with the cleartext initial admin password — check the standard XDG path
find ~/.config/bloodhound ~/Library/"Application Support"/bloodhound 2>/dev/null -name "bloodhound.config.json" -exec cat {} \;

# Compose files with default/rotated DB credentials in the working directory tree
find / -maxdepth 6 -iname "docker-compose*.yml" 2>/dev/null -exec grep -l "bloodhoundcommunityedition\|NEO4J_AUTH\|bhe_neo4j_connection" {} \;

# The distinctive multi-port persistent listener signature — three+ bound ports from one
# container-runtime process tree, unlike this repo's mostly one-shot lateral-movement tools
ss -tlnp | grep -E ':8080|:7687|:7474|:5432'

# Docker/Podman volumes holding the full ingested graph, readable without container auth
docker volume ls --filter "name=neo4j-data" --filter "name=postgres-data"

# Shell-history sweep for setup/ingest commands
grep -E "bloodhound-cli|docker[- ]compose.*bloodhound|azurehound|file-upload" ~/.bash_history ~/.zsh_history 2>/dev/null

# auditd equivalent, durable past history clearing
ausearch -x bloodhound-cli -x docker -x podman 2>/dev/null
```

## Hunting on Target (BloodHound as a Target Itself)

Applies to a defender scanning their own environment for exposed/compromised BloodHound CE instances — not the underlying AD/Azure environment BloodHound was used against (that hunting content lives in `SharpHound/05` and in each specific technique's own `05` file, cross-linked from `02` above).

```bash
# Fleet-wide sweep for the ports this stack uses, from any host with network reach —
# a listener on 8080/7687/7474 that ISN'T supposed to be there is the finding itself
nmap -p 8080,7687,7474,5432 --open <subnet>

# Confirm whether a discovered 8080 is actually BloodHound CE (its login page/API has a
# distinctive response) vs. an unrelated service on the same port
curl -s -o /dev/null -w "%{http_code}\n" http://<host>:8080/ui/login
curl -s http://<host>:8080/api/version | jq .

# Test the shipped default credentials directly against a discovered Neo4j bolt/browser
# port — the single highest-value, lowest-effort check for an exposed instance
curl -u neo4j:bloodhoundcommunityedition -s http://<host>:7474/db/data/ | jq .
```

```powershell
# Windows-hosted deployments (Docker Desktop) — same port-exposure question, host-local view
Get-NetTCPConnection -LocalPort 8080,7687,7474,5432 -State Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress,LocalPort,OwningProcess
```

If access to a suspected-compromised instance's own logs/database is possible:

- Review the Postgres `users`/API-key tables for accounts or keys the legitimate operator team doesn't recognize
- Review file-upload ingest-job history for uploads the legitimate operator didn't initiate
- Review any available Cypher query history for patterns inconsistent with the expected operator's usual query set (broad exploratory queries vs. the prebuilt-library-driven pattern most legitimate operators follow)

## Fleet-Wide Sweep

```bash
# Organization-wide check for any host exposing BloodHound CE's port signature beyond
# localhost — the single most actionable proactive hunt this file can offer, since an
# internet- or intranet-exposed instance with default creds is a near-immediate compromise
for subnet in $(cat internal_subnets.txt); do
    nmap -p 8080,7687,7474 --open "$subnet" -oG - | grep -E '8080/open|7687/open|7474/open'
done
```

Cross-reference any hit against the organization's own known-legitimate BloodHound deployments (red team, purple team, internal AD security tooling) — an unaccounted-for instance is either shadow-IT tooling or a genuinely attacker-deployed one, both worth immediate follow-up.

## Remediation

```bash
# Rotate every default credential immediately if a deployment is found still using them
bloodhound-cli config set NEO4J_SECRET "$(openssl rand -base64 32)"
bloodhound-cli config set POSTGRES_PASSWORD "$(openssl rand -base64 32)"
bloodhound-cli containers down && bloodhound-cli containers up   # required for config changes to take effect

# Force-rotate the admin account if compromise of that specific credential is suspected —
# NOTE this destroys the existing admin user's data, capture any needed evidence first
bloodhound-cli resetpwd
```

- **Capture evidence before remediating** — a compromised instance's Postgres ingest-job history, asset-group tag timestamps, and any recoverable Cypher query history are the best available record of exactly what an attacker learned; rotating credentials and restarting containers doesn't destroy this data, but a full `bloodhound-cli uninstall`/volume wipe does
- Confirm all three ports (8080, 7687, 7474) are bound to `127.0.0.1` unless there's a specific, deliberate, firewalled reason for broader exposure — this is the shipped default and should be the norm, not the exception
- If the instance was reachable from an unexpected network segment, treat the underlying **AD/Azure environment the graph describes** as having had its own attack-path map potentially exposed — this may warrant accelerating remediation of the specific paths (DCSync rights, ADCS misconfigurations, RBCD writes) that instance's graph would have revealed, since an attacker with that data has a head start regardless of whether further compromise is confirmed
