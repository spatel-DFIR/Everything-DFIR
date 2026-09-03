# BloodHound — BloodHound CE — Hands-On Use Cases

## Contents
- [Baseline Deployment](#baseline-deployment)
- [Ingesting a SharpHound Collection via the Web UI](#ingesting-a-sharphound-collection-via-the-web-ui)
- [Automating Ingestion via the File-Upload API](#automating-ingestion-via-the-file-upload-api)
- [Ingesting AzureHound Output for Entra ID/Azure Paths](#ingesting-azurehound-output-for-entra-idazure-paths)
- [Shortest Path to Domain Admins](#shortest-path-to-domain-admins)
- [Shortest Path from an Owned Principal to Tier Zero](#shortest-path-from-an-owned-principal-to-tier-zero)
- [Finding Kerberoastable Users](#finding-kerberoastable-users)
- [Finding AS-REP Roastable Users](#finding-as-rep-roastable-users)
- [ACL-Abuse Path Discovery](#acl-abuse-path-discovery)
- [Finding Principals with DCSync Rights](#finding-principals-with-dcsync-rights)
- [RBCD and Shadow Credentials Path Discovery](#rbcd-and-shadow-credentials-path-discovery)
- [AD CS (ADCS) Attack Path Discovery](#ad-cs-adcs-attack-path-discovery)
- [Cross-Domain / Forest Trust-Abuse Paths](#cross-domain--forest-trust-abuse-paths)
- [Custom Cypher Queries](#custom-cypher-queries)
- [Marking Owned and Tier Zero Nodes](#marking-owned-and-tier-zero-nodes)
- [OpenGraph — Custom Data Source Ingestion](#opengraph--custom-data-source-ingestion)
- [Chained Workflow: Path Found → Real-World Execution](#chained-workflow-path-found--real-world-execution)

---

## Baseline Deployment

**MITRE ATT&CK:** not applicable — this is analysis-environment setup, not an action against a target.

```bash
# Linux example — verified against the official quickstart and bloodhound-cli source
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install
```

`install` writes default configuration (including a randomly generated `admin` password), pulls the container images, and brings the stack up. The admin password is printed to the terminal/container logs in a decorated block:

```
################################################
# Initial Password Set To:    <random-password> #
################################################
```

```bash
# Watch startup, confirm the "Server started successfully" message before logging in
./bloodhound-cli logs bloodhound -l 200
```

Log in at `http://localhost:8080/ui/login` as `admin` with the printed password; the UI forces an immediate password change on first login. If the password is lost:

```bash
./bloodhound-cli resetpwd   # requires BloodHound >= v7.1.0; wipes existing admin user data
```

By default every container port (`8080` web UI, `7687` bolt, `7474` Neo4j browser) binds to `127.0.0.1` only — verified directly in `examples/docker-compose/docker-compose.yml`. Exposing any of these beyond localhost without changing the shipped default credentials is a self-inflicted target (see `04 - Target Evidence.md`).

## Ingesting a SharpHound Collection via the Web UI

**MITRE ATT&CK:** N/A (local data-processing step; the collection itself is `T1069`/`T1087`/`T1482`-relevant on the SharpHound side — see `SharpHound/02 - Hands-On Use Cases.md`).

1. Run SharpHound against the target (see `SharpHound/`), producing a timestamped `*_BloodHound.zip`.
2. In the BloodHound CE web UI: **Administration → Data Collection → Upload Files**, select the zip (or raw JSON), and submit.
3. BloodHound parses the JSON payload(s) inside, resolves object SIDs/GUIDs, writes nodes/edges into the graph, then runs its post-ingest analysis pass (transitive/composite edge computation) — the UI shows a progress indicator; a typical single-domain environment finishes in a few minutes.

## Automating Ingestion via the File-Upload API

**MITRE ATT&CK:** N/A.

The exact three-call flow, verified directly against the API route registration in `SpecterOps/BloodHound` (`cmd/api/src/api/registration/v2.go`):

```bash
# 1. Start an ingest job (requires the GraphDBIngestManage permission)
curl -s -X POST https://bloodhound.local/api/v2/file-upload/start \
  -H "Authorization: bhesignature $TOKEN_ID" \
  -H "RequestDate: $(date -u +%Y-%m-%dT%H:%M:%S.000Z)" \
  -H "Signature: $COMPUTED_HMAC" | jq .

# 2. Upload the collection bytes to the returned job ID
curl -s -X POST https://bloodhound.local/api/v2/file-upload/$JOB_ID \
  -H "Content-Type: application/zip" \
  --data-binary @sharphound_collection.zip \
  -H "Authorization: bhesignature $TOKEN_ID" -H "RequestDate: ..." -H "Signature: ..."

# 3. Close the job to trigger ingestion
curl -s -X POST https://bloodhound.local/api/v2/file-upload/$JOB_ID/end \
  -H "Authorization: bhesignature $TOKEN_ID" -H "RequestDate: ..." -H "Signature: ..."
```

Programmatic auth uses **HMAC-signed API keys**, not the browser session JWT: every request carries `Authorization: bhesignature <TOKEN_ID>`, `RequestDate` (RFC3339), and `Signature` (base64 HMAC over the request, keyed by the API key's secret) — this is the mechanism behind third-party upload helpers and CI/automation pipelines that feed BloodHound without a human clicking Upload Files. `GET /api/v2/file-upload/accepted-types` lists which MIME types the running version accepts; `GET /api/v2/file-upload/{id}/completed-tasks` (requires `GraphDBIngestRead`) reports per-file ingest status for a job.

## Ingesting AzureHound Output for Entra ID/Azure Paths

**MITRE ATT&CK:** `T1087.004` (Account Discovery: Cloud Account), `T1069.003` (Permission Groups Discovery: Cloud Groups).

```bash
azurehound list --tenant <tenant-id> -u <user> -p <pass> -o azurehound_output.json
```

Upload `azurehound_output.json` exactly like a SharpHound zip — same **Upload Files** UI action, same three-call file-upload API, no separate ingestion mechanism. Once ingested, Azure/Entra objects (`AZUser`, `AZGroup`, `AZApp`, `AZServicePrincipal`, `AZKeyVault`, `AZManagedCluster`, etc.) sit in the **same graph** as the on-prem AD objects, and BloodHound's pathfinding can traverse **across** the two — e.g. an on-prem user with a hybrid-synced Entra identity into an over-privileged Azure role.

## Shortest Path to Domain Admins

**MITRE ATT&CK:** `T1069` (Permission Groups Discovery), `T1069.002` (Domain Groups).

**Prebuilt query name:** *Shortest paths to Domain Admins* (category: Shortest Paths). Verified live production Cypher, `packages/javascript/bh-shared-ui/src/commonSearchesAGT.ts`:

```cypher
MATCH p=shortestPath((t:Group)<-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDACL|MemberOf|
ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|
AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|
ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|
SyncLAPSPassword*1..]-(s:Base))
WHERE t.objectid ENDS WITH '-512' AND s<>t
RETURN p
LIMIT 1000
```

The long relationship-type union is BloodHound's curated **pathfinding edge set** — every edge kind the UI considers a legitimate traversal step for an attack path, not every edge type the graph contains (a handful of purely informational/collection-metadata edges are deliberately excluded). `-512` is the well-known RID suffix for the Domain Admins group, matched via `objectid ENDS WITH` rather than a hardcoded SID since the domain prefix varies per environment. Same query, run via UI: **Explore → Pathfinding tab**, start node left blank/any, end node = the Domain Admins group (or use the prebuilt query directly).

## Shortest Path from an Owned Principal to Tier Zero

**MITRE ATT&CK:** `T1069`, `T1087`.

**Prebuilt query name:** *Shortest paths from Owned objects* — verified production Cypher:

```cypher
MATCH p=shortestPath((s:Base)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDACL|MemberOf|
ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|
AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|
ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|
SyncLAPSPassword*1..]->(t:Base))
WHERE (s:Tag_Owned)
AND s<>t
RETURN p
LIMIT 1000
```

`Tag_Owned` is the dynamic label BloodHound applies internally to every node carrying the `owned` asset-group tag (see `01`). The **many-to-many** variant — *every* Owned node to *every* Tier Zero node at once — ships **commented out** in BloodHound's own source, with the source comment warning it "USE[S] EXCESSIVE SYSTEM RESOURCES AND TYPICALLY WILL NOT COMPLETE." In practice, operators run the one-to-many form above (single Owned node outward) or pick a specific Owned→specific-Tier-Zero pair via Pathfinding rather than the full cross-product.

## Finding Kerberoastable Users

**MITRE ATT&CK:** `T1558.003` (Steal or Forge Kerberos Tickets: Kerberoasting), `T1087.002` (Account Discovery: Domain Account).

**Prebuilt query name:** *All Kerberoastable users* — verified production Cypher:

```cypher
MATCH (u:User)
WHERE u.hasspn=true
AND u.enabled = true
AND NOT u.objectid ENDS WITH '-502'
AND NOT COALESCE(u.gmsa, false) = true
AND NOT COALESCE(u.msa, false) = true
RETURN u
LIMIT 100
```

Note the exclusions: `-502` filters out the built-in `krbtgt` account (technically `hasspn`-eligible logic doesn't apply the same way, and roasting it is not the intended target), and both `gmsa`/`msa` flags exclude (Group) Managed Service Accounts, whose passwords are randomized and rotated automatically — Kerberoasting them yields a hash that's cryptographically useless within hours. A companion prebuilt query, **Kerberoastable users with most admin privileges**, ranks the same result set by `MemberOf|AdminTo` fan-out to prioritize which roastable account is worth cracking first. Once a target account is identified here, the actual roast happens in `Impacket/GetUserSPNs (Kerberoasting)/02 - Hands-On Use Cases.md` — BloodHound only identifies the candidate, it never requests a TGS itself.

## Finding AS-REP Roastable Users

**MITRE ATT&CK:** `T1558.004` (Steal or Forge Kerberos Tickets: AS-REP Roasting).

**Prebuilt query name:** *AS-REP Roastable users (DontReqPreAuth)* — verified production Cypher:

```cypher
MATCH (u:User)
WHERE u.dontreqpreauth = true
AND u.enabled = true
RETURN u
LIMIT 100
```

`dontreqpreauth` mirrors the `DONT_REQ_PREAUTH` bit in `userAccountControl`, collected by SharpHound directly off each user object — BloodHound is only surfacing a property that was always present in AD, not deriving anything new. As with Kerberoasting, BloodHound identifies the candidate; requesting the actual AS-REP and cracking it is a separate tool's job (Impacket's `GetNPUsers.py`, Rubeus `asreproast`).

## ACL-Abuse Path Discovery

**MITRE ATT&CK:** `T1222.001` (File and Directory Permissions Modification — Windows, closest umbrella for AD-object ACL abuse), `T1078.002` (Valid Accounts: Domain Accounts) as the eventual outcome.

**Prebuilt query name:** *Dangerous privileges for Domain Users groups* — verified production Cypher:

```cypher
MATCH p=(s:Group)-[r:Owns|GenericAll|GenericWrite|WriteOwner|WriteDACL|MemberOf|ForceChangePassword|
AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|
CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|
DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword]->(:Base)
WHERE s.objectid ENDS WITH '-513'
AND NOT r:MemberOf
RETURN p
LIMIT 1000
```

`-513` is Domain Users' well-known RID — this query specifically surfaces what the **default, everyone-belongs-to-it group** can already do, excluding plain `MemberOf` edges (since every user trivially satisfies that one and it would drown the result). Every one of the edge kinds in the union corresponds to a real Windows DACL right: `GenericAll` = full control of the object; `GenericWrite` = write any non-protected attribute (can be used to push a logon script or, on a computer object, an SPN); `WriteOwner`/`WriteDACL` = take/rewrite the object's own security descriptor to grant further rights; `ForceChangePassword` = the `User-Force-Change-Password` extended right, reset a password without knowing the current one; `AddMember` = add principals to a group. These are AD-native rights, not something BloodHound invents — it's reading them straight out of `nTSecurityDescriptor` at collection time and rendering them as edges.

## Finding Principals with DCSync Rights

**MITRE ATT&CK:** `T1003.006` (OS Credential Dumping: DCSync).

**Prebuilt query name:** *Principals with DCSync privileges* — verified production Cypher:

```cypher
MATCH p=(:Base)-[:DCSync|AllExtendedRights|GenericAll]->(:Domain)
RETURN p
LIMIT 1000
```

`DCSync` is a real, source-verified edge kind in `packages/go/graphschema/ad/ad.go` — BloodHound synthesizes it whenever a principal holds **both** the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights (or their filtered-set variant) on the domain object, the exact combination `secretsdump.py`'s `-just-dc` and Mimikatz's `lsadump::dcsync` both rely on. The query's union with `AllExtendedRights`/`GenericAll` catches principals who hold a **broader** right that implicitly grants DCSync too (all-extended-rights or full-object-control subsumes the two specific replication rights). Full DRSUAPI protocol mechanics, the exact extended-right GUIDs, and Event 4662 detection are already covered in depth in `Mimikatz/lsadump (DCSync)/` and `Impacket/secretsdump/` — this note does not re-derive them, only maps the graph edge to that existing coverage.

## RBCD and Shadow Credentials Path Discovery

**MITRE ATT&CK:** `T1550.003` (Use Alternate Authentication Material: Pass the Ticket, via the S4U2Self/S4U2Proxy chain RBCD enables), `T1558` (Steal or Forge Kerberos Tickets).

Two distinct edges surface in pathfinding results:

- **`AllowedToAct`** — the target already has Resource-Based Constrained Delegation configured toward a controllable principal (`msDS-AllowedToActOnBehalfOfOtherIdentity` already set).
- **`AddAllowedToAct`** — the operator's identity has *write* rights sufficient to **set** that attribute themselves (the actual RBCD-abuse primitive most engagements use — see `Impacket/ntlmrelayx/02 - Hands-On Use Cases.md`'s `--delegate-access` use case for the write step itself).
- **`AddKeyCredentialLink`** — write rights on `msDS-KeyCredentialLink`, the Shadow Credentials primitive (write an attacker-controlled key-trust certificate onto the target, then request a TGT via PKINIT with no password change).

```cypher
MATCH p=(s)-[:AddAllowedToAct|AddKeyCredentialLink]->(t:Computer)
RETURN p
LIMIT 1000
```

(Not a shipped prebuilt query by this exact name — a straightforward custom Cypher combining the two write-primitive edges, useful as a single hunt for "what RBCD/Shadow-Creds writes can this identity make.")

## AD CS (ADCS) Attack Path Discovery

**MITRE ATT&CK:** `T1649` (Steal or Forge Authentication Certificates).

BloodHound ships a full **Active Directory Certificate Services** query category mapping directly onto the published ESC1–ESC13 misconfiguration classes (SpecterOps's own ADCS research). Verified production Cypher for the most commonly abused, ESC1:

```cypher
MATCH p = (:Base)-[:Enroll|GenericAll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)
WHERE ct.enrolleesuppliessubject = True
AND ct.authenticationenabled = True
AND ct.requiresmanagerapproval = False
AND (ct.authorizedsignatures = 0 OR ct.schemaversion = 1)
RETURN p
LIMIT 1000
```

This finds every principal with enrollment rights on a certificate template that lets the *requester* supply an arbitrary Subject Alternative Name, is usable for client authentication, requires no manager approval, and needs no additional authorized signatures — the exact ESC1 combination that lets a low-privileged enrollee request a certificate impersonating any account, including Domain Admin. Companion prebuilt queries in the same category cover **ESC2** (any-purpose/no-EKU templates), enrollment-agent templates, no-security-extension templates, **ESC7** (CA Administrator/Manager rights), and **ESC8** (published web-enrollment HTTP(S) endpoints — the same primitive `Impacket/ntlmrelayx/`'s `--adcs` relay attack targets). BloodHound identifies the vulnerable template/CA combination; actually requesting the abusive certificate is a separate tool's job (Certipy).

## Cross-Domain / Forest Trust-Abuse Paths

**MITRE ATT&CK:** `T1482` (Domain Trust Discovery).

**Prebuilt query name:** *Map domain trusts* — verified production Cypher:

```cypher
MATCH p = (:Domain)-[:SameForestTrust|CrossForestTrust]->(:Domain)
RETURN p
LIMIT 1000
```

Paired with **Principals with foreign domain group membership** (`MATCH p=(s:Base)-[:MemberOf]->(t:Group) WHERE s.domainsid<>t.domainsid RETURN p`) — the combination of "which domains trust which other domains" plus "which principals already cross that boundary via group membership" is how an operator scopes whether a foothold in Domain A actually has a path into Domain B, without manually walking `nltest /domain_trusts` output and cross-referencing group memberships by hand.

## Custom Cypher Queries

**MITRE ATT&CK:** varies by query intent — no single ID.

The **Cypher tab** accepts arbitrary read queries (and, if `bhe_enable_cypher_mutations` is set, write queries) against the graph, subject to the complexity/memory guardrails covered in `01`. Example — computers where a Kerberoastable user already has an active session, a direct chain from "roast this" to "land here":

```cypher
MATCH p = (u:User {hasspn: true})-[:HasSession]->(c:Computer)
RETURN p
LIMIT 100
```

Custom Cypher is where engagement-specific questions live that no prebuilt query anticipates — e.g. "which service accounts have both `hasspn: true` and `admincount: true`" or "shortest path from this specific phished user to this specific finance-system service account" (narrower and cheaper than the full Owned→Tier-Zero many-to-many).

## Marking Owned and Tier Zero Nodes

**MITRE ATT&CK:** N/A — analyst/operator bookkeeping, not a technique against the target.

Right-click any node in Explore → **"Mark as Owned"** (writes the `owned` asset-group tag) or **"Add to Tier Zero"** (writes `admin_tier_0`). Both are also settable in bulk via the Asset Group Tags API for scripted engagement tracking. Marking is what turns generic pathfinding into "show me paths from *specifically what I've already compromised* to *specifically what actually matters here*" — most real engagements mark Owned incrementally as each new foothold lands, re-running Shortest-Paths-from-Owned after every credential win.

## OpenGraph — Custom Data Source Ingestion

**MITRE ATT&CK:** varies by the underlying system modeled — not AD/Azure-specific.

OpenGraph (introduced v8.0.0, extended in v9.0.0 with structured schema support) lets an operator ingest **non-AD, non-Azure** data — other identity providers, developer platforms (e.g. CI/CD systems), device-management platforms — into the same graph engine, as custom-formatted JSON payloads uploaded through the same file-upload mechanism. This is peripheral to a standard AD/Azure engagement (SharpHound/AzureHound cover that surface completely) but relevant where an environment's actual attack surface extends into systems BloodHound wasn't originally built for.

## Chained Workflow: Path Found → Real-World Execution

**MITRE ATT&CK:** the ID of whatever technique the discovered edge maps to — see the specific use case above.

```
BloodHound identifies edge/path         Real tool executes it against the live target
────────────────────────────────         ─────────────────────────────────────────────
Kerberoastable user (hasspn)      ──▶    Impacket/GetUserSPNs (Kerberoasting)/ → Hashcat/
DCSync rights on Domain object    ──▶    Mimikatz/lsadump (DCSync)/ or Impacket/secretsdump/
AllowedToDelegate / AllowedToAct  ──▶    Rubeus s4u / Impacket ticket chaining
AddKeyCredentialLink              ──▶    Whisker/Certipy-style Shadow Credentials abuse
GenericAll / ForceChangePassword  ──▶    net rpc password reset, Impacket's changepasswd.py
ADCS ESC1/ESC8 template           ──▶    Certipy request / Impacket ntlmrelayx --adcs
Golden/Silver Ticket prerequisite
  (krbtgt or service account hash
  already obtained via another path) ──▶ Mimikatz/kerberos (Golden-Silver Ticket)/
```

This is the loop most engagements actually run: ingest → find a path → execute the edge with the appropriate tool → land a new credential/session → mark it Owned → re-run pathfinding from the new foothold → repeat until Domain Admin or the engagement's defined objective is reached.
