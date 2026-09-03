# BloodHound — BloodHound CE — Source Evidence

## Contents
- [Scoping Note — What "Source" Means for an Offline Analysis Tool](#scoping-note--what-source-means-for-an-offline-analysis-tool)
- [Configuration Files — Cleartext Credentials by Design](#configuration-files--cleartext-credentials-by-design)
- [Docker/Podman Artifacts](#dockerpodman-artifacts)
- [Collection Files Staged for Upload](#collection-files-staged-for-upload)
- [Live Process and Container State](#live-process-and-container-state)
- [Local Network-Connection State](#local-network-connection-state)
- [Shell History](#shell-history)
- [Browser Artifacts](#browser-artifacts)
- [Application-Level Evidence — the PostgreSQL App Database Itself](#application-level-evidence--the-postgresql-app-database-itself)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Scoping Note — What "Source" Means for an Offline Analysis Tool

Every other tool in this repo's `Source Evidence` file describes the attacker's own box mid-operation against a live target. BloodHound CE breaks that pattern: **it never talks to the target domain at all**. Everything in this file is what a forensic examiner finds on the **operator's analysis host** — a laptop, a team server, a jump box — running the Docker Compose stack, independent of when or how the underlying SharpHound/AzureHound collection happened. If that analysis host itself is later seized or imaged (e.g. a red-team engagement box recovered during an actual incident, or a purple-team retro), this is what's there.

## Configuration Files — Cleartext Credentials by Design

The single richest artifact on an operator's host is **`bloodhound.config.json`**, written by `bloodhound-cli` at `$XDG_CONFIG_HOME/bloodhound/bloodhound.config.json` — typically `~/.config/bloodhound/bloodhound.config.json` on Linux, an XDG-equivalent path on macOS, verified directly in `bloodhound-cli`'s own source (`cmd/internal/env.go`/`utils.go`: `GetDefaultConfigDir()` returns `filepath.Join(xdg.ConfigHome, "bloodhound")`). This file is created with the CLI's own default settings the first time `install` runs and includes, in plaintext JSON:

- `default_admin.principal_name` — always `admin`
- `default_admin.password` — the **initial randomly generated admin password**, stored in cleartext even after the operator changes it in the UI (the config file isn't automatically updated on password rotation — a stale-but-real initial credential can persist on disk indefinitely)
- `bind_addr`, `root_url`, `work_dir`, `log_path`, `collectors_base_path` — deployment topology

Alongside it, the operator's working directory (wherever `bloodhound-cli install`/`check` was run from) holds the downloaded **`docker-compose.yml`** and **`docker-compose.dev.yml`** — verified in `bloodhound-cli`'s `docker.go` (`DownloadDockerComposeFiles()`), pulled straight from the project repo. If the operator never overrides them via a `.env` file, these YAML files contain the **literal, publicly known default credentials as fallback values** — `NEO4J_AUTH=neo4j/bloodhoundcommunityedition`, `POSTGRES_PASSWORD=bloodhoundcommunityedition` — readable by anyone with filesystem access to the box, no decryption or cracking needed. A `.env` file in the same directory, if present, is where an operator who *did* rotate credentials stores them — also plaintext.

## Docker/Podman Artifacts

- **Container images pulled**: `docker.io/specterops/bloodhound:<tag>`, `docker.io/library/postgres:18`, `docker.io/library/neo4j:4.4.42` — visible in `docker images` / `podman images`, and in the Docker/Podman image-pull event log, timestamped to when the operator first deployed
- **Named volumes**: `neo4j-data` and `postgres-data` (per the compose file's `volumes:` block) — these persist the **entire ingested graph** across container restarts. On a Linux Docker install, the underlying data lives under `/var/lib/docker/volumes/<project>_neo4j-data/_data` and `..._postgres-data/_data` — an examiner with root/filesystem access to the host (not just the containers) can mount and read the raw Neo4j/Postgres data files directly, without ever starting the containers or knowing any BloodHound credential
- **Container logs** (`docker logs <container>` / `bloodhound-cli logs <name>`) retain, by default, the entire startup history including the original admin-password announcement block, database migration output, and every ingest job's processing log lines

## Collection Files Staged for Upload

SharpHound/AzureHound output has to exist on the operator's filesystem (or be piped directly) before it can be uploaded — a `*_BloodHound.zip` or raw `.json` file, typically named with a collection timestamp, sitting in whatever directory the operator ran the collector or downloaded results into. Full mechanics of that file's own origin and naming are covered in `SharpHound/03 - Source Evidence.md`; from BloodHound CE's side, the relevant fact is that **the raw collection file is never deleted or consumed by upload** — it remains on disk as a durable copy of everything the graph now contains, often long after the engagement ends and frequently swept up wholesale in `~/Downloads`, `~/Desktop`, or an engagement working directory during triage.

## Live Process and Container State

Unlike this repo's single-shot lateral-movement tools, BloodHound CE is a **long-running, multi-process service**, not a one-off client invocation:

```bash
# Every BloodHound-stack container running at once, by design
docker ps --filter "name=bhce" --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"
```

Expect to see (container names verified against the compose file's `services:` block) `app-db` (Postgres), `graph-db` (Neo4j), and `bloodhound` (the Go API + bundled web UI), all started together and typically staying up for the life of the engagement rather than exiting after a single task — a distinctive process-tree shape compared to, say, a psexec.py or wmiexec.py invocation that starts and terminates around one command.

## Local Network-Connection State

```bash
# Confirm which interfaces the stack is actually bound to — 127.0.0.1-only is the safe
# default; 0.0.0.0 means the operator deliberately (or carelessly) exposed it
ss -tlnp | grep -E ':8080|:7687|:7474|:5432'
```

Three (sometimes four, if Postgres's port is also uncommented) simultaneously bound listening ports on one host, all owned by container-runtime child processes, is itself a fingerprint distinguishing a BloodHound deployment from most other tools in this repo — nothing else here runs a persistent multi-port local service stack.

## Shell History

```bash
grep -E "bloodhound-cli|docker[- ]compose|azurehound|file-upload" ~/.bash_history ~/.zsh_history 2>/dev/null
```

`bloodhound-cli install`/`up`/`down`/`resetpwd`/`config set` invocations, raw `docker compose -f docker-compose.yml up -d` calls, and any manual `curl`/scripted calls against `/api/v2/file-upload/*` (which, if run with inline HMAC key material rather than a wrapper script, directly exposes the API key ID in plain shell history) all land here. As with every other tool in this module, this survives only until history is cleared or the shell exits without persisting it — pair with process-execution logging (`auditd` `execve` records, Windows Sysmon Event ID 1 if the analysis host is Windows-based) for a durable equivalent.

## Browser Artifacts

The web UI is the primary operator interface, so standard browser forensics apply and are unusually informative here:

- Browser history hitting `http://localhost:8080/ui/...` (or whatever hostname/port the operator configured) — URL paths often encode which page was open (`/ui/explore`, `/ui/administration/...`), giving a rough activity timeline even without deeper access
- The session **JWT** issued on login is stored in browser local storage/cookies (mechanism depends on BloodHound CE release) — recoverable from a live browser profile or, in some configurations, from disk-cached storage, and usable to resume the operator's authenticated session if not yet expired
- Saved/recently-run Cypher queries and prebuilt-query selections may be recoverable from browser autofill/form-history artifacts even independent of the application's own saved-query store (below)

## Application-Level Evidence — the PostgreSQL App Database Itself

Because BloodHound CE is a real multi-user web application, its own **Postgres app database** is itself a rich evidence source once accessed (either via the exposed Postgres port with recovered credentials, or via the BloodHound admin API):

- **User accounts and sessions** — every operator who logged in, with timestamps
- **Saved queries** — any custom Cypher an operator explicitly saved (not just the ephemeral queries run once and discarded)
- **Asset-group tag history** — every node ever marked `owned` or `admin_tier_0`, effectively a chronological list of every principal/asset the operator confirmed compromising or flagged as high-value, if timestamps on tag application are retained
- **Ingest job history** — every file-upload job, its status, and (depending on retention) the originating filename — a durable record of every SharpHound/AzureHound collection round ever fed into this instance, even after the raw collection files themselves are deleted
- **Audit log** (if enabled) — administrative actions, permission changes, API key creation

## OS-Level Audit Trail

```bash
# Linux auditd — persistent record even if shell history is cleared
ausearch -x bloodhound-cli -x docker -x podman
ausearch -x curl -k execve 2>/dev/null | grep -i file-upload
```

Container-runtime `execve` events for `bloodhound-cli`, `docker`, `podman`, and any scripted `curl`/API-client invocations against the file-upload endpoints are the durable equivalent of shell history, and — unlike shell history — capture invocations even from non-interactive automation (cron jobs, CI pipelines feeding continuous SharpHound ingestion).

## Memory Forensics

- The Neo4j/Postgres **container processes'** memory holds the live, unencrypted graph and app-state data for as long as the stack is running — a memory-only capture of the host (not the containers, the underlying host kernel's process memory) can, in principle, recover graph fragments without ever touching disk or needing credentials, though this is a heavier lift than simply reading the Docker volume data directly (above)
- The **JWT signing key** and any in-flight session tokens live in the `bloodhound` API process's memory
- If the operator ran `bloodhound-cli resetpwd` or `install` recently, the freshly generated admin password is briefly visible in **terminal scrollback buffer** memory in addition to the persisted log file — a narrow but real memory-forensics window immediately after setup

## Timeline Correlation Value

Because BloodHound CE's own operation generates zero traffic against the target domain, this file's evidence correlates almost entirely with **when the analysis happened relative to the collection and the subsequent exploitation**, not with target-side timestamps directly. The useful timeline chain an examiner reconstructs is: SharpHound/AzureHound collection timestamp (target-side, see `SharpHound/04`) → collection file's filesystem `mtime`/staging on the operator's box (this file) → BloodHound ingest-job timestamp in the Postgres app database (this file) → asset-group tag timestamps marking specific nodes Owned/Tier Zero as the engagement progressed (this file) → the real-world tool invocation (Rubeus/Mimikatz/Impacket/Certipy) that acted on each discovered path, whose own source/target evidence is covered in that tool's own folder. BloodHound's contribution to a reconstructed timeline is almost entirely this **decision-making layer** — proving an operator *knew* about a specific path before a specific exploitation tool ran against it, which is often the strongest available evidence of *intent* even when the exploitation step itself is otherwise ambiguous.
