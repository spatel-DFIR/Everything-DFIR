# PowerShell Empire — Source Evidence

Evidence left on the **operator/server-side** infrastructure — the host running `ps-empire server`, and any browser/client reaching its API or Starkiller GUI. Unlike a tool with a heavy standalone client (Sliver's `sliver-client`), Empire's entire operator-facing surface is one process: the FastAPI server. Everything an operator ever did lives in that server's database and log directory — there is no separate client-side state to correlate beyond browser history and JWTs cached wherever `curl`/scripts ran.

## Contents
- [The Server Data Directory](#the-server-data-directory)
- [The Server Database](#the-server-database)
- [Log Files](#log-files)
- [Server Configuration](#server-configuration)
- [Downloads and Loot](#downloads-and-loot)
- [Empire-Compiler and Starkiller Artifacts](#empire-compiler-and-starkiller-artifacts)
- [Live Process and Socket State](#live-process-and-socket-state)
- [Authentication Artifacts](#authentication-artifacts)
- [Shell History](#shell-history)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## The Server Data Directory

As of Empire 6.0, **all writeable runtime data was moved out of the install path** into a single, predictable per-user location — verified directly against `empire/server/core/config/config_manager.py`'s `DATA_DIR` definition:

```bash
DATA_DIR="$HOME/.local/share/empire"
ls -la "$DATA_DIR"
```

This one directory is the highest-value target on a server host: it holds the database, all logs, all downloaded/uploaded files, and build caches — a single `tar`/copy of `~/.local/share/empire` captures nearly everything Empire ever did on that server, short of in-flight memory state.

## The Server Database

**SQLite by default** (`sqlite.location: empire.db`, resolved under `DATA_DIR` — confirmed as the Pydantic model default in `config_manager.py`, `use: "sqlite"`), with **MySQL** as an install-time opt-in (the install script offers to stand up a local MySQL instance with default credentials `empire_user`/`empire_password`, verified against `setup/install.sh`).

```bash
# SQLite default location
sqlite3 "$HOME/.local/share/empire/empire.db" ".tables"

# If MySQL was chosen at install:
mysql -u empire_user -p'empire_password' empire -e "SHOW TABLES;"
```

This single database holds:
- **Every listener ever created**, including its full option set — `StagingKey`, `Host`, `Port`, `DefaultProfile`, `Cookie` — in plaintext, because the server needs the raw `StagingKey` to decrypt every future stage-0 request against that listener. A seized server database directly yields the pre-shared key for every listener it ever ran.
- **Every stager ever generated**, its options, and (if `save=true`) the rendered artifact itself.
- **Every agent that ever checked in** — hostname, internal IP, username, OS, process, language, session ID, delay/jitter, and full check-in history (`agents/{id}/checkins`).
- **Every task ever issued to every agent** and its full result output — this is the single richest record of "what did the operator actually do," equivalent to Sliver's task-history table or a Cobalt Strike beacon log.
- **Harvested credentials** stored via the `/credentials` API, whether entered manually or written automatically by a credential-harvesting module.
- **User accounts** (`empireadmin` plus any provisioned operators) and their hashed passwords.
- **Malleable profiles, bypasses, and obfuscation config** — the exact traffic-shaping/evasion posture used for the engagement.

## Log Files

Verified against `empire/server/utils/log_util.py` — plaintext, human-readable logs under `$DATA_DIR/logs/`:

```bash
ls "$HOME/.local/share/empire/logs/"
# empire_server.log        — root server log, DEBUG-level to file regardless of console verbosity
# listener_<name>.log      — one file per listener job, named after the listener's own Name
```

`empire_server.log` captures startup, API request handling errors, module load activity, and plugin execution — a DEBUG-level file log exists even when the console output is set quieter (`--log-level`/`-d` only affects the **console** stream handler, not the file handler, which is always DEBUG). Each listener's own log file isolates that listener's request-handling activity, useful for correlating exactly which listener served a specific stage-0/1/2 exchange without grepping through mixed output.

## Server Configuration

| Artifact | Location | Notes |
|---|---|---|
| `config.yaml` | Empire install path (`empire/server/config.yaml`, or a custom path via `--config`) | API bind IP/port (default `0.0.0.0:1337`), `secure` flag (HTTP vs. HTTPS-with-self-signed-cert), default admin username/password, default MySQL creds, default bypasses (`mattifestation`, `etw`), default obfuscation settings, `plugin_marketplace` registries and `auto_install` list |
| `empire.pem` | `empire/server/data/` | Self-signed cert auto-generated at startup when the API runs with `--secure-api` |
| Plugin registry cache | `$DATA_DIR` (plugin-marketplace-managed) | Cloned/synced git registries (default: `BC-SECURITY/Empire-Plugin-Registry`) and any installed plugin code |
| Malleable profile files | Synced from the `Malleable-C2-Profiles` submodule at install, plus any profiles added via `/api/v2/malleable-profiles` | The active profile identifies exactly which real-world threat/tool the operator was emulating |

The default admin credentials (`empireadmin`/`password123`) and default MySQL credentials (`empire_user`/`empire_password`) are **both documented, static values in the project's own shipped `config.yaml`** — treat any server found still using either as a strong indicator the deployment was stood up quickly/carelessly (a useful signal when assessing how rigorous a given engagement's or intrusion's operational security was).

## Downloads and Loot

```bash
ls "$HOME/.local/share/empire/downloads/"
```

Files pulled from agents (`download` tasks, the file browser), saved stagers, task-attached artifacts (C#/BOF task inputs are attached as `download`-tagged records per the 6.0 changelog), and anything an operator uploaded for later use in a module all land here, tracked in the database's `Download` table with a reference from whatever task/agent/stager produced them.

## Empire-Compiler and Starkiller Artifacts

```bash
ls "$HOME/.local/share/empire/.cache/"
```

- **Empire-Compiler** — downloaded at startup (or built from source with `-c`), used for Roslyn-based C# module/agent compilation; its cache holds compiled C# artifacts and reference assemblies used across the engagement.
- **Go build cache** — for Go (Gopire) agent compilation, also cached under `.cache/`.
- **Starkiller** — bundled as a git submodule of the main repo at a fixed path (`empire/server/data/...` or the top-level submodule path per `.gitmodules`-adjacent config); its static web assets are served directly by the API process, so Starkiller usage leaves no separate server-side artifact beyond the API request log itself.

## Live Process and Socket State

```bash
ps aux | grep -i "[e]mpire\|ps-empire"
sudo ss -tlnp | grep -E ':1337|:80|:443|:53|:8080'   # API port + whatever listener ports are active
```

Cross-reference bound ports against the database's `Listener` table rather than assuming defaults — every listener's `Port`/`BindIP` is fully operator-configurable, and the API's own port (default 1337) is separate from any C2 listener port.

## Authentication Artifacts

- **JWT secret** — generated per-database at first startup (`models.Config.jwt_secret_key`, confirmed **not** a static/hardcoded value like the listener `StagingKey`), stored in the database and used to sign/verify every issued token (`HS256`). Compromising the database therefore also compromises every currently-valid and future-issuable JWT for that server.
- **Cached tokens** — any `Authorization: Bearer <jwt>` value an operator's script or shell history captured; JWTs are self-contained (decode the payload without the secret to read expiry/username, even without forging a new one).
- **Browser artifacts (Starkiller users)** — the JWT is typically held in browser storage for the session; standard browser-history/cache forensics against the operator's workstation recovers the server URL and login timing even without server-side access.

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash/zsh | `~/.bash_history` / `~/.zsh_history` | `./ps-empire install`/`server` invocation lines, and — critically — any `curl -d "username=...&password=..."` login call typed directly (rather than piped from a credentials file) leaks operator credentials into shell history in cleartext |
| Python/requests scripts | Wherever the operator's automation lives | A script hardcoding the JWT-acquisition credentials or a static bearer token is common and directly recoverable from source |

## Memory Forensics

The running server process holds, for as long as it's up: the JWT signing secret (if not otherwise protected), all currently-active listener `StagingKey` values in a decrypted, in-use state, and any in-flight request/response data mid-handshake. Because the database already stores `StagingKey`/credential values in plaintext (by design — the server must be able to decrypt future stage-0 requests), memory forensics is **less uniquely valuable here** than for a tool that only holds key material transiently in memory (contrast with Sliver's CA private key, which memory capture is the *only* way to recover if the on-disk cert store is hardware-backed) — the on-disk database is already the equivalent-or-better source for Empire.

## Timeline Correlation Value

The database's `AgentTask` and `Checkin` tables carry precise timestamps for every operator action and every agent check-in — this is the anchor for correlating against `04 - Target Evidence.md`'s target-side timeline. Because Empire's default delay/jitter model (`DefaultDelay` seconds ± `DefaultJitter` × `DefaultDelay`) governs check-in spacing, expect target-side outbound-connection timestamps to fall within that window of the prior check-in rather than at an exact fixed offset — the same reasoning `Purple Teaming/Sliver/03 - Source Evidence.md` applies to beacon jitter. A task issued at time T in the database, matched against a target-side process/network event shortly after the *next* check-in following T (not immediately after T), is the correct way to bind an operator action to its on-target effect.
