# LaZagne — Overview

> 🔴 **Red Flag Principle:** LaZagne's headline capability is "parse 100+ applications' credential stores," but its actual *execution* footprint is much narrower and more mechanical than that variety suggests — and none of it touches LSASS memory. When run elevated it (1) spawns `reg.exe save hklm\{sam,security,system}` three times to a randomly-named file in `%TEMP%`, (2) walks **every running process on the box**, opening each one's token (`OpenProcess`/`OpenProcessToken`) to find and impersonate every other locally logged-on user (`DuplicateTokenEx`+`ImpersonateLoggedOnUser`), and (3) falls back to enumerating every profile directory under `C:\Users`. **A single host process opening handles to dozens of unrelated processes' tokens, immediately followed by three short-lived `reg.exe save` child processes, is the distinctive signature — not a "credential-stealer" signature so much as a "token-theft tool" signature**, and it's present regardless of which of LaZagne's ~15 software categories the operator actually asked for.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`github.com/AlessandroZ/LaZagne`](https://github.com/AlessandroZ/LaZagne) (GitHub API metadata: created 2015-02-16), its `CHANGELOG`, and its `README.md`:

- **Author:** **Alessandro Zanni** (`@AlessandroZ`). The project's own description is blunt about its purpose: *"an open source application used to retrieve lots of passwords stored on a local computer."*
- **License:** **GNU Lesser General Public License v3.0 (LGPL-3.0)** — confirmed against the repo's `LICENSE` file and GitHub's own license metadata for the repository.
- **Origin and early growth:** the earliest `CHANGELOG` entries date to April–May 2015 (v0.2–v0.4), adding Windows hashdump/LSA Secrets extraction, WiFi password recovery, and a Linux Kwallet module within the first few months — the tool grew module-by-module from the start rather than shipping as one designed system, a pattern still visible in the current per-application module layout (see below).
- **Current version:** `2.4.7`, released 2025-04-10 per the repo's own Releases page, and confirmed directly in source (`constant.py`'s `CURRENT_VERSION = '2.4.7'`).
- **Pupy integration:** the README notes LaZagne has been bundled into [pupy](https://github.com/n1nj4sec/pupy/), a Python/C2 post-exploitation project, as an in-memory post-exploitation module — one of several places LaZagne shows up embedded inside other offensive tooling rather than run standalone.
- **Distribution:** source is Python (2/3-compatible), but the project ships **prebuilt standalone executables** via PyInstaller on its [Releases page](https://github.com/AlessandroZ/LaZagne/releases) — this is overwhelmingly how the tool is actually deployed against a target, not as a Python script requiring an interpreter on the victim host (see `01`'s Prerequisites and `04 - Target Evidence.md`'s PyInstaller-artifact discussion).
- **A real structural surprise, verified directly against the repo tree, not assumed:** LaZagne is **not one shared cross-platform codebase**. The repository root splits into three **independent** top-level projects — `Windows/`, `Linux/`, and `Mac/` — each with its own `lazagne/` package, its own `config/` (including its own crypto and DPAPI implementations on Windows), and its own entry-point script. There is no shared `common/` package between them; a module implemented for Windows (e.g. `windows/hashdump.py`) has no Linux or Mac equivalent unless someone wrote one separately in that platform's own tree. This note covers the **Windows** tree exclusively, since that's where the vast majority of real-world usage and incident reporting concentrates.

## How It Works

### Module architecture

LaZagne organizes its ~150 individual per-application extractors into **categories** — the CLI's first positional argument (`browsers`, `windows`, `wifi`, etc.). On the Windows build, verified directly against the `Windows/lazagne/softwares/` directory tree, the categories are:

| Category | What it targets (per the project's own README table) |
|---|---|
| `browsers` | 30+ Chromium/Gecko-based browsers (Chrome, Edge, Firefox, Opera, Brave, Vivaldi, and many rebadged Chromium forks) |
| `chats` | Pidgin, Psi, Skype |
| `databases` | DBVisualizer, PostgreSQL, Robomongo, Squirrel SQL, SQL Developer |
| `games` | GalconFusion, KalypsoMedia, RogueTale, Turba |
| `git` | Git for Windows credential storage |
| `mails` | Epyrus, Interlink, Outlook, Thunderbird |
| `maven` | Apache Maven `settings.xml` |
| `memory` | **Disabled in current source** — see the callout below |
| `multimedia` | EyeCON |
| `php` | Composer |
| `svn` | TortoiseSVN |
| `sysadmin` | FileZilla (client + server), CoreFTP, CyberDuck, FTP Navigator, OpenSSH for Windows, OpenVPN, mRemoteNG, KeePass 1/2 **configuration files** (not the master password), PuTTY Connection Manager, **Rclone** (its own `rclone.conf` — see this repo's `Rclone/` for what that credential actually unlocks), RDPManager, VNC, WinSCP, unattended-install answer files, and Windows Subsystem for Linux |
| `wifi` | Saved WLAN profile pre-shared keys |
| `windows` | The OS-level credential stores: SAM hashes, LSA Secrets, cached domain logons (mscache/DCC2), Credential Manager, Credential/Vault DPAPI blobs, and Autologon registry values — see the dedicated breakdown below |

Every module in a category is registered as a `ModuleInfo` subclass with a fixed CLI flag pattern: `-{module_name}` (e.g. `-firefox`, `-hashdump`). Running just the category name with no per-module flag (`laZagne.exe browsers`) runs **every** module registered in that category — the per-module flags exist to narrow, not to opt in.

**A module still registering doesn't mean it still works.** Two modules found live in source are stubbed out entirely, both for the same stated reason:

- `windows/ppypykatz.py` — historically called the [`pypykatz`](https://github.com/skelsec/pypykatz) library's `go_live()` to pull cleartext/hash material directly out of **LSASS memory** (credential manager, SSP, LiveSSP, TsPkg, WDigest sources — the same provider list Mimikatz's `sekurlsa` targets). The current source's `run()` method returns immediately: `'Not supported anymore !'`, with a code comment attributing the removal to AV/EDR detection.
- `memory/memorydump.py` — historically scanned **browser and KeePass process memory** (via the bundled `memorpy` library and a `KeeThief`-derived class) for cleartext credentials/master passwords. Also stubbed to `'Not supported anymore!'`, same stated reason (the comment specifically calls out the `KeeThief` binary as "too much detected").

**The practical consequence: current-release LaZagne has no live-memory credential-reading capability at all**, despite both modules still appearing in the tool's own category/module listing. Every real extraction path left in the tool is disk-, registry-, or DPAPI-blob-based — this is *why* the Mimikatz-vs-LaZagne split in this repo is clean rather than overlapping: LaZagne isn't "a weaker Mimikatz that also reads memory," it's a tool that tried the memory-reading approach and walked it back.

### The `windows` category and the SAM/SYSTEM/SECURITY hive dance

The `windows` category's system-level modules — `hashdump` (SAM/NT hashes), `lsa_secrets`, and `mscache` (domain cached credentials, registered internally as `mscache` even though the source file is named `cachedump.py`) — all depend on the same three registry hives and use the vendored **`creddump7`** library (an offline SAM/SECURITY/SYSTEM hive parser) to do the actual decoding, verified directly against `windows/lazagne/softwares/windows/creddump7/win32/hashdump.py`, `lsasecrets.py`, and `domcachedump.py`. None of these three functions touch a live registry handle — they all take **file paths** and parse an on-disk hive copy.

Those file paths come from `execute_cmd.py`'s `save_hives()`, called once up front whenever LaZagne detects it's running elevated:

```python
# execute_cmd.py — verified against live source
def save_hives():
    for h in constant.hives:  # 'sam', 'security', 'system'
        cmdline = 'reg.exe save hklm\\%s %s' % (h, constant.hives[h])
        command = ['cmd.exe', '/c', cmdline]
        ...  # spawned hidden (STARTF_USESHOWWINDOW / SW_HIDE)
```

`constant.hives[h]` is a **randomly generated, extension-less filename** — 6 to 12 lowercase ASCII letters, `os.path.join(tempfile.gettempdir(), <random>)` — freshly regenerated every run (`constant.py`):

```python
'sam': os.path.join(tmp, ''.join(random.choice(string.ascii_lowercase) for x in range(random.randint(6, 12))))
```

So a single run against the `windows` category produces **three short-lived `cmd.exe`/`reg.exe` child processes** (`reg.exe save hklm\sam <randomname>`, `hklm\security <randomname>`, `hklm\system <randomname>`), each writing an unnamed file into `%TEMP%`. `delete_hives()` removes all three in a `finally` block once the system-module pass completes — but the `reg.exe` process creation events themselves, and the brief on-disk hive copies, are real artifacts regardless of that cleanup. See `03`/`04` for the exact hunt.

### The three-phase execution model

`run.py`'s own docstring lays out the intended workflow; the code matches it exactly. This is the single most important mechanic to understand for reading LaZagne's evidence correctly — it explains why a single invocation can touch far more than just the operator's own user context:

```
Phase 1 — SYSTEM/admin pass (only if IsUserAnAdmin())
  save_hives() → reg.exe save x3 (SAM/SECURITY/SYSTEM → %TEMP%, random name)
  → run every system_module=True module (hashdump, lsa_secrets, mscache, autologon)
  → delete_hives() [finally block — runs even on exception]

Phase 2 — current-user pass (always runs)
  is_current_user = True
  → run every module NOT requiring registry/current-user-only exclusion:
      - "winapi_used" modules call CryptUnprotectData directly
        (valid only inside the calling user's own logon session)
      - "dpapi_used" modules decrypt an on-disk blob using the
        current user's already-unlocked DPAPI master key

Phase 3 — impersonate every OTHER locally logged-on user (admin only)
  list_sids(): loop every running PID → OpenProcess(PROCESS_QUERY_INFORMATION)
               → OpenProcessToken → record each distinct user SID found
  for each distinct SID (excluding self and SYSTEM):
      DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)
      ImpersonateLoggedOnUser(duplicated_token)
      → re-run Phase 2's module set AS that user
      RevertToSelf()

Phase 4 — walk every remaining profile on disk (admin only)
  get_user_list_on_filesystem(): list C:\Users\* (minus system/impersonated
                                  profiles already covered)
  for each remaining profile directory:
      point APPDATA/USERPROFILE env-equivalents at that profile
      → re-run file-based modules (no live token needed — Firefox-style
        stores parse without decryption; DPAPI blobs decrypt only if a
        password/hash for that specific user was already recovered
        elsewhere in this same run, e.g. via hashdump)
```

Phase 3 is the part most third-party write-ups miss entirely: **LaZagne doesn't just read files as its own user — when run elevated, it actively steals and impersonates the token of every other user with a running process on the box**, using the exact `OpenProcess`→`OpenProcessToken`→`DuplicateTokenEx`→`ImpersonateLoggedOnUser` sequence Meterpreter's `incognito` extension and similar token-theft tooling use. `get_debug_privilege()` (an `SeDebugPrivilege`-enabling `RtlAdjustPrivilege` call) is what makes opening other users' process tokens possible in the first place.

### DPAPI: two independent decryption paths

A large share of what LaZagne recovers — Credential Manager generic/domain entries via files, Windows Vault entries, WiFi keys, saved-credential blobs — is DPAPI-protected. LaZagne implements **two separate paths**, chosen automatically depending on context (`run.py`'s `winapi`/`dpapi` deferred-module split):

1. **`CryptUnprotectData` (live session, "winapi" path)** — valid only when running *as* the account whose data is being decrypted (Phase 2, the operator's own current session). This is the easy case: no key material handling needed, the OS does it.
2. **Full offline DPAPI reimplementation ("dpapi" path)** — used for every other case (impersonated users in Phase 3, filesystem-walked profiles in Phase 4, or explicit `-password` use). LaZagne carries its own DPAPI masterkey/CREDHIST/blob parser (`config/DPAPI/`, credited in source to the DPAPICK and dpapilab projects) that derives the masterkey decryption key from a **SHA1 hash of the user's plaintext password** (`hashlib.new("sha1", pwd).digest()`), then HMAC-validates the result — a real, from-scratch DPAPI implementation, not a shell-out to a Windows API. Deep masterkey/CREDHIST/blob internals are general Windows DPAPI mechanics, not LaZagne-specific — see `Windows/05 - Users, Groups & Authentication.md` for this repo's existing DPAPI coverage (notably the Microsoft-account 44-character surrogate-password wrinkle, which also blocks this offline path for MSA-linked users unless that surrogate is separately recovered).

When neither a password nor a pre-recovered hash is available, LaZagne's masterkey code (`config/DPAPI/masterkey.py`'s `jhash()`) can instead emit a crackable hash string in the exact `$DPAPImk$...` format hashcat and John the Ripper expect — corresponding to **hashcat modes 15300/15310** (DPAPI masterkey file v1, local/domain context) and **15900/15910** (v2, AD domain context), verified against hashcat's own published example-hash list. This is the same offline-cracking handoff pattern this repo's `Hashcat/` note documents for other credential types — LaZagne is a DPAPI-hash *producer* here, not the tool doing the cracking.

### WiFi: two paths, one of them spawns `netsh.exe`

The `wifi` module (`softwares/wifi/wifi.py`) is a clean, small illustration of the same "prefer the API, fall back to a legitimate binary" pattern seen elsewhere in the tool. It tries, in order:

1. `decrypt_using_lsa_secret()` — admin-only, decrypts the WLAN profile XML's encrypted key material directly using the **machine/SYSTEM DPAPI context** (unlocked via the `DPAPI_SYSTEM` LSA secret the `lsa_secrets` module already extracts) — no subprocess involved.
2. `decrypt_using_netsh()` — no admin required, literally shells out: `netsh.exe wlan show profile "<SSID>" key=clear`, then greps the English/French-localized "key content" line out of stdout.

Path 2 means a WiFi-focused run (or a non-admin run where path 1 isn't available) leaves a **`netsh.exe` child process with `wlan show profile ... key=clear` on its command line** — a concrete, high-signal, easily-hunted artifact independent of anything LaZagne itself writes to disk.

### Output

By default, results print to the console only. `-oN`/`-oJ`/`-oA` write them to disk as `credentials_<DDMMYYYY_HHMMSS>.txt` / `.json` (both, for `-oA`) in the current directory, or under whatever path `-output` specifies — verified directly in `constant.py`'s `file_name_results = 'credentials_{current_time}'.format(...)` with `date = time.strftime("%d%m%Y_%H%M%S")`. **This is not a fixed filename** (several third-party summaries assume something like `lazagne_output.txt`) — it's timestamp-derived and different on every run, which matters for a filesystem hunt (see `05`).

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Registry access | Live `winreg`/`RegOpenKey`-style reads (autologon, some config lookups) plus offline parsing of `reg.exe`-exported SAM/SECURITY/SYSTEM hive copies (`hashdump`, `lsa_secrets`, `mscache`) |
| Credential APIs | `CredEnumerate`/`CredFree` (Windows Credential Manager, current-session only) and `CryptUnprotectData` (DPAPI, current-session only) — both native `advapi32.dll`/`crypt32.dll` calls via `ctypes`, not a managed wrapper |
| DPAPI (offline) | A from-scratch Python reimplementation of masterkey/CREDHIST/blob decryption (credited to the DPAPICK/dpapilab projects), used for every context outside the operator's own live session |
| Token manipulation | `OpenProcess`/`OpenProcessToken` (mass-enumerated across every running PID), `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `RevertToSelf` — classic local token-theft/impersonation, requiring `SeDebugPrivilege` |
| Child-process execution | `reg.exe save` (hive export, x3, admin system-module pass) and `netsh.exe wlan show profile ... key=clear` (WiFi fallback path, no admin required) |
| Application-specific parsing | Per-software SQLite/JSON/XML/INI parsing and, for browsers, each vendor's own local-encryption-key handling (itself usually DPAPI or `CryptUnprotectData`-backed) |
| Execution vector | Purely **local** — LaZagne has no network client of its own; every module operates against local files, the local registry, or local process tokens. It must already be executing on the host whose secrets are being harvested (contrast with `Impacket/secretsdump/`, which can pull the same SAM/LSA Secrets/NTDS material **remotely** over SMB/RPC without ever landing a binary on the target) |

## Command-Line Switches — Quick Reference

Verified directly against `Windows/laZagne.py`'s `argparse` setup and `config/module_info.py`'s per-module flag convention.

| Switch | Plain-English meaning |
|---|---|
| `<category>` (positional, required) | Which category to run — `browsers`, `chats`, `databases`, `games`, `git`, `mails`, `maven`, `memory` *(non-functional, see above)*, `multimedia`, `php`, `svn`, `sysadmin`, `wifi`, `windows`, or `all` (every category) |
| `-<module_name>` | Restrict a category run to one specific software (e.g. `browsers -firefox`, `windows -hashdump`, `windows -mscache`) — omit to run every module in the chosen category |
| `-v` | Increase verbosity (repeatable — `-v`, `-vv`) |
| `-quiet` | Suppress all console output entirely |
| `-oN` | Write results to a text file (`credentials_<timestamp>.txt`) |
| `-oJ` | Write results to a JSON file (`credentials_<timestamp>.json`) |
| `-oA` | Write both formats |
| `-output <path>` | Destination directory for `-oN`/`-oJ`/`-oA` output (default: current directory) |
| `-password <pwd>` | A known Windows user password — used to unlock that user's DPAPI-protected material (Credential/Vault files) offline, without needing a live session as them |
| `-version` | Print the tool's version and exit |
| `-h` / `<category> -h` | Built-in help — top-level or per-category (lists every module flag in that category) |

**Not present in the current Windows build**, despite appearing in older CHANGELOG entries or third-party write-ups: `-drive` (alternate-drive targeting) and `-i` (interactive password prompt) are Mac-build or historical-only options — verified absent from `Windows/laZagne.py`'s current argument parser.

## Quick Use-Case List

- Full sweep of every category in one run, written to disk for offline review (`all -oA`)
- Category-scoped pull — e.g. every installed browser's saved logins
- Single-software targeted pull within a category (`browsers -firefox`)
- SAM/NTLM hash extraction from the local machine (`windows -hashdump`)
- LSA Secrets extraction — service-account passwords, cached DPAPI_SYSTEM key material, and (on unpatched/legacy configurations) Autologon cleartext (`windows -lsa_secrets`)
- Domain cached-credential (MSCache/DCC2) extraction from a domain-joined host (`windows -mscache`)
- DPAPI masterkey hash extraction (`$DPAPImk$...`) for offline hashcat/John cracking when no plaintext password is available
- Using a known/cracked Windows password to unlock DPAPI-protected material for every recovered user (`-password`)
- WiFi profile pre-shared-key recovery, via either the admin-only SYSTEM-DPAPI path or the no-admin `netsh.exe` fallback
- Windows Credential Manager dump for the current interactive session (`windows -credman`)
- Windows Vault / Credentials-files DPAPI blob decryption (`windows -vault`, `windows -credfiles`, `windows -vaultfiles`)
- Autologon registry credential check (`windows -autologon`)
- `sysadmin` category sweep for remote-access/lateral-movement credential material — WinSCP, PuTTY CM, mRemoteNG, RDPManager, VNC, OpenSSH for Windows, FileZilla, Rclone's own config, unattended-install answer files
- Git for Windows stored credential harvesting (`git`)
- Multi-user harvest on a shared host or jump box in a single elevated run — the automatic token-impersonation (Phase 3) and filesystem-profile-walk (Phase 4) mechanics mean one invocation can recover material for every user who has ever logged onto that box, not just the operator's own session
- Non-admin run limited to the operator's own current-session material — useful where privilege escalation hasn't happened yet but a foothold has
- JSON output (`-oJ`) for programmatic ingestion into a loot store or downstream tooling
- Cross-platform equivalents on Linux/Mac footholds — a structurally separate codebase (see History) but the same category/module CLI shape
- Chained workflow: LaZagne's output feeding a next step — a recovered RDP/VNC/SSH credential into lateral movement, a recovered DPAPI hash into `Hashcat/`, or a recovered Windows password into decrypting every other user's blobs on the same box in a follow-up run

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Execution host | Must run **on** the host whose secrets are being harvested — no remote/network mode exists. Getting the binary there is a separate problem this tool doesn't solve (PsExec, Impacket, RDP, a C2 implant, etc.) |
| Distribution form | Either a PyInstaller-compiled standalone `.exe` (the overwhelmingly common real-world form — no Python runtime needed on the target) or the raw Python source with `pip install -r requirements.txt` on a host that already has an interpreter |
| Privilege — unprivileged | Current-user-only material (most browsers, Credential Manager via `CryptUnprotectData`, DPAPI blobs the operator's own session can already decrypt) needs no elevation at all |
| Privilege — admin | SAM hashes, LSA Secrets, MSCache/DCC2, Autologon, the Phase 3 token-impersonation sweep across other users, and the Phase 4 filesystem-wide profile walk all require local administrator rights (`IsUserAnAdmin()` gates every one of them) |
| Cross-user DPAPI decryption without admin | A known plaintext password for that specific user (`-password`), supplied by the operator from another source (password spray hit, phishing, a cracked hash) |
| Network reachability | None required — this is the one clean, structural difference from most other tools in this repo's Wave 2 (`Rclone`, `AnyDesk`, `PsExec`, AdFind all assume or require some network reach; LaZagne needs none) |
