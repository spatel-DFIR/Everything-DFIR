# Dropbox

**Scope boundary (read this first):** this note covers only what's forensically recoverable from **the local Windows host** — filesystem, registry, local databases, client-side logs — when the Dropbox desktop sync client has been installed and used. It does **not** cover Dropbox's Business/Team admin console, the Dropbox Events API, shared-link/collaboration audit investigation, or any server-side activity log — that's `Cloud/`'s job per the module's structure decision (PLANNING.md §3, R3): **Windows/ owns the "evidence on disk" lens, Cloud/ owns the "server-side API/admin-log" lens** for the same service. As of this writing there is **no `Cloud/` counterpart note for Dropbox** in this repo yet (the same gap Box Drive.md flagged for Box) — see Correlate With below. This note stands alone for now; when a Cloud/ Dropbox note is written, link it the same way OneDrive.md and the Google Drive note link theirs.

This is the closing note in the Cloud Storage Artifacts (Local Evidence) subfolder, and Dropbox is a useful one to end on: it's the **oldest** of the four clients covered here, and its local SQLite databases have been picked apart by the DFIR community for longer and more thoroughly than OneDrive's, Google Drive's, or Box's equivalents. That history means this note can be more specific and confident about the local database's evidentiary role than Box Drive.md was — but Dropbox has also changed its local storage format meaningfully across major client versions (a plaintext/lightly-obfuscated `.dbx` era giving way to a SQLCipher-encrypted database in more recent clients), so exact current filenames and schema still get the same hedge as the other three notes. Treat the history below as reliable; treat "what's on the specific host in front of you today" as something to verify.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Sync Modes: Full Mirror by Default, Smart Sync On Top](#sync-modes-full-mirror-by-default-smart-sync-on-top)
- [Sync Root](#sync-root)
- [The Local Database: History and Evolution](#the-local-database-history-and-evolution)
- [Encryption: SQLCipher in Newer Clients](#encryption-sqlcipher-in-newer-clients)
- [Registry Artifacts](#registry-artifacts)
- [Client-Side Logs](#client-side-logs)
- [Four-Way Comparison: Local-Presence Guarantees Across Sync Clients](#four-way-comparison-local-presence-guarantees-across-sync-clients)
- [Browser-Adjacent Evidence](#browser-adjacent-evidence)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across `%LocalAppData%\Dropbox\` (and `%AppData%\Dropbox\` as the legacy fallback) before touching any database or third-party parser — no third-party modules required. PowerShell can enumerate the surrounding filesystem/registry evidence; it cannot open or decrypt the local database itself (plain SQLite or SQLCipher-encrypted) — see the PowerShell notes under The Local Database and Encryption sections below for exactly where that limit falls.

```powershell
# Does a Dropbox client footprint even exist on this host, and how recently was it touched
Get-ChildItem 'C:\Users\*\AppData\Local\Dropbox' -Directory -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# Personal + Business sync roots coexisting on the same profile - a ready-made exfil-vector correlation lead
Get-ChildItem 'C:\Users\*\Dropbox*' -Directory -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime

# Legacy .dbx-era files vs. a modern consolidated DB - tells you which forensic path (plaintext vs. SQLCipher) applies
Get-ChildItem 'C:\Users\*\AppData\Local\Dropbox' -Recurse -Include '*.dbx','*.db','*.sqlite' -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime

# Files modified under the sync root in the last 24 hours - fast pivot into recent user/sync activity
Get-ChildItem 'C:\Users\*\Dropbox*' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -gt (Get-Date).AddHours(-24) | Select-Object FullName, LastWriteTime

# Is the Dropbox client actually running right now, and from what binary path
Get-Process -Name Dropbox -ErrorAction SilentlyContinue | Select-Object Id, Path, StartTime

# HKCU\Software\Dropbox present at all, and what subkeys it exposes - fast account/install-attribution check
Get-ChildItem 'HKCU:\Software\Dropbox' -ErrorAction SilentlyContinue
```

## Sync Modes: Full Mirror by Default, Smart Sync On Top

Dropbox's original design point — and still, historically, its default posture more than any of the other three clients in this subfolder — is a **traditional full local mirror**: every file in the account's Dropbox is downloaded and kept present on disk under the sync root, full stop. This is the opposite end of the spectrum from Box Drive's stream-only-by-design architecture (Box Drive.md), and closer to (though not identical to) how OneDrive and Google Drive behaved before Files On-Demand / Stream mode existed.

Dropbox later added **Smart Sync** — its equivalent of OneDrive's Files On-Demand and Google Drive's Stream mode — letting the user (or a Business admin policy) mark individual files or folders as **Online-only** rather than **Local**. An Online-only item shows up in File Explorer with full name/metadata/icon, exactly like a real file, but its content has not been downloaded to this host.

🔴 **The same core pitfall applies here as in the other three notes, just with a different default-severity.** A directory listing, Shell Bag entry, or LNK reference under the Dropbox sync root does not, by itself, prove the file's content was ever present on this host — you have to check whether that specific item is Online-only or Local. What's different about Dropbox: because full local mirroring has historically been the client's *default* posture and Smart Sync/Online-only status is something a user or admin has to actively choose per file or folder, the pitfall is real but less universally-guaranteed-to-bite than Box Drive's (where *every* file is conditional, all the time, by default). Don't let that lower baseline risk turn into a false assumption, though — confirm Online-only vs. Local status per item rather than assuming "Dropbox generally mirrors everything" still holds for the specific host and account you're examining; Smart Sync adoption and default behavior can vary by client version, account tier (Business plans have historically pushed Smart Sync harder than personal accounts), and admin policy.

**How to check hydration/Online-only state:** the same general approach as the OneDrive and Google Drive notes — `attrib`'s cloud-file attribute flags and `fsutil reparsepoint query` are worth trying first, since Dropbox's newer clients implement Smart Sync using the same Windows Cloud Files API (`CfApi`) that OneDrive and Google Drive for Desktop use for their own placeholder mechanisms; confirm the exact flag semantics on the client version in front of you rather than assuming they behave identically to OneDrive's.

### PowerShell

attribute flags on every file under the sync root; `ReparsePoint`/`Offline` marks a Cloud Files API placeholder rather than local content:

```powershell
Get-ChildItem 'C:\Users\*\Dropbox*' -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, Attributes, Length
```

isolate the Online-only placeholders specifically, since these list normally but have no recoverable content on this host:

```powershell
Get-ChildItem 'C:\Users\*\Dropbox*' -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -match 'ReparsePoint|Offline' } | Select-Object FullName, Attributes
```

- Confirm the reparse tag on a specific item natively — the authoritative check when `Attributes` alone is ambiguous:

```powershell
fsutil reparsepoint query 'C:\Users\jdoe\Dropbox\Contracts\file.pdf'
```

## Sync Root

| Account type | Default sync root |
|---|---|
| Personal | `%UserProfile%\Dropbox` |
| Business/Team account | `%UserProfile%\Dropbox (<Business Name>)` |
| Personal + Business on the same host | Both folders can coexist side by side, each its own root |

This is a direct parallel to OneDrive's `OneDrive - <Organization Name>` convention (OneDrive.md) — the business name embedded in the folder path is itself informative during triage, revealing which Dropbox Team the host has been connected to from a bare directory listing alone, before touching the registry or any database. As with the other three clients, the sync root is user-relocatable to an arbitrary path — don't assume the default location is authoritative; confirm the actual configured root via the registry artifacts below.

### PowerShell

Pull the Business Name straight out of a `Dropbox (<Business Name>)` root, turning a bare directory listing into direct Team attribution:

```powershell
Get-ChildItem 'C:\Users\*\Dropbox (*)' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Name -match '^Dropbox \((.+)\)$') { [PSCustomObject]@{ Path = $_.FullName; BusinessName = $Matches[1] } }
}
```

Sweep an estate for hosts running a Business sync root to scope which machines matter for a Team-account investigation:

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-ChildItem 'C:\Users\*\Dropbox (*)' -Directory -ErrorAction SilentlyContinue | Select-Object FullName
} | Select-Object PSComputerName, FullName
```

## The Local Database: History and Evolution

This is the forensic core of the note, and the area where Dropbox's local artifacts are genuinely the best-documented of the four clients in this subfolder.

**What I'm confident about:** Dropbox has maintained SQLite-based local databases tracking synced files, deletion state, and sync history for essentially its entire product history, and this artifact family has been one of the most actively reverse-engineered sync-client databases in the DFIR community — more so than OneDrive's, Google Drive's, or Box's equivalents, which is exactly why this note can speak more specifically than Box Drive.md did about the *category* of evidence available, even while hedging on *current* filenames.

**Historical naming (legacy clients):** older Dropbox client versions — the multi-year era before the client's architecture was substantially reworked — stored local state in a set of files with the `.dbx` extension under a location generally referenced as `%AppData%\Dropbox\` or `%LocalAppData%\Dropbox\` (the exact AppData-vs-LocalAppData boundary has shifted across versions; verify against the client version present rather than assuming one). Names that recur consistently across community research from that era include:

| Legacy filename | Historically understood purpose |
|---|---|
| `config.dbx` | Client configuration — account info, sync root path, settings |
| `filecache.dbx` | The core file-tracking database — per-file metadata for the synced tree |
| `deleted.dbx` | Deletion-state tracking |
| `sigstore.dbx` | Block-level signature/hash store supporting Dropbox's delta-sync (block-level diffing) mechanism |

These `.dbx` files, in the era they were documented, were SQLite databases (despite the non-standard extension) and were openable directly with standard SQLite tooling once identified — this was a large part of why this artifact family became so well-studied early on.

**Where things stand now, hedged:** Dropbox has since evolved its local storage toward a more consolidated database design, and more recent client versions are understood to use encryption on the local database (see next section) rather than the plaintext-SQLite `.dbx` files described above. I do not have high confidence in the exact current filename(s), consolidated schema, or precise version boundary at which the change took effect — do not treat `config.dbx`/`filecache.dbx`/etc. as guaranteed present on a current client install. The correct approach on a live engagement: enumerate `%LocalAppData%\Dropbox\` (checking `%AppData%\Dropbox\` as a fallback for an older install) and identify what's actually present by file signature rather than assuming legacy filenames still apply.

**What this database proves, regardless of exact current schema:** the same "database entry outlives file" pattern established in OneDrive.md and the Google Drive note — see note 08 (Deleted Items and File Existence). A per-file record of what the client has synced, including files since deleted from the sync folder, gives you a "file was here" artifact independent of current on-disk presence. Given how much deeper the historical reverse-engineering of this artifact family goes compared to the other three clients, a fully-parsed legacy `filecache.dbx` (or its modern successor, once its schema is confirmed on the target version) can plausibly yield more granular sync history — including local and remote modification timestamps, file size, and revision/hash identifiers tying an entry back to a specific Dropbox file revision — than the equivalent artifact for OneDrive, Google Drive, or Box currently supports with confidence.

### PowerShell

Check for the named legacy `.dbx` files specifically, which tells you whether the plaintext filecache-era forensic path applies to this host at all before you go looking for a schema that may not exist here:

```powershell
Test-Path 'C:\Users\jdoe\AppData\Local\Dropbox\config.dbx', 'C:\Users\jdoe\AppData\Local\Dropbox\filecache.dbx', `
          'C:\Users\jdoe\AppData\Local\Dropbox\deleted.dbx', 'C:\Users\jdoe\AppData\Local\Dropbox\sigstore.dbx'
```

PowerShell has no native cmdlet for opening or querying SQLite/SQLCipher content — the commands above (and the Hunt Evil block's broader `.dbx`/`.db`/`.sqlite` sweep) can locate and identify the database file, not read its rows. See Tooling below for DB Browser for SQLite (legacy, plaintext) versus a SQLCipher-aware tool (modern, encrypted).

## Encryption: SQLCipher in Newer Clients

🔴 **This is the single most consequential difference between Dropbox and the other three clients covered in this subfolder.** More recent Dropbox client versions are understood to have moved the local database to **SQLCipher-encrypted SQLite** as an anti-tampering/security hardening measure. If accurate for the client version on your target host, this has direct forensic consequences:

- **Standard SQLite tooling will not open the file.** DB Browser for SQLite in its stock configuration cannot read a SQLCipher-encrypted database — it will report the file as not a valid SQLite database (SQLCipher databases deliberately don't present a standard SQLite header). You need a SQLCipher-aware build or plugin, not the stock tool.
- **You need the encryption key/passphrase to get in.** I do not have high confidence in the exact key-derivation mechanism for the current client, but the pattern is plausible and worth investigating on a real engagement: Windows-native sync clients commonly derive or protect local secrets using **DPAPI**, tied to the logged-in Windows account's credentials, meaning the key material may be recoverable from the same user profile (or, in some designs, may require the user's live logon session / unlocked profile to derive). Don't assume this is trivial or guaranteed — verify the actual key-protection mechanism for the specific client version at hand, since getting this wrong either overstates or understates how hard the database is to access.
- **Practical effect on investigation planning:** budget time for identifying whether a target host's Dropbox database is SQLCipher-encrypted *before* promising a client or examiner report artifact-level detail from it — this is a meaningfully different lift than opening a plaintext OneDrive/Google Drive cache file, and it's the one place in this note where Dropbox's local evidence is genuinely harder to get at than the other three clients', despite the underlying schema being better understood historically.

### PowerShell

Read the first 16 bytes of a candidate database file — the literal string `SQLite format 3` means plaintext-openable, anything else means SQLCipher (no standard header) or an unrecognized format:

```powershell
Format-Hex 'C:\Users\jdoe\AppData\Local\Dropbox\instance1\config.dbx' -Count 16
```

Run the same header check across every candidate DB file found on the host and classify each one, so triage time isn't spent guessing which files are even worth pursuing:

```powershell
Get-ChildItem 'C:\Users\*\AppData\Local\Dropbox' -Recurse -Include '*.dbx','*.db' -ErrorAction SilentlyContinue | ForEach-Object {
    $bytes  = [System.IO.File]::ReadAllBytes($_.FullName) | Select-Object -First 16
    $header = [System.Text.Encoding]::ASCII.GetString($bytes)
    [PSCustomObject]@{ File = $_.FullName; Header = $header; Encrypted = ($header -notmatch '^SQLite format 3') }
}
```

Enumerate this profile's DPAPI master-key store — if the local DB's encryption key turns out to be DPAPI-protected, the derivation material lives here (this only surfaces the key files, it does not derive or decrypt anything):

```powershell
Get-ChildItem "$env:AppData\Microsoft\Protect\$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)" -ErrorAction SilentlyContinue |
    Select-Object Name, LastWriteTime
```

## Registry Artifacts

`HKCU\Software\Dropbox` (exact subkey/value-name schema not something I can assert with full confidence across client versions — enumerate the subkeys present under this key rather than assuming fixed names) is expected to track, by analogy with the equivalent OneDrive/Google Drive/Box keys:

| Value (expected category, naming unverified) | Meaning |
|---|---|
| Configured account identifier / email | Direct account attribution |
| Install path | Where the Dropbox client binaries are installed |
| Sync root path | The actual configured sync root — confirms/corroborates folder-structure evidence, especially important given user-relocation is supported |
| Account type indicator | Personal vs. Business/Team |

See Registry Forensics Fundamentals (note 04) for `NTUSER.DAT`/hive-access mechanics generally — assume ordinary `HKCU` values with no special live-vs-offline considerations beyond the standard ones covered there.

### PowerShell

Perform a full value dump across every subkey under `HKCU\Software\Dropbox` — since the exact value-name schema isn't guaranteed across client versions, enumerate what's actually present rather than querying named values that may not exist:

```powershell
Get-ChildItem 'HKCU:\Software\Dropbox' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
} | Select-Object PSChildName, *
```

Cross-host sweep for the same account identifier appearing under multiple profiles to tie a single Dropbox account back to several machines (runs in the context of the remote session, not necessarily every local profile on the target — confirm which user context applies):

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-ItemProperty 'HKCU:\Software\Dropbox' -ErrorAction SilentlyContinue
} | Select-Object PSComputerName, *
```

## Client-Side Logs

Dropbox's desktop client is understood to maintain its own operational logs, generically expected under a location resembling `%LocalAppData%\Dropbox\logs\` (or a similarly-named subfolder) — I don't have high confidence in the exact current path or log format (plaintext, structured, or otherwise) for the client version you'll encounter, so treat this as a starting point for on-host verification rather than a confirmed location to cite directly in a report. If present, expect the same general category of content the other three clients' logs record: connection/authentication events, sync errors, and file-operation history — useful when the local database shows *that* something happened but not *why*.

### PowerShell

Inventory whatever's actually present under the logs folder, newest first, since exact filenames and formats aren't guaranteed across client versions:

```powershell
Get-ChildItem 'C:\Users\*\AppData\Local\Dropbox\logs' -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime | Sort-Object LastWriteTime -Descending
```

Grep across the log files for authentication, connection, and error keywords once the format is confirmed as plaintext — finding the "why" behind a database sync event the local DB alone won't explain:

```powershell
Get-ChildItem 'C:\Users\*\AppData\Local\Dropbox\logs' -Recurse -File -ErrorAction SilentlyContinue |
    Select-String -Pattern 'auth','error','connect','fail' -ErrorAction SilentlyContinue |
    Select-Object Path, LineNumber, Line
```

## Four-Way Comparison: Local-Presence Guarantees Across Sync Clients

The single most valuable takeaway across this entire subfolder is that "a filename shows up under the sync folder" means something different for each of these four clients. This table closes the family:

| Client | Default local-presence model | On-demand/streaming feature | Local-presence guarantee for a listed file |
|---|---|---|---|
| **OneDrive** | Historically full mirror; Files On-Demand widely enabled by default on modern Win10/11 | Files On-Demand (placeholder reparse points) | Conditional per file — confirm hydration via `attrib`/`fsutil` before assuming content is local |
| **Google Drive for Desktop** | User/admin-selectable: Mirror mode (full local) or Stream mode (virtual drive) | Stream mode | Conditional and mode-dependent — a Mirror-mode file is a straightforward local-recovery target; a Stream-mode file is not |
| **Box Drive** | **No mirror mode exists** — stream-only by design, always | N/A (always streaming) | **Never guaranteed, for any file, with no exceptions** — positive evidence of hydration required in every case |
| **Dropbox** | Full mirror by default, historically the strongest "mirror-first" posture of the four | Smart Sync (Online-only vs. Local, per item) | Conditional only where Smart Sync/Online-only has been actively applied — a lower baseline risk than the other three, but not zero, and not to be assumed without checking |

Read left to right, this is roughly a spectrum from "assume local content is present, verify streaming exceptions" (Dropbox, loosely OneDrive) to "assume local content is absent, verify hydration" (Box). Get the client identified correctly before applying either default assumption.

## Browser-Adjacent Evidence

Accessing Dropbox through a web browser (`dropbox.com`) rather than the desktop client leaves its own separate trail — browser history, cache, and IndexedDB/LevelDB storage referencing `dropbox.com`. That's real evidence but belongs to the future `14 - Web Browser Forensics/` subfolder's depth, not here — this note is scoped to the desktop sync client's on-disk footprint.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Mass file access/addition in the local database immediately preceding a resignation/termination date | Classic insider-exfiltration narrative shared across all four notes in this subfolder — tie file-add/access timestamps to HR-provided dates; corroborate against server-side Dropbox evidence once a Cloud/ note exists for this account |
| A personal Dropbox account configured on a corporate machine | Same policy-violation/exfiltration-vector pattern flagged in OneDrive.md, the Google Drive note, and Box Drive.md — a ready-made channel to move corporate files to an account outside organizational control, especially notable if both `Dropbox` (personal) and `Dropbox (<Business Name>)` folders coexist on the same profile |
| Online-only (Smart Sync) files assumed never to have been touched locally, without checking actual database hydration state | Same core pitfall as the other three notes, applied here — confirm Local vs. Online-only status for the specific item before asserting content was or wasn't present on this host, rather than leaning on Dropbox's generally-mirror-first reputation as a substitute for checking |
| Dropbox's public link-sharing feature used on files shortly before or after suspicious local access | Dropbox has a long, well-known history as a public-link-sharing exfiltration vector — a user can generate a shareable link to a file (or an entire folder) and hand it to an external party without that party needing any Dropbox account at all. Local evidence of this (link creation isn't itself a filesystem artifact this note tracks with confidence) is limited — this is primarily a server-side/Cloud investigation angle — but local access immediately surrounding suspected link-sharing activity is still corroborating context worth flagging here, and it's a Dropbox-specific angle none of the other three clients in this subfolder needed |
| Encrypted local database (SQLCipher) blocking triage on a time-sensitive engagement | Not a sign of malicious activity by itself — it's simply the current client's default security posture — but plan for the added key-recovery/derivation step rather than assuming the database will open like the other three clients' plaintext or lightly-obfuscated caches |

## Tooling

| Tool | Use |
|---|---|
| **DB Browser for SQLite** | Works directly on legacy `.dbx`-era plaintext SQLite databases (`config.dbx`, `filecache.dbx`, etc.) once identified. **Will not open a SQLCipher-encrypted database on newer clients** — see next row |
| **A SQLCipher-aware tool/plugin** (e.g. a SQLCipher-compiled build of the sqlite3 CLI, or a SQLCipher extension for DB Browser for SQLite) | Required if the target host's local database turns out to be SQLCipher-encrypted (see Encryption section above) — stock SQLite tooling will report the file as invalid without this. Confirm encryption status by attempting to open the file first (a magic-byte/header check distinguishes standard SQLite from SQLCipher, which lacks the standard header) before assuming which tooling path applies |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `HKCU\Software\Dropbox` — see Registry Forensics Fundamentals (note 04) for hive-access mechanics |
| **RegRipper** | Plugin-based registry extraction — check whether a Dropbox-specific plugin exists at investigation time; a generic key-dump against `HKCU\Software\Dropbox\` works regardless |
| **Community `.dbx`/Dropbox-database parsers** | Dropbox's local databases are the most actively researched of the four clients in this subfolder, and DFIR-community write-ups and parsing scripts targeting the legacy `.dbx` filecache format do exist. I don't have current confidence in a single, actively-maintained, canonically "the" tool to name here (comparable to how confidently Eric Zimmerman's suite can be named for registry/EVTX artifacts) — the tooling landscape for this specific artifact has shifted as Dropbox's own format has evolved toward encryption, and a script written against the legacy `.dbx` schema will not help against a SQLCipher-encrypted modern database. Search for current `.dbx`/Dropbox-filecache parsing research at investigation time rather than assuming a name from memory, and fall back to DB Browser for SQLite (legacy) or a SQLCipher-aware tool (current) plus manual schema review either way |
| **`attrib`** / **`fsutil reparsepoint query`** | Same hydration-state checks used for OneDrive/Google Drive Smart Sync-equivalent Online-only items, given Dropbox's newer clients' use of the Windows Cloud Files API — see Sync Modes section above |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Server-side/admin-console evidence for the same Dropbox account — Events API equivalent, sharing/link audit, download/exfil confirmation from the cloud side | **Not yet covered in this repo** — no `Cloud/` Dropbox note currently exists (the same gap Box Drive.md flagged for Box). This note stands alone for now; add the cross-link here once a Cloud/ Dropbox note is written |
| Registry hive structure, `NTUSER.DAT` access mechanics used to read the keys in this note | Registry Forensics Fundamentals (note 04) |
| User-activity artifacts (Shell Bags, RecentDocs, LNK files, Jump Lists) that may reference files under the Dropbox sync root | File and Folder Opening (User Activity) (note 07) |
| The "database/artifact entry outlives the file" evidentiary pattern, applied more broadly | Deleted Items and File Existence (note 08) |
| The shared "on-demand/streaming local-presence pitfall" pattern across all four sync clients in this subfolder, and how each client's default posture differs | OneDrive.md ("Files On-Demand: Placeholders vs. Hydrated Files"), Google Drive for Desktop.md ("Mirror vs. Stream Mode"), and Box Drive.md ("The Core Forensic Pitfall: Stream-Only Means No Mirror Fallback") — see also the four-way comparison table above, which draws all four together |
| Closing out this subfolder: compare/contrast Dropbox's mirror-first default and encrypted-database posture against the other three clients' architectures | OneDrive.md, Google Drive for Desktop.md, Box Drive.md (this subfolder) |

## Resources

- Dropbox's own support/help documentation (generic reference — check Dropbox's current support site directly for the current article rather than relying on a specific link cited here, as Dropbox has reorganized this documentation across releases)
- DFIR-community research on Dropbox's local `.dbx`/filecache database structure — this is genuinely one of the more thoroughly published sync-client artifact families in the field; search current literature for `.dbx`/`filecache.dbx` parsing research at investigation time rather than relying on a specific citation here, since this note does not have a verified, current reference to name
- MITRE ATT&CK T1567.002 (Exfiltration to Cloud Storage) — https://attack.mitre.org/techniques/T1567/002/
