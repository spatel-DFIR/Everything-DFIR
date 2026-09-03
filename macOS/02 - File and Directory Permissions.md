# File and Directory Permissions

Reading and extracting forensic value from macOS permissions, flags, ACLs, and extended attributes. macOS stacks **four** independent access layers on a file: POSIX permissions → BSD flags → ACLs → extended attributes. Check all four.

## Contents
- [Quick Triage](#quick-triage)
- [Quick Reference — Listing Commands](#quick-reference--listing-commands)
- [POSIX rwx Model](#posix-rwx-model)
- [Reading Metadata & Timestamps with `stat`](#reading-metadata--timestamps-with-stat)
- [Special Permissions (setuid / setgid / sticky)](#special-permissions-setuid--setgid--sticky)
- [BSD File Flags (chflags)](#bsd-file-flags-chflags)
- [ACLs (Access Control Lists)](#acls-access-control-lists)
- [Extended Attributes (xattrs)](#extended-attributes-xattrs)
- [Red Flags](#red-flags)

---

## Quick Triage

Sweep the four access layers for anti-forensics and implants. On a dead-box, retarget paths at the mounted Data volume.

```bash
# --- SETUID/SETGID outside the known-good system paths ---
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null \
  | grep -vE '^/(usr/(bin|sbin|libexec)|bin|sbin|System)/'

# --- WORLD-WRITABLE files, and dirs missing the sticky bit ---
find / -type f -perm -0002 2>/dev/null | grep -vE '^/(private/)?(tmp|var/tmp|var/folders)'

find / -type d -perm -0002 ! -perm -1000 2>/dev/null      # writable dir, no sticky

# --- IMMUTABLE / HIDDEN / OFFLOADED flags (locked or hidden malware) ---
find / \( -flags +uchg -o -flags +schg \) 2>/dev/null      # immutable

find /Users /tmp /var -flags +hidden 2>/dev/null           # Finder-hidden

find / -flags +dataless 2>/dev/null                        # content offloaded (not on disk)

# --- ACLs present (look for deny/hidden-allow) ---
ls -lRe /Users /Library 2>/dev/null | grep -E '^\s+[0-9]+: ' -B1

# --- QUARANTINE: download origins, and files placed WITHOUT quarantine ---
find ~/Downloads -type f -exec sh -c \
  'o=$(xattr -p com.apple.quarantine "$1" 2>/dev/null); \
   [ -z "$o" ] && echo "NO-QUARANTINE: $1" || echo "$o  <-  $1"' _ {} \;

# Pull the download source URL for a specific file
mdls -name kMDItemWhereFroms -name kMDItemDownloadedDate file

# --- BROAD: anything modified in a window of interest ---
find /Users /Library /usr/local -type f -newermt '2026-06-20' ! -newermt '2026-06-29' 2>/dev/null

# --- TIMESTOMPING: Birth later than Modify (impossible) across a tree ---
find /Users /tmp /usr/local/bin -type f 2>/dev/null -exec \
  stat -f '%SB | %Sm | %N' -t '%s' {} \; | awk -F' \\| ' '$1>$2{print "STOMPED?:",$0}'

# Full MACB for a suspect file
stat -f "B:%SB M:%Sm C:%Sc A:%Sa  %N" -t "%F %T" /path/to/suspect
```

---

## Quick Reference — Listing Commands

| Command | Shows |
|---|---|
| `ls -l` | POSIX permissions, owner, group |
| `ls -le` | + ACLs (one line per ACE) |
| `ls -l@` | + extended attributes (names + sizes) |
| `ls -lO` | + BSD file flags (capital O) |
| `ls -le@O` | **everything at once** (perms + ACL + xattr + flags) |
| `stat -f "%Sp %Su %Sg %Sf %N" file` | perms, owner, group, flags in one line |
| `xattr -l file` | all xattrs **with values** |
| `xattr -p <name> file` | print one xattr's value |
| `mdls file` | Spotlight metadata (incl. WhereFroms, dates) |
| `GetFileInfo file` | classic flags/type/creator (dev tools) |

> Trailing markers on the `ls` perm string: `@` = has xattrs, `+` = has ACL. Both can appear: `-rw-r--r--@+`.

---

## POSIX rwx Model

```
-rwxr-xr--   1  sek   staff   ...
│└┬┘└┬┘└┬┘
│ │  │  └── other:  r--
│ │  └───── group:  r-x
│ └──────── owner:  rwx
└────────── type
```

**Type char (1st position):**

| Char | Type | Char | Type |
|---|---|---|---|
| `-` | regular file | `p` | named pipe (FIFO) |
| `d` | directory | `s` | socket |
| `l` | symlink | `b` / `c` | block / char device |

**Permission bits / octal:** `r=4  w=2  x=1` per triad → e.g. `rwxr-xr--` = `754`.

**Meaning differs file vs directory:**

| Bit | On file | On directory |
|---|---|---|
| `r` | read contents | list entries (names) |
| `w` | modify contents | create/rename/**delete** entries |
| `x` | execute | traverse / enter (`cd`), access entries by name |

> Dir `w` lets a user delete files they don't own — unless the **sticky bit** is set (see §3).

### Changing perms & ownership

| Command | Does | Notes |
|---|---|---|
| `chmod 754 file` | Set perms by octal | |
| `chmod u+x,g-w,o-r file` | Set perms symbolically (`u`/`g`/`o`/`a` + `+`/`-`/`=`) | |
| `chmod -R 755 dir` | Recursive | Careful: hits every child |
| `chmod -h ... symlink` | Operate on the **symlink itself**, not its target | |
| `chown sek file` | Change **owner** | **root only** |
| `chown sek:staff file` | Change owner **and** group | root only |
| `chgrp staff file` | Change **group** | Owner (if member of target group) or root |
| `chown -R sek:staff dir` | Recursive owner+group | |
| `sudo chown -R $(id -un):staff dir` | Re-own a tree to current user | Common during evidence handling |

🔴 **Forensic footprint:** `chmod`/`chown`/`chgrp` update the inode **change time (ctime)** — *not* mtime or atime. A file whose **ctime ≫ mtime** is a tell that perms/ownership were altered *after* the content last changed (tampering, staging, or your own handling — document it). Changing owner needs root, so an unexpected owner change implies privileged access.

---

## Reading Metadata & Timestamps with `stat`

`stat` dumps the whole inode: perms, owner, flags, size, link count, and the **four timestamps**. macOS ships **BSD `stat`** (not GNU) — different flags.

### Output modes

| Command | Output |
|---|---|
| `stat file` | Raw one-line — numeric fields in fixed order |
| `stat -x file` | Verbose, labeled (human-readable) |
| `stat -f "<fmt>" -t "<timefmt>" file` | Custom format string |

`stat -x` example:
```
  File: "payload"
  Size: 52384      FileType: Regular File
  Mode: (0755/-rwxr-xr-x)   Uid: (501/sek)  Gid: (20/staff)
Device: 1,16   Inode: 8675309   Links: 1
Access: Sun Jun 28 09:14:02 2026
Modify: Sat Jun 20 11:02:50 2026
Change: Mon Jun 29 16:40:10 2026
 Birth: Sat Jun 20 11:02:50 2026
```

### The four timestamps (MACB)

| `stat -x` label | Spec | Updates when | Forensic note |
|---|---|---|---|
| **Access** (atime) | `%a` | File is read/accessed | Unreliable — Spotlight/AV/backups touch it; may be suppressed |
| **Modify** (mtime) | `%m` | **Content** changes | Primary "edited" time; settable by `touch -m` |
| 🔴 **Change** (ctime) | `%c` | **Inode metadata** changes (perms, owner, rename, links) — **NOT creation** | Jumps to "now" on any metadata change; **cannot be backdated with `touch`** |
| **Birth** (btime) | `%B` | File **created** | True creation (APFS/HFS+); settable by `SetFile -d` |

### Custom format (timeline-friendly)
```bash
stat -f "%Sp %Su:%Sg %z  B:%SB M:%Sm C:%Sc A:%Sa  %N" -t "%F %T" file

# %Sp perms · %Su/%Sg owner/group · %z size · %SB/%Sm/%Sc/%Sa = Birth/Modify/Change/Access · %N name
```

### 🔴 Detecting timestomping

| Pattern | Interpretation |
|---|---|
| `ctime` ≫ `mtime`/`atime` | Metadata changed long after content → `chmod`/`chown` or post-hoc tampering |
| **Birth later than Modify** | File "modified before it existed" → impossible → **timestomped** |
| mtime old but **ctime recent** (no legit reason) | `touch -t` backdated mtime/atime, but **ctime betrays the real change time** |
| All four identical to the second | Often a fresh copy/extract — or deliberately normalized timestamps |

> `touch -t`/`SetFile` can fake Modify (and Birth), but **ctime updates to the moment of tampering** and isn't user-settable — always compare all four and corroborate with FSEvents, Spotlight (`kMDItemFSCreationDate`), and the unified log.

---

## Special Permissions (setuid / setgid / sticky)

Shown in the **execute** position of a triad. Lowercase = special bit **+** execute; **uppercase** = special bit set but **no** execute (often a misconfig/red flag).

| Bit | Octal | Appears as | Effect | DFIR meaning |
|---|---|---|---|---|
| 🔴 setuid | `4000` | `s`/`S` in **owner** x (`-rwsr-xr-x`) | Runs as the **file owner** (often root) regardless of who launches it | Classic privesc / backdoor. Attacker-planted setuid-root binary = persistence + escalation |
| setgid | `2000` | `s`/`S` in **group** x | Runs with file's **group**; on dirs, new files inherit the group | Less common abuse; still flag unexpected ones |
| sticky | `1000` | `t`/`T` in **other** x (`drwxrwxrwt`) | On dirs: only the **owner** can delete their files (e.g. `/tmp`) | Expected on `/tmp`, `/var/tmp`; absence on shared dirs = anti-forensic risk |

**Hunt for them:**
```bash
find / -type f -perm -4000 2>/dev/null     # setuid

find / -type f -perm -2000 2>/dev/null     # setgid

find / -perm -4000 -user root 2>/dev/null  # setuid-root specifically
```
🔴 Compare results against a known-good baseline. Setuid-root binaries outside `/usr/bin`, `/usr/libexec`, `/usr/sbin`, `/System` are suspicious.

---

## BSD File Flags (chflags)

A **second, independent** layer stored in the inode (`st_flags`) — completely separate from POSIX perms. A file can be `777` yet impossible to modify or delete because of a flag. View with `ls -lO` (flags print as a comma-list after the perms, or `-` if none); set with `chflags <flag>`, clear with the `no`-prefix.

```bash
ls -lO file

# -rw-r--r--  1 sek staff  uchg,hidden  1234 Jun 29 ... file
#                          └────┬─────┘
#                          active flags (comma-separated)
```

**Two classes of flag** — this determines who can clear it:

| Class | Prefix | Who can set/clear |
|---|---|---|
| **User** | `u…` | File **owner** or root, anytime |
| **System / super-user** | `s…` | **root only**, and clearing requires **securelevel ≤ 0** (i.e. single-user / recovery). Under **SIP**, even root is blocked on protected paths. |

### Flag reference

| Flag | Class | Meaning | DFIR meaning |
|---|---|---|---|
| 🔴 `uchg` | user | **User immutable** — no modify, rename, move, delete, or attr change | Top anti-deletion trick; `rm` fails with "Operation not permitted" despite open POSIX bits |
| 🔴 `schg` | system | **System immutable** — same lock, but clearable only in single-user mode | Strongest on-disk lock; on a user-area file = deliberate hardening of malware |
| `uappnd` / `sappnd` | user / system | **Append-only** — can add to, but not modify/truncate/delete | Log-tamper protection; rare on user files (suspicious if present) |
| `uunlnk` / `sunlnk` | user / system | **Cannot be unlinked/deleted** (but content still editable) | Keeps a file undeletable; rarely seen legitimately |
| 🔴 `hidden` | user | **Invisible in Finder** (kIsInvisible) — still listed by `ls`/terminal | Cheap GUI-hiding of payloads; distinct from dot-prefix hiding |
| `restricted` | system | **SIP**-protected ("rootless") | Expected on system files; on a user file = abnormal |
| `compressed` | (read-only) | Content transparently compressed (decmpfs) | Real size differs from on-disk; affects carving/hashing assumptions |
| `dataless` | (system) | **Placeholder** — content evicted to iCloud / not materialized on disk | 🔴 File content may live in the **cloud, not the image**; reading it triggers download |
| `nodump`, `opaque`, `arch` | misc | Backup / union-mount / archived hints | Rarely investigation-relevant |

### Key flags — detail

- 🔴 **`uchg` (user immutable):** Set/cleared by **owner or root** at any time. Blocks all changes to the file. Linux equivalent: `chattr +i`. To delete or copy a locked file you must first clear it: `chflags nouchg file`. ⚠️ Clearing it updates the file's **ctime** — note that you did this before acquisition.
- 🔴 **`schg` (system immutable):** Set by **root only**; can be cleared **only when securelevel ≤ 0** — in practice, boot to **single-user / Recovery**. At normal runtime even root gets "Operation not permitted." Strongest persistence lock for a planted file.
- 🔴 **`hidden`:** Toggles the Finder-invisible bit. The file is fully present and runnable; only Finder hides it. **Always enumerate with the terminal (`ls -laO`), never trust Finder** during triage.
- 🔴 **`dataless`:** APFS marks files whose data was offloaded (e.g. "Optimize Mac Storage" / iCloud Drive). The directory entry and metadata are local but the bytes are not — relevant when content is "missing" from a dead-box image.

### Commands

```bash
ls -lO file                          # view flags

ls -laO@e dir                        # full picture: perms, flags, xattrs, ACLs

chflags uchg  file                   # set user-immutable

chflags nouchg file                  # clear it (needed before deleting/copying a locked file)

chflags hidden / nohidden file       # toggle Finder visibility

sudo chflags -R nouchg dir           # recursively unlock a tree

find / -flags +uchg    2>/dev/null   # hunt immutable files

find / -flags +schg    2>/dev/null   # hunt system-immutable files

find / -flags +hidden  2>/dev/null   # hunt Finder-hidden files

find / -flags +dataless 2>/dev/null  # hunt offloaded/placeholder files
```
> If a delete or edit "won't work" despite good POSIX perms, **check flags** (`ls -lO`) before assuming corruption.

---

## ACLs (Access Control Lists)

Extend POSIX with per-user/group allow/deny rules + inheritance. A trailing **`+`** on the perm string = ACL present.

```bash
ls -le file        # list ACEs, numbered, in evaluation order

chmod +a "user:bob allow read,write" file

chmod -a# 0 file   # remove ACE index 0

chmod -N file # remove all ACLs from file 
```

ACE format: `who allow|deny perm1,perm2 [inheritance]`

🔴 Forensic angles:

| Observation | What it means |
|---|---|
| **`deny` ACE** (incl. against owner) | Blocks access despite good POSIX bits → explains "permission denied"; possible anti-forensics |
| **`allow` ACE** for a user/group POSIX doesn't show | Silent hidden access path / backdoor |
| Order matters | ACLs evaluated **top-down, first match wins** — a `deny` above an `allow` overrides it |

---

## Extended Attributes (xattrs)

Arbitrary key→value metadata. Trailing **`@`** on the perm string = xattrs present. **Highest forensic payoff in this note.**

```bash
ls -l@ file                 # names + sizes

xattr file                  # just names

xattr -l file               # names + values (hex/text)

xattr -p com.apple.quarantine file   # one attribute

xattr -px com.apple.quarantine file | xxd -r -p | plutil-p -  # human redable
```

### High-value attributes

| Attribute | Contains | DFIR use |
|---|---|---|
| 🔴 `com.apple.quarantine` | flags ; timestamp ; **agent app** ; event UUID | **How/when/by-what a file arrived.** Set on downloads/email/AirDrop. Drives Gatekeeper. |
| 🔴 `com.apple.metadata:kMDItemWhereFroms` | binary plist of **source URL(s)** | Origin URL of a download (and referrer) |
| `com.apple.metadata:_kMDItemUserTags` | Finder color/text tags | User intent / organization |
| `com.apple.lastuseddate#PS` | last-used timestamp | File usage timing |
| `com.apple.macl` | app UUID(s) granted access (TCC) | Which app was given access to the file |
| `com.apple.provenance` | install/provenance tracking | Origin tracking on newer macOS |
| `com.apple.FinderInfo` | legacy Finder type/creator/flags | Older metadata |
| `com.apple.ResourceFork` | legacy resource fork data | Old-format files; can hide data |

### Parse quarantine
```bash
xattr -p com.apple.quarantine file

# => 0081;5f3a1c2e;Safari;A1B2C3D4-...-UUID
#    │     │        │       └─ event UUID (cross-ref LSQuarantineEvent DB)
#    │     │        └────────── agent that downloaded it (Safari, Chrome, Mail…)
#    │     └─────────────────── HEX epoch download time → date -r $((16#5f3a1c2e))
#    └───────────────────────── flag bits
```
Cross-reference the UUID/agent against the LaunchServices quarantine DB:
`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` (SQLite — one row per download with URL, agent, timestamp; survives even if the file is deleted).

**Flag field (1st value, hex):** low bit `0001` = "quarantined, not yet user-approved"; once the user approves/opens, Gatekeeper clears that bit (e.g. `0081`→`0083`). So the flag shows **whether the file was actually opened/approved** on this host.

### Parse WhereFroms (binary plist)
```bash
xattr -p com.apple.metadata:kMDItemWhereFroms file | xxd -r -p > /tmp/wf.plist

plutil -p /tmp/wf.plist

# or in one shot:
mdls -name kMDItemWhereFroms file
```

> Copying files **off** the system can strip xattrs/flags/ACLs. Preserve them: `cp -p`, `ditto --preserve...`, or `rsync -aE`. Capture metadata **before** moving evidence.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| setuid-root binary in a non-standard path | Privesc / backdoor |
| `uchg`/`schg` on a user-area file | Locked malware / anti-deletion |
| `hidden` flag on an executable | Deliberate hiding |
| `deny` ACE blocking owner/admin | Anti-forensics |
| `allow` ACE granting access POSIX bits don't reveal | Hidden backdoor access |
| quarantine xattr agent/URL from suspicious origin | Initial access vector |
| expected file but **no** quarantine xattr where one's normally set | Manual placement / xattr stripping |
| `ctime` recent but `mtime` old (no admin action), or **Birth after Modify** | Timestomping (`touch -t` / `SetFile`) |
