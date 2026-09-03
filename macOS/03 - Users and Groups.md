# Users and Groups

How macOS stores accounts, groups, and passwords, where to find them on disk, and how to extract/crack hashes and credentials. macOS does **not** use `/etc/passwd` as its live store — accounts live in the **OpenDirectory local node (DSLocal)** as per-user plists. `/etc/passwd` and `/etc/master.passwd` exist only as legacy/single-user fallbacks.

## Contents
- [Quick Triage](#quick-triage)
- [Where Account Data Lives](#where-account-data-lives)
- [Account Types & UID Ranges](#account-types--uid-ranges)
- [Management & Enumeration Tools](#management--enumeration-tools)
- [Password Storage — ShadowHashData (PBKDF2-SHA512)](#password-storage--shadowhashdata-pbkdf2-sha512)
- [Keychain & Passwords](#keychain--passwords)
- [Secure Token, Bootstrap Token & Volume Owners](#secure-token-bootstrap-token--volume-owners)
- [Local vs Mobile vs Network Accounts](#local-vs-mobile-vs-network-accounts)
- [Hidden Accounts — How They Hide & How to Find Them](#hidden-accounts--how-they-hide--how-to-find-them)
- [Forensic Logs & Timeline](#forensic-logs--timeline)
- [Auto-Login Password Decode (`/etc/kcpassword`)](#auto-login-password-decode-etckcpassword)
- [Red Flags](#red-flags)

---

## Quick Triage

```bash
# --- ALL users + UID, sorted (spot UID 0 dupes / hidden / out-of-range) ---
dscl . -list /Users UniqueID | sort -k2 -n

# Any NON-root account with UID 0
dscl . -list /Users UniqueID | awk '$1!="root" && $2==0 {print "UID-0 BACKDOOR:",$1}'

# Service (_) accounts that have a REAL login shell (should be false/nologin)
dscl . -list /Users UserShell | awk '/^_/ && $2!="/usr/bin/false" && $2!="/sbin/nologin"'

# Admin group membership (unexpected members = privesc)
dscl . -read /Groups/admin GroupMembership

# Hidden-user settings
defaults read /Library/Preferences/com.apple.loginwindow Hide500Users HiddenUsersList 2>/dev/null

# Secure Token holders + FileVault crypto users (who can decrypt)
for u in $(dscl . -list /Users | grep -v '^_'); do \
  printf '%-15s ' "$u"; sysadminctl -secureTokenStatus "$u" 2>&1 | tail -1; done

fdesetup list; diskutil apfs listCryptoUsers /

# --- DEAD-BOX: recently changed account records ---
ls -lat /var/db/dslocal/nodes/Default/users/*.plist | head

ls -la  /var/db/dslocal/nodes/Default/users/ | grep -vE '/_'   # non-service accounts

# Auto-login password present? (then decode in §10)
ls -la /etc/kcpassword 2>/dev/null

defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null

# Sudoers tampering (NOPASSWD / extra users)
grep -rEv '^\s*#|^\s*$' /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Account lifecycle events in the unified log
log show --predicate 'process=="opendirectoryd" AND (eventMessage CONTAINS[c] "create" OR eventMessage CONTAINS[c] "password" OR eventMessage CONTAINS[c] "membership")' --info --last 30d
```

---

## Where Account Data Lives

| Path | Contains | Notes |
|---|---|---|
| 🔴 `/var/db/dslocal/nodes/Default/users/<user>.plist` | Per-user record: UID, GID, home, shell, **`ShadowHashData`** (password hash) | Authoritative local account store. Binary plist |
| `/var/db/dslocal/nodes/Default/groups/<group>.plist` | Group record: GID, `GroupMembership`, `GroupMembers` (GUIDs) | Group definitions + membership |
| `/etc/passwd`, `/etc/master.passwd` | Legacy account list | Fallback only (single-user mode); **not** the live source |
| `/etc/group` | Legacy group list | Fallback only |
| 🔴 `~/Library/Keychains/login.keychain-db` | User's default keychain (passwords, keys, notes) | Unlocked by login password (§4) |
| `/Library/Keychains/System.keychain` | System-wide secrets (Wi-Fi, 802.1X, certs) | Machine credentials |
| `~/Library/Preferences/com.apple.loginwindow.plist` / `/Library/Preferences/...` | Login window config, hidden-user settings | `Hide500Users`, `HiddenUsersList` (§7) |
| 🔴 `/etc/kcpassword` | **Auto-login** user's password, XOR-obfuscated with a static key | Trivially decodable cleartext password (see below) |
| 🔴 `/etc/sudoers`, `/etc/sudoers.d/` | Who may `sudo` and how | `NOPASSWD`, added users/rules = privesc persistence |
| `/etc/pam.d/` (`sudo`, `login`, `screensaver`) | PAM auth stack | `pam_tid.so` = Touch ID for sudo; modified modules = auth bypass |
| `/var/db/AuthorizationDB` / `/System/.../authorizationdb` | Authorization rights DB | Weakened rights = privilege abuse |

> 🔴 **`/etc/kcpassword`** exists only when **auto-login** is enabled (`com.apple.loginwindow autoLoginUser`). It's the account password XOR'd with the static key `0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`. Decode it (Perl one-liner in §10) → **plaintext login password**, which also unlocks that user's login keychain.

> **Dead-box:** read the `.plist` files directly. **Live box:** use `dscl` / `dscacheutil` (below).

---

## Account Types & UID Ranges

| Type | UID | Identifying trait | DFIR meaning |
|---|---|---|---|
| 🔴 root | `0` | "System Administrator"; disabled by default | Enabled root, or a *second* account with UID 0 = backdoor |
| Admin | `≥ 501` | Member of group **`admin`** (GID 80); has `sudo` | Privileged; check `admin` membership for surprises |
| Standard | `≥ 501` | Normal local user, no admin group | Baseline user |
| Guest | `201` | `Guest` account | Home wiped at logout; remnants may survive |
| Sharing-only | `≥ 501` | File-sharing access, **no login/shell** (`/usr/bin/false`) | Often overlooked; can mask access |
| Service / daemon | `1–500` | **`_`-prefixed** name (`_www`, `_spotlight`, `_mdnsresponder`) | Should have no login; a `_acct` with real shell/home = suspicious |
| `nobody` | `-2` / `4294967294` | Unprivileged placeholder | Normal |
| Mobile / Network | `≥ 1000` typ. | Directory (AD/LDAP) account | Domain binding present (§6) |

> Standard local users start at **UID 501** and increment. **Hidden from login window** when UID `< 500` (§7).

---

## Management & Enumeration Tools

### `dscl` — Directory Service command line (read/modify the local node `.`)

| Command | Does |
|---|---|
| `dscl . -list /Users` | List all users |
| `dscl . -list /Users UniqueID` | 🔴 List users **with UID** (spot hidden/dup UIDs) |
| `dscl . -read /Users/<u>` | Full record for a user |
| `dscl . -read /Users/<u> UniqueID PrimaryGroupID NFSHomeDirectory UserShell` | Key fields only |
| `dscl . -read /Users/<u> ShadowHashData` | Raw hash blob (live) |
| `dscl . -list /Groups` / `-read /Groups/admin GroupMembership` | Groups + members |
| `dscl . -append /Groups/admin GroupMembership <u>` | 🔴 Add user to admins (how privesc is done) |
| `dscl . -create /Users/<u> ...` / `-delete /Users/<u>` | Create / delete account |

### `sysadminctl` — modern account admin (macOS 10.10+)

| Command | Does |
|---|---|
| `sysadminctl -addUser <u> -fullName "…" -password <pw> -admin` | Create admin user |
| `sysadminctl -deleteUser <u>` | Delete user |
| `sysadminctl -resetPasswordFor <u> -newPassword <pw>` | Reset password |
| `sysadminctl -secureTokenStatus <u>` | 🔴 Check Secure Token (§5) |
| `sysadminctl -secureTokenOn/-secureTokenOff <u> -password <pw>` | Grant/revoke Secure Token |

### Other

| Command | Does |
|---|---|
| `dseditgroup -o edit -a <u> -t user admin` | Add user to a group |
| `dscacheutil -q user [-a name <u>]` | Query the directory cache |
| `id <u>` / `groups <u>` | Show UID/GID/group membership |
| `last` | Login/logout history (from `utmpx`) |
| `who` / `w` | Currently logged-in users (live) |
| `fdesetup list` | FileVault-enabled users |
| `diskutil apfs listCryptoUsers /` | APFS volume crypto-owners (§5) |

---

## Password Storage — ShadowHashData (PBKDF2-SHA512)

Each user's `<user>.plist` holds **`ShadowHashData`**: Base64 → a binary plist containing a `SALTED-SHA512-PBKDF2` dict with three crackable components:

| Component | What it is |
|---|---|
| `iterations` | PBKDF2 round count |
| `salt` | Per-user random salt (32 bytes) |
| `entropy` | The derived **hash** (128 bytes) |

Algorithm: **PBKDF2-HMAC-SHA512**. (Newer systems may also store `SRP-…-PBKDF2` for some auth flows.)

### Extract the hash (modern macOS)

```bash
# 1. Copy the user plist out
sudo cp /var/db/dslocal/nodes/Default/users/<username>.plist ~/Desktop/

# 2. Loosen perms for manipulation
sudo chmod 660 ~/Desktop/<username>.plist

# 3. Convert binary plist -> XML
plutil -convert xml1 ~/Desktop/<username>.plist

# 4. Pull the ShadowHashData <data> blob into ShadowHashData.xml (text editor),
#    then Base64-decode it to a binary plist
cat ShadowHashData.xml | base64 -d > ShadowHashData.bin

# 5. Verify it starts with the bplist00 magic
xxd ShadowHashData.bin | head    # expect: bplist00

plutil -convert xml1 ShadowHashData.bin -o -   # read iterations/salt/entropy
```

### Format for cracking

Convert `salt` and `entropy` to **hex**, then build the tool-specific string:

| Tool | Mode | Format |
|---|---|---|
| Hashcat | `-m 7100` | `$ml$<iterations>$<salt-hex>$<entropy-hex>` |
| John the Ripper | `--format=pbkdf2-hmac-sha512` | `$pbkdf2-hmac-sha512$<iterations>$<salt>$<hash>` |

```bash
hashcat -m 7100 hashes.txt wordlist.txt
```

> 🔴 Requires root/disk access to read the plist. ShadowHashData is the **only** place the local password hash lives on modern macOS (no `/etc/shadow`).

---

## Keychain & Passwords

Encrypted credential vaults. The **login keychain** is unlocked automatically at login because it's encrypted with a key derived from the user's **login password** (so it stays in sync with password changes).

| File | Scope | Holds |
|---|---|---|
| 🔴 `~/Library/Keychains/login.keychain-db` | User | App/internet passwords, secure notes, private keys, certs |
| `~/Library/Keychains/<UUID>/keychain-2.db` | User | Local iCloud Keychain data |
| `/Library/Keychains/System.keychain` | System | Wi-Fi (AirPort), 802.1X, machine certs |
| `/System/Library/Keychains/SystemRootCertificates.keychain` | System | Trusted root CAs |

**Encryption:** AES; login keychain's master key is derived from the login password via PBKDF2. Locked keychain = encrypted at rest.

### `security` CLI (live system)

| Command | Does |
|---|---|
| `security list-keychains` | Show keychains in search list |
| `security dump-keychain` | Dump metadata of items |
| `security find-generic-password -ga <name>` | 🔴 Print a stored app password (prompts/authorizes) |
| `security find-internet-password -gs <host>` | Print a stored website password |
| `security unlock-keychain ~/Library/Keychains/login.keychain-db` | Unlock (prompts for pw) |

### The front-end apps

| App | Path | What it surfaces |
|---|---|---|
| **Keychain Access** | `/System/Applications/Utilities/Keychain Access.app` | Classic browser over `login.keychain-db` / `System.keychain` — view/reveal passwords, certs, keys, secure notes (needs unlock password) |
| 🔴 **Passwords** (macOS **Sequoia 15+**) | `/System/Applications/Passwords.app` | Dedicated front-end for the **iCloud Keychain**: website/app passwords, **passkeys**, **Wi-Fi** passwords, **verification codes (TOTP/2FA)**, shared groups, security recommendations |

🔴 **Passwords app — forensic detail:**
- **Not a new database** — it's a UI over the **iCloud Keychain**. Items live in `~/Library/Keychains/<UUID>/keychain-2.db` (the local cloud-keychain copy) and **sync across the user's Apple devices**.
- Opening it **requires auth** (login password / Touch ID).
- **TOTP secrets stored here let you generate the victim's 2FA codes** — high-value for account takeover analysis. **Passkeys** are non-exportable WebAuthn credentials, but their presence reveals which services the user registered.
- Because items sync, the same credentials are also obtainable via an **iCloud account acquisition** (with creds/token). For offline disk analysis, pull the whole `~/Library/Keychains/<UUID>/` directory.

### Offline extraction & cracking

- **`chainbreaker`** (Python) parses `login.keychain-db` and decrypts items given the **user password**, the **master key**, or the **SystemKey** — the standard dead-box keychain extraction tool.
- **Crack the keychain password:** Hashcat **`-m 23100`** (Apple Keychain) takes a hash extracted from `login.keychain-db` and brute-forces the keychain password offline.

---

## Secure Token, Bootstrap Token & Volume Owners

On **FileVault/APFS-encrypted** systems, only certain users can unlock the disk — this is independent of being an "admin."

| Concept | What it is | Why it matters |
|---|---|---|
| **Secure Token** | A wrapped key tied to a user's password; granted to the **first** admin to log in / set a password. | Only Secure-Token users can be added to FileVault and **decrypt** the volume |
| **Volume Owner** | APFS cryptographic user (has Secure Token) | List with `diskutil apfs listCryptoUsers /` |
| **Bootstrap Token** | Escrowed token (often via MDM) that helps grant Secure Token to other users | Managed-Mac context; can enable silent token grants |

```bash
sysadminctl -secureTokenStatus <user>     # ENABLED / DISABLED

diskutil apfs listCryptoUsers /           # who can unlock the volume

fdesetup list                             # FileVault-enabled accounts
```

> 🔴 A hidden/backdoor admin **without** Secure Token cannot decrypt FileVault — but one *with* it is a serious finding. Token grants appear in the unified log.

---

## Local vs Mobile vs Network Accounts

| Type | Auth source | Home dir | Local hash? | Tell |
|---|---|---|---|---|
| Local | DSLocal (on device) | Local | ✅ ShadowHashData | Standard standalone Mac |
| Mobile | Directory (AD/LDAP), **cached** locally | Local | ✅ cached hash | `OriginalNodeName`, `SMBSID`, `_writers_*` keys in the plist; created by directory binding |
| Network | Directory server (live) | Often network/SMB | ❌ usually none local | Requires connectivity; minimal local artifact |

> Presence of **mobile accounts** = the Mac was **bound to a domain** (AD/LDAP). Check the user plist for `OriginalNodeName`/`SMBSID` and `/Library/Preferences/OpenDirectory/` config.

---

## Hidden Accounts — How They Hide & How to Find Them

| Hiding method | Mechanism |
|---|---|
| UID `< 500` | Automatically hidden from the login window |
| `IsHidden = 1` | Flag in the user's plist / set via `dscl` |
| `Hide500Users = true` | `com.apple.loginwindow.plist` hides all UID `< 500` |
| `HiddenUsersList` | Array of specific usernames to hide (loginwindow plist) |
| `_`-prefixed name | Looks like a service account |

### Detection

```bash
dscl . -list /Users UniqueID            # every user + UID (compare to /Users dirs)

ls -la /Users                            # home dirs that exist

defaults read /Library/Preferences/com.apple.loginwindow Hide500Users HiddenUsersList

# Dead-box: enumerate /var/db/dslocal/nodes/Default/users/*.plist directly
```

🔴 Red flags: an account in `HiddenUsersList`; `IsHidden` **+** membership in `admin`; a `_`-prefixed account with a real shell (`/bin/zsh`) and home dir; a second account with **UID 0**; duplicate UIDs.

---

## Forensic Logs & Timeline

| Source | Yields |
|---|---|
| 🔴 Unified Log (`opendirectoryd`, `authd`, `sysadminctl`) | Account create/delete, password change, group changes, Secure Token grants |
| `loginwindow`, `securityd`, `authorizationhost` log events | Interactive logins / auth attempts |
| `last` / `/var/log/...` (`utmpx`) | Login/logout/reboot history |
| `.plist` file **mtime** in dslocal | Approx. last modification of an account record |
| `/var/log/install.log` | User-creation events during setup/MDM |

```bash
log show --predicate 'process == "opendirectoryd"' --info --last 7d

log show --predicate 'eventMessage CONTAINS[c] "secure token"' --info

log show --predicate 'process == "sysadminctl" OR process == "sysadminserviced"' --last 30d

last                                   # login history
```

---

## Auto-Login Password Decode (`/etc/kcpassword`)

```bash
# Decode the XOR-obfuscated auto-login password to plaintext
sudo perl -e '@k=(0x7d,0x89,0x52,0x23,0xd2,0xbc,0xdd,0xea,0xa3,0xb9,0x1f);
  open(F,"/etc/kcpassword");$d=<F>;@b=unpack("C*",$d);
  for($i=0;$i<@b;$i++){last if $b[$i]==$k[$i%11];print chr($b[$i]^$k[$i%11]);}print"\n";'
```
> Yields the auto-login account's **plaintext password** — which also unlocks that user's `login.keychain-db`.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Second account with **UID 0** | Root-equivalent backdoor |
| `_`-prefixed account with real shell + home | Disguised attacker account |
| Admin account in `HiddenUsersList` / `IsHidden=1` | Concealed privileged access |
| Account created near incident time | Attacker persistence |
| Unexpected member added to group `admin` | Privilege escalation |
| Duplicate UID across accounts | Attribution confusion / hiding |
| Backdoor account holding a **Secure Token** | Can decrypt FileVault |
| Mobile account on a "standalone" Mac | Undisclosed domain binding |
| `NOPASSWD` rule or added user in `/etc/sudoers.d/` | Sudo-based persistence |
| `/etc/kcpassword` present (auto-login on) | Recoverable plaintext password |
| Modified `/etc/pam.d/` module | Authentication bypass |
