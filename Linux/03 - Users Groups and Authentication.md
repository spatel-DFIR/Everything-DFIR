# Users Groups and Authentication

Identity is where intrusions consolidate. After initial access an attacker wants durable, legitimate-looking credentials — a new account, a second UID-0 user, membership in a privileged group, a PAM tweak, or an empty password — because those survive reboots and blend into normal administration far better than a dropped binary. This note covers the local identity stores (`passwd`/`shadow`/`group`), the privilege model (`sudoers`, privileged groups), the pluggable authentication layer (PAM), and the enterprise reality that on domain-joined hosts most users don't live in `/etc/passwd` at all.

> 🔴 The flat files are not the whole picture. **`getent passwd` (NSS) resolves local *and* directory users; `cat /etc/passwd` shows only local ones.** On an enterprise host, enumerating just the file misses every SSSD/LDAP/AD account — and a *local* account created to shadow a domain name is a classic backdoor. Always compare the two.

## Contents

- [Quick Triage](#quick-triage)
- [Where the Identity Data Lives](#where-the-identity-data-lives)
- [What to Check for What](#what-to-check-for-what)
- [passwd shadow group gshadow](#passwd-shadow-group-gshadow)
- [getent vs Files and NSS](#getent-vs-files-and-nss)
- [UID and GID Reality](#uid-and-gid-reality)
- [Sudo and Privileged Groups](#sudo-and-privileged-groups)
- [PAM Overview](#pam-overview)
- [Account and Group Change Hunting](#account-and-group-change-hunting)
- [Enterprise Directory Join](#enterprise-directory-join)
- [Extracting and Cracking Hashes](#extracting-and-cracking-hashes)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Scenarios](#scenarios)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Every account NSS can resolve (local + domain)
getent passwd

# Any account with UID 0 other than root
awk -F: '$3==0 {print}' /etc/passwd

# Accounts with a real login shell
getent passwd | grep -Ev '/(nologin|false|sync|shutdown|halt)$'

# Passwordless or locked-status anomalies (root only)
sudo awk -F: '($2==""){print $1" NO PASSWORD"}' /etc/shadow

# Who can sudo
getent group sudo wheel

# Root-equivalent groups
getent group docker lxd
```

## Where the Identity Data Lives

🔴 = highest-value. Two zones: the local flat files (`/etc/*`) and, on enterprise hosts, the directory cache (`/var/lib/sss/`).

| Path | Holds | Notes |
|------|-------|-------|
| `/etc/passwd` | Accounts (name, UID, GID, home, shell) | World-readable |
| `/etc/shadow` | 🔴 Password hashes + aging | Root-only; field 3 = last-change date |
| `/etc/group` / `/etc/gshadow` | Group membership / group secrets | Watch privileged-group adds |
| `/etc/login.defs` | UID/GID ranges, password policy | Defines the system/user boundary |
| `/etc/sudoers` + `/etc/sudoers.d/*` | 🔴 Sudo policy | Read **every** drop-in |
| `/etc/pam.d/*` + `/lib*/security/pam_*.so` | Auth stacks + modules | Backdoor surface (→ Persistence/PAM) |
| `/etc/nsswitch.conf` | Resolution order (files/sss/ldap) | Tells you if the host is domain-joined |
| `/etc/sssd/sssd.conf` + `/var/lib/sss/` | 🔴 Domain join + cached creds | Offline: parse the cache, `getent` won't resolve |
| `/etc/skel/` | 🔴 Template copied into every new home | Payload here → every future user inherits it |
| `/etc/subuid` / `/etc/subgid` | Rootless-container ID maps | Namespace-abuse context |
| `~/.ssh/authorized_keys` | Key-based access (→ SSH note) | Backdoor key vector |
| `~/.k5login` / `~/.rhosts` | 🔴 Legacy passwordless-login backdoors | Listed principals log in as that user |

## What to Check for What

| Investigative question | Command / filter |
|------------------------|------------------|
| Is there a second root? | `awk -F: '($3==0)||($4==0)' /etc/passwd` |
| Any passwordless account? | `awk -F: '$2==""{print $1}' /etc/shadow` (+ passwd field) |
| Full user set incl. domain? | `getent passwd` vs `cat /etc/passwd` (diff) |
| Who can escalate (sudo/groups)? | `getent group sudo wheel admin docker lxd`; `cat /etc/sudoers.d/*` |
| When did the last account change happen? | `stat -c '%n %y' /etc/passwd /etc/shadow /etc/group` |
| Which accounts have real shells? | `getent passwd \| grep -Ev '/(nologin\|false)$'` |
| Whose password changed recently? | shadow field 3 (days-since-epoch) vs incident window |
| Is the host domain-joined? | `cat /etc/nsswitch.conf`; `realm list`; `systemctl status sssd` |
| Any PAM backdoor in the stack? | `grep -rE 'pam_exec\|pam_python\|unknown .so' /etc/pam.d/` |
| Legacy passwordless login files? | `find /root /home -name '.k5login' -o -name '.rhosts'` |

## passwd shadow group gshadow

These four files are the local identity store. You'll read them constantly, so know each field — the shell field alone distinguishes an interactive account from a service account, and the shadow hash field distinguishes a real password from a locked account.

**`/etc/passwd`** (world-readable) — one line per account:

```
dek:x:1000:1000:dek:/home/dek:/bin/bash
name : passwd : UID : GID : GECOS : home : login shell
```

- `x` in field 2 → the password hash lives in `/etc/shadow` (the normal case).
- Shell `/usr/sbin/nologin` or `/bin/false` → a service/system account not meant for interactive login. 🔴 A service account whose shell was *changed* to `/bin/bash` is a repurposing tell.
- UID/GID ≥ 1000 → a normal user on Debian and RHEL; below is reserved for system/service accounts (very old systems used 500).

**`/etc/shadow`** (root-only) — password hash + aging metadata:

```
user:$6$salt$hash:19500:0:99999:7:::
name : hash : last_change : min : max : warn : inactive : expire
```

| Hash prefix | Algorithm |
|-------------|-----------|
| `$1$` | MD5 (weak) |
| `$5$` | SHA-256 |
| `$6$` | SHA-512 (common default) |
| `$y$` | yescrypt (modern default) |
| `!` or `*` | No valid password (locked / login disabled) |
| *(empty field)* | 🔴 No password required — anyone can log in as this account |

The `last_change` field (days since epoch) is a quiet timeline artifact: it tells you when a password was last set, which you can correlate with the incident window. **`/etc/group`** lists group memberships and **`/etc/gshadow`** holds group passwords/admins (root-only).

## getent vs Files and NSS

The Name Service Switch (`/etc/nsswitch.conf`) decides where identity lookups actually go — files, then possibly SSSD/LDAP/systemd. `getent` follows that chain; reading the file doesn't.

```bash
# NSS-resolved view (files + LDAP/SSSD/systemd)
getent passwd

getent group

# Compare against the raw file - domain users appear in getent but NOT in the file
diff <(getent passwd | cut -d: -f1 | sort) <(cut -d: -f1 /etc/passwd | sort)

# What sources NSS consults
cat /etc/nsswitch.conf
```

🔴 On enterprise hosts many legitimate users exist only in the directory (SSSD/LDAP/winbind), never in `/etc/passwd`. Enumerating only the flat file both *misses* real accounts and *over-weights* a local account that shouldn't be there. The `diff` above is the fast way to spot a local account masquerading as (or shadowing) a directory user.

## UID and GID Reality

UID 0 is root, full stop — the *name* is irrelevant. The kernel authorizes by UID, so a second account with UID 0 is a second root by another name, and it's one of the quietest backdoors an attacker can leave.

```bash
# All UID-0 accounts (should be just 'root')
awk -F: '$3==0 {print $1}' /etc/passwd

# Duplicate UIDs (two names, one identity)
awk -F: '{print $3}' /etc/passwd | sort | uniq -d

# The system/user UID boundary for this host
grep -E '^UID_MIN|^UID_MAX|^SYS_UID' /etc/login.defs
```

🔴 A second UID-0 account (`awk` returns anything besides `root`) is high-signal — it's root that won't show up if you only look for the literal user `root`. Duplicate UIDs let an attacker "become" an existing user for logging cover, so their actions attribute to a legitimate account.

## Sudo and Privileged Groups

Beyond UID 0, privilege comes from sudo policy and a handful of groups whose membership is effectively root. `docker` and `lxd` are the sleepers here — anyone in them can mount the host and get root without a single sudo entry.

```bash
# Main sudoers policy + drop-ins
cat /etc/sudoers

ls -al /etc/sudoers.d/

cat /etc/sudoers.d/* 2>/dev/null

# Who's in the privilege groups
getent group sudo wheel admin

# Root-equivalent groups (container/VM control = host root)
getent group docker lxd libvirt
```

| Pattern | Meaning |
|---------|---------|
| `NOPASSWD: ALL` | 🔴 Passwordless root for that user/group |
| `user ALL=(ALL:ALL) ALL` | Full sudo |
| `#includedir /etc/sudoers.d` | Drop-in files — read every one (attackers hide a NOPASSWD line here) |
| `!authenticate` | Skips password |
| Membership in `docker`/`lxd` | 🔴 Trivially escalate to host root without sudo |

🔴 The `/etc/sudoers.d/` drop-in directory is the favored hiding spot — a one-line `attacker ALL=(ALL) NOPASSWD:ALL` file there grants silent passwordless root and is easy to overlook if you only read `/etc/sudoers`.

🔴 **`doas` is `sudo`'s lighter alternative** — the *default* privilege tool on Alpine and common on Arch/BSD-influenced setups, so a sudoers-only sweep misses it entirely. Its config is one small file:

```bash
# doas config — a permit rule = who can escalate, and whether nopass
cat /etc/doas.conf /etc/doas.d/*.conf 2>/dev/null

# 🔴 'permit nopass <user>' = passwordless root; 'permit <user> as root' = full escalation
grep -Ei 'permit.*nopass|permit .* as root' /etc/doas.conf 2>/dev/null
```

A `permit nopass` line for an unexpected user in `doas.conf` is the doas equivalent of a `NOPASSWD` sudoers backdoor.

## PAM Overview

PAM (Pluggable Authentication Modules) is the framework every login, sudo, and SSH auth flows through. Deep backdoor analysis lives in the Persistence note; here, sanity-check the stack and know what a healthy one looks like.

```bash
# Service auth stacks
ls -l /etc/pam.d/

# Common auth chain
cat /etc/pam.d/common-auth        # Debian

cat /etc/pam.d/system-auth        # RHEL

# Modules present on disk
ls -l /lib*/security/pam_*.so /usr/lib*/security/pam_*.so 2>/dev/null
```

🔴 The two PAM red flags to note here (and chase in the Persistence note): a `pam_*.so` reference in a stack that isn't a standard module name, and a `pam_exec.so`/`pam_python.so` line that runs a script during authentication. Either can be a backdoor that logs an attacker in with a magic password and survives password resets.

## Account and Group Change Hunting

Account and group changes leave traces in the logs and in file mtimes. This is how you time-bound *when* a rogue account appeared.

```bash
# Account/group management commands across all logs
grep -RIEHn "useradd|userdel|usermod|chsh|passwd|groupadd|groupdel|groupmod|gpasswd" /var/log 2>/dev/null

# Same, via journald
journalctl | grep -Ei "useradd|usermod|new user|password changed|to group"
```

| Command | Action |
|---------|--------|
| `useradd` / `userdel` / `usermod` | Add / delete / modify user |
| `chsh` | Change login shell (service account → shell = repurposing) |
| `passwd` | Change password |
| `groupadd` / `groupdel` / `groupmod` / `gpasswd` | Group changes (watch `gpasswd -a user sudo`) |

Correlate hits with login records (auth log / wtmp) and the file mtime of `/etc/passwd`, `/etc/shadow`, and `/etc/group` — their mtime is effectively the timestamp of the last account change on the box.

## Enterprise Directory Join

Establish whether the host is domain-joined so you know where identities really originate. Full baseline coverage is in the Enterprise Management note; here just determine the model.

```bash
# SSSD (most common modern join)
cat /etc/sssd/sssd.conf 2>/dev/null

systemctl status sssd

# realmd / AD join state
realm list 2>/dev/null

# Winbind / Samba
cat /etc/samba/smb.conf 2>/dev/null

# Kerberos
cat /etc/krb5.conf 2>/dev/null
```

If the host is joined, remember that authentication and authorization decisions may be made by the directory, cached credentials live under `/var/lib/sss/`, and a change to `sssd.conf` pointing at a rogue LDAP server is a redirection attack worth checking.

## Extracting and Cracking Hashes

When you need to test password strength or recover a credential (with authorization), the local hashes live in `/etc/shadow` (root-only). The workflow combines it with `/etc/passwd` and feeds the tool-specific format.

```bash
# 1. Combine passwd + shadow into John's input format (unshadow)
sudo unshadow /etc/passwd /etc/shadow > /evidence/hashes.txt

# 2a. Crack with John (auto-detects the $6$/$y$ format)
john --wordlist=rockyou.txt /evidence/hashes.txt; john --show /evidence/hashes.txt

# 2b. Or with hashcat - pick the mode from the hash prefix
hashcat -m 1800 -a 0 hashes.txt rockyou.txt      # $6$  SHA-512 crypt
hashcat -m 7400 -a 0 hashes.txt rockyou.txt      # $5$  SHA-256 crypt
hashcat -m 500  -a 0 hashes.txt rockyou.txt      # $1$  MD5 crypt
```

| Shadow prefix | Algorithm | hashcat mode | John format |
|---------------|-----------|--------------|-------------|
| `$1$` | MD5 crypt | `500` | `md5crypt` |
| `$5$` | SHA-256 crypt | `7400` | `sha256crypt` |
| `$6$` | SHA-512 crypt | `1800` | `sha512crypt` |
| `$y$` | yescrypt | `-` (John: `crypt`) | `crypt` |

🔴 Requires root/disk access to read `/etc/shadow`. On a mounted image, point `unshadow` at `/mnt/evidence/etc/{passwd,shadow}`. A weak/crackable password on a privileged or service account is itself a finding.

## Deep Threat Hunts

Consolidated identity-backdoor sweep. *(seasoned-DFIR additions on top of the RTR grep)*

```bash
# 1. Root by any name — UID 0 OR GID 0
awk -F: '($3==0)||($4==0){print}' /etc/passwd

# 2. Empty password FIELD in passwd itself (no shadow indirection = no prompt)
awk -F: '($2==""){print $1" empty passwd field"}' /etc/passwd

# 3. Home dirs with no matching account (deleted-user leftovers / rogue home)
comm -23 <(ls /home | sort) <(getent passwd | cut -d: -f1 | sort)

# 4. Passwords changed in the last 7 days (shadow field 3 = days since epoch)
awk -F: -v d=$(( $(date +%s)/86400 - 7 )) '($3>d){print $1" changed day "$3}' /etc/shadow

# 5. Every account that has EVER logged in (dormant service account now active = repurposed)
lastlog | grep -v 'Never logged in'

# 6. Legacy passwordless-login backdoors in home dirs
find /root /home -maxdepth 2 \( -name '.k5login' -o -name '.rhosts' \) -ls 2>/dev/null

# 7. Rootless-container ID maps (namespace-abuse context)
cat /etc/subuid /etc/subgid 2>/dev/null

# 8. Identity-file mtimes = timestamp of the last account change
stat -c '%n  %y' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers

# 9. Anyone slipped into a privileged group
getent group sudo wheel admin docker lxd libvirt adm

# 10. PAM stacks that run a script or reference an odd module
grep -rEn "pam_exec|pam_python|pam_permit" /etc/pam.d/ 2>/dev/null
```

**Hunt ideas:**

- **Diff `getent passwd` vs `/etc/passwd`** — a name present locally but not in the directory (on a joined host) is a local account *shadowing* a domain user: a classic blend-in backdoor.
- **The identity-file mtime is a free timeline anchor** — if `/etc/passwd`/`shadow`/`group` changed inside the incident window, an account event happened then; go find the command that did it (auditd `USER_MGMT`, journald).
- **`/etc/skel` is an overlooked persistence spot** — a payload dropped there is copied into *every* future user's home. Check its contents and mtime.
- **A dormant service account appearing in `lastlog`** (or with a freshly-set password) is repurposing — treat that account as compromised.
- **`.k5login`/`.rhosts` bypass passwords entirely** — always read root's home for them; they're rare and high-signal.

## Getting Max Value

- **Record the mtimes of `passwd`/`shadow`/`group`/`sudoers` first** — they're a free, precise anchor for *when* the last identity change occurred.
- **On a mounted image, `getent` won't resolve domain users** (no live NSS) — parse `/mnt/evidence/etc/passwd` directly and, for cached domain creds, the SSSD cache under `/var/lib/sss/db/`.
- **`unshadow` + crack to prioritize resets** — after containment, crack the shadow hashes to find which privileged/service accounts had weak or reused passwords the attacker likely leveraged.
- **Keep the `getent`-vs-file diff and the UID-0 `awk` as one-liners in your kit** — they answer "is there a hidden root / masquerading account" in one command.

## Scenarios

🔴 When this note earns its keep:

- **Hidden backdoor account** — an attacker adds a second UID-0 user or a `_`-lookalike service account with a real shell. `awk -F: '$3==0'` and the shell-anomaly checks surface it; the `/etc/passwd`/`shadow` mtime dates the change.
- **Quiet privilege escalation** — a user is slipped into `sudo`/`wheel`/`docker` or a `NOPASSWD` line is dropped in `/etc/sudoers.d/`. Group and sudoers enumeration finds it even when no new account was created.
- **Domain-user confusion** — on an enterprise host you can't see the real user set with `cat /etc/passwd`; `getent` vs the file exposes both missing directory users and a local account masquerading as a domain name.
- **Credential-strength triage** — after containment, crack the shadow hashes to find which accounts had weak/reused passwords the attacker likely leveraged, and prioritize their rotation.

## Correlate With

| To answer | Pivot to (note) |
|-----------|-----------------|
| *When* was the account created/changed? | File mtime of `/etc/passwd`/`shadow`; Timelining |
| Did the new account log in? | Auth and Login Records (`last`, `Accepted`) |
| Was a PAM backdoor used instead of a new account? | Persistence → PAM Backdoors |
| Was the escalation via SUID/caps rather than sudo? | Permissions |
| Command run under the account/sudo? | Auditd (`USER_CMD`); Shells (history) |
| Is the host domain-joined (identity source)? | Enterprise Management and Baseline |

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Second account with UID 0 | Hidden root |
| Empty password field in `/etc/shadow` | Anyone can log in as that user |
| New user created near incident time | Attacker foothold |
| User added to `sudo`/`wheel`/`docker`/`lxd` | Privilege escalation |
| Service account with a login shell | Repurposed for interactive access |
| `NOPASSWD: ALL` in a `sudoers.d` drop-in | Quiet passwordless root |
| Duplicate UID | Identity spoofing / logging cover |
| `/etc/passwd` or `/etc/shadow` recently modified | Timestamp of last account change |
| Local account shadowing a domain username | Backdoor blending with directory users |
| Empty password field in `/etc/passwd` itself | No prompt at all for that account |
| `.k5login` / `.rhosts` in a home directory | Legacy passwordless-login backdoor |
| Payload / changed mtime in `/etc/skel` | Persistence inherited by every new user |
| Dormant service account now in `lastlog` / password freshly set | Account repurposed for access |
| `pam_exec`/`pam_python` line in a `/etc/pam.d/` stack | Possible auth backdoor (→ Persistence/PAM) |

## Resources

- `passwd(5)`, `shadow(5)`, `group(5)`, `gshadow(5)`, `sudoers(5)`, `nsswitch.conf(5)`, `pam.conf(5)` man pages
- Understanding `/etc/shadow`: https://www.cyberciti.biz/faq/understanding-etcshadow-file/
- GTFOBins (sudo privesc): https://gtfobins.github.io
- MITRE ATT&CK: T1136 (Create Account), T1098 (Account Manipulation), T1548.003 (Sudo), T1078 (Valid Accounts), T1556.003 (Modify Auth Process: PAM), T1552.004 (Private Keys)
