# SSH Keys

Adding an attacker's **public key** to a user's `~/.ssh/authorized_keys` grants stealthy, passwordless SSH access that survives password changes and looks like a normal login. It's the most portable persistence technique across all UNIX-likes, and one of the quietest — no process, no scheduler, just a line in a file. Detection comes down to reviewing `authorized_keys` for every account (including root and service accounts) and checking file timestamps for recent tampering.

> 🔴 An `authorized_keys` line the user didn't add is a backdoor, and changing the user's password does nothing to remove it. Its **mtime/ctime** often shows exactly when it was planted, and a key in a **service account's** home (`www-data`, `postgres`) — which rarely needs SSH — is especially high-signal. This note is the persistence lens; the broader forensic view of SSH artifacts (known_hosts as a movement map, private-key theft, host keys) is in the SSH Artifacts note.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [How the Persistence Works](#how-the-persistence-works)
- [Key Files](#key-files)
- [Reviewing authorized_keys](#reviewing-authorized_keys)
- [Config-Based Variants](#config-based-variants)
- [Timestamps Tell the Story](#timestamps-tell-the-story)
- [Logs](#logs)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Every account's authorized_keys with timestamps + content (root)
for h in /root /home/*; do echo "== $h =="; ls -l "$h/.ssh/authorized_keys" 2>/dev/null; cat "$h/.ssh/authorized_keys" 2>/dev/null; done

# Fingerprint the authorized keys (identify them)
ssh-keygen -lf ~/.ssh/authorized_keys 2>/dev/null

# When was authorized_keys last changed?
stat -c 'authorized_keys ctime=%z mtime=%y' ~/.ssh/authorized_keys 2>/dev/null

# sshd effective config - forced commands, redirected key file
sshd -T 2>/dev/null | grep -Ei "forcecommand|authorizedkeysfile|permitrootlogin"
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Backdoor key on any account? | sweep `authorized_keys`(+2) for root + every user + service accounts |
| Which key was used at login? | fingerprint keys → match `auth.log` `SHA256:` |
| Key with a stealth option? | `grep 'command=\|environment=\|from=' authorized_keys*` |
| Key file redirected outside `~/.ssh`? | `sshd -T \| grep authorizedkeysfile` |
| sshd fetching keys via a **program**? | `sshd -T \| grep authorizedkeyscommand` |
| Forced command on every login? | `sshd -T \| grep forcecommand` |
| When was the key planted? | `authorized_keys` mtime/ctime vs account age |
| Armored against removal? | `lsattr ~/.ssh/authorized_keys*` (`+i`) |

## How the Persistence Works

The attacker generates a key pair and appends the public half to the target's `authorized_keys`:

```bash
# 1) Attacker creates a key pair (their side)
ssh-keygen -t ed25519 -f ./demo_key

# 2) Append the PUBLIC key to the target user's authorized_keys
cat demo_key.pub >> ~/.ssh/authorized_keys

# 3) Log in with no password using the private key
ssh -i demo_key user@target
```

🔴 From then on the attacker logs in **without a password** whenever sshd is reachable, and a password reset on the account does nothing to stop it. Only removing the key (and rotating any legitimate keys that may also be compromised) ends the access.

## Key Files

| Path | Holds |
|------|-------|
| 🔴 `~/.ssh/authorized_keys` | **Public keys allowed to log in as this user** — the backdoor lives here |
| 🔴 `~/.ssh/authorized_keys2` | Legacy variant, still honored — an overlooked backdoor spot |
| `~/.ssh/id_*` / `id_*.pub` | The user's own private/public keys |
| `~/.ssh/known_hosts` | Hosts this account SSH'd **out** to (lateral movement — see SSH Artifacts) |
| `/etc/ssh/sshd_config` + `sshd_config.d/` | Server policy (root login, key file location, ForceCommand) |

## Reviewing authorized_keys

```bash
# Show keys with their comments (often user@host of the creator)
cat ~/.ssh/authorized_keys

# Fingerprint + type each entry
ssh-keygen -lf ~/.ssh/authorized_keys

# Sweep every account, including root + service accounts
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys2; do
  echo "== $f =="; cat "$f" 2>/dev/null
done
```

🔴 Investigate any key whose **comment** is an unfamiliar `user@host`, that the user doesn't recognize, that carries a **forced command** (`command="..."`) or restriction (`no-pty`, `permitopen`), or that appears on an account — root, `www-data`, `postgres`, `nobody` — that shouldn't have remote keys at all.

## Config-Based Variants

A subtler variant hides the backdoor key outside `~/.ssh` by redirecting where sshd looks:

```bash
# Effective config (resolves includes/defaults) - the authoritative view
sshd -T 2>/dev/null | grep -Ei "authorizedkeysfile|forcecommand|permitrootlogin|permitemptypasswords"

# Drop-in fragments that can re-enable root login or redirect the key file
ls -l /etc/ssh/sshd_config.d/ 2>/dev/null; cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

🔴 `AuthorizedKeysFile` pointing at an attacker-writable path means the backdoor key lives somewhere other than `~/.ssh/authorized_keys`. `ForceCommand` runs a command on *every* login (a backdoor in its own right). `PermitRootLogin yes` / `PermitEmptyPasswords yes` weaken access to pair with the key.

🔴 **`AuthorizedKeysCommand`** is the stealthiest variant: sshd runs an *external program* to produce the authorized keys for a login. An attacker who sets it (with `AuthorizedKeysCommandUser`) to a script that always returns their public key gets a backdoor with **no key file on disk at all**.

```bash
# sshd running a PROGRAM to fetch keys (dynamic backdoor, no key file)
grep -rEni 'AuthorizedKeysCommand|AuthorizedKeysCommandUser' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
```

## Timestamps Tell the Story

```bash
# All timestamps on the .ssh dir and authorized_keys
stat -c 'Birth=%w Mod=%y Change=%z %n' ~/.ssh ~/.ssh/authorized_keys 2>/dev/null

ls -la --time-style=full-iso ~/.ssh/
```

🔴 If `authorized_keys` **mtime/ctime** is recent — or much newer than the account and its other dotfiles — it was likely modified to plant a key. Correlate with the auth log (`Accepted publickey`), the `.ssh` dir birth time, and (on ext4) `crtime` via `debugfs`.

## Logs

```bash
# Successful key-based logins + source IP (the backdoor in use)
grep "Accepted publickey" /var/log/auth.log /var/log/secure 2>/dev/null

journalctl _COMM=sshd | grep "Accepted publickey"
```

🔴 An `Accepted publickey` from an unfamiliar source IP, using a key fingerprint you can't attribute, is the planted key being used — cross-reference the timestamp with when `authorized_keys` was modified.

## Deep Threat Hunts

Every key source + fingerprint-match + config variants. *(seasoned-DFIR)*

```bash
# 1. Every authorized_keys(+2) on the box, fingerprinted (match to auth.log + inventory)
find / \( -name authorized_keys -o -name authorized_keys2 \) 2>/dev/null | while read f; do
  echo "== $f =="; ls -l "$f"; ssh-keygen -lf "$f" 2>/dev/null
done

# 2. Stealth key OPTIONS (forced command, env injection, source restriction)
grep -REn 'command=|environment=|from=|permitopen=' /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys* 2>/dev/null

# 3. sshd config variants: redirected file, dynamic command, forced command, weakened auth
sshd -T 2>/dev/null | grep -Ei 'authorizedkeysfile|authorizedkeyscommand|forcecommand|permitrootlogin|permitemptypasswords'

grep -rEni 'AuthorizedKeysCommand|AuthorizedKeysFile' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null

# 4. Match the login pubkey fingerprint (auth.log) to a planted key
grep -Eo 'SHA256:[A-Za-z0-9+/]+' /var/log/auth.log* /var/log/secure* 2>/dev/null | sort -u

# 5. Timeline: keys planted recently vs account age
find /root/.ssh /home/*/.ssh -name 'authorized_keys*' -newermt '-30 days' -ls 2>/dev/null

# 6. Immutable-armored keys
lsattr /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys* 2>/dev/null | grep -E '^....i'
```

**Hunt ideas:**

- **Look beyond `~/.ssh/authorized_keys`** — `authorized_keys2`, a redirected `AuthorizedKeysFile`, and especially `AuthorizedKeysCommand` (sshd runs a program to fetch keys — a script that always returns the attacker's key is a file-less backdoor).
- **Fingerprint every authorized key and match against `auth.log` "Accepted publickey"** fingerprints to see which planted key was actually used, and from where.
- **Key OPTIONS turn a key into a scripted backdoor** — `command=` runs a payload on login, `environment=` injects env (LD_PRELOAD with `PermitUserEnvironment`).
- **`authorized_keys` mtime vs the account's age dates the plant** — cross-ref the first `Accepted publickey` from a new IP.
- **A key on root or a service account that shouldn't have SSH** is the highest-signal finding.

## Getting Max Value

- **Sweep all key sources** — `authorized_keys`, `authorized_keys2`, redirected `AuthorizedKeysFile`, and `AuthorizedKeysCommand`.
- **Fingerprint + match** each key to `auth.log` and to your known-good key inventory.
- **mtime/ctime + `crtime` (ext4 `debugfs`) date the plant** — correlate with first use.
- **Removal isn't complete** until you also rotate legit keys that may be compromised *and* check the config variants (redirect/command/forcecommand).
- **Cross-ref SSH Artifacts (08)** for agent hijack, ControlMaster, and private-key theft.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Agent hijack / ControlMaster / private-key theft / `known_hosts` map | **SSH Artifacts** (08) |
| Which key was used at login | **Authentication and Login Records** (fingerprint match) |
| A trojaned `sshd` binary with a hardcoded key | **Package Managers and Integrity** (08), **ELF and Malware Triage** (11b) |
| When the key was planted / timestomp | **File and Directory Permissions** (02), **Timelining** (13) |
| Lateral movement to the next host | **Cross-Artifact Correlation** (00) |
| Remove it safely | **Remediation and Containment** (14) |

## Scenarios

- **Classic backdoor:** an `authorized_keys` line added to root or a service account.
- **Redirected file:** `AuthorizedKeysFile` points at an attacker-writable path outside `~/.ssh`.
- **Dynamic/file-less:** an `AuthorizedKeysCommand` script that always returns the attacker's key.
- **Forced command:** `command="…"` on the key runs a payload on every login.
- **Config weakening:** `PermitRootLogin yes` re-enabled to pair with a planted root key.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| `authorized_keys` key the user doesn't recognize | Backdoor public key planted |
| Key comment = unfamiliar `user@host` | Attacker's key origin |
| Key on `root` or a service account | High-value backdoor |
| `command="..."` / `no-pty` forced-command entry | Scripted backdoor access |
| `authorized_keys` mtime/ctime recent vs account age | Recently planted (timeline anchor) |
| `AuthorizedKeysFile` redirected / `ForceCommand` set | sshd policy tampered into a backdoor |
| `Accepted publickey` from an unknown IP | The backdoor in use |
| `.ssh` files with `+i` immutable bit | Armored persistence |
| `AuthorizedKeysCommand` set in sshd_config | File-less dynamic key backdoor |
| `authorized_keys2` present | Overlooked legacy backdoor spot |

## Resources

- `sshd(8)`, `sshd_config(5)`, `ssh-keygen(1)`, `authorized_keys(5)` man pages
- MITRE ATT&CK: T1098.004 (SSH Authorized Keys), T1556 (Modify Authentication Process), T1021.004 (SSH)
