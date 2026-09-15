# SSH Keys

Adding an attacker's **public key** to a user's `~/.ssh/authorized_keys` grants **stealthy, passwordless** access that survives password changes and looks like normal SSH. It's a portable persistence technique across macOS and all UNIX-likes. Detection comes down to **reviewing `authorized_keys` for unknown keys** and **checking file-system timestamps** for recent tampering.

> 🔴 An `authorized_keys` line the user didn't add = a backdoor. Its **mtime/ctime** often betrays exactly when it was planted, and `known_hosts` reveals where the host has SSH'd **out** to (lateral movement). Also confirm whether **Remote Login (sshd)** is even supposed to be enabled.

## Contents
- [Quick Triage](#quick-triage)
- [How the Persistence Works](#how-the-persistence-works)
- [Key Files](#key-files)
- [Reviewing authorized_keys](#reviewing-authorized_keys)
- [Timestamps Tell the Story](#timestamps-tell-the-story)
- [sshd Configuration](#sshd-configuration)
- [Is Remote Login Enabled](#is-remote-login-enabled)
- [Logs](#logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Every user's authorized_keys + key files with timestamps
sudo sh -c 'for u in /Users/* /var/root; do echo "== $u =="; ls -le "$u/.ssh/" 2>/dev/null; cat "$u/.ssh/authorized_keys" 2>/dev/null; done'

# Fingerprint the authorized keys (identify them)
ssh-keygen -lf ~/.ssh/authorized_keys 2>/dev/null

# When was authorized_keys last changed?
stat -f 'authorized_keys  ctime=%Sc  mtime=%Sm  birth=%SB' ~/.ssh/authorized_keys 2>/dev/null

# Is SSH even supposed to be on?
sudo systemsetup -getremotelogin
```

---

## How the Persistence Works

The attacker (with some access) does the classic three steps:

```bash
# 1) Create a key pair (attacker side)
ssh-keygen -t ed25519 -f ./demo_key

# 2) Append the PUBLIC key to the target user's authorized_keys
cat demo_key.pub >> ~/.ssh/authorized_keys

# 3) Log in with no password, using the private key
ssh -i demo_key user@target
```

🔴 From then on the attacker logs in **without a password** whenever sshd is reachable — and changing the user's password does **nothing** to stop it.

---

## Key Files

| Path | Holds |
|---|---|
| 🔴 `~/.ssh/authorized_keys` | **Public keys allowed to log in as this user** (the backdoor lives here) |
| `~/.ssh/id_*` / `id_*.pub` | The user's own private/public keys |
| `~/.ssh/known_hosts` | Hosts this account has SSH'd **out** to (lateral movement) |
| `~/.ssh/config` | Per-user SSH client config (shortcuts to targets) |
| `/etc/ssh/sshd_config` | Server policy (root login, password auth, key file location) |
| `/etc/ssh/ssh_host_*` | Host keys |

---

## Reviewing authorized_keys

```bash
# Show keys with their comments (often user@host of the creator)
cat ~/.ssh/authorized_keys

# Fingerprint + type each entry
ssh-keygen -lf ~/.ssh/authorized_keys

# Sweep all users (root needed)
sudo sh -c 'for f in /Users/*/.ssh/authorized_keys /var/root/.ssh/authorized_keys; do echo "== $f =="; cat "$f" 2>/dev/null; done'
```

🔴 Investigate any key whose **comment** is an unfamiliar `user@host`, that the user doesn't recognize, or that appears on accounts (like **root** or a service account) that shouldn't have remote keys. Watch for **`command=`/`no-pty` forced-command** entries too.

---

## Timestamps Tell the Story

```bash
# MACB on the .ssh dir and authorized_keys
stat -f 'Birth=%SB  Mod(mtime)=%Sm  Change(ctime)=%Sc  %N' ~/.ssh ~/.ssh/authorized_keys

ls -le ~/.ssh/
```

🔴 If `authorized_keys` **mtime/ctime** is recent — or much newer than the account and its other dotfiles — it was likely **modified to plant a key**. Correlate with **FSEvents** (write to the path), **Unified Logs** (`sshd` Accepted publickey), and the **`.ssh` dir** birth time.

---

## sshd Configuration

```bash
# Key server-policy lines
sudo grep -Ei 'PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AuthorizedKeysFile|AllowUsers|AllowGroups' /etc/ssh/sshd_config

# Drop-in overrides (modern macOS)
sudo cat /etc/ssh/sshd_config.d/* 2>/dev/null
```

🔴 Tampering signs: `PermitRootLogin yes`, `PasswordAuthentication no` (forcing key-only after planting a key), or a **non-default `AuthorizedKeysFile`** pointing somewhere the attacker controls.

---

## Is Remote Login Enabled

```bash
# Remote Login (sshd) on/off
sudo systemsetup -getremotelogin

# Is the sshd job loaded?
sudo launchctl list | grep -i ssh
```

🔴 SSH **enabled when it shouldn't be** (especially right before keys appear) is itself a finding — the attacker turned on the door they planted a key for.

---

## Logs

```bash
# Successful key-based logins (+ source IP) — cross-ref Advanced Authentication note
log show --predicate 'process == "sshd" AND eventMessage CONTAINS "Accepted"' --info --last 7d

# Any sshd activity
log show --predicate 'process == "sshd"' --info --last 7d
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `authorized_keys` key the user doesn't recognize | Backdoor public key planted |
| Key comment = unfamiliar `user@host` | Attacker's key origin |
| `authorized_keys` mtime/ctime **recent** vs account age | Recently planted (timeline) |
| `root` or a service account has `authorized_keys` | High-value backdoor |
| Forced-command / `no-pty` key entry | Scripted backdoor access |
| `PermitRootLogin yes` / non-default `AuthorizedKeysFile` | sshd policy tampered |
| Remote Login enabled unexpectedly | Door opened for the planted key |
| `SSH Accepted publickey` from an unknown IP | The backdoor in use (Advanced Auth) |

---

## Resources

- `man sshd` · `man ssh-keygen` · `man authorized_keys`
