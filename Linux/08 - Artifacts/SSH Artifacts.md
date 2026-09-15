# SSH Artifacts

SSH is the primary remote-access path on Linux, which makes the `~/.ssh` directory and the server config a concentrated source of persistence, lateral-movement, and credential evidence. An attacker who lands on a box drops a key in `authorized_keys` for durable access; the `known_hosts` file maps out where that account has connected, giving you the lateral-movement trail; and private keys sitting on disk are credentials to steal and reuse. This note walks each file and what it tells you.

> 🔴 `authorized_keys` is the quiet backdoor to check first — a single added public key grants passwordless login that survives password resets and reboots, and it's trivial to overlook. Enumerate it for *every* user (including service accounts and root), note each key's age, and flag any key in an account that shouldn't have SSH access at all.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Per-User .ssh Directory](#per-user-ssh-directory)
- [authorized_keys](#authorized_keys)
- [known_hosts as a Movement Map](#known_hosts-as-a-movement-map)
- [Private Keys](#private-keys)
- [Agent and Control Sockets](#agent-and-control-sockets)
- [Server Config](#server-config)
- [Client Config](#client-config)
- [Host Keys](#host-keys)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Every authorized_keys on the box (persistence)
find / -name authorized_keys -exec ls -la {} \; -exec cat {} \; 2>/dev/null

# Private keys anywhere (theft / staged for lateral movement)
find / -type f \( -name "id_*" ! -name "*.pub" -o -name "*.pem" \) -ls 2>/dev/null

# sshd effective config, comments stripped
sshd -T 2>/dev/null | grep -Ei "permitrootlogin|passwordauthentication|authorizedkeysfile|forcecommand|permitemptypasswords"

# Recently modified SSH files
find /home /root /etc/ssh -path "*/.ssh/*" -o -path "/etc/ssh/*" -type f -mtime -30 -ls 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Backdoor key added anywhere? | `find / -name authorized_keys* -exec cat {} \;`; fingerprint each |
| A key with a stealth **option** backdoor? | `grep -E 'command=\|environment=\|from=' */authorized_keys*` |
| Which key was used at login? | match `authorized_keys` fingerprint to `auth.log` `SHA256:` |
| SSH usable with **no key/passphrase**? | agent sockets (`/tmp/ssh-*/agent.*`) + ControlMaster sockets |
| Credentials to steal / already staged? | `find / -name 'id_*' ! -name '*.pub' -o -name '*.pem'` |
| Where did this account pivot to? | `~/.ssh/known_hosts` (+ `ssh-keygen -F`), client `config` |
| sshd weakened / backdoored? | `sshd -T`; `sshd_config.d/*` drop-ins |
| Client-config code execution? | `ProxyCommand`/`LocalCommand` in `~/.ssh/config` |
| Login-triggered script / env injection? | `~/.ssh/rc`, `/etc/ssh/sshrc`, `~/.ssh/environment` |

## Per-User .ssh Directory

Each file in `~/.ssh` answers a different investigative question — who can get in as this user, where this user has been, and what credentials are lying around.

| File | Meaning | DFIR value |
|------|---------|------------|
| `authorized_keys` | Public keys allowed to log in as this user | 🔴 Persistence / backdoor access |
| `authorized_keys2` | Legacy variant (still honored) | 🔴 Overlooked backdoor spot |
| `known_hosts` | Hosts this user has SSH'd **to** | Lateral-movement map |
| `id_rsa` / `id_ed25519` / `id_ecdsa` | Private keys | 🔴 Credentials to steal/reuse |
| `*.pub` | Public keys | Match to authorized_keys elsewhere |
| `config` | Client config (Host aliases, ProxyJump, IdentityFile) | Intended destinations, bastion paths |

```bash
# Enumerate every user's .ssh
for h in /root /home/*; do echo "== $h =="; ls -la "$h/.ssh" 2>/dev/null; done
```

## authorized_keys

```bash
# Dump all authorized_keys with owning path + timestamps
find / -name "authorized_keys*" -exec sh -c 'echo "== $1 =="; ls -l "$1"; cat "$1"' _ {} \; 2>/dev/null
```

🔴 What to check per key entry:
- A key **added near the incident time** — compare the file mtime, and if logs/`HISTTIMEFORMAT` exist, when it was written.
- A `command="..."` **forced-command prefix** that runs a payload on every login regardless of what the user requested.
- Options like `no-pty`/`permitopen`, or a key comment that matches no legitimate user or host.
- `authorized_keys` present in a **service account's** home (`www-data`, `postgres`, `nobody`) — those accounts rarely need SSH keys, so one there is high-signal.
- `AuthorizedKeysFile` redirected in `sshd_config` to an attacker-writable path (see Server Config) — a subtler variant where the backdoor key lives outside `~/.ssh` entirely.

## known_hosts as a Movement Map

`known_hosts` records every host the account has SSH'd *to*, making it a map of outbound connections — invaluable for tracing lateral movement away from a compromised host.

```bash
# Read (may be hashed)
cat ~/.ssh/known_hosts

# If HashKnownHosts is on, test a candidate host against the hashes
ssh-keygen -F 10.0.0.5 -f ~/.ssh/known_hosts

# List all host keys (hashed entries still enumerate)
ssh-keygen -H -f ~/.ssh/known_hosts 2>/dev/null
```

🔴 Unexpected internal IPs or hostnames in a compromised account's `known_hosts` are the next hops the attacker reached. Modern SSH hashes these entries (`HashKnownHosts`), so you can't read them directly — use `ssh-keygen -F <candidate>` to test whether a specific host you suspect is present. Then pull those target hosts' auth logs for a matching `Accepted` from this box.

## Private Keys

```bash
# Find private keys across the system
find / -type f \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" -o -name "*.pem" -o -name "*.key" \) -ls 2>/dev/null

# Is a key passphrase-protected? (unencrypted = immediately usable if stolen)
head -3 /path/id_rsa    # "Proc-Type: 4,ENCRYPTED" or an OpenSSH header
```

🔴 An **unencrypted** private key, or any private key sitting in `/tmp`, `/dev/shm`, or a web root, is either staged for theft or already exfiltrated. Keys copied into unusual locations near the incident are a strong lateral-movement signal — the attacker is gathering credentials to pivot to the hosts in `known_hosts`.

## Agent and Control Sockets

🔴 The live-only SSH surface that `authorized_keys` analysis misses: an attacker with access can use SSH **without any key or passphrase** by hijacking a running **ssh-agent** (which holds decrypted keys) or piggybacking on an existing **ControlMaster** multiplexed session. Both are sockets in `/tmp`/`/run`, gone on reboot — check them on the live host.

```bash
# ssh-agent sockets — decrypted keys usable by whoever can reach the socket
find /tmp /run -type s -name 'agent.*' 2>/dev/null

ls -la /tmp/ssh-*/ 2>/dev/null

# List keys loaded in an agent (point SSH_AUTH_SOCK at the socket)
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNN ssh-add -l 2>/dev/null

# ControlMaster sockets — reuse a live authenticated session with NO creds
find /root /home -path '*/.ssh/*' -type s 2>/dev/null

grep -REn 'ControlMaster|ControlPath|ControlPersist' /root/.ssh/config /home/*/.ssh/config /etc/ssh/ssh_config* 2>/dev/null

# Who has SSH_AUTH_SOCK set (agent forwarding in play)
for p in /proc/[0-9]*; do tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -q SSH_AUTH_SOCK && echo "$p"; done
```

🔴 **Agent forwarding (`ForwardAgent yes`)** compounds this: a user who forwards their agent to a compromised host lets the attacker on that host use their keys to pivot onward. A ControlMaster socket lets `ssh -O check`/a new session ride the existing authenticated channel outright.

## Server Config

The sshd config governs who can log in and how, and several directives are direct backdoor or weakening opportunities. `sshd -T` is the best source because it resolves includes and defaults into the *effective* config.

```bash
# Effective config (resolves includes + defaults) - best source of truth
sshd -T 2>/dev/null

# Raw config, comments/blanks removed
grep -vE '^\s*(#|$)' /etc/ssh/sshd_config

# Drop-in config fragments
ls -l /etc/ssh/sshd_config.d/ 2>/dev/null; cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

| Directive | Attacker interest |
|-----------|-------------------|
| `PermitRootLogin yes` | 🔴 Direct root SSH |
| `PasswordAuthentication yes` | Brute-force surface |
| `PermitEmptyPasswords yes` | 🔴 Login with no password |
| `AuthorizedKeysFile <path>` | 🔴 Redirected to an attacker-writable file |
| `ForceCommand` | Runs a command on every login (can be a backdoor) |
| `Match` blocks | Per-user/host overrides — read them all |
| `AllowUsers`/`AllowGroups` | Who can log in |

🔴 Don't skip the `sshd_config.d/` drop-in directory — a small fragment there can re-enable root login or redirect `AuthorizedKeysFile` without touching the main config file. Also flag `PermitUserEnvironment yes` (lets `~/.ssh/environment` inject env like `LD_PRELOAD` at login) and `PermitTunnel`/`AllowTcpForwarding` (tunneling/pivot surface).

## Client Config

The client `~/.ssh/config` is an execution surface, not just aliases — `ProxyCommand` and `LocalCommand` run arbitrary shell on connect.

```bash
# Client configs (per-user + system)
grep -REn 'ProxyCommand|LocalCommand|PermitLocalCommand|ProxyJump|IdentityFile|ForwardAgent' \
  /root/.ssh/config /home/*/.ssh/config /etc/ssh/ssh_config /etc/ssh/ssh_config.d/ 2>/dev/null
```

🔴 A `ProxyCommand`/`LocalCommand` pointing at `/tmp/x` or a script is a backdoor that fires whenever the user SSHes to a matching `Host`. `ProxyJump`/`ProxyCommand` also reveal the bastion path the account uses to reach segmented networks.

## Host Keys

```bash
# Server's own host keys + fingerprints
ls -l /etc/ssh/ssh_host_*

for k in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$k"; done
```

A change in the server's host keys can indicate re-imaging or a spoofing attempt; recording the fingerprints preserves that state for the record. A trojaned `sshd` binary itself (one that captures passwords) is caught by the package-integrity check in the Package Managers note.

## Deep Threat Hunts

Beyond "was a key added" — the full backdoor + credential + no-creds-access sweep. *(seasoned-DFIR)*

```bash
# 1. Every authorized_keys, fingerprinted (match against found private keys + auth.log)
find / -name 'authorized_keys*' 2>/dev/null | while read f; do
  echo "== $f =="; ls -l "$f"; ssh-keygen -lf "$f" 2>/dev/null; done

# 2. Stealth key OPTIONS: forced command, env injection, source bypass
grep -REn 'command=|environment=|permitopen=|from=' /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys* 2>/dev/null

# 3. ssh-agent sockets — decrypted keys usable with no passphrase (hijack)
find /tmp /run -type s -name 'agent.*' 2>/dev/null

# 4. ControlMaster sockets — ride a live authenticated session, no creds
find /root /home -path '*/.ssh/*' -type s 2>/dev/null

# 5. Client-config code execution
grep -REn 'ProxyCommand|LocalCommand|PermitLocalCommand' /root/.ssh/config /home/*/.ssh/config 2>/dev/null

# 6. sshd backdoors incl. drop-ins + env/tunnel permits
sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|passwordauth|permitempty|authorizedkeysfile|forcecommand|permituserenv|permittunnel|allowtcpforwarding'

# 7. Login-triggered scripts + env injection files
ls -l /home/*/.ssh/rc /etc/ssh/sshrc /home/*/.ssh/environment 2>/dev/null

# 8. Match the login pubkey fingerprint (auth.log) to an authorized_keys entry
grep -Eo 'SHA256:[A-Za-z0-9+/]+' /var/log/auth.log* 2>/dev/null | sort -u
```

**Hunt ideas:**

- **Agent + ControlMaster sockets let an attacker use SSH with no key or passphrase** — check `/tmp` for both, not just `authorized_keys`.
- **Fingerprint every `authorized_keys` entry** and match it against the private keys you found *and* the `SHA256:` fingerprints in `auth.log` "Accepted publickey" lines — that ties a specific key to a specific login.
- **Key OPTIONS (`command=`, `environment=`, `from=`) are stealth backdoors** beyond "a key was added" — a `command="…"` runs a payload on every login.
- **`ProxyCommand`/`LocalCommand` in a client config runs arbitrary shell** — a backdoor hidden in `~/.ssh/config`.
- **`known_hosts` + private keys together** are the pivot *map* plus the *credentials* to walk it — pull the target hosts' logs.

## Getting Max Value

- **Enumerate `authorized_keys` for every account** (service accounts + root included), fingerprint each, and cross-match to private keys and `auth.log` key fingerprints.
- **Grab the live-only surface first** — agent and ControlMaster sockets vanish on reboot.
- **Read `sshd -T` (effective config), not just the file** — it resolves includes, defaults, and `sshd_config.d/` drop-ins.
- **`known_hosts` (even hashed) + client config map the outbound pivot** — then pull those target hosts' auth logs for a matching `Accepted` from this box.
- **Preserve `~/.ssh` mtimes** — a fresh `authorized_keys` dates the plant.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Which key was used at login | **Authentication and Login Records** (fingerprint match) |
| SSH persistence mechanism detail/ranking | **Persistence → SSH Keys** |
| Where the account pivoted to | the target hosts' logs; **Cross-Artifact Correlation** (00, lateral movement) |
| A trojaned `sshd` binary | **Package Managers and Integrity** (08), **ELF and Malware Triage** (11b) |
| `LD_PRELOAD` via `~/.ssh/environment` | **Persistence → Preload Hijacking**, **Shells** (04) |
| Live tunnels / port forwards | **Network and PCAP Forensics** (10c), **Live Response** (10) |

## Scenarios

- **Backdoor key:** an `authorized_keys` entry added to a service account (`www-data`) that has no business having one.
- **Agent hijack:** the attacker uses a live `ssh-agent`'s loaded keys without ever knowing the passphrase.
- **Session piggyback:** a ControlMaster socket reused to run commands over an already-authenticated channel.
- **Config backdoor:** `AuthorizedKeysFile` redirected, a `ForceCommand`, or a `ProxyCommand` running a dropped script.
- **Credential theft + pivot:** an unencrypted private key plus a `known_hosts` map = the keys and the route to move laterally.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| authorized_keys added near incident / in a service account | SSH persistence backdoor |
| `command="..."` forced command on a key | Payload on login |
| `AuthorizedKeysFile` redirected to a writable path | Backdoor via config |
| `PermitRootLogin yes` / `PermitEmptyPasswords yes` | Weakened access controls |
| Unencrypted private key, or key in `/tmp`/web root | Staged/stolen credential |
| Unexpected internal hosts in `known_hosts` | Lateral-movement trail |
| `.ssh` files with `+i` immutable bit | Armored persistence |
| ssh-agent socket in `/tmp` with loaded keys | Passphrase-free key use (agent hijack) |
| ControlMaster socket present | Session piggyback (no-creds SSH) |
| `command=`/`environment=` option on a key | Stealth key backdoor / env injection |
| `ProxyCommand`/`LocalCommand` in client config | Arbitrary command on connect |
| `PermitUserEnvironment yes` + `~/.ssh/environment` | LD_PRELOAD-style login injection |

## Resources

- `sshd_config(5)`, `ssh_config(5)`, `ssh-keygen(1)`, `ssh-agent(1)`, `ssh(1)` (ControlMaster) man pages — https://www.openssh.com
- MITRE ATT&CK: T1098.004 (SSH Authorized Keys), T1563.001 (SSH Hijacking), T1552.004 (Private Keys), T1021.004 (SSH), T1563 (Remote Service Session Hijacking)
