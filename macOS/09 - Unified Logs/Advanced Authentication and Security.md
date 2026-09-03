# Unified Logs – Advanced Authentication and Security

Continuation of *Authentication and Security* — the **four daemons** that record the deeper authentication and security plumbing: **`authd`** (Authorization Services), **`opendirectoryd`** (the actual credential check, local & directory), **`sshd`** (remote login), and **`securityd`** (keychain / credentials / trust). Together they give visibility into **local and remote** auth that `loginwindow`/`sudo` alone don't.

> 🔴 `opendirectoryd` is where the real **password verification** happens (DSLocal and AD/LDAP) — the highest-fidelity source for auth success/failure. `sshd` is the front line for **remote brute force and lateral movement**. Collect both early.

## Contents
- [Quick Triage](#quick-triage)
- [The Four Daemons](#the-four-daemons)
- [authd Authorization Services](#authd-authorization-services)
- [opendirectoryd Credential Checks](#opendirectoryd-credential-checks)
- [sshd Remote Authentication](#sshd-remote-authentication)
- [securityd Keychain and Trust](#securityd-keychain-and-trust)
- [Correlating Local and Remote Auth](#correlating-local-and-remote-auth)
- [Live Streaming](#live-streaming)
- [Preserving the Logs](#preserving-the-logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
log show --predicate 'process == "sshd" AND eventMessage CONTAINS "Failed"' --last 24h | grep -ci failed

log show --predicate 'process == "sshd" AND eventMessage CONTAINS "Accepted"' --info --last 7d

log show --predicate 'subsystem == "com.apple.opendirectoryd" AND eventMessage CONTAINS[c] "fail"' --info --last 7d

cat /Users/*/.ssh/authorized_keys 2>/dev/null                       # planted persistence keys

log show --predicate 'process == "securityd" AND eventMessage CONTAINS[c] "keychain"' --info --last 7d
```

---

## The Four Daemons

| Daemon | Role | Query handle |
|---|---|---|
| `authd` | Authorization Services — grants/denies privileged **rights** (the `/System/Library/Security` policy DB) | `process == "authd"` |
| `opendirectoryd` | Directory services — **verifies passwords**, resolves users/groups (DSLocal, AD/LDAP) | `subsystem == "com.apple.opendirectoryd"` |
| `sshd` | OpenSSH server — **remote** interactive/key auth | `process == "sshd"` |
| `securityd` | Keychain, credential & **trust/certificate** evaluation | `process == "securityd"` |

> Many fields are `<private>` (usernames, IPs). On a live box, `sudo log config --mode "private_data:on"` reveals them (document the change). For dead-box, correlate with DSLocal, `last`, and `~/.ssh/authorized_keys`.

---

## authd Authorization Services

`authd` evaluates **authorization rights** (e.g. `system.privilege.admin`, installer/`SMJobBless` rights) — used by GUI privilege prompts ("enter your password to allow…"), installers, and helper-tool installs.

```bash
# authd entries (last hour)
log show --predicate 'process == "authd"' --last 1h

# Custom time window (example: 2025-01-01 10:00–11:00)
log show --predicate 'process == "authd"' --start '2025-01-01 10:00:00' --end '2025-01-01 11:00:00'
```

🔴 Watch for grants of powerful rights (`system.privilege.admin`, `com.apple.*`), privileged-helper installs (`SMJobBless`), and repeated right-denials (probing). The authorization policy DB itself: `/var/db/auth.db` and `/System/Library/Security/authorization.plist` (cross-ref Users and Groups).

---

## opendirectoryd Credential Checks

The **password check** for local (DSLocal) and network (AD/LDAP) accounts runs here — the authoritative auth success/failure record.

```bash
# opendirectoryd activity (last hour)
log show --predicate 'subsystem == "com.apple.opendirectoryd"' --last 1h

# Auth failures specifically (password guessing against accounts)
log show --predicate 'subsystem == "com.apple.opendirectoryd" AND eventMessage CONTAINS[c] "fail"' --info --last 7d

# Count failures over a window (brute-force triage)
log show --predicate 'subsystem == "com.apple.opendirectoryd" AND eventMessage CONTAINS[c] "fail"' --last 24h | grep -ci fail
```

| Signal | Meaning |
|---|---|
| 🔴 Bursts of auth **failures** then a success | Local/AD password brute force succeeded |
| Auth against **hidden / UID<500 / newly created** accounts | Backdoor account use (cross-ref Users and Groups) |
| AD/LDAP node activity on a box that **shouldn't be domain-joined** | Rogue directory binding |
| Record lookups for accounts that don't exist | Enumeration |

### OpenDirectory auth result names (recognition aids)

These `eDSAuth*` constants come from the OpenDirectory framework and can appear in `opendirectoryd` failure lines. The highest-value distinction is **bad password (real user)** vs **unknown user** — it separates brute force against a valid account from spray against accounts that don't exist.

| Result name (if present) | Meaning | DFIR signal |
|---|---|---|
| `eDSAuthBadPassword` / `eDSAuthFailed` | Wrong password for a **real** account | 🔴 Brute force / guessing vs a valid user |
| `eDSAuthUnknownUser` / `eDSRecordNotFound` | Username **does not exist** | Enumeration / password spray |
| `eDSAuthAccountDisabled` / `eDSAuthAccountInactive` | Account disabled or inactive | Attempts against a dormant account |
| `eDSAuthAccountExpired` / `eDSAuthPasswordExpired` | Account or password expired | Stale credentials being reused |
| `eDSAuthNewPasswordRequired` | Must set a new password | First-use / forced-reset state |

> ⚠️ **Caveat:** these are framework constants, **not** stable numeric log codes. They surface **inconsistently** and vary by macOS version — `opendirectoryd` often logs a plain-text reason instead. Treat them as names to *recognize if present*, not a guaranteed lookup. (macOS has no documented Windows-style numeric login-failure codes.)

---

## sshd Remote Authentication

Front line for **remote access** — external brute force and **lateral movement**. (Network/tunnel details live in the network sections; here = the auth events.)

```bash
# sshd entries (last hour)
log show --predicate 'process == "sshd"' --last 1h

# Anything mentioning "ssh" (broad, last hour)
log show --predicate 'eventMessage CONTAINS[c] "ssh"' --last 1h --info

# Accepted / failed SSH logins (demo predicate)
log show --predicate 'processImagePath CONTAINS[c] "sshd" && (eventMessage CONTAINS[c] "accepted" || eventMessage CONTAINS[c] "error")' --last 1h --info

# Accepted vs failed broken out (+ source IP, method, user in the message)
log show --predicate 'process == "sshd" AND eventMessage CONTAINS "Accepted"' --info --last 7d

log show --predicate 'process == "sshd" AND eventMessage CONTAINS "Failed"' --info --last 7d

# Brute-force count
log show --predicate 'process == "sshd" AND eventMessage CONTAINS "Failed"' --last 24h | grep -ci failed
```

| Signal | Meaning |
|---|---|
| 🔴 `Accepted password/publickey for <user> from <IP>` | Successful remote login — is the source IP expected? |
| 🔴 Many `Failed password … from <IP>` then an `Accepted` | Successful brute force |
| 🔴 `Accepted publickey` for a user with no expected key | Planted `~/.ssh/authorized_keys` (persistence) |
| Remote logins to admin/hidden accounts | Lateral movement / backdoor use |
| `Invalid user <name> from <IP>` floods | Username enumeration / spray |

SSH on-disk artifacts to pull alongside the logs (survive log rollover):

```bash
# Planted persistence keys (per user) + who the host has connected TO
for u in /Users/*; do echo "== $u =="; cat "$u/.ssh/authorized_keys" 2>/dev/null; done

cat /Users/*/.ssh/known_hosts 2>/dev/null          # hosts this Mac SSH'd out to (lateral movement)

ls -la /Users/*/.ssh/ /var/root/.ssh/ 2>/dev/null  # key files + mtimes

sudo grep -Ei 'PermitRootLogin|PasswordAuthentication|AllowUsers' /etc/ssh/sshd_config

# Is Remote Login (SSH) even enabled?
sudo systemsetup -getremotelogin
```

> 🔴 An `authorized_keys` entry the user didn't add = backdoor persistence; `known_hosts` reveals outbound SSH targets (pivoting). Correlate accepted logins with `last`.

---

## securityd Keychain and Trust

`securityd` brokers **keychain** access, credential storage, and **certificate/trust** evaluation.

```bash
# securityd entries (last hour)
log show --predicate 'process == "securityd"' --last 1h

# Keychain unlock / access + trust evaluations (deeper)
log show --predicate 'process == "securityd" AND (eventMessage CONTAINS[c] "keychain" OR eventMessage CONTAINS[c] "trust" OR eventMessage CONTAINS[c] "unlock")' --info --last 7d
```

🔴 Watch for: unexpected **keychain unlocks** (credential theft tooling reads the login keychain), trust-evaluation **failures/overrides** (rogue or expired certs accepted), and bursts of keychain access from an unusual process (cross-ref Users and Groups → Keychain).

---

## Correlating Local and Remote Auth

Build one timeline across daemons to separate **remote** from **at-keyboard** activity:

| Source | Tells you |
|---|---|
| `sshd` Accepted/Failed | Remote login + source IP + method |
| `opendirectoryd` | Whether the password actually verified (any path) |
| `authd` | Whether a privileged **right** was then granted |
| `securityd` | Whether the keychain was unlocked / creds touched |
| `last` / `loginwindow` | Console vs remote session, session times |

> 🔴 Classic intrusion chain: `sshd Accepted from <ext IP>` → `opendirectoryd` success → `sudo`/`authd` right grant → `securityd` keychain unlock. Seeing that sequence = remote compromise escalating locally.

---

## Live Streaming

```bash
# Watch all four daemons live (resource-intensive)
log stream --predicate 'process == "sshd" OR process == "authd" OR process == "securityd" OR subsystem == "com.apple.opendirectoryd"' --info
```

---

## Preserving the Logs

```bash
# Snapshot the four daemons to a file
log show --predicate 'process == "sshd" OR process == "authd" OR process == "securityd" OR subsystem == "com.apple.opendirectoryd"' --info --last 7d > advanced_auth_7d.txt

# Full store for evidence
sudo log collect --output /evidence/host.logarchive

log show --archive /evidence/host.logarchive --predicate 'process == "sshd"' --info
```

> Pair with on-disk corroboration that survives log rollover: `~/.ssh/authorized_keys` & `known_hosts`, DSLocal account store, `last`, and the login keychain.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| SSH `Accepted` from an **unfamiliar external IP** | Remote intrusion / lateral movement |
| `Failed password` flood then `Accepted` (sshd or opendirectoryd) | Successful brute force |
| `Accepted publickey` for a user with no expected key | Planted `authorized_keys` persistence |
| `Invalid user … from <IP>` floods | Enumeration / password spray |
| `opendirectoryd` auth success for hidden/UID<500/new account | Backdoor account in use |
| AD/LDAP node activity on a non-domain box | Rogue directory binding |
| `authd` granting `system.privilege.admin` / `SMJobBless` unexpectedly | Privileged-helper / escalation abuse |
| `securityd` unexpected **keychain unlocks** | Credential-theft tooling reading the keychain |
| `securityd` trust **override** / bad cert accepted | MITM / rogue certificate |
| Full chain sshd→opendirectoryd→authd/sudo→securityd | Remote compromise escalating locally |

---

## Resources

- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
- The Eclectic Light Company – Consolation / Ulbow / log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
