# PAM Backdoors

PAM (Pluggable Authentication Modules) is the framework every login, `sudo`, SSH, and `su` authenticates through, which makes it a devastating persistence target: a backdoored PAM module can accept a **magic password** for any account, log every real password to a file, or run a script on each login — and it **survives password changes** because it *is* the thing that checks passwords. It's an advanced, stealthy vector, and detection is about spotting non-standard modules referenced in the stacks and verifying the core modules against their package.

> 🔴 Two signatures give PAM backdoors away: a `pam_*.so` **name that isn't a standard module** referenced in `/etc/pam.d/*`, and a **`pam_unix.so` that fails package verification** (patched to accept a hardcoded password — a "skeleton key"). A `pam_exec.so` line running a script during auth is a third. Because PAM backdoors defeat password resets, finding one changes the whole remediation plan.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [How the Persistence Works](#how-the-persistence-works)
- [The PAM Stack](#the-pam-stack)
- [The One-Line pam_permit Backdoor](#the-one-line-pam_permit-backdoor)
- [Hunting Rogue Modules](#hunting-rogue-modules)
- [Verifying Core Modules](#verifying-core-modules)
- [pam_exec Script Execution](#pam_exec-script-execution)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Non-standard modules referenced in the PAM stacks
grep -rEH "pam_" /etc/pam.d/ | grep -Ev "pam_(unix|deny|permit|env|limits|systemd|securetty|nologin|faillock|pwquality|cracklib|sss|krb5|winbind|mkhomedir|loginuid|lastlog|motd|mail|keyinit|namespace|selinux|umask|tty_audit|access|group|time|listfile|rootok|wheel|xauth|gnome_keyring|ecryptfs|exec)\.so"

# pam_exec.so running a script (data theft / trigger)
grep -rEH "pam_exec" /etc/pam.d/

# Verify the core auth module against its package (skeleton-key check)
rpm -Vf /usr/lib64/security/pam_unix.so 2>/dev/null; debsums -c 2>/dev/null | grep -i pam

# All PAM modules on disk, with timestamps (recent mtime = suspect)
ls -la /lib*/security/pam_*.so /usr/lib*/security/pam_*.so 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Simplest backdoor (any password works)? | `grep -rn 'sufficient.*pam_permit' /etc/pam.d/` |
| Non-standard module referenced? | exclude-list grep of `/etc/pam.d/*` |
| Dropped `.so` in the security dir? | package-map every `pam_*.so` |
| Skeleton-key (patched `pam_unix`)? | `rpm -Vf`/`debsums`; hash vs clean package |
| Module pulls in extra libs (exfil)? | `ldd pam_unix.so` (libcurl/libpcap) |
| Password-harvesting script? | `grep pam_exec /etc/pam.d/` + read the script |
| Targeted (sshd only)? | `cat /etc/pam.d/sshd` |
| When was it planted? | module + `/etc/pam.d/*` mtime |

## How the Persistence Works

The attacker either drops a malicious module and references it in a PAM stack, or replaces a legitimate module (usually `pam_unix.so`) with a patched version. The patched `pam_unix.so` typically adds a hardcoded "magic" password that authenticates *any* account, while still passing real credentials through so nothing looks broken.

```
# In /etc/pam.d/sshd or /etc/pam.d/common-auth, an added line like:
auth  sufficient  pam_exec.so  /usr/local/bin/harvest.sh     # runs a script every auth
# or a replaced pam_unix.so on disk that accepts a magic password
```

🔴 The magic-password variant is the nastiest: the attacker logs into **any** account with one password, real users keep logging in normally, and a password reset changes nothing because the backdoor is in the authentication code itself. The script variant (`pam_exec`) commonly logs every plaintext password to a file.

## The PAM Stack

PAM config lives in `/etc/pam.d/`, one file per service, each listing modules by *type* (`auth`, `account`, `password`, `session`) and *control* (`required`, `sufficient`, etc.). Modules are `.so` files in the security directory.

```bash
# Per-service stacks
ls -l /etc/pam.d/

# The common auth chains that most services include
cat /etc/pam.d/common-auth /etc/pam.d/common-session   # Debian

cat /etc/pam.d/system-auth /etc/pam.d/password-auth     # RHEL

# Where the modules live
ls -l /lib/x86_64-linux-gnu/security/ /lib64/security/ /usr/lib*/security/ 2>/dev/null
```

## The One-Line pam_permit Backdoor

🔴 The simplest and most common PAM backdoor isn't a patched binary at all — it's a **single added line**. `pam_permit.so` always returns success, so an `auth sufficient pam_permit.so` inserted near the top of a stack makes **any password authenticate** the account. No file replacement, no dropped module — just one config line.

```bash
# pam_permit / pam_succeed_if used as sufficient in an AUTH stack (any password works)
grep -rEn 'auth\s+(sufficient|\[success=)[^#]*pam_(permit|succeed_if)' /etc/pam.d/ 2>/dev/null

# The whole auth stack of the highest-value services, read top to bottom
cat /etc/pam.d/sshd /etc/pam.d/common-auth /etc/pam.d/system-auth 2>/dev/null
```

`pam_permit.so` legitimately appears in a few places (e.g. `other`), but in the **auth** type of `sshd`/`common-auth`/`system-auth` as `sufficient` it's a skeleton key.

## Hunting Rogue Modules

```bash
# List every module referenced across all stacks, sorted unique
grep -rhoE "pam_[a-z_]+\.so" /etc/pam.d/ | sort -u

# Flag references that aren't standard module names (see the quick-triage exclude list)
grep -rEH "pam_" /etc/pam.d/ | grep -Ev "pam_(unix|deny|permit|env|limits|systemd|securetty|nologin|faillock|pwquality|cracklib|sss|krb5|winbind|mkhomedir|loginuid|lastlog|motd|mail|keyinit|namespace|selinux|umask|tty_audit|access|group|time|listfile|rootok|wheel|xauth|gnome_keyring|ecryptfs|exec)\.so"

# Modules on disk NOT owned by a package (dropped modules)
for m in /lib*/security/pam_*.so /usr/lib*/security/pam_*.so; do
  dpkg -S "$m" >/dev/null 2>&1 || rpm -qf "$m" >/dev/null 2>&1 || echo "UNOWNED MODULE: $m"
done
```

🔴 A referenced module name you don't recognize, or a `.so` in the security directory that no package owns, is a planted PAM module. Also flag `pam_python.so` in a stack where it isn't expected — it lets an attacker run arbitrary Python in the auth path.

## Verifying Core Modules

The skeleton-key attack replaces a legitimate module, so integrity verification is the direct detection:

```bash
# RHEL: verify the PAM modules against the package DB
rpm -Vf /usr/lib64/security/pam_unix.so
rpm -V pam

# Debian: checksum the modules against the package md5sums
debsums -c 2>/dev/null | grep -i pam

# Compare module mtime to the package install time (recent = suspect)
ls -la --time-style=full-iso /lib*/security/pam_unix.so /usr/lib*/security/pam_unix.so 2>/dev/null

# Strings in pam_unix.so - a hardcoded backdoor password may be visible
strings /lib*/security/pam_unix.so 2>/dev/null | grep -iE "backdoor|magic" 
```

🔴 A `pam_unix.so` (or any core PAM module) that **fails `rpm -V`/`debsums`** was modified — on a module that authenticates every login, that's almost certainly a skeleton-key backdoor. A recent mtime on the module, out of step with the package install, is the same signal.

## pam_exec Script Execution

`pam_exec.so` legitimately exists but is a favorite backdoor primitive because it runs an arbitrary program during authentication.

```bash
# Every pam_exec reference + the script it runs
grep -rEH "pam_exec" /etc/pam.d/

# Inspect the referenced scripts
for s in $(grep -rhoE "pam_exec\.so[^\n]*/[^ ]+" /etc/pam.d/ | grep -oE "/[^ ]+$"); do echo "== $s =="; cat "$s" 2>/dev/null; done
```

🔴 A `pam_exec.so` line pointing at a script in `/usr/local/bin`, `/tmp`, or a home directory typically **harvests the plaintext password** (PAM passes it to the script via stdin/env) or triggers a payload on each login. Read the referenced script.

## Deep Threat Hunts

Simple-first, then skeleton-key. *(seasoned-DFIR)*

```bash
# 1. One-line backdoor: pam_permit sufficient in an auth stack (any password works)
grep -rEn 'auth\s+(sufficient|\[success=)[^#]*pam_(permit|succeed_if)' /etc/pam.d/ 2>/dev/null

# 2. Non-standard modules referenced across all stacks
grep -rEH 'pam_' /etc/pam.d/ | grep -Ev 'pam_(unix|deny|permit|env|limits|systemd|securetty|nologin|faillock|pwquality|cracklib|sss|krb5|winbind|mkhomedir|loginuid|lastlog|motd|mail|keyinit|namespace|selinux|umask|tty_audit|access|group|time|listfile|rootok|wheel|xauth|gnome_keyring|ecryptfs|exec|succeed_if|faildelay)\.so'

# 3. Modules on disk unowned by any package
for m in /lib*/security/pam_*.so /usr/lib*/security/pam_*.so; do
  [ -e "$m" ] || continue; dpkg -S "$m" >/dev/null 2>&1 || rpm -qf "$m" >/dev/null 2>&1 || echo "UNOWNED: $m"
done

# 4. Skeleton-key: verify core modules; if rpmdb suspect, HASH vs a clean same-version package
rpm -Vf /usr/lib64/security/pam_unix.so 2>/dev/null; debsums -c 2>/dev/null | grep -i pam

sha256sum /lib*/security/pam_unix.so /usr/lib*/security/pam_unix.so 2>/dev/null

# 5. Extra libraries linked into a PAM module (backdoor pulls in libcurl/libpcap to exfil)
for m in /lib*/security/pam_unix.so /usr/lib*/security/pam_*.so; do
  ldd "$m" 2>/dev/null | grep -Eqi 'curl|pcap|ssl|json' && echo "SUSPECT LIBS: $m"
done

# 6. pam_exec / pam_python running a script (password harvest)
grep -rEHn 'pam_exec|pam_python' /etc/pam.d/ 2>/dev/null

# 7. Recently modified PAM config or modules
find /etc/pam.d /lib*/security /usr/lib*/security -newermt '-30 days' -ls 2>/dev/null

# 8. Hardcoded magic password visible in the module
strings /lib*/security/pam_unix.so 2>/dev/null | grep -iE 'backdoor|magic|passw'
```

**Hunt ideas:**

- **Check the *simple* backdoor first** — `auth sufficient pam_permit.so` is one line and makes every password valid; grep the auth stacks before hunting patched binaries.
- **`rpm -V`/`debsums` can be fooled if the rpmdb was rebuilt** (→ Package Managers) — hash `pam_unix.so` against a clean same-version package to be certain.
- **A backdoored module links *extra* libraries** — `ldd` on `pam_unix.so` showing `libcurl`/`libpcap`/`libssl` that a stock module wouldn't pull in is a strong tell.
- **Attackers often backdoor only `/etc/pam.d/sshd`** (targeted, low-noise) — read that stack specifically.
- **`pam_exec`/`pam_python` in an auth stack** hands the plaintext password to a script — read the script; it's usually harvesting.

## Getting Max Value

- **Verify integrity, but don't trust `rpm -V` alone** if a rpmdb rebuild is possible — hash the module against a clean package.
- **Triage cheapest-first:** the one-line `pam_permit` backdoor, then dropped/non-standard modules, then the patched skeleton-key.
- **Read every `pam_exec`/`pam_python` script** — that's where the password harvesting lives.
- **A PAM backdoor rewrites remediation** — it defeats password resets, so the fix is rebuild/replace the modules *and* the config, not just rotate credentials.
- **Timeline the module + `/etc/pam.d/*` mtimes** for the plant time.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Was the core module trojaned / rpmdb rebuilt | **Package Managers and Integrity** (08) |
| Which account/IP used the magic password | **Authentication and Login Records** (a success with no prior failure) |
| The harvested-password file the script writes | **Temp and Staging** (08), the script's output path |
| When it was planted | **Timelining** (13), **Permissions** (02) |
| Full remediation (rebuild modules) | **Remediation and Containment** (14) |
| Reverse the malicious module | **ELF and Malware Triage** (11b) |

## Scenarios

- **Skeleton key:** a patched `pam_unix.so` accepts a hardcoded magic password for any account, while real logins still work.
- **One-line permit:** `auth sufficient pam_permit.so` added to `sshd`/`common-auth` — every password authenticates.
- **Password harvest:** `pam_exec.so` runs a script that logs every plaintext password to a file.
- **Targeted:** the backdoor lives only in `/etc/pam.d/sshd` to stay quiet.
- **Dropped module:** an unowned `pam_*.so` referenced in a stack.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| `pam_unix.so`/core module fails `rpm -V`/`debsums` | Skeleton-key backdoor (magic password) |
| Non-standard `pam_*.so` referenced in a stack | Planted PAM module |
| `.so` in the security dir owned by no package | Dropped module |
| `pam_exec.so` running a script | Password harvesting / login trigger |
| `pam_python.so` where unexpected | Arbitrary code in the auth path |
| PAM module mtime recent / out of step with package | Recently replaced |
| `auth sufficient pam_permit.so` in sshd/common-auth | One-line skeleton key |
| PAM module linking libcurl/libpcap (`ldd`) | Backdoor with exfil/sniff capability |

## Resources

- `pam.conf(5)`, `pam.d(5)`, `pam_exec(8)`, `pam_unix(8)`, `pam_permit(8)` man pages
- MITRE ATT&CK: T1556.003 (Modify Authentication Process: PAM), T1543 (Create/Modify System Process)
