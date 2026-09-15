# Hydra (THC-Hydra) — Overview

> 🔴 **Red Flag Principle:** Hydra is a raw, high-parallelism network login cracker — it opens many simultaneous authenticated-logon attempts against one service and moves on the instant a pair is accepted or the list is exhausted. The signature this leaves is **volume and velocity of authentication events against one account/service in a tight window**, not any single distinctive artifact — every credential attempt is a completely normal-looking logon to the target service, just repeated dozens-to-hundreds of times faster than a human could type. The one flag that most directly defeats velocity-based detection is `-c` (throttle every attempt across all threads, forcing `-t 1`); the one mode that most directly defeats per-account lockout-threshold detection is `-e`/`-C` password-spray mode (one password against many accounts, never enough failures against any single account to trip a lockout policy).

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`vanhauser-thc/thc-hydra`](https://github.com/vanhauser-thc/thc-hydra), its `README`, and `CHANGES` file:

- **Primary author:** van Hauser (`vh@thc.org`) of **THC** (The Hacker's Choice), the same collective/handle behind other long-running offensive tools. Many protocol modules were written by **David Maciejak**; the `-x` brute-force password-generation engine (BFG) was written by **Jan Dlabal**.
- **License:** GNU Affero General Public License v3.0 (AGPLv3) — verified against the repo's own `license` metadata field.
- **Origin/purpose, in the author's own words (README):** "a proof-of-concept code to give researchers and security consultants the possibility of showing how easy it would be to gain unauthorized access from a remote to a system." The README frames it explicitly as filling a gap that existed circa its creation — several single-protocol login crackers existed, but none supported many protocols *and* parallelized connections in one tool.
- **Current release:** the latest tagged/released version is **v9.7** (confirmed against the repo's GitHub Releases/tags). The live `master` branch's `CHANGES` file carries an in-progress, unreleased **`9.8-dev`** entry that is worth flagging on its own: it is almost entirely a security-hardening pass over Hydra's own code — buffer-overflow fixes across more than a dozen protocol modules (ICQ, IRC, rlogin/rsh/rexec, Telnet, SMB1, NCP, PCNFS, pcAnywhere, AFP, SNMP, LDAP, SOCKS5, Oracle-listener) and, notably, hardening of the `hydra.restore` session file itself — the file is now opened `0600` with `O_NOFOLLOW`, and on read Hydra validates that the file is a regular file owned by the invoking user before trusting its contents, plus clamps every length/count/offset field before using it to drive `malloc()` or loop bounds. **This means the restore file was, until this hardening, a plausible local attack surface (untrusted deserialization) in its own right** — a detail worth knowing if analyzing an older Hydra build's artifacts.
- No CVE-numbered advisory for Hydra itself was found during this research; the 9.8-dev hardening reads as proactive/CodeQL-driven cleanup (the CHANGES entry credits reporters Elpe Pinillo and TristanInSec) rather than a response to a single named vulnerability.
- Hydra ships a companion GTK GUI, `xhydra`, and a companion tool, `pw-inspector` (filters a wordlist down to entries matching a target password policy — length/character-class minimums) — both built from the same source tree.

## How It Works

Hydra's architecture is a thin, protocol-agnostic **core** (`hydra.c` — argument parsing, target/credential-list management, task scheduling, the `hydra.restore` session mechanism) driving a large set of interchangeable **protocol modules** (`hydra-<protocol>.c`, one file per service — `hydra-ftp.c`, `hydra-ssh.c`, `hydra-smb.c`, `hydra-http-form.c`, etc.), each exposing a small, fixed interface (an `_init()` connectivity/handshake check and a per-attempt `service_<name>()` function). The core doesn't know or care what FTP or RDP authentication actually looks like on the wire — it just feeds each module a login/password pair and asks "accepted, rejected, or error?"

```
                         Hydra core (hydra.c)
   ┌─────────────────────────────────────────────────────────────┐
   │  1. Build the credential set:                                │
   │     -l/-L (logins) x -p/-P (passwords)   [combinatorial]      │
   │     -C (login:pass pairs)                [1:1, credential stuffing]
   │     -e n/s/r                              [derived from login] │
   │     -x MIN:MAX:CHARSET                    [BFG-generated]      │
   │                                                                 │
   │  2. Fan the credential set out across -t parallel connections │
   │     PER TARGET (default 16) -- or -T total connections across │
   │     a whole -M target list (default 64)                       │
   │                                                                 │
   │  3. Hand each (login, password, target) tuple to the selected │
   │     protocol module's service_<name>() function                │
   └───────────────────────┬────────────────────────────────────────┘
                            │  many concurrent, independent
                            │  authentication attempts
                            ▼
      ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐
      │ target: FTP│   │target: SSH│   │target: SMB│   │  ... etc  │
      │ real logon │   │ real logon│   │ real logon│   │            │
      │ attempt    │   │ attempt   │   │ attempt   │   │            │
      └───────────┘   └───────────┘   └───────────┘   └───────────┘
                            │
      4. Module reports success/failure back to the core, which
         records it, optionally exits early (-f/-F), and every
         ~299 seconds (README: "every 5 minutes") checkpoints full
         session state to ./hydra.restore for -R resume.
```

Two mechanics matter disproportionately for forensic read-back:

- **Every attempt is a real, complete authentication handshake against the actual target service** — Hydra does not pre-validate anything offline. There is no "protocol-level shortcut" the way, say, a Kerberoasting tool gets a crackable hash from one TGS-REQ; each guess is its own full logon exposed to whatever native logging the target service already does. This is why `04 - Target Evidence.md` is organized entirely around each protocol's own native auth-log format rather than a Hydra-specific artifact — Hydra has none on the target side.
- **`./hydra.restore` is the one persistent, Hydra-specific artifact, and it lives only on the attacking host.** Verified directly in source (`hydra.c`, `RESTOREFILE "./hydra.restore"`, `hydra_restore_write()`): it is written relative to the **current working directory** the operator launched Hydra from (not a fixed path), on a periodic timer (`time(NULL) - elapsed_restore > 299`, i.e. roughly every 5 minutes) and again on clean exit/interrupt. It is a full binary checkpoint — sufficient for `hydra -R` to resume a killed/crashed run from the same in-progress position, including remaining credential-list offset. In current source it is written mode `0600`. `hydra -R` reading it back checks the file's owner and validates it was built by a compatible Hydra version and the **same platform/endianness** it was written on (the README states this explicitly: "the hydra.restore file can NOT be copied to a different platform"). See `03 - Source Evidence.md` for what this means forensically.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Authentication protocols attacked | 50+ distinct service modules — see the full, source-verified list below |
| Attack modes | Dictionary (`-l`/`-L` × `-p`/`-P`), credential stuffing (`-C`, 1:1 pairs), password spraying (`-e`/`-C` — one/few passwords against many logins), pure brute-force generation (`-x`, the BFG engine) |
| Transport | TCP/UDP direct to each protocol's native port; optional TLS (`-S`) for the services that support it; optional HTTP/SOCKS4/SOCKS5 proxying via `HYDRA_PROXY`/`HYDRA_PROXY_HTTP` environment variables |
| Session persistence | `hydra.restore` binary checkpoint file (attacking host only) |

**Full verified protocol module list** (pulled directly from the `SERVICES` string in `hydra.c`, which is the tool's own live dispatch table — more current and complete than the README's prose summary, which is missing several modules entirely, see the callout below):

`adam6500`, `asterisk`, `afp`, `cisco`, `cisco-enable`, `cobaltstrike`, `cvs`, `firebird`, `ftp[s]`, `http[s]-{head|get|post}`, `http[s]-{get|post}-form`, `http-proxy`, `http-proxy-urlenum`, `icq`, `imap[s]`, `irc`, `ldap2[s]`, `ldap3[-{cram|digest}md5][s]`, `memcached`, `mongodb`, `mssql`, `mysql`, `ncp`, `nntp`, `oracle`, `oracle-listener`, `oracle-sid`, `pcanywhere`, `pcnfs`, `pop3[s]`, `postgres`, `radmin2`, `rdp`, `redis`, `rexec`, `rlogin`, `rpcap`, `rsh`, `rtsp`, `s7-300`, `sapr3`, `sip`, `smb`, `smb2`, `smtp[s]`, `smtp-enum`, `snmp`, `socks5`, `ssh`, `sshkey`, `svn`, `teamspeak`, `telnet[s]`, `vmauthd`, `vnc`, `xmpp`.

> **Correction found during verification:** the README's own hand-written protocol-list paragraph is stale relative to the live `SERVICES` dispatch table in `hydra.c` — it omits `adam6500` (an ICS/SCADA relay protocol), `cobaltstrike` (a module for cracking Cobalt Strike's own auth), `redis`, `rpcap` (remote packet capture), and `s7-300` (Siemens PLC) entirely, even though source files (`hydra-adam6500.c`, `hydra-cobaltstrike.c`, `hydra-redis.c`, `hydra-rpcap.c`, `hydra-s7-300.c`) and `extern` declarations for all five exist and are wired into `SERVICES` in the current `master` branch. Anyone scoping Hydra's real reach off the README text alone would undercount it by five protocols, several of which (ICS/SCADA `adam6500`/`s7-300`, C2-framework `cobaltstrike`) are unusually notable inclusions.

Not every module compiles in by default — several require optional third-party libraries the README's `apt-get` line lists (`libssh` for `ssh`/`sshkey`, `libssl` for TLS-wrapped services, `libmysqlclient` for `mysql`, `libpq` for `postgres`, `libsvn` for `svn`, `firebird-dev` for `firebird`, `libmemcached` for `memcached`, `libgcrypt` for `radmin2`) or a vendor SDK entirely unavailable via package manager (`oracle`, `sapr3`, `ncp`, `afp` — must be built against vendor-supplied headers). A given Hydra binary's actual protocol coverage is therefore build-dependent; `hydra -h` prints "These services were not compiled in: ..." for whatever was skipped.

## Command-Line Switches — Quick Reference

Verified live against [`vanhauser-thc/thc-hydra`](https://github.com/vanhauser-thc/thc-hydra)'s `hydra.c` `help()`/`help_bfg()` functions (the actual text `hydra -h` prints) — every flag below is a real, current switch, not a guessed default.

| Switch | Plain-English meaning |
|---|---|
| `-l LOGIN` / `-L FILE` | One login name, or a file of login names to try |
| `-p PASS` / `-P FILE` | One password, or a file of passwords to try |
| `-C FILE` | Colon-separated `login:pass` pair file — credential stuffing / known-default-account mode. **Cannot** be combined with `-l`/`-L`/`-p`/`-P` (can combine with `-e`) |
| `-e nsr` | Derive extra password guesses from the login itself: `n` = try an empty/null password, `s` = try the login string as its own password, `r` = try the reversed login string |
| `-x MIN:MAX:CHARSET` | Pure brute-force password generation (the BFG engine) instead of a wordlist — `CHARSET`: `a`=lowercase, `A`=uppercase, `1`=digits, any other character is used literally |
| `-y` | Disable the `a`/`A`/`1` placeholder letters in `-x`'s charset (so a literal `a` in the charset means the letter `a`, not "all lowercase") |
| `-r` | Use non-random (deterministic) ordering for `-x` generation instead of shuffled |
| `-u` | Loop through logins in the outer loop instead of passwords (i.e., try password 1 against every login, then password 2 against every login...) — this is the mechanical core of password-spray mode, and is automatically implied when `-x` is used |
| `-M FILE` | Attack a list of targets from a file (one host per line, `:port` optional per line) instead of a single target |
| `-D XofY` | Divide the wordlist into `Y` equal segments and run only segment `X` — for splitting one job across multiple parallel Hydra instances/hosts |
| `-o FILE` | Write found login/password pairs to `FILE` instead of stdout |
| `-b FORMAT` | Output format for `-o`: `text` (default), `json`, or `jsonv1` |
| `-f` / `-F` | Exit as soon as one valid pair is found — `-f` is per-target (with `-M`, stop that target but keep going on others), `-F` is global (stop the entire run) |
| `-t TASKS` | Parallel connections **per target** (default 16) |
| `-T TASKS` | Parallel connections **overall**, across all targets (relevant with `-M`; default 64) |
| `-w TIME` | Seconds to wait for a response before giving up on an attempt |
| `-W TIME` | Seconds to wait between connects, per thread |
| `-c TIME` | Wait `TIME` seconds per login attempt, applied **across all threads together** — this option forces `-t 1` (fully serializes the attack); the primary built-in timing/OPSEC throttle |
| `-4` / `-6` | Use IPv4 (default) or IPv6 targets |
| `-S` | Use an SSL/TLS connection (where the module supports it — see the `[s]` suffix in protocol names above) |
| `-O` | Allow old/deprecated SSL v2/v3 (for legacy targets that reject modern TLS) |
| `-s PORT` | Use a non-default port for the service |
| `-v` / `-V` / `-d` | Verbose mode / show each login+password attempted as it happens / full debug output |
| `-K` | Don't retry attempts that previously failed with a connection error (useful for large `-M` mass-scan runs, avoids re-wasting time on dead hosts) |
| `-q` | Suppress connection-error messages |
| `-R` | Resume a previous session from `./hydra.restore` |
| `-I` | Ignore an existing restore file immediately, without Hydra's normal 10-second "found existing restore file" pause/prompt |
| `-U` | Print module-specific usage/options help for the given protocol (e.g. `hydra -U http-post-form`) |
| `-m OPT` | Pass a protocol-specific option string to the module (see `-U` output per protocol — e.g. SMB dialect/domain selection, HTTP form field mapping) |
| `-h` | Full/extended help output |

**Environment-variable proxy controls** (not command-line flags, but part of the same operational surface):

| Variable | Purpose |
|---|---|
| `HYDRA_PROXY_HTTP` | Route HTTP-family module traffic through a web proxy — `http://host:port`, `http://user:pass@host:port`, or a path to a file listing up to 64 proxies |
| `HYDRA_PROXY` | Route **all other** module traffic through a CONNECT/SOCKS4/SOCKS5 proxy — `[connect\|socks4\|socks5]://[login:pass@]host:port`, or a proxy-list file for round-robin use |

## Quick Use-Case List

- Single-target, single-protocol dictionary brute force (one login, wordlist of passwords, or the reverse)
- Full combinatorial attack — every login in `-L` against every password in `-P`
- Credential stuffing — a 1:1 `login:pass` pair list via `-C`, simulating reused/breached credentials
- Password spraying — `-e`/`-C` plus `-u` (looping logins, not passwords), one or a few passwords against many accounts, purpose-built to stay under a per-account lockout threshold
- Pure brute-force password generation with no wordlist at all (`-x`, the BFG charset engine)
- Login-derived guesses (`-e nsr`) as a fast, low-noise first pass before a full wordlist run
- SSH password-authentication brute force
- SSH private-key-based brute force (`sshkey` module — tests a directory/list of unencrypted PEM private keys instead of passwords)
- RDP credential validation, with the real current-source caveat that only NLA/CredSSP-enforcing targets can be tested at all
- SMB/SMB2 credential validation, including NTLM-hash-based (pass-the-hash-style) attempts and domain/workgroup/trusted-domain targeting via `-m`
- HTTP(S) Basic/Digest auth brute force (`http[s]-get`/`http[s]-head`)
- HTTP(S) form-based (web login page) brute force (`http[s]-{get|post}-form`), including custom success/failure-condition strings, custom headers, and multipart forms
- FTP, POP3(S), IMAP(S), SMTP(S), Telnet, and other classic service credential brute force
- Database service credential brute force (MySQL, MSSQL, PostgreSQL, Oracle, MongoDB, Redis, Memcached)
- Threading/timing tuning for speed (`-t`/`-T`) versus stealth/lockout-avoidance (`-c`, `-W`)
- Stop-on-success conditions (`-f`/`-F`) to end a run the moment a valid pair is found, rather than exhausting the whole list
- Splitting one large job across multiple parallel Hydra processes/hosts (`-D XofY`)
- Multi-target mass scanning from a target list (`-M`), including mixed non-default ports per line
- Proxying attack traffic through an HTTP or SOCKS4/5 proxy (or proxy list) via the `HYDRA_PROXY`/`HYDRA_PROXY_HTTP` environment variables
- Resuming an aborted/crashed long-running session (`-R`, reading `./hydra.restore`)
- A chained workflow — feeding a Hydra-discovered valid credential pair into `NetExec/` or `Impacket/` for authenticated follow-on access (SMB shares, remote execution, secrets dumping) rather than stopping at "credential confirmed"

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Compiled Hydra binary | Ships in most pentest distros (Kali, etc.) pre-built; a from-source build's actual protocol coverage depends on which optional libraries (`libssh`, `libssl`, `libmysqlclient`, `libpq`, `libsvn`, vendor SDKs for Oracle/SAP/NCP/AFP) were present at compile time — check `hydra -h`'s "not compiled in" line |
| Network reachability | Direct TCP/UDP reachability to the target service's port (or an accessible HTTP/SOCKS proxy configured via `HYDRA_PROXY`/`HYDRA_PROXY_HTTP`) |
| A login list, a password list, or both | Varies by attack mode — `-C` needs a combined pair file instead; `-x` needs no wordlist at all, just a charset/length spec; `sshkey` needs a directory/list of candidate private key files instead of passwords |
| No special privilege on the attacking host | Hydra runs as an unprivileged user process — no elevation needed to run it (though writing `./hydra.restore` and any `-o` output requires normal filesystem write access to the working directory) |
| Protocol-specific knowledge for accuracy | HTTP form-based auth (`http-post-form`) in particular requires the operator to already know the exact POST field names and a failure/success string from the target's own login page — a wrong condition string produces false positives/negatives, not an error |
| A target that hasn't already locked/rate-limited the account | Most services with a lockout or rate-limit policy will silently or explicitly defeat a naive dictionary run; this is the direct motivation for the spray-mode and timing-tuning use cases covered in `02` |
