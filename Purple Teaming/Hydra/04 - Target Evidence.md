# Hydra — Target Evidence

Because every Hydra attempt is a real authentication handshake against the target's own service, **target-side evidence is entirely native to whatever protocol was attacked** — Hydra leaves no protocol-specific artifact of its own on the target. This file is organized by protocol accordingly, rather than around a single artifact set the way a lateral-movement tool's page would be. What's genuinely cross-cutting across every protocol is the **shape** of the traffic: a burst of many authentication events, for one or many accounts, in a tight time window, sourced from one (or a small, coordinated set of) client IP(s) — that shape, not any single event ID, is what separates automated guessing from a human mistyping a password.

## Contents
- [The Cross-Cutting Signal — Burst and Velocity](#the-cross-cutting-signal--burst-and-velocity)
- [Windows-Adjacent Targets — SMB / RDP / Local & Domain Auth](#windows-adjacent-targets--smb--rdp--local--domain-auth)
- [SSH](#ssh)
- [FTP and Classic Mail Protocols](#ftp-and-classic-mail-protocols)
- [HTTP(S) Basic/Digest and Form-Based Auth](#https-basicdigest-and-form-based-auth)
- [Database Services](#database-services)
- [Account Lockout Behavior](#account-lockout-behavior)
- [Building a Timeline](#building-a-timeline)

---

## The Cross-Cutting Signal — Burst and Velocity

Regardless of protocol, three shape-based questions distinguish a Hydra run from routine failed-login noise:

1. **Attempt count per unit time, from one source, against one target service.** A human mistyping a password produces one, occasionally two or three, failures in a burst, seconds apart, then either succeeds or gives up. Hydra at default settings (`-t 16`) produces dozens of attempts across parallel connections within the same second-to-minute window.
2. **Account fan-out.** A single-account dictionary run (`-l`) shows one account name repeated across many failures. A spray run (`-e`/`-C` with `-u`) shows the *opposite* shape — many distinct account names, each failing once or a handful of times, in the same window. Both are automated; the fan-out pattern is specifically what defeats a naive "N failures on one account" lockout/alert threshold, and is the reason a hunt tuned only to single-account failure counts misses spray mode entirely (see `05`'s Hunting Priority table).
3. **Invalid-username hits.** Where the target's own auth error distinguishes "wrong password" from "no such account" (many protocols don't, deliberately, to avoid username enumeration — but some log-level detail still leaks it), a burst that includes attempts against **non-existent** accounts is a strong automated-tooling tell no legitimate user could produce.

## Windows-Adjacent Targets — SMB / RDP / Local & Domain Auth

Hydra's `smb`/`smb2` and `rdp` modules produce a real Windows logon attempt against the target exactly as any other client would — the full Logon Type / Event ID 4624 (success) / 4625 (failure) framework this repo already documents in depth applies directly. **Don't re-derive that table here** — see `Windows/05 - Users, Groups & Authentication.md`'s Logon Types (Event ID 4624 / 4625) section for the full Logon Type reference and the exact field layout.

What's specific to a Hydra run against these two modules:

| Module | Logon Type on the target | Notes |
|---|---|---|
| `smb`/`smb2` | **3** (Network) | Each attempt is a fresh SMB session-setup/NTLM (or, with `-m "... ntlmv2"`, NTLMv2) negotiation — a burst of Type 3 4625 events from one source IP against one or many account names is the signature. The `-m "local hash"` NTLM-hash-based mode still produces a normal Type 3 logon on the target; the target-side event looks identical whether the attacker supplied a plaintext password or a hash, since NTLM auth doesn't distinguish the two at the protocol layer |
| `rdp` | **10** (RemoteInteractive), but **only against NLA/CredSSP-enforcing targets** | As `02` and `01` both note, Hydra's `rdp` module cannot brute-force a non-NLA target at all — it reports those as not verifiable rather than generating any logon attempt. On an NLA-enforcing target, expect a burst of Type 10 4625 failures, then (if successful) a Type 10 4624. This exact fail-then-succeed shape, for RDP specifically, is already the subject of a dedicated playbook in this repo: `Windows/Threat Landscape and Playbooks/RDP Brute-Force and Foothold Playbook.md` — apply its Step 1/Step 2 hunt queries directly rather than rebuilding them here, and continue into that playbook's later steps if a Hydra RDP spray is confirmed to have succeeded |


A Hydra `smb`/`rdp` spray run (many accounts, one/few passwords, `-u`) shows up on a domain controller or member server's Security log as many distinct `Account Name` values, each with a small failure count, from one source IP, in a tight window — the domain-wide version of this pattern is covered in `05`'s Fleet-Wide Sweep.

## SSH

SSH's own authentication logging is the classic, well-understood case — and this repo already has a full reference for it. **See `Linux/06 - Logs/Authentication and Login Records.md`'s Brute Force Detection and SSH Activity sections** for the `Failed password` / `Accepted password` / `Invalid user` log-line reference, `journalctl`/`auth.log`/`secure` locations, and the fail-then-success correlation pattern — apply it directly against a Hydra `ssh` run.

Two Hydra-specific notes on top of that existing reference:

- The `sshkey` module (private-key brute force) produces the **same** `sshd` log lines as password auth from the target's perspective — OpenSSH logs `Failed publickey for X from Y` / `Accepted publickey for X from Y` distinctly from the password variants, so a target-side hunt scoped only to `Failed password` misses a `sshkey`-based Hydra run entirely; explicitly include `Failed publickey`/`Accepted publickey` lines in any SSH brute-force sweep.
- Modern OpenSSH's `Connection closed by authenticating user … [preauth]` line (called out in the Linux note as "the modern OpenSSH brute-force shape, no 'Failed password'") is exactly the log signature a high-`-t` Hydra run against a rate-limiting or connection-capping `sshd` (`MaxStartups`) produces once the server starts refusing/dropping excess concurrent auth attempts — a burst of these lines from one source IP is as strong a signal as a burst of `Failed password` lines, and is easy to miss if a hunt query only greps for the latter.

## FTP and Classic Mail Protocols

FTP, POP3(S), IMAP(S), SMTP(S), NNTP, and Telnet each log authentication failures in their own native, service-specific log format (`vsftpd.log`/`xferlog` for FTP; Dovecot/Cyrus logs for POP3/IMAP; Postfix/Exim/Sendmail mail logs for SMTP) — none of these have a dedicated reference elsewhere in this repo at the time of writing. The cross-cutting signal from the top of this file (burst count, account fan-out, invalid-username hits) is the primary hunting lever for all of them; look for the service's own repeated `530 Login incorrect` (FTP), `-ERR authentication failed` (POP3), `a NO [AUTHENTICATIONFAILED]` (IMAP), or `SMTP AUTH LOGIN failed` (SMTP)-style lines clustering from one source IP.

## HTTP(S) Basic/Digest and Form-Based Auth

- **HTTP Basic/Digest** (`http[s]-get`/`http[s]-head`): the web server returns `401 Unauthorized` on every failed attempt and `200`/`3xx` on success — a burst of `401` responses to the same URI, from one client IP, is directly visible in the web server's own access log. Where the target is IIS, this repo's `Windows/23 - Special Services/IIS - Web Server Forensics.md` already documents the log location, field layout (`sc-status`), and hunting workflow for exactly this kind of client-IP/status-code sweep — apply it directly (`sc-status = 401`, grouped by `c-ip`) rather than rebuilding the IIS log-parsing mechanics here.
- **HTTP(S) form-based auth** (`http[s]-{get|post}-form`): the log-visible signal depends entirely on how the application itself responds to a failed login — there is no universal status code the way Basic/Digest auth has. What's consistently visible in the web server's own access log regardless of the application's specific behavior: a burst of `POST` (or `GET`, for `-form-get`) requests to the exact same login URI, from one client IP, at high frequency, each producing the same response size/status (a strong signal on its own — legitimate users produce varied response patterns depending on which account they're logging into and whether they succeed; a scripted attack against a static form produces a near-identical response shape on every failed attempt). If the operator used `h=X-Forwarded-For\: ^RAND_IP^` (see `02`) specifically to probe whether the application trusts a spoofable header for rate-limiting, application-level logs that key off `X-Forwarded-For` instead of the true TCP source IP will show a rotating, clearly-fabricated set of "source" addresses — itself a tell, since real client IPs don't appear as sequential or obviously-randomized values.

## Database Services

MySQL, MSSQL, PostgreSQL, Oracle, MongoDB, and Redis each carry their own native connection/auth-failure logging (MySQL's `general_log`/error log, MSSQL's own login-failure audit, PostgreSQL's `log_connections`/`log_hostname`, etc.) — none is default-on in most of these engines, meaning a Hydra run against an under-logged database service can leave a materially thinner target-side trail than an OS-level or application-level auth surface. Where enabled, the same burst/fan-out shape from the top of this file applies. Redis in particular has historically shipped with **no authentication at all** by default in many deployments — a Hydra `redis` run against an unauthenticated instance won't generate failed-auth events because there was no auth check to fail in the first place; the absence of any Hydra-attributable log noise on an exposed, unauthenticated Redis instance is not evidence nothing happened.

## Account Lockout Behavior

Where a target enforces an account-lockout policy (a fixed number of failures within an observation window locks the account for a period or until admin reset), a single-account Hydra dictionary run that crosses that threshold triggers it directly. On Windows/AD targets this is **Event ID 4740** (a user account was locked out), logged on the domain controller that processed the lockout, naming the account and the **Caller Computer Name** — which, for a network-based lockout (as opposed to a bad password typed at a physical console), names the machine the failed authentication actually originated from, a direct pivot back toward the attacking host if it's a domain-joined system. A password-spray run deliberately never accumulates enough per-account failures to reach this threshold — which is precisely why `-u`/spray mode is the mode of choice against any environment with a meaningfully-tuned lockout policy, and why 4740 alone is a poor primary hunting signal against a competent spray (see `05`'s Hunting Priority table for how this ranks against other signals).

## Building a Timeline

1. **Anchor on the burst window** — the first and last authentication-failure events in the cluster define the attack's start/end on the target side; this should align closely with (or fall shortly after) the source-side window `03 - Source Evidence.md` establishes from shell history and `hydra.restore` timestamps.
2. **Identify the pivot event** — the first *successful* authentication (4624 Type 3/10, `Accepted password`/`publickey`, a `200`/`3xx` response following a run of `401`s or matching a form's success condition) inside or immediately after the failure burst. Everything from that account/session onward is now suspect.
3. **Cross-reference account fan-out against a known user list** — if the failing/succeeding account names correspond to a real, enumerable list (employee usernames, service accounts), that's independent evidence of prior reconnaissance (an AD enumeration tool from this repo, e.g. `AdFind/` or `BloodHound/`, having supplied the target list) rather than a purely opportunistic scan.
4. **Chain into post-compromise evidence** — once a successful pivot event is identified, hand off to whatever the confirmed account/service enables next: `Windows/12 - Lateral Movement.md`-class evidence if the successful protocol was SMB/RDP, or the relevant sibling tool's own `04 - Target Evidence.md` (`NetExec/`, `Impacket/psexec/`, etc.) if the operator chained a follow-on tool against the newly-confirmed credential, per `02`'s chained-workflow example.
