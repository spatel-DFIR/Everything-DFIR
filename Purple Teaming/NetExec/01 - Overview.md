# NetExec — Overview

> 🔴 **Red Flag Principle:** On **every single target it touches**, before a single real credential is even tried, NetExec's SMB module unconditionally attempts an **anonymous null-session login (`login("", "")`)**, and — unless the operator explicitly passes `--no-admin-check` — follows a successful authentication with an **`\svcctl` (Service Control Manager) RPC bind and `OpenSCManagerW`/`EnumServicesStatusW` call** just to print the `(Pwn3d!)` admin marker. This is not a module or an opt-in "check" — it's unconditional in the connection code path, with **no CLI flag to disable the null-session probe at all**. A single `nxc smb <targets> -u user -p pass` run against 500 hosts therefore produces **500 anonymous-logon Security 4624 events interleaved with 500 real-credential 4624/4625 events**, plus (on every host where auth succeeds) an `\svcctl` named-pipe open that has nothing to do with whatever the operator actually asked the tool to do. That fixed, always-on double-probe — independent of whichever protocol, module, or evasion flag is in play — is the single most reliable fleet-wide fingerprint for this tool.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, **[github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)** (README.md, fetched live for this note):

- **Origin (2015):** The project began life as **CrackMapExec (CME)**, created by **@byt3bl33d3r**, styled as "a swiss army knife for pentesting networks." MITRE ATT&CK still catalogs the tool exclusively under this name — **CrackMapExec, Software ID [S0488](https://attack.mitre.org/software/S0488/)** — with named procedure examples from APT39, FIN7, Ember Bear, Dragonfly, and MuddyWater, plus the *Cutting Edge* campaign (C0029). **There is no separate NetExec entry in MITRE's Software catalog as of this note** — ATT&CK mapping work for this tool still has to be done under the old CME name.
- **2019–2023:** **@mpgn_x64** took over as primary maintainer for roughly four years, adding substantial functionality.
- **September 2023:** mpgn retired from the maintainer role. The project had been developed in parallel across both a private and a public repository during this period, and the README states the resulting **6–8 month discrepancy between the two codebases "caused many development issues and heavily reduced community-driven development."**
- **The rename:** The remaining active contributors — **NeffIsBack, Marshall-Hallenbeck (MJHallenbeck), and zblurx** — forked/continued the project as a **fully open-source, community-maintained project under the new name NetExec**, dropping the private/public split. The original `byt3bl33d3r/CrackMapExec` repository is confirmed **archived** (checked live via the GitHub API for this note).
- **License:** BSD 2-Clause "Simplified" License (confirmed via the GitHub API).
- **Current identity:** command `nxc`, tagline "The Network Execution Tool." Actively maintained — the repository showed commits within the last several days at the time of this research.
- **Install:** `pipx install git+https://github.com/Pennyw0rth/NetExec` is the documented method (README) — same pipx-based distribution pattern as `Impacket/` in this repo, not a pip package published to PyPI as the primary channel.

**Practical takeaway for this repo:** wherever older write-ups, MITRE ATT&CK procedure examples, or Sigma rules say "CrackMapExec" or "CME," they are describing the direct ancestor of the tool documented here — the SMB null-session/guest-check pattern, the credential-matrix spraying model, and most of the module ecosystem carried over unchanged. Per this module's Wave 4 decision log, **no separate `CrackMapExec/` folder exists in this repo** — CME's lineage is documented here instead of duplicated.

## How It Works

NetExec is a **Python framework, not a single exploit** — it wraps Impacket's protocol implementations (the same library underlying `Impacket/psexec/`, `Impacket/wmiexec/`, `Impacket/secretsdump/`, etc. in this repo) behind a single consistent operational loop that runs identically across ten supported protocols: **SMB, WinRM, LDAP, MSSQL, SSH, RDP, VNC, FTP, NFS, and WMI** (confirmed by direct enumeration of the `nxc/protocols/` source tree).

### The per-target connection loop

Every single target in a target list — a single IP, a CIDR range, a hostname, a file of hosts, or even a parsed Nmap XML/`.nessus` scan file (the `target` argument accepts all of these) — goes through the identical sequence, one thread per target (default **256 concurrent threads**, `-t`/`--threads`):

```
For each target host, for each protocol module in play:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Connect + enum_host_info()                                       │
│    - SMB: negotiate dialect, check signing, check SMBv1 support     │
│    - UNCONDITIONAL: attempt anonymous null-session login ("","")    │
│      -> sets null_auth True/False, no flag disables this probe      │
│    - IF check_guest_account=True in nxc.conf (default: False):      │
│      also attempt Guest/"" login                                    │
│                                                                      │
│ 2. login() -- try the supplied credential(s) against this host      │
│    - plaintext / NTLM hash (-H) / Kerberos (-k, ticket or AES key)  │
│    - default: FULL MATRIX -- every -u value x every -p value        │
│      (unless --no-bruteforce forces strict 1:1 pairing)             │
│    - --continue-on-success keeps trying creds after a hit           │
│    - --gfail-limit/--ufail-limit/--fail-limit throttle lockouts     │
│                                                                      │
│ 3. IF login succeeded AND protocol == smb AND not --no-admin-check: │
│    check_if_admin() -- bind \svcctl, OpenSCManagerW,                │
│    EnumServicesStatusW -- sets the "(Pwn3d!)" marker on success     │
│                                                                      │
│ 4. call_cmd_args() -- run whatever -x/-X/--shares/--sam/etc were    │
│    requested on the command line for this protocol                 │
│                                                                      │
│ 5. IF -M/--module given: load_modules() -> call_modules()           │
│    (only runs on_admin_login() hooks if step 3 marked admin)        │
└─────────────────────────────────────────────────────────────────────┘
```

This loop is the entire reason NetExec is the operator's tool of choice for **fleet-wide credential validation**: one invocation, one credential set (or one file of many), hundreds of hosts, and a single scrolling console showing which hosts authenticated and which of those are local admin — the `(Pwn3d!)` tag from step 3.

### Command execution paths (SMB)

When `-x`/`-X` is used against SMB, NetExec doesn't implement its own remote-execution primitive — it calls into one of four selectable Impacket-derived execution classes via `--exec-method` (default **`wmiexec`**):

| `--exec-method` value | Mechanism | Already documented in this repo |
|---|---|---|
| `wmiexec` (default) | WMI `Win32_Process.Create()` via DCOM | `Impacket/wmiexec/` |
| `smbexec` | Service-based cmd.exe wrapper via SVCCTL | `Impacket/smbexec/` |
| `atexec` | Scheduled Task via `ATSvc`/Task Scheduler RPC | Cross-link `LOLBins/schtasks/` for the target-side Task Scheduler artifact set this produces |
| `mmcexec` | MMC's `MMC20.Application` DCOM object (no service/task ever touches disk on the target) | Not yet its own page in this repo — no service-creation or scheduled-task event fires for this method at all, since it drives an existing COM application object instead |

**This module deliberately does not re-derive the wmiexec/smbexec protocol mechanics already documented in `Impacket/`** — the target-side evidence differs only in *which* Impacket-class artifact set appears, not in a NetExec-specific mechanism. `04 - Target Evidence.md` below cross-links each method back to its sibling page rather than duplicating it.

### The module system

`-M <module>`/`-o <key=value>` loads one of NetExec's ~100+ Python modules (enumerated directly from `nxc/modules/`) — small, purpose-built plugins that hook into the connection object once authentication succeeds. They span the entire post-auth kill chain:

| Category | Representative modules |
|---|---|
| Credential harvesting | `lsassy` (remote LSASS parse via a helper library), `nanodump` (stealthy indirect-syscall LSASS minidump), `handlekatz`, `gpp_password`/`gpp_autologin` (SYSVOL Group Policy Preferences cpassword), `dpapi_hash`, `firefox`, `mremoteng`, `winscp`, `putty` |
| Kerberos abuse | `timeroast` (2024 technique — hashes computer/trust accounts' NTP-auth secrets **without needing any AD credential at all**), `pre2k`, `maq` (`ms-DS-MachineAccountQuota` check) |
| ADCS | `adcs`, `certipy-find`, `enum_ca` — cross-link `Certipy/` and `GhostPack/Certify/` (both Wave 3) for the exploitation side |
| Vulnerability checks | `zerologon`, `nopac`, `printnightmare`, `smbghost`, `petitpotam`/`printerbug`/`dfscoerce`/`shadowcoerce` (NTLM coercion primitives) |
| AD privilege-path discovery | `--bloodhound` is a **native LDAP-protocol flag**, not a module — a built-in BloodHound CE collector invoked with `-c/--collection` (cross-link `BloodHound/SharpHound/` for what the resulting JSON/edge set means) |
| Recently added (currency check) | `badsuccessor` — added 2025, checks for the dMSA-based (`msDS-DelegatedManagedServiceAccount`) privilege-escalation path published by Akamai researchers, confirming the project tracks new AD attack research quickly |

### Workspace/database concept

NetExec persists everything to `~/.nxc/` (overridable via the `NXC_PATH` environment variable): a per-protocol SQLite database under `~/.nxc/workspaces/<workspace>/<protocol>.db` (hosts, credentials, loot, admin status — the same "hosts/services/loot/creds" concept as Metasploit's database, cross-link `Metasploit/msfconsole/`), plus a flat-file log tree at `~/.nxc/logs/<output_folder>/<hostname>_<ip>_<timestamp>.<ext>` for every SAM/LSA/NTDS/DPAPI dump and general session transcript. `03 - Source Evidence.md` covers this in depth — it's the single richest operator-host artifact this tool leaves.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Protocols wrapped | SMB (445), WinRM (5985/5986), LDAP/LDAPS (389/636), MSSQL (1433), SSH (22), RDP (3389), VNC, FTP, NFS, WMI — all via Impacket's protocol implementations under the hood |
| Authentication | Plaintext password, NTLM hash (pass-the-hash, `-H`), Kerberos ticket (`-k`/`--use-kcache`/`KRB5CCNAME`), Kerberos AES key (`--aesKey`), PFX/PEM certificate (AD CS / PKINIT-adjacent auth), LAPS-resolved local-admin password (`--laps`) |
| Credential-matrix logic | Full cartesian spray by default (every username × every password/hash); `--no-bruteforce` forces strict positional 1:1 pairing (credential stuffing) instead |
| Remote execution | WMI (`wmiexec`), SVCCTL service (`smbexec`), Task Scheduler (`atexec`), DCOM `MMC20.Application` (`mmcexec`), plus native WinRM/SSH/MSSQL/RDP command execution paths per-protocol |
| Credential/secret extraction | Remote Registry SAM/LSA dump (`regdump`) or `secretsdump`-style (`secdump`), NTDS.dit via VSS or DRSUAPI, DPAPI (masterkeys/Credential Manager/cookies), GPP cpassword, LSASS (via module) |
| AD enumeration | Native LDAP queries (users/groups/computers/trusts/PSOs/gMSA), RID brute-forcing, native BloodHound CE collector |
| Kerberos attacks | AS-REP roasting (`--asreproast`), Kerberoasting (`--kerberoasting`), **targeted Kerberoasting** (`--targeted-kerberoast` — temporarily writes an SPN onto a target account, requests the ticket, then removes the SPN; the same "make a non-roastable account roastable" primitive already documented for `LOLBins/setspn/`) |

## Command-Line Switches — Quick Reference

Verified live against `nxc/cli.py` and each protocol's `proto_args.py` in the official source. NetExec's full flag surface is large (100+ across all protocols); the table below covers the flags that matter for reading or writing a real command line.

### Global / shared across every protocol

| Switch | Plain-English meaning |
|---|---|
| `<target>` (positional) | IP, CIDR, hostname, FQDN, file of targets, Nmap XML, or `.nessus` file — accepts all of these interchangeably |
| `-u`/`--username` | Username(s), or a file of usernames (spray list) |
| `-p`/`--password` | Password(s), or a file of passwords (spray list) |
| `-H`/`--hash` | NTLM hash(es) (`LM:NT` or `NT`-only) — pass-the-hash, no plaintext needed |
| `-id` | Reuse a credential already stored in the workspace database by its ID, instead of retyping it |
| `-d`/`--domain` | Domain to authenticate to |
| `--local-auth` | Authenticate against each target's **local** SAM instead of a domain — mutually exclusive with `-d` |
| `--no-bruteforce` | Switch off the default full-matrix spray; pair usernames/passwords positionally 1:1 instead |
| `--continue-on-success` | Keep trying remaining credentials after one succeeds (useful for a full credential-validation audit, not just "find one way in") |
| `--gfail-limit` / `--ufail-limit` / `--fail-limit` | Cap failed attempts globally / per-user / per-host — lockout-avoidance controls for a spray |
| `--jitter <interval>` | Random delay between each authentication attempt — timing-based evasion |
| `-k`/`--kerberos` | Use Kerberos auth instead of NTLM |
| `--use-kcache` | Authenticate from an existing `KRB5CCNAME` ticket cache (pass-the-ticket) |
| `--aesKey` | AES128/256 key for Kerberos auth (works from an offline-cracked/extracted key without ever touching the plaintext password) |
| `--kdcHost` | Explicit KDC/DC FQDN, if it can't be inferred from the target |
| `--pfx-cert` / `--pfx-base64` / `--pfx-pass` / `--pem-cert` / `--pem-key` | Certificate-based authentication (PKI-issued cert instead of a password/hash) |
| `-t`/`--threads` | Concurrent connection threads (default **256**) |
| `-M`/`--module` | Load a post-auth module by name (repeatable) |
| `-o` | `key=value` option(s) passed to the loaded module |
| `-L`/`--list-modules` | List available modules |
| `--options` | Show a loaded module's own option list |
| `--log` | Write session output to a custom log file path |
| `--no-progress` | Suppress the live progress bar (useful piping to a file) |
| `--verbose` / `--debug` | Increase console verbosity |

### SMB-specific (the deepest protocol surface — see `01`'s How It Works for full context)

| Switch | Plain-English meaning |
|---|---|
| `--port` | SMB port (default 445) |
| `--share` | Share to use for file-drop-based execution methods (default `C$`) |
| `--no-smbv1` | Force-disable SMBv1 negotiation |
| `--no-admin-check` | Skip the `\svcctl` admin-rights probe described in the red-flag callout |
| `--exec-method` | `wmiexec` (default) / `smbexec` / `atexec` / `mmcexec` — see the table above |
| `-x` / `-X` | Run a `cmd.exe` command / a PowerShell command |
| `--sam` / `--lsa` | Dump SAM / LSA secrets — `regdump` (Remote Registry) or `secdump` (`secretsdump`-style) method |
| `--ntds` | Dump NTDS.dit — `vss` (Volume Shadow Copy) or `drsuapi` (DCSync-style, default) method; cross-link `Impacket/secretsdump/` and `Mimikatz/lsadump (DCSync)/` for the shared DRSUAPI mechanics |
| `--dpapi` | Harvest and decrypt DPAPI-protected secrets (masterkeys, Credential Manager, browser cookies with `cookies`) |
| `--shares` / `--rid-brute` / `--users` / `--groups` / `--pass-pol` | Enumeration primitives — shares w/ access level, RID-bruteforced users, domain users/groups, password policy |
| `--put-file` / `--get-file` | Push/pull a file over the mapped share |
| `--spider` / `--content` / `--pattern`/`--regex` | Recursively search a share's contents, optionally by filename/content pattern |
| `--gen-relay-list` | Output every host that does **not** require SMB signing — a direct target list for `Impacket/ntlmrelayx/` |
| `--obfs` / `--amsi-bypass` / `--force-ps32` / `--no-encode` | PowerShell-delivery evasion options for `-X` |

### LDAP-specific (Kerberos roasting / AD enumeration — see `01`'s Techniques table)

| Switch | Plain-English meaning |
|---|---|
| `--asreproast <file>` | Dump AS-REP hashes (hashcat mode 18200) for accounts without Kerberos pre-auth |
| `--kerberoasting`/`--kerberoast <file>` | Dump TGS hashes (hashcat mode 13100/19600/19700 depending on etype — cross-link `Hashcat/` and `Impacket/GetUserSPNs (Kerberoasting)/`) for every SPN-bearing account |
| `--kerberoast-account` | Scope Kerberoasting to specific `sAMAccountName`(s) instead of every SPN holder |
| `--targeted-kerberoast` | Write a temporary SPN onto the named account(s), roast it, then remove the SPN — cross-link `LOLBins/setspn/` |
| `--bloodhound` | Run the native BloodHound CE collector; `-c/--collection` selects the collection method set |
| `--gmsa` | Dump and decrypt Group Managed Service Account passwords |
| `--find-delegation` / `--trusted-for-delegation` | Enumerate unconstrained/constrained delegation misconfigurations |
| `--password-not-required` / `--admin-count` | AdFind-style weak-account discovery (`PASSWD_NOTREQD`, stale `adminCount=1`) — cross-link `AdFind/` for the same finding via a different tool |

## Quick Use-Case List

- Fleet-wide password spraying (full matrix, default) or credential-stuffing (`--no-bruteforce`, paired list)
- Pass-the-hash validation across a target range with `-H`
- Pass-the-ticket / Kerberos-cache authentication with `--use-kcache`
- Credential-validation-only sweeps (no `-x`/`-M`) to map which hosts a credential set works on and which of those grant local admin
- Command execution via any of four selectable methods (`wmiexec`/`smbexec`/`atexec`/`mmcexec`), single-command or PowerShell
- SAM/LSA secret dumping at scale (`--sam`/`--lsa`, `regdump` or `secdump`)
- NTDS.dit extraction from a DC (`--ntds`, VSS or DRSUAPI/DCSync method)
- DPAPI secret/browser-credential harvesting (`--dpapi`)
- LDAP-native Kerberoasting, AS-REP roasting, and **targeted** Kerberoasting (writing a temporary SPN)
- Native BloodHound CE data collection (`--bloodhound`) without a separate SharpHound run
- Share enumeration, spidering, and bulk file pull/push across every reachable host
- Module-driven credential harvesting (`lsassy`, `nanodump`, `gpp_password`, `dpapi_hash`, browser/app credential modules)
- Module-driven vulnerability screening (`zerologon`, `nopac`, `printnightmare`, `smbghost`, NTLM-coercion primitives)
- Non-Windows/non-SMB protocol validation and command execution (WinRM, MSSQL `xp_cmdshell`-style, SSH, RDP with screenshotting, VNC)
- Generating an SMB-signing-not-required relay target list (`--gen-relay-list`) to hand directly to `Impacket/ntlmrelayx/`
- Recon/OPSEC-light checks that need no credential at all (`timeroast`, LDAP null-bind style enumeration where the target allows it)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Execution host | Any Linux/macOS/Windows host with Python 3.10+ (per the README's badge) and network reachability to targets — `pipx install` is the documented install path, matching `Impacket/`'s distribution model |
| Network reachability | Whichever protocol port(s) are in play (445/5985-5986/389/636/1433/22/3389/etc.) from the operator host to every target |
| Credentials | None required for a null-session/guest-check sweep or unauthenticated modules like `timeroast`; a valid password, NTLM hash, Kerberos ticket/key, or certificate for everything else |
| Elevated rights on target | Not required for authentication itself, but required (local admin / equivalent) for `-x`/`-X` command execution, SAM/LSA/NTDS dumping, and most modules — the `(Pwn3d!)` marker is exactly this check |
| DC-level rights for `--ntds drsuapi` | Requires DCSync-equivalent replication rights (`Replicating Directory Changes`/`...All`) on the account used, same requirement as `Impacket/secretsdump/`'s `-just-dc` and `Mimikatz/lsadump (DCSync)/` |
