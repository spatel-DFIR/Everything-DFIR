# Mimikatz — lsadump (DCSync) — Overview

> 🔴 **Red Flag Principle:** `lsadump::dcsync` doesn't touch the target's disk, registry, or LSASS memory at all — it makes the target Domain Controller **replicate to it as if it were a peer DC**, over the legitimate MS-DRSR RPC protocol. The single strongest signal it leaves is therefore not a file or a process, it's an **authorization mismatch**: **Event ID 4662** on the DC, `AccessMask 0x100` (Control Access), carrying the `DS-Replication-Get-Changes` (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) or `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) rights-GUID, where the requesting account is **not** one of the domain's actual Domain Controller computer accounts (or another well-known legitimate holder — Azure AD Connect/Entra Connect's sync account, Domain/Enterprise Admins). Every real DC does this constantly as normal replication traffic; the only thing that makes one instance an attack is *who* asked.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command Reference — lsadump Sub-Commands](#command-reference--lsadump-sub-commands)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`lsadump` is mimikatz's second flagship module (after `sekurlsa`), covering credential extraction that happens **without** reading `lsass.exe`'s live memory — local SAM/LSA-secrets decryption from the registry, and the network-based DCSync/DCShadow/netsync techniques. It ships as part of the core [`gentilkiwi/mimikatz`](https://github.com/gentilkiwi/mimikatz) repository (source: `mimikatz/modules/kuhl_m_lsadump.c` and `mimikatz/modules/lsadump/kuhl_m_lsadump_dc.c`), licensed under CC BY 4.0 — see `00 - Mimikatz Overview.md` for the tool-level history.

**DCSync specifically** — `lsadump::dcsync` — was added to mimikatz in **August 2015**, co-authored by Benjamin Delpy (`@gentilkiwi`) and **Vincent Le Toux**, whose name is credited directly in the `kuhl_m_lsadump_dc.c` source header alongside Delpy's. Le Toux is also the author of the related tool **DSInternals** and co-presented DCSync's sibling technique DCShadow with Delpy at BlueHat/Hack.lu 2018 ("So I Became a Domain Controller"). The canonical public write-up of the technique is Sean Metcalf's ["Mimikatz DCSync Usage, Exploitation, and Detection"](https://adsecurity.org/?p=1729) (ADSecurity.org), which remains the most-cited reference for how the attack works and what it requires. DCSync's core insight — proven out by Le Toux's earlier research into the Directory Replication Service Remote Protocol (**MS-DRSR**) — is that **any principal holding the right AD permissions can request replication data the same way a real Domain Controller does**, without ever needing interactive logon rights on a DC, a copy of `ntds.dit`, or malware running on a DC at all. This eliminated the two previous, far noisier ways of getting the same data (volume-shadow-copy the NTDS database, or run `sekurlsa`/`lsadump::lsa` interactively on a DC itself).

The module also carries the older, pre-DCSync techniques it superseded operationally: `lsadump::sam`/`lsadump::secrets`/`lsadump::cache` (local SAM/LSA-secrets/cached-domain-logon decryption — conceptually identical to what Impacket's `secretsdump.py` and the Sysinternals-era `pwdump` family have always done), and `lsadump::netsync`, a legacy Netlogon-protocol technique that predates DCSync and requires already knowing a machine/trust account's current NTLM hash rather than AD permissions. `lsadump::trust` extracts inter-domain/inter-forest trust key material via the LSA Policy API. A separate, undocumented `lsadump::zerologon`/`lsadump::postzerologon` pair also lives in this module (implementing CVE-2020-1472) — genuinely part of the same module, but a distinct vulnerability-exploitation technique rather than a credential-*read* technique, and out of scope for this note.

## How It Works

### DCSync — the headline technique

DCSync abuses the **Directory Replication Service Remote Protocol (MS-DRSR)** — the same RPC interface real Domain Controllers use to replicate the AD database (`ntds.dit`) to each other. Mimikatz doesn't reverse-engineer anything hidden here; `IDL_DRSGetNCChanges` is a **documented, intended** DC-to-DC replication API. The attack is that Active Directory has no way to verify the caller is *actually* a Domain Controller — it only checks whether the calling security principal holds the right **extended rights** on the domain naming context. If it does, AD serves the data to whoever asks.

```
Operator (mimikatz.exe / any MS-DRSR-speaking client)            Domain Controller (target)
───────────────────────────────────────────────────              ──────────────────────────────
1. Resolve a DC for the target domain (DNS SRV lookup for
   _ldap._tcp.dc._msdcs.<domain>, or an explicit /dc:)   ──────▶

2. RPC bind: ncacn_ip_tcp to the DC's DRSUAPI endpoint
   (endpoint mapper TCP/135 ─▶ dynamic high port),
   authenticated as the operator's own principal via
   Kerberos/Negotiate by default (RPC_C_AUTHN_GSS_NEGOTIATE),
   or NTLM if /authntlm is set                            ──────▶  DC's RPC runtime accepts the
                                                                     bind — this is standard,
                                                                     unauthenticated-at-the-transport-
                                                                     -layer RPC connection setup

3. IDL_DRSBind()  ─────────────────────────────────────────────▶  DC returns a DRS_HANDLE, negotiates
   (drsuapi interface UUID e3514235-4b06-11d1-ab04-00c04fc2dcd2)    protocol extensions/capabilities

4. IDL_DRSGetNCChanges(hDrs, 8, getChReq)   ────────────────────▶  DC evaluates the caller's ACEs
     pNC          = target object's naming context + GUID/DN        against the NC head object:
     ulFlags      = DRS_INIT_SYNC | DRS_WRIT_REP |                  does SubjectUserSid hold
                    DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW |           DS-Replication-Get-Changes
                    DRS_SYNC_URGENT                                 (non-secret attrs) and/or
     ulExtendedOp = EXOP_REPL_OBJ (single-object replication,       DS-Replication-Get-Changes-All
                    not a full NC sync)                              (secret attrs, incl. passwords)?
     pPartialAttrSet = ~20 curated attribute OIDs: name,
       sAMAccountName, objectSid, sIDHistory, userAccountControl,
       unicodePwd, ntPwdHistory, dBCSPwd, lmPwdHistory,
       supplementalCredentials, msFVE* (BitLocker), trustAuth*,
       currentValue, isDeleted

5. ◀──────────────────────────────────────────────────────────  DC returns REPLENTINFLIST: the
                                                                   requested object's attribute
                                                                   values, exactly as it would to
                                                                   a peer DC during real replication.
                                                                   Confidential attributes
                                                                   (unicodePwd etc.) travel inside
                                                                   the RPC session's negotiated
                                                                   security context (sealed per the
                                                                   authentication level from step 2)

6. Locally decrypt/derive NTLM/LM hash, Kerberos keys,
   WDigest, and other supplemental-credential material
   from the returned attribute blobs — entirely on the
   operator's own machine; nothing further touches the DC
```

Step-by-step, in plain terms:

1. **Find a DC.** If `/domain:` isn't given, mimikatz uses the current computer's own domain. If `/dc:`/`/kdc:` isn't given, it performs a normal DC-locator lookup — no special access needed for this step, any domain member can do it.
2. **Bind to DRSUAPI.** A completely ordinary RPC bind (`ncacn_ip_tcp`) to the target DC. Nothing about this step distinguishes an attacker from a legitimate replication partner or, for that matter, any RPC client at all.
3. **`IDL_DRSBind`.** Establishes the replication session and negotiates protocol extensions — again, unremarkable RPC housekeeping.
4. **`IDL_DRSGetNCChanges` — the actual ask.** This is where authorization is checked, and it's checked **once, on the DC, against the caller's AD permissions** — not against any property of the client software, network path, or prior behavior. Two rights matter (verified against `[MS-ADTS]`):
   - **`DS-Replication-Get-Changes`** (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) — lets the caller replicate ordinary (non-secret) attributes.
   - **`DS-Replication-Get-Changes-All`** (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) — the one that actually matters for credential theft: required for AD's schema-marked-**confidential** attributes, which is where `unicodePwd`, `ntPwdHistory`, `dBCSPwd`, `lmPwdHistory`, and `supplementalCredentials` (the encrypted blob holding Kerberos keys, WDigest, etc.) all live. A caller with only `Get-Changes` and not `Get-Changes-All` can replicate the object but gets back empty/redacted values for these specific attributes.
   - A third right, **`DS-Replication-Get-Changes-In-Filtered-Set`** (`89e95b76-444d-4c62-991a-0facbeda640c`), is only relevant against RODCs (Read-Only Domain Controllers) whose Password Replication Policy filters which secrets replicate to them, and for reading gMSA-managed-password-adjacent data in some configurations — a narrower, less commonly needed right.

   By default, only **Domain Controller computer accounts, Domain Admins, Enterprise Admins**, and (built-in) **Administrators** hold `Get-Changes-All` on the domain NC — but because these are ordinary, delegable AD ACEs, they routinely end up granted to service accounts too, deliberately: **Azure AD Connect / Microsoft Entra Connect's sync account is a standard example** — password-hash sync requires exactly these rights by design. This is precisely why the mere presence of these rights on an account is not itself suspicious; the account performing the read, matched against your own inventory of legitimate holders, is what determines whether a given `IDL_DRSGetNCChanges` call is DCSync or Tuesday.
5. **The DC replies exactly as it would to a real DC.** No special "you're not a real DC" check exists at this layer — that's the whole point of the technique. `mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt` returns the same `unicodePwd` value a genuine DC would receive during ordinary replication.
6. **Decrypt locally.** The attribute values returned aren't further "hacked" out of anything — `supplementalCredentials` is a documented (if binary/undocumented-format) blob that mimikatz parses to pull out Kerberos AES/RC4 keys, WDigest material, and NTLM history, entirely offline once the reply has arrived.

**`/all` vs `/user`/`/guid`:** a single-object pull (`/user:` or `/guid:`) sets `cMaxObjects=1` and `ulExtendedOp=EXOP_REPL_OBJ` — a full-domain pull (`/all`) instead sets `cMaxObjects=1000` per round and `ulExtendedOp=0`, looping `IDL_DRSGetNCChanges` calls (feeding each reply's USN watermark back into the next request's `usnvecFrom`) until the DC reports `fMoreData=FALSE`. This is a materially louder operation — many round-trips pulling every object in the domain, rather than one request for one object — see `04 - Target Evidence.md` for the volumetric signal this creates.

### `lsadump::sam` / `lsadump::secrets` / `lsadump::cache` — local, registry-based extraction

These three share one code path (`kuhl_m_lsadump_secretsOrCache` for secrets/cache; a near-identical one for `sam`) and one core mechanic: Windows encrypts the local SAM database and the LSA "Secrets" store using a machine-specific **boot key** (a.k.a. "syskey"), and every credential blob inside those stores is just ciphertext once you have that key.

- **Boot key derivation (verified from source):** four registry values under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\` — subkeys named **`JD`, `Skew1`, `GBG`, `Data`** — each hold part of the key encoded in their key **Class** name (not their data), scrambled together via a fixed 16-byte permutation table (`kuhl_m_lsadump_SYSKEY_PERMUT`). This is the same "syskey" scheme every SAM-dumping tool (Impacket's `secretsdump.py`, the old `pwdump`/`fgdump` family) reimplements independently — it isn't mimikatz-specific.
- **From boot key to per-hash decryption:** the boot key is combined (via MD5, for the older "Revision 1" scheme, or AES-128 for the newer "Revision 2" scheme mimikatz's source distinguishes explicitly) with per-account salt material to derive a SAM key, which then decrypts each user's stored LM/NTLM hash and history. LSA Secrets (`lsadump::secrets`) and cached domain logons (`lsadump::cache`, MSCache/DCC2) follow the equivalent pattern against the `SECURITY` hive instead of `SAM`.
- **Live vs. offline — the same split sekurlsa draws between a live LSASS read and `sekurlsa::minidump`:**
  - **Live** (no `/system`/`/sam`/`/security` arguments): mimikatz opens `HKLM\SYSTEM`, `HKLM\SAM`, and `HKLM\SECURITY` directly via the registry API on the running system. **`SAM` and `SECURITY` are ACL'd so that only the `SYSTEM` account can read them** — a plain local-administrator token cannot open these keys even with `privilege::debug` enabled, which is exactly why `token::elevate` (see `00 - Mimikatz Overview.md`) is a near-universal prerequisite before running these live.
  - **Offline** (`/system:<path>` plus `/sam:<path>` or `/security:<path>`): mimikatz opens raw **hive files** via `CreateFile` — copies of `C:\Windows\System32\config\SAM`/`SECURITY`/`SYSTEM`, typically pulled from a Volume Shadow Copy, a backup, or a mounted offline disk image, since the live files are locked while Windows is running. This path touches **no live registry or LSASS at all** — the "quiet" variant, directly analogous to `sekurlsa::minidump`.

### `lsadump::trust` — inter-domain/forest trust key extraction

Queries the LSA Policy API (`LsaEnumerateTrustedDomainsEx` / `LsaQueryTrustedDomainInfoByName`) for every trusted-domain object's incoming/outgoing authentication information, then — where the auth type is `TRUST_AUTH_TYPE_CLEAR` — derives Kerberos AES128/AES256/RC4 keys from the recovered trust password (verified from source: `kuhl_m_lsadump_trust_authinformation`). Two modes: the **default** call requires the caller already be running as `SYSTEM` to receive real (non-redacted) authentication blobs from the LSA Policy API; the **`/patch`** flag instead in-memory-patches `lsasrv.dll`/`lsadb.dll` inside `lsass.exe` (opening it with `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`, write access) to bypass that same-SYSTEM requirement without actually holding a SYSTEM token — a materially more invasive LSASS access than the default path, and one that leaves the same write-capable `GrantedAccess` signature category as `sekurlsa::pth` (see `04 - Target Evidence.md`).

### `lsadump::netsync` — legacy Netlogon secure-channel abuse

The oldest technique in this module, predating both DCSync and the MS-DRSR-based approach entirely. It **requires already knowing the target machine or trust account's current NTLM hash** — it is not a rights-based or zero-knowledge attack. Using that known hash, mimikatz performs a legitimate Netlogon secure-channel establishment (`I_NetServerReqChallenge` → `I_NetServerAuthenticate2`, computing credentials via DES with the known hash as key material) against a target DC, then calls **`I_NetServerTrustPasswordsGet`** to retrieve the **current and previous** NTLM hash of the specified computer/trust account. Its value is narrow and specific: rotating the recovered "previous" hash reveals what the account's password *was* before its last scheduled machine-account password change (every 30 days by default) — useful for confirming a hash is still valid or recovering a very recently rotated one. **This is distinct from mimikatz's separate `zerologon`/`postzerologon` commands**, which exploit CVE-2020-1472 to establish a Netlogon secure channel with an *unknown*, all-zero credential — a vulnerability-exploitation technique, not covered in this note.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| DCSync | **MS-DRSR** (Directory Replication Service Remote Protocol) — RPC interface `drsuapi`, UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2`, transported over `ncacn_ip_tcp` (RPC endpoint mapper TCP/135 → dynamic high port) |
| sam/secrets/cache | Local Windows Registry API (live) or raw hive-file parsing (offline) — no network component |
| trust | LSA Policy RPC (`lsasrv`/`lsadb`), or local in-process LSASS memory patch for `/patch` |
| netsync | Legacy **MS-NRPC** (Netlogon Remote Protocol) — `I_NetServerReqChallenge`/`I_NetServerAuthenticate2`/`I_NetServerTrustPasswordsGet` |
| Authorization model exploited (DCSync) | Standard AD **extended/control access rights** on the domain naming context — `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, `DS-Replication-Get-Changes-In-Filtered-Set` |
| Credential material recovered | NTLM/LM hashes + history, Kerberos keys (RC4/AES128/AES256), WDigest, cleartext trust passwords, BitLocker recovery data (`msFVE*` attributes), cached domain logons (MSCache/DCC2) |

## Command Reference — lsadump Sub-Commands

Verified directly against `kuhl_m_c_lsadump[]` in `kuhl_m_lsadump.c` and the individual command implementations in `kuhl_m_lsadump.c`/`lsadump/kuhl_m_lsadump_dc.c` — every command below is registered exactly as listed there. Commands with no built-in help string in the source are marked accordingly.

| Command | Plain-English meaning |
|---|---|
| `lsadump::sam [/system:<hive> /sam:<hive>]` | Local SAM database dump — every local account's LM/NTLM hash. Live (needs SYSTEM) or offline against copied `SYSTEM`/`SAM` hive files |
| `lsadump::secrets [/system:<hive> /security:<hive>]` | LSA Secrets — service-account passwords, scheduled-task credentials, and other secrets stored under `HKLM\SECURITY\Policy\Secrets` |
| `lsadump::cache [/system:<hive> /security:<hive>]` | Cached domain logon hashes (MSCache/DCC2) — what lets a domain-joined machine authenticate a previously-logged-on domain user while offline |
| `lsadump::lsa [/patch \| /inject]` | Live SAM-equivalent read via direct in-process calls into `samsrv.dll` inside `lsass.exe` — no source description string; understood from source. `/patch` and `/inject` both write into LSASS to bypass restrictions, materially more invasive than the default call |
| `lsadump::trust [/patch]` | Inter-domain/inter-forest trust key material — see **How It Works** above |
| `lsadump::backupkeys [/export]` | Domain DPAPI "preferred backup key" — retrieved via the LSA Policy API's private-data store (`G$BCKUPKEY_*` LSA secrets), not from LSASS memory (compare `sekurlsa::backupkeys`, which reads the equivalent material live from memory) |
| `lsadump::rpdata /name:<secret-name> [/secret] [/system:<remote>]` | Raw LSA private-data retrieval by name — no source description string; a lower-level primitive `backupkeys`/`secrets` build on |
| `lsadump::dcsync /user:<u> \| /guid:<g> \| /all [/domain:<d>] [/dc:<dc>] [/csv] [/export] [/deleted] [/uac] [/authntlm] [/laps]` | **The headline technique.** See **How It Works** above |
| `lsadump::dcshadow [/push] [/object:...] [...]` | Registers the operator's own host as a **rogue replication partner** to push (not pull) unauthorized changes into AD — a materially different, offensive-write technique; out of scope for this credential-*theft*-focused note |
| `lsadump::setntlm /user:<u> /ntlm:<hash>` | Sets a target user's NTLM hash directly via SAMR — a credential-*modification* primitive, not extraction |
| `lsadump::changentlm /user:<u> /oldntlm:<hash> /newntlm:<hash>` | Changes (rather than force-sets) a user's NTLM hash via SAMR, using the old hash as authorization |
| `lsadump::netsync /dc:<dc> /user:<account> /ntlm:<hash> [/computer:<name>] [/account:<name>]` | Legacy Netlogon current+previous-hash retrieval — see **How It Works** above |
| `lsadump::packages [<target-name>]` | Enumerates locally registered SSP/AP security packages (WDigest, Kerberos, NTLM, etc.) — a reconnaissance/diagnostic command, not credential extraction |
| `lsadump::mbc` | Reads the `MachineBoundCertificate` value under `HKLM\SYSTEM\...\Control\Lsa\Kerberos\Parameters` — no source description string |
| `lsadump::zerologon [/account:<dc$>] [/exploit]` | Implements CVE-2020-1472 detection/exploitation against Netlogon — a vulnerability exploit, not a credential-read technique; **out of scope for this note** |
| `lsadump::postzerologon` | Restores a DC's machine-account password after a `zerologon` exploitation run — companion cleanup command, out of scope |

## Quick Use-Case List

- Full DCSync pull of a single high-value account's credentials (`lsadump::dcsync /user:krbtgt`) — the canonical Golden Ticket feeder
- DCSync a regular user account to obtain their NTLM hash without ever touching their workstation or the DC's filesystem
- Full-domain DCSync (`/all`) to replicate every account's credential material in one operation — the network-protocol equivalent of exfiltrating `ntds.dit`
- DCSync against a deleted/tombstoned account (`/deleted`) — recovering credentials for an account that's since been removed but whose tombstone hasn't yet been garbage-collected
- DCSync with `/csv` for bulk, script-friendly output across many accounts
- DCSync with `/authntlm` to force NTLM authentication for the RPC bind, when Kerberos isn't available to the operator (e.g. no line-of-sight to a KDC, or operating cross-forest without a trust)
- DCSync with `/laps` to additionally pull the LAPS-managed local administrator password (`ms-Mcs-AdmPwd`) for a computer object, resolving the attribute's schema ID dynamically first
- Local SAM dump on a standalone/workgroup machine or a domain member for its local Administrator/local-account hashes (`lsadump::sam`)
- Offline SAM/SECURITY hive analysis from a Volume-Shadow-Copy or forensic image, with no live registry touch at all (`lsadump::sam /system:... /sam:...`)
- LSA Secrets extraction to recover a service account's or scheduled task's stored plaintext-equivalent credential (`lsadump::secrets`)
- Cached domain logon (MSCache/DCC2) extraction for offline cracking, when only a hashed cached credential — not the live domain hash — is available (`lsadump::cache`)
- Inter-domain/inter-forest trust key extraction to forge cross-trust authentication material (`lsadump::trust`)
- Legacy machine/trust-account current+previous-NTLM-hash retrieval when the current hash is already known but confirmation or the prior hash is needed (`lsadump::netsync`)
- Chained immediately after obtaining any account with `Get-Changes-All` rights via a separate privilege-escalation or ACL-abuse path (e.g. a BloodHound-identified `GenericAll`/`WriteDacl` grant on the domain object) — DCSync as the payoff step, not the initial-access step

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| **For DCSync:** a principal holding `DS-Replication-Get-Changes-All` (and `Get-Changes`) on the target domain naming context | Default holders: Domain Admins, Enterprise Admins, built-in Administrators, and DC computer accounts — but any account can be delegated these rights, deliberately (Azure AD Connect/Entra Connect) or via ACL misconfiguration. **No local admin rights on any machine are required at all** if the operator already controls a qualifying account |
| Network reachability to a DC's DRSUAPI RPC endpoint | RPC endpoint mapper TCP/135, plus whatever dynamic high port it hands back — routinely blocked between untrusted network segments and DCs in a well-segmented environment, which is a real mitigating control |
| **For `sam`/`secrets`/`cache` (live):** local administrator + `token::elevate` to SYSTEM | The SAM/SECURITY hive ACLs block even administrator-token reads; only a SYSTEM token can open them directly |
| **For `sam`/`secrets`/`cache` (offline):** copies of the relevant hive files | Typically pulled via Volume Shadow Copy (`vssadmin`), a backup, or a mounted offline disk/VM image — no live access to the source machine needed at parse time |
| **For `trust`:** SYSTEM context (default), or LSASS write access (`/patch`) | Same SYSTEM-token gate as `sam`/`secrets` by default; `/patch` trades that requirement for a more invasive, detectable LSASS memory write |
| **For `netsync`:** the target machine/trust account's current NTLM hash, already known | This is *not* a zero-knowledge or rights-based technique — it confirms/extends an already-compromised credential, it doesn't independently grant new access |
| Kerberos or NTLM credential for the RPC bind (DCSync) | Whichever the operator's context already has — `/authntlm` forces NTLM specifically, useful when only an NTLM-authenticatable credential (e.g. a relayed/passed hash) is available |
