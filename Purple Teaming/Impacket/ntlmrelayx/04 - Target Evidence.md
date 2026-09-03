# Impacket — ntlmrelayx.py — Target Evidence

`ntlmrelayx.py` touches **two** target-side hosts per successful relay, not one: the **victim** (whose live authentication got hijacked) and **Target B** (the relay destination the attack module actually runs against). Both matter, but they are evidentially very different — the victim mostly shows *nothing distinctive at all* (from its own point of view, it just authenticated somewhere; the coercion/poisoning primitive that made it do so is what generates victim-side evidence, and that's covered in `Responder/` and MITRE T1187 territory, not re-derived here), while Target B carries the full weight of this note. Target B's evidence is further split by **which relay-target protocol/attack module fired**, since SMB, LDAP, DCSync, ADCS, MSSQL, WinRM, RPC, SCCM, and IMAP each leave a structurally different trail — mirroring the per-path organization `Impacket/secretsdump/04 - Target Evidence.md` uses for its own three extraction paths.

## Contents
- [The Core Signature — Two Logons for One Authentication](#the-core-signature--two-logons-for-one-authentication)
- [Victim-Side Evidence — the Hijacked Host](#victim-side-evidence--the-hijacked-host)
- [Target B — SMB Relay](#target-b--smb-relay)
- [Target B — LDAP(S) Relay](#target-b--ldaps-relay)
- [Target B — DCSync Relay (Zerologon Path)](#target-b--dcsync-relay-zerologon-path)
- [Target B — ADCS Relay (HTTP/ESC8 and RPC/ICPR)](#target-b--adcs-relay-httpesc8-and-rpcicpr)
- [Target B — MSSQL Relay](#target-b--mssql-relay)
- [Target B — WinRM Relay](#target-b--winrm-relay)
- [Target B — RPC/TSCH Relay](#target-b--rpctsch-relay)
- [Target B — SCCM Management Point / Distribution Point Relay](#target-b--sccm-management-point--distribution-point-relay)
- [Target B — IMAP Relay](#target-b--imap-relay)
- [Building a Timeline](#building-a-timeline)

---

## The Core Signature — Two Logons for One Authentication

Every relay produces a logon event on Target B that is authentic in every technical sense — it validates, it carries the victim's real identity — but is **structurally impossible for the victim to have actually performed**, because the victim's client software never talked to Target B at all; it talked to `ntlmrelayx.py`'s listener, believing that was the intended destination. Read that logon (Security **4624**) with `01 - Overview.md`'s red-flag principle in mind and cross-reference the field-level logon-type mechanics already documented in **`Windows/05 - Users, Groups & Authentication.md`**'s Logon Types table rather than re-deriving it here:

- **Logon Type mismatch with the protocol used** — relay to SMB/LDAP/RPC/MSSQL/IMAP all produce **Type 3 (Network)** logons on Target B, per that table's row for Type 3; a Type 3 logon carrying a workstation-name field that doesn't match the victim's actual computer name is the single strongest per-event tell.
- **`WorkstationName` field** in the 4624 record — for a genuine network logon this is populated with the client's real NetBIOS name; for a relayed logon it reflects whatever `ntlmrelayx.py`'s listener sent, which is either blank, generic, or (depending on which listening server handled the inbound leg) doesn't match the victim's real hostname at all. Compare this field against the `IpAddress` field too — a **relay host's IP paired with a workstation name that resolves to a completely different, unrelated machine** (or to no machine on the network at all) is the concrete, checkable version of this note's red-flag principle.
- **`IpAddress` is the relay host, never the victim** — this is the one field that is *always* wrong in a relay, unconditionally, regardless of which evasion flags (`--remove-mic`, `--remove-sign-seal`) are in play, because it is a structural property of relaying (Target B's TCP connection terminates at the relay host, full stop) rather than something the NTLM protocol exchange itself carries. **This is the single most invariant signal in this entire note** — see `05 - Detection and Hunting.md`'s priority table.

## Victim-Side Evidence — the Hijacked Host

The victim's own machine generates **little to nothing distinctive** from this specific technique — it authenticated to what it believed was a legitimate destination and, from its own local perspective, nothing failed. What victim-side evidence does exist:

| Source | What it shows | Prerequisite |
|---|---|---|
| Sysmon Event ID 3 (Network Connection) on the victim | An outbound connection to the relay host's IP, on the protocol/port the victim's client software intended to reach its real destination on — this is the closest thing to "proof the victim was talking to the wrong host" available on the victim side itself | Sysmon deployed with network-connection logging enabled for the relevant process |
| Sysmon Event ID 22 (DNS Query), if poisoning-triggered | A failed/`NXDOMAIN`-adjacent or stale name lookup immediately preceding the anomalous outbound connection above — the LLMNR/NBT-NS-poisoning-specific victim-side signature, fully covered in `Responder/04 - Target Evidence.md` rather than re-derived here | Sysmon DNS-query logging enabled |
| **Microsoft-Windows-NTLM/Operational**, Event IDs **8001-8004** | If **Restrict NTLM: Audit outgoing NTLM traffic to remote servers** is enabled, the victim's own NTLM-client stack logs the **server name it believed it was authenticating to** — a direct, victim-side record of intended-destination-vs-actual-destination mismatch, independent of anything on Target B's log at all | **Not enabled by default** — requires three separate GPO settings (audit NTLM authentication, audit incoming/outgoing NTLM traffic) turned on ahead of the incident; absence of these events proves nothing if the policy was never enabled |
| Whatever triggered the authentication in the first place | Coercion-primitive artifacts (PetitPotam/PrinterBug/ShadowCoerce RPC calls landing on the victim) or LLMNR/NBT-NS/mDNS poisoning response acceptance | Fully covered in `Responder/04 - Target Evidence.md` and MITRE [T1187](https://attack.mitre.org/techniques/T1187/)'s technique page — not re-derived here |

**Practical implication:** an investigation that only has the victim's own logs, with none of the above non-default auditing enabled, will most likely find **no evidence at all** that the victim's authentication was hijacked — the entire evidentiary weight of this technique sits on Target B and on whatever coercion/poisoning primitive is in play. Don't expect the victim's log to carry the story.

## Target B — SMB Relay

Default (no `-c`/`-e`) — verified SAM-only dump, see `02`'s correction:

- **This is the same Remote-Registry-based technique as `secretsdump.py`'s Path 1**, minus the LSA-Secrets/cached-creds legs — the full filesystem/registry/event-log/Sysmon/network-layer evidence table for that mechanism (the `%SystemRoot%\Temp\<8-random-letters>.tmp` hive-copy pattern, System 7036 for `RemoteRegistry`, Security 5140/5145, Sysmon 11/23) is documented in **`Impacket/secretsdump/04 - Target Evidence.md`**'s "Path 1 — Remote Registry" section and applies here without modification. Only difference: expect exactly one `.tmp` hive-copy cycle for `SAM`, never `SECURITY`.

`-c` (command execution) and `-e` (service-based file drop):

- **`-c` output relay file:** `ADMIN$\Temp\__output` — verified in `smbattack.py`. This is the **same filename `wmiexec.py`'s own transient output-relay file uses**; a Sysmon 11 (File Create) hit on exactly this path is a strong signal shared between both tools, not unique to one — see `Impacket/wmiexec/04 - Target Evidence.md` for that file's full write/read/delete cycle.
- **`-e` service install:** verified in `smbattack.py` to reuse the identical `serviceinstall.ServiceInstall` class `psexec.py` uses — expect the same random-4-character service name and random-cased 8-character dropped-binary pattern, System **7045** (service install), and the full evidence table already built in `Impacket/psexec/04 - Target Evidence.md`. Cross-link rather than re-derive.
- **`--add-computer` over SMB (SAMR):** verified in `smbattack.py` — a machine account is added via SAMR rather than LDAP, logged as `Successfully added machine account %s`. Produces Security **4741** (a computer account was created) on the DC that processed the SAMR call, and Security **4624** (Type 3) for the SMB session itself on the relay target.

## Target B — LDAP(S) Relay

All writes below require the corresponding Directory Service Access audit subcategory + a SACL on the modified object/attribute to generate a Security-log event at all — the same non-default-audit-policy caveat `Windows/05b`'s DCSync/4662 section already flags for this general class of AD-object evidence.

| Attack | Attribute/object changed | Primary event | Notes |
|---|---|---|---|
| Default — ACL attack (preferred path, see `02`'s correction) | `nTSecurityDescriptor` on the **domain object itself** | Security **5136** (directory service object modified), Attribute = `nTSecurityDescriptor` | The new ACE grants `DS-Replication-Get-Changes-All` to the escalated/created account — this is the event that shows a user quietly became DCSync-capable without ever touching the DA/Enterprise Admins group |
| Default — Group attack (fallback path) | Group membership | Security **4728**/**4732** (member added to a global/security-enabled local group) | This is the literal "added to Domain Admins"-style signature most write-ups describe — verified to fire only when the ACL path above wasn't available to the relayed identity |
| New user/computer created for either escalation path | New AD object | Security **4720** (user account created) or **4741** (computer account created) | Precedes whichever escalation event above by seconds — the creating account is the relayed identity, not a legitimate admin workflow |
| RBCD grant (`--delegate-access`) | `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer object | Security **5136**, Attribute = `msDS-AllowedToActOnBehalfOfOtherIdentity` | The `Get-ADComputer -Properties msDS-AllowedToActOnBehalfOfOtherIdentity` hunt already documented in `Windows/05b - Active Directory & Domain Forensic Artifacts.md`'s Hunt Evil section finds the **resulting state**; 5136 finds the **moment it was written** |
| Shadow Credentials (`--shadow-credentials`) | `msDS-KeyCredentialLink` on the target user/computer object | Security **5136**, Attribute = `msDS-KeyCredentialLink`; also Security **4738** (user account changed) or **4742** (computer account changed), since this is a generic-object-attribute-change event that fires alongside the more specific 5136 | The subsequent PKINIT authentication using the injected key produces its own Kerberos event trail — see the DCSync/Kerberos cross-links in `Windows/05b` for 4768/4769 mechanics generally |
| LAPS/gMSA/`info`-attribute/ADCS-template/pre-Windows-2000 dumps (`--dump-laps`, `--dump-gmsa`, etc.) | Read-only LDAP searches | Security **4662** (object access), if a SACL happens to be configured on the specific attribute (`ms-Mcs-AdmPwd`, `msDS-ManagedPassword`, etc.) | Uncommon by default — same rarity caveat that applies throughout this repo's registry/LDAP read-access hunts; absence of 4662 does not mean the read didn't happen |

## Target B — DCSync Relay (Zerologon Path)

> 🔴 **This is not a normal DCSync signature — read `02`'s use-case section first.** Because `-t dcsync://<dc>` actually executes the Zerologon exploit (CVE-2020-1472) against the target DC's own Netlogon RPC service before ever reaching DRSUAPI, the target-side evidence trail is dominated by the **Netlogon exploit attempt itself**, not by the eventual data pull.

| Source | Event ID / Signal | Notes |
|---|---|---|
| System log, `Microsoft-Windows-Netlogon` provider | **5829** — a vulnerable Netlogon secure-channel connection was **allowed** | Logging for this ID existed only in the pre-enforcement window (August 2020 – February 2021); **on any DC updated since Microsoft's enforcement phase began, this event no longer fires at all**, because the connection is rejected outright instead |
| System log, `Microsoft-Windows-Netlogon` provider | **5827** / **5828** — a vulnerable Netlogon secure-channel connection was **denied** | This is the **expected outcome on a modern, current DC** — a burst of these two IDs is direct, current evidence of an active Zerologon attempt, successful or not |
| Network/RPC layer | Up to **6,000** rapid `NetrServerReqChallenge`/`NetrServerAuthenticate3` RPC calls against the DC's Netlogon endpoint, from a single source, in a tight time window | A volumetric anomaly with no equivalent in a legitimate DCSync — see `05`'s priority table; visible in Zeek `dce_rpc.log` independent of any Windows-side audit policy |
| DRSUAPI leg (only reached on Zerologon success) | Same `IDL_DRSGetNCChanges` / Security **4662** signature as any other DCSync — full mechanics in `Mimikatz/lsadump (DCSync)/04 - Target Evidence.md` and `Impacket/secretsdump/04 - Target Evidence.md`'s Path 2 section, not re-derived here | With no `-auth-smb` supplied, expect exactly **three** `IDL_DRSGetNCChanges` calls for named objects (`krbtgt`, the DC's own machine account, `Administrator`) rather than a full-domain volumetric sweep — a materially smaller 4662 count than a genuine `-just-dc` pull, which is itself a distinguishing detail once audit policy is confirmed enabled |

Netlogon debug logging (`Nltest /dbflag:2080ffff` on the DC, if already enabled for troubleshooting) captures the raw `NetrServerAuthenticate3` failure/success sequence at a level of detail the Security/System logs don't — worth pulling specifically if a Zerologon attempt is suspected and this logging happened to already be on.

## Target B — ADCS Relay (HTTP/ESC8 and RPC/ICPR)

| Source | Event ID / Signal | Notes |
|---|---|---|
| CA server Security log | **4886** — Certificate Services received a certificate request | Requires the CA's own "Issue and manage certificate requests" audit category enabled — **not on by default** |
| CA server Security log | **4887** — Certificate Services approved a request and issued a certificate | Pair with 4886 by Request ID; the SAN/CN in the resulting certificate not matching the requesting account's real identity, or a `Machine`-template certificate issued to what should be a user relay, is the concrete anomaly to check for |
| CA server Security log | **4888** — Certificate Services denied a request | A denied request still proves an enrollment attempt occurred — useful even when the attack fails |
| IIS logs on the CA's web-enrollment role (HTTP path only) | `POST /certsrv/certfnsh.asp` followed by `GET /certsrv/certnew.cer?ReqID=...`, from a source IP that is the relay host, not the requesting account's normal workstation | The clearest network-layer confirmation for the HTTP/ESC8 path specifically — absent entirely for the RPC/ICPR path, which never touches the web role at all |
| RPC/network layer (ICPR path only) | MS-ICPR `CertServerRequest` RPC call, visible in Zeek `dce_rpc.log` | The only network-layer evidence for the RPC path — no IIS log exists because no HTTP request was ever made |
| Downstream — the certificate's own later use | Kerberos **4768** with a **Pre-Authentication Type** indicating certificate-based (PKINIT) authentication, on whatever DC services the eventual logon | This is where the persistence value of the stolen cert actually surfaces — potentially far later than the enrollment itself, and on a different host's log entirely |

## Target B — MSSQL Relay

No Windows Security-log event is generated by MSSQL relay/query execution on its own — SQL Server's own audit trail (SQL Server Audit, `sys.fn_get_audit_file`, or the plain Error Log if `xp_cmdshell` usage logging is enabled) is the only source, and it is off by default in most deployments. Security **4624** (Type 3) still fires for the underlying network authentication to the SQL Server service on Windows, which is the only free/default-enabled evidence available for this relay target without dedicated SQL auditing turned on ahead of time.

## Target B — WinRM Relay

Reuses the exact evidence model `Windows/12 - Lateral Movement.md`'s "PowerShell Remoting (WinRM)" section and `Windows/11 - Event Log Analysis.md`'s WinRM/Operational coverage already document — Security **4624** (Type 3), the destination-host `WinRM/Operational` log recording the WS-Man shell lifecycle (`Create`/`Command`/`Receive`/`Delete`), and PowerShell/Operational **4104** if script-block logging is enabled on the target and the relayed session runs PowerShell. Not re-derived here — the relay's local `TcpShell`/`WinRMShell` on the operator side is the only part of this that's unique to `ntlmrelayx.py`, and it produces no target-side artifact of its own.

## Target B — RPC/TSCH Relay

Reuses `Windows/10 - Persistence Mechanisms`' Scheduled Tasks evidence and `Windows/12 - Lateral Movement.md`'s "Remote Scheduled Tasks" row directly, since `rpcattack.py`'s TSCH mode is mechanically identical to `atexec.py`'s own register→run→poll→delete cycle: TaskScheduler/Operational **106** (task registered), **200**/**201** (task started/completed), Security **4624** (Type 3) for the underlying RPC session, and the task's own randomly-named `TaskCache` GUID entry in the registry. The create-then-delete-in-seconds pattern (verified in `02`'s ICPR/TSCH source citations) is the key tell — a legitimately scheduled task doesn't get deleted moments after its first run.

## Target B — SCCM Management Point / Distribution Point Relay

This relay target has the **thinnest Windows-native event-log footprint in this entire note** — SCCM's own server roles run as IIS applications, and the attack traffic looks, at the Windows Security-log level, like ordinary authenticated HTTP requests (Security 4624 Type 3, nothing more specific).

| Source | Signal | Notes |
|---|---|---|
| IIS W3C logs on the MP | `POST /ccm_system_windowsauth/request` (device registration) then `POST /ccm_system/request` (policy request), `User-Agent: ConfigMgr Messaging HTTP Sender` | The registration-then-sleep-then-policy-request pattern with a ~180-second gap between the two POSTs (the tool's default `--sccm-policies-sleep`) is the strongest available signal, and it's only visible in the web server's own log, not in Windows Security |
| IIS W3C logs on the DP | A rapid, recursive sequence of `GET /sms_dp_smspkg$/Datalib` then many `GET /sms_dp_smspkg$/<packageID>/...` requests from one source in a short window, `User-Agent: SMS CCM 5.0 TS` | The User-Agent string is **legitimate** SCCM client traffic and cannot be used alone as a discriminator — the *volume and recursion depth* against many/all package IDs from a single source in a tight window is the actual anomaly |
| SCCM's own component logs (`MP_RegistrationManager.log`, `PolicyAgent.log` on the MP; DP-side content-transfer logs) | A device registration/policy request from a client GUID and certificate that doesn't correspond to any real managed endpoint in the SCCM console | Requires access to SCCM's own log set, which is typically outside a Windows-event-log-only collection scope — flag as a follow-up source if SCCM abuse is suspected, not something this Impacket-focused note derives further |

## Target B — IMAP Relay

Evidence here depends entirely on the mail platform relayed against — an on-premises Exchange server's own transport/connectivity logs, or a cloud provider's authentication/audit log, neither of which is a Windows Security-log event and both of which are out of scope for a from-first-principles derivation in this note. If the mail platform is Exchange, cross-reference `Windows/15 - Email Forensics.md` for the platform-side evidence model; the Impacket-specific contribution here is limited to what's already covered in `02`'s use case (the `.eml` naming pattern and `SEARCH`/`FETCH` IMAP verbs used, visible at the network layer via any IMAP-aware sensor regardless of platform).

## Building a Timeline

Because Target B's evidence is split across as many as nine structurally different protocols, a timeline has to anchor on the **one moment common to every relay path** — the first successful NTLM Type 3 forward — and build outward from there:

```
[Victim's original outbound connection attempt — Sysmon 3/22 if available, or the
 coercion-primitive/poisoning evidence in Responder/04 or T1187 territory]
        │
        ▼
[ntlmrelayx.py source-side: listener already bound, possibly hours earlier — 03]
        │
        ▼
[Target B: Security 4624 Type 3 — the relayed logon, WorkstationName/IpAddress mismatch]
        │
        ▼
[Protocol-specific attack-module evidence — pick the relevant section above]
        │
        ▼
[Loot landing in the operator's -l/lootdir — 03, correlatable by timestamp]
```

The **4624 on Target B is the pivot point** for correlating everything else — work backward from it to the victim's original (coerced or poisoned) connection attempt, and forward from it into whichever attack-module-specific evidence table above applies. For the DCSync/Zerologon path specifically, insert the Netlogon 5827/5828/5829 burst (or the raw RPC-call volume, if audit policy wasn't enabled) **before** the 4624/DRSUAPI leg, since the exploit attempt against Netlogon has to succeed before any DRSUAPI activity happens at all — a DCSync-relay timeline with DRSUAPI evidence but no preceding Netlogon-flood evidence should be treated as suspicious in itself (possible evidence gap, not a "cleaner" attack).
