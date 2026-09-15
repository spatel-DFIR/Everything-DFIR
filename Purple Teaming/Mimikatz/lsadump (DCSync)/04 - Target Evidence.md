# Mimikatz — lsadump (DCSync) — Target Evidence

"Target" means different hosts for different sub-commands here, and that split matters for how to read this file. For **`dcsync`, `trust` (when queried remotely), and `netsync`**, the target is the **Domain Controller** being asked to replicate/authenticate — a genuinely separate host from the operator, exactly like a normal lateral-movement scenario. For **`sam`/`secrets`/`cache`/`trust` (default, local)**, the "target" is whichever host the operator is running mimikatz *on* — there's no network hop at all unless that host was itself reached via a prior remote-execution chain (in which case, see `Impacket/psexec/04 - Target Evidence.md` for that leg). This file leads with **DCSync's DC-side evidence**, since it's this module's headline technique and the deepest, most distinctive evidentiary trail — the local-extraction sub-commands get comparatively thinner treatment, flagged as such rather than padded.

## Contents
- [DCSync: Filesystem and Registry on the DC](#dcsync-filesystem-and-registry-on-the-dc)
- [DCSync: Windows Security Event Log — Event 4662](#dcsync-windows-security-event-log--event-4662)
- [DCSync: Sysmon on the DC](#dcsync-sysmon-on-the-dc)
- [DCSync: Network-Layer Evidence (MS-DRSR / drsuapi)](#dcsync-network-layer-evidence-ms-drsr--drsuapi)
- [DCSync: Endpoint/Identity Security Product Signatures](#dcsync-endpointidentity-security-product-signatures)
- [DCSync: Memory Forensics](#dcsync-memory-forensics)
- [DCSync: Building a Timeline](#dcsync-building-a-timeline)
- [sam / secrets / cache: Local Target Evidence](#sam--secrets--cache-local-target-evidence)
- [trust: Target Evidence](#trust-target-evidence)
- [netsync: Target Evidence](#netsync-target-evidence)
- [Distinguishing DCSync from Legitimate DC-to-DC Replication](#distinguishing-dcsync-from-legitimate-dc-to-dc-replication)

---

## DCSync: Filesystem and Registry on the DC

**None.** This is the sharpest possible contrast with a technique like Impacket's `psexec`: `IDL_DRSGetNCChanges` is a read-only RPC call the DC answers entirely from its own AD database and in-memory replication state. It writes no file, creates no service, and touches no registry key on the DC. There is no filesystem or registry artifact to look for here at all — say so plainly rather than padding this section, exactly as `sekurlsa/04 - Target Evidence.md` does for its own thin filesystem section.

## DCSync: Windows Security Event Log — Event 4662

**The headline event for this entire technique**, but it comes with real prerequisites that don't exist by default — understanding those prerequisites is as important as the event itself.

| Field | Value for a DCSync-style request |
|---|---|
| Event ID | **4662** — "An operation was performed on an object" |
| `ObjectServer` | `DS` (Directory Service) |
| `ObjectType` | The **domainDNS** class schema GUID, `19195a5b-6da0-11d0-afd3-00c04fd930c9` — confirms the object being accessed is the domain naming-context head itself |
| `AccessMask` | **`0x100`** — Control Access (`ACTRL_DS_CONTROL_ACCESS`) |
| `Properties` | Contains one or more of the three extended-right GUIDs (verified against `[MS-ADTS]`): **`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`** (`DS-Replication-Get-Changes`), **`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`** (`DS-Replication-Get-Changes-All`), **`89e95b76-444d-4c62-991a-0facbeda640c`** (`DS-Replication-Get-Changes-In-Filtered-Set`) |
| `SubjectUserName`/`SubjectUserSid` | The account that made the request — this is the field the whole detection hinges on |

**Both of these must already be true, and neither is default, for 4662 to fire at all for this activity:**
1. The **Advanced Audit Policy** subcategory **"Audit Directory Service Access"** must be enabled for Success events — off by default on a stock Default Domain Controllers Policy.
2. A **SACL entry auditing that access** must exist on the domain NC head object itself (commonly, an audit ACE for `Everyone`/`Authenticated Users` covering the Control Access right) — enabling the audit-policy subcategory alone does **not** retroactively add this; it has to be configured separately.

Both are widely recommended as baseline AD-monitoring hardening (Microsoft's own Security Compliance Toolkit and most enterprise SIEM/AD-monitoring guidance include this exact configuration specifically *because* it's what makes DCSync detection possible) — but confirm both are actually in place in a given environment before treating an absence of 4662 hits as "clean." An environment that has never configured this SACL will show **nothing** for a DCSync run, regardless of how it happened.

```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} |
  Where-Object { $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c' }
```

**False-positive baseline — this is not optional context, it's required for the detection to be usable at all:** every real DC's own computer account performs this exact access constantly as part of ordinary AD replication. Any working detection **must** exclude:
- Accounts ending in `$` (computer accounts — covers every legitimate DC)
- `NT AUTHORITY\SYSTEM` and similar built-in system principals
- Known legitimate non-DC holders — most commonly an **Azure AD Connect / Microsoft Entra Connect** sync account (frequently named `MSOL_<hash>` in the on-prem directory), which requires exactly these rights by design for password-hash sync

A 4662 hit from an account **not** in that allow-list — especially a human/service account with no legitimate replication reason — is the specific signature to alert on.

## DCSync: Sysmon on the DC

Sysmon adds comparatively little here, since the entire technique is a single authenticated RPC call rather than a process-spawning or file-writing operation on the DC itself:

| Event ID | Relevance |
|---|---|
| 3 (Network Connection) | If the DC's own Sysmon config logs inbound connections (uncommon — Sysmon 3 is usually tuned for outbound-from-this-host), a connection to TCP/135 followed by a dynamic high port from a non-DC source IP is visible here too — redundant with, but independently corroborating, the network-layer evidence below |
| 1 (Process Create) | **Not applicable** — no new process is created on the DC to service the RPC call; it's handled by `lsass.exe`'s existing NTDS/DRS service code, which is already running |

Sysmon's real value for this module is on the **operator's** side (`03 - Source Evidence.md`), not the DC's.

## DCSync: Network-Layer Evidence (MS-DRSR / drsuapi)

This is the strongest **evasion-resistant** signal available for DCSync, because it doesn't depend on any audit policy or SACL being pre-configured — it's a property of the traffic itself:

| Artifact | Notes |
|---|---|
| Zeek `dce_rpc.log` | Zeek's DCE-RPC analyzer natively recognizes the `drsuapi` interface (UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2`) — a `dce_rpc.log` entry with `endpoint == "drsuapi"` and `operation` resolving to `IDL_DRSGetNCChanges`, where `orig_h` (the connection's source) is **not** one of the domain's known DC IPs, is a direct, audit-policy-independent detection |
| RPC endpoint-mapper query (TCP/135) followed by a connection to a dynamic high port | The two-step pattern any `ncacn_ip_tcp` RPC bind produces — visible in NetFlow/firewall logs even without full packet decode, though this pattern alone isn't unique to DRSUAPI (any RPC service uses the same handshake) |
| Segmentation/firewall logs showing a DC accepting an inbound connection from an unexpected network segment | If DCs are properly network-segmented (a real, meaningful mitigating control — see `05 - Detection and Hunting.md`), a connection attempt from a workstation VLAN or a non-DC subnet is itself an anomaly worth alerting on, independent of whether the RPC call ever completes |

## DCSync: Endpoint/Identity Security Product Signatures

- **Microsoft Defender for Identity (formerly Azure ATP)** ships a purpose-built, out-of-the-box detection: **"Suspected DCSync attack (replication of directory services)"** (external ID **2006**), which specifically fires when a replication request using MS-DRSR is initiated from a machine that isn't a Domain Controller. This is a sensor-based detection (Defender for Identity's sensor runs on the DC itself, observing the DRS traffic directly) rather than a log-based one — it does **not** depend on the Event 4662 audit-policy/SACL prerequisites above, making it meaningfully more reliable in environments that haven't configured that auditing. It shares the same false-positive population as the 4662 hunt (a misconfigured or newly-onboarded Azure AD Connect/Entra Connect sync account is the most common cause of a benign trigger).
- **Generic EDR/NDR products** with AD-aware detection logic increasingly implement equivalent DRSUAPI-source monitoring independently of Microsoft's own tooling — verify what a specific deployed product actually covers rather than assuming DCSync detection is automatic just because an EDR agent is present on the DC.
- There is **no meaningful static-file signature angle** for DCSync at all — unlike `sekurlsa`, where the dropped `mimikatz.exe` binary itself carries near-universal AV signature, DCSync's payload is a protocol exchange, not an executable. A reflectively-loaded mimikatz DLL running `lsadump::dcsync` is exactly as detectable via file signature as one running `sekurlsa::logonpasswords` — which is to say, not at all, once loaded reflectively (`00 - Mimikatz Overview.md`). File-based detection is simply the wrong layer for this technique.

## DCSync: Memory Forensics

- **On the DC:** unaltered by a read-only DCSync call — there's no content-level change to recover forensically from `lsass.exe`'s (or `ntdsai.dll`'s in-process state within it) memory on the DC side. A memory capture of the DC around the time of an incident is far more useful for confirming *what the DC's own replication-service logging shows* than for finding attack residue in memory, since the DC did nothing exceptional at the OS level to service the request.
- **On the operator's side:** covered in `03 - Source Evidence.md` — the recovered credential material exists in the calling process's memory, not the DC's.

## DCSync: Building a Timeline

```
[DNS query for _ldap._tcp.dc._msdcs.<domain>, if /dc: wasn't specified — operator-side]
  → [RPC bind: TCP/135 then dynamic port, operator → DC — Zeek dce_rpc.log / NetFlow]
  → [IDL_DRSBind — no distinct log signature]
  → [IDL_DRSGetNCChanges — Security 4662 on the DC, if audited (see prerequisites above);
     MDI alert 2006, if deployed, independent of that audit configuration]
  → [reply parsed on the operator's own machine — no further DC-side artifact]
  → [process exit on the operator's machine]
```
For a **full-domain pull (`/all`)**, expect this sequence to repeat as many `IDL_DRSGetNCChanges` round-trips as needed to page through every object — a burst of many 4662 events (or MDI alert triggers) against the same `SubjectUserSid` in a tight time window, rather than the single hit a targeted `/user:` pull produces. That volumetric shape is itself a useful discriminator between "someone DCSync'd one account" and "someone DCSync'd the domain" even before looking at which accounts were targeted.

---

## sam / secrets / cache: Local Target Evidence

Thin, by the same logic `sekurlsa/04 - Target Evidence.md` applies to its own live-read path — these commands read local registry state, they don't write anything as part of normal operation:

| Artifact | Notes |
|---|---|
| Filesystem | **None**, live mode. Offline mode (`/system:`/`/sam:`/`/security:`) leaves whatever copied hive files the operator staged — standard execution-evidence trail (Prefetch/Amcache/ShimCache) applies to `vssadmin.exe` if used to create the shadow copy those hives were pulled from, not to mimikatz itself |
| Registry | **No write** as part of normal operation — `HKLM\SAM`/`HKLM\SECURITY` are read-only accessed. `HKLM\SYSTEM\...\Control\Lsa\{JD,Skew1,GBG,Data}` (the boot-key material, `01 - Overview.md`) is pre-existing configuration, not evidence generated by running the command |
| Windows Security Event Log | **4656/4663** (object access), if a SACL happens to be configured on the `SAM`/`SECURITY` hive keys themselves — uncommon, same rarity caveat as `sekurlsa/04 - Target Evidence.md`'s equivalent note for `lsass.exe` |
| Sysmon | Event 1 for `mimikatz.exe`/the hosting process, if run interactively on this host — same general pattern as `sekurlsa/04 - Target Evidence.md`. Event 12/13/14 (Registry) if Sysmon's registry-auditing config happens to cover `HKLM\SAM`/`HKLM\SECURITY` reads specifically (uncommon default tuning) |
| VSS usage, if offline mode was used to bypass the live-hive lock | `vssadmin.exe create shadow` generates Security Event **8222** and leaves the shadow copy itself discoverable (`vssadmin list shadows`) until deleted — a distinctive artifact worth checking whenever an offline hive-extraction technique is suspected |

## trust: Target Evidence

Same thin local-registry/LSA-policy shape as `sam`/`secrets` for the **default** call. The **`/patch`** variant is materially different and should be evaluated the same way `sekurlsa/04 - Target Evidence.md` evaluates `sekurlsa::pth`: it opens `lsass.exe` with `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION` — a write-capable handle — to patch `lsasrv.dll`/`lsadb.dll` in memory. **Sysmon Event 10 (Process Access)** against `lsass.exe` carrying write-capable access bits from a non-allow-listed `SourceImage` is the relevant signal here, using the same `GrantedAccess`-mask reasoning `sekurlsa/04 - Target Evidence.md`'s "Deep Dive" section builds out in full — not re-derived here.

## netsync: Target Evidence

`netsync` targets a DC over the legacy **Netlogon** protocol (`I_NetServerReqChallenge`/`I_NetServerAuthenticate2`/`I_NetServerTrustPasswordsGet`), not DRSUAPI. There is **no equivalent to Event 4662** for this path — Netlogon secure-channel establishment isn't an AD-object access in the same sense DCSync is, so it doesn't route through Directory Service auditing at all. The most durable target-side signal is **network-layer**: Zeek and most DCE-RPC-aware NDR tooling recognize the Netlogon (`MS-NRPC`) interface distinctly from `drsuapi`, so a `netsync` call is visible as Netlogon RPC traffic from a non-DC source rather than DRSUAPI traffic — verify against whatever specific network-monitoring stack is deployed, since generic signature coverage for legacy Netlogon secure-channel calls (as opposed to the well-known Zerologon exploit pattern specifically) is less consistently documented than DCSync's.

## Distinguishing DCSync from Legitimate DC-to-DC Replication

> 🔴 **The one thing this technique cannot fake:** every field in a DCSync `IDL_DRSGetNCChanges` call — the RPC interface, the opnum, the request flags, the returned attribute values — is **byte-for-byte identical** to what a real DC sends and receives during ordinary replication. There is no "attack mode" flag anywhere in the protocol. The **only** distinguishing fact, ever, is whether `SubjectUserSid` in Event 4662 (or the source of the MDI alert) corresponds to an actual Domain Controller computer account. Any detection strategy that tries to distinguish DCSync from legitimate replication by looking at *how* the call was made rather than *who* made it is looking at the wrong layer entirely.
