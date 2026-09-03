# Mimikatz — kerberos (Golden/Silver Ticket) — Target Evidence

"Target" splits into up to **three** distinct hosts for this module, and which ones are even in play depends entirely on Golden vs. Silver:

- **The Domain Controller (KDC)** — sees a Golden Ticket's first TGS-REQ (`01 - Overview.md` step 3). **Never sees a Silver Ticket at all, at any point.** This is the single most consequential fact in this entire file.
- **The target application server** — sees the `AP-REQ` for both variants; this is the only host a Silver Ticket ever touches.
- **A remote pivot host**, if `kerberos::ptt` was run there rather than on the operator's own machine — carries the same local-ticket-cache evidence `03 - Source Evidence.md` describes, just relocated; cross-reference whatever lateral-movement chain got the operator there.

This file leads with the **DC-side evidence for Golden Tickets**, since it's the deepest and most-tooled detection surface in the entire module — then covers the target-application-server evidence both variants share, and closes with the stark **Silver Ticket detection gap** this split creates.

## Contents
- [Domain Controller: Filesystem and Registry](#domain-controller-filesystem-and-registry)
- [Domain Controller: Windows Security Event Log — 4768/4769](#domain-controller-windows-security-event-log--47684769)
- [Domain Controller: Sysmon](#domain-controller-sysmon)
- [Domain Controller: Network-Layer Evidence](#domain-controller-network-layer-evidence)
- [Domain Controller: Microsoft Defender for Identity Alerts](#domain-controller-microsoft-defender-for-identity-alerts)
- [Target Application Server: Event Logs and Access Evidence](#target-application-server-event-logs-and-access-evidence)
- [Target Application Server: Memory Forensics](#target-application-server-memory-forensics)
- [Remote Pivot Host (If `kerberos::ptt` Ran There)](#remote-pivot-host-if-kerberosptt-ran-there)
- [Building a Timeline](#building-a-timeline)
- [The Silver Ticket Detection Gap](#the-silver-ticket-detection-gap)

---

## Domain Controller: Filesystem and Registry

**None, for either variant.** Neither forging nor presenting a ticket writes any file or registry key on a DC — the entire technique is protocol-level. Say so plainly, as the sibling notes in this folder set do for their own thin filesystem sections, rather than padding it.

## Domain Controller: Windows Security Event Log — 4768/4769

**Applies to Golden Tickets only.** A Silver Ticket generates **zero** entries in this section, ever — see [The Silver Ticket Detection Gap](#the-silver-ticket-detection-gap) below.

| Event ID | Meaning | Relevance here |
|---|---|---|
| **4768** | "A Kerberos authentication ticket (TGT) was requested" — the AS-REQ/AS-REP exchange | **Never fires for the forged ticket itself** — it was never issued by a real AS-REQ. This absence is the headline signature |
| **4769** | "A Kerberos service ticket was requested" — the TGS-REQ/TGS-REP exchange | **Fires the first time the forged "TGT" is used** (`01 - Overview.md` step 3) — this is the earliest DC-side artifact a Golden Ticket produces, full stop |
| 4770 | A Kerberos service ticket was renewed | Fires if the forged ticket's renewal window (`/renewmax`) is exercised — same absence-of-4768 logic applies |
| 4771 | Kerberos pre-authentication failed | Not directly relevant — pre-auth doesn't occur for a forged ticket's first use, since there's no AS-REQ at all |

**The core detection logic — worth stating precisely, since it's frequently oversimplified:** Windows Security events carry no literal "ticket ID" field that would let a 4769 be directly joined back to a specific prior 4768 the way a database foreign key would. The correlation is **heuristic**: a 4769 for a given `TargetUserName`/`ServiceName` with **no** 4768 for that same account in a plausible preceding window (accounting for legitimate ticket renewal across multiple 4769s from one original 4768) is the tell — not a literal missing-reference lookup. Two additional 4769 fields matter directly:

- **`Ticket Encryption Type`** — `0x17` (RC4-HMAC) is the classic anomaly signal (`05 - Detection and Hunting.md`) on a domain that has otherwise moved to AES; `0x12` (AES256-CTS-HMAC-SHA1-96) or `0x11` (AES128) defeats this specific signal entirely (`02 - Hands-On Use Cases.md`'s AES forging scenario)
- **Ticket lifetime fields** (`renew-till`, effectively derived from the ticket's stated validity) — a lifetime far exceeding the domain's **actual configured** Kerberos policy (`Maximum lifetime for user ticket`, default 10 hours) is what Microsoft Defender for Identity's "time anomaly" alert keys on, below

**A note the tool's own source substantiates directly (`01 - Overview.md`):** mimikatz hardcodes the forged ticket's key-version number (`TicketKvno`) to a fixed value (`2`, or an RODC-pattern value if `/rodc` is set) rather than the domain's actual current krbtgt key version. This mismatch exists **inside the encrypted ticket structure itself** — it is not a field exposed in any Windows Security event, and confirming it requires actually decrypting/parsing the presented ticket (a Rubeus `describe`/`triage`-style tool, or a Zeek Kerberos plugin with the key available) rather than a native-log hunt. State this limitation explicitly rather than implying a native event-log hunt can see it — it can't.

## Domain Controller: Sysmon

Sysmon adds comparatively little here, for the same reason it added little to `lsadump (DCSync)/04 - Target Evidence.md`'s DC-side coverage — the technique is an authenticated protocol exchange, not a process-spawning or file-writing operation on the DC:

| Event ID | Relevance |
|---|---|
| 3 (Network Connection) | If the DC's Sysmon config logs inbound connections (uncommon default tuning), a connection on UDP/TCP 88 from the operator's host is visible — redundant with, but independently corroborating, the network-layer evidence below |
| 1 (Process Create) | **Not applicable** — the KDC service (`lsass.exe`'s existing Kerberos-package code) is already running; no new process services the request |

## Domain Controller: Network-Layer Evidence

This is the strongest **evasion-resistant** signal for Golden Tickets, for the same reason it was for DCSync (`lsadump (DCSync)/04 - Target Evidence.md`) — it doesn't depend on any Windows audit-policy configuration, only on network visibility:

| Artifact | Notes |
|---|---|
| Zeek `kerberos.log` | Zeek's Kerberos analyzer natively decodes AS-REQ/AS-REP/TGS-REQ/TGS-REP over port 88, including `client`, `service`, `success`, `cipher` (encryption type), and `forwardable` fields. **A TGS-REQ entry with no corresponding earlier AS-REQ/AS-REP for the same `client` principal, within the observation window**, is the direct network-layer equivalent of the missing-4768 signature above — and unlike the Windows event-log version, it's available even where DC audit logging is misconfigured or the logs haven't been forwarded |
| Encryption type field in `kerberos.log` | Same RC4-vs-AES anomaly signal as the 4769 field above, independently observable at the packet layer |
| Ticket lifetime fields | Same time-anomaly signal, independently observable |

**None of this applies to a Silver Ticket** — its only Kerberos-adjacent network traffic is the `AP-REQ`, which for most services travels embedded inside the *application* protocol itself (SPNEGO within an SMB2 Session Setup, an HTTP `Authorization: Negotiate` header, etc.) rather than as standalone traffic to port 88 — Zeek's `kerberos.log` and equivalent NDR Kerberos analyzers generally do not decode this embedded form, so there is no meaningful DC-adjacent or protocol-level network signal for a Silver Ticket to hunt for at all.

## Domain Controller: Microsoft Defender for Identity Alerts

**Golden Ticket only** — MDI's sensor runs on Domain Controllers, observing DC-side Kerberos traffic directly; a technique that never reaches a DC generates nothing for it to see. Verified against Microsoft's current alert documentation ([classic alerts](https://learn.microsoft.com/en-us/defender-for-identity/alerts-mdi-classic), [XDR-format alerts](https://learn.microsoft.com/en-us/defender-for-identity/alerts-xdr)):

| Alert name | Classic external ID | What it detects |
|---|---|---|
| Suspected Golden Ticket usage (**nonexistent account**) | **2027** | The TGS-REQ names an account that doesn't actually exist in AD — no learning period |
| Suspected Golden Ticket usage (**ticket anomaly**) | **2032** | Structural characteristics unique to forged tickets built by known tooling |
| Suspected Golden Ticket usage (**ticket anomaly using RBCD**) | **2040** | A variant where Resource-Based Constrained Delegation permissions were set using the krbtgt account for the targeted principal |
| Suspected Golden Ticket usage (**time anomaly**) | **2022** | The presented ticket's lifetime exceeds the domain's actual configured `Maximum lifetime for user ticket` Kerberos policy value — directly defeated by `02 - Hands-On Use Cases.md`'s backdating/lifetime-matching scenario |
| Suspected Golden Ticket usage (**encryption downgrade**) | **2009** | The TGT field's encryption method is weaker than previously learned/baselined behavior for that source computer/user, with no corresponding prior authentication request observed — directly defeated by forging with AES key material |
| Suspected Golden Ticket usage (**forged authorization data**) | **2013** | PAC manipulation exploiting legacy vulnerabilities (MS11-013/"Silver PAC", MS14-068/"Forged PAC") — largely a legacy-patch-gap detection, not the general modern forgery path this module covers |
| Possible Kerberos key list attack | (XDR-format; no classic numeric ID published) | The RODC-scoped `/rodc` variant (`02 - Hands-On Use Cases.md`) |

Every one of these depends on the MDI sensor observing DC-side Kerberos traffic — meaning **every one of them requires the ticket to reach a DC at all**, which only ever happens for a Golden Ticket. Cross-reference `lsadump (DCSync)/04 - Target Evidence.md` for the DCSync-specific alert (external ID 2006) that typically precedes this module's use in a real intrusion chain — obtaining the krbtgt key is a distinct, separately-alertable step from forging and using it.

## Target Application Server: Event Logs and Access Evidence

**This is the only detection surface a Silver Ticket ever produces, and it's the same surface a Golden Ticket's final hop produces too.** Once either variant's ticket is presented via `AP-REQ`, the target server processes it like any other Kerberos authentication:

| Artifact | Notes |
|---|---|
| Security 4624 (Logon) | Logon Type 3 (Network), authentication package `Kerberos`, on the target server — the forged identity's username and any group SIDs the PAC carried appear here exactly as they would for a legitimate logon, since the server has no independent way to know the PAC was fabricated |
| Security 4672 (Special privileges assigned) | Fires if the forged group memberships include any privileged group mapped to special-privilege logon rights (the default Golden Ticket group set — Domain Admins, Enterprise Admins — reliably triggers this on most servers) |
| Application-specific audit logs | SMB file-access auditing, RDP/WinRM session logs, or (for a Silver Ticket against a database/app service) that application's own authentication/authorization log — whatever the specific service normally produces for any authenticated session. This is genuinely no different from the target-side evidence any other lateral-movement/access technique leaves at this layer — see the relevant `Windows/` artifact-reference notes for the specific service involved (e.g. SMB access → `Windows/12 - Lateral Movement.md`) rather than re-deriving that table here, per this module's cross-linking convention |
| Sysmon Event 1 (Process Create) | Only relevant if the forged ticket was used to spawn a remote process (e.g. chained into `Impacket/psexec/` or WinRM) — Kerberos ticket presentation itself has no process-layer footprint; Sysmon's value here is entirely indirect, through whatever the ticket was subsequently used to do |

## Target Application Server: Memory Forensics

The target server's own `lsass.exe` accepts and caches the presented ticket/session exactly as it would for a legitimate authentication — a memory capture of the target server around the time of an incident recovers the accepted session, retrievable via `sekurlsa::logonpasswords`/`klist` run **on that server** (full-circle cross-link to `sekurlsa (Credential Dumping)/`). The server has no forensic marker distinguishing "this session came from a forged ticket" from "this session came from a real one" at the memory layer — that distinction only exists upstream, in whether a corresponding real 4768/AS-REQ chain exists (Golden) or never existed at all by design (Silver).

## Remote Pivot Host (If `kerberos::ptt` Ran There)

If the operator ran `kerberos::ptt`/`kerberos::golden /ptt` on a **compromised pivot host** rather than their own attack workstation, that host's own LSA ticket cache now carries the injected ticket — identical to the evidence category `03 - Source Evidence.md` describes for the operator's own machine, just relocated. Read this host as "target" for whatever remote-execution chain got the operator onto it in the first place (cross-reference `Impacket/psexec/04 - Target Evidence.md` or the equivalent for that leg), and as a **second** source-evidence location for this module's own technique.

## Building a Timeline

**Golden Ticket:**
```
[Forging — pure local computation, zero artifacts anywhere except the operator's own host/process memory]
  → [kerberos::ptt injection — local LSA call, zero network traffic]
  → [First resource access — Windows silently issues a TGS-REQ using the forged "TGT"]
      → [Security 4769 on the DC, NO preceding 4768 for this account — the headline signature]
      → [Zeek kerberos.log: TGS-REQ with no matching AS-REQ/AS-REP, independent of DC audit config]
      → [MDI alert(s), if deployed — 2027/2032/2009/2022/2040 depending on which anomaly the specific
         forging parameters happened to trip]
  → [AP-REQ to the target application server]
      → [Security 4624/4672 on the target server, application-specific audit logs]
```

**Silver Ticket:**
```
[Forging — pure local computation, zero artifacts anywhere except the operator's own host/process memory]
  → [kerberos::ptt injection — local LSA call, zero network traffic]
  → [AP-REQ DIRECTLY to the target application server — NO DC contact at any point, ever]
      → [Security 4624/4672 on the target server, application-specific audit logs]
      → [NOTHING on any Domain Controller. No 4768, no 4769, no MDI alert, no Zeek kerberos.log
         entry of any kind, because a DC was never involved at all]
```

## The Silver Ticket Detection Gap

> 🔴 **The one thing this file needs to leave no ambiguity about:** every DC-side detection mechanism described above — Event 4769's missing-4768 heuristic, Zeek's `kerberos.log` correlation, every Microsoft Defender for Identity Golden-Ticket-family alert — depends on the DC observing the ticket. **A Silver Ticket is built specifically so the DC never does.** The **only** place a Silver Ticket is observable at all is the one application server it targets, and at that layer it is — barring the rare case of full PAC validation being enabled (`01 - Overview.md`) — **indistinguishable from a legitimate authentication using that account's real credentials**. Effective Silver Ticket detection therefore isn't a log-signature problem the way Golden Ticket detection is; it's a **behavioral/authorization-anomaly problem** on the target application itself: does this account's access pattern, at this time, from this source, match what's normal for it? That's a fundamentally different (and harder) detection posture than anything else in this module, and it should be treated as such rather than assumed to inherit the DC-side tooling above.
