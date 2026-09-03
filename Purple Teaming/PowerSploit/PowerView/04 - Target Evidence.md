# PowerView — Target Evidence

PowerView's "target" is the same thing AdFind's is: **a domain controller answering authenticated LDAP reads**, plus (for the session/local-admin-hunting functions) a SAMR endpoint on every enumerated member computer. This page leans heavily on two already-built pages rather than re-deriving their mechanics: `Purple Teaming/LOLBins/powershell/04 - Target Evidence.md` for the PowerShell-engine-side logging subsystem (Script Block/Module Logging, transcription, the classic-vs-Operational channel split), and `Purple Teaming/AdFind/04 - Target Evidence.md` for the near-absence of default DC-side LDAP-query logging. Verified live (2026-08-04) that both pages' findings still hold — nothing in Microsoft's current `about_Logging`/`about_Logging_Windows` reference pages has changed the 4103/4104 default-off posture, and DC-side Directory Service Diagnostics (Event 1644) is still off by default per the same `Field Engineering` registry-value mechanism.

## Contents
- [PowerShell-Logging-Driven Evidence — Cross-Linked, Not Re-Derived](#powershell-logging-driven-evidence--cross-linked-not-re-derived)
- [LDAP Query Telemetry on the Domain Controller](#ldap-query-telemetry-on-the-domain-controller)
- [SAMR-Based Session/Local-Admin Enumeration on Member Computers](#samr-based-sessionlocal-admin-enumeration-on-member-computers)
- [Directory Writes — The Fork-Only ACL/RBCD/DCSync-Rights Functions](#directory-writes--the-fork-only-aclrbcddcsync-rights-functions)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Behavior](#endpoint-security-product-behavior)
- [Building a Timeline](#building-a-timeline)

---

## PowerShell-Logging-Driven Evidence — Cross-Linked, Not Re-Derived

Whatever content-level visibility exists into a PowerView session comes from the **executing PowerShell engine's own instrumentation**, on whichever host that engine runs — not from anything PowerView itself writes. `LOLBins/powershell/04 - Target Evidence.md` already documents this in full; the key points, re-confirmed live and restated here only as a pointer:

| Source | Default state | What it would show for a PowerView session |
|---|---|---|
| Module Logging (4103) | **Off** | Pipeline execution detail — which PowerView function was called, with what parameter values |
| Script Block Logging (4104) | **Off**, except a narrow PS 5.0+ Warning-level heuristic for a hardcoded suspicious-strings list | The full decoded text of the PowerView script itself, including every function definition |
| Classic "Windows PowerShell" channel, Event 400 | **On** by default | Session start with the full `HostApplication` command line — catches a `-EncodedCommand`-wrapped download cradle even with zero PowerShell-specific configuration |
| Transcription | **Off** | Every command and its output, in plaintext, if enabled |
| `pwsh.exe` (PS7) events | Separate `PowerShellCore/Operational` channel/provider, must be manually registered | A hunt scoped only to the classic `Microsoft-Windows-PowerShell/Operational` channel misses PS7-hosted PowerView entirely |

**The practical consequence for PowerView specifically:** on the large majority of real-world estates (logging not specially configured for this), the only PowerShell-engine-level evidence that a script ran at all is Event 400's command line — which shows the *invocation* (e.g. a download-cradle one-liner) but not which PowerView functions were subsequently called or what they returned. That detail either lived only in memory (see `03 - Source Evidence.md`) or is entirely absent.

## LDAP Query Telemetry on the Domain Controller

Directly inheriting `AdFind/04 - Target Evidence.md`'s finding, re-verified live: **Windows domain controllers do not log LDAP search content by default.** The one native mechanism that can capture a query — Directory Service Diagnostics Event **1644** — requires the non-default `Field Engineering` registry value and, by design, only fires for searches that cross an expensive/slow threshold. PowerView's LDAP queries are built the same way AdFind's are (targeting indexed attributes like `objectCategory`/`objectClass`), so the same caveat applies: a typical PowerView query is fast enough to never trigger 1644 even where diagnostics were already turned on for unrelated performance-troubleshooting reasons.

**One distinction from AdFind worth flagging directly:** PowerView's `Find-InterestingDomainAcl`/`Find-DomainShare`/`Find-DomainUserLocation`-class functions issue **far more individual LDAP round-trips per invocation** than a single AdFind command — a domain-wide ACL sweep or share-finder run against a large domain can generate thousands of discrete searches in a short window. Even with 1644 diagnostics off, this makes PowerView's DC-side connection *volume* (see Network-Layer Evidence below) a comparatively stronger anomaly signal than AdFind's typically much smaller number of individual queries — the content is equally invisible, but the shape of the traffic is more distinctive.

## SAMR-Based Session/Local-Admin Enumeration on Member Computers

`Find-LocalAdminAccess`, `Find-DomainUserLocation`, and the underlying `Get-NetSession`/`Get-NetLoggedon`-style helpers query each target computer's SAMR endpoint directly (see `01 - Overview.md`'s reflective-P/Invoke mechanics) rather than the DC. This has its own, separate evidentiary gap:

- **No dedicated Windows Security event exists for a SAMR session/local-group enumeration query by default.** Unlike a logon, this is a read against the target's own local SAM/session state over an already-established authenticated connection — it does not itself generate a 4624/4625 logon event distinct from whatever connection (SMB session, prior logon) was already in place.
- Hardened SAMR access restrictions (the `RestrictRemoteSAM` policy, `NT AUTHORITY\NETWORK` access to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSAM`, on by default since Windows 10 1607/Server 2016) can cause these queries to fail for non-admin callers on hardened builds — meaning a failed `Find-LocalAdminAccess` sweep against a hardened estate is itself weak evidence of *attempted* access, if the failure mode is otherwise observable (process/network activity present, useful SAMR result absent).
- Where object-access auditing is explicitly configured with a SACL on the relevant SAM objects (not a default configuration), Event **4661** (a handle to an object was requested) can surface — flagged as a non-default, environment-specific possibility rather than something to plan a detection strategy around.

## Directory Writes — The Fork-Only ACL/RBCD/DCSync-Rights Functions

`Add-DomainObjectAcl`, `Set-DomainObjectSD` (fork-only), and `Set-DomainRBCD` (fork-only) are **writes** to the directory, not reads — this changes the evidence picture meaningfully from the rest of PowerView's read-only surface:

- The write itself is a standard LDAP modify operation against the target object's `nTSecurityDescriptor` (ACL functions) or `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) attribute.
- Per `LOLBins/setspn/04 - Target Evidence.md`'s already-verified finding for a structurally identical problem (an attribute write, not a group-membership or delegation-trust change that has its own dedicated event): **Event 4738 does not cover this** — 4738's "User Account Management" auditing tracks a specific fixed set of attributes (including `msDS-AllowedToDelegateTo`, but not `nTSecurityDescriptor` or `msDS-AllowedToActOnBehalfOfOtherIdentity`). The actual signal is **Event 5136** (Directory Service Changes), which requires **both** the non-default "Audit Directory Service Changes" advanced audit policy **and** a SACL configured on the specific object/attribute — neither is on by default. Where 5136 auditing *is* configured, it records the old and new attribute values, the modifying principal, and the object modified — a strong, precise signal when present, but not something to assume exists.
- `Get-DomainDCSync`, `Get-DomainRBCD`, and `Get-DomainLAPSReaders` (all fork-only) are **read-only rights checks** — they decode an already-readable ACL to answer "do I have this right," and generate no write-side evidence at all. The actual DCSync pull, once rights are confirmed, is a separate operation covered by `Mimikatz/lsadump (DCSync)/` and `Impacket/secretsdump/`'s own Event 4662 discussion.

## Network-Layer Evidence

The one evidence class reliably present regardless of DC/SAMR logging configuration, because it's produced below the application-audit layer:

| Source | What it shows |
|---|---|
| Firewall / network-flow logs at or in front of the DC | Inbound connections on 389/636/3268/3269 (LDAP), 88 (Kerberos, `Invoke-Kerberoast`), 445/135+dynamic (SAMR) — source IP, timestamp, duration, and (for a volumetric tool like PowerView) connection/request **count**, which is where PowerView's higher per-invocation query volume (noted above) becomes the more useful anomaly signal versus a single-query tool like AdFind |
| Zeek `ldap.log`/`kerberos.log` (if the segment is monitored) | Structured bind/request metadata for unencrypted LDAP and cleartext-visible Kerberos exchange fields; LDAPS (636/3269) is opaque to a passive sensor without TLS inspection, same caveat as `AdFind/04 - Target Evidence.md` |
| NetFlow / switch logs | A source host issuing a high volume of short LDAP/SAMR connections to many domain computers in a short window (the `Find-LocalAdminAccess`/`Find-DomainUserLocation` fan-out pattern) is a distinctive flow shape independent of any host-level logging — see `05 - Detection and Hunting.md`'s fleet-wide sweep block |

## Endpoint Security Product Behavior

No target-side (DC) endpoint-security angle distinct from what's already covered — the DC isn't running PowerView, it's answering queries from it, exactly as `AdFind/04 - Target Evidence.md` notes for that tool. On **member computers** targeted by the SAMR-based hunting functions, an EDR product with SAMR/network-behavioral visibility (not a file- or process-based detection, since no PowerView-related file or process exists on the queried computer) is the relevant angle, if the product has that telemetry class at all.

## Memory Forensics

Because PowerView runs entirely on the **source** side of every interaction documented on this page, target-side memory forensics contributes nothing PowerView-specific — see `03 - Source Evidence.md`'s Memory-Forensics Angle section for where that analysis actually applies.

## Building a Timeline

Given how thin native target-side logging is by default, timeline-building for a PowerView operation is, like AdFind's, primarily a **source-side exercise correlated against sparse target-side network telemetry**: `[Sysmon 1 / Security 4688 on the source host, if the engine launched directly]` → `[outbound LDAP/Kerberos/SAMR connections in the same window, source-side netstat/EDR or target-side firewall/NetFlow]` → `[Event 5136 on the DC, only if Directory Service Changes auditing + a SACL were already configured and a write function (Add-DomainObjectAcl/Set-DomainRBCD) was used]`. See `05 - Detection and Hunting.md`'s Hunting Priority table for how this shapes which signal to hunt on first.
