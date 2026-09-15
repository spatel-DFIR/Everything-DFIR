# Certipy — Target Evidence

Certipy's target-side footprint spans the same three systems `GhostPack/Certify/04 - Target Evidence.md` already documents in depth for the identical underlying AD CS mechanics — the **CA server**, the **domain controller(s)** holding the LDAP-readable PKI objects, and a **KDC** for the PKINIT redemption step — since both tools attack the same misconfigurations over the same protocols. This page cross-links that existing material rather than re-deriving it, and focuses on what's genuinely **Certipy-specific**: the `ca -backup` SVCCTL service-creation mechanic (see `01`'s Red Flag callout), the LDAP-write patterns behind `account`/`template`/`shadow`, and Certipy's own relay engine.

## Contents
- [The CA's Own Request Database — Cross-Linked, Not Re-Derived](#the-cas-own-request-database--cross-linked-not-re-derived)
- [CA-Side Security Event Log — Cross-Linked](#ca-side-security-event-log--cross-linked)
- [`ca -backup`'s Service-Creation Footprint on the CA Server](#ca--backups-service-creation-footprint-on-the-ca-server)
- [LDAP Enumeration — Same Silent-Read Gap](#ldap-enumeration--same-silent-read-gap)
- [Directory Service Writes — `account`, `template`, `shadow`](#directory-service-writes--account-template-shadow)
- [Shadow Credentials — Defender for Identity Alert](#shadow-credentials--defender-for-identity-alert)
- [Relay (ESC8/ESC11) — Network-Layer Evidence](#relay-esc8esc11--network-layer-evidence)
- [PKINIT / Schannel Authentication Evidence](#pkinit--schannel-authentication-evidence)
- [Endpoint-Security-Product Signature Behavior](#endpoint-security-product-signature-behavior)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)

---

## The CA's Own Request Database — Cross-Linked, Not Re-Derived

Every `certipy req`/`req -renew`/`req -retrieve` that reaches the CA at all lands in the CA's own persistent request database exactly as `GhostPack/Certify/04 - Target Evidence.md` documents — `certutil -view` queries this database regardless of which client (Certify, Certipy, `certreq.exe`, a browser against Web Enrollment) submitted the request, and regardless of whether Windows Security auditing is configured. Apply that page's `certutil -view -restrict "Request.RequesterName=..."` guidance directly; not repeated here.

**One Certipy-specific exception: `forge` never touches the CA database at all.** Because `forge` is fully offline (see `01`), an offline "Golden Certificate" minted from a stolen CA key generates **zero** CA-side database or event evidence at mint time — the only place it becomes visible is at *use* time, via the PKINIT/Schannel authentication it's later redeemed for (see below). A `certutil -view` sweep showing no record of a given identity's certificate does not rule out a forged one.

## CA-Side Security Event Log — Cross-Linked

The full `certutil.exe -setreg CA\AuditFilter`-gated 4868–4898 event catalog, and the two independent non-default configuration steps required before any of it fires, are documented in depth in `GhostPack/Certify/04 - Target Evidence.md`'s "CA-Side Security Event Log" section — apply that table directly against `certipy req`/`ca -enable-template`/`ca -issue-request`/`ca -deny-request`/`ca -add-officer` exactly as written for Certify's equivalent verbs (4886/4887/4888/4889 for request submission/issuance/denial/pending; 4868/4870 for manual approve/revoke; 4882 for role-grant changes; 4891/4892 for CA-config flag toggles). Not re-derived here.

## `ca -backup`'s Service-Creation Footprint on the CA Server

This is the one target-side artifact class genuinely unique to Certipy among the tools in this repo's ADCS coverage, since Certify's `manage-ca`/`manage-template` verbs never create a Windows service on the CA at all. Verified against `certipy/commands/ca.py`'s `backup()` (see `01`'s Red Flag callout for the full mechanic):

- **First invocation against a given CA is loud on install-specific events.** Creating a brand-new service named `Certipy` via `hRCreateServiceW` triggers **Event 4697** (A service was installed in the system — requires the non-default "Audit Security System Extension" subcategory) and **System-log Event 7045** (A service was installed in the system — logged unconditionally by the Service Control Manager, no audit-policy gating). **Event 7036** (the service entered the running state) follows when `hRStartServiceW` fires it.
- **Every subsequent invocation against the same CA is quieter, on purpose or not.** Certipy's own source checks for `ERROR_SERVICE_EXISTS` and, if the `Certipy` service is already present from a prior run, calls `hRChangeServiceConfigW` to update its `ImagePath` instead of creating a new service. Per the finding already documented in `Purple Teaming/LOLBins/sc/05 - Detection and Hunting.md` — reconfiguring an **existing** service's `binPath`/`ImagePath` triggers **neither 4697 nor 7045**, and 7040 only fires on a start-type change (which this doesn't touch) — a repeat `ca -backup` run on a CA where the `Certipy` service already exists from a previous operation leaves **no native install/config event at all**, only the 7036 start/stop pair. This directly extends that existing repo finding to a second tool.
- **Cleanup deletes the service (`hRDeleteService`) after retrieval**, so `HKLM\SYSTEM\CurrentControlSet\Services\Certipy` does not persist — but its brief creation-to-deletion window (seconds, matching the create/start/delete-per-invocation pattern already documented for `Impacket/smbexec/`) is itself recoverable via registry-transaction-log or `$MFT`/USN-journal-based deleted-key/deleted-file forensics even after live cleanup completes.
- **Process tree on the CA server**: the service's `ImagePath` (`cmd.exe /c certutil ... -backupkey -f -p certipy ...`) runs `cmd.exe` directly as the service's own process (no `svchost.exe` hosting, since it's registered as its own executable path) — parented by `services.exe`, itself spawning `certutil.exe` as a child. A `services.exe → cmd.exe → certutil.exe` tree, with `certutil.exe`'s command line containing the **literal, hardcoded, source-fixed password `certipy`**, is the single highest-confidence process-level signature for this operation — Sysmon Event ID 1 (process creation) captures the full chain and command line if configured on the CA server.
- **Filesystem**: `C:\Windows\Tasks\Certipy\` is created, populated with the backed-up `.pfx`, then deleted by the cleanup command (`del /f /q ... && rmdir ...`) — Sysmon Event ID 11 (file create) if configured; the directory's brief existence is otherwise recoverable via standard deleted-file/USN-journal forensics on the CA server's own disk.

## LDAP Enumeration — Same Silent-Read Gap

`certipy find`'s LDAP reads against the five PKI containers, and its Remote Registry Protocol reads against the CA server for ESC6/ESC9/ESC11/ESC16, are mechanically identical to Certify's `enum-*` verbs — apply `GhostPack/Certify/04 - Target Evidence.md`'s "LDAP Enumeration Evidence" section directly (Event 1644 requiring non-default Field Engineering diagnostics; registry value **reads** having no dedicated default Windows audit event at all). Not re-derived here.

## Directory Service Writes — `account`, `template`, `shadow`

Three Certipy commands write directly to Active Directory objects, all subject to the same non-default "Audit Directory Service Changes" auditing gap already established elsewhere in this repo (`LOLBins/setspn/`, `PowerSploit/PowerView/`, `GhostPack/Certify/04`'s own `manage-template` section):

| Command | AD write | Event (requires Directory Service Changes auditing + SACL on the object) |
|---|---|---|
| `account update -upn` | `userPrincipalName` attribute change (ESC9/ESC10 UPN-manipulation primitive) | **5136** — old/new value visible if enabled; the manipulate-then-revert pattern (set → enroll/auth → revert, per `02`) produces **two** 5136 events on the same attribute in a short window, a recognizable shape independent of the values themselves |
| `template -write-default-configuration` | Multiple template attributes (`msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `nTSecurityDescriptor`) rewritten to an ESC1-shaped config | **5136** per changed attribute — identical to Certify's `manage-template` finding, cross-linked rather than re-derived |
| `shadow add`/`auto` | `msDS-KeyCredentialLink` attribute write | **5136** if enabled — see the dedicated MDI alert below, which does not depend on this auditing being configured |

`ca -enable-template`/`-disable-template`/`-add-officer`/`-remove-officer` write to the **CA object** rather than a template object, and are covered by the CA-side 4882/4891/4892 events cross-linked above, not by 5136.

## Shadow Credentials — Defender for Identity Alert

Unlike the LDAP-write events above, Microsoft Defender for Identity's dedicated alert for this technique does **not** depend on Directory Service Changes auditing being configured — verified live against Microsoft's own "Microsoft Defender for Identity classic security alerts" reference: **"Suspected account takeover using shadow credentials"** (External ID **2431**, severity **High**, categorized under Credential Access). This is the primary target-side signal for `certipy shadow add`/`auto` where MDI/Defender for Identity sensors are deployed on the DC, independent of native Windows audit-policy state.

## Relay (ESC8/ESC11) — Network-Layer Evidence

`certipy relay`'s NTLM-relay traffic against the CA's Web Enrollment (ESC8) or ICPR RPC interface (ESC11) is mechanically the same relay pattern already documented for `Impacket/ntlmrelayx/04 - Target Evidence.md` — an SMB-based relay listener, a coerced authentication (via a separate tool, PetitPotam/Coercer), and a relayed session against the CA rather than against the coerced host itself. Apply that page's coercion-detection and relay-signature guidance directly. The certificate-issuance half of a successful ESC8/ESC11 relay lands in the same CA request database/event trail documented above, with the **requester identity in the CA's own record being the coerced/relayed account** (e.g. `DC$`) rather than the operator's own — a request record naming a machine account or service account for a template it would not normally self-enroll for is the CA-side tell that a relay (not a legitimate self-service request) produced it.

## PKINIT / Schannel Authentication Evidence

`certipy auth`'s Kerberos PKINIT redemption generates the identical DC-side Kerberos evidence documented in `Rubeus/04 - Target Evidence.md` and cross-linked from `GhostPack/Certify/04` — Event 4768 with a certificate-based pre-authentication type, apply that analysis directly. The U2U follow-up request Certipy performs for NT-hash recovery (see `01`) generates a TGS-REQ/TGS-REP pair distinct from a normal service-ticket request; `-ldap-shell`'s Schannel path instead generates a TLS client-certificate handshake against LDAPS (636) with no Kerberos event at all — the DC's Schannel-specific logging (if any) is the only native trail for that path, and it inherits the same weak-mapping caveats already covered in `01`'s ESC10 row.

## Endpoint-Security-Product Signature Behavior

- CA servers remain generally under-monitored relative to domain controllers despite comparable value — the same asymmetry `GhostPack/Certify/04` already flags, unchanged by which client tool is used against the CA.
- Static signature detection has a genuinely different profile than Certify's: Certipy run from a `pip`-installed package invokes a plain `python3` interpreter with no distinctive binary to fingerprint at all, while the **official CI-built `Certipy.exe`** (see `01`'s History) does carry real, checkable PE metadata and a publicly documented SHA-256 per GitHub release — trivially defeated by anyone building from source themselves (the CI workflow is public), but still a genuine, narrow signal against an operator using the pre-built release asset unmodified. Neither case matches Certify's own posture, where no official binary of any kind exists to hash against.
- A `Certipy`-named service (even a short-lived one) or a `certutil.exe` process with `certipy` as a literal command-line argument are both extremely high-confidence, low-false-positive signatures precisely because the string is the tool's own unobfuscated name — see `05` for why this only holds against an unmodified build.

## Memory Forensics

Certipy itself runs remotely and never executes on the CA/DC/target — there is no LSASS-equivalent memory artifact to recover on those systems from Certipy's own activity (contrast with `Mimikatz/`/`ProcDump/`, which run *on* the target). The one process-memory angle on the **CA server** specifically is the short-lived `cmd.exe`/`certutil.exe` process pair spawned by the `ca -backup` service — a memory capture taken during that narrow window could recover the CA private key material in transit before it's written to `C:\Windows\Tasks\Certipy\`, but the window is measured in seconds and this is a low-yield approach compared to the filesystem/event-log artifacts above.

## Building a Timeline

1. **Source-host command/output-file evidence** (`03`) — which command ran, against which template/CA/identity, and when (Certipy's own predictable filenames often substitute for shell history entirely).
2. **CA database record** (`certutil -view`, always available) — authoritative record of any `req`/`relay`-driven request, independent of audit configuration; **absent for `forge`**, which never touches the CA.
3. **[If CA auditing enabled] CA Security-log events** (4886–4892 family) — cross-linked from `GhostPack/Certify/04`, applies identically.
4. **`ca -backup` specific**: 7045/4697 (first-ever invocation on this CA only) or their absence (repeat invocation), 7036 start/stop pair, `services.exe → cmd.exe → certutil.exe` process tree, transient `C:\Windows\Tasks\Certipy\` filesystem artifact.
5. **[If Directory Service Changes auditing enabled] Event 5136** — for `account`/`template`/`shadow` LDAP writes, with old/new attribute values.
6. **Shadow Credentials specifically**: MDI alert 2431, independent of #5's auditing state.
7. **Relay-specific**: coercion + relay network evidence cross-linked from `Impacket/ntlmrelayx/`, plus a CA request record naming an unexpected (coerced) requester identity.
8. **DC-side PKINIT/Schannel redemption** — cross-referenced from `Rubeus/04 - Target Evidence.md`'s Event 4768 analysis, plus whatever the resulting TGT/LDAP session was subsequently used for.

Step 2's caveat (silent for `forge`) is the load-bearing difference from Certify's own timeline: a CA-key-theft-then-offline-forge chain leaves its *only* target-side evidence at redemption time (step 8), with steps 2–4 covering the theft itself but nothing at all covering the forge step, since it never reaches the CA or DC until the forged certificate is actually used.
