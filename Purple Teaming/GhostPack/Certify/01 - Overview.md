# Certify — Overview

> 🔴 **Red Flag Principle:** Certify's endpoint isn't a session, a hash, or a ticket — it's a **certificate**, and a certificate is a durable bearer credential that outlives the account's own password. A cert minted via an ESC1-class abuse authenticates as the named principal via Kerberos PKINIT for the certificate's entire validity window (commonly a year or more on default templates) and **survives a password reset on the impersonated account** — resetting `Administrator`'s password does nothing to a certificate already issued in `Administrator`'s name. Layer on top of that a genuine, source-verified gap: Windows Server's own Certificate Services auditing (the event IDs that would log the request/issuance itself, `4886`/`4887`/`4888`) is **off by default** — verified against Microsoft's own "Audit Certification Services" documentation, which requires both the CA's own Audit-tab configuration *and* the Windows "Object Access" audit subcategory to be explicitly enabled before a single one of these events fires. The step that mints the walk-away credential is, on a default-configured CA, simply not logged at all.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`GhostPack/Certify`](https://github.com/GhostPack/Certify), its `README.md`/`CHANGELOG.md`, and the live commit/release/tag history via the GitHub API:

- **Primary authors:** [Will Schroeder](https://twitter.com/harmj0y) (`@harmj0y`) and **Lee Christensen** (`@tifkin_`) — the same GhostPack author family behind `Rubeus/`, `SharpUp/`, and the rest of this folder. **License:** BSD 3-Clause, copyright 2021 Will Schroeder and Lee Christensen (verified against the repo's own `LICENSE` file).
- **Origin:** released alongside Schroeder and Christensen's Black Hat USA 2021 talk, ["Certified Pre-Owned: Abusing Active Directory Certificate Services"](https://www.blackhat.com/us-21/briefings/schedule/#certified-pre-owned-abusing-active-directory-certificate-services-23168), and the accompanying SpecterOps [whitepaper](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) that coined the ESC1–ESC8 misconfiguration taxonomy this whole page builds on. Per the README's own "Reflections" section, the authors deliberately self-embargoed public release of Certify (and the sibling `ForgeCert`, below) for roughly 45 days after the whitepaper to give organizations time to react before proof-of-concept tooling landed.
- **Not archived, not stale — actively maintained on the canonical repo itself.** Verified live via the GitHub API: `archived: false`, most recent push **2026-07-29**. Development is not a solo-author effort anymore: the current top contributor by commit count is `bytewreck` (20 commits), who is actively merging community pull requests directly into `GhostPack/Certify` — e.g. a 2026-07-29 merge of contributor `thegreatmhn`'s PR adding LDAP alternate-credential bind support to `EnumTemplates`/`EnumCas`. Because this activity lands on the main repo rather than a diverging fork, `GhostPack/Certify` remains the single canonical, current version — there is no separate community fork to redirect to.
- **Version milestones**, per `CHANGELOG.md`:
  - **`[1.0.0]` — 2021-08-04**: initial release.
  - **`[1.1.0]` — 2022-11-08**: added a `/sidextension` flag to comply with the 2023 strong-certificate-mapping patch (the SID security extension, `szOID_NTDS_CA_SECURITY_EXT`, that Microsoft began requiring after **KB5014754**).
  - **`[2.0.0]` — 2025-08-11**: *"Revamped the entire tool."* **This is the single most important fact on this page.** Every widely-circulated blog post, conference talk, and cheat sheet describing `Certify.exe find /vulnerable` or `Certify.exe request /ca:X /template:Y` is describing the **pre-2025-08-11 v1.x command surface**, which no longer exists in the live source. Certify 2.0 replaced it wholesale with a new kebab-case verb set (`enum-templates`, `enum-cas`, `enum-pkiobjects`, `request`, `request-agent`, `request-download`, `request-renew`, `forge`, `manage-ca`, `manage-template`, `manage-self`) built on the `CommandLine` NuGet parser rather than a hand-rolled argument reader. **Every switch and verb documented below was pulled directly from the live `Certify/Commands/*.cs` source, not from memory or older write-ups** — do not trust a v1.x-era command line against a current build.
- **`ForgeCert` was a separate sibling GhostPack repository** (`github.com/GhostPack/ForgeCert`) for offline "golden certificate" forgery against a stolen CA private key. Checked live: it is **not archived**, but its last push is **2024-08-17** — stale relative to Certify's own 2026-07-29 activity. Its core capability has been **folded directly into Certify 2.0** as the `forge` verb (`Certify/Commands/CertForge.cs`) — confirmed by reading the source: same "golden certificate" framing, same BouncyCastle-based offline X.509 construction signed against a supplied CA `.pfx`. Certify now duplicates ForgeCert's functionality in an actively-maintained home; treat `ForgeCert` as functionally superseded rather than a required separate tool.
- **No compiled binaries are ever released** — verified live via the GitHub API (`gh api repos/GhostPack/Certify/releases` and `/tags` both return empty arrays, matching Rubeus's and SharpUp's posture). The README states this explicitly: *"We are not planning on releasing binaries for Certify, so you will have to compile yourself."* Built against **.NET 4.7.2** with Visual Studio 2022 Community per the README. As with Rubeus/SharpUp, there is no canonical shipped binary to fingerprint against — every real-world `Certify.exe` is a custom operator compile.
- **A genuine, undocumented build-configuration footgun**, found by reading `Certify.csproj` directly rather than the README (which says nothing about it): the project defines **two** non-standard build configurations — one named **`Disarmed`**, which defines the preprocessor constant `DISARM`, and one named **`Disarm`**, which defines the constant `DISARMED`. Every weaponized command file (`CertRequest.cs`, `CertRequestOnBehalf.cs`, `CertRequestDownload.cs`, `CertRequestRenewal.cs`, `CertForge.cs`, `ManageCa.cs`, `ManageTemplate.cs`, `ManageSelf.cs`) is wrapped in `#if !DISARMED ... #endif`. Because the guard checks for `DISARMED` (not `DISARM`), **building the configuration literally named "Disarmed" does not disarm the tool at all** — its `#define DISARM` doesn't match anything the code checks. Only the confusingly-named **`Disarm`** configuration actually strips the tool down to the three enumeration-only verbs (`enum-cas`, `enum-templates`, `enum-pkiobjects`). This is a real, source-verified naming mismatch, not a documented feature — flag it explicitly if evaluating a "disarmed" compile someone else produced.
- **Acknowledged research lineage** (per the README): built on prior public research from Christoph Falta (`PoshADCS`), CQURE's Enhanced Key Usage work, Keyfactor's SAN-abuse research, Carl Sörqvist's misconfiguration-scenario writeup, Ceri Coburn (`@_ethicalchaos_`, smart-card AD CS research — the same `CCob`/Ceri Coburn credited as a Rubeus S4U/RBCD contributor), and Brad Hill's PKINIT/smart-card whitepaper — plus the open Microsoft protocol specifications this page cites directly below (MS-WCCE, MS-CSRA, MS-ICPR, MS-CRTD).
- Certify's Linux/Python sibling for the same attack surface, **Certipy**, is planned but not yet built in this repo (`Purple Teaming/Certipy/`) — see `Purple Teaming/IDEAS.md`'s Wave 3 table, which explicitly frames the pair as "Windows (Certify) and Linux/Python (Certipy) sides of the same attack."

## How It Works

Certify's command surface splits cleanly into two phases with very different evidentiary footprints: **enumeration** (pure LDAP reads, present even in a `Disarm`-configured build) and **weaponization** (COM calls that ride DCOM/RPC to the CA, LDAP *writes*, or fully offline cryptography — all compiled out of a `Disarm` build).

### Enumeration — LDAP reads against five fixed PKI containers

Every enumeration command binds to `RootDSE`, resolves `configurationNamingContext`, and reads fixed containers under `CN=Public Key Services,CN=Services,<Configuration NC>` — confirmed directly against `Certify/Lib/LdapOperations.cs`:

| Container (relative to `CN=Public Key Services,CN=Services,...`) | What it holds | Read by |
|---|---|---|
| `CN=Certification Authorities` | Trusted root CA certificate objects | `enum-cas` |
| `CN=Enrollment Services` | One `pKIEnrollmentService` object per enterprise/enrollment CA — DNS hostname, published-template list, CA certificate | `enum-cas`, `enum-templates` |
| `CN=NTAuthCertificates` | The `certificationAuthority`-class object listing every CA cert trusted for **domain authentication** specifically (a narrower trust list than "trusted root") | `enum-cas` |
| `CN=Certificate Templates` | `pKICertificateTemplate` objects — every `msPKI-*` flag, EKU/application-policy OID list, and the template's own DACL | `enum-templates`, `enum-pkiobjects` |
| `CN=OID` | Enterprise issuance/application-policy OID objects, including any group-linked issuance policy | `enum-pkiobjects` (and `enum-templates` for ESC13 classification) |

Each object's security descriptor is parsed into ACEs and passed through a per-object `FindVulnerabilities()` classifier — this is what produces the `Vulnerabilities` list attached to every template/CA in the console output, and what `--filter-vulnerable` filters on.

**A sixth data source that is *not* LDAP:** `enum-cas`'s ESC6/ESC7/ESC11/ESC16 checks read the **CA server's own `HKLM` registry hive remotely** (`RegistryKey.OpenRemoteBaseKey`, the Remote Registry Protocol, port 445) — `EditFlags`, `InterfaceFlags`, and `DisableExtensionList` under `SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-Name>` are not exposed via LDAP at all. Certify's own source comment notes this "appears to work even if admin rights aren't available on the remote CA server" — a genuinely low-barrier remote read.

### The vulnerability classifier — what Certify actually checks (and what it doesn't)

Verified directly against `Certify/Domain/CertificateTemplate.cs`'s and `CertificateAuthorityEnterprise.cs`'s `FindVulnerabilities()` methods — the literal, current source of truth for what a `--filter-vulnerable` run will and won't flag:

| ESC ID | Scope | What the source checks |
|---|---|---|
| ESC1 | Template | Client-auth-capable EKU (or none) **and** `ENROLLEE_SUPPLIES_SUBJECT` **and** the requester holds Enroll rights **and** no manager approval / zero required RA signatures |
| ESC2 | Template | No EKU restriction at all, or the `Any Purpose` EKU explicitly present |
| ESC3 | Template | `Certificate Request Agent` EKU present (flagged as schema-v1-only if `Any Purpose` is also present, per SpecterOps's own later corrections) |
| ESC4 | Template | Low-privileged/attacker-controlled owner, or an ACE granting `GenericAll`/`WriteOwner`/`WriteDacl`/unrestricted `WriteProperty` |
| ESC6 | CA | `EDITF_ATTRIBUTESUBJECTALTNAME2` set CA-wide (`0x00040000` in `EditFlags`) |
| ESC7 | CA | Low-privileged/attacker-controlled owner of the CA object, or an ACE granting `ManageCA`/`ManageCertificates` |
| ESC8 | CA | Live-probes `http(s)://<CA-host>/certsrv/` and succeeds authenticating both **with and without** NTLM channel binding — confirms web enrollment accepts NTLM relay |
| ESC9 | Template | Client-auth-capable EKU **and** `NO_SECURITY_EXTENSION` enrollment flag set (flagged as ESC6-dependent if the template doesn't also require a SAN via `SUBJECT_ALT_REQUIRE_*`) |
| ESC11 | CA | `IF_ENFORCEENCRYPTICERTREQUEST` **not** set in `InterfaceFlags` — the CA doesn't mandate RPC packet-privacy encryption on certificate-request calls |
| ESC13 | Template | Client-auth-capable EKU **and** an issuance policy linked to a domain group |
| ESC15 ("EKUwu") | Template | Schema version 1 **and** `ENROLLEE_SUPPLIES_SUBJECT` — schema-v1 templates ignore the request's declared "Application Policies" restriction entirely, letting an attacker smuggle a client-auth EKU into a template that was never configured to allow one |
| ESC16 | CA | The security extension (`szOID_NTDS_CA_SECURITY_EXT`) is globally disabled CA-wide via `DisableExtensionList` |

**Real, source-confirmed coverage gap:** Certify's automatic classifier has **no ESC5, ESC10, ESC12, or ESC14 check** — grepping every `FindVulnerabilities()`/`CheckVulnerable*` method in the current source turns up none. ESC5 (a broader "PKI object control chain" category — e.g. compromising an intermediate AD object like the `NTAuthCertificates` container or a CA's own AD computer object) and ESC10 (weak certificate-to-account mapping registry settings on the domain controller itself, not the CA) fall outside what a template/CA-object LDAP-and-registry scan can see — they need graph-based AD ACL analysis (`Purple Teaming/BloodHound/`) or DC-side registry inspection instead. Don't read a clean `--filter-vulnerable` run as "no ESC misconfigurations exist anywhere in this environment."

### ESC1 mechanically, end to end

ESC1 is the template misconfiguration most write-ups lead with, and the one this page walks through in full since it's the cleanest illustration of how *all* the template-based ESCs work — a name-flag misconfiguration plus a permissive ACL:

```
1. Template has msPKI-Certificate-Name-Flag & ENROLLEE_SUPPLIES_SUBJECT (bit 0x1) set
       → the REQUESTER, not the CA, gets to name the Subject/SAN of the issued cert

2. Template's EKU list is empty, OR contains one of:
       Client Authentication (1.3.6.1.5.5.7.3.2)
       PKINIT Client Authentication (1.3.6.1.5.2.3.4)
       Smartcard Logon (1.3.6.1.4.1.311.20.2.2)
       Any Purpose (2.5.29.37.0)
       → the resulting cert is USABLE for Kerberos PKINIT client authentication

3. msPKI-Enrollment-Flag does NOT have PEND_ALL_REQUESTS set,
   AND msPKI-RA-Signature == 0
       → the cert issues IMMEDIATELY, no human approval step

4. The requesting principal (or a group it belongs to) holds the Enroll
   extended right (GUID 0e10c968-78fb-11d2-90d4-00c04f79dc55) on the
   template's own ACL
       → often "Domain Users" or "Authenticated Users" on a template
         nobody has re-scoped since it was cloned from a built-in default

──────────────────────────────────────────────────────────────────────
    All four conditions true → any Enroll-rights principal submits a
    CSR that names an ARBITRARY UPN/SAN — e.g. administrator@domain —
    and the CA issues a fully valid, chain-trusted certificate for
    that identity with zero manual review. The certificate then
    authenticates via Kerberos PKINIT AS that principal.
```

The requester never touches the impersonated account's password or NTLM hash — the CA's own signature on the forged-identity certificate does all the work. See `02 - Hands-On Use Cases.md` for the exact `Certify.exe request` command line and the `Rubeus asktgt /certificate:` handoff that redeems it.

### Certificate request delivery — two distinct COM code paths

Certify's `request` and `request-agent` verbs build fundamentally different PKCS structures, both via the `CERTENROLLLib`/`CERTCLILib` COM interop (Microsoft's own MS-WCCE client library, the same one `certreq.exe`/`certutil.exe` use under the hood):

| Verb | Structure | Mechanism |
|---|---|---|
| `request`, `request-renew` | `CX509CertificateRequestPkcs10` (PKCS#10, a plain CSR) | Signed with the **requester's own** freshly-generated private key, submitted under the requester's own (or, with `--machine`, the machine's) authenticated context |
| `request-agent` | `CX509CertificateRequestPkcs7` (PKCS#7, an enveloped/co-signed request) | Built as a normal PKCS#10 inner request, then **wrapped and co-signed with an Enrollment Agent certificate**, with `RequesterName` set to an arbitrary target UPN — this is the literal ESC3 mechanism: an Enrollment Agent cert lets its holder request a certificate *as* someone else without ever authenticating as that someone else |

Both paths converge on the same submission call: `CCertRequest.Submit(CR_IN_BASE64 | CR_IN_FORMATANY, csr, "", ca)` — a COM call into `ICertRequest`, which MS-WCCE (Windows Client Certificate Enrollment Protocol) carries over DCOM (itself riding RPC, typically an SMB named pipe or a dynamic RPC port depending on the CA's own binding). `CCertRequest.RetrievePending()`/`GetCertificate()` complete the download once the CA has issued.

**A process-startup-level tell independent of which verb is run:** `Program.cs`'s `ParserInitialize()` calls `DistributedComUtil.Initialize()`/`InitializeSecurity()` **unconditionally**, wrapped only in `#if !DISARMED` — meaning any full (non-`Disarm`) build initializes DCOM security at process startup before the argument parser even determines which verb was requested, including a pure `enum-templates` run. A `Disarm`-configured build skips this entirely, since the whole block is compiled out.

### CA/template management — `manage-ca` and `manage-template`

These aren't enumeration or one-shot cert requests — they **persistently modify** AD CS configuration, via two different write paths:

- `manage-template`'s ACL/attribute/flag toggles (`--owner`, `--enroll`, `--write-*`, `--esc9`, EKU toggles) are plain **LDAP writes** via `DirectoryEntry.ObjectSecurity`/`.Properties` + `CommitChanges()` — the same protocol as enumeration, just writing instead of reading.
- `manage-ca`'s CA-wide toggles (`--esc6`, `--esc11`, `--esc16`, published-template list, role grants) go through **`ICertAdminD2`** (verified via `Certify/Lib/CertAdmin.cs`: `[Guid("7fe0d935-dda6-443f-85d0-1cfb58fe41dd")]`), the COM interface for **MS-CSRA** (Certificate Services Remote Administration Protocol) — a second, distinct DCOM/RPC interface from MS-WCCE, used for administrative rather than enrollment operations.
- **Every `manage-ca` flag toggle ends by restarting the CA service** — `Certify/Commands/ManageCa.cs`'s `RestartCaService()` calls `ServiceController("CertSvc", server).Stop()`/`.Start()` unconditionally after any `--esc6`/`--esc11`/`--esc16` change, since the CA process caches these flags at startup. This is loud and structurally unavoidable: the CA server process visibly bounces every time an operator flips one of these CA-wide backdoor flags.

### Offline paths — no network contact at all

- **`forge`**: builds a fully offline "golden certificate" using BouncyCastle, signed with a supplied CA `.pfx`'s own private key — no LDAP, no MS-WCCE, no network of any kind. This is structurally the certificate-world equivalent of a Golden Ticket (`Mimikatz/kerberos (Golden-Silver Ticket)/`, `Rubeus/`'s `golden` command): a stolen CA private key stands in for a stolen `krbtgt` key, and possessing it lets an attacker mint trusted, chain-valid identity material entirely offline, redeemable later via PKINIT exactly like any other cert.
- **`manage-self --dump-certs`**: pure local Win32 crypto API (`crypt32.dll`'s `CertOpenStore`/`CertGetCertificateChain`/`PFXExportCertStoreEx`) — no network at all, harvests every certificate **and its exportable private key** already sitting in the local machine certificate store, re-packaged as PFX.

### Elevation for `--machine` — the same primitive as Rubeus

`request`, `request-agent`, and `request-renew` all support `--machine` to request/renew a certificate under the local **machine account's** identity rather than the operator's own. If the caller is high-integrity but not already SYSTEM, `Certify/Util/ElevationUtil.cs`'s `GetSystem()` runs **byte-for-byte the same pattern documented for Rubeus's own `GetSystem()`**: `OpenProcessToken()` against a running `winlogon.exe` with `TOKEN_DUPLICATE`, `DuplicateToken()` to clone its SYSTEM token, `ImpersonateLoggedOnUser()`, run the action, then `RevertToSelf()`. This isn't a coincidental similarity — it's the same GhostPack author family reusing the identical Windows primitive across tools. See `Rubeus/01 - Overview.md`'s "Elevated ticket extraction" section for the shared forensic signature (a handle opened to `winlogon.exe` by an unusual process, followed by that process suddenly running as SYSTEM).

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| LDAP/LDAPS | Enumeration of the five PKI containers under `CN=Public Key Services,CN=Services,<Config NC>`; `--username`/`--password` supports an alternate-credential bind (masked-input prompt if a username is given with no password) |
| Remote Registry Protocol (RRP, port 445) | `enum-cas`'s ESC6/ESC7/ESC11/ESC16 checks — reads the target CA server's own `HKLM` hive remotely, not via LDAP |
| MS-WCCE (`ICertRequest`, `CERTCLILib`/`CERTENROLLLib` COM → DCOM/RPC) | `request`, `request-agent`, `request-download`, `request-renew` — certificate submission and retrieval |
| MS-CSRA (`ICertAdminD2` COM → DCOM/RPC) | `manage-ca` — CA-wide configuration, role, and certificate-lifecycle administration |
| SCM (Service Control Manager) | `manage-ca`'s mandatory `CertSvc` service restart after any flag toggle |
| HTTP/HTTPS (NTLM/Negotiate) | ESC8 web-enrollment channel-binding probe; CES/CEP/NDES web-service discovery in `enum-cas` |
| Local Win32 Crypto API (`crypt32.dll`) | `manage-self --dump-certs` — certificate store enumeration/export, no network |
| Windows Token APIs | `winlogon.exe` token duplication for `--machine` SYSTEM elevation — identical mechanism to Rubeus's `GetSystem()` |
| Kerberos PKINIT (RFC 4556) | **Not performed by Certify itself** — the actual authentication redemption of a minted certificate is a separate step, typically `Rubeus asktgt /certificate:` (see `02`) or a native Windows logon; cross-link `Rubeus/01 - Overview.md`'s PKINIT row rather than re-deriving |

## Command-Line Switches — Quick Reference

Verified live against [`GhostPack/Certify`](https://github.com/GhostPack/Certify)'s `Certify/Commands/*.cs` and `Certify/Program.cs` source — every verb and switch below reflects the **current (post-2.0.0) command surface**, not the older `find`/`request`/`pkiobjects`/`cas` verbs older material describes.

**Global options** (every verb inherits these from `DefaultOptions`):

| Option | Plain-English meaning |
|---|---|
| `--out-file <PATH>` | Redirect all console output to a file instead of stdout |
| `--quiet` | Suppress the ASCII-art banner |

**The 11 verbs:**

| Verb | Group | What it does |
|---|---|---|
| `enum-cas` | Enumeration | List root CAs, NTAuth-trusted CA certs, and enterprise/enrollment CAs — including per-CA vulnerability classification and published-template lists |
| `enum-templates` | Enumeration | List certificate templates with full flag/EKU/ACL detail and vulnerability classification |
| `enum-pkiobjects` | Enumeration | List access controls on PKI objects (enterprise OIDs, group-linked issuance policies) |
| `request` | Weaponization | Request a certificate directly for the current (or `--machine`) context |
| `request-agent` | Weaponization | Request a certificate **on behalf of another user**, using a held Enrollment Agent certificate (ESC3) |
| `request-download` | Weaponization | Download a previously submitted, now-issued certificate request by ID |
| `request-renew` | Weaponization | Renew an already-issued certificate, inheriting its prior request's attributes |
| `forge` | Weaponization (offline) | Build an offline "golden certificate" signed with a supplied stolen CA private key — no network contact |
| `manage-ca` | Weaponization | Modify CA-wide configuration: published templates, role grants, ESC6/ESC11/ESC16 flags, pending-request issue/deny, certificate revocation |
| `manage-template` | Weaponization | Modify a certificate template's ACL, owner, EKUs, or ESC9 flag |
| `manage-self` | Weaponization (local only) | Dump every certificate + exportable private key from the local machine certificate store |

**`enum-templates` / `enum-cas` / `enum-pkiobjects` (enumeration)** — shared filter/context switches:

| Switch | Plain-English meaning |
|---|---|
| `--ca SERVER\CA-NAME` | Restrict to a specific certificate authority |
| `--template NAME` | Restrict to a specific template (enum-templates only) |
| `--domain FQDN` / `--ldap-server HOST` | Target a non-default domain or a specific LDAP server |
| `--current-user` | Classify vulnerabilities against the **current process's** identity and its unrolled group memberships, instead of generic low-privileged groups |
| `--target-user NAME` | Classify vulnerabilities as if evaluating from a **different named principal's** perspective — useful for assumed-breach scoping against a specific compromised account |
| `--filter-enabled` | Only show templates actually published/enabled on a CA |
| `--filter-vulnerable` | Only show templates/CAs the classifier flagged with at least one ESC ID |
| `--filter-request-agent` | Only show templates with the Certificate Request Agent EKU (ESC3 candidates) |
| `--filter-client-auth` | Only show templates whose EKU permits client authentication |
| `--filter-supply-subject` | Only show templates with `ENROLLEE_SUPPLIES_SUBJECT` set |
| `--filter-manager-approval` | Only show templates requiring manager approval |
| `--hide-admins` | Suppress well-known admin-principal ACEs from the printed permission listing (noise reduction, not a filter on vulnerability logic) |
| `--show-all-perms` | Print every ACE, not just the interesting ones |
| `--skip-web-checks` | Skip the live ESC8 HTTP(S) channel-binding probe (`enum-cas` only) |
| `-u/--username`, `-p/--password` | Alternate-credential LDAP bind (`user@domain.fqdn`); omitting `-p` while `-u` is set prompts interactively with masked input rather than exposing it on the command line |

**`request` (weaponization — ESC1/ESC2/ESC9/etc. exploitation):**

| Switch | Plain-English meaning |
|---|---|
| `--ca SERVER\CA-NAME` *(required)* | Target CA |
| `--template NAME` *(required)* | Target template |
| `--subject NAME` | Explicit Subject DN (defaults to the current user/machine's own DN) |
| `--upn`, `--dns`, `--email` | Subject Alternative Name value(s) — **this is the ESC1 impersonation lever**: any value here is attacker-controlled when the template allows `ENROLLEE_SUPPLIES_SUBJECT` |
| `--sid` | Embeds the actual X.509 SID security extension (`szOID_NTDS_CA_SECURITY_EXT`, `1.3.6.1.4.1.311.25.2`) — required if the CA/DC enforces strong certificate mapping |
| `--sid-url` | A **mechanically different** SID hint: adds a SAN `GeneralName` URL entry in the format `tag:microsoft.com,2022-09-14:sid:<value>` rather than the dedicated security extension above — a separate, alternate way some clients/servers recognize a mapped SID |
| `--application-policy OID` | Additional application-policy OID(s) to embed |
| `--key-size {512\|1024\|2048\|4096}` | Private-key size (default 2048) |
| `--machine` | Request as the local machine account (triggers `winlogon.exe`-based SYSTEM elevation if not already SYSTEM) |
| `--output-pem` / `--output-csr` | Output format — PEM cert+key, or just the raw CSR without submitting |
| `--install` | Install the resulting certificate into the current certificate store |
| `-u/-p` | Alternate credentials for the request submission itself |

**`request-agent` (ESC3 — Enrollment Agent abuse):**

| Switch | Plain-English meaning |
|---|---|
| `--ca`, `--template` *(required)* | As above |
| `--target NAME` *(required)* | The **user being impersonated** — set as the PKCS#7 request's `RequesterName`, with no need to ever authenticate as them |
| `--agent-pfx PATH` *(required)* | The held Enrollment Agent certificate used to co-sign the on-behalf-of request |
| `--agent-pass` | Password for the agent PFX |
| `--application-policy`, `--key-size`, `--machine`, `--output-pem`, `--install` | Same meaning as `request` |

**`request-download` / `request-renew`:**

| Switch | Plain-English meaning |
|---|---|
| `--ca` *(required)* | Target CA |
| `--id N` *(request-download, required)* | The pending request ID to retrieve (e.g. one approved after manager review) |
| `--private-key` | Base64 private key to pair with the downloaded cert |
| `--cert-pfx` / `--cert-pass` *(request-renew, required)* | The existing certificate being renewed |
| `--install-machine` / `--install-user` | Install destination for the downloaded cert |
| `--machine`, `--output-pem`, `--install` | Same meaning as `request` |

**`forge` (offline golden certificate):**

| Switch | Plain-English meaning |
|---|---|
| `--ca-cert PATH` *(required)* | The stolen CA private key, as a PFX/P12 file (or base64 blob) |
| `--ca-pass` | Password for the CA private key file |
| `--subject NAME` | Forged certificate's Subject (default `CN=User`) |
| `--upn`, `--dns`, `--email` | Forged SAN value(s) — the impersonated identity |
| `--sid` | SID security extension — **strongly recommended**; Certify itself warns at runtime if omitted, since strong-mapping-enforcing DCs will reject a SID-less forged cert |
| `--crl` | LDAP path to a CRL, required for chain validation when forging against a subordinate (not root) CA cert |
| `--serial` | Hardcoded serial number (default: random) |
| `--output-path` / `--output-pass` | Save the forged PFX to disk instead of printing base64 |

**`manage-ca` (CA-wide persistence/backdoor):**

| Switch | Plain-English meaning |
|---|---|
| `--ca SERVER\CA-NAME` *(required)* | Target CA |
| `--template NAME` (repeatable) | Toggle a template's published/unpublished state on this CA |
| `--template-domain FQDN` / `--template-ldap-server HOST` | Non-default domain/LDAP server to resolve the `--template` name(s) against |
| `--issue-id` / `--deny-id` / `--revoke-cert` | Approve, deny, or revoke a specific pending request/issued certificate by ID or serial |
| `--issuance-policy REQUEST-ID:OID` / `--application-policy REQUEST-ID:OID` | Set the issuance/application policy extension on a specific pending/issued request |
| `--enroll`, `--officer`, `--admin` (SID) | Toggle Enroll / ManageCertificates / ManageCA role grants for a principal |
| `--esc6` | Toggle `EDITF_ATTRIBUTESUBJECTALTNAME2` CA-wide |
| `--esc11` | Toggle `IF_ENFORCEENCRYPTICERTREQUEST` (RPC encryption enforcement) |
| `--esc16` | Toggle the CA-wide security-extension-disable list |
| *(any `--esc*` flag)* | **Restarts the `CertSvc` service on the target CA unconditionally** — see How It Works |

**`manage-template` (template ACL/attribute persistence):**

| Switch | Plain-English meaning |
|---|---|
| `--template NAME` *(required)* | Target template |
| `--template-domain FQDN` / `--template-ldap-server HOST` | Non-default domain/LDAP server to resolve `--template` against |
| `--owner` (SID) | Set the template AD object's owner |
| `--enroll`, `--write-property`, `--write-owner`, `--write-dacl` (SID) | Grant/toggle the named right for a principal |
| `--authorized-signatures N` | Set the required-RA-signature count |
| `--manager-approval` | Toggle manager-approval requirement |
| `--supply-subject` | Toggle `ENROLLEE_SUPPLIES_SUBJECT` — directly enables/disables the ESC1 precondition |
| `--client-auth`, `--pkinit-auth`, `--smartcard-logon` | Toggle the named EKU |
| `--esc9` | Toggle `NO_SECURITY_EXTENSION` |

**`manage-self` (local-only):**

| Switch | Plain-English meaning |
|---|---|
| `--dump-certs` | Dump every certificate + exportable private key from the local machine store, as base64 PFX |

## Quick Use-Case List

- Enumerating every certificate template and enterprise CA in a domain, with built-in ESC1/2/3/4/9/13/15 (template) and ESC6/7/8/11/16 (CA) vulnerability classification
- Filtering that enumeration down to just enabled, vulnerable, client-auth-capable templates (`--filter-enabled --filter-vulnerable --filter-client-auth`) — the realistic first-pass triage command
- Re-classifying the same enumeration data against a **specific compromised principal's** group memberships (`--target-user`) rather than generic low-privileged groups, for assumed-breach scoping
- Enumerating PKI object access controls, including group-linked enterprise issuance policies (`enum-pkiobjects`)
- Exploiting ESC1 — requesting a certificate with an attacker-chosen SAN (UPN of a privileged account) via a template that allows `ENROLLEE_SUPPLIES_SUBJECT`
- Exploiting ESC3 — using a held Enrollment Agent certificate to request a certificate **as another user** without ever authenticating as them (`request-agent`)
- Exploiting ESC4 — using a template's own weak ACL to grant yourself additional rights via `manage-template`, then requesting against the now-more-exploitable template
- Backdooring a CA domain-wide via `manage-ca`'s ESC6/ESC11/ESC16 flag toggles — a persistence primitive that survives individual account resets and affects every template on that CA
- Requesting a machine-identity certificate (`--machine`) for computer-account authentication and lateral movement
- Downloading a certificate request that required manager approval, once it clears review (`request-download`)
- Renewing an already-issued certificate for quiet, low-noise persistence (`request-renew`) — reuses the original request's attributes without a fresh ESC1-style abuse pattern repeating
- Forging an entirely offline "golden certificate" from a stolen CA private key (`forge`) — no network contact, no CA-side log of any kind, structurally parallel to Golden Ticket forging
- Harvesting every certificate and exportable private key already sitting in the local machine certificate store (`manage-self --dump-certs`)
- A chained workflow: `Certify.exe request` mints a cert impersonating a privileged principal → `Rubeus.exe asktgt /certificate:` redeems it via Kerberos PKINIT for a usable TGT (see `02` for the full command pair, and `Rubeus/01 - Overview.md`'s PKINIT row)
- In-memory execution via a C2 loader's "execute .NET assembly" capability (Cobalt Strike `execute-assembly`, Covenant, Sliver `execute-assembly`) — same reflective-loading pattern documented for Rubeus/SharpUp
- Compiling the (mis-named, see History) `Disarm` configuration for an enumeration-only build in lower-risk assessment scopes where weaponization capability isn't wanted at all

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Compiled binary or in-memory host | No official binaries are ever released — every deployment is a custom Visual Studio (.NET 4.7.2) build, run standalone or reflectively loaded (`execute-assembly`, `[Certify.Program]::Main()`/`MainString()` per the README's own PowerShell-wrapper instructions) |
| Domain reachability for enumeration | LDAP/LDAPS (389/636) to a domain controller — current-user Windows-integrated bind by default, or `-u`/`-p` for alternate credentials; no elevation required |
| Enrollment rights for `request`/`request-agent` | The requesting principal (or `--target`, for `request-agent`) needs the Enroll extended right on the target template's ACL — discoverable via `enum-templates` |
| CA reachability for weaponization | MS-WCCE/MS-CSRA ride DCOM/RPC to the CA server — typically SMB (445) plus a dynamic RPC endpoint, or a fixed RPC port if the CA is configured for one |
| Held Enrollment Agent certificate (`request-agent` only) | A `.pfx` with the Certificate Request Agent EKU, obtained from a prior ESC3-vulnerable template request |
| Stolen CA private key (`forge` only) | A `.pfx`/P12 of the CA's own (or a subordinate CA's) signing key — no network reachability needed at all once obtained |
| Elevation (`--machine` only) | Requires an already-high-integrity process; `ElevationUtil.GetSystem()` self-elevates to SYSTEM via `winlogon.exe` token duplication if not already SYSTEM |
| Target OS | Windows only — every path depends on `CERTENROLLLib`/`CERTCLILib` COM interop and Win32 crypto APIs; no cross-platform build exists (see Certipy for the Linux/Python equivalent, not yet built in this repo) |
