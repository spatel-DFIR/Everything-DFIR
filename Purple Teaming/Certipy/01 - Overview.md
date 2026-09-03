# Certipy — Overview

> 🔴 **Red Flag Principle:** Certipy's most operationally reckless default lives in a single command. `certipy ca -backup` doesn't read the CA's private signing key over some quiet API — verified directly against `certipy/commands/ca.py`'s `backup()` method, it opens a Service Control Manager (SVCCTL) connection to the CA server and **creates, starts, and deletes a real Windows service literally named `Certipy`**, whose `ImagePath` is `cmd.exe /c certutil ... -backupkey -f -p certipy C:\Windows\Tasks\Certipy && move ...` — a hardcoded password (`certipy`) baked directly into the tool's own source, spawning `certutil.exe` as a child of `services.exe` on the CA server itself. If a service named `Certipy` ever appears in a CA's service list — even for the few seconds before Certipy tears it down — the CA's own signing key has already left the building. Every other Certipy command (`find`, `req`, `auth`, `shadow`, `relay`) is quiet LDAP/RPC/Kerberos traffic; this one command is a loud, source-verified SVCCTL service-creation event.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`ly4k/Certipy`](https://github.com/ly4k/Certipy), its `README.md`, `pyproject.toml`, and the live GitHub API (repo metadata, tags, releases):

- **Author/maintainer:** [Oliver Lyak](https://github.com/ly4k) (`@ly4k`), with community pull-request contributions. **License:** MIT (verified against the repo's own `LICENSE` file via the API).
- **Origin:** the repo was created **2021-10-06** — roughly two months after Will Schroeder and Lee Christensen's Black Hat USA 2021 "Certified Pre-Owned" talk and the accompanying SpecterOps whitepaper that coined the ESC1–ESC8 taxonomy (see `Purple Teaming/GhostPack/Certify/01 - Overview.md`'s History section for that origin story in full — not re-derived here). Certipy was built as the **Linux/Python-native counterpart to Certify**: same misconfiguration taxonomy, same attack surface, but implemented on Impacket rather than .NET/COM, so it runs from a Linux operator box with no Windows host, .NET runtime, or DCOM/COM interop required at all.
- **Not archived, actively maintained.** Verified live via the GitHub API: **3,622 stars**, most recent push **2026-07-30**, latest tag **`5.1.0`**. Version history shows real churn: tags run `2.0` → `2.0.9`, then jump directly to `4.0.0` (no `3.x` line ever tagged), then `4.1.0` → `4.8.2`, then a `5.0.0` "revamped" line up through the current `5.1.0` — confirming this is a living, still-evolving tool rather than a stable, frozen one.
- **PyPI package name is `certipy-ad`, not `certipy`** — confirmed directly in `pyproject.toml`'s `[project] name = "certipy-ad"` — but the installed CLI entry point is still the plain `certipy` command (`[project.scripts] certipy = "certipy.entry:main"`). Anyone installing via `pip install certipy` alone will get the wrong (unrelated) package; `pip install certipy-ad` or `pipx install certipy-ad` is the correct invocation, and this naming split is itself a minor but real fingerprint when reviewing a host's installed-package inventory.
- **Requires Python 3.12+** (`pyproject.toml`'s `requires-python = ">=3.12"`), and is built directly on **Impacket** (`impacket~=0.13.0`, the same library underpinning every tool in `Purple Teaming/Impacket/`) plus `ldap3`, `cryptography`, `dnspython`, and `httpx`. This is why Certipy's own network behavior — LDAP binds, DCE/RPC session setup, Kerberos AS-REQ/TGS-REQ construction — inherits Impacket's implementation characteristics rather than the real Windows client library's; cross-link `Impacket/00 - Impacket Overview.md` for the shared-library context rather than re-deriving it here.
- **A genuine, surprising divergence from every GhostPack tool in this repo:** unlike Rubeus, Certify, SafetyKatz, SharpUp, SharpDump, and SharpWMI — every one of which explicitly states in its own README that **no compiled binaries are ever released** — Certipy's `.github/workflows/release.yml` CI pipeline **builds and publishes a compiled Windows `Certipy.exe`** as a GitHub Release asset on every tagged version (confirmed live: the `5.1.0` release carries a `Certipy.exe` asset, ~26 MB, `github-actions[bot]`-uploaded, SHA-256 digest published alongside it). So despite being framed throughout this repo as "the Linux/Python side" of the Certify/Certipy pair, Certipy is the one of the two that actually ships an **official, consistently-built Windows executable** an operator can run with no Python environment at all — meaning PE-metadata/hash matching against the *official* release build is a real, checkable signal for Certipy in a way it structurally can never be for Certify (see `05` for how to use this without over-trusting it).
- **A `bloodhound` optional pip extra** (`pyproject.toml`'s `[project.optional-dependencies] bloodhound = ["neo4j~=5.28.1"]`) powers a genuine, source-confirmed integration point: `certipy parse`'s `-use-owned-sids` flag, paired with `-neo4j-user`/`-neo4j-pass`/`-neo4j-host`/`-neo4j-port`, connects **directly to a live BloodHound Neo4j database** and pulls every principal BloodHound has been marked "owned," feeding those SIDs straight into Certipy's own vulnerability classifier as attacker-controlled starting points — a tighter BloodHound coupling than anything documented on the Certify page. This lives only on `parse`, not on `find` itself (verified — `find`'s own parser has no Neo4j-related flags at all).
- **A second, equally real integration most write-ups miss:** `certipy parse` accepts three distinct offline input formats (`certipy/commands/parse.py`'s `ParserType` enum) — `reg` (a plain Windows `.reg` registry export), `bof` (raw output from a Beacon Object File that queried the CA's registry directly from an existing C2 implant), and **`oc2_bof`**, named explicitly for **Outflank C2**'s own registry-query BOF output format. This means an operator already running a C2 implant (Cobalt Strike, Outflank C2/OST) on a domain-joined host can collect the CA's raw registry configuration through that implant alone — no Python, no LDAP bind, no `impacket` traffic at all reaches the wire from the target — and then pipe the captured blob through Certipy's classifier entirely offline, on the attacker's own machine, later. This is Certipy's quietest possible reconnaissance path and has no equivalent documented on the Certify page.
- **ESC coverage is broader than Certify's, on paper — with an important caveat.** Certipy's README/wiki state support for the full **ESC1–ESC17** range (one more than Certify's page documents, and including ESC17 — "Enrollee-Supplied Subject for Server Authentication," the newest addition covered in `06 - Privilege Escalation` of Certipy's own wiki). But — verified directly against the wiki's own per-ESC "Identification" sections — `certipy find` **auto-flags only 13 of the 17** via a literal `[!] Vulnerabilities` line in its output: **ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC9, ESC11, ESC13, ESC15, ESC16, ESC17**. Four (**ESC5, ESC10, ESC12, ESC14**) are explicitly documented as **not automatically detected** — they require BloodHound ACL analysis, manual registry inspection on a server Certipy has no access to, or (for ESC12, a narrow YubiHSM2-specific local-shell scenario) an unrelated hardware vulnerability entirely outside AD CS misconfiguration. See the ESC table below for the full breakdown — a clean `certipy find` run is not proof an environment has no ESC exposure.

## How It Works

### Enumeration — `find` reads LDAP and the CA's own remote registry

`certipy find` binds LDAP against a domain controller and reads the same PKI object classes documented in depth on `Purple Teaming/GhostPack/Certify/01 - Overview.md`'s "Enumeration" table (`CN=Certification Authorities`, `CN=Enrollment Services`, `CN=NTAuthCertificates`, `CN=Certificate Templates`, `CN=OID`, all under `CN=Public Key Services,CN=Services,<Configuration NC>`) — not re-derived here since the LDAP container layout is identical regardless of which tool reads it. Where Certipy diverges mechanically from Certify:

- **Same Remote Registry Protocol (RRP) fallback for CA-level checks.** Verified in `certipy/commands/find.py`: Certipy opens `ncacn_np:445[\pipe\winreg]` to the CA server directly (with up to 3 retry attempts if the Remote Registry service needs to auto-start) to read `InterfaceFlags`/`EditFlags`/`DisableExtensionList` for the ESC6/ESC11/ESC16 checks — the identical RRP-over-port-445 mechanism Certify uses, not a DCOM/RPC call into the CA's own `ICertAdmin` interface.
- **`-dc-only` deliberately skips the CA touch entirely** — a pure-LDAP enumeration mode that never opens a connection to the CA server at all (no RRP, no web-enrollment probe), useful when the CA itself is more closely monitored than the DC.
- **Default output is two files, written simultaneously, every run with no flags at all.** Verified in `find.py`'s `_save_output()`: if none of `-text`/`-json`/`-csv` is passed, Certipy writes **both** `<prefix>_Certipy.txt` and `<prefix>_Certipy.json` to the current working directory in the same invocation — not one file, both. `<prefix>` defaults to `datetime.now().strftime("%Y%m%d%H%M%S")` (a 14-digit timestamp) unless `-output <prefix>` overrides it. `-stdout` suppresses the `.txt` write and prints to console instead, but the `.json` file still lands on disk regardless. `-csv` produces two further, separate files: `<prefix>_Templates_Certipy.csv` and `<prefix>_CAs_Certipy.csv`. This timestamp-prefixed, dual-file default footprint is a concrete, checkable filesystem artifact — see `03`.

### The ESC vulnerability classifier — what's auto-flagged vs. what isn't

| ESC | Auto-flagged by `certipy find`? | What triggers it |
|---|---|---|
| ESC1 | ✅ Yes | `ENROLLEE_SUPPLIES_SUBJECT` + client-auth EKU + attacker enrollment rights + no approval gate |
| ESC2 | ✅ Yes | Template has no EKU restriction, or the explicit "Any Purpose" EKU (`2.5.29.37.0`) |
| ESC3 | ✅ Yes | Template issues the "Certificate Request Agent" EKU (`1.3.6.1.4.1.311.20.2.1`) to low-privileged enrollees |
| ESC4 | ✅ Yes | Attacker-controlled owner, or an ACE granting `WriteOwner`/`WriteDacl`/`GenericAll` on the template object |
| ESC5 | ❌ **No** | Vulnerable ACLs on other PKI AD objects (`NTAuthCertificates`, OID container, etc.) — needs BloodHound/`Get-Acl`/`ADSIEdit` |
| ESC6 | ✅ Yes | CA-wide `EDITF_ATTRIBUTESUBJECTALTNAME2` flag — enrollee can specify arbitrary SAN via request attributes |
| ESC7 | ✅ Yes | `ManageCA`/`ManageCertificates` granted to a non-admin principal on the CA object |
| ESC8 | ✅ Yes | Web Enrollment (HTTP, or HTTPS with Channel Binding/EPA disabled) — NTLM-relayable |
| ESC9 | ✅ Yes | `CT_FLAG_NO_SECURITY_EXTENSION` set on the template — no SID security extension in issued certs |
| ESC10 | ❌ **No** | Schannel's `CertificateMappingMethods` registry key on the DC/target server allows UPN mapping — requires host access Certipy doesn't have |
| ESC11 | ✅ Yes | CA's ICPR (RPC) interface doesn't enforce `IF_ENFORCEENCRYPTICERTREQUEST` — NTLM-relayable over RPC |
| ESC12 | ❌ **No** | Narrow YubiHSM2 local-software-stack weakness (Hans-Joachim Knobloch's research) exploitable only from an existing low-privileged shell on the CA host — not an AD CS misconfiguration at all |
| ESC13 | ✅ Yes | Template's Issuance Policy OID is linked (`msDS-OIDToGroupLink`) to a privileged AD group |
| ESC14 | ❌ **No** | Weak `altSecurityIdentities` explicit-mapping strings on a target account — needs manual/BloodHound review |
| ESC15 ("EKUwu", CVE-2024-49019) | ✅ Yes | Schema-v1 template + `ENROLLEE_SUPPLIES_SUBJECT`, on an unpatched CA — lets an attacker inject arbitrary Application Policy OIDs |
| ESC16 | ✅ Yes | CA-wide `DisableExtensionList` includes the SID security extension OID — every issued cert lacks it, CA-wide |
| ESC17 | ✅ Yes | `ENROLLEE_SUPPLIES_SUBJECT` + a **Server Authentication**-capable EKU (not client-auth) — used to impersonate servers like WSUS, not user accounts |

ESC1–ESC4, ESC6–ESC9, ESC11, ESC13, ESC15–ESC17 map onto exactly the same underlying AD CS misconfigurations Certify's classifier checks (cross-link `GhostPack/Certify/01 - Overview.md`'s own ESC table — the mechanics are identical regardless of which tool reads them); this page does not re-derive the ESC1 walkthrough Certify's page already covers end-to-end.

### Certificate request — three delivery protocols, one default

`certipy req` submits the CSR via one of three transports (`certipy/lib/req.py`'s `RPCRequestInterface`/`DCOMRequestInterface`/`WebRequestInterface`), selected by flag:

| Transport | Flag | Protocol detail |
|---|---|---|
| RPC (default) | *(none needed)* | MS-ICPR (`ICertRequestD`, UUID `91ae6020-9e3c-11cf-8d7c-00aa00c091be`) over a dynamic RPC endpoint or `\pipe\cert` named pipe |
| DCOM | `-dcom` | Same `ICertRequestD` interface, reached via DCOM activation instead of a raw RPC bind — a mechanically distinct code path Certify does not offer at all (Certify's request path is always DCOM/COM-interop by nature of being a .NET tool) |
| Web Enrollment | `-web` | HTTP(S) POST to `/certsrv/certfnsh.asp`, with `-http-scheme`/`-http-port` controlling the target URL and `-no-channel-binding` disabling EPA on the client side |

Regardless of transport, a successful request is saved as `<identity>.pfx`, where `<identity>` is derived (verified in `_determine_output_filename()`) from the **certificate's own returned identity** (its UPN/SAN, lowercased, with a trailing `$` stripped for machine accounts) — not from the `-out` flag unless explicitly given, and not from the requesting user's own username if the certificate names someone else (e.g. an ESC1 request naming `administrator@corp.local` saves to `administrator.pfx` even though the *requester* was a low-privileged account). A **pending** request (manager-approval-gated) writes its freshly generated **unencrypted PEM private key to `<request-id>.key` on disk immediately**, before any certificate exists — `certipy req -retrieve` later pairs that key file back up with the now-issued cert.

### Authentication — PKINIT plus the same U2U hash-recovery trick as Rubeus

`certipy auth -pfx <file>` performs RFC 4556 PKINIT with the loaded certificate to obtain a TGT, then — unless `-no-hash` is passed — follows up with a **User-to-User (U2U) Kerberos exchange** (confirmed in `auth.py`: an AP-REQ built for delegation, then a TGS-REQ with `enc-tkt-in-skey` set) to recover the account's own **NT hash**, exactly the same mechanic Rubeus's `asktgt /getcredentials` uses (cross-link `Rubeus/01 - Overview.md`'s PKINIT row rather than re-deriving the U2U trick here). Output naming: a ccache saves as `<identity>.ccache` (`-kirbi` instead saves `<identity>.kirbi`); `-no-save` skips writing anything to disk. `-ldap-shell` swaps Kerberos entirely for a **Schannel TLS client-certificate bind to LDAPS (port 636)**, dropping the operator into an interactive `# ` prompt for direct LDAP commands as the mapped identity — the mechanism ESC10's exploitation and machine-account impersonation both rely on.

### Relay — one command, two distinct relay targets

`certipy relay -target <scheme>://<host>` implements NTLM relay against AD CS's two exploitable endpoints (ESC8 and ESC11) as one command, selected purely by the target URL's **scheme** (verified in `relay.py`): `http://`/`https://` relays to Web Enrollment (`/certsrv/certfnsh.asp`), `rpc://` relays to the CA's ICPR RPC interface directly (`-ca <name>` becomes required for the RPC path). A bare hostname with no scheme silently defaults to `http://`. The relay server listens on `0.0.0.0:445` by default (`-interface`/`-port` override), the same SMB-listener pattern Impacket's `ntlmrelayx.py` uses — cross-link `Impacket/ntlmrelayx/` for the shared coercion-tooling ecosystem (PetitPotam, Coercer, etc.) rather than re-deriving it.

### Shadow Credentials — `msDS-KeyCredentialLink` abuse

`certipy shadow` (`add`/`list`/`remove`/`clear`/`info`/`auto`) generates a fresh **RSA-2048 self-signed certificate valid for roughly 80 years (-40/+40 years from issuance)** and a matching `KeyCredential` structure with a randomly generated `DeviceID`, then writes it directly into the target account's `msDS-KeyCredentialLink` attribute via an LDAP `MODIFY_REPLACE` (confirmed in `shadow.py`'s `generate_key_credential()`/`add_new_key_credential()`). `auto` chains generation, the LDAP write, and an immediate `certipy auth` in one command; the deliberately absurd validity window makes this a durable, low-maintenance persistence primitive once a `GenericWrite`/`WriteProperty` foothold on any account is obtained — no password reset on the target account invalidates it, since it never touches the password at all.

### CA private-key theft — the service-creation mechanic (see Red Flag above)

`certipy ca -backup` is covered in the Red Flag callout above in full; summarized here for the mechanics table: SVCCTL service creation (`Certipy`) → `certutil -backupkey -f -p certipy` on the CA server, dumped to `C:\Windows\Tasks\Certipy\` → file retrieved and saved locally first as raw `pfx.p12` (still password-protected with the hardcoded `certipy` string), then re-packaged with no password as `<CA-Common-Name>.pfx` → cleanup deletes the server-side temp directory and the `Certipy` service itself. The resulting `.pfx` feeds directly into `certipy forge` for fully offline "Golden Certificate" minting — the certificate-world parallel to a Golden Ticket forged from a stolen `krbtgt` key (cross-link `Mimikatz/kerberos (Golden-Silver Ticket)/`, `Rubeus/`'s `golden` command, and `GhostPack/Certify/01 - Overview.md`'s own `forge` verb, all three structurally identical once the signing key is in hand).

### Offline analysis — `parse`

`certipy parse <file> -format {reg,bof,oc2_bof}` runs the identical vulnerability classifier `find` uses against **offline-collected** registry/template data instead of a live LDAP session — see History above for the `reg`/`bof`/`oc2_bof` format distinction and the BloodHound-owned-SIDs integration this command uniquely exposes via `-use-owned-sids`.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| LDAP/LDAPS | `find`'s PKI-container enumeration; `account`'s attribute reads/writes; `shadow`'s `msDS-KeyCredentialLink` write — same containers as `GhostPack/Certify/` |
| Remote Registry Protocol (RRP, `\pipe\winreg`, port 445) | `find`'s ESC6/ESC9/ESC11/ESC16 CA-registry checks |
| MS-ICPR / MS-WCCE (`ICertRequestD`, RPC or DCOM) | `req` (RPC/DCOM transports), `relay -target rpc://` (ESC11) |
| HTTP/HTTPS (Web Enrollment, `/certsrv/`) | `req -web`, `relay -target http(s)://` (ESC8) |
| SVCCTL (Service Control Manager Remote Protocol) | `ca -backup`'s ephemeral `Certipy` service — see Red Flag |
| Kerberos PKINIT (RFC 4556) + U2U | `auth` — certificate-to-TGT exchange, plus NT-hash recovery via U2U, identical to Rubeus's `/getcredentials` |
| Schannel (TLS client-cert auth to LDAPS) | `auth -ldap-shell` |
| SMB (445) as an NTLM-relay listener | `relay` |
| Beacon Object File output (C2-native, offline) | `parse -format bof`/`-format oc2_bof` — reads registry data collected by an existing implant, no network traffic of Certipy's own |
| Neo4j Bolt protocol | `parse -use-owned-sids` — direct query against a live BloodHound database |

## Command-Line Switches — Quick Reference

Verified live against [`ly4k/Certipy`](https://github.com/ly4k/Certipy)'s `certipy/commands/*.py` and `certipy/commands/parsers/*.py` source and the project's own GitHub wiki (`08 - Command Reference`). All 11 top-level commands, each inheriting a shared set of connection/auth flags (`-u`/`-p`, `-hashes`, `-k` for Kerberos ccache auth, `-aes`, `-dc-ip`, `-target`/`-ns`) from Impacket-style target argument parsing — not repeated per table below.

**`find` (enumeration):**

| Switch | Plain-English meaning |
|---|---|
| `-text` / `-stdout` / `-json` / `-csv` | Output format(s) — with none specified, both `.txt` and `.json` are written by default (see How It Works) |
| `-output <prefix>` | Override the default timestamp-based output filename prefix |
| `-enabled` | Only show templates actually published/enabled on a CA |
| `-dc-only` | Skip the CA server entirely — LDAP-only enumeration, no RRP/web-enrollment probe |
| `-vulnerable` | Only show templates/CAs flagged with at least one ESC ID (based on nested group membership resolution) |
| `-oids` | Enumerate Issuance Policy OID objects and their `Linked Group` (ESC13 context) |
| `-hide-admins` | Suppress well-known admin-principal ACEs from the printed output (noise reduction) |
| `-sid` / `-dn` | Supply the current user's own SID/DN explicitly — useful for cross-domain/cross-forest enumeration |

**`req` (certificate request):**

| Switch | Plain-English meaning |
|---|---|
| `-ca <name>` | Target CA (required for RPC/DCOM) |
| `-template <name>` | Certificate template (default: `User`) |
| `-upn` / `-dns` / `-sid` | Attacker-controlled SAN values — the ESC1/ESC6/ESC9/ESC16/ESC17 impersonation lever |
| `-on-behalf-of <domain\account>` | ESC3 — request as another user, using a held Enrollment Agent cert supplied via `-pfx` |
| `-retrieve <ID>` | Fetch a previously submitted, now-approved pending request by its ID |
| `-renew` | Renew an already-issued certificate, using `-pfx`/`-pfx-password` for the existing cert |
| `-archive-key` | Submit the private key for CA-side archival in the request (key-archival templates) |
| `-cax-cert` | Retrieve the CAX certificate needed for key-archived relay scenarios |
| `-web` / `-dcom` | Force Web Enrollment or DCOM transport instead of the default RPC |
| `-application-policies <OID...>` | Inject Application Policy OIDs (ESC15/EKUwu on unpatched CAs) |
| `-out <file>` | Explicit output filename, overriding the identity-derived default |

**`auth` (pass-the-certificate):**

| Switch | Plain-English meaning |
|---|---|
| `-pfx <file>` | Certificate + private key to authenticate with (required) |
| `-username` / `-domain` | Explicitly target a principal when the cert's own identity is ambiguous |
| `-no-hash` | Skip the U2U NT-hash-recovery follow-up request |
| `-no-save` | Don't write a ccache/kirbi file to disk |
| `-kirbi` | Save as `.kirbi` instead of the default `.ccache` |
| `-ldap-shell` | Authenticate via Schannel directly to LDAPS instead of Kerberos PKINIT — drops into an interactive LDAP shell |

**`relay` (NTLM relay to AD CS — ESC8/ESC11):**

| Switch | Plain-English meaning |
|---|---|
| `-target <scheme>://<host>` | `http(s)://` for Web Enrollment (ESC8), `rpc://` for ICPR (ESC11) — scheme selects the attack |
| `-ca <name>` | Required for the RPC target |
| `-template <name>` | Template to request against once a victim authenticates |
| `-interface` / `-port` | Listener bind address/port (default `0.0.0.0:445`) |
| `-forever` | Keep the listener alive after one successful relay instead of exiting |
| `-no-skip` | Don't skip users already attacked in this run |
| `-enum-templates` | Relay just to enumerate available templates, without requesting a cert |

**`shadow` (Key Credential / Shadow Credentials abuse):**

| Action/switch | Plain-English meaning |
|---|---|
| `auto` | Generate, write, and immediately authenticate — one-shot takeover |
| `add` | Write a new Key Credential without authenticating |
| `list` / `info` | Enumerate existing Key Credentials on the target (with DeviceIDs) |
| `remove` / `clear` | Remove one (`-device-id`) or all Key Credentials — cleanup |
| `-account <name>` | Target AD account |

**`ca` (CA administration):**

| Switch | Plain-English meaning |
|---|---|
| `-ca <name>` | Target CA (required) |
| `-backup` | Steal the CA's private signing key — see Red Flag callout |
| `-list-templates` / `-enable-template` / `-disable-template` | View/modify which templates a CA issues |
| `-issue-request <ID>` / `-deny-request <ID>` | Approve/deny a pending request (requires `ManageCA`/`ManageCertificates` — ESC7) |
| `-add-officer` / `-remove-officer` | Grant/revoke `ManageCertificates` on a principal |

**`forge` (offline golden certificate):**

| Switch | Plain-English meaning |
|---|---|
| `-ca-pfx <file>` | Stolen CA private key (from `ca -backup`); if omitted, forges a self-signed test cert instead |
| `-upn` / `-dns` / `-sid` | Impersonated identity's SAN values |
| `-crl <ldap-path>` | CRL distribution point — required when forging against a subordinate (non-root) CA for chain validation |
| `-out` | Save the forged PFX to disk |

**`shadow`/`template`/`account`/`cert`/`ca` share these persistence/manipulation switches:**

| Command | Key switch | Plain-English meaning |
|---|---|---|
| `template` | `-write-default-configuration` | Rewrite a template's config to an ESC1-shaped default (ESC4 exploitation) |
| `template` | `-save-configuration` / `-write-configuration` | Back up / restore a template's full config as JSON (cleanup after ESC4) |
| `account` | `create` / `read` / `update` / `delete` | Manage AD account attributes (`-upn`, `-dns`, `-spns`, `-pass`) — the ESC9/ESC10 UPN-manipulation primitive, and rogue machine-account creation |
| `cert` | `-pfx` / `-key` / `-cert` / `-export` | Local-only PFX/PEM/DER conversion, no network traffic |

**`parse` (offline analysis):**

| Switch | Plain-English meaning |
|---|---|
| `file` | A `.reg` export or captured BOF output |
| `-format {reg,bof,oc2_bof}` | Input format — `oc2_bof` is Outflank C2's own registry-query BOF output |
| `-sids` / `-published` | Manually supply owned SIDs / published-template context the offline data lacks |
| `-use-owned-sids` + `-neo4j-*` | Pull "owned" principal SIDs directly from a live BloodHound Neo4j database |

## Quick Use-Case List

- Enumerating every certificate template and CA in a domain with full ESC1–ESC17-aware vulnerability classification (`find`)
- `-dc-only` enumeration when the CA server itself is more tightly monitored than the DC
- Offline vulnerability analysis of registry data collected by a separate C2 implant, including Outflank C2's own BOF format (`parse -format oc2_bof`) — zero LDAP/RPC traffic of Certipy's own reaching the target
- Cross-referencing enumeration results against a live BloodHound "owned" dataset (`parse -use-owned-sids`)
- Exploiting ESC1 — requesting a cert with an attacker-chosen UPN/SID via a template allowing `ENROLLEE_SUPPLIES_SUBJECT`
- Exploiting ESC3 — enrollment-agent on-behalf-of requests (`-on-behalf-of`)
- Exploiting ESC4 — hijacking a template's own weak ACL via `template -write-default-configuration`, then requesting against it
- Exploiting ESC6/ESC9 combined — CA-level SAN injection paired with a no-SID-extension template to bypass Full Enforcement mode
- Exploiting ESC7 — abusing `ManageCA`/`ManageCertificates` rights to enable a vulnerable template and approve your own pending request
- Exploiting ESC8 — NTLM relay to AD CS Web Enrollment (`relay -target http(s)://`), typically chained with a coercion tool
- Exploiting ESC11 — NTLM relay to the CA's RPC/ICPR interface (`relay -target rpc://`)
- Exploiting ESC13 — enrolling against a template whose Issuance Policy is linked to a privileged AD group
- Exploiting ESC15 ("EKUwu") — injecting arbitrary Application Policy OIDs into a Schema v1 template's CSR on an unpatched CA
- Exploiting ESC17 — impersonating a server identity (e.g. WSUS) via a Server-Authentication-EKU template with enrollee-supplied subject
- UPN-manipulation attacks against ESC9/ESC10 (`account update -upn`, revert-after-use pattern)
- Installing Shadow Credentials for certificate-based account takeover or long-lived persistence, with no password reset required (`shadow auto`)
- Stealing a CA's private signing key via the SVCCTL service-creation mechanic (`ca -backup`), then forging arbitrary offline "Golden Certificates" (`forge`)
- Passing a stolen/forged/requested certificate to obtain a Kerberos TGT and the account's own NT hash in one step (`auth`)
- Authenticating via Schannel directly to LDAPS for an interactive LDAP shell instead of going through Kerberos (`auth -ldap-shell`)
- Local-only PFX/PEM/DER certificate format conversion and key extraction (`cert`) for staging material obtained elsewhere
- A chained workflow: `certipy find` → `certipy req` (ESC1) → `certipy auth` → `secretsdump.py`/`wmiexec.py` (see `02` for the full command chain, cross-linked to `Impacket/`)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| `pip install certipy-ad` (or `pipx install certipy-ad`) | Package name differs from the `certipy` command it installs — see History |
| Python 3.12+ | Current `pyproject.toml` requirement; older installs may run on an older interpreter if using a pinned older release |
| Domain reachability for enumeration | LDAP/LDAPS (389/636) to a DC — any valid domain credential (password, NTLM hash, AES key, or Kerberos ccache via `-k`), no elevation required |
| CA reachability for registry-based ESC checks | RRP over SMB (445) to the CA server — anonymous-adjacent, Certify's own source notes this "appears to work even if admin rights aren't available" |
| Enrollment rights for `req` | The requesting principal needs the Enroll extended right on the target template — discoverable via `find` |
| CA reachability for weaponization | RPC/DCOM (dynamic port or `\pipe\cert`) or HTTP(S) (80/443) to the CA server, depending on transport |
| Coercion tooling for `relay` (ESC8/ESC11) | Certipy relays; a separate tool (PetitPotam, Coercer, `ntlmrelayx.py`'s own coercion helpers) triggers the privileged authentication |
| `GenericWrite`/`WriteProperty` on a target account | Required for `shadow` (Key Credential write) and for the ESC9/ESC10 UPN-manipulation primitive |
| Local admin on the CA server (transitively, via SVCCTL) | Required for `ca -backup` to succeed — this is a post-CA-compromise action, not an initial-foothold one |
| Stolen CA private key (`forge` only) | A `.pfx` of the CA's own (or a subordinate CA's) signing key, typically obtained via `ca -backup` |
| Neo4j/BloodHound access (`parse -use-owned-sids` only) | A reachable BloodHound Neo4j instance with `-neo4j-user`/`-neo4j-pass` |
| Target OS | Fully cross-platform operator side (Linux, macOS, Windows) — Certipy itself has no Windows-only dependency, unlike Certify (see Certify's own Prerequisites table for the contrast) |
