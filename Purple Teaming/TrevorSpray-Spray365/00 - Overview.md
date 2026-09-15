# TrevorSpray / Spray365 — Overview

This folder bundles **two independent Python password-spraying tools targeting Microsoft 365/Entra ID (and, for TrevorSpray, several other identity providers)** — [`blacklanternsecurity/TREVORspray`](https://github.com/blacklanternsecurity/TREVORspray) and [`MarkoH17/Spray365`](https://github.com/MarkoH17/Spray365) — because they're same-purpose alternatives per the pattern already set by `../Advanced IP Scanner-SoftPerfect NetScan/`. They share no codebase and no author, but they solve the identical first problem in a cloud-identity engagement — *"which of these usernames/passwords actually works against this tenant"* — with genuinely different architectures, evasion philosophies, and (as of this build) genuinely different maintenance states.

## Contents
- [Why These Two Are Bundled](#why-these-two-are-bundled)
- [The Core Distinction — Built-In IP Rotation vs. Identity Randomization](#the-core-distinction--built-in-ip-rotation-vs-identity-randomization)
- [Side-by-Side Comparison](#side-by-side-comparison)
- [When an Analyst Sees One vs. the Other](#when-an-analyst-sees-one-vs-the-other)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## Why These Two Are Bundled

Both tools were found in the same SEC560-personal-index gap analysis (`IDEAS.md`, Wave 3) as the two Azure/Entra ID password-spraying entries, and both attack the identical target surface — a tenant's password-based sign-in endpoint(s) — with the same operator goal: find one valid credential, then (optionally) characterize how far that credential reaches. Neither tool has any dedicated MITRE ATT&CK Software entry, and — verified directly against the live [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) technique page's full Procedure Examples table — **neither is even named as a procedure example**, a genuine gap in ATT&CK's own coverage of this space that both sub-tool pages flag explicitly.

## The Core Distinction — Built-In IP Rotation vs. Identity Randomization

Read each sub-tool's own `01 - Overview.md` for full mechanics — this is the fast disambiguation an analyst needs before reading either page in depth:

```
TrevorSpray                                   Spray365
────────────                                  ────────
Actively maintained (2026)                    Archived by its own author
Hand-built HTTP requests, own AADSTS parser   Genuine MSAL ROPC flow (Microsoft's own library)
8 auth modules: msol/adfs/owa/okta/           Microsoft/Azure AD only — no other IdP support
  anyconnect/auth0/jumpcloud/officehome
BUILT-IN IP diversity:                        NO built-in IP diversity — needs external
  SSH round-robin, IPv6-subnet spoofing         -x/--proxy chaining for source-IP rotation
Default-on legacy-auth MFA-bypass "loot"      Two-step execution-plan model (generate → spray)
  burst on every valid credential                with resumability and an "audit" mode that
                                                   cross-products client_id×endpoint×user_agent
Static hardcoded UA by default                Random client_id/endpoint/UA PER CREDENTIAL
  (defeated by --random-useragent)              by default — defeats AppId-based hunting
Built-in domain recon + 3 user-enum methods   No recon/enumeration features of its own
                    │                                       │
                    ▼                                       ▼
     Population-wide spray tool with            Precision instrument for mapping WHICH
     first-class evasion infrastructure         application/resource identity bypasses a
     as a core design goal                      tenant's Conditional Access, once a credential
                                                 is already known
```

TrevorSpray answers **"spray this user list against this tenant (or IdP), stay under the radar via IP rotation, and automatically test how far any hit reaches into legacy-auth-exposed mail/management surfaces."** Spray365 answers **"given this credential (found or already known), which of Microsoft's own first-party application identities and resource endpoints does this tenant's Conditional Access fail to properly restrict"** — its `audit` mode in particular is less a spray tool and more a **Conditional Access fuzzer**. An operator with a fresh target list reaches for TrevorSpray first; an operator who already has one working credential and wants to know exactly how exploitable it is reaches for Spray365's `audit` mode.

## Side-by-Side Comparison

| | TrevorSpray (TREVORspray) | Spray365 |
|---|---|---|
| Author | TheTechromancer / Black Lantern Security | Mark Hedrick (MarkoH17) |
| License | GPL-3.0 | MIT |
| Maintenance state (verified live via GitHub API) | **Active** — pushed 2026-05-21, not archived | **Archived** — last push 2025-06-24, last tagged release `0.2.2-beta` (2022-07-14) |
| Core auth protocol | Hand-built OAuth2 ROPC HTTP requests, own AADSTS-code parser | Microsoft's own MSAL library, `acquire_token_by_username_password()` |
| Supported identity providers | O365/Azure AD, ADFS, OWA, Okta, Cisco AnyConnect, Auth0, JumpCloud, OfficeHome | Microsoft/Azure AD (`/organizations` authority) only |
| Built-in IP rotation | **Yes** — SSH round-robin, IPv6-subnet spoofing | **No** — requires external `-x/--proxy` chaining |
| Application-identity randomization | Only with `--random-useragent` (and only for `msol`'s `client_id`) | **Default-on** for both `client_id` and `endpoint`, from a ~45×12 catalog sourced from `AADInternals` |
| Recon/user-enumeration | Built-in (`--recon`: DNS, tenant ID, federation, sibling domains; 3 user-enum methods) | None |
| Post-success MFA-bypass "loot" phase | **Default-on** — 9 legacy-protocol probes per valid credential | None — `review --show_valid_aad_access` instead maps which app/resource combos succeeded |
| Resumability | Automatic (`tried_logins.txt`), transparent | Manual (`-R/--resume_index` against the plan's own position) |
| Execution model | Single invocation, live | Two-step: `generate` a plan file, then `spray` it (separable/replayable) |
| Output artifacts | `~/.trevorspray/{trevorspray.log, tried_logins.txt, existent_users.txt, valid_logins.txt, loot/}` | Operator-named `.s365` plan file (cleartext creds) + `spray365_results_<timestamp>.json` |
| MITRE ATT&CK Software entry | None (verified live) | None (verified live) |

## When an Analyst Sees One vs. the Other

- **Many distinct `AppDisplayName`/`AppId` values, static User-Agent, `resource=graph.windows.net`, and a burst of IMAP/SMTP/POP3/EWS/EAS/UM sign-ins immediately following one hit** → TrevorSpray's default `msol` module plus its default-on loot phase; see `TrevorSpray/04 - Target Evidence.md`.
- **Sign-ins against `login.microsoftonline.com/organizations` (not a tenant-specific authority), varied User-Agents, and dozens of distinct `AppId`s scattered across a moderate volume of users** → Spray365's `generate normal` default randomization; see `Spray365/04 - Target Evidence.md`.
- **One user, one or two passwords, but 30+ distinct `AppId` values in a tight 15-minute window** → Spray365's `audit` mode — a strong indicator the credential is **already confirmed valid** and the operator is actively mapping Conditional Access gaps, not still searching for a working password. Treat as higher-severity than a routine spray hit.
- **Sign-in traffic against an on-prem ADFS server, or an OWA/Exchange front-end with internal-format usernames** → TrevorSpray's `adfs`/`owa` modules — this traffic never touches Entra ID Sign-in Logs at all; pivot to the on-prem server's own event logs per `TrevorSpray/04 - Target Evidence.md`.
- **A recovered `.s365` file or `~/.trevorspray/` directory on a source host** → the single richest available artifact either way; see each sub-tool's own `03 - Source Evidence.md` for exactly what each exposes (Spray365's plan file exposes the full candidate password list up front; TrevorSpray's `valid_logins.txt` only accumulates confirmed hits).

## Sub-Tool Table of Contents

| Sub-Tool | Covers |
|---|---|
| [`TrevorSpray/`](<TrevorSpray/01%20-%20Overview.md>) | Actively maintained, 8-identity-provider spray tool with built-in SSH/IPv6-subnet IP rotation, domain recon, user enumeration, and a default-on 9-protocol legacy-auth MFA-bypass loot phase on every valid `msol` credential |
| [`Spray365/`](<Spray365/01%20-%20Overview.md>) | Archived two-step execution-plan spray tool built on Microsoft's own MSAL library; default per-credential client_id/endpoint randomization (sourced from `AADInternals`) and a dedicated `audit` mode for fingerprinting Conditional Access gaps against an already-known credential |

Both sub-tool folders share this page's comparison table and "when an analyst sees one vs. the other" framing above — neither re-derives it.
