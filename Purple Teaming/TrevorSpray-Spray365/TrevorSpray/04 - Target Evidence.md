# TrevorSpray — Target Evidence

What the operation leaves on the **target** — the Entra ID tenant (and, for `adfs`/`owa`/`anyconnect`, any on-prem-adjacent infrastructure). Full field-by-field Sign-in Log mechanics, KQL collection, and the general password-spray investigation flow already live in `Cloud/Microsoft/Entra ID/`; this file gives TrevorSpray-specific values within that structure rather than re-deriving it.

## Contents
- [Start Here: The Existing Password Spray Playbook](#start-here-the-existing-password-spray-playbook)
- [Entra ID Sign-in Logs — the msol Module](#entra-id-sign-in-logs--the-msol-module)
- [The Loot-Phase Burst — the Strongest Target-Side Signal](#the-loot-phase-burst--the-strongest-target-side-signal)
- [Non-msol Modules — Where the Evidence Lives Instead](#non-msol-modules--where-the-evidence-lives-instead)
- [Recon Phase — What Does and Doesn't Log](#recon-phase--what-does-and-doesnt-log)
- [Identity Protection Risk Detections](#identity-protection-risk-detections)
- [Network-Layer Evidence](#network-layer-evidence)
- [Building a Timeline](#building-a-timeline)

---

## Start Here: The Existing Password Spray Playbook

`Cloud/Microsoft/Entra ID/Playbooks/Password Spray.md` already documents the general investigation flow for any O365/Azure AD password-spray incident — the `50126`-across-many-users-from-few-IPs KQL pattern, the legacy-auth-favoring hypothesis, and the contain/eradicate/recover steps. Everything below is the TrevorSpray-specific detail layered on top of that playbook, not a replacement for it.

## Entra ID Sign-in Logs — the `msol` Module

Full field mechanics live in `Cloud/Microsoft/Entra ID/Sign-in Logs/Sign-in Logs for DFIR.md`. TrevorSpray-specific values within that structure:

- **`AppId` / `AppDisplayName`**: the default `msol` module authenticates as client ID `38aa3b87-a06d-4817-b275-7a316988d93b` — Microsoft's own first-party **"Microsoft Azure PowerShell"** application. This is a legitimate, common `AppDisplayName` in almost any tenant with normal admin PowerShell usage, so it does **not** stand out on its own — the same "don't rely on AppDisplayName alone" caveat already documented for `AADInternals/` applies here, since both tools reuse genuine Microsoft first-party client IDs. With `--random-useragent`, the `msol` module additionally randomizes its `client_id` to a fresh UUID on every request — meaning `AppId` itself becomes non-constant across a single spray run when that flag is used, actively defeating an `AppId`-based correlation hunt.
- **`ResultType`**: maps directly to the `AADSTS` code table in `01 - Overview.md`. `50126` (invalid credential) is expected in bulk across a spray; `0` (success) or the "valid but blocked" codes (`53003`/`50076`/`50079`/`50158`/`50055`/`50131`) are the hits worth chasing per the Playbook's own "Did Any Account Fall?" table.
- **`ResourceDisplayName`**: `msol` requests `resource=https://graph.windows.net` — the now-retired **Azure AD Graph API**. This resource choice itself is a minor anomaly signal: legitimate first-party "Microsoft Azure PowerShell" traffic in a modern tenant increasingly targets Microsoft Graph (`graph.microsoft.com`) rather than the deprecated AAD Graph endpoint, so a cluster of AAD-Graph-resource sign-ins from that `AppId` is worth a second look even outside an obvious spray pattern.
- **`UserAgent`**: default is a hardcoded **iPhone Mobile Safari string** (`Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 ...) ... Version/13.0.3 Mobile/15E148 Safari/604.1`) across every module unless overridden — a single, static, dated iOS User-Agent appearing across many distinct sign-in attempts (rather than the mix of UAs a real user population produces) is a durable fingerprint that survives IP rotation entirely, since it's baked into the tool's source rather than tied to network path.
- **`ClientAppUsed`**: for the `msol` module's raw OAuth2 ROPC POST, this typically surfaces as a legacy/other-clients category rather than a modern browser sign-in — consistent with the Password Spray playbook's own "legacy-auth-favoring" hypothesis even for the primary spray traffic, not just the loot phase.

## The Loot-Phase Burst — the Strongest Target-Side Signal

This is the single most distinctive, hardest-to-miss TrevorSpray artifact, and it doesn't require catching the spray traffic itself:

**On any valid `msol` credential, expect up to 9 additional, distinct sign-in/auth events for the same user, from the same source IP, within a few seconds of the triggering hit** — one each for IMAP, SMTP, POP3, EWS, EAS, Exchange Online PowerShell, Autodiscover, Unified Messaging, and the Azure Service Management API (unless `-nl/--no-loot` was passed). Each targets a genuinely different Microsoft endpoint and shows up with a **different `ClientAppUsed`/protocol signature** in the Sign-in Logs than the original `msol` hit:

| Loot probe | Expected Sign-in Log signature |
|---|---|
| IMAP4 | `ClientAppUsed: IMAP4` — a classic legacy-auth entry, directly matching the Playbook's own "Check legacy auth" KQL block |
| SMTP | `ClientAppUsed: Authenticated SMTP` or `SMTP` |
| POP3 | `ClientAppUsed: POP3` |
| EWS | `ClientAppUsed: Exchange Web Services` — success here also means a GAL/OAB `.lzx` download occurred, an Exchange Online mailbox-access event worth correlating separately if Message Trace / mailbox audit logging is enabled |
| EAS | `ClientAppUsed: Exchange ActiveSync` |
| Exchange Online PowerShell | `ClientAppUsed: Exchange Online PowerShell` — notable because this is also a **management-plane** access path, not just mail access |
| Autodiscover | Often folds into `Other clients`/`Autodiscover`-tagged entries; a second GAL/OAB pull attempt mirrors the EWS row above |
| Unified Messaging | Legacy `ClientAppUsed` value, rare enough in most modern tenants that its mere appearance is itself worth flagging |
| Azure Service Management API | Surfaces against `ResourceDisplayName: Windows Azure Service Management API` rather than any mail-related resource — success here is a **management-plane MFA bypass**, materially more severe than a mailbox-read bypass |

A hunt built around "single sign-in success" will catch the initial `msol` hit and stop looking — but the loot burst is what actually confirms real MFA-bypass impact (mailbox access, or worse, management-API access), and it is **on by default**. Build detection around the burst pattern (many distinct `ClientAppUsed`/`ResourceDisplayName` combinations, same user, same source IP, sub-minute window) rather than any single event in isolation.

## Non-`msol` Modules — Where the Evidence Lives Instead

- **`adfs`**: traffic never touches Microsoft's cloud sign-in endpoints at all — it's a direct `FormsAuthentication` POST to the organization's own on-prem/hosted ADFS server. **No Entra ID Sign-in Log entry is produced.** The evidence lives entirely in the ADFS server's own **Security Event Log (Event ID 411 for failed, 412/510 for various audit states depending on ADFS version)** and IIS/ADFS request logs on that server — this is genuinely on-prem evidence, out of scope for this file; treat it like any other Windows-hosted service and pull the relevant events directly from that server.
- **`owa`**: also an on-prem/hosted Exchange front-end, not a cloud endpoint by default — IIS logs and Exchange's own protocol logging (IMAP/OWA/EAS logs under the Exchange server's own `Logging` directories) are the primary target-side evidence, not Entra ID.
- **`okta`/`auth0`/`jumpcloud`/`anyconnect`**: entirely outside Microsoft/Entra's logging surface — each vendor's own admin console/audit log (Okta System Log, Auth0 Logs, JumpCloud Directory Insights, the AnyConnect-fronting ASA/FTD's own auth logs) is the relevant target-side source. None of it appears in Entra ID Sign-in Logs even if the same AD-backed identity is ultimately involved.

## Recon Phase — What Does and Doesn't Log

Per the mechanics in `01 - Overview.md`, `--recon` hits `.well-known/openid-configuration`, `getuserrealm.srf`, `autodiscover.json`, and DNS — all **unauthenticated, tenant-agnostic Microsoft front-end endpoints**. Same conclusion as already documented for `AADInternals/`'s unauthenticated recon: **none of this produces a Sign-in Log or Audit Log entry**, since both logs are scoped to authenticated directory activity. The OWA-discovery NTLM probe against the target's own hosted OWA/Exchange front-end is the one exception — that hits real target infrastructure and would appear in that server's own IIS logs as a sequence of unauthenticated `autodiscover.xml` requests carrying a crafted NTLM `Authorization` header, from a single source IP, across many subdomain permutations in rapid succession — a distinctive pattern worth a dedicated Sigma-style rule on any exposed Exchange front-end.

## Identity Protection Risk Detections

`Cloud/Microsoft/Entra ID/Identity Protection/What is Identity Protection.md` already documents the **"Malicious IP / password spray"** risk detection as the relevant catalog entry — TrevorSpray's traffic pattern (many users, few source IPs even under SSH rotation, uniform password) is exactly the shape that detection is built to catch, independent of any TrevorSpray-specific signature. SSH-based IP rotation reduces (but given a small proxy-host count, rarely eliminates) the "few source IPs" component of that detection; IPv6-subnet spoofing is the one evasion option genuinely capable of defeating it at scale, since it can present a functionally unbounded number of distinct source addresses.

## Network-Layer Evidence

- All Microsoft-endpoint traffic is HTTPS/TLS — a network sensor (Zeek/NetFlow) sees a burst of short TLS sessions to Microsoft's own IP ranges (or the target's own on-prem infrastructure for `adfs`/`owa`/`anyconnect`), with no plaintext content available.
- The static iPhone/Mobile-Safari `User-Agent` described above is visible in any TLS-terminating proxy or WAF logging that captures HTTP headers (e.g. an Azure AD Application Proxy, or a network appliance doing TLS inspection) even though it's invisible to a pure netflow view.
- JA3/JA3S TLS client-fingerprinting is possible in principle (Python `requests`/`urllib3`'s TLS stack has a distinct, non-browser fingerprint from genuine Mobile Safari) but wasn't independently verified against a live capture for this page — flagged as a plausible additional signal rather than a confirmed one.

## Building a Timeline

1. Anchor on the loot-phase burst (the multi-`ClientAppUsed` cluster) as the highest-confidence "this account was actually compromised, not just guessed" marker — it's harder to miss than the initial spray hit and confirms real impact.
2. Walk backward from the burst's shared source IP/ASN to find the original bulk `50126`-heavy spray window using the existing Playbook's KQL.
3. Cross-reference `ResourceDisplayName: Windows Azure Service Management API` hits specifically — a management-plane bypass changes incident severity and response scope (potential Azure resource access, not just mailbox access) and should immediately escalate beyond the standard Password Spray playbook's steps.
4. For federated/on-prem modules (`adfs`/`owa`/`anyconnect`/IdP-fronted modules), pull the relevant non-Entra log source identified above and align its timestamps against any Entra-side activity for the same identity — a successful on-prem/IdP auth followed shortly by Entra ID activity for the same user is the expected hybrid-identity correlation pattern.
