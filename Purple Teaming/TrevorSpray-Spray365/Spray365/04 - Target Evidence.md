# Spray365 — Target Evidence

What the operation leaves on the **target** — the Entra ID tenant. Full field-by-field Sign-in Log mechanics, KQL collection, and the general password-spray investigation flow already live in `Cloud/Microsoft/Entra ID/`; this file gives Spray365-specific values within that structure.

## Contents
- [Start Here: The Existing Password Spray Playbook](#start-here-the-existing-password-spray-playbook)
- [Entra ID Sign-in Logs — Why AppId Hunting Fails Here](#entra-id-sign-in-logs--why-appid-hunting-fails-here)
- [The MSAL Signature — What Doesn't Change](#the-msal-signature--what-doesnt-change)
- [Audit-Mode Traffic — a Distinct Shape](#audit-mode-traffic--a-distinct-shape)
- [Identity Protection Risk Detections](#identity-protection-risk-detections)
- [Network-Layer Evidence](#network-layer-evidence)
- [Building a Timeline](#building-a-timeline)

---

## Start Here: The Existing Password Spray Playbook

`Cloud/Microsoft/Entra ID/Playbooks/Password Spray.md` already documents the general investigation flow — the `50126`-across-many-users-from-few-IPs KQL pattern and the contain/eradicate/recover steps. The one place Spray365's shape genuinely diverges from that playbook's default assumption is the **"from few IPs" part** — Spray365 has no built-in IP-rotation mechanism (`03 - Source Evidence.md`), so unlike a spray tool that actively rotates source addresses, Spray365 traffic *should* show the textbook single/few-IP spray pattern the playbook's KQL is built to catch, **unless** the operator separately chained an external rotating proxy via `-x`.

## Entra ID Sign-in Logs — Why AppId Hunting Fails Here

This is the load-bearing fact for the whole file, already flagged in the red-flag callout: **`AppId`/`AppDisplayName` is randomized per credential by default**, drawn from `constants.py`'s ~45-entry catalog of genuine Microsoft first-party client IDs (Azure CLI, Teams, OneDrive, `aadsync`/Azure AD Connect, Skype, PowerBI, several mobile/device-registration apps, and more — the same catalog `../../AADInternals/`'s own `AccessToken_utils.ps1` sources). Practical consequence for an analyst:

- A single `generate normal` run against 50 users with 3 passwords (150 credentials) can surface as sign-in attempts from **up to ~45 distinct `AppDisplayName` values**, each individually plausible on its own — "Azure AD Connect" traffic, "Microsoft Teams" traffic, "Skype for Business" traffic, all in the same short window, all actually the same spray tool.
- **Do not build a Spray365 hunt around any specific `AppId`.** A rule that alerts on `AppId == <one client ID>` will, at best, catch roughly 1/45th of the run's traffic; at worst, it fires on entirely legitimate baseline usage of that one first-party app and gets tuned out.
- The correct pivot is **`UserPrincipalName` + `IPAddress` + high `ResultType` volume across many distinct `AppId`s in a short window** — i.e., the same underlying user/source-IP volume pattern the general Password Spray playbook already hunts for, just without relying on application identity as a filter at all.
- `-cID`/`-eID` pinning (when an operator deliberately narrows to one client/endpoint, e.g. to test one specific application) is the one case where a fixed `AppId` *does* show up consistently across a run — but this is an operator choice, not the tool's default behavior, so don't assume it.

## The MSAL Signature — What Doesn't Change

Regardless of which `client_id`/`endpoint` is selected per attempt, every Spray365 request goes through the **same MSAL code path** and the **same fixed authority**:

- **Token endpoint**: always `https://login.microsoftonline.com/organizations/oauth2/v2.0/token` — MSAL's `PublicClientApplication` is constructed with `authority="https://login.microsoftonline.com/organizations"` on every single credential, never a tenant-specific authority URL. A high volume of ROPC grant requests against the `/organizations` multi-tenant endpoint (rather than a `/<tenant-id>/` or `/<domain>/` tenant-specific authority) targeting many distinct `UserPrincipalName`s is a durable pattern that survives every one of Spray365's own randomization options, since it's structural to how the tool constructs its MSAL client, not something `-cID`/`-eID`/`-S` can change.
- **Grant type**: OAuth2 ROPC (`grant_type=password`) — same underlying AADSTS error-code taxonomy as `../TrevorSpray/`'s hand-built requests (`50126`/`50053`/`50055`/`50057`/`50076`/`53003`/`50158`/`50034`), so the Password Spray playbook's existing `ResultType`-based KQL applies unchanged regardless of which tool generated the traffic.
- **User-Agent**: `-rUA/--random_user_agent` defaults to **True** — expect a mix of UA strings across a single run rather than one static fingerprint, the opposite of `../TrevorSpray/`'s default hardcoded-iPhone-UA behavior. `-cUA` (custom, fixed UA) is the one path that produces a consistent UA fingerprint, and only if the operator explicitly sets it.

## Audit-Mode Traffic — a Distinct Shape

`generate audit` plans are structurally different traffic from a `normal` spray and should be recognized as such: **one user, one (or few) password(s), but hundreds of attempts** in a short window — the full client_id × endpoint × user_agent cross-product. This looks nothing like a population-wide spray (many users, one password) and nothing like a classic brute force (one user, many passwords) — it's **one user, one password, many distinct application/resource identities**, which is a distinctive enough shape to hunt for directly:

```kql
// Audit-mode signature: one user, ~1 password, 50+ distinct AppId values
// in a short window — a Conditional-Access-fingerprinting run, not a spray
SigninLogs
| where TimeGenerated > ago(7d)
| summarize DistinctApps = dcount(AppId), Attempts = count() by UserPrincipalName, bin(TimeGenerated, 15m)
| where DistinctApps > 30
| order by DistinctApps desc
```

A hit here means an operator (or attacker) already has a working credential for that user and is actively mapping which application/resource combination evades Conditional Access — treat it as **confirmed compromise plus active CA-gap reconnaissance**, materially more urgent than an ordinary spray hit.

## Identity Protection Risk Detections

`Cloud/Microsoft/Entra ID/Identity Protection/What is Identity Protection.md`'s **"Malicious IP / password spray"** risk detection is the relevant catalog entry, same as for `../TrevorSpray/`. Because Spray365 has no IP-rotation of its own, its traffic is generally **more, not less**, likely to trip a source-IP-based risk detection than a rotated spray — a genuine practical weakness of the tool as shipped, absent an operator-supplied external proxy layer.

## Network-Layer Evidence

- All traffic is HTTPS to `login.microsoftonline.com` — no plaintext content visible to a network sensor, same as any MSAL-based tool.
- MSAL's own HTTP client (built on `requests`) has a distinct TLS/HTTP fingerprint from genuine first-party Microsoft client applications (the Azure CLI, Teams desktop client, etc. each have their own real TLS stacks) — a JA3/JA3S mismatch between the claimed `AppDisplayName`'s expected client fingerprint and the actual observed TLS fingerprint is a plausible detection angle, though not independently verified against a live capture for this page.
- Because every request goes through the single `/organizations` authority regardless of the randomized `client_id`, a network-layer view (SNI = `login.microsoftonline.com` for every single connection) is completely uniform across the whole run — the variation is entirely in the HTTP body/response, not in anything visible at the TLS layer.

## Building a Timeline

1. Anchor on the `UserPrincipalName` + `IPAddress` + multi-`AppId` volume pattern above rather than any single `AppId`, since application identity is randomized by default.
2. Distinguish `normal`-mode traffic (many users, few passwords, moderate AppId diversity) from `audit`-mode traffic (one user, one password, high AppId diversity in a tight window) — they represent different attacker intents (population spraying vs. CA-gap mapping against an already-compromised credential) and should drive different response urgency.
3. Cross-reference any confirmed-successful sign-in against the `Conditional Access & MFA for DFIR.md` note's own "How Did They Beat MFA?" checklist — a Spray365 hit that lands as a full `ResultType: 0` success (not just a partial-success/MFA-required response) means the specific `client_id`/`endpoint` combination genuinely bypassed whatever Conditional Access policy should have applied.
4. Since Spray365 typically runs from a single static source IP (no built-in rotation), that IP is usually the durable pivot point tying the entire session together across Sign-in Logs — a simpler correlation task than `../TrevorSpray/`'s potential multi-egress sessions.
