# TrevorSpray (TREVORspray) — Overview

> 🔴 **Red Flag Principle:** A single valid credential found by TrevorSpray's default `msol` module doesn't stay a single sign-in event — by default (unless `--no-loot` is passed) it immediately fires off **up to nine additional authentication attempts against nine different Exchange/Azure protocol endpoints** (IMAP, SMTP, POP3, EWS, EAS, Exchange Online PowerShell, Autodiscover, Unified Messaging, and the Azure Service Management API) to test for legacy-auth MFA bypass. One "hit" in the Entra ID Sign-in Logs should make an analyst immediately expect a **burst of distinct-`ClientAppUsed`/distinct-`AppId` sign-ins for the same user, from the same source, within seconds** — that burst pattern is a stronger, harder-to-miss signal than the initial spray traffic itself.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

- The tool's actual repository name is **`TREVORspray`** (all-caps TREVOR) at [`blacklanternsecurity/TREVORspray`](https://github.com/blacklanternsecurity/TREVORspray) — this folder uses the PLANNING.md-locked spelling "TrevorSpray" for the directory name, but every command/install path below uses the real casing. Authored by **TheTechromancer** ([@thetechr0mancer](https://twitter.com/thetechr0mancer)) of **Black Lantern Security**, licensed **GPL-3.0**. Repo created 2020-09-06; verified live against the GitHub API as **actively maintained** (last push 2026-05-21, 1,366 stars, not archived) — a real contrast with its bundled sibling in this folder.
- TrevorSpray began as a build on top of **MSOLSpray** (Beau Bullock, [@dafthack](https://twitter.com/dafthack)), credited explicitly in the README along with **[@Mrtn9](https://twitter.com/Mrtn9)** for an early Python port. The tool's own README credits **[@CarsonSallis](https://github.com/CarsonSallis)** for the O365 legacy-auth MFA-bypass modules, **[@DrAzureAD](https://twitter.com/DrAzureAD)** (Dr. Nestori Syynimaa, author of `AADInternals` — already built in this repo at `../../AADInternals/`) for Azure AD recon techniques, **[@nyxgeek](https://twitter.com/nyxgeek)** for the OneDrive user-enumeration technique, and **[@gremwell](https://twitter.com/gremwell)** for the Seamless SSO enumeration technique — this tool is a synthesis of several named community O365-attack primitives, not a single author's original research.
- **"TREVORspray 2.0"** shipped 2022-01-19 (per the accompanying [blog post](https://blog.blacklanternsecurity.com/p/introducing-trevorproxy-and-trevorspray)), rewritten as a modular sprayer-class architecture and split into two packages: `trevorspray` (this tool) and a new companion, **`trevorproxy`** (a standalone SOCKS proxy for SSH round-robin and IPv6-subnet traffic distribution — also usable on its own with `curl`/Burp Suite). Current version per `pyproject.toml`: **2.4.0**, depending on `trevorproxy ^1.0.8`. The default branch is `trevorspray-v2`.
- **Motivation, per the author's own blog post:** increasing MFA adoption and Azure AD **Smart Lockout** (a defense that factors in source IP when deciding whether to lock an account) were making naive single-IP password spraying far less viable — TrevorSpray/TrevorProxy's whole reason for existing is to make IP-diverse spraying practical again ("make password spraying fun again," in the author's words).
- **Correcting a common assumption:** this tool does **not** use FireProx or any AWS API-Gateway-based IP rotation. Verified directly against the live source (`grep -ri fireprox` across the full `trevorspray/` package returns zero matches) — IP diversity comes exclusively from the SSH round-robin and IPv6-subnet mechanisms described below, both implemented via the separate `trevorproxy` package.
- **No MITRE ATT&CK Software (S-number) entry exists for this tool**, and — more notably — it isn't even named as a procedure example anywhere on the live [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) technique page (verified directly against that page's full Procedure Examples table). Neither tool in this bundled folder has any MITRE ATT&CK citation at all, a genuine gap worth flagging up front rather than assuming coverage exists.

## How It Works

### Modular sprayer architecture

Every authentication surface is a `BaseSprayModule` subclass (`trevorspray/lib/sprayers/*.py`) that declares a `default_url`, an HTTP `method`, request headers/body template (`request_data` or `request_json`), and a `check_response()` method that inspects the HTTP response and returns `(valid, exists, locked, msg)`. The `msol` module (the default) is the canonical example: it POSTs an OAuth2 Resource Owner Password Credentials (ROPC) grant directly to `https://login.microsoft.com/common/oauth2/token` with `client_id=38aa3b87-a06d-4817-b275-7a316988d93b` ("Microsoft Azure PowerShell") and `resource=https://graph.windows.net` (the now-retired Azure AD Graph API), then parses the returned `AADSTS<code>` error string to classify the result:

| AADSTS code | Meaning in `msol.py` |
|---|---|
| `50126` | Invalid email or password — account may still exist |
| `50128` / `50059` | Tenant for this domain doesn't exist |
| `50034` | User does not exist |
| `900023` | No tenant registered for this domain |
| `90072` | Valid credential, but not valid for this tenant |
| `530031` | Valid credential, but access policy blocks token issuance |
| `53003` | Valid credential, blocked by Conditional Access |
| `50055` | Valid credential, password is expired |
| `50131` | Valid credential, correct password but login blocked |
| `50076` / `50079` | Valid credential — MFA required / must be onboarded |
| `50158` | Valid credential — Conditional Access response, commonly associated with third-party MFA (e.g. DUO) |
| `50053` | Account locked (or Smart Lockout triggered) |
| `50056` | Account exists but has no password in Azure AD |
| `50057` | Account disabled |
| `80014` | Account exists, Pass-through Authentication time exceeded |
| HTTP 200 | Fully valid credential |

### Domain discovery (`--recon`)

`DomainDiscovery` (`trevorspray/lib/discover.py`) runs a chain of unauthenticated lookups against a target domain before any spray begins:

```
--recon evilcorp.com
        │
        ├─ MX / TXT DNS records
        ├─ https://login.windows.net/<domain>/.well-known/openid-configuration
        │      → extracts the tenant's GUID Tenant ID from authorization_endpoint
        ├─ https://login.microsoftonline.com/getuserrealm.srf?login=test@<domain>
        │      → NameSpaceType: "Managed" (use msol) vs. "Federated" (use adfs),
        │        plus the real ADFS AuthURL if federated
        ├─ https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/test@<domain>
        ├─ DKIM selector1./selector2._domainkey.<domain> CNAME → tenant short name
        ├─ OWA discovery: probes 8+ subdomain permutations
        │      (autodiscover./exchange./webmail./owa./mail./mx.<domain> + every MX host)
        │      for an autodiscover.xml response, then sends a crafted NTLM Type-1
        │      message to recover the internal AD NetBIOS/DNS domain name from the
        │      Type-2 response — the same NTLM-info-leak technique MailSniper and
        │      Metasploit's owa_login.rb scanner use
        └─ https://azmap.dev/api/tenant?domain=<domain>&extract=true
               → tenant name + every other domain registered under the same
                 M365 tenant, exported to ~/.trevorspray/loot/recon_<domain>_
                 other_tenant_domains.txt
```

**OPSEC note:** the `msoldomains()` lookup queries `azmap.dev`, a **third-party, non-Microsoft service** — recon traffic isn't confined to Microsoft's own infrastructure. This is worth flagging in any engagement scoping discussion, since it means the target domain is disclosed to an external party outside the client's own environment.

### The proxying model — three mutually exclusive modes

`cli.py` explicitly rejects combining `--ssh`, `--subnet`, and `--proxy` (any two together is a hard error). Internally, TrevorSpray spins up one `ProxyThread` per configured egress path, each pulling one `(user, password)` job at a time in round-robin:

```
┌─────────────────────────────────────────────────────────────────┐
│  --ssh user@host1 user@host2 ...   (default, unless -n given,   │
│         includes the operator's own current IP once per round)  │
│         → each host gets its own trevorproxy.lib.ssh.SSHProxy   │
│           (a local SOCKS5 listener tunneled over that SSH conn) │
│                                                                   │
│  --subnet <cidr> --interface <if>  (IPv6 /64 only, needs         │
│         iptables + root)                                        │
│         → trevorproxy.lib.subnet.SubnetProxy spoofs a fresh     │
│           source address from the /64 (≈1.8×10^19 addresses)    │
│           per request via raw sockets                           │
│                                                                   │
│  --proxy <url>                     (single plain HTTP/HTTPS      │
│         proxy — e.g. Burp Suite for traffic inspection)         │
└─────────────────────────────────────────────────────────────────┘
```

`--threads` is silently overridden and ignored the moment `--ssh` is supplied — thread count becomes "one thread per SSH host" instead. Delay/jitter (`-d`/`-j`/`-ld`) apply **per proxy thread**, not globally — `cli.py` prints the effective aggregate rate at startup (`N hosts × delay == X attempts/min == Y attempts/min/IP`) so an operator can see the real per-source-IP request rate before launching.

### The default-on loot phase

On any `valid` credential (unless `-nl`/`--no-loot`), `sprayer.loot()` (`trevorspray/lib/looters/msol.py`) runs a fixed sequence of **legacy-authentication probes** against the *same* credential, each a completely separate protocol/endpoint from the original spray:

```
Valid msol credential found
        │
        ├─ IMAP4  (imaps://outlook.office365.com:993)
        ├─ SMTP   (outlook.office365.com:587, smtp.office365.com:587)
        ├─ POP3   (pop3s://outlook.office365.com:995)
        ├─ EWS    (https://outlook.office365.com/EWS/Exchange.asmx)
        │      → on success, auto-pulls the Global Address List (GAL) by
        │        locating and downloading the tenant's Offline Address
        │        Book (OAB) .lzx file to ~/.trevorspray/loot/
        ├─ EAS    (Exchange ActiveSync)
        ├─ EXO PowerShell (Exchange Online remote PowerShell endpoint)
        ├─ Autodiscover (also attempts an OAB/GAL pull on success)
        ├─ Unified Messaging (EWS/UM2007Legacy.asmx)
        └─ Azure Service Management API (management.core.windows.net)
               → success here means the "az" CLI / classic ASM tooling
                 works with this credential
```

Each of these is a genuine, independent authentication event against a different Microsoft endpoint, generated automatically and immediately after the triggering spray hit — see `04 - Target Evidence.md` for how this surfaces in Sign-in Logs.

### User enumeration (`-ue`)

Three independent, unauthenticated-or-near-unauthenticated methods (`trevorspray/lib/enumerators/`), selectable when `--recon` and `--users` are both given:

| Module | Mechanism |
|---|---|
| `onedrive` | `HEAD` request to `https://<tenant>-my.sharepoint.com/personal/<user>_<domain>/_layouts/15/onedrive.aspx` — any of 200/401/403/302 confirms the user's personal OneDrive site exists |
| `seamless_sso` | `POST` to `login.microsoftonline.com/common/GetCredentialType` and reads `IfExistsResult` — the tool's own code explicitly warns this method is unreliable and gets throttled/poisoned with false results after high volume |
| `teams_photo` | Same SharePoint-personal-site pattern as `onedrive`, against `.../userphoto.aspx` instead |

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Core auth protocol | OAuth2 Resource Owner Password Credentials (ROPC) grant, hand-built HTTP requests (no MSAL/ADAL library — raw `requests`) |
| Auth surfaces (modules) | `msol` (O365/Azure AD Graph), `adfs`, `owa`, `okta`, `anyconnect` (Cisco VPN), `auth0`, `jumpcloud`, `officehome` |
| Recon protocols | DNS (MX/TXT/CNAME), HTTPS to Microsoft OIDC/userrealm/autodiscover endpoints, NTLM Type1/Type2 handshake against OWA/EWS |
| IP diversity | SSH SOCKS5 tunneling (round-robin), spoofed source addressing within an IPv6 /64 via raw sockets + iptables |
| Loot/legacy-auth | IMAP4, SMTP, POP3, EWS SOAP, EAS, Exchange Online PowerShell, MAPI/Autodiscover, Unified Messaging SOAP, Azure Service Management REST |
| User enumeration | Unauthenticated SharePoint personal-site probing, Seamless SSO credential-type probing |

## Command-Line Switches — Quick Reference

Verified directly against `trevorspray/cli.py` (v2.4.0) — every flag below is real and current.

**Basic arguments**

| Switch | Plain-English meaning |
|---|---|
| `-m, --module <name>` | Which auth surface to spray (`msol`, `adfs`, `owa`, `okta`, `anyconnect`, `auth0`, `jumpcloud`, `officehome`). Default: `msol` |
| `-up, --userpass <file...>` | File(s) of pre-paired `username:password` lines — skips the users×passwords cross-product |
| `-u, --users <user/file...>` | Username(s) and/or file(s) of usernames |
| `-p, --passwords <pw/file...>` | Password(s) and/or file(s) of passwords |
| `--url <url>` | Overrides the module's default target URL (used for a discovered ADFS/tenant-specific endpoint) |
| `-r, --recon, --enumerate <domain>` | Runs the full domain-discovery chain above; combined with `-u` also enables user enumeration |
| `--export-tenants <file>` | Writes every discovered sibling tenant domain (excluding `*.onmicrosoft.com`) to a file |
| `--skip-owa` | Skips the OWA-discovery/NTLM-domain-leak sub-step during `--recon` |
| `-ue, --user-enum <method>` | Pins the user-enumeration method (`onedrive`/`seamless_sso`/`teams_photo`) instead of prompting interactively |

**Advanced arguments**

| Switch | Plain-English meaning |
|---|---|
| `-t, --threads <n>` | Concurrent request threads (default 1; ignored/overridden once `--ssh` is set) |
| `-f, --force` | Re-tries user/pass combos already recorded in `tried_logins.txt` |
| `-d, --delay <sec>` | Fixed sleep between requests per proxy thread |
| `-ld, --lockout-delay <sec>` | Extra sleep specifically after a detected lockout response |
| `-j, --jitter <sec>` | Adds a random 0–N second delay on top of `-d` |
| `-e, --exit-on-success` | Stops the entire spray the moment one valid credential is found |
| `-nl, --no-loot` | Disables the legacy-auth MFA-bypass loot phase described above |
| `--ignore-lockouts` | Suppresses the interactive "10 lockouts detected, continue? Y/N" prompt and keeps going |
| `--timeout <sec>` | Per-request connection timeout (default 10) |
| `--random-useragent` | Appends a random numeric suffix to the User-Agent (and, for `msol`, randomizes the `client_id` to a fresh UUID) on every request |
| `-6, --prefer-ipv6` | Prefers IPv6 resolution/routing over IPv4 |
| `--proxy <url>` | Routes all requests through a single HTTP/HTTPS proxy (mutually exclusive with `--ssh`) |
| `-v, --verbose, --debug` | Shows which proxy/IP served each individual request |

**SSH Proxy arguments**

| Switch | Plain-English meaning |
|---|---|
| `-s, --ssh <user@host...>` | Round-robins traffic through these SSH-reachable hosts (each becomes a SOCKS5 egress); the operator's own current IP is also used once per round unless `-n` is given |
| `-i, -k, --key <path>` | SSH private key to use for the proxy hosts |
| `-b, --base-port <n>` | Base local port for the SOCKS5 listeners spun up per SSH host (default 33482) |
| `-n, --no-current-ip` | Excludes the operator's own IP from the rotation — SSH hosts only |

**Subnet Proxy arguments**

| Switch | Plain-English meaning |
|---|---|
| `--subnet <cidr>` | IPv6 /64 (or other) subnet to spoof source addresses from, via raw sockets |
| `--interface <if>` | Network interface to send the spoofed packets on |

## Quick Use-Case List

- Baseline O365/Azure AD spray with the default `msol` module against a list of users and one or more passwords
- Unauthenticated domain recon (`--recon`) to fingerprint tenant ID, Managed vs. Federated namespace, sibling tenant domains, and any exposed OWA/internal AD domain name before spraying anything
- Federated-tenant spray with `-m adfs` once recon confirms `NameSpaceType: Federated`
- Internal-username OWA spray (`-m owa`) against an on-prem or hybrid Exchange front-end using `DOMAIN\username` format
- Okta-fronted tenant spray (`-m okta`) — note the module's own built-in warning that Okta silently hides lockout failures without `--delay`
- Cisco AnyConnect VPN portal spray (`-m anyconnect`) when the target uses AD-backed VPN auth
- Auth0- or JumpCloud-fronted SSO spray (`-m auth0` / `-m jumpcloud`) for organizations using either as an IdP
- Unauthenticated user enumeration via OneDrive/Teams-photo/SeamlessSSO probing (`-r --recon <domain> -u users.txt -ue onedrive`) to trim a username list before spending spray attempts
- Rate-limited, jittered spray (`-d 5 -j 3`) to stay under Smart Lockout's per-IP threshold on a single egress
- IP-diverse spray via SSH round-robin (`-s root@vps1 root@vps2 root@vps3`) to spread attempts across multiple source IPs and dodge IP-based lockout/blocking
- IPv6-subnet spoofed spray (`--subnet 2001:db8::/64 --interface eth0`) for near-unlimited unique source addresses from a single box with IPv6 transit
- Proxying every request through Burp Suite (`--proxy http://127.0.0.1:8080`) for manual traffic inspection/replay
- Exit-on-first-hit spray (`-e`) for a quick "does any of these creds work" check without continuing to burn attempts
- Resuming an interrupted spray unattended — `tried_logins.txt` is consulted automatically on the next run unless `-f/--force` is passed
- Disabling the default legacy-auth loot burst (`-nl`) when the goal is a quiet credential-validity check only, not MFA-bypass testing
- Custom spray-module authoring for an unsupported endpoint (subclass `BaseSprayModule`, implement `check_response()`, drop the file in `sprayers/` — auto-discovered by module name)
- Chained workflow: feeding a valid O365 credential recovered here into `../../AADInternals/` for deeper Entra ID enumeration/attack, or into `../../Impacket/` / `../../NetExec/` if the same password is reused on-prem (a common finding once hybrid-identity organizations are confirmed via `--recon`)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Python | 3.9+ (per `pyproject.toml`) |
| Install | `pip install git+https://github.com/blacklanternsecurity/trevorproxy` then `pip install git+https://github.com/blacklanternsecurity/trevorspray` — both packages are required |
| Target domain/tenant identification | At minimum a target domain (for `--recon`) or a directly known token/auth endpoint (`--url`) |
| Username list | Required for anything beyond pure `--recon` |
| SSH proxy hosts | Only for `--ssh` — operator-controlled boxes reachable via SSH with a working key |
| Subnet spoofing | Only for `--subnet` — root privileges, `iptables` installed, and genuine routed IPv6 transit for the spoofed range (spoofing alone doesn't grant return-traffic routing) |
| No credentials needed to run recon/enumeration | `--recon` and the enumerator modules work entirely pre-credential |
