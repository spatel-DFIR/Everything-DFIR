# Playbook — BEC and Mail Forwarding

The most common — and most expensive — Workspace incident. An attacker takes over a mailbox (phish, token theft, or spray), then **hides in it**: sets **filters/forwarding** to exfil and conceal replies, reads finance/vendor mail, and sends **fraudulent payment requests** from a trusted identity. This playbook reconstructs the takeover, finds the persistence the audit log won't show, quantifies the fraud, and locks it down.

> **Tier 2 (cross-service).** Spans Login audit + Gmail settings + ELS. Read **Workspace → Gmail for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Quantify the Fraud](#quantify-the-fraud)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **User/finance report** | A vendor/customer got a fake invoice or bank-change from us |
| **Alert Center** | Suspicious login / leaked password on the mailbox owner |
| **Login audit** | New IP/ASN then activity |
| **Gmail** | Auto-forwarding to an external domain |

## Hypothesis

An attacker controls the mailbox and is committing payment fraud while hiding replies. Establish the initial access, the persistence (filters/forwarding/delegation), the fraudulent sends, and every party contacted.

## Step-by-Step Investigation

**1. Find the takeover sign-in.** Login audit: new IP/ASN/country, legacy/less-secure login, `suspicious_login`. Cross with the mailbox owner.

**2. Snapshot mailbox persistence** (the audit log won't show these — read the settings):

```bash
gam user victim@contoso.com show filters      # rules forwarding/deleting finance mail
gam user victim@contoso.com show forwards     # + autoforwarding on?
gam user victim@contoso.com show delegates    # attacker granted mailbox access
gam user victim@contoso.com show sendas       # alias impersonating an exec
```

**3. Find the fraudulent sends.** Email Log Search by sender `victim@contoso.com` → external recipients + subjects (invoices, wire changes).

**4. Map who was contacted.** Every external recipient of the fraud mail — to warn **out of band**.

**5. Prove reads (if content logging/SIT).** Which threads (banking, invoices) the attacker opened.

## Quantify the Fraud

| Question | Evidence |
|----------|----------|
| What fraud mail was sent, to whom? | ELS + sends |
| Were payment/bank details changed? | SIT / Vault content of replies |
| Did money move? | Coordinate with finance/bank immediately |
| Is a filter hiding replies? | The rule moving vendor mail to a hidden label + delete |

## Decision Points

| Question | If yes → |
|----------|----------|
| Money in motion? | 🔴 **Immediate** finance + bank recall; law enforcement |
| Token/OAuth theft (not password)? | Run **Account Takeover** / **Illicit OAuth Grant**; revoke tokens/grants |
| Multiple mailboxes hit? | Campaign — hunt the filter/forward pattern org-wide |
| Admin mailbox? | Check Admin audit for role/DWD changes (escalation) |

## Contain

```bash
# 1. Cut the identity — reset password + sign out everywhere (Admin console)
# 2. Kill mail persistence
gam user victim@contoso.com delete filter <id>
gam user victim@contoso.com turnoff forward
gam user victim@contoso.com delete delegate attacker@...
gam user victim@contoso.com delete sendas <alias>
```
Warn contacted vendors/customers **out of band** (the mailbox is untrusted).

## Eradicate

- Remove **all** malicious filters, forwarding, delegates, and `sendAs` aliases.
- Reset password **after** sign-out; re-enroll 2SV; fix swapped recovery email/phone.
- Revoke any **OAuth app grants** the attacker planted.
- Check the **Admin audit** for org-level auto-forwarding / routing rules the attacker added.

## Recover

- Re-enable with fresh creds + phishing-resistant 2SV.
- **Disable automatic external forwarding** org-wide; alert on new filters/forwarding.
- Notify affected parties + follow fraud/legal/regulatory process.
- Preserve: login timeline, mailbox settings snapshot, sends (ELS), and fraud-mail content on Vault hold.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Filter forwarding finance mail + deleting the copy | BEC concealment |
| Auto-forwarding to an external/lookalike domain | Silent exfil |
| New mailbox delegate / `sendAs` alias | Stealth access / spoofing |
| External sends of wire/bank-change requests | Payment fraud |
| Settings changed the same hour as a suspicious login | Attacker persistence |

## References

- Related notes: **Gmail for DFIR**, **Login & Auth Audit**, **Account Takeover**, **Admin Audit Log**
- Respond to a compromised account — https://support.google.com/a/answer/2984349
- Disable automatic forwarding — https://support.google.com/a/answer/2491924
- MITRE ATT&CK: T1114 Email Collection / T1564.008 Email Hiding Rules — https://attack.mitre.org/techniques/T1114/
