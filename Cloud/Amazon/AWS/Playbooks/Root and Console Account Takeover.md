# Playbook — Root & Console Account Takeover

Someone logged into the AWS **Management Console** as a human — the **root user** or an IAM user with a password — from somewhere they shouldn't. Root takeover is a **top-severity** event: root can do anything and can't be restrained by IAM. This playbook covers interactive-login compromise.

> **Tier 2 (cross-service).** Touches IAM, CloudTrail (`ConsoleLogin`), account settings, Organizations. Read **CloudTrail for DFIR**, **IAM for DFIR**.

## Contents

- [Attack Chain](#attack-chain)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Attack Chain

```
Credential theft (phishing / reuse / leaked root creds) [+ MFA bypass]
   → ConsoleLogin from a new IP/geo/device
   → (root) can do anything: change account email/contacts, remove MFA, view all
   → persistence: create IAM users/keys, change account settings, add MFA of their own
   → objective: data access / financial abuse / full account control
```

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **GuardDuty** | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`, `.../ConsoleLogin` from bad IP |
| **CloudTrail** | `ConsoleLogin` with `MFAUsed = No` from a new IP/geo; **root** login |
| **Account-change email** | AWS emailed about an email/contact/MFA change nobody made |
| **Impossible travel** | Logins from two far-apart geos in a short window |

## Hypothesis

An attacker authenticated interactively as root or an IAM user. Confirm the login is malicious, scope everything done in-session, and — for root — treat as the highest-severity account compromise.

## Step-by-Step Investigation

**1. Pull the console logins.**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --max-results 50
```

For each, read: `userIdentity.type` (🔴 `Root`), `sourceIPAddress`, `additionalEventData.MFAUsed`, `responseElements.ConsoleLogin` (Success/Failure), user-agent.

**2. Judge malicious vs legit.** 🔴 New country/ASN, **`MFAUsed: No`**, a device/UA never seen for this identity, or **any** root login (root should be near-silent) = suspicious. A burst of `Failure` then a `Success` = brute/spray that worked.

**3. Scope the session.** Everything the identity did after login, sorted by `eventTime`. For root, check especially:
- **Account settings**: `PutAccountPasswordPolicy`, contact/email changes (often via the account API, not always CloudTrail — check the account-settings emails).
- **MFA**: `DeactivateMFADevice` / `CreateVirtualMFADevice` (attacker replacing MFA).
- **Persistence**: `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`.

**4. Check the blast radius.** Root/console-admin can touch everything — sweep for exfil, resource changes, logging tampering, and (in an Org) management-account actions.

## Decision Points

| Question | If yes → |
|----------|----------|
| Was it **root**? | Top-severity; assume total account control until proven otherwise |
| MFA used? | `No` on a sensitive login = strong compromise signal |
| Account email/contact changed? | Attacker is taking ownership — recover the account with AWS urgently |
| MFA device swapped? | They're locking you out — act fast |
| Management account? | Org-wide incident (→ Organizations) |

## Contain

- **Root:** reset the **root password**, **remove/re-enroll the root MFA**, and **delete any root access keys**. If the attacker changed the account email, contact **AWS Support** immediately to recover ownership.
- **IAM user:** disable the login profile (`delete-login-profile` or reset password), deactivate keys, revoke sessions.
- Force-sign-out / revoke active sessions where possible.
- If MFA was removed, re-enroll a **hardware** MFA you control.

```bash
# IAM user console access off + keys off
aws iam delete-login-profile --user-name <u>
aws iam update-access-key --user-name <u> --access-key-id AKIA... --status Inactive
```

## Eradicate

- Remove all persistence created in-session (users/keys/login profiles/policies — → Persistence Hunt).
- Restore correct account settings (email, contacts, password policy).
- Re-enable any logging tampered with.
- Fix the entry: phishing awareness, kill password reuse, enforce MFA.

## Recover

- Re-secure root: lock it away, hardware MFA, no access keys, alert on any use.
- Reset affected human credentials; move humans to **SSO + phishing-resistant MFA**.
- Preserve: the `ConsoleLogin` events + in-session timeline + any AWS account-change notices.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| **Any** root login | Root should be silent — investigate always |
| `ConsoleLogin` `MFAUsed: No` from a new IP | Stolen creds without MFA |
| Failure burst → success | Password spray/brute that worked |
| `DeactivateMFADevice` then changes | Attacker replacing MFA to persist/lock you out |
| Account email/contact change | Account-ownership takeover |
| Impossible-travel logins | Session/credential theft |

## References

- Related notes: **CloudTrail for DFIR**, **IAM for DFIR**, **Persistence and Backdoor Hunt**, **Organizations for DFIR**
- Securing the root user — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
- What to do if you suspect an account compromise — https://repost.aws/knowledge-center/potential-account-compromise
- MITRE ATT&CK: Valid Accounts – Cloud (T1078.004), Modify Authentication Process (T1556) — https://attack.mitre.org/techniques/T1078/004/
