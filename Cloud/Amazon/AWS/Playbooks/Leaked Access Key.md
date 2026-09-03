# Playbook — Leaked Access Key

**The most common AWS intrusion.** A long-term IAM access key (`AKIA…`) leaks — in a public GitHub repo, a laptop, a CI variable, a mobile app — and an attacker uses it. This playbook takes you from the first alert to full eradication.

> **Tier 2 (cross-service).** Touches IAM, STS, CloudTrail, and whatever the key could reach (S3, EC2…). Read **01 IAM & Identities**, **CloudTrail for DFIR**, and **IAM for DFIR** alongside it.

## Contents

- [Attack Chain](#attack-chain)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Fleet Hunt / Scope Check](#fleet-hunt--scope-check)
- [Red Flags](#red-flags)
- [References](#references)

## Attack Chain

```
Key leaks (git/laptop/CI/app)
   → attacker runs GetCallerIdentity ("whoami")
   → enumerates (List*/Describe*/Get*) — lots of AccessDenied
   → finds a privesc primitive OR the key is already powerful
   → persistence: CreateAccessKey / CreateUser / CreateLoginProfile
   → objective: S3 exfil / EBS-RDS snapshot share / cryptomining (RunInstances)
   → evasion: StopLogging / DeleteTrail (sometimes)
```

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **AWS abuse notice / AWS Health** | AWS detected the key public and emailed you (they scan GitHub) |
| **GuardDuty** | `UnauthorizedAccess:IAMUser/MaliciousIPCaller`, `.../InstanceCredentialExfiltration`, `Recon:IAMUser/...` |
| **Billing alarm** | Sudden cost spike (usually mining) |
| **Secret scanner** | Your own git-secrets / scanner flagged the key |
| **A weird action** | Someone noticed a resource/user they didn't create |

## Hypothesis

An external actor holds a valid `AKIA…` key and is acting as that IAM user. Goals: confirm the key is compromised, scope every action it took, find any persistence it planted, and cut it off completely — not just the one key.

## Step-by-Step Investigation

**1. Identify the key and its owner.**

```bash
aws iam get-access-key-last-used --access-key-id AKIA...   # user + last-used service/region/time
aws iam list-access-keys --user-name <user>                # how many keys does this user have?
```

**2. Confirm logging integrity first** (so you trust the timeline):

```bash
aws cloudtrail get-trail-status --name <trail> \
  --query '{Logging:IsLogging,Stopped:TimeLoggingStopped}'
# and check for StopLogging/DeleteTrail in the window (→ CloudTrail for DFIR)
```

**3. Build the key's full timeline.**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... --max-results 50
# Past 90 days → Athena/Lake over S3 logs
```

Sort by `eventTime`. Read it as a story: first-seen IP/UA → `GetCallerIdentity` → enumeration → what worked.

**4. Split legitimate from malicious.** Compare source IP / geo / user-agent to the key's *normal* use. The attacker's activity is usually a **new IP/ASN/country** and **scripted** (`boto3`/`aws-cli` from a residential/hosting IP), often a **burst of `AccessDenied`** (permission mapping).

**5. Did they pivot?** Look for `AssumeRole` from this key → follow the `ASIA` session (→ STS for DFIR). The role may be far more powerful than the user.

**6. Did they persist?** Hunt (→ IAM for DFIR):
- `CreateAccessKey` (a 2nd key on this or another user)
- `CreateUser` / `CreateLoginProfile`
- `AttachUserPolicy` / `PutUserPolicy` (admin)
- `CreateRole` / `UpdateAssumeRolePolicy` (trust backdoor)
- `Create*Provider` (rogue federation)

**7. What did they do?** Classify by phase (→ Investigating AWS): exfil (S3 `GetObject`/`CopyObject`, snapshot shares), mining (`RunInstances`), destruction (`Delete*`).

## Decision Points

| Question | If yes → |
|----------|----------|
| Is logging intact across the window? | Trust the timeline. If **no** → pivot to GuardDuty/Config/Flow; assume worst case |
| Did the key assume a role? | Follow the session; revoke role sessions too, not just the key |
| Did it create other creds/users? | You must kill **all** of them, or the attacker walks back in |
| Is the account in an Org? | Check the org trail for cross-account pivots |
| Public exposure confirmed (AWS notice)? | Treat as *definitely* compromised — rotate immediately |

## Contain

**Do this fast — the key works until you stop it.**

```bash
# 1. Deactivate the leaked key (reversible; preferred over delete while investigating)
aws iam update-access-key --user-name <user> --access-key-id AKIA... --status Inactive

# 2. If they assumed roles, revoke those sessions too (the ASIA keeps working otherwise)
#    IAM → Role → Revoke active sessions  (or inline deny by aws:TokenIssueTime)

# 3. Fast, broad quarantine of the identity if needed
aws iam attach-user-policy --user-name <user> \
  --policy-arn arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3
```

> 🔴 Deactivating the key does **not** stop an already-minted `ASIA` role session — revoke role sessions too.

## Eradicate

Work the **complete** persistence list — the leaked key is just the entry:

- Delete attacker-created **access keys**, **users**, **login profiles**.
- Detach attacker-added **policies**; delete rogue **inline policies** and **policy versions**.
- Fix tampered **role trust policies**; remove rogue **identity providers**.
- Delete backdoor **Lambda + EventBridge** self-healing loops (→ CloudWatch / Lambda).
- Re-enable any **logging** they disabled.

## Recover

- **Rotate the credential at its source** — the real fix. Find *where* it leaked (git history, laptop, CI variable, app) and remove/rotate it there, or it recurs.
- Rotate anything the identity could read (secrets, other keys).
- Restore/clean any resources touched (terminate rogue instances, re-privatize buckets, revert snapshots).
- Preserve evidence: export the CloudTrail slice + any GuardDuty findings.

## Fleet Hunt / Scope Check

- 🔴 **All regions** — re-check enumeration/`RunInstances` everywhere (mining hides in unused regions).
- 🔴 **All accounts** — org trail for cross-account `AssumeRole`.
- **Other leaked secrets** — if one key was in that repo/laptop/CI, assume others were too.
- **Same source IP** — pivot on the attacker IP across CloudTrail/Flow to find other footholds.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `GetCallerIdentity` from a new IP, then enumeration | Attacker "whoami" after landing the key |
| Burst of `AccessDenied` then a success | Permission mapping → privesc |
| `CreateAccessKey` / `CreateUser` | Persistence |
| `AssumeRole` you can't attribute | Pivot to a stronger role |
| `RunInstances` (large/GPU, odd region) | Cryptomining |
| `StopLogging` / `DeleteTrail` | Evasion |
| AWS abuse email / public-key notice | Definitive exposure |

## References

- Related notes: **IAM for DFIR**, **STS for DFIR**, **CloudTrail for DFIR**, **01 IAM & Identities**, **Secrets Manager for DFIR** (scope which downstream secrets the key could read)
- What to do if you inadvertently expose an AWS key — https://repost.aws/knowledge-center/potential-account-compromise
- Compromised-credentials quarantine policy — https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html
- MITRE ATT&CK: Valid Accounts – Cloud (T1078.004) — https://attack.mitre.org/techniques/T1078/004/
