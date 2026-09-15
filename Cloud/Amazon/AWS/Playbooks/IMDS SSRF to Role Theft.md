# Playbook — IMDS SSRF to Role Theft

The **Capital One-class** breach. A web app on EC2 has an **SSRF** flaw; the attacker uses it to reach the **Instance Metadata Service (IMDS)** at `169.254.169.254`, steals the instance's IAM **role credentials**, and uses them **from outside AWS** to reach S3 and beyond.

> **Tier 2 (cross-service).** Touches EC2, IMDS, STS, IAM, S3, and ELB/app logs. Read **EC2 for DFIR** (IMDS section) and **STS for DFIR** alongside it.

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
Web app on EC2 has an SSRF (or RCE/webshell)
   → attacker makes the app fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
   → receives the role's TEMPORARY creds (ASIA + secret + token)
   → uses them FROM OUTSIDE AWS (their own machine)
   → GuardDuty: InstanceCredentialExfiltration.OutsideAWS
   → acts as the instance role: S3 GetObject/ListBucket, enumerate, exfil
```

The root enabler is usually **IMDSv1 still allowed** (no session-token requirement), which a basic SSRF can hit.

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **GuardDuty** | 🔴 `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — the signature finding |
| **CloudTrail anomaly** | The instance role's `ASIA` session used from a non-AWS IP |
| **App/ALB logs** | Requests containing `169.254.169.254` / `latest/meta-data` |
| **S3 exfil alert** | Unusual bulk reads by the instance role |

## Hypothesis

An attacker exploited an app-layer flaw on an EC2 instance to steal its role credentials and is now using them externally. Confirm the theft, scope what the role accessed, and cut both the app flaw and the credentials.

## Step-by-Step Investigation

**1. Confirm the theft — creds used outside AWS.**

```bash
# The instance role's session activity; compare sourceIPAddress to the instance's own AWS IPs
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<instance-role-name> --max-results 50
```

🔴 The session ARN is `assumed-role/<role>/<instance-id>` — the **session name is the instance ID**, tying stolen creds to the exact box. Actions from a **non-AWS IP** = confirmed exfiltration.

**2. Identify the instance and confirm the exposure.**

```bash
aws ec2 describe-instances --instance-ids i-0abc123 \
  --query 'Reservations[].Instances[].{IMDS:MetadataOptions.HttpTokens,Role:IamInstanceProfile.Arn,PubIP:PublicIpAddress}'
# HttpTokens = "optional" → 🔴 IMDSv1 allowed (the SSRF-able state)
```

**3. Find the app-layer entry.** Pull **ALB access logs** and the app/web-server logs (→ ELB for DFIR) for requests to `169.254.169.254` / `/latest/meta-data/` — that's the SSRF, with the attacker's real client IP.

**4. Scope what the role reached.** The role's blast radius = its policy. Timeline every action the `ASIA` session took: `ListBucket`, `GetObject` (which buckets/objects — needs data events), enumeration, any further `AssumeRole`.

**5. Assess data loss.** For each S3 bucket the role touched, determine what was read (→ S3 for DFIR: "Did Data Actually Leave?").

## Decision Points

| Question | If yes → |
|----------|----------|
| Creds used from a non-AWS IP? | Confirmed theft — revoke sessions now |
| Was IMDSv1 allowed? | Root cause — require IMDSv2 as part of eradication |
| Did the role reach S3/secrets? | Scope + assume exfil of what it could read |
| Is memory/disk needed? | Capture the instance **before** you terminate it |
| Did the role assume further roles? | Follow the chain (→ STS) |

## Contain

```bash
# 1. Revoke the instance role's sessions (the ASIA works from anywhere until you do)
#    IAM → Role → Revoke active sessions  (deny by aws:TokenIssueTime)

# 2. Isolate the instance WITHOUT terminating (preserve evidence)
#    Swap to an empty quarantine security group (stateful → cuts C2/return traffic)

# 3. Snapshot the volume(s) + capture memory if live (→ EC2 for DFIR)
```

> 🔴 You **cannot** contain by "deleting the key" — it's a role session. Revoke the role's sessions *and* fix the instance, or the creds keep working until expiry.

## Eradicate

- **Require IMDSv2** on the instance (and the whole fleet) + hop limit 1:
  ```bash
  aws ec2 modify-instance-metadata-options --instance-id i-0abc123 \
    --http-tokens required --http-put-response-hop-limit 1
  ```
- **Fix the app flaw** (the SSRF/RCE) — otherwise they re-steal after your reset.
- Rebuild the instance from a **known-good AMI** (assume host compromise if RCE, not just SSRF).
- Rotate anything the role could read (secrets, other creds).
- Remove any persistence the attacker planted using the stolen role (new users/keys, etc. — → IAM for DFIR).

## Recover

- Redeploy a patched app on a hardened instance (IMDSv2-only).
- Re-privatize / assess any S3 data touched.
- Preserve: the ALB/app logs showing the SSRF, the CloudTrail slice, the GuardDuty finding, the volume snapshot.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `InstanceCredentialExfiltration.OutsideAWS` | Definitive IMDS role theft |
| Instance role session from a non-AWS IP | Stolen credentials in use |
| ALB/app logs hitting `169.254.169.254` | The SSRF request itself |
| `HttpTokens: optional` (IMDSv1 allowed) | The enabling misconfiguration |
| Instance role doing S3/IAM enum unlike the app | Stolen-cred abuse |
| Role assuming further roles | Deeper pivot |

## References

- Related notes: **EC2 for DFIR**, **STS for DFIR**, **S3 for DFIR**, **ELB for DFIR**
- Use IMDSv2 — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Add defense-in-depth against SSRF — https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/
- MITRE ATT&CK: Unsecured Credentials – Cloud Instance Metadata API (T1552.005) — https://attack.mitre.org/techniques/T1552/005/
