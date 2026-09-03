# Playbook — SSM Run Command and Session Abuse

An attacker with the right IAM permissions uses **AWS Systems Manager** to run commands and open shells on your EC2 fleet **as root/SYSTEM** — no SSH, no open port, no VPC ingress. Every network and OS-auth control you have stays quiet while they own the boxes. This is the AWS-native twin of **Azure Run Command Abuse**.

> **Tier 1 (single service, but pivots wide).** Anchored on SSM; touches EC2/IMDS, IAM/STS, Parameter Store/KMS, and CloudTrail. Read **Systems Manager (SSM) for DFIR** alongside it.

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
attacker holds a principal with ssm:SendCommand / ssm:StartSession
   (leaked IAM key, assumed role, or a compromised instance's own role via IMDS)
   → DescribeInstanceInformation  (enumerate every managed instance)
   → SendCommand  AWS-RunShellScript  --targets tag:Env=prod   (root RCE, whole fleet, one call)
        or  StartSession  (interactive root shell, SSH-less)
   → reads Parameter Store SecureStrings  (GetParametersByPath --with-decryption)
   → CreateAssociation / CreateDocument   (scheduled persistence)
   → pivots with each instance's role  (IMDS → S3, more SSM, more accounts)
```

The enabler is almost always an **over-broad `ssm:*` grant** — often on an *instance role itself*, so one compromised box becomes fleet-wide RCE.

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **CloudTrail** | 🔴 `SendCommand` / `StartSession` from an unexpected principal, IP, or geo |
| **GuardDuty** | Anomalous API by a role; instance-credential exfil if the instance role was stolen first |
| **Cost / EDR / CPU** | A box mining or beaconing with *no* SSH login to explain it |
| **Host telemetry** | Commands executing as root with parent `amazon-ssm-agent`, no interactive login |
| **Config/EventBridge rule** | Alert on `CreateAssociation` / `CreateDocument` / `StartAutomationExecution` |

## Hypothesis

A principal is using SSM to execute on instances outside change control. Confirm *who*, reconstruct *what ran on which instances*, find any persistence and secret theft, then cut the capability and the sessions.

## Step-by-Step Investigation

**1. Pull every SSM execution in the window.**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand --max-results 50
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StartSession --max-results 50
```
For each: read `userIdentity` (AKIA long-term vs ASIA role session → **01 IAM & Identities**), `sourceIPAddress`, `userAgent`.

**2. Recover the payload.** For each `SendCommand`, open `requestParameters.documentName` + `parameters.commands` — the literal command. If truncated/omitted, pull it from SSM history and the document body:
```bash
aws ssm list-command-invocations --command-id <id> --details
aws ssm get-document --name <documentName>
```

**3. Map the targets.** `requestParameters.instanceIds` or `targets`. Tag-based targeting = fleet-wide — enumerate what matched (`describe-instance-information`). Every matched instance is now suspect.

**4. Check for secret theft.** Hunt `GetParameter*` / `GetParametersByPath` with `withDecryption: true`. List what was under those paths — treat each as burned.

**5. Check for persistence.**
```bash
aws ssm list-associations                                   # scheduled re-runs
aws ssm list-documents --filters Key=Owner,Values=Self      # planted docs
aws ssm describe-document-permission --name <doc> --permission-type Share
```

**6. Find how they got the capability.** Was it a leaked user key, an SSO/assumed role, or an **instance role** read from IMDS (→ **IMDS SSRF to Role Theft**)? Trace the `ASIA` session back to its `AssumeRole`.

**7. Recover on-host truth.** If Session Manager logging was off, go to the instance: shell history, `/var/log/amazon/ssm/amazon-ssm-agent.log`, and the dropped script under `/var/lib/amazon/ssm/<id>/document/`.

## Decision Points

| Question | If yes → |
|----------|----------|
| Was `SendCommand`/`StartSession` from an unexpected principal/IP? | Confirmed abuse — contain now |
| Tag-based `targets` used? | Treat the whole matched fleet as compromised |
| Were `SecureString` params decrypted? | Rotate every secret on those paths |
| `CreateAssociation` / `CreateDocument` present? | Persistence — remove before you close |
| Did an *instance role* carry `ssm:*`? | Root cause — one box owned the fleet |
| Session logging off? | No transcript — pivot to on-host artifacts |

## Contain

```bash
# 1. Terminate live interactive sessions
aws ssm describe-sessions --state Active
aws ssm terminate-session --session-id <id>

# 2. Strip the capability from the compromised principal
#    Attach an explicit Deny on ssm:SendCommand/StartSession/StartAutomationExecution,
#    or detach the offending policy.

# 3. Revoke the temporary sessions — an ASIA keeps working until you do
#    IAM → Role → Revoke active sessions (deny by aws:TokenIssueTime).  See STS → Respond.
```

> 🔴 Disabling one access key is **not** containment if the actor already holds an assumed-role session — revoke the role's sessions too.

## Eradicate

- **Remove the malicious persistence:** `delete-association`, `delete-document`, and un-share any doc (`modify-document-permission … --account-ids-to-remove all`).
- **Fix the root grant:** scope `ssm:SendCommand`/`StartSession` to admins only, add an IAM condition on `ssm:resourceTag/...`, and **remove `ssm:*` from instance roles** unless truly required.
- **Rotate** every Parameter Store / KMS-backed secret the actor could read.
- **Rebuild** any instance that received an unknown command from a known-good AMI (assume host compromise).
- If the capability came via a **stolen instance role**, require **IMDSv2** and fix the app flaw (→ IMDS SSRF playbook).

## Recover

- Turn on **Session Manager logging** (S3/CloudWatch, KMS-encrypted) and **RunAs** so future sessions are attributable and non-root.
- Add EventBridge/detection alerts on `SendCommand`, `StartSession`, `StartAutomationExecution`, `CreateAssociation`.
- Preserve: the CloudTrail slice, SSM command/session history, any session transcript, and the on-host agent logs + dropped scripts.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `SendCommand` from a non-automation principal | Root RCE on instances |
| Tag-based `targets` on `SendCommand` | One-call whole-fleet execution |
| `AWS-RunShellScript` with `curl\|sh` / base64 inline | Payload delivery |
| `StartSession` from a new IP/geo, off-hours | SSH-less intruder shell |
| Session Manager logging off on a sessioned host | Keystrokes never recorded |
| `GetParametersByPath --with-decryption` broad path | Bulk secret theft |
| `CreateAssociation` / new custom document | Scheduled persistence |
| Instance role with `ssm:SendCommand` over `*` | Single box → fleet pivot |

## References

- Related notes: **Systems Manager (SSM) for DFIR**, **EC2 for DFIR**, **STS for DFIR**, **IMDS SSRF to Role Theft**, **Azure → Run Command Abuse**
- Run Command — https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html
- Session Manager auditing — https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging-auditing.html
- MITRE ATT&CK: Cloud Administration Command (T1651) — https://attack.mitre.org/techniques/T1651/
- MITRE ATT&CK: Serverless/Cloud Execution & Command — https://attack.mitre.org/matrices/enterprise/cloud/
