# Systems Manager (SSM) for DFIR

SSM is where an attacker gets **root on your fleet without ever touching the network** — no SSH login, no open port, no VPC ingress. That makes it a blind spot for anyone who only watches network and OS auth logs. This note is how you *see* it: read the SSM events in CloudTrail, reconstruct exactly what ran on which instance, and shut it down.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading the Log](#reading-the-log)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig / Harden](#fix-the-misconfig--harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

- **Root code execution, network-invisible.** `SendCommand` and `StartSession` run as the agent (root/SYSTEM). Your security groups, NACLs, bastion logs, and SSH auth logs see nothing.
- **Whole-fleet blast radius in one call.** Tag-based targeting hits every matching instance at once.
- **Persistence + secret theft live here too.** State Manager associations re-run code on a schedule; Parameter Store `SecureString` values are decryptable secrets.
- **The command content is recoverable** — if you know where to look.

## Evidence It Produces

| Evidence | Where it lives | Default | Retention | Notes |
|----------|---------------|---------|-----------|-------|
| **CloudTrail management events** (`SendCommand`, `StartSession`, `StartAutomationExecution`, `CreateAssociation`, `GetParameter*`…) | CloudTrail / CloudTrail Lake / S3 | ✅ On | Your trail's | The backbone — *who ran what*. Command text is inside `SendCommand` request params. |
| **SSM Command history** | SSM console → Run Command → Command history; `ListCommands` | ✅ On | **~30 days** | Command status per instance; survives even if CloudTrail is thin. Pull it early. |
| **Session history** | SSM console → Session Manager → Session history; `DescribeSessions` | ✅ On | ~30 days | Who opened a session, target, start/end. **Not keystrokes.** |
| **Session Manager logging** (keystrokes + output) | S3 bucket / CloudWatch Logs you nominate | 🔴 **Off** | Yours | The only source of *what was typed in a session*. Enable it before you need it. |
| **Run Command output** | S3 / CloudWatch (if configured), else truncated in `GetCommandInvocation` | 🔴 Off (full output) | Yours | Command *output* — separate from the command itself. |
| **On-instance agent logs** | `/var/log/amazon/ssm/amazon-ssm-agent.log`, `errors.log`; Windows: `%PROGRAMDATA%\Amazon\SSM\Logs\` | ✅ On (on host) | Host | Proves execution locally; useful when CloudTrail was tampered. |
| **On-instance command artifacts** | `/var/lib/amazon/ssm/<instance-id>/document/` | ✅ On (on host) | Host | The actual script SSM dropped and ran. |

> 🔴 **The gap to state out loud on every SSM case:** by default you can prove *a session was opened* but **not what was typed in it**, and you get the *command sent* but not always its full *output*. If Session Manager logging and Run Command output-to-S3 were off, the keystrokes/output were **never recorded** — pivot to on-instance artifacts (shell history, agent logs, `/var/lib/amazon/ssm/`).

## Collect It

**Managed instances (recon of scope):**
```bash
# Every instance SSM can reach + its ping status, agent version, IAM role
aws ssm describe-instance-information \
  --query 'InstanceInformationList[].[InstanceId,PingStatus,IamRole,PlatformName,LastPingDateTime]' --output table
```
*Console:* Systems Manager → **Fleet Manager** (or **Node Management → Managed instances**).

**Run Command history + the actual commands:**
```bash
# All commands in a window
aws ssm list-commands --query 'Commands[].[CommandId,DocumentName,Status,RequestedDateTime,Comment]' --output table
# Per-instance detail INCLUDING the command text and output
aws ssm list-command-invocations --command-id <id> --details
aws ssm get-command-invocation --command-id <id> --instance-id i-0abc123
```
*Console:* Systems Manager → **Run Command → Command history** → pick a command → **Output**.

**Session history:**
```bash
aws ssm describe-sessions --state History \
  --query 'Sessions[].[SessionId,Target,Owner,StartDate,EndDate]' --output table
```
*Console:* Systems Manager → **Session Manager → Session history**.

**The command/session events in CloudTrail (source of truth for *who*):**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
  --start-time 2026-07-01 --end-time 2026-07-12
```

**Persistence + payload objects:**
```bash
aws ssm list-associations                         # scheduled runs (State Manager)
aws ssm list-documents --filters Key=Owner,Values=Self   # custom docs
aws ssm describe-document-permission --name <doc> --permission-type Share  # shared out?
```

## Investigate on the Platform

Work it in this order:

1. **Was code run? By whom?** In CloudTrail, pull every `SendCommand` and `StartSession` in your window. For each, read `userIdentity` (the AKIA/ASIA decoder from **01 - IAM & Identities**), `sourceIPAddress`, `userAgent`.
2. **What exactly ran?** For `SendCommand`, open `requestParameters` → `documentName` + `parameters.commands` — *that is the payload*. `AWS-RunShellScript` / `AWS-RunPowerShellScript` with an inline command is the classic. Custom `documentName` → pull the document body (`aws ssm get-document --name`).
3. **Which instances?** `requestParameters.instanceIds` or `targets` (tag-based). Tag-based targeting = potential whole-fleet hit — enumerate what matched.
4. **Did they read secrets?** Look for `GetParameter`, `GetParameters`, `GetParametersByPath` — especially `withDecryption: true` on `SecureString` paths. `GetParametersByPath` on a broad path = bulk harvest.
5. **Did they establish persistence?** `CreateAssociation` / `UpdateAssociation` (scheduled re-run), `CreateDocument` / `UpdateDocument` (planted payload), `ModifyDocumentPermission` (shared a doc out to another account or public).
6. **Did they escalate?** `StartAutomationExecution` runs a runbook under a **passed IAM role** — check which role and what it can do.
7. **Pivot to the instance.** The session/command ran as the instance's role. Read that role from IMDS/EC2, then hunt for what *those* credentials did next (attacker who owns one box uses its role to reach others). See **IMDS SSRF to Role Theft**.
8. **Recover session content.** If Session Manager logging was on → pull the S3/CloudWatch transcript. If not → go on-instance: shell history, `amazon-ssm-agent.log`, `/var/lib/amazon/ssm/<id>/document/`.

## Reading the Log

The high-value fields in an SSM CloudTrail event:

| Field | Tells you | Watch for |
|-------|-----------|-----------|
| `eventName` | The SSM action | 🔴 `SendCommand`, `StartSession`, `StartAutomationExecution`, `CreateAssociation` |
| `userIdentity` | Who called it | 🔴 An `AssumedRole` / instance role you didn't expect running commands |
| `requestParameters.documentName` | Which SSM doc | `AWS-RunShellScript` w/ inline cmd; unknown custom docs |
| `requestParameters.parameters.commands` | **The actual command text** | 🔴 the payload — decode it |
| `requestParameters.instanceIds` / `targets` | Target(s) | 🔴 tag-based `targets` = fleet-wide |
| `requestParameters.withDecryption` | Secret was decrypted | 🔴 `true` on `GetParametersByPath` |
| `responseElements.commandId` / `sessionId` | Ties event → history record | Pivot to `get-command-invocation` |
| `sourceIPAddress` / `userAgent` | Origin & tool | 🔴 new geo/IP; odd SDK; not your automation host |

> ⚠️ `parameters.commands` can be large; CloudTrail may truncate or (if the doc marks params sensitive) omit it. When it's absent, reconstruct from **SSM command history**, the **document body**, and **on-instance artifacts**.

## Hunt at Scale

**CloudTrail Lake / Athena — every command run and by whom:**
```sql
SELECT eventTime, userIdentity.arn AS who, sourceIPAddress,
       element_at(requestParameters, 'documentName') AS document,
       element_at(requestParameters, 'instanceIds')  AS targets
FROM cloudtrail
WHERE eventName = 'SendCommand'
ORDER BY eventTime DESC;
```

**Interactive sessions from outside your admin ranges:**
```sql
SELECT eventTime, userIdentity.arn, sourceIPAddress,
       element_at(requestParameters, 'target') AS instance
FROM cloudtrail
WHERE eventName = 'StartSession'
  AND sourceIPAddress NOT IN ('<your VPN/egress IPs>')
ORDER BY eventTime DESC;
```

**Bulk parameter (secret) reads:**
```sql
SELECT eventTime, userIdentity.arn, eventName,
       element_at(requestParameters, 'path') AS param_path
FROM cloudtrail
WHERE eventName IN ('GetParametersByPath','GetParameters','GetParameter')
ORDER BY eventTime DESC;
```

**SecOps (UDM) — land it and ask "has this happened elsewhere?"**

| UDM field | SSM value |
|-----------|-----------|
| `metadata.product_event_type` | `SendCommand` / `StartSession` |
| `principal.user.userid` | `userIdentity.arn` |
| `principal.ip` | `sourceIPAddress` |
| `target.resource.name` | instance ID / target |

```
metadata.log_type="AWS_CLOUDTRAIL"
(metadata.product_event_type="SendCommand" OR metadata.product_event_type="StartSession")
principal.ip != <known_admin_ranges>
```

## Respond

**Kill active access first:**
```bash
aws ssm describe-sessions --state Active                # find live sessions
aws ssm terminate-session --session-id <id>             # cut them
```

**Remove the capability from the compromised principal** (strip `ssm:SendCommand`, `ssm:StartSession`, `ssm:StartAutomationExecution` from the role/user, or attach an explicit deny), then **revoke temporary sessions** — an `ASIA` session keeps working until you revoke it (see **STS → Respond**).

**Rip out persistence:**
```bash
aws ssm delete-association --association-id <id>        # scheduled re-run
aws ssm delete-document --name <malicious-doc>          # planted payload
# Un-share a document pushed to another account/public:
aws ssm modify-document-permission --name <doc> --permission-type Share \
  --account-ids-to-remove all
```

**Isolate the instance** if it was the launch point: detach/replace its instance profile (kills its AWS reach) and move it to a quarantine security group — but **snapshot the EBS volume and capture `/var/lib/amazon/ssm/` + agent logs first** (see **EBS for DFIR**).

**Rotate every secret** read from Parameter Store (`GetParameter*` on `SecureString`) — treat them as burned.

## Fix the Misconfig / Harden

| Fix | How | Verify |
|-----|-----|--------|
| **Least-privilege `ssm:*`** | Grant `SendCommand`/`StartSession` only to admins; scope with an IAM condition on `ssm:resourceTag/...` so a role can only target its own instances | IAM Access Analyzer; simulate the policy |
| **Force session logging** | Configure Session Manager preferences → **log to S3/CloudWatch**, KMS-encrypted, and enable **RunAs** (sessions run as a named user, not root) | Start a test session → transcript appears in the bucket |
| **Log Run Command output** | Set `OutputS3BucketName`/CloudWatch on documents or as an org default | Output object lands for a test command |
| **Restrict documents** | SCP/IAM to block `ModifyDocumentPermission` public sharing and limit which docs can run (`AWS-RunShellScript` allow-listing) | Attempt to share a doc public → denied |
| **Lock down Parameter Store** | `SecureString` for all secrets, tight KMS key policy, per-path IAM; deny broad `GetParametersByPath` | Read attempt from a low-priv role → `AccessDenied` |
| **Private-only SSM** | VPC endpoints for `ssm`, `ssmmessages`, `ec2messages`; no public egress needed | Endpoints present; agent connects privately |
| **Alarm on the danger ops** | EventBridge rule / GuardDuty + detection on `SendCommand`, `StartSession`, `StartAutomationExecution`, `CreateAssociation` from unexpected principals | Test event triggers alert |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `SendCommand` from a principal that isn't your automation/admin | Root RCE on the fleet |
| `SendCommand` with tag-based `targets` (not specific IDs) | Whole-fleet execution in one call |
| `AWS-RunShellScript`/`PowerShell` with an inline base64/`curl\|sh` command | Payload delivery |
| `StartSession` from a new IP/geo, off-hours | SSH-less interactive access by an intruder |
| Session Manager logging **off** on an instance that got a session | No transcript — evidence was never captured |
| `GetParametersByPath --with-decryption` over a broad path | Bulk secret theft |
| `CreateAssociation` / new custom `CreateDocument` | Persistence via scheduled re-execution |
| `StartAutomationExecution` under a privileged passed role | Privilege escalation |
| `ModifyDocumentPermission` sharing a doc to another account/public | Cross-account abuse / exfil |
| An instance role carrying `ssm:SendCommand` over `*` | One compromised box → whole-fleet pivot |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What SSM is and why it's an attacker tool | **What is Systems Manager (SSM)** |
| The full attack chain end-to-end | **Playbooks → SSM Run Command and Session Abuse** |
| The instance role SSM ran as, and IMDS theft | **AWS → Compute → EC2** · **Playbooks → IMDS SSRF to Role Theft** |
| Reading `userIdentity` (AKIA vs ASIA, role sessions) | **AWS → 01 IAM & Identities** · **STS** |
| Killing temporary sessions properly | **AWS → Identity & Access → STS** |
| Secrets read from Parameter Store / KMS-encrypted values | **AWS → Data Protection → KMS** · **Secrets Manager** |
| The same technique in Azure | **Azure → Virtual Machines → Run Command Abuse** |

## Resources

- Systems Manager Run Command — https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html
- Auditing session activity — https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging-auditing.html
- Logging Run Command activity in CloudTrail — https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html
- Restricting Run Command / RunAs & least privilege — https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-configuring-access-role.html
- Parameter Store security — https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-securestring.html
- SSM Agent — https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent.html
- MITRE ATT&CK: Cloud Administration Command (T1651) — https://attack.mitre.org/techniques/T1651/
