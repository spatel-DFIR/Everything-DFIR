# CloudTrail for DFIR

CloudTrail is the **first place you look** in almost every AWS investigation. It tells you what an identity did, from where, and whether it worked.

New to the service? Read **What is CloudTrail** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading a CloudTrail Event](#reading-a-cloudtrail-event)
- [What to Look For, by Phase](#what-to-look-for-by-phase)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

Three places to get CloudTrail data, each with trade-offs:

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Event history** (console) | Last 90 days, management events only | 90 days | Fast first look |
| **S3 bucket** | The durable `.json.gz` log files | Bucket lifecycle (often years) | The real evidence; long look-back |
| **CloudTrail Lake** | Events queryable with SQL | Up to 7–10 years | Retro-hunt across accounts |

**In SecOps:** ingests as log type `AWS_CLOUDTRAIL`. Rough UDM landing: principal → `principal.user.userid`, API → `metadata.product_event_type`, source IP → `principal.ip`, tool → `network.http.user_agent`. Confirm against a sample event — parsers vary.

## Collect It

**Step 1 — Confirm logging was even on.** Do this before anything else.

```bash
# List trails and whether they cover all regions / the whole org
aws cloudtrail describe-trails \
  --query 'trailList[].{Name:Name,Multi:IsMultiRegionTrail,Org:IsOrganizationTrail}' --output table

# 🔴 Is the trail logging now, and did it ever stop?
aws cloudtrail get-trail-status --name <trail> \
  --query '{Logging:IsLogging,Stopped:TimeLoggingStopped,Started:TimeLoggingStarted}'
```

> **Console:** CloudTrail → Trails → open the trail → *Logging* toggle + status.

**Step 2 — Pull the events.**

```bash
# Everything a user did
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<user> --max-results 50

# Everything tied to a leaked key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...
```

> **Console:** CloudTrail → Event history → filter by *User name* / *Event name* / *Access key ID* → **Download events**.

**Step 3 — Go past 90 days (from S3).**

```bash
aws s3 sync s3://<bucket>/AWSLogs/<acct>/CloudTrail/us-east-1/2026/07/09/ ./ct/
zcat ./ct/*.json.gz | jq '.Records[]' > events.json

# 🔴 Prove the logs weren't altered (needs log-file validation enabled)
aws cloudtrail validate-logs --trail-arn <trail-arn> --start-time 2026-07-09T00:00:00Z
```

## Investigate on the Platform

The flow — five steps:

| Step | Do this |
|------|---------|
| 1. Check for gaps | Confirm logging ran across your whole window. A stop inside it = blind spot → pivot to GuardDuty / VPC Flow / Config |
| 2. Scope the principal | Pull the full timeline for the user / key / IP from the alert. Sort by `eventTime` |
| 3. Classify each action | Bucket every `eventName` into a phase (see table below) |
| 4. Follow the role chain | A user key → `AssumeRole` → temporary `ASIA…` session → acts as the role. Tie them together |
| 5. Split human vs script | `userAgent` = browser/`AWS Internal` (console) vs `aws-cli`/`Boto3` (scripted) |

## Reading a CloudTrail Event

Five fields carry most investigations:

| Field | Answers | Notes |
|-------|---------|-------|
| `userIdentity` | **Who** | `type` = Root / IAMUser / AssumedRole / FederatedUser / AWSService |
| `eventName` + `eventSource` | **What** | The API and the service |
| `sourceIPAddress` | **From where** | 🔴 Can be an AWS service name for service-initiated calls |
| `userAgent` | **With what tool** | CLI, SDK, or console |
| `errorCode` | **Did it work** | Present + `AccessDenied` when the call failed |

Two fields hold the loot:

- `requestParameters` — **what they asked for** (the username, the bucket, the snapshot).
- `responseElements` — **what they got** (the new access key, the assumed-role creds).

For an **assumed role**, the pivot is `userIdentity.sessionContext`:

- `sessionIssuer.arn` — the role that was assumed.
- `attributes.mfaAuthenticated` — 🔴 was MFA used? `false` on an admin role is a flag.

## What to Look For, by Phase

| Phase | Telltale API calls |
|-------|--------------------|
| **Recon / enum** | `GetCallerIdentity`, then a wall of `List*` / `Describe*` / `Get*` (all `readOnly=true`) |
| **Persistence / privesc** | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `AttachUserPolicy`, `PutUserPolicy`, `CreateRole`, `AddUserToGroup` |
| **Creds / lateral** | `AssumeRole`, `GetSessionToken`, `GetFederationToken`, `GetSecretValue`, `Decrypt` |
| **Exfil / impact** | `GetObject` (data event), `CopyObject`, `PutBucketPolicy`, `ModifySnapshotAttribute` (share out), `RunInstances` (mining) |
| **Defense evasion** | 🔴 `StopLogging`, `DeleteTrail`, `PutEventSelectors`, `DeleteFlowLogs`, GuardDuty `DeleteDetector` |

🔴 A burst of `AccessDenied` errors is an attacker mapping what a stolen identity can reach — permission enumeration in the raw.

## Hunt at Scale

Work in-platform first, then SecOps for cross-account look-back.

**In-platform — CloudTrail Lake (SQL):**

```sql
SELECT eventTime, userIdentity.arn, sourceIPAddress, eventName
FROM <event_data_store_id>
WHERE eventName IN ('StopLogging','DeleteTrail','PutEventSelectors')
ORDER BY eventTime DESC;
```

> **Console:** CloudTrail → **Lake** → *Query* → paste SQL → *Run*. Save useful queries as a **saved query**.

**In-platform — Athena over the S3 logs (when there's no Lake):**

Athena runs SQL directly on the raw `.json.gz` files. Once a table exists (create it once via the CloudTrail console → *Create Athena table*, or a DDL statement), you query years of history:

```sql
-- Every action from a suspect IP, newest first
SELECT eventtime, useridentity.arn, eventname, awsregion, errorcode
FROM cloudtrail_logs
WHERE sourceipaddress = '203.0.113.10'
  AND eventtime > '2026-07-01'
ORDER BY eventtime DESC;

-- Permission-enumeration hunt: who is racking up AccessDenied?
SELECT useridentity.arn, count(*) AS denies
FROM cloudtrail_logs
WHERE errorcode = 'AccessDenied' AND eventtime > '2026-07-09'
GROUP BY useridentity.arn ORDER BY denies DESC;
```

> **Partitioning matters:** an unpartitioned Athena table scans *every* file (slow + costly). Use a partition-projected table (by region/date) so a one-day query scans one day. Your platform team usually has this set up.

**At the very end — SecOps UDM (optional, for cross-account retro-hunt):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "StopLogging"
```

Keep SecOps light — it answers "has this happened elsewhere / before?" across accounts. The deep read stays on the platform (Lake / Athena).

## Respond

Act on the identity first, then close the logging gap.

| Goal | Action |
|------|--------|
| Kill a leaked long-term key | `aws iam update-access-key --access-key-id AKIA... --status Inactive` |
| Revoke live temporary sessions | Console: IAM → Role → **Revoke active sessions**. CLI: put a deny-by-`aws:TokenIssueTime` inline policy |
| Neutralize a user fast | `aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2` |
| Re-enable logging | `aws cloudtrail start-logging --name <trail>` |

Then rotate the credential at its source (leaked secret, CI variable, laptop) and preserve the S3 logs + digest before any lifecycle rule expires them.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| One **multi-region organization trail** → a locked logging-account bucket | No unmonitored regions/accounts |
| Turn on **log file validation** (digest files) | Detect tampering |
| **SCP** denying `StopLogging` / `DeleteTrail` / `UpdateTrail` / `PutEventSelectors` outside break-glass | Removes the "attacker turns off logging" move |
| Bucket: block public access, **Object Lock / MFA-delete** | Logs can't be deleted |
| **Data events** on crown-jewel S3 / Lambda | See object-level exfil |
| Wire `StopLogging`/`DeleteTrail` → **EventBridge** alert | Catch blinding in real time |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `StopLogging` / `DeleteTrail` / `PutEventSelectors` | Attacker blinding the audit log |
| `get-trail-status` shows a stop inside the incident window | Logging gap — pivot to other evidence |
| `ConsoleLogin` with `MFAUsed = No` from a new IP | Stolen creds / session, no MFA |
| `CreateAccessKey` / `CreateLoginProfile` where none belongs | Persistence — new key / console password |
| `AssumeRole` into admin with `mfaAuthenticated: false` | Privilege escalation |
| Burst of `AccessDenied` | Permission enumeration |
| `ModifySnapshotAttribute` sharing a snapshot out | Data exfil via shared snapshot |
| Temporary `ASIA…` activity with no matching `AssumeRole` | Session minted outside your logging scope — widen window/region |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the service is + terminology | **CloudTrail → What is CloudTrail** |
| Identity types (user vs role vs token) | **AWS → 01 IAM & Identities** |
| Managed findings that pre-triage this | **AWS → Security & Detection → GuardDuty** |
| Data exfil / bucket exposure | **AWS → Storage → S3** |
| Instance/IMDS that leaked role creds | **AWS → Compute → EC2** |
| A full leaked-key intrusion | **AWS → Playbooks → Leaked Access Key** |
| Same identity pivoting to Azure/GCP | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- Record contents — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- `userIdentity` element — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
- Log file integrity validation — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
- MITRE ATT&CK Cloud (IaaS) — https://attack.mitre.org/matrices/enterprise/cloud/iaas/
