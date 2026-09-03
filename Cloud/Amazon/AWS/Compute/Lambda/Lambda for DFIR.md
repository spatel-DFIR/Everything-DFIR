# Lambda for DFIR

There's no box to image. A Lambda investigation is about **the code, the config, the role, and the logs**: retrieve the function, read what it does, see what its role can reach, and find how it's triggered (persistence).

New to the service? Read **What is Lambda** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate](#investigate)
- [Finding Lambda Persistence](#finding-lambda-persistence)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Lambda answers **"what does this function do, what can its role reach, and is it a persistence mechanism?"** Serverless backdoors are stealthy precisely because there's no host to inspect the usual way.

## Evidence It Produces

| Evidence | Gives you | Notes |
|----------|-----------|-------|
| **Function code** | The actual payload | `GetFunction` returns a download URL |
| **Function config** | Role, env vars (🔴 secrets), layers, triggers, timeout | `get-function-configuration` |
| **CloudWatch logs** (`/aws/lambda/<fn>`) | Runtime output — what it did each run | If the function logs |
| CloudTrail `lambda.*` | Create/update/permission/URL changes + actor | Always (mgmt) |
| `Invoke` data events | Per-invocation record | Only if enabled |
| Execution-role session activity | What the function's creds did in AWS | CloudTrail filter `assumed-role/<role>/<fn>` |

## Collect It

```bash
# Enumerate functions (sweep every region)
aws lambda list-functions --query 'Functions[].{Name:FunctionName,Role:Role,Runtime:Runtime,Modified:LastModified}' --output table

# 🔴 Download the code + read the config (role, env vars, layers, URL)
aws lambda get-function --function-name <fn> --query 'Code.Location' --output text   # → presigned URL, curl it
aws lambda get-function-configuration --function-name <fn>
aws lambda get-function-url-config --function-name <fn> 2>/dev/null                  # public endpoint?
aws lambda get-policy --function-name <fn> 2>/dev/null                               # who can invoke?
aws lambda list-event-source-mappings --function-name <fn>                           # what triggers it?

# Read the function's logs
aws logs tail /aws/lambda/<fn> --since 24h
```

> **Console:** Lambda → function → **Code** (read it), **Configuration → Environment variables / Permissions (role) / Triggers / Function URL**, **Monitor → View CloudWatch logs**.

## Investigate

| Step | Do this |
|------|---------|
| 1. Provenance | `CreateFunction`/`UpdateFunctionCode` — who created/changed it, when? Recent + unexpected = suspicious |
| 2. Read the code | Retrieve and inspect — reverse shells, cred-dumping, exfil, IAM manipulation |
| 3. Read env vars | 🔴 Plaintext secrets? An attacker-added exfil URL/token? |
| 4. Assess the role | What can the execution role do? Over-broad = the backdoor's reach (→ IAM) |
| 5. Map triggers | Function URL (public), API Gateway, EventBridge schedule, S3/SQS events — how is it invoked? |
| 6. Read logs | CloudWatch `/aws/lambda/<fn>` for what it actually did |

## Finding Lambda Persistence

The stealthy patterns to hunt:

| Pattern | Signature |
|---------|-----------|
| **Scheduled re-grant** | EventBridge `rate()/cron()` rule → Lambda that calls `CreateAccessKey`/`CreateUser` |
| **Trigger backdoor** | Function invoked on a specific event, acting covertly |
| **Public Function URL** | `CreateFunctionUrlConfig` + a permissive/`AuthType: NONE` policy = internet-callable |
| **Cross-account invoke** | `AddPermission` letting an external account invoke |
| **Poisoned layer** | A layer added/updated with malicious shared code |
| **Role swap** | `UpdateFunctionConfiguration` pointing the function at a more powerful role |

> 🔴 A function whose **code, role, or trigger changed during the incident window** — especially one paired with an EventBridge schedule or a public URL — is persistence until proven otherwise. Kill the trigger *and* the function.

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The action | `CreateFunction`, `UpdateFunctionCode`, `CreateFunctionUrlConfig`, `AddPermission` |
| `userIdentity` | Who | Unexpected identity deploying functions |
| `requestParameters.functionName` | Which function | Track it |
| `requestParameters.role` | Execution role assigned | 🔴 admin/over-broad role |
| `requestParameters.environment` | Env vars set | 🔴 secrets / exfil config |
| `requestParameters.authType` (URL) | `NONE` vs `AWS_IAM` | 🔴 `NONE` = unauthenticated public |

## Hunt at Scale

**In-platform — Athena / Lake:**

```sql
SELECT eventtime, useridentity.arn, eventname,
       json_extract_scalar(requestparameters,'$.functionName') AS fn
FROM cloudtrail_logs
WHERE eventsource = 'lambda.amazonaws.com'
  AND eventname IN ('CreateFunction','UpdateFunctionCode','UpdateFunctionConfiguration',
                    'CreateFunctionUrlConfig','AddPermission')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "CreateFunction" OR metadata.product_event_type = "CreateFunctionUrlConfig"
```

## Respond

| Goal | Action |
|------|--------|
| Stop a malicious function | Remove its triggers / event-source mappings; delete the Function URL; then delete the function (collect code first) |
| Kill self-healing persistence | Delete the paired EventBridge rule (→ CloudWatch) *and* the function |
| Cut public/cross-account invoke | Remove the offending resource-policy statements (`remove-permission`) |
| Contain the role | Revoke the execution role's sessions; scope its policy down (→ STS/IAM) |
| Rotate exposed secrets | Anything in env vars or reachable by the role |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Least-privilege execution roles**; no `*`, restrict `iam:*`/`PassRole` | Limits a backdoor's reach |
| **No secrets in env vars** — use Secrets Manager with tight access | Nothing to harvest in plaintext |
| **Function URLs `AWS_IAM` auth** (or none at all) | No unauthenticated public endpoints |
| **Code signing** for Lambda; trusted layers only | Blocks poisoned code/layers |
| **Enable `Invoke` data events** on sensitive functions | See each run |
| **SCP/alert** on `CreateFunctionUrlConfig`, `AddPermission` (public), role swaps | Catch backdoor wiring |
| **Review EventBridge rules → Lambda** regularly | No hidden self-healing persistence |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Function created/changed in the window with a broad role | Backdoor / privesc |
| `CreateFunctionUrlConfig` with `AuthType: NONE` | Public, unauthenticated code endpoint |
| `AddPermission` allowing external-account/public invoke | Cross-account/public backdoor |
| EventBridge schedule → Lambda → IAM writes | Self-healing persistence |
| Secrets or an exfil URL in environment variables | Cred harvesting / exfil |
| Execution role doing things unlike the app | Stolen-role abuse |
| Newly added/updated layer of unknown origin | Supply-chain backdoor |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Lambda is | **Lambda → What is Lambda** |
| The execution role's power | **AWS → Identity & Access → IAM** |
| The EventBridge trigger | **AWS → Logging & Monitoring → CloudWatch** |
| Public exposure via HTTP | **AWS → Networking → API Gateway** |
| Revoking the role session | **AWS → Identity & Access → STS** |

## Resources

- Lambda execution role — https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html
- Function URLs & auth — https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
- Lambda code signing — https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html
- MITRE ATT&CK: Serverless Execution (T1648) — https://attack.mitre.org/techniques/T1648/
