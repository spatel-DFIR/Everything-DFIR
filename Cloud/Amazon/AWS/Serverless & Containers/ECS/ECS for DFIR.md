# ECS for DFIR

A container compromise in ECS is investigated through **logs, the task definition, the task role, and the image** — plus the host if it's the EC2 launch type. The two big questions: *what did the compromised container's role reach*, and *did the attacker deploy or exec their own container*.

New to the service? Read **What is ECS** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate](#investigate)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

ECS answers **"what did the compromised container's role reach, and did an attacker deploy/exec their own container?"** With Fargate there's no host to image, so the cloud-side evidence carries the case.

## Evidence It Produces

| Evidence | Gives you | Notes |
|----------|-----------|-------|
| **CloudWatch logs** (awslogs) | Container stdout/stderr | If the awslogs driver was set |
| **Task definition** (all revisions) | Image, roles, env/secrets | `describe-task-definition` |
| CloudTrail `ecs.*` | RunTask/UpdateService/Exec + actor | Always (mgmt) |
| Task-role session activity | What the container's creds did in AWS | CloudTrail `assumed-role/<task-role>/<task-id>` |
| ECS Exec / SSM session logs | Commands run inside containers | If exec logging on |
| The ECR image | Container filesystem for offline analysis | Pull + inspect |

## Collect It

```bash
# What's running, and from what blueprint?
aws ecs list-clusters
aws ecs list-tasks --cluster <c>
aws ecs describe-tasks --cluster <c> --tasks <task-arn> \
  --query 'tasks[].{Def:taskDefinitionArn,LaunchType:launchType,Image:containers[].image}'

# 🔴 The blueprint: image, roles, env/secrets
aws ecs describe-task-definition --task-definition <name>:<rev> \
  --query 'taskDefinition.{TaskRole:taskRoleArn,ExecRole:executionRoleArn,Containers:containerDefinitions[].{img:image,env:environment,secrets:secrets}}'

# Container logs
aws logs tail /ecs/<task> --since 24h

# Who ran tasks / execed in?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ExecuteCommand --max-results 30
```

> **Console:** ECS → cluster → **Tasks** (running/stopped), each task → **Logs** + **Configuration** (image, roles). ECS → **Task definitions** (revisions).

## Investigate

| Step | Do this |
|------|---------|
| 1. Blueprint | Read the task definition: unexpected image? recently registered? secrets in plaintext env? |
| 2. Task-role reach | Filter CloudTrail by the task-role session — did the container's creds do things the app shouldn't? |
| 3. Attacker deploys | `RegisterTaskDefinition` / `RunTask` / `UpdateService` in the window — a malicious container? |
| 4. Hands-on-keyboard | `ExecuteCommand` (ECS Exec) events — who ran what inside a container |
| 5. Image analysis | Pull the ECR image; inspect layers for backdoors/malware |
| 6. Host (EC2 launch type) | Snapshot the instance; check for container→host IMDS theft (→ EC2) |

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The action | `RunTask`, `RegisterTaskDefinition`, `UpdateService`, `ExecuteCommand` |
| `requestParameters` (task def) | Image + roles + env | 🔴 unknown image; admin task role; secrets in env |
| `userIdentity` | Who deployed/execed | Unexpected identity |
| task-role `sourceIPAddress` | Where the creds were used | 🔴 outside AWS = stolen container creds |

## Hunt at Scale

**In-platform — Athena / Lake:**

```sql
SELECT eventtime, useridentity.arn, eventname,
       json_extract_scalar(requestparameters,'$.taskDefinition') AS taskdef
FROM cloudtrail_logs
WHERE eventsource = 'ecs.amazonaws.com'
  AND eventname IN ('RegisterTaskDefinition','RunTask','UpdateService','ExecuteCommand')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "RunTask" OR metadata.product_event_type = "ExecuteCommand"
```

## Respond

| Goal | Action |
|------|--------|
| Stop a malicious task/service | `stop-task` / scale the service to 0 / update to a known-good task def |
| Kill stolen task-role creds | Revoke the task role's sessions; scope its policy down (→ STS/IAM) |
| Remove a backdoor blueprint | Deregister the malicious task definition; fix the service to a clean revision |
| Contain the host (EC2 type) | Isolate + snapshot the instance (→ EC2 for DFIR) |
| Clean the image | Rebuild from a trusted base; rescan ECR |
| Preserve | Export logs; pull the image; snapshot the host |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Least-privilege task roles**; separate from execution roles | Small container blast radius |
| **Block container→instance IMDS** (IMDSv2 + hop limit 1) | Stops container→host role theft (EC2 type) |
| **Prefer Fargate** for sensitive workloads | No host IMDS / shared host |
| **Secrets via Secrets Manager**, not env vars | Nothing to harvest in the task def |
| **ECR image scanning** + signed/trusted images only | Blocks supply-chain backdoors |
| **ECS Exec logging on**; restrict who can exec | Records hands-on-keyboard |
| **GuardDuty Runtime Monitoring** (ECS) | On-container behavior detection |
| **Alert** on `RegisterTaskDefinition`, `RunTask`, `ExecuteCommand` by unexpected identities | Catch attacker deploys |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Task-role creds used from outside AWS | Stolen container credentials |
| `RegisterTaskDefinition` with an unknown image / admin role | Backdoor container |
| `RunTask`/`UpdateService` deploying an unexpected image | Malicious workload |
| `ExecuteCommand` by an unexpected identity | Hands-on-keyboard in a container |
| Container reaching `169.254.169.254` (EC2 type) | Container→host IMDS role theft |
| Secrets in plaintext task-def env | Credential harvesting |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What ECS is + the two roles | **ECS → What is ECS** |
| Container/host forensics concepts | **Container → (Kubernetes/Docker notes)** |
| The host instance (EC2 type) | **AWS → Compute → EC2** |
| Serverless launch type | **AWS → Serverless & Containers → Fargate** |
| The task role's power | **AWS → Identity & Access → IAM/STS** |

## Resources

- Task IAM roles — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- ECS Exec — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html
- ECR image scanning — https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
- MITRE ATT&CK: Deploy Container (T1610) / Container Admin Command (T1609) — https://attack.mitre.org/techniques/T1610/
