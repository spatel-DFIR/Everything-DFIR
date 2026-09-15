# What is Fargate?

**Fargate** is the **serverless compute engine** that runs ECS tasks and EKS pods **without you managing any EC2 hosts.** You hand AWS a container; AWS runs it on infrastructure you never see or touch.

For DFIR, Fargate's defining trait is **you have no host.** You can't SSH to the node, snapshot its disk, or capture its memory the normal way. That changes both the **risk profile** (safer — no shared host, no node IMDS to steal) and the **evidence model** (logs, task/pod definition, and the image — that's it).

## Contents

- [How It Works](#how-it-works)
- [Why It's Safer — and What You Lose](#why-its-safer--and-what-you-lose)
- [The Evidence Model](#the-evidence-model)
- [How to Identify Fargate in Evidence](#how-to-identify-fargate-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
You define an ECS task / EKS pod with launch type "Fargate"
   → AWS provisions an isolated micro-VM per task/pod (you don't manage it)
   → the container runs, gets its TASK/POD role creds from the local credentials endpoint
   → logs → CloudWatch;  the micro-VM is destroyed when the task ends
```

- **No EC2 to manage** — no patching, no node access, no shared kernel between tasks.
- Each task/pod runs in its **own isolated micro-VM** (strong isolation).
- The container gets IAM creds from the **task metadata / credentials endpoint** — **not** an EC2 IMDS.

## Why It's Safer — and What You Lose

| | Fargate advantage | DFIR cost |
|-|-------------------|-----------|
| **No node IMDS** | 🔴 Container can't steal a node instance role (the ECS/EKS-on-EC2 escalation is gone) | — |
| **Per-task isolation** | No noisy-neighbor / cross-task host compromise | — |
| **No host to patch** | Smaller ops attack surface | — |
| **No host access** | — | 🔴 No node disk snapshot / memory capture; can't do classic host forensics |
| **Ephemeral** | Attacker footprint disappears when the task ends | 🔴 Volatile evidence is gone unless logged live |

> 🔴 **The trade:** Fargate removes the worst container-escape-to-host path, but it also removes your ability to image the host. Your forensic readiness must shift *left* — into **logging, image scanning, and runtime monitoring** — because you can't grab the box after the fact.

## The Evidence Model

With no host, these are your sources:

| Source | Gives you | Note |
|--------|-----------|------|
| **CloudWatch logs** (awslogs / FireLens) | Container stdout/stderr | Enable it — it's often all you get |
| **Task / pod definition** | Image, roles, env/secrets | The blueprint |
| **CloudTrail** | Who deployed/changed/execed + IRSA/task-role assumes | AWS side |
| **The task/pod role's AWS activity** | What the container's creds did | CloudTrail (filter the role session) |
| **GuardDuty Runtime Monitoring** | On-container process/network behavior | The closest thing to host telemetry on Fargate |
| **The ECR image** | Offline filesystem analysis | Pull + inspect |
| **ECS Exec / kubectl exec** | Live triage *while the task runs* | Only chance at "in-container" evidence |

> 🔴 On Fargate, **GuardDuty Runtime Monitoring** and **live `exec` triage while the task is still running** are your substitutes for host forensics. If a task has stopped, the in-container evidence is usually gone — you're left with logs, the image, and the role's CloudTrail trail.

## How to Identify Fargate in Evidence

- In ECS: task `launchType: "FARGATE"`; in EKS: pods scheduled via a **Fargate profile**.
- **`eventSource`:** the parent — `ecs.amazonaws.com` / `eks.amazonaws.com` (Fargate has no separate API).
- Task metadata endpoint: `169.254.170.2` (creds) — **not** `169.254.169.254`.

## Common Operations You Will See

Fargate itself has no distinct API — you'll see the **ECS/EKS** operations, filtered to Fargate tasks/pods. The DFIR-relevant ones (see ECS/EKS notes):

| Operation | Watch? |
|-----------|--------|
| `RunTask` / `RegisterTaskDefinition` (Fargate) | 🔴 malicious container deploy |
| `ExecuteCommand` / `kubectl exec` | 🔴 hands-on-keyboard (and your live-triage window) |
| `AssumeRoleWithWebIdentity` (EKS/IRSA on Fargate) | Pod role assume |
| Task-role session activity | 🔴 creds used from outside AWS |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| Fargate | Container Apps / ACI | Cloud Run / GKE Autopilot |
| Task metadata endpoint | Instance metadata (managed) | Metadata server (managed) |

## Common Use Cases

Your "normal":

- **Serverless microservices** (ECS-on-Fargate).
- **Serverless Kubernetes pods** (EKS-on-Fargate).
- **Bursty/batch** workloads without capacity planning.
- **Security-sensitive workloads** wanting strong per-task isolation.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Launch type / Fargate profile** | How ECS/EKS selects Fargate |
| **Micro-VM** | The isolated per-task compute |
| **Task metadata endpoint** | `169.254.170.2` — creds/metadata (not EC2 IMDS) |
| **Task/pod role** | The IAM role the container uses |
| **FireLens** | Log-routing sidecar for Fargate |
| **Ephemeral storage** | Per-task scratch space (gone at task end) |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Fargate-specific investigation | **Fargate → Fargate for DFIR** |
| ECS orchestration + task roles | **AWS → Serverless & Containers → ECS** |
| EKS orchestration + IRSA | **AWS → Serverless & Containers → EKS** |
| The role's AWS blast radius | **AWS → Identity & Access → IAM / STS** |

## Resources

- What is Fargate — https://docs.aws.amazon.com/AmazonECS/latest/userguide/what-is-fargate.html
- Fargate security considerations — https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/security-fargate.html
- Task metadata endpoint v4 — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4-fargate.html
- GuardDuty Runtime Monitoring — https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html
