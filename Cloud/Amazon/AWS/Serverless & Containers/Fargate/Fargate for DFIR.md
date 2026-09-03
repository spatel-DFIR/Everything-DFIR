# Fargate for DFIR

Fargate DFIR is **cloud-side forensics under a constraint: there is no host to image.** The method is the same as ECS/EKS, but your evidence window is narrower and more time-sensitive — capture while the task runs, because when it stops, the in-container evidence is gone.

New to the service? Read **What is Fargate** first, plus the **ECS** or **EKS** note for the orchestration layer.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It — While It's Still Running](#collect-it--while-its-still-running)
- [Investigate](#investigate)
- [Reading the Events](#reading-the-events)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Fargate answers **"what did this container do and what did its role reach — using only logs, the image, and the role's trail?"** The absence of a host makes prior logging and runtime monitoring decisive.

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| CloudWatch logs (awslogs/FireLens) | Container stdout/stderr | If configured |
| Task/pod definition | Image, roles, env/secrets | Live pull |
| CloudTrail (`ecs`/`eks`, task-role, IRSA) | Deploy/exec/assume + actor | Always |
| GuardDuty Runtime Monitoring | On-container process/network telemetry | Add-on (turn it on) |
| The ECR image | Offline filesystem analysis | Pull + inspect |
| Live `exec` capture | In-container state — **only while running** | Time-limited |

## Collect It — While It's Still Running

🔴 **Time-critical.** If the task/pod is live, capture in-container evidence *now*:

```bash
# ECS-on-Fargate: exec in and capture volatile state before it dies
aws ecs execute-command --cluster <c> --task <task-id> --container <name> \
  --interactive --command "/bin/sh"
#   inside: ps, netstat, ls -la /tmp, env, list processes/connections, copy suspect files out

# Pull the exact image for offline analysis
aws ecs describe-task-definition --task-definition <name>:<rev> --query 'taskDefinition.containerDefinitions[].image'
# docker pull <ecr-image>  → inspect layers, scan, diff against a known-good build

# The task-role's AWS activity (works even after the task stops)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<task-role-name> --max-results 50
```

> **EKS-on-Fargate:** use `kubectl exec` into the pod for the same live capture, and `kubectl logs`. Snapshot pod spec + events with `kubectl get pod -o yaml` and `kubectl describe`.
>
> 🔴 **You cannot snapshot the node** — there isn't one you control. Live `exec`, logs, the image, and the role's CloudTrail trail are the whole case. Decide fast whether to preserve-then-contain or contain-immediately, knowing containment (stopping the task) destroys volatile evidence.

## Investigate

| Step | Do this |
|------|---------|
| 1. Live capture | If running: `exec` in, grab process/network/filesystem state, copy suspect artifacts out |
| 2. Logs | CloudWatch container logs for the window — the app's behavior |
| 3. Blueprint | Task/pod definition: unexpected image, over-broad role, secrets in env |
| 4. Role reach | CloudTrail on the task/pod role session — used from outside AWS? doing app-unlike things? |
| 5. Image | Pull + analyze the ECR image for backdoors/malware |
| 6. Runtime telemetry | GuardDuty Runtime Monitoring findings for the task/pod |

## Reading the Events

Fargate rides ECS/EKS events — see those notes. The Fargate-specific tells:

| Signal | 🔴 Meaning |
|--------|-----------|
| Task/pod-role creds used from an external IP | Container credentials stolen |
| `ExecuteCommand`/`kubectl exec` by an unexpected identity | Hands-on-keyboard in the container |
| An unknown image in a Fargate task def | Malicious workload deployed |
| GuardDuty Runtime finding on a Fargate task | On-container malicious behavior |

## Respond

| Goal | Action |
|------|--------|
| Preserve first (if feasible) | Live `exec` capture + pull the image **before** stopping |
| Contain | Stop the task / scale the service to 0 / delete the pod (this destroys volatile state) |
| Kill stolen creds | Revoke the task/pod role's sessions; scope the role down |
| Remove the backdoor | Fix the task def / deployment to a clean image; deregister the malicious revision |
| Rotate | Any secret the role or container could read |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable GuardDuty Runtime Monitoring** for Fargate | Your main substitute for host telemetry |
| **Ship logs** (awslogs/FireLens) to a durable, locked destination | Evidence survives the ephemeral task |
| **Least-privilege task/pod roles** | Small blast radius when a container is popped |
| **Secrets via Secrets Manager**, never env | Nothing to harvest in the definition |
| **ECR scanning + signed/trusted images** | Blocks supply-chain backdoors you can't inspect on a host later |
| **Restrict `ExecuteCommand`/`exec`**; log it | Controls + records interactive access |
| **Read-only root FS + non-root user** in the task def | Harder to persist inside a container |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Task/pod-role creds used from outside AWS | Stolen container credentials |
| Unexpected image deployed to a Fargate task | Malicious workload |
| `exec` into a Fargate container by an unexpected identity | Hands-on-keyboard |
| GuardDuty Runtime finding on the task | On-container attack behavior |
| No logging configured on a sensitive Fargate workload | No evidence — hardening gap (you can't image the host) |
| Secrets in the task/pod definition env | Credential exposure |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Fargate is + evidence model | **Fargate → What is Fargate** |
| ECS orchestration | **AWS → Serverless & Containers → ECS** |
| EKS orchestration + IRSA | **AWS → Serverless & Containers → EKS** |
| The role's AWS blast radius | **AWS → Identity & Access → IAM / STS** |
| Core container forensics | **Container → (Kubernetes/Docker notes)** |

## Resources

- Fargate security best practices — https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/security-fargate.html
- ECS Exec — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html
- GuardDuty Runtime Monitoring — https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html
- MITRE ATT&CK: Containers matrix — https://attack.mitre.org/matrices/enterprise/containers/
