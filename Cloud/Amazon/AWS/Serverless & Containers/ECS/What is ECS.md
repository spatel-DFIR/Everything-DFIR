# What is ECS?

**ECS (Elastic Container Service)** is AWS's **native container orchestrator** — it runs your Docker containers as **tasks** across a **cluster**, either on **EC2** instances you manage or on **Fargate** (serverless, no hosts). It's the simpler alternative to Kubernetes/EKS.

For DFIR, the container angle brings new surface: containers carry an IAM **task role** (stealable, like an instance role), pull images from **ECR** (supply-chain risk), and — critically — a container that can reach **IMDS** can steal the *host's* role. There's no long-lived host with Fargate, so evidence lives in **logs, task definitions, and the image**.

## Contents

- [How It Works](#how-it-works)
- [The Two Roles That Matter](#the-two-roles-that-matter)
- [Container Escape to Credentials](#container-escape-to-credentials)
- [Where the Evidence Is](#where-the-evidence-is)
- [How to Identify ECS in Evidence](#how-to-identify-ecs-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Cluster → Service (keeps N tasks running) → Task (1+ containers) from a Task Definition
   Task Definition = image (from ECR) + CPU/mem + TASK ROLE + EXECUTION ROLE + env/secrets
   Launch type: EC2 (your instances)  OR  Fargate (serverless, AWS-managed hosts)
   Logs → CloudWatch (awslogs driver)
```

- A **task definition** is the blueprint: which image, what resources, which IAM roles, what env/secrets.
- A **service** keeps a desired count of tasks alive; tasks are **ephemeral**.
- **ECS Exec** lets operators run a command *inside* a running container (like `docker exec`) — useful for IR *and* abusable by attackers.

## The Two Roles That Matter

Confusing these two is the #1 ECS mistake:

| Role | Who uses it | For what | 🔴 Risk |
|------|-------------|----------|---------|
| **Task role** | **Your app code** in the container | Calls AWS (S3/DynamoDB/etc.) at runtime | 🔴 stolen via app compromise → acts as the app |
| **Execution role** | **The ECS agent** (not your code) | Pull the image, fetch secrets, write logs | 🔴 over-broad = pull any image / read any secret |

> 🔴 When an app in a container is compromised, the attacker gets the **task role's** credentials (via the container credentials endpoint). Investigate what that role could reach — it's the container's blast radius. See **How data leaves** in ECS for DFIR.

## Container Escape to Credentials

Containers fetch task-role creds from a **container credentials endpoint** (`169.254.170.2`), not the EC2 IMDS. But on the **EC2 launch type**, a container that can reach **`169.254.169.254`** can steal the *host instance's* role — often more powerful than the task role.

| Path | What's stolen |
|------|---------------|
| App compromise → task-role creds (`169.254.170.2`) | The task role |
| Container → host IMDS (`169.254.169.254`) on EC2 launch type | 🔴 the **instance** role (usually broader) |
| Container breakout → host | Full host + everything on it |

> 🔴 **Block container access to the instance IMDS** (IMDSv2 + hop limit 1, or network policy). Otherwise a single container RCE escalates to the host's IAM role. On **Fargate** there's no host IMDS to reach — one reason Fargate is safer.

## Where the Evidence Is

| Evidence | Gives you |
|----------|-----------|
| **CloudWatch logs** (awslogs) | Container stdout/stderr — the app's behavior |
| **Task definition** | Image, roles, env/secrets — the blueprint |
| **CloudTrail `ecs.*`** | Task/service/exec changes + actor |
| **ECS Exec / SSM logs** | Who ran what *inside* a container |
| **The ECR image** | The container filesystem for offline analysis |
| **EC2 host** (EC2 launch type) | Snapshot the instance for host forensics (→ EC2) |

## How to Identify ECS in Evidence

- **`eventSource`:** `ecs.amazonaws.com`.
- **ARNs:** `arn:aws:ecs:<region>:<acct>:task/<cluster>/<id>`, `…:service/…`, `…:task-definition/<name>:<rev>`.
- **Role sessions:** task-role activity shows as `assumed-role/<task-role>/<task-id>`.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `RunTask` / `StartTask` | Launch tasks | 🔴 attacker running a malicious container |
| `RegisterTaskDefinition` | Define a new task blueprint | 🔴 new image/role/secrets — backdoor task |
| `UpdateService` | Change what a service runs | 🔴 swap in a malicious image |
| `ExecuteCommand` (ECS Exec) | Run a command in a container | 🔴 hands-on-keyboard in a container |
| `CreateCluster` / `DeleteCluster` | Cluster lifecycle | Config / destruction |
| `PutAccountSetting` (exec) | Enable ECS Exec | 🔴 enabling interactive access |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| ECS | Container Instances / Container Apps | Cloud Run / GKE Autopilot |
| Task | Container group | Pod / service |
| Task role | Container managed identity | Workload identity |
| ECR | Azure Container Registry | Artifact Registry |
| Fargate | Container Apps (serverless) | Cloud Run |

## Common Use Cases

Your "normal":

- **Microservices / web apps** in containers.
- **Batch/worker** tasks.
- **Fargate** for no-ops serverless containers.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Cluster** | A logical group of tasks/capacity |
| **Task** | A running unit of 1+ containers |
| **Task definition** | The blueprint (image, roles, env) |
| **Service** | Keeps a desired task count running |
| **Task role** | IAM role your app code uses |
| **Execution role** | IAM role the ECS agent uses |
| **ECS Exec** | Run commands inside a container |
| **ECR** | Elastic Container Registry (image store) |
| **Fargate** | Serverless launch type (no hosts) |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a container compromise | **ECS → ECS for DFIR** |
| Container concepts / on-host forensics | **Container → (Kubernetes/Docker notes)** |
| The serverless launch type | **AWS → Serverless & Containers → Fargate** |
| Kubernetes on AWS | **AWS → Serverless & Containers → EKS** |
| The host instance (EC2 launch type) | **AWS → Compute → EC2** |
| The task role's power | **AWS → Identity & Access → IAM** |

## Resources

- What is ECS — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/Welcome.html
- Task IAM roles — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- ECS Exec — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html
- Task metadata endpoint — https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html
