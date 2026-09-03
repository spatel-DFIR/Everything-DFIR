# What is Cloud Run?

**Cloud Run** runs **containers serverlessly** — you deploy an image, Google scales it, and it runs **as a service account**. It's GCP's answer to AWS Fargate/App Runner and Azure Container Apps (and it's what **Gen2 Cloud Functions** run on). For DFIR it's a **deploy-as-SA privilege-escalation** and **public-endpoint** surface.

## Contents

- [How It Works](#how-it-works)
- [The Runtime Service Account](#the-runtime-service-account)
- [Attack Surface](#attack-surface)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- A **service** runs a container image; each deploy is a **revision**. **Jobs** run to completion.
- Each service runs as a **runtime service account** and can be **public** (`allUsers` invoker) or **IAM-authenticated**.
- Deploy events are Admin Activity logged; requests + stdout/stderr go to Cloud Logging.

## The Runtime Service Account

🔴 A Cloud Run service **runs as an SA** — its access is that SA's roles.

| Fact | Detail |
|------|--------|
| **Default** | The Compute default SA (`<project-number>-compute@developer…`) unless you set one — often over-privileged |
| **Deploying needs `actAs`** | To deploy running as an SA, the deployer needs `iam.serviceAccounts.actAs` on it |
| 🔴 **The escalation** | `run.services.create` + `actAs` on a privileged SA = **run arbitrary code as that SA** |

## Attack Surface

| Vector | 🔴 |
|--------|----|
| **Deploy/update a service** running as a privileged SA | Code execution + privesc |
| **Malicious image** from an untrusted registry | Backdoored workload |
| **Public service** (`allUsers` invoker) | Unauthenticated endpoint |
| **Env vars / mounted secrets** | Credential access |

## How to Identify It in Evidence

- **Resource name:** `//run.googleapis.com/projects/<p>/locations/<r>/services/<name>`.
- **Deploy events:** `google.cloud.run.v1.Services.CreateService/ReplaceService`.
- **Runtime SA:** the service's `serviceAccountName`.
- **Public exposure:** `SetIamPolicy` adding `allUsers` as `run.invoker`.

## Common Operations You Will See

| methodName | What it does | 🔴 |
|-----------|--------------|----|
| `CreateService` / `ReplaceService` | Deploy/update a revision | 🔴 backdoor / privesc via `actAs` |
| `SetIamPolicy` (add `allUsers` invoker) | Make it public | 🔴 exposed endpoint |
| `CreateJob` / `RunJob` | Run a job container | 🔴 one-off malicious execution |
| `DeleteService` | Remove | Cover tracks |

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Cloud Run | Fargate / App Runner | Container Apps |
| Runtime SA | Task role | Container managed identity |
| `actAs` to deploy-as-SA | `PassRole` | — |
| Public invoker (`allUsers`) | Public ALB / Function URL | Ingress (external) |

## Common Use Cases

Your "normal": web services, APIs, event consumers, batch jobs, Gen2 functions. The job is to spot an **attacker-deployed/modified** service (privesc/backdoor) or a **public** one leaking data.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Service / revision** | A running container / a versioned deploy |
| **Job** | A run-to-completion container |
| **Runtime SA** | The identity the service runs as |
| **Invoker** | Who may call the service |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a Cloud Run case | **Cloud Run → for DFIR** |
| The runtime SA's reach | **GCP → Service Accounts** · **Cloud IAM** |
| Gen1 functions | **GCP → Cloud Functions** |
| Privesc via deploy | **GCP → Playbooks → IAM Privilege Escalation** |

## Resources

- Cloud Run — https://cloud.google.com/run/docs
- Service identity — https://cloud.google.com/run/docs/securing/service-identity
- Authentication overview — https://cloud.google.com/run/docs/authenticating/overview
