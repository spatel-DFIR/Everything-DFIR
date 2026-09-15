# What is Cloud Functions?

**Cloud Functions** is GCP's serverless functions-as-a-service — the equivalent of AWS Lambda and Azure Functions. Code runs on a trigger (HTTP, Pub/Sub, GCS event) **as a service account**. For DFIR it's both a **persistence/execution** surface (deploy a function that runs as a privileged SA) and a place secrets hide (env vars, source).

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

- A function has **source code**, a **trigger**, **environment variables**, and a **runtime service account**.
- **Gen2** functions run on **Cloud Run** under the hood (see the Cloud Run note).
- Deploy/update is **Admin Activity** logged; execution logs go to **Cloud Logging**.

## The Runtime Service Account

🔴 A function **runs as a service account** — its access is that SA's roles.

| Fact | Detail |
|------|--------|
| **Default** | The App Engine default SA (`<project-id>@appspot.gserviceaccount.com`) — often over-privileged |
| **Deploying needs `actAs`** | To deploy a function running as an SA, the deployer needs `iam.serviceAccounts.actAs` on it |
| 🔴 **The escalation** | `cloudfunctions.functions.create` + `actAs` on a privileged SA = **run arbitrary code as that SA** |

## Attack Surface

| Vector | 🔴 |
|--------|----|
| **Deploy/update a function** running as a privileged SA | Code execution + privilege escalation |
| **Backdoor** — a function that mints keys / exfils on trigger | Persistence |
| **Public HTTP function** (`allUsers` invoker) | Exposed, unauthenticated endpoint |
| **Env vars / source** holding secrets | Credential access |

## How to Identify It in Evidence

- **Resource name:** `//cloudfunctions.googleapis.com/projects/<p>/locations/<r>/functions/<name>`.
- **Deploy events:** `google.cloud.functions.v1.CloudFunctionsService.CreateFunction/UpdateFunction`.
- **Runtime SA:** the function's `serviceAccountEmail`.
- **Execution logs:** Cloud Logging, `resource.type="cloud_function"`.

## Common Operations You Will See

| methodName | What it does | 🔴 |
|-----------|--------------|----|
| `CreateFunction` / `UpdateFunction` | Deploy/change code | 🔴 backdoor / privesc via `actAs` |
| `SetIamPolicy` (add `allUsers` invoker) | Make it public | 🔴 exposed endpoint |
| `CallFunction` / HTTP invoke | Execution | Volume/anomaly |
| `DeleteFunction` | Remove | Cover tracks |

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Cloud Functions | Lambda | Azure Functions |
| Runtime SA | Lambda execution role | Function managed identity |
| `actAs` to deploy-as-SA | `PassRole` | — |
| Public invoker (`allUsers`) | Function URL / public API GW | Anonymous function |

## Common Use Cases

Your "normal": event glue, webhooks, lightweight APIs, automation. The job is to spot an **attacker-deployed/modified** function (privesc, backdoor, exfil) or a **public** one leaking data.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Function** | A unit of serverless code |
| **Trigger** | What invokes it (HTTP/Pub-Sub/GCS) |
| **Runtime SA** | The identity the function runs as |
| **Gen2** | Cloud Functions on Cloud Run |
| **Invoker** | Who may call the function |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a function in a case | **Cloud Functions → for DFIR** |
| The runtime SA's reach | **GCP → Service Accounts** · **Cloud IAM** |
| Gen2 internals | **GCP → Cloud Run** |
| Privilege escalation via deploy | **GCP → Playbooks → IAM Privilege Escalation** |

## Resources

- Cloud Functions — https://cloud.google.com/functions/docs
- Function identity (runtime SA) — https://cloud.google.com/functions/docs/securing/function-identity
- Audit logging — https://cloud.google.com/functions/docs/audit-logging
