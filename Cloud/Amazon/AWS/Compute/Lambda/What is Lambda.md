# What is Lambda?

**Lambda** runs your code **without servers** — you upload a function, AWS runs it on demand (an API call, a schedule, an S3 upload, a queue message) and you pay per invocation. There's no instance to log into.

For DFIR, Lambda is a favorite for **stealthy persistence** (a backdoor function that re-creates access, triggered by an event) and **privilege abuse** (functions carry an IAM **execution role**). No box means no traditional host forensics — the evidence is the **function code, its config, and its CloudWatch logs**.

## Contents

- [How It Works](#how-it-works)
- [The Pieces That Matter](#the-pieces-that-matter)
- [Why Attackers Love Lambda](#why-attackers-love-lambda)
- [How to Identify Lambda in Evidence](#how-to-identify-lambda-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Trigger (API Gateway / EventBridge schedule / S3 event / SQS / Function URL)
   → Lambda runs your CODE in an ephemeral micro-environment
   → the code acts in AWS using the function's EXECUTION ROLE (temp creds via the runtime)
   → logs go to CloudWatch (/aws/lambda/<function>)
```

- **Ephemeral** — the execution environment is created and torn down; nothing persists on "the box."
- The function assumes its **execution role**, so its code gets `ASIA` creds just like an instance role.
- **Regional**; invoked synchronously or asynchronously; triggered by dozens of event sources.

## The Pieces That Matter

| Piece | What it is | 🔴 DFIR relevance |
|-------|-----------|-------------------|
| **Function code** | The uploaded zip / container image | 🔴 the payload — retrieve and read it |
| **Execution role** | The IAM role the function runs as | 🔴 over-broad = privesc; what the backdoor can do |
| **Environment variables** | Config, often **secrets** | 🔴 plaintext creds/keys live here |
| **Triggers / event sources** | What invokes it | 🔴 a schedule/event = self-healing persistence |
| **Layers** | Shared code dependencies | 🔴 poisoned layer = supply-chain backdoor |
| **Function URL** | A public HTTPS endpoint for the function | 🔴 an internet-exposed backdoor |
| **Resource policy** | Who/what may invoke it | 🔴 public/cross-account invoke |

## Why Attackers Love Lambda

| Use | How it works |
|-----|--------------|
| **Self-healing persistence** | EventBridge schedule → Lambda → `CreateAccessKey`/`CreateUser` every hour; delete the key, it comes back |
| **Trigger backdoor** | Function fires on a specific event (new login, S3 put) to act covertly |
| **Privilege escalation** | `CreateFunction` + `PassRole` (admin role) + invoke → run as admin |
| **Exfil pipeline** | Function reads data and ships it out on each event |
| **Secret harvesting** | Read env vars / the role's Secrets-Manager access |
| **Public backdoor** | A **Function URL** exposes attacker code to the internet |

> 🔴 The **EventBridge-schedule → Lambda → IAM** combo is the archetypal AWS persistence mechanism. When you kill an obvious backdoor user, check for the Lambda that recreates it. See **CloudWatch** (EventBridge) + **IAM for DFIR**.

## How to Identify Lambda in Evidence

- **`eventSource`:** `lambda.amazonaws.com`.
- **ARNs:** `arn:aws:lambda:<region>:<acct>:function:<name>`.
- **Logs:** CloudWatch log group `/aws/lambda/<function>` (stdout/stderr + `START/END/REPORT` lines).
- **Role sessions:** the function's actions appear as `assumed-role/<exec-role>/<function-name>`.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateFunction` / `UpdateFunctionCode` | Deploy / change code | 🔴 backdoor / poisoned code |
| `UpdateFunctionConfiguration` | Change role, env vars, timeout | 🔴 swap to admin role; add secrets |
| `AddPermission` (resource policy) | Allow an invoker | 🔴 public/cross-account invoke |
| `CreateFunctionUrlConfig` | Expose a public HTTPS endpoint | 🔴 internet-facing backdoor |
| `PublishLayerVersion` / `UpdateFunctionConfiguration` (layers) | Add a layer | 🔴 supply-chain backdoor |
| `Invoke` | Run the function | Data-event; volume/abuse |
| `GetFunction` | Download code + config | Normal analyst use (and attacker recon) |
| `TagResource`/`ListFunctions` | Enumerate | Recon |

> Note: `Invoke` is a **data event** (off by default). Without it you see the function was *created/changed* but not each *run*.

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| Lambda | Azure Functions | Cloud Functions / Cloud Run |
| Execution role | Function managed identity | Function service account |
| Function URL | Function HTTP trigger | Function HTTPS trigger |
| Layer | — (deployment package) | — |
| EventBridge trigger | Event Grid trigger | Eventarc trigger |

## Common Use Cases

Your "normal":

- **Event-driven glue** — process S3 uploads, queue messages, stream records.
- **APIs** — behind API Gateway.
- **Scheduled jobs** — cron-like via EventBridge.
- **Automation / auto-response** — including *security* automation (isolate on GuardDuty finding).

## Key Terminology

| Term | Meaning |
|------|---------|
| **Function** | The unit of code you deploy |
| **Execution role** | The IAM role the function runs as |
| **Trigger / event source** | What invokes the function |
| **Layer** | Shared dependency package |
| **Function URL** | A built-in public HTTPS endpoint |
| **Resource (invoke) policy** | Who may invoke the function |
| **Environment variables** | Function config (often secrets) |
| **Cold/warm start** | Fresh vs reused execution environment |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a malicious/abused function | **Lambda → Lambda for DFIR** |
| The execution role's permissions | **AWS → Identity & Access → IAM** |
| The EventBridge trigger (persistence) | **AWS → Logging & Monitoring → CloudWatch** |
| Function logs | **AWS → Logging & Monitoring → CloudWatch** |
| Public exposure via API Gateway | **AWS → Networking → API Gateway** |

## Resources

- What is Lambda — https://docs.aws.amazon.com/lambda/latest/dg/welcome.html
- Lambda execution role — https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html
- Lambda function URLs — https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html
- Logging with CloudTrail — https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
