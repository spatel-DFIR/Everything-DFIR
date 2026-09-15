# What is API Gateway?

**API Gateway** is a managed **front door for APIs** — it publishes HTTP/REST/WebSocket endpoints, handles auth, throttling, and routing, then forwards requests to a backend (usually **Lambda** or an HTTP service). It's the public entry point to a lot of serverless apps.

For DFIR it matters as an **exposed attack surface** (a misconfigured or auth-less API), a **request-log source** (access/execution logs), and the **trigger** for backend Lambda abuse.

## Contents

- [How It Works](#how-it-works)
- [Auth — Where It Goes Wrong](#auth--where-it-goes-wrong)
- [Logging](#logging)
- [How to Identify API Gateway in Evidence](#how-to-identify-api-gateway-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Client → API Gateway (stage/route) → Authorizer (optional) → Integration → Backend (Lambda / HTTP / AWS service)
                                    → logs to CloudWatch (access + execution)
```

- **Regional** (or edge-optimized via CloudFront); each API has **stages** (e.g. `prod`, `dev`).
- An **authorizer** (IAM, Cognito, or a custom Lambda) can gate each route — or the route can be **wide open**.
- The **integration** wires a route to a backend; most commonly a Lambda function.

## Auth — Where It Goes Wrong

The most common API Gateway security failure is **an endpoint with no (or broken) auth**:

| Auth type | What it is | 🔴 Failure mode |
|-----------|-----------|-----------------|
| **None** | Public route | 🔴 anyone calls the backend directly |
| **IAM (SigV4)** | Caller must sign with AWS creds | Over-broad invoke policy |
| **Cognito** | User-pool JWT required | Weak pool / token issues (→ Cognito) |
| **Lambda authorizer** | Custom code decides | 🔴 buggy authorizer = bypass; cached wrong |
| **API key** | A shared key (for throttling, *not* real auth) | 🔴 mistaken for security; leaks in client code |

> 🔴 **API keys are for usage plans/throttling, not authentication.** Treating an API key as a security control — or shipping it in client-side code — is a recurring finding. Real auth is IAM/Cognito/a correct Lambda authorizer.

## Logging

| Log type | Contains | Default |
|----------|----------|---------|
| **Access logs** | Per-request: source IP, route, status, latency, identity | 🔴 Off — enable per stage |
| **Execution logs** | Detailed request/response, authorizer decisions | 🔴 Off (verbose; enable for debugging/IR) |
| CloudTrail `apigateway.*` | API/route/authorizer/stage config changes | ✅ On (mgmt) |

## How to Identify API Gateway in Evidence

- **`eventSource`:** `apigateway.amazonaws.com`.
- **Endpoints:** `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/…`.
- **Logs:** CloudWatch log groups per API/stage (`API-Gateway-Execution-Logs_<id>/<stage>`).

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateRestApi` / `CreateApi` | Create an API | Config |
| `PutMethod` / `CreateRoute` (auth `NONE`) | Add a route | 🔴 unauthenticated route |
| `CreateDeployment` | Push changes live to a stage | 🔴 deploying attacker changes |
| `UpdateAuthorizer` / `DeleteAuthorizer` | Change/remove auth | 🔴 auth bypass |
| `PutIntegration` | Wire a route to a backend | 🔴 repoint to attacker backend/Lambda |
| `UpdateStage` (logging off) | Change stage config | 🔴 disabling logs |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| API Gateway | API Management (APIM) | API Gateway / Apigee |
| Authorizer | APIM policies / JWT validation | API Gateway auth |
| Access logs | APIM diagnostic logs | API Gateway logging |
| Usage plan / API key | APIM subscription key | API key |

## Common Use Cases

Your "normal":

- **Serverless APIs** in front of Lambda.
- **Public/partner APIs** with throttling + auth.
- **WebSocket** real-time backends.
- **Facade** over legacy HTTP services.

## Key Terminology

| Term | Meaning |
|------|---------|
| **REST / HTTP / WebSocket API** | The API flavors |
| **Stage** | A deployed version (prod/dev) |
| **Route / method / resource** | An endpoint path + verb |
| **Authorizer** | The auth mechanism gating routes |
| **Integration** | The backend a route forwards to |
| **Usage plan / API key** | Throttling + metering (not auth) |
| **Access / execution logs** | Per-request logging |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating API abuse | **API Gateway → API Gateway for DFIR** |
| The Lambda backend | **AWS → Compute → Lambda** |
| Cognito-based auth | **AWS → Identity & Access → Cognito** |
| Edge protection (WAF/ELB) | **AWS → Networking → ELB** |

## Resources

- What is API Gateway — https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html
- Controlling access — https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html
- CloudWatch logging — https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html
