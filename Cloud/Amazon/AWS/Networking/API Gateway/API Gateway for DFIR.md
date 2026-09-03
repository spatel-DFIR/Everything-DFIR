# API Gateway for DFIR

API Gateway investigations center on two questions: **who called this API and did they get through auth?** (access/execution logs), and **did the API's exposure or auth get weakened?** (config changes). It's often the entry point to a serverless-backend compromise.

New to the service? Read **What is API Gateway** first.

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

API Gateway answers **"who hit this endpoint, did auth let them in, and did someone open it up or repoint it?"** — and links the public request to the backend Lambda/service it triggered.

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| **Access logs** | Per-request source IP, route, status, identity | 🔴 Off — enable per stage |
| **Execution logs** | Authorizer decisions, request/response detail | 🔴 Off — enable for IR |
| CloudTrail `apigateway.*` | API/route/authorizer/stage changes + actor | ✅ On |
| Backend (Lambda) logs | What the triggered function did | → Lambda / CloudWatch |

## Collect It

```bash
# Enumerate APIs, routes, and their AUTH
aws apigateway get-rest-apis
aws apigatewayv2 get-apis                              # HTTP/WebSocket APIs
aws apigateway get-resources --rest-api-id <id>       # routes/methods
aws apigateway get-authorizers --rest-api-id <id>     # what gates them
aws apigateway get-stages --rest-api-id <id> \
  --query 'item[].{Stage:stageName,Logging:accessLogSettings}'   # access logs on?

# Config changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateAuthorizer --max-results 30
```

> **Console:** API Gateway → API → **Routes/Resources** (auth per method), **Authorizers**, **Stages → Logs/Tracing** (access + execution logging), **Integrations** (backend).

## Investigate

| Step | Do this |
|------|---------|
| 1. Map exposure | Which routes have **auth `NONE`**? Those are directly callable |
| 2. Read access logs | Attacker IPs, the routes/params hit, status codes (2xx on sensitive routes = success) |
| 3. Read execution logs | Authorizer **allow/deny** decisions — was auth bypassed or misconfigured? |
| 4. Config tamper | `UpdateAuthorizer`/`DeleteAuthorizer` (auth removed), `PutMethod` auth→NONE, `PutIntegration` repoint |
| 5. Follow to backend | The request → the Lambda it invoked → what that function did (→ Lambda for DFIR) |

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The action | `UpdateAuthorizer`, `DeleteAuthorizer`, `PutMethod`, `PutIntegration`, `CreateDeployment` |
| `requestParameters.authorizationType` | Route auth | 🔴 `NONE` |
| `requestParameters` (integration) | Backend target | 🔴 repoint to attacker resource |
| `userIdentity` | Who changed it | Unexpected identity |

## Hunt at Scale

**In-platform — Athena over access logs + CloudTrail:**

```sql
-- Config changes weakening API auth
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'apigateway.amazonaws.com'
  AND eventname IN ('UpdateAuthorizer','DeleteAuthorizer','PutMethod','PutIntegration')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):** access logs (if forwarded) correlate request sources across the fleet; pivot to the backend for impact.

## Respond

| Goal | Action |
|------|--------|
| Re-enable auth | Restore the authorizer / set routes back to IAM/Cognito auth; redeploy the stage |
| Block the attacker | WAF on the API; block IPs; tighten throttling/usage plan |
| Fix a repointed integration | Restore the correct backend integration |
| Contain the backend | Investigate/isolate the triggered Lambda (→ Lambda for DFIR) |
| Re-enable logging | Turn on access + execution logs |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Auth on every route** (IAM/Cognito/validated authorizer) | No open backdoors to the backend |
| **Don't rely on API keys for auth**; keys for throttling only | Keys aren't a security boundary |
| **Enable access + execution logs** per stage | Request evidence + authorizer decisions |
| **Attach WAF**; set throttling/usage plans | Blocks abuse/scraping |
| **Alert** on `UpdateAuthorizer`/`DeleteAuthorizer`/method-auth changes | Catch auth weakening |
| **Least-privilege backend** (Lambda role) | Limits blast radius of a reached backend |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Route with `authorizationType: NONE` on sensitive data | Unauthenticated access to the backend |
| `UpdateAuthorizer`/`DeleteAuthorizer` in the window | Auth bypass enabled |
| Method auth changed to NONE | Route opened up |
| Integration repointed to an unexpected backend | Traffic hijack |
| Execution logs show authorizer allowing bad tokens | Broken auth logic |
| Access logging disabled mid-incident | Evidence turned off |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What API Gateway is + auth | **API Gateway → What is API Gateway** |
| The Lambda backend | **AWS → Compute → Lambda** |
| Cognito auth issues | **AWS → Identity & Access → Cognito** |
| Edge/WAF protection | **AWS → Networking → ELB** |

## Resources

- Controlling access to an API — https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html
- Set up CloudWatch logging — https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html
- MITRE ATT&CK: Exploit Public-Facing Application (T1190) — https://attack.mitre.org/techniques/T1190/
