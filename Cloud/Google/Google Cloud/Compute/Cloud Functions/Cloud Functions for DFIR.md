# Cloud Functions for DFIR

Function cases ask: **did an attacker deploy or modify a function to run code as a privileged SA, backdoor the environment, or expose an endpoint — and what did the runtime SA reach?**

New to it? Read **What is Cloud Functions** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Best for |
|--------|--------------|----------|
| **Admin Activity** | Create/Update/SetIamPolicy on functions | Deploy/backdoor |
| **Runtime SA activity** | What the function's identity did | Blast radius |
| **Execution logs** | Per-invocation logs | Behavior |
| **Function config/source** | Code, env vars, trigger, SA | The payload |

## Collect It

```bash
# Enumerate functions + their runtime SA + public exposure
gcloud functions list --format='table(name,serviceAccountEmail,httpsTrigger.securityLevel)'
gcloud functions describe <fn> --region=<r> --format=json

# Deploy/backdoor events
gcloud logging read \
 'protoPayload.methodName:("CreateFunction" OR "UpdateFunction" OR "SetIamPolicy")
  AND resource.type="cloud_function"' --freshness=30d --format=json
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Recent deploys | Create/Update events in the window — who, which function |
| 2. Read the runtime SA | Over-privileged? Deployed via `actAs` on a privileged SA? |
| 3. Inspect the code/env | Backdoor logic, secrets, exfil destinations |
| 4. Public? | `allUsers` invoker = exposed endpoint |
| 5. Trace SA actions | What the runtime SA did in Cloud Audit Logs |

## Hunt at Scale

**Functions deployed to run as a privileged SA:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS deployer,
       protopayload_auditlog.resourceName AS fn
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName LIKE '%UpdateFunction%'
   OR protopayload_auditlog.methodName LIKE '%CreateFunction%'
ORDER BY timestamp DESC;
```

> **At the very end — SecOps UDM (optional):** land function deploy + public-invoker events to correlate the actor. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Kill a backdoor function | Delete/disable it; remove the trigger |
| Cut privilege | Remove `allUsers` invoker; re-point to a least-privilege SA |
| Contain the SA | Disable/rotate the runtime SA if abused |
| Preserve | Export the source, config, deploy events, and SA activity |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Dedicated least-privilege runtime SA** per function | No default over-privilege |
| **Restrict `actAs`** on privileged SAs | Blocks deploy-as-SA privesc |
| **Require authentication** (no `allUsers` invoker) | No open endpoints |
| **Secrets in Secret Manager**, not env vars | Reduce credential exposure |
| **Alert** on Create/Update/SetIamPolicy for functions | Catch backdoors live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Function deployed/updated running as a privileged SA | Privesc / backdoor |
| `allUsers` invoker added | Public endpoint |
| Env vars / source containing secrets | Credential access |
| Runtime SA doing unexpected API calls | Abuse of function identity |
| Function created by an unexpected principal | Attacker persistence |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Function fundamentals | **Cloud Functions → What is** |
| The runtime SA's reach | **GCP → Service Accounts** · **Cloud IAM** |
| Gen2 internals | **GCP → Cloud Run** |
| Privesc via deploy | **GCP → Playbooks → IAM Privilege Escalation** |

## Resources

- Function identity — https://cloud.google.com/functions/docs/securing/function-identity
- Authentication — https://cloud.google.com/functions/docs/securing/authenticating
- Audit logging — https://cloud.google.com/functions/docs/audit-logging
- MITRE ATT&CK: T1648 Serverless Execution / T1078.004 Cloud Accounts — https://attack.mitre.org/techniques/T1648/
