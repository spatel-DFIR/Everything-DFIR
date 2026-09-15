# Cloud Run for DFIR

Cloud Run cases ask: **did an attacker deploy or modify a service to run code as a privileged SA, ship a malicious image, or expose an endpoint — and what did the runtime SA reach?**

New to it? Read **What is Cloud Run** first.

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
| **Admin Activity** | Create/Replace/SetIamPolicy on services/jobs | Deploy/backdoor |
| **Runtime SA activity** | What the service's identity did | Blast radius |
| **Request + container logs** | Invocations + stdout/stderr | Behavior |
| **Revision/image config** | Image, env, SA, invoker | The payload |

## Collect It

```bash
# Services + runtime SA + public exposure
gcloud run services list --format='table(metadata.name,spec.template.spec.serviceAccountName)'
gcloud run services get-iam-policy <svc> --region=<r>   # allUsers invoker?
gcloud run services describe <svc> --region=<r> --format=json   # image + env

# Deploy/backdoor events
gcloud logging read \
 'protoPayload.serviceName="run.googleapis.com"
  AND protoPayload.methodName:("CreateService" OR "ReplaceService" OR "SetIamPolicy")' --freshness=30d
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Recent deploys | Create/Replace events — who, which service, which image |
| 2. Read the runtime SA | Over-privileged? Deployed via `actAs` on a privileged SA? |
| 3. Inspect image + env | Untrusted registry? Secrets in env? Backdoor logic? |
| 4. Public? | `allUsers` invoker = exposed endpoint |
| 5. Trace SA actions | What the runtime SA did in Cloud Audit Logs |

## Hunt at Scale

**Services deployed with a privileged SA or made public:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       protopayload_auditlog.methodName AS method, protopayload_auditlog.resourceName AS svc
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.serviceName='run.googleapis.com'
  AND protopayload_auditlog.methodName IN
      ('google.cloud.run.v1.Services.CreateService','google.cloud.run.v1.Services.ReplaceService','SetIamPolicy')
ORDER BY timestamp DESC;
```

> **At the very end — SecOps UDM (optional):** land Cloud Run deploy + public-invoker events to correlate the actor. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Kill a backdoor service | Delete/disable it; roll back to a known-good revision |
| Cut exposure | Remove `allUsers` invoker; require IAM auth |
| Contain the SA | Disable/rotate the runtime SA if abused |
| Preserve | Export the image ref, config, deploy events, SA activity |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Dedicated least-privilege runtime SA** per service | No default over-privilege |
| **Restrict `actAs`** on privileged SAs | Blocks deploy-as-SA privesc |
| **Require authentication** (no `allUsers`) | No open endpoints |
| **Binary Authorization** (trusted images only) | No malicious images |
| **Secrets via Secret Manager** | Reduce credential exposure |
| **Alert** on Create/Replace/SetIamPolicy for services | Catch backdoors live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Service deployed/updated running as a privileged SA | Privesc / backdoor |
| `allUsers` invoker added | Public endpoint |
| Image from an untrusted registry | Malicious workload |
| Env vars / mounts containing secrets | Credential access |
| Runtime SA doing unexpected API calls | Abuse of service identity |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Cloud Run fundamentals | **Cloud Run → What is** |
| The runtime SA's reach | **GCP → Service Accounts** · **Cloud IAM** |
| Gen1 functions | **GCP → Cloud Functions** |
| Privesc via deploy | **GCP → Playbooks → IAM Privilege Escalation** |

## Resources

- Service identity — https://cloud.google.com/run/docs/securing/service-identity
- Authentication — https://cloud.google.com/run/docs/authenticating/overview
- Binary Authorization — https://cloud.google.com/binary-authorization/docs
- MITRE ATT&CK: T1648 Serverless Execution / T1610 Deploy Container — https://attack.mitre.org/techniques/T1648/
