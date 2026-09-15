# Cross-Cloud Correlation

Modern intrusions don't respect provider boundaries. A phished Microsoft 365 user becomes an Entra token, which federates into AWS, whose stolen role reads a secret holding a Google service-account key. One actor, three logs, three vocabularies. This note is the method for **stitching those logs into a single timeline** and proving it's the *same* actor across clouds.

Read it with **01 Cloud Identity and Federation** (the identity shapes) and **02 Evidence Acquisition** (getting the logs in the first place). For the full source-side/destination-side field-level depth on a *specific* pair, go to **[Cross-Cloud Investigations/](Cross-Cloud%20Investigations/README.md)** — this note stays the general method; that folder is where each bridge gets worked end to end.

## Contents

- [Why Actors Cross Clouds](#why-actors-cross-clouds)
- [The Bridges Between Clouds](#the-bridges-between-clouds)
- [Correlation Anchors — What Survives a Hop](#correlation-anchors--what-survives-a-hop)
- [Normalizing the Three Logs](#normalizing-the-three-logs)
- [Building the Unified Timeline](#building-the-unified-timeline)
- [Worked Example](#worked-example)
- [Pivot Table — From One Cloud to the Next](#pivot-table--from-one-cloud-to-the-next)
- [Pitfalls](#pitfalls)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why Actors Cross Clouds

- **Identity is federated.** SSO/IdP trust means one stolen human unlocks several clouds.
- **Secrets leak sideways.** An AWS Secrets Manager entry or a GCP secret can hold *another* cloud's credentials.
- **Orgs are multi-cloud.** Data in one, identity in another, CI/CD spanning all — the attacker follows the value.
- **CI/CD is the connective tissue.** A pipeline with OIDC trust into multiple clouds is a single compromise that reaches all of them.

## The Bridges Between Clouds

The specific wiring an actor rides across the boundary — check each for whether it exists in your environment:

| Bridge | From → To | Where it shows |
|--------|-----------|----------------|
| **Entra as IdP for AWS** | M365/Entra user → AWS (IAM Identity Center) | Entra sign-in → AWS SSO `AssumeRole`, `AWSReservedSSO_*` |
| **Google Workspace SSO → apps/GCP** | Workspace user → SAML apps / GCP | Workspace Login audit → downstream |
| **GitHub/GitLab OIDC → any cloud** | CI pipeline → AWS/Azure/GCP roles | `AssumeRoleWithWebIdentity` / federated cred / WIF with a repo subject |
| **Secret holding a foreign cred** | Any secret store → another cloud | `GetSecretValue`/Key Vault/Secret Manager read → new cloud's key used |
| **Cross-cloud service accounts** | An app in cloud A authenticating to cloud B | Long-lived key (`AKIA`/SA-JSON) used from cloud A's IP range |

> Each bridge above has its own directional deep-dive — the exact log fields, example values, and evidence gaps per pair — in **[Cross-Cloud Investigations/](Cross-Cloud%20Investigations/README.md)**, starting with **[00 - Cross-Cloud Bridges Overview](Cross-Cloud%20Investigations/00%20-%20Cross-Cloud%20Bridges%20Overview.md)**.

## Correlation Anchors — What Survives a Hop

To prove "same actor," lean on fields that persist across identities and providers:

| Anchor | Strength | Notes |
|--------|----------|-------|
| **Email / UPN / principalEmail** | High for the *human* | Same person across IdP + each cloud |
| **IdP correlation / session ID** | High | Ties one SSO login to the downstream cloud actions |
| **Source IP + ASN/geo** | Medium–High | Same infra within a window; VPN/Tor weakens it |
| **`userAgent` / tooling fingerprint** | Medium | A distinctive SDK/exploit-tool string reused across clouds |
| **Timing sequence** | Medium | Tight login→assume→act chains across logs |
| **`sourceIdentity` (AWS)** | High (if set) | Propagates through role chains to the origin human |
| **Certificate/thumbprint, key ID** | High | A specific SP cert or SA key reused |

> No single anchor is proof; **corroboration is.** Same IP *and* same tooling *and* a matching timing sequence across two clouds = one actor, with confidence.

## Normalizing the Three Logs

To compare across clouds, map every event to a **common five-field shape** (the model from **00**). This is the crux of cross-cloud work — and the same normalization SecOps/UDM does (→ **04**):

| Common field | AWS (CloudTrail) | Azure/Entra | Google (Cloud Audit) |
|--------------|------------------|-------------|----------------------|
| **who** | `userIdentity.arn` | `identity` / `appId` | `authenticationInfo.principalEmail` |
| **what** | `eventName` | `operationName` | `protoPayload.methodName` |
| **on what** | `requestParameters` / resource ARN | `targetResources` | `protoPayload.resourceName` |
| **from where** | `sourceIPAddress` | `ipAddress` | `requestMetadata.callerIp` |
| **when** | `eventTime` | `activityDateTime` | `timestamp` |
| **outcome** | `errorCode` (or success) | `resultType` | `status.code` |

Reduce each log to `who / what / where / when / outcome`, then merge on a shared timeline and hunt the anchors.

## Building the Unified Timeline

1. **Collect all three** (→ 02): CloudTrail, Entra Sign-in/Audit + Activity Log + UAL, Cloud Audit Logs.
2. **Normalize** each to the five fields above.
3. **Merge on time** into one ordered list (normalize to UTC).
4. **Seed with the known bad** — the confirmed compromised identity/IP/tool.
5. **Expand by anchor** — pull every event sharing that IP/UA/email/session, in each cloud.
6. **Find the bridges** — a federated sign-in, a secret read, a foreign key first-used; those are the seams where the actor crossed.
7. **Iterate** — each newly-found identity becomes a new seed until the graph stops growing.

## Worked Example

```
09:02  M365 (UAL)        user@corp phished — MFA satisfied via AiTM proxy, new mail rule created
09:14  Entra (Sign-in)   same user, new ASN, token issued; app consent to a rogue OAuth app
09:31  AWS (CloudTrail)   AWSReservedSSO_Admin assumed via SSO — same user upstream, same ASN
09:36  AWS (CloudTrail)   Secrets Manager GetSecretValue on "gcp-deploy-sa-key"
09:49  GCP (Audit)        that SA key first used from the SAME ASN → storage.objects.list, BigQuery extract
```

Anchors that stitch it: **same user email** (M365↔Entra↔AWS-SSO), **same ASN** (all four), **the secret read** (AWS→GCP bridge), **the SA key first-seen** at the same time/IP. One actor, three clouds, one story.

## Pivot Table — From One Cloud to the Next

| You found in… | Pivot to… | By |
|---------------|-----------|-----|
| M365/Entra compromise | AWS | SSO/Identity Center sign-ins for that user; `AWSReservedSSO_*` roles |
| AWS role/secret access | GCP/Azure | Secrets read that hold foreign creds; first-use of those creds |
| GCP SA key abuse | AWS/Azure | Where the key/secret was stored; who could read it |
| A CI/CD OIDC role | All clouds it trusts | The pipeline's federated identities in each cloud |
| A shared source IP/UA | Every cloud | Same-anchor events in each provider's log |

## Pitfalls

- **Clock skew / timezones** — normalize everything to UTC before merging.
- **Shared egress IPs** — NAT/VPN/proxy makes IP a weak sole anchor; corroborate.
- **Federated blind spots** — the cloud log stops at the permission-set; the *human* is only in the IdP log — pull it.
- **Missing data-plane** — you may see the pivot (control plane) but not the theft (data plane off); state the gap.
- **Responder noise** — exclude your own IR principal so it doesn't look like lateral movement.

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Full pair-by-pair bridge depth (source + destination evidence) | **[Cross-Cloud Investigations/](Cross-Cloud%20Investigations/README.md)** |
| The identity shapes you're linking | **01 Cloud Identity and Federation** |
| Getting the logs to correlate | **02 Evidence Acquisition in the Cloud** |
| Normalizing into SecOps/UDM + detections | **04 SecOps Detection & Response Engineering** |
| A full multi-cloud intrusion, step by step | **Cross-Cloud Investigations → Multi-Cloud Intrusion Playbook** |
| Who runs these campaigns | **05 Cloud Threat Landscape** |

## Resources

- MITRE ATT&CK: Valid Accounts – Cloud Accounts (T1078.004) — https://attack.mitre.org/techniques/T1078/004/
- CISA cloud IR / cross-service guidance — https://www.cisa.gov/resources-tools/resources
- The DFIR Report (cloud + identity intrusions) — https://thedfirreport.com/
