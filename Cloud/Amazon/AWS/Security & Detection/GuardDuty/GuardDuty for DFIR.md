# GuardDuty for DFIR

A GuardDuty finding is a **lead, not a verdict.** Your job is to take that lead — confirm it against the raw evidence, scope the true blast radius, and respond — while remembering that a smart attacker will try to switch GuardDuty off.

New to the service? Read **What is GuardDuty** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Working a Finding — The Flow](#working-a-finding--the-flow)
- [Confirm, Don't Trust](#confirm-dont-trust)
- [When GuardDuty Itself Is the Target](#when-guardduty-itself-is-the-target)
- [Reading a Finding](#reading-a-finding)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

GuardDuty answers **"what does AWS already think is wrong, and where should I look first?"** It compresses hours of log-reading into a typed, scored lead — but it only sees what its enabled data sources cover, and it can be disabled or suppressed.

## Evidence It Produces

| Evidence | What it gives you | Where |
|----------|-------------------|-------|
| **Findings** | Typed, scored detections with actor + evidence | GuardDuty console / API / EventBridge |
| Finding detail JSON | The API call, remote IP, threat-intel context | `get-findings` |
| **CloudTrail `guardduty.*`** | Who changed GuardDuty config (🔴 disable/suppress) | CloudTrail |
| Detector/coverage state | Which data sources are on per account/region | `get-detector`, coverage APIs |

## Collect It

```bash
# Find the detector, then list + read findings (do this PER REGION)
aws guardduty list-detectors
aws guardduty list-findings --detector-id <id> \
  --finding-criteria '{"Criterion":{"severity":{"GreaterThanOrEqual":4}}}'
aws guardduty get-findings --detector-id <id> --finding-ids <fid1> <fid2> > findings.json

# 🔴 Confirm nobody disabled or suppressed detection during the incident
aws guardduty get-detector --detector-id <id>            # Status: ENABLED? sources on?
aws guardduty list-filters --detector-id <id>            # suppression rules?
aws guardduty list-ip-sets --detector-id <id>            # trusted (whitelisted) IPs?
```

> **Console:** GuardDuty → **Findings** (filter by severity/type/resource) → open a finding for full detail + *Investigate with Detective*. Settings → **Lists** (suppression/trusted IP), **Accounts** (org coverage).
>
> 🔴 **Sweep every region.** GuardDuty is regional; a finding may only exist in the region the attacker used.

## Working a Finding — The Flow

| Step | Do this |
|------|---------|
| 1. Read the type | The `type` string tells you the pattern; map it to a phase (recon/exfil/impact) |
| 2. Identify the actor + resource | `service.action` (IP, user, role) + `resource` (which EC2/bucket/identity) |
| 3. Pivot to raw evidence | Pull the underlying CloudTrail / VPC Flow / DNS to **confirm** (next section) |
| 4. Scope | Same actor/IP/role across other findings, regions, accounts? Build the timeline |
| 5. Decide response | Confirmed → contain the resource + identity; false positive → suppress *carefully* |

## Confirm, Don't Trust

A finding points you at evidence — go read it. Each finding type has a native pivot:

| Finding family | Confirm by reading… |
|----------------|---------------------|
| `UnauthorizedAccess:IAMUser/*`, `Recon:*`, `Persistence:*` | **CloudTrail** for that identity/IP (→ CloudTrail for DFIR) |
| `InstanceCredentialExfiltration.OutsideAWS` | CloudTrail: the role's `ASIA` session used from an external IP (→ STS, EC2) |
| `CryptoCurrency:*`, `Backdoor:*`, `Trojan:*!DNS` | **VPC Flow Logs** + DNS for the instance's egress (→ VPC Flow Logs) |
| `Exfiltration:S3/*`, `Discovery:S3/*` | **S3 data events** for the objects touched (→ S3 for DFIR) |
| `Policy:S3/BucketAnonymousAccessGranted` | The bucket's policy + `PutBucketPolicy` event (→ S3) |

> 🔴 **False positives happen** (a pen-test, a legit tool from a flagged IP, an admin from a new country). But **archive/suppress only after confirming** — mass-suppressing to "clear the board" is exactly what an attacker wants you to do.

## When GuardDuty Itself Is the Target

Attackers blind detection. Always verify GuardDuty was healthy across your window:

| Move | Signature | Check |
|------|-----------|-------|
| Disable the detector | `DeleteDetector` / `UpdateDetector` (suspend) | `get-detector` status; CloudTrail |
| Turn off a data source | `UpdateDetector` disabling S3/DNS/etc. | Coverage APIs |
| Suppress their own alerts | `CreateFilter` + `CreateSuppressionRule` | `list-filters` — read the criteria |
| Whitelist their IP | `CreateIPSet` / `UpdateIPSet` (trusted) | `list-ip-sets` — is the attacker IP trusted? |
| Drop org coverage | `DisassociateMembers` / `DeleteMembers` | Org GuardDuty membership |

> 🔴 A **suppression rule or trusted-IP list created during the incident** is a defense-evasion smoking gun — and it means findings you'd expect may have been silently archived. Un-suppress and re-review.

## Reading a Finding

```jsonc
{
  "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
  "severity": 8,
  "resource": { "resourceType": "AccessKey",
    "accessKeyDetails": { "userName": "app-role", "accessKeyId": "ASIA..." } },
  "service": {
    "action": { "awsApiCallAction": {
        "remoteIpDetails": { "ipAddressV4": "203.0.113.9", "country": {"countryName":"..."} } } },
    "eventFirstSeen": "2026-07-09T14:00:00Z", "count": 12 }
}
```

Read it as: *the `app-role` instance credentials (`ASIA…`) were used from `203.0.113.9` **outside AWS**, 12 times, starting 14:00* → confirmed IMDS/SSRF role theft. Pivot to **EC2** (which instance leaked it) and **STS/CloudTrail** (what the session did).

## Hunt at Scale

**In-platform — GuardDuty findings + the config-tamper CloudTrail:**

```sql
-- Did anyone touch GuardDuty during the window? (Athena/Lake)
SELECT eventtime, useridentity.arn, eventname, awsregion
FROM cloudtrail_logs
WHERE eventsource = 'guardduty.amazonaws.com'
  AND eventname IN ('DeleteDetector','UpdateDetector','CreateFilter','CreateIPSet',
                    'DisassociateMembers','DeleteMembers')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):** GuardDuty findings often ship to SecOps directly as their own log type; use it to correlate findings across accounts, then pivot back to AWS for the raw evidence.

## Respond

| Goal | Action |
|------|--------|
| Contain a compromised instance | Isolate SG + snapshot (→ EC2 for DFIR); don't terminate before capture |
| Kill exfiltrated role creds | Revoke the role's sessions; fix the instance profile (→ STS/EC2) |
| Kill a compromised key/user | Deactivate key / quarantine identity (→ IAM for DFIR) |
| Re-enable detection | `CreateDetector` / `UpdateDetector` to restore sources |
| Remove attacker suppression | Delete rogue filters/trusted-IP entries; re-scan findings |
| Automate next time | EventBridge rule: High-severity finding → Lambda/SSM auto-isolate |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable GuardDuty org-wide, all regions**, from a delegated admin | No blind account/region |
| **Turn on the add-ons** you need (S3, EKS, Malware, Runtime) | Core-three misses object exfil / on-host / K8s |
| **SCP denying** `guardduty:DeleteDetector` / `UpdateDetector` / `Create*Set` outside break-glass | Attacker can't disable/suppress |
| **Alert** on any `guardduty.*` config change | Catch blinding in real time |
| **Auto-response** wiring (EventBridge → isolate) | Contain faster than a human can |
| **Send findings to Security Hub + SecOps** | One pane; cross-account correlation |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `DeleteDetector` / `UpdateDetector` (disable) in the window | Detection turned off |
| New suppression rule / trusted-IP list mid-incident | Attacker silencing their own alerts |
| `InstanceCredentialExfiltration.OutsideAWS` | Role creds stolen from an instance |
| `CloudTrailLoggingDisabled` finding | Logging tampered — pivot immediately |
| High-severity finding archived without investigation | Someone clearing the board |
| Findings clustered in an **unused region** | Attacker hiding where nobody looks |
| GuardDuty never enabled in the breached account | You're flying blind — hardening finding |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What GuardDuty is + finding types | **GuardDuty → What is GuardDuty** |
| Confirming IAM/API findings | **AWS → Logging & Monitoring → CloudTrail**, **IAM** |
| Confirming network findings | **AWS → Logging & Monitoring → VPC Flow Logs** |
| Instance findings (mining/C2/IMDS) | **AWS → Compute → EC2** |
| Graph-based pivoting | **AWS → Security & Detection → Detective** |
| Aggregating across tools | **AWS → Security & Detection → Security Hub** |

## Resources

- Remediating GuardDuty findings — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html
- Finding types (active) — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
- Auto-remediation with EventBridge — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html
- MITRE ATT&CK Cloud (IaaS) — https://attack.mitre.org/matrices/enterprise/cloud/iaas/
