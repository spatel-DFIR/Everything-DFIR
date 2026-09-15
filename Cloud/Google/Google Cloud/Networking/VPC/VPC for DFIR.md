# VPC for DFIR

VPC cases answer: **what got exposed, what new connectivity appeared, and was the exfil perimeter weakened?**

New to it? Read **What is VPC** first.

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
| **Admin Activity** | Firewall/network/peering/VPC-SC changes | Config edits |
| **Firewall Rules Logging** | Allow/deny decisions | What was permitted |
| **VPC Flow Logs** | Actual connections | Traffic (separate note) |
| **Policy Denied** | Perimeter-blocked requests | Exfil attempts |

## Collect It

```bash
# Current firewall exposure
gcloud compute firewall-rules list --format='table(name,direction,sourceRanges.list(),allowed[].map().firewall_rule().list())'

# Firewall / peering / perimeter changes in the window
gcloud logging read \
 'protoPayload.methodName:("compute.firewalls" OR "addPeering" OR "accessPolicies" OR "servicePerimeters")' \
 --freshness=30d --format=json
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Exposure review | New ingress allows, esp. `0.0.0.0/0` to sensitive ports |
| 2. Connectivity review | New peering / routes / Shared-VPC changes |
| 3. Perimeter review | VPC-SC changes adding projects or weakening restrictions |
| 4. Attribute | Who made each change, from where |
| 5. Correlate traffic | VPC Flow Logs for the exposed resource |

## Hunt at Scale

**Firewall rules opened to the internet:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       protopayload_auditlog.resourceName AS rule
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName LIKE '%compute.firewalls.insert%'
  -- inspect request.sourceRanges for 0.0.0.0/0
ORDER BY timestamp DESC;
```

> **At the very end — SecOps UDM (optional):** land firewall-open + perimeter-change events to correlate the actor. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Close exposure | Delete/patch the open firewall rule |
| Cut connectivity | Remove rogue peering/routes |
| Restore the perimeter | Revert VPC-SC changes; re-add protected services |
| Preserve | Export the config-change events + flow logs |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Deny-by-default egress + tight ingress** | Minimize exposure |
| **VPC Service Controls** around GCS/BigQuery | Blocks data exfil outside the perimeter |
| **Firewall Rules Logging** on | See allow/deny |
| **Org Policy** restricting external IPs / peering | Fewer paths out |
| **Alert** on `0.0.0.0/0` ingress + VPC-SC changes | Catch exposure/evasion live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| New ingress allow from `0.0.0.0/0` to SSH/RDP/DB | Direct exposure |
| New VPC peering / route | Lateral / exfil path |
| VPC-SC perimeter weakened / project added | Defense evasion for exfil |
| Firewall change by an unexpected principal | Attacker exposure |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| VPC fundamentals + VPC-SC | **VPC → What is** |
| Actual traffic | **GCP → VPC Flow Logs** |
| The exposed VM | **GCP → Compute Engine** |
| Data exfil end to end | **GCP → Playbooks → Data Exfiltration** |

## Resources

- Firewall rules — https://cloud.google.com/firewall/docs/firewalls
- VPC Service Controls — https://cloud.google.com/vpc-service-controls/docs/overview
- MITRE ATT&CK: T1562.007 Disable/Modify Cloud Firewall — https://attack.mitre.org/techniques/T1562/007/
