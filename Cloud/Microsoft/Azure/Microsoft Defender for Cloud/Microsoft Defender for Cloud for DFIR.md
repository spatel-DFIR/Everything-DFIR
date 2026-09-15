# Microsoft Defender for Cloud for DFIR

MDC is usually **where the case starts** — a pre-triaged alert naming a resource and technique. This note is how you work an alert: confirm it, pivot to the underlying evidence, and use the posture side to find the root-cause misconfig.

New to the service? Read **What is Microsoft Defender for Cloud** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Working an Alert](#working-an-alert)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there |
|--------|--------------|
| **Security alerts** | Threat detections w/ MITRE mapping + entities |
| **Recommendations** | Misconfigs (the root cause) |
| **Sentinel / XDR** (`SecurityAlert`) | Alerts as incidents for correlation |
| **Graph Security API** | Programmatic alert access |

## Collect It

```bash
# Recent alerts (via Graph / Sentinel; portal is primary)
az security alert list --query "[].{time:timeGeneratedUtc,sev:reportedSeverity,name:alertDisplayName,resource:compromisedEntity}" -o table
```

> **Console:** Defender for Cloud → **Security alerts** → open the alert → **entities**, **MITRE mapping**, **take action**. Multi-stage related alerts group into an **incident**.

## Working an Alert

| Step | Do this |
|------|---------|
| 1. Triage | Severity + title + affected resource + ATT&CK technique |
| 2. Read the entities | IPs, accounts, processes → your pivots |
| 3. Confirm, don't trust | Verify against the underlying log (Activity Log, sign-ins, flow, guest) |
| 4. Pivot to the workload note | VM / Storage / Key Vault / AKS `for DFIR` |
| 5. Root cause | Check the matching **recommendation** — what misconfig enabled it |
| 6. Scope | Related alerts / same actor across resources |

## Hunt at Scale

**All high-severity alerts in the window (Sentinel):**

```kql
SecurityAlert
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertSeverity in ("High","Medium")
| project TimeGenerated, AlertName, CompromisedEntity, Entities, Tactics
| order by TimeGenerated desc
```

**Resource-Manager anomalies (suspicious control-plane):**

```kql
SecurityAlert
| where AlertName has_any ("Azure Resource Manager operation from suspicious","Tor","MicroBurst","elevated access")
```

## Respond

| Goal | Action |
|------|--------|
| Act on the lead | Follow the workload playbook for the named resource |
| Contain | Isolate the resource / cut the identity per the specific note |
| Fix root cause | Remediate the matching MDC recommendation |
| Tune | Suppress confirmed false positives; enable missing Defender plans |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable the right Defender plans** (Servers, Storage, Key Vault, Containers, ARM) | No detection gaps |
| **Raise Secure Score** — remediate top recommendations | Fewer misconfigs to exploit |
| **Send alerts → Sentinel/XDR** | Correlation + IR workflow |
| **Auto-provision agents** (MDE on servers) | Guest-level detection |
| **Enable Defender for Resource Manager** | Catches control-plane abuse |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| High-severity workload alert (server/storage/KV/container) | Active attack on a resource |
| Resource-Manager op from Tor/anonymizer | Stealthy control-plane abuse |
| Anonymous storage access alert | Public-exposure exploitation |
| Crypto-mining container alert | AKS/container compromise |
| Anomalous Key Vault access | Secret looting |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What MDC is + the plans | **Defender for Cloud → What is** |
| The control-plane it watches | **Azure → Activity Log** |
| The named workload | **Azure → Virtual Machines / Storage / Key Vault / AKS** |
| Network confirmation | **Azure → NSG Flow Logs** |

## Resources

- Manage security alerts — https://learn.microsoft.com/azure/defender-for-cloud/managing-and-responding-alerts
- Alerts reference — https://learn.microsoft.com/azure/defender-for-cloud/alerts-reference
- Integrate with Sentinel — https://learn.microsoft.com/azure/sentinel/connect-defender-for-cloud
