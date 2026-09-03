# What is Microsoft Defender for Cloud?

**Microsoft Defender for Cloud (MDC)** is Azure's **cloud security posture + workload protection** platform — the **GuardDuty + Security Hub equivalent**. It does two jobs: **CSPM** (finds misconfigurations, scores your posture) and **CWPP** (the "**Defender for X**" plans that generate **threat alerts** for servers, storage, Key Vault, SQL, containers, and more).

On a case it's often **where the alert came from** — a pre-triaged finding that points you at the resource and technique.

## Contents

- [How It Works](#how-it-works)
- [CSPM vs CWPP — Posture vs Threats](#cspm-vs-cwpp--posture-vs-threats)
- [The Defender Plans](#the-defender-plans)
- [What an Alert Gives You](#what-an-alert-gives-you)
- [How to Identify MDC in Evidence](#how-to-identify-mdc-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

MDC continuously assesses resources against security **recommendations** (posture) and runs **analytics/behavioral detections** on enabled workloads (threats), surfacing **security alerts** — which flow to the MDC portal, **Defender XDR**, and **Sentinel**.

## CSPM vs CWPP — Posture vs Threats

| | **CSPM** (posture) | **CWPP** (workload protection) |
|-|--------------------|--------------------------------|
| Answers | "What's misconfigured / risky?" | "What's being attacked *now*?" |
| Output | Recommendations + **Secure Score** | **Security alerts** |
| DFIR use | Find the misconfig that let it happen | The detection that started the case |
| Free vs paid | Foundational CSPM free; Defender CSPM paid | Per-resource **Defender plans** (paid) |

## The Defender Plans

Each plan protects one workload; know which are on (it decides what alerts exist):

| Plan | Detects |
|------|---------|
| **Defender for Servers** | VM guest threats (uses MDE) — malware, suspicious processes |
| **Defender for Storage** | Malware uploads, anonymous/anomalous blob access |
| **Defender for Key Vault** | Anomalous secret access |
| **Defender for Containers** | AKS/container threats — crypto pods, exec, K8s API abuse |
| **Defender for Resource Manager** | Suspicious control-plane ops (e.g. from Tor, mass ops) |
| **Defender for SQL / App Service / DNS** | Workload-specific threats |

> 🔴 **Defender for Resource Manager** is especially useful in IR — it flags suspicious **Activity Log** operations (mass role grants, ops from anonymizers) you might otherwise miss.

## What an Alert Gives You

| Field | Use |
|-------|-----|
| **Severity + title** | Triage priority + technique |
| **Affected resource** | Where to look |
| **MITRE ATT&CK mapping** | The tactic/technique |
| **Entities** (IPs, accounts, processes) | Investigation pivots |
| **Remediation steps** | Suggested response |

> Treat an alert as a **lead, not a verdict** — confirm it against the underlying logs (Activity Log, sign-ins, flow logs) before acting. It pre-triages; you verify.

## How to Identify MDC in Evidence

- **Portal:** Defender for Cloud → **Security alerts** / **Recommendations** / **Secure Score**.
- **Defender XDR / Sentinel:** alerts land as incidents (`SecurityAlert` table).
- **Graph Security API:** `security/alerts_v2`.

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Defender for Cloud (CWPP) | GuardDuty | Security Command Center (threats) |
| Defender for Cloud (CSPM) | Security Hub / Config | SCC (posture) |
| Secure Score | Security Hub score | SCC posture score |
| Defender for Servers | GuardDuty + Inspector | SCC + agents |

## Common Use Cases

Your "normal" baseline:

- Posture management + compliance (Secure Score).
- Multicloud/hybrid protection (AWS/GCP connectors too).
- Feeding alerts into Sentinel/XDR for IR.

## Key Terminology

| Term | Meaning |
|------|---------|
| **CSPM** | Cloud Security Posture Management |
| **CWPP** | Cloud Workload Protection Platform |
| **Defender plan** | Per-workload paid protection |
| **Security alert** | A threat detection |
| **Recommendation** | A posture/misconfig finding |
| **Secure Score** | Posture rating |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating an MDC alert | **Defender for Cloud → for DFIR** |
| The control-plane it watches | **Azure → Activity Log** |
| The workload the alert names | **Azure → Virtual Machines / Storage / Key Vault / AKS** |

## Resources

- Defender for Cloud overview — https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction
- Security alerts reference — https://learn.microsoft.com/azure/defender-for-cloud/alerts-reference
- Defender plans — https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction#cloud-workload-protection-platform
