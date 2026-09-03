# What is Cloud Load Balancing?

**Cloud Load Balancing** fronts your services with global/regional load balancers, distributing traffic to backends (VMs, GKE, serverless). Paired with **Cloud Armor** (GCP's WAF/DDoS), it's where you see **web attacks, DDoS, and the request logs** that reconstruct an app-layer intrusion.

## Contents

- [How It Works](#how-it-works)
- [Cloud Armor — The WAF](#cloud-armor--the-waf)
- [The Request Logs](#the-request-logs)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- A load balancer has a **frontend** (IP/port/protocol), a **backend service**, and **backends** (instance groups / NEGs).
- **HTTP(S) LBs** log each request; **Cloud Armor** security policies filter traffic before it reaches backends.

## Cloud Armor — The WAF

| Feature | What it does |
|---------|--------------|
| **Security policies** | Allow/deny by IP, geo, or expression |
| **Preconfigured WAF rules** | OWASP (SQLi, XSS, LFI/RFI, etc.) |
| **Rate limiting / DDoS** | Throttle or block floods |
| **Adaptive Protection** | ML-based L7 DDoS detection |

🔴 Cloud Armor **allowed/denied** decisions are logged — the evidence of a web attack (blocked SQLi bursts) or a bypass (allowed malicious request).

## The Request Logs

HTTP(S) LB logs each request: client IP, method, URL, status, user-agent, backend, latency, and the Cloud Armor verdict. This is your **web-attack forensics** trail — recon scans, exploit attempts, and the request that hit a vulnerable backend (leading to RCE / metadata SSRF).

## How to Identify It in Evidence

- **LB request logs:** Cloud Logging, `resource.type="http_load_balancer"`.
- **Cloud Armor logs:** the `enforcedSecurityPolicy` field in request logs (name + outcome).
- **Config events:** `compute.backendServices.*`, `compute.securityPolicies.*` in Admin Activity.

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Cloud Load Balancing | ELB/ALB | Azure Load Balancer / App Gateway |
| Cloud Armor | AWS WAF / Shield | Azure WAF / DDoS Protection |
| LB request logs | ALB access logs | App Gateway / Front Door logs |
| Backend service/NEG | Target group | Backend pool |

## Common Use Cases

Your "normal": fronting web apps/APIs, TLS termination, global anycast, DDoS protection. On a case, LB + Armor logs reconstruct **web attacks** and tell you whether a malicious request reached a backend.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Backend service / NEG** | Where traffic is sent |
| **Cloud Armor policy** | WAF/DDoS ruleset |
| **Preconfigured WAF rule** | OWASP rule set |
| **Adaptive Protection** | ML L7 DDoS detection |
| **enforcedSecurityPolicy** | The Armor verdict in a log |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating web attacks | **Cloud Load Balancing → for DFIR** |
| The backend VM that was hit | **GCP → Compute Engine** |
| Metadata SSRF from a web RCE | **GCP → Playbooks → Metadata SSRF to SA Token Theft** |
| Network flows | **GCP → VPC Flow Logs** |

## Resources

- Cloud Load Balancing — https://cloud.google.com/load-balancing/docs
- Cloud Armor — https://cloud.google.com/armor/docs/cloud-armor-overview
- LB logging — https://cloud.google.com/load-balancing/docs/https/https-logging-monitoring
