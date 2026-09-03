# What is ELB?

**Elastic Load Balancing (ELB)** spreads incoming traffic across your backends. Most web apps sit behind one, which makes it the **front door** of an attack — and its **access logs** are some of the best web-request evidence you'll get in AWS.

The type you'll meet most is the **Application Load Balancer (ALB)** — HTTP/HTTPS aware, so it logs URLs, status codes, and client IPs.

## Contents

- [How It Works](#how-it-works)
- [The Three Load Balancer Types](#the-three-load-balancer-types)
- [Access Logs — The Web Evidence](#access-logs--the-web-evidence)
- [How to Identify ELB in Evidence](#how-to-identify-elb-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Client → ELB (public entry, TLS termination) → Target group (EC2 / IP / Lambda / containers)
      ALB (L7, HTTP-aware) logs each request to S3 if access logs are on
```

- **Regional**, spanning AZs; the public entry point for a service.
- **ALB** understands HTTP → rich per-request logging + routing rules + WAF integration.
- Terminates TLS, so the backend sees the ALB; the **client IP is in the log / `X-Forwarded-For`**.

## The Three Load Balancer Types

| Type | Layer | Logs contain | DFIR value |
|------|-------|--------------|------------|
| **Application (ALB)** | L7 (HTTP) | URL, method, status, client IP, user-agent | 🎯 High — web-attack evidence |
| **Network (NLB)** | L4 (TCP/UDP) | Connection-level (flow) logs | Lower — no HTTP detail |
| **Gateway (GWLB)** | L3 | Appliance traffic | Niche (inline security appliances) |
| **Classic (CLB)** | L4/L7 (legacy) | Basic HTTP/TCP | Legacy; being retired |

## Access Logs — The Web Evidence

🔴 **ALB access logs are off by default** — but when on, they're gold for web incidents:

Each line includes: `time`, `client:port`, `target`, `request` (method + URL + protocol), `elb_status_code`, `target_status_code`, `user_agent`, `ssl_cipher`, and more.

What they let you do:

- Find the **attacker's requests** — the exact URLs hit (SQLi, path traversal, `/169.254.169.254` SSRF attempts, webshell access).
- Get the **real client IP** and user-agent even though the backend only saw the ALB.
- See **status codes** — a wall of 404s (scanning), a 200 on a suspicious path (successful exploit).

> 🔴 If you're investigating a web-app compromise (RCE, SSRF, webshell), **ALB access logs are often the clearest record of the attack request** — pair them with the backend's own logs. Turn them on before you need them; you can't recreate them.

## How to Identify ELB in Evidence

- **`eventSource`:** `elasticloadbalancing.amazonaws.com`.
- **ARNs:** `arn:aws:elasticloadbalancing:<region>:<acct>:loadbalancer/app/<name>/<id>`.
- **Access logs in S3:** `AWSLogs/<acct>/elasticloadbalancing/<region>/YYYY/MM/DD/…`.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateLoadBalancer` / `DeleteLoadBalancer` | Add/remove an LB | Config change |
| `CreateTargetGroup` / `RegisterTargets` | Point the LB at backends | 🔴 registering an attacker backend |
| `ModifyListener` / `CreateRule` | Change routing/TLS | 🔴 redirect / TLS downgrade |
| `SetWebAcl` (WAF) | Attach/detach WAF | 🔴 removing WAF protection |
| `ModifyLoadBalancerAttributes` | Change attributes incl. access logs | 🔴 disabling access logs |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| ALB | Application Gateway | HTTP(S) Load Balancer |
| NLB | Load Balancer (L4) | Network Load Balancer |
| Access logs | App Gateway access logs | Cloud LB logging |
| WAF integration | Azure WAF | Cloud Armor |

## Common Use Cases

Your "normal":

- **Fronting web apps / APIs** with TLS + health checks.
- **Path/host routing** to microservices.
- **WAF attachment** for L7 protection.

## Key Terminology

| Term | Meaning |
|------|---------|
| **ALB / NLB / GWLB / CLB** | Load balancer types |
| **Listener** | The port/protocol the LB accepts on |
| **Target group** | The backend pool |
| **Access logs** | Per-request S3 logs (ALB) |
| **X-Forwarded-For** | Header carrying the real client IP |
| **WAF / Web ACL** | L7 filtering in front of the app |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating web attacks via ELB | **ELB → ELB for DFIR** |
| The backend instances | **AWS → Compute → EC2** |
| The network/SG exposure | **AWS → Networking → VPC** |
| IMDS SSRF (seen in ALB logs) | **AWS → Playbooks → IMDS SSRF to Role Theft** |

## Resources

- What is ELB — https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/what-is-load-balancing.html
- ALB access logs — https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
- Access log entry format — https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-log-entry-format
