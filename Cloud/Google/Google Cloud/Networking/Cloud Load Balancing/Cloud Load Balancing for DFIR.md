# Cloud Load Balancing for DFIR

LB/Armor cases are web-attack cases: **what requests hit the app, which were malicious, were they blocked, and did one reach a vulnerable backend?**

New to it? Read **What is Cloud Load Balancing** first.

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
| **LB request logs** | Per-request client IP/URL/status/UA + Armor verdict | Web-attack trail |
| **Cloud Armor logs** | Allowed/denied by policy | WAF outcomes |
| **Admin Activity** | Policy/backend changes | Config tamper |

## Collect It

```bash
# Requests to a backend in the window
gcloud logging read \
 'resource.type="http_load_balancer" AND httpRequest.requestUrl:"<path>"' --freshness=7d --format=json

# Cloud Armor denies (or allows of attack signatures)
gcloud logging read \
 'resource.type="http_load_balancer" AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"' --freshness=7d
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Scope the attacker IPs | Group requests by client IP / UA; find scanners |
| 2. Classify requests | Recon (404 sweeps), exploit attempts (SQLi/XSS/traversal), success (200 on odd paths) |
| 3. Armor verdicts | Was the malicious request **allowed** or **denied**? |
| 4. Find the hit backend | Which backend served an allowed exploit request |
| 5. Pivot to the backend | RCE → metadata SSRF? (→ Compute Engine) |

## Hunt at Scale

**Top attacker IPs by denied requests:**

```sql
SELECT httpRequest.remoteIp AS ip, COUNT(*) denies
FROM `contoso.lb.requests`
WHERE jsonPayload.enforcedSecurityPolicy.outcome = 'DENY'
GROUP BY ip ORDER BY denies DESC LIMIT 50;
```

**Allowed requests to sensitive paths:**

```sql
SELECT timestamp, httpRequest.remoteIp, httpRequest.requestUrl, httpRequest.status
FROM `contoso.lb.requests`
WHERE httpRequest.requestUrl LIKE '%/admin%' OR httpRequest.requestUrl LIKE '%..%'
ORDER BY timestamp DESC;
```

> **At the very end — SecOps UDM (optional):** land LB/Armor logs to correlate attacker IPs across services. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Block the attacker | Cloud Armor deny rule (IP/geo); rate-limit |
| Virtual-patch | Enable/adjust preconfigured WAF rules |
| Contain a hit backend | Isolate the VM/GKE backend (→ Compute/GKE) |
| Preserve | Export LB/Armor logs for the window |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Cloud Armor with OWASP rules** in front of web apps | Blocks common exploits |
| **Rate limiting + Adaptive Protection** | DDoS resilience |
| **Enable LB request logging** (sample 100% for sensitive apps) | The forensic trail exists |
| **No direct backend exposure** (only via LB) | Removes the bypass |
| **Alert** on Armor deny spikes + allowed exploit signatures | Early web-attack detection |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Burst of denied SQLi/XSS/traversal from one IP | Active web attack |
| An exploit request **allowed** (200) to a backend | Possible compromise |
| Requests to `/admin`, `..`, metadata paths | Recon / SSRF attempt |
| Backend/policy changed by an unexpected principal | Tamper / bypass |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| LB + Armor fundamentals | **Cloud Load Balancing → What is** |
| The backend that was hit | **GCP → Compute Engine** · **GKE** |
| Web RCE → token theft | **GCP → Playbooks → Metadata SSRF to SA Token Theft** |
| Network flows | **GCP → VPC Flow Logs** |

## Resources

- LB logging — https://cloud.google.com/load-balancing/docs/https/https-logging-monitoring
- Cloud Armor — https://cloud.google.com/armor/docs/cloud-armor-overview
- MITRE ATT&CK: T1190 Exploit Public-Facing Application — https://attack.mitre.org/techniques/T1190/
