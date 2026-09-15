# EyeWitness: Overview

## Description

EyeWitness is an open-source web application reconnaissance tool that takes screenshots of web applications and performs passive fingerprinting. Developed by Chris Truncer, it automates the process of enumerating web services across networks and generating visual reports of discovered applications, versions, and technologies in use.

## Key Capabilities

- **Web Screenshots:** Captures full-page screenshots of HTTP/HTTPS applications via headless browser automation
- **Passive Fingerprinting:** Identifies web technologies, server versions, and frameworks from HTTP responses and page content
- **Parallel Processing:** Processes multiple URLs concurrently, enabling rapid reconnaissance of large networks
- **Report Generation:** Produces interactive HTML reports with searchable screenshots, metadata, and categorized services
- **Credential Testing:** Optional integration for testing default/weak credentials against discovered services
- **Multiple Input Formats:** Accepts IP ranges (CIDR notation), port lists, URL files, and nmap XML output

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Tactic | Relevance |
|-----------|---------------|--------|-----------|
| **T1592** | Web Screenshots (004) | Reconnaissance | Primary use—captures visual application state for targeting intelligence |
| **T1046** | Network Service Enumeration | Reconnaissance | Fingerprints web services, ports, and versions across ranges |
| **T1592.003** | Server Software and Version Detection | Reconnaissance | Passive identification of backend technologies |
| **T1518.001** | Software Enumeration | Discovery | Maps installed applications and web frameworks post-compromise |

## Threat Actor Use

- **Initial Reconnaissance:** Purple teamers and adversaries enumerate web-facing assets before targeted compromise attempts
- **Vulnerability Correlation:** Screenshots and version data feed into vulnerability databases to identify exploitable targets
- **Social Engineering:** Application screenshots reveal branding, technology stacks, and UI elements for phishing campaigns
- **Network Mapping:** Identifies organizational internet presence, redundancy patterns, and geographic application distribution
- **Post-Compromise Staging:** Internal lateral reconnaissance to catalog intranet applications and administrative interfaces

## Common Variants & Related Tools

- **Aquatone:** Similar screenshot-based reconnaissance; focuses on subdomain enumeration and clustering
- **Shodan Integration:** EyeWitness can process Shodan queries for targeted reconnaissance
- **Manual cURL/wget:** Basic alternative requiring manual inspection; less scalable
- **Burp Suite Pro:** Commercial alternative with integrated reconnaissance; more feature-rich but slower

## Operational Context

EyeWitness is a legitimate penetration testing tool freely available on GitHub. It appears in authorized red team assessments, CTF scenarios, and security research. Detection requires behavioral analysis; the tool itself is not malicious, but reconnaissance activity using it may violate rules of engagement if uncontrolled.
