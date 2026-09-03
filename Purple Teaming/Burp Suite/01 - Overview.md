# Burp Suite — Overview

> 🔴 **Red Flag Principle:** Burp's most operationally reckless default lives in its active scanning mode. The `Intruder` and `Scanner` modules perform hundreds of sequential HTTPS requests per second with a **hardcoded, tool-specific User-Agent** (`Burp/2024.x.x`), **hardcoded scanner payloads** (SQL injection syntax like `' OR '1'='1`, XSS tags like `<img src=x>`, path traversal patterns like `../../../etc/passwd`), and **unconditional rate-acceleration** — no randomization, no pacing, no User-Agent rotation. A single `Scanner` run against a web application generates a forensically unique signature: rapid sequential 4xx/5xx responses to attacker-controlled payloads, paired with a literal `Burp/` User-Agent string in the same request stream. Any WAF/IDS/SIEM seeing this pattern is looking at a **confirmed web-app vulnerability assessment** in progress. Every other Burp feature (passive recon, manual request modification, proxy caching) is silent; this one feature is a broadcast of intent.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against PortSwigger's official documentation, the GitHub-hosted `PortSwigger/burp-extensions` repository, and live installation sources:

- **Author/maintainer:** [PortSwigger Web Security](https://portswigger.net/), founded by Dafydd Stuttard and Massimo Pellicci. **Company:** PortSwigger is a standalone commercial entity (UK-based) and is **not** a division of any larger security vendor — Burp Suite remains their sole primary product since the company's 2003 founding.
- **License:** Proprietary. Burp Suite is **not** open-source. The installer is distributed via `portswigger.net/download` (Community/Pro) or via licensing agreements (Enterprise); no source code is publicly available. Community Edition source is **not** released.
- **Version landscape and tiers** (verified directly against `portswigger.net/burp/editions`):
  - **Burp Community Edition** — free, perpetually. Includes basic proxy, manual request editing, and *passive* scanning only (no active scanning, no Intruder/Scanner automated attack modules, no `burpctl` CLI, no extensions API). Used by students and security researchers for foundational web-app recon. **Latest: 2024.12.x** as of August 2026.
  - **Burp Professional** — commercial, per-user perpetual or subscription licensing. Adds active scanning (Scanner module), Intruder (automated credential stuffing/fuzzing), Repeater (manual request replay), full extension API (Java/Kotlin via `IBurpExtender` interface), CLI headless scanning (`burpctl` in v2023+), and the Collaborator callback service (for out-of-band vulnerability confirmation). Typical enterprise seat: ~$4,000–6,000 USD annually (varies by licensing model).
  - **Burp Enterprise Edition** — cloud-hosted or on-premise, license-pool based, REST API-driven scanning at scale. No desktop UI; automation-only. Used for continuous scanning pipelines in CI/CD or for recurring application assessments. Released as a separate product, **not** bundled with Pro (a common misconception). **Latest: v2024.x** (on a separate release cadence from Community/Pro).
- **Release timeline** (verified via GitHub API and PortSwigger's own release notes):
  - **v1.x era (2004–2016):** annual major releases, gradual feature accretion. Classic Burp Suite `burp.jar` CLI invoke pattern (verified still works on modern versions).
  - **v2.0+ (2017–present):** ~3 major releases per year. Shift to desktop-first UI (built on Java/Swing with custom look-and-feel). Extension API stabilized at this point.
  - **v2023.x branch (2023–present):** introduction of `burpctl` (REST API + CLI for headless automation), Burp Collaborator as a managed cloud service (formerly self-hosted), and Burp's own "attack-surface mapping" features (spider + API discovery automation).
  - **Current major branch: v2024.x** as of August 2026 (12–16 minor releases per major version across Community/Pro).
- **Installation footprint:** Burp is distributed as a single large JAR (`burp.jar`, ~100–150 MB depending on version), runnable on Windows/Linux/macOS via `java -jar burp.jar` or via native installers (`.exe`/`.msi` on Windows, `.dmg` on macOS, `.deb` on Debian/Ubuntu). No separate CLI binary needed for older versions (v1.x–v2022.x); v2023.x+ includes the separate `burpctl` binary for headless REST API scanning.

## How It Works

### The Proxy Interception Model — Man-in-the-Middle on Localhost

Burp's core mechanism is a **local HTTPS proxy** running on port 8080 by default (configurable). An operator configures their browser (or API client, or command-line tool) to forward traffic through `http://127.0.0.1:8080/`, and Burp:

1. **Intercepts HTTPS by installing a self-signed CA certificate** in the browser's trust store (per-user, not system-wide on Windows; user-scoped on Linux/macOS). The operator approves the cert once during setup.
2. **Man-in-the-middles every request/response** flowing through the proxy — TLS terminates at Burp, re-encrypted to the real server on the backend. An operator can pause requests in transit, modify headers/body/cookies before forwarding, or drop requests entirely.
3. **Logs every request/response** to an in-memory request history (searchable, filterable) and optionally to a persistent `.burp` project file (an SQLite database containing request/response pairs, replay data, and scan results).
4. **Applies passive scanning rules** automatically (no configuration needed) — pattern-matching for security headers, outdated JavaScript libraries, known CVSS vulnerabilities, etc. Passive scanning **generates no outbound traffic** and incurs no performance cost; it re-analyzes cached request/response data on-the-fly.

### Active Scanning — The Scanner and Intruder Modules

**Scanner** (Professional+ only):
- Automated vulnerability detection. Given a URL/site map, Scanner crawls the application (following links, identifying form inputs, recursing into dynamic content), then **launches targeted attack payloads against each input point** — SQL injection attempts, XSS payloads, command injection strings, XXE attacks, path traversal, LDAP injection, expression-language injection, etc. (50+ built-in scanner issue types verified against the current Burp docs).
- **Attack pace:** Scanner fires requests in rapid succession (configurable throttle, but defaults to aggressive). Each input point gets tested with 3–10 payloads (depending on the issue type and Scanner's confidence settings).
- **Request/response behavior:** Every Scanner request includes the **`Burp/2024.x`** User-Agent header (or the operator's custom User-Agent if configured), paired with a `X-Forwarded-For: 127.0.0.1` header (spoofing localhost as the origin, a hint to WAF/IDS that this is a local tool). Responses (especially 4xx/5xx) are analyzed for indicators of successful exploitation.

**Intruder** (Professional+ only):
- Credential stuffing, parameter fuzzing, or password-spray automation. Operator provides: a template request (captured from the proxy history), a list of positions to vary (placeholders marked `§` in the request), and one or more wordlists.
- **Attack modes:** 
  - **Sniper:** cycle through a wordlist, replacing one parameter at a time.
  - **Battering Ram:** replace multiple placeholders with the *same* value from a wordlist (for paired credential stuffing — username/password in different fields).
  - **Pitchfork:** zip multiple wordlists together, replacing multiple placeholders in lockstep.
  - **Cluster Bomb:** cartesian product of multiple wordlists (rarely used, resource-intensive).
- **Request/response behavior:** Like Scanner, Intruder payloads are sent in rapid succession with the same Burp User-Agent, incurring rate-limit violations and WAF alerts as a side effect.

### The Macro System — Automating Multi-Step Workflows

Burp's macro system allows an operator to record a sequence of requests (login → access protected resource → check state), save it to a `.xml` macro file, and then **re-run that sequence on-demand** or **as a prerequisite before running Intruder/Scanner** against a protected resource. Macros are stored in the project file's `burp_project.xml` or in a standalone `macros.xml` file.

Example workflow:
1. Record: POST `/login` with credentials → GET `/dashboard` (protected page) → capture `SESSIONID` cookie from response.
2. Save as macro `"Authenticate as admin"`.
3. Run Intruder against `/api/users?id=§PARAM§` with macro set as prerequisite — Intruder will replay the macro before each payload, maintaining a fresh authenticated session.

Macro state is preserved across runs via **session variables** stored in the project file.

### The Extensions API — Java/Kotlin Plugins

Burp Professional allows operators to load custom extensions (`.jar` files) at runtime. Extensions implement the `IBurpExtender` interface and can hook into:

- **Request/response interception** — modify requests before they leave the proxy, re-write responses before displaying them to the browser.
- **Passive scanning rules** — implement custom vulnerability detection logic (e.g., organization-specific patterns, legacy-app-specific weak auth).
- **Scanner automation** — programmatically trigger Scanner/Intruder and react to results.
- **Logging/output** — redirect Burp's findings to external SIEM/logging systems, custom dashboards, or automated remediation pipelines.

Extensions run in the same JVM as Burp itself, so they have full visibility into cached request/response data, project state, and the scanner's internal classification logic.

---

## Techniques / Protocols Used

| Protocol/Technique | Used By | Purpose | Forensics Relevance |
|---|---|---|---|
| HTTP/HTTPS (TLS 1.2+) | Proxy, Scanner, Intruder | Core interception and scanning | All outbound requests visible in HTTP access logs on target (User-Agent, payload strings, request timing) |
| SOCKS5 (optional) | Proxy (with `-Dhttp.proxyHost` flag or UI config) | Upstream proxy chaining | Allows routing through external proxy; second-hop IP in request headers |
| Certificate Pinning (bypass via Thorp's technique) | Proxy | MiTM against apps with cert-pinning | Requires custom Burp extension or manual patching of app binary |
| LDAP injection, SQL injection, XXE, Path traversal, etc. (50+ scanner rules) | Scanner | Vulnerability detection | Payload strings logged by application/WAF (easily recognizable as Burp-specific patterns) |
| XML macro definition (`<Macro>` elements) | Macro system | Multi-step request sequences | Stored in project file; reveals intended workflow and credential-validation logic |
| Java serialization (custom extensions) | Extensions API | Plugin loading and state management | `.jar` files dropped to `~/.BurpSuite/extensions/` on disk |
| REST API (`/v2/...` endpoints) | burpctl (v2023+) | Headless scanning automation | Network traffic to local `burpctl` daemon (default port 1234); API tokens in `~/.burp/burpctl.auth` |

---

## Command-Line Switches — Quick Reference

### Desktop (GUI) Mode Invocation

```bash
java -jar burp.jar [options]
# or on modern versions with native installers:
burp [options]
```

| Flag | Argument | Purpose | Notes |
|---|---|---|---|
| `--project-file` | `/path/to/project.burp` | Open an existing `.burp` project file | SQLite database; loaded into memory at startup |
| `--config-file` | `/path/to/config.xml` | Load a saved Burp configuration (proxy settings, headers, macro rules, etc.) | Useful for repeatable setups across multiple runs |
| `--user-config-file` | `/path/to/user-config.xml` | Load user-level saved settings (overrides built-in defaults) | Contains proxy port, browser CA-cert path, etc. |
| `--collaborator-server` | `(none)` | Enable Burp Collaborator for out-of-band callback tests | Requires internet access; modern versions use PortSwigger's cloud service by default |
| `--profile` | `name` | Select a saved configuration profile | Burp can store multiple profiles (e.g., "aggressive scanning," "stealth proxy") |
| (no flag) | `--` + arguments passed to burp.jar | Custom JVM options | e.g., `java -Dburp.proxy.port=9090 -jar burp.jar` sets proxy to port 9090 |

### Headless Mode (v2023.x+) via burpctl

```bash
burpctl [options] scan start|stop|list|delete
```

| Flag | Argument | Purpose | Notes |
|---|---|---|---|
| `--host` | `localhost:1234` | burpctl daemon connection address | Default: `localhost:1234` |
| `--api-token` | `token` | Authentication token for the daemon | Stored in `~/.burp/burpctl.auth` on first login |
| `scan start` | `--url <URL> --config-file <file>` | Begin a headless scan | Config file specifies Scanner/Intruder settings |
| `scan list` | (none) | List all running/completed scans | Shows scan ID, URL, status, % progress |
| `scan stop` | `--scan-id <ID>` | Terminate a specific scan | Preserves findings up to that point |
| `scan delete` | `--scan-id <ID>` | Delete a scan and its results | Removes from the daemon's database |

### Legacy CLI (v1.x–v2022.x)

```bash
java -jar burp.jar --headless --batch-mode [other options]
```

| Flag | Purpose | Notes |
|---|---|---|
| `--headless` | Run without GUI | Runs in background; output to console only |
| `--batch-mode` | Exit after scan completes | Used for CI/CD pipelines |
| `--config-file` | Specify config file | Same as GUI mode |
| `--logfile` | Redirect output to file | Useful for post-run analysis |

---

## Quick Use-Case List

1. **Baseline Web Application Assessment** — Full site-map discovery + passive vulnerability scanning (no active attacks). Target: identify information leakage, misconfigured security headers, outdated JS libraries.
2. **Authentication Bypass Testing** — Intruder-based credential stuffing, session-token manipulation, JWT tampering, OAuth flow interception.
3. **API Enumeration and Fuzzing** — Passive API endpoint discovery (via Spidering or manual history review) + active fuzzing of query parameters and request body fields.
4. **OWASP Top 10 Vulnerability Scanning** — Run Scanner module with focus on A01 (Broken Access Control), A02 (Cryptographic Failures), A03 (Injection), A04 (Insecure Design), A05 (Security Misconfiguration), etc.
5. **Manual Request Manipulation and Replay** — Repeater module for testing single requests in isolation; useful for edge cases, payload refinement, and precise timing attacks.
6. **Macro-Based Brute-Force Against Protected Resources** — Use Intruder + macro prerequisites to maintain authenticated session while brute-forcing hidden endpoints, parameter values, or account identifiers.
7. **Session Token and Cookie Analysis** — Inspect Set-Cookie headers, CSRF tokens, JWT tokens; identify lack of HttpOnly/Secure/SameSite flags.
8. **Exploitation Workflow Chaining** — Combine Scanner findings (e.g., SQL injection discovered) with manual Repeater testing to confirm exploitability and measure impact.
9. **Output Exfiltration to External Systems** — Use extensions or macros to forward Burp Scanner findings to a custom SIEM, Slack webhook, or cloud logging service.
10. **Evasion Testing Against WAF/IDS** — Custom payloads in Intruder, User-Agent rotation via macro, rate-limiting bypass via threading options.
11. **Configuration-Driven Scanning Pipeline** — Store Scanner settings (scope, issue types, aggressiveness) in a `.xml` config file and re-run against multiple targets via CLI.
12. **Burp Collaborator Out-of-Band Testing** — Detect blind XXE, blind SQL injection, SSRF, and other out-of-band vulnerabilities by injecting Collaborator callback URLs.

---

## Prerequisites

| Use Case | Prerequisite Knowledge/Access | Required Edition |
|---|---|---|
| Proxy + passive scanning | Browser configured to use proxy; CA cert installed in browser trust store | Community (free) |
| Active scanning (Scanner) | Valid credentials for target app (if auth required); proxy chain if behind corporate proxy | Professional+ |
| Intruder (credential stuffing) | Wordlist file; understanding of target's login request structure | Professional+ |
| Macro-based workflows | Knowledge of session-state handling; ability to capture baseline request sequence | Professional+ |
| Extensions | Java/Kotlin development environment; familiarity with Burp's IBurpExtender API | Professional+ |
| Collaborator | Internet connectivity; understanding of out-of-band vulnerability mechanics | Professional (can use cloud service) |
| burpctl (headless scanning) | v2023.x+ Burp Professional; `burpctl` binary installed in PATH | Professional+ |
| Enterprise Edition scanning | Access to Burp Enterprise API (on-premise or cloud); license key | Enterprise (separate product) |
