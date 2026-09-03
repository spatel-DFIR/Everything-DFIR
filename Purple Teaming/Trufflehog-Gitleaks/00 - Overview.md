# Secret Scanning: Trufflehog and Gitleaks

Two complementary approaches to detecting hardcoded credentials and secrets in source code repositories, Git history, and local filesystems. This overview covers their shared purpose (credential discovery in accessed repositories), their defining technical differences (scope, detection methods, validation), and when to choose each.

## Shared Purpose

Both tools solve the same offensive problem: **finding leaked credentials in source code after gaining access to repositories or filesystems.**

**Scenario:** Attacker compromises a developer's machine, gains access to internal Git repos (via GitHub Enterprise, GitLab, Gitea), or finds a backup of source code. Rather than manually searching 100+ commits for hardcoded API keys, database passwords, or private encryption keys, these tools automatically scan repositories and flag suspicious credential-like strings for follow-up.

Both leverage the insight that developers often commit secrets by mistake, and those secrets survive in Git history even after deletion from the latest version. The strongest signals come from verified, working credentials that can be tested for authenticity.

## Quick Decision Matrix

| Use Case | Trufflehog | Gitleaks |
|----------|-----------|----------|
| **Git history scanning** | ✅ Yes | ✅ Yes (primary) |
| **AWS/Azure/GCP credential validation** | ✅ Yes (analyzes permissions) | ❌ No (detection only) |
| **Multi-source scanning (S3, Slack, GitHub, etc.)** | ✅ Yes (primary strength) | ❌ No (git-history focused) |
| **800+ secret types** | ✅ Yes | ✅ ~100 rules (rule-driven) |
| **Entropy-based detection** | ✅ Yes + regex | ✅ Regex + entropy option |
| **Live secret validation** | ✅ Yes (tests credentials) | ❌ No |
| **Custom TOML rule configuration** | ⚠️ Basic | ✅ Full (TOML-native) |
| **Local filesystem scan** | ✅ Yes | ✅ Yes (via `dir` command) |
| **Maintenance status** | ✅ Actively maintained (v3.96.0, July 2024) | ⚠️ Feature-complete, maintenance only (v8.30.1, March 2026) |

## Choose Trufflehog if:
- Multi-source credential discovery needed (Git + S3 + GitHub + Slack + Jira)
- Live credential validation/verification important
- Need to understand leaked credential scope (permissions, resource access)
- Post-compromise lateral-movement phase (found creds → test them immediately)
- Actively developed tool preferred
- 800+ secret-type classification needed

## Choose Gitleaks if:
- Git history is the primary/only target
- Custom rule configuration (TOML) and filtering needed
- Compliance/pre-commit-hook deployment (CI/CD native)
- Simpler, lightweight tool preferred
- Baseline/ignore-list management important
- Feature-complete tool preferred (no active feature development)

## Common Workflow

```
Post-Compromise Repo Access
          ↓
    Run Trufflehog (multi-source)
    or Gitleaks (git history)
          ↓
   [Credential found]
          ↓
   Trufflehog: Validate & analyze (permissions, scope)
   Gitleaks: Manual test (credentials in output)
          ↓
   Use credentials for:
   - Lateral movement
   - Privilege escalation
   - Data exfiltration
   - Credential stuffing (other services)
```

## Architectural Differences

### Trufflehog
- **Multi-tenant credential finder:** Pluggable detector architecture (200+ detectors in `pkg/detectors/`)
- **Classification-first:** Identifies credential type (AWS_KEY, GitHub_Token, Stripe_API, etc.) before validation
- **Verification step:** For high-value credential types, actually logs in to confirm the secret is live/working
- **Scope:** Git repos, S3 buckets, GitHub/GitLab APIs, Slack workspace, Jira, Confluence, filesystem, stdin
- **Output:** Structured JSON with detector ID, credential type, confidence, verification status

### Gitleaks
- **Git-history specialist:** Built around git CLI and Go's `git` library
- **Rule-driven:** Each rule is a TOML stanza defining a pattern (regex), description, keywords, and entropy threshold
- **Detection-only:** Flags suspicious strings; does not test if they work
- **Scope:** Git repositories (local or remote), directories, files, stdin
- **Configuration:** `.gitleaks.toml` config file per repo; pre-built rules shipped with binary; easy custom rules
- **Output:** JSON report with findings, line number, commit hash, author, email, fingerprint

## Evidence Profile Comparison

| Artifact | Trufflehog | Gitleaks |
|----------|-----------|----------|
| **Process execution** | `trufflehog` CLI | `gitleaks` CLI |
| **Command-line arguments** | Source-specific (github --org, s3 --bucket, slack --workspace) | Repository path, output format, rule config |
| **Network activity** | Git protocol, S3 API, GitHub/GitLab API, Slack API, Jira API | Git protocol only (unless scanning GitHub/GitLab APIs separately) |
| **Output files** | JSON (by default) | JSON, CSV, or sarif (security-audit-report-format) |
| **Scan speed** | Slower (validation step adds latency) | Faster (regex-only, no network requests) |
| **Source host artifacts** | Git credential cache, AWS CLI config, GitHub token store | Git config, `.gitleaks.toml` baseline files |

## Cross-Links

- **Credential exfiltration & usage:** See `Hashcat/` (cracking found hashes), `Impacket/` (using stolen credentials for lateral movement), `LaZagne/` (harvesting other local credentials)
- **Repository access methods:** See `Chisel-Ligolo-ng-proxychains/` (pivoting to internal Git servers), `AnyDesk/` (RMM access to development machines), `evil-winrm/` (remote access to Windows machines with Git repos)
- **Post-compromise hunting signals:** See `Windows/12 - Lateral Movement.md`, `Linux/06 - Logs/Authentication and Login Records.md`, `Cloud/AWS/GuardDuty.md` (for credential usage after discovery)

## Documentation Structure

- **[Trufflehog/](Trufflehog/)** — Multi-source secret scanner, verification-capable, 800+ detectors
- **[Gitleaks/](Gitleaks/)** — Git-history secret scanner, rule-driven, TOML configuration

Each sub-folder contains the full 5-file template: Overview, Hands-On Use Cases, Source Evidence, Target Evidence, Detection & Hunting.
