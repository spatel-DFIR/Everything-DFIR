🔴 **RED FLAG:** Trufflehog scans Git history, S3 buckets, GitHub APIs, Slack workspaces, and more for hardcoded secrets, then **verifies if those secrets actually work** — making it uniquely dangerous in post-compromise scenarios where a single found/validated credential unlocks lateral movement or data access.

## History

**Trufflehog** is an open-source secret-scanning tool maintained by **TruffleHog Security** (backed by commercial entity), developed by multiple contributors with active sponsorship. The project lives at **[github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)** with current version **v3.96.0** (released 2024-07-24).

Originally created as a simple git-history scanner around 2017, Trufflehog evolved into a multi-source credential discovery platform. By v3 (2021+), it added:
- Pluggable detector architecture (200+ built-in detectors for AWS, GitHub, Stripe, Twilio, etc.)
- Credential verification (actually logs in to confirm secrets work)
- Multi-source scanning (S3, GCS, GitHub, GitLab, Slack, Jira, Confluence, filesystem)
- Permissioning analysis (for certain credential types, learns what resources the credential can access)

Licensed under AGPL-3.0 (open source, copyleft).

## Key Mechanics

**Multi-Source Scanner:**
- Scans Git repositories (local `.git` directories or remote HTTPS/SSH URLs)
- Queries cloud-object stores (S3 bucket enumeration, GCS bucket scans)
- Integrates with APIs (GitHub/GitLab/Jira organizational scanning via tokens)
- Sniffs network traffic (Slack workspace inspection via workspace token)
- Filesystem walking (searches all files in a directory tree)
- Stdin input (pipes logs or code samples to scan)

**Detector Pipeline:**
1. **Discovery:** Find credential-like strings via regex or entropy heuristics
2. **Classification:** Identify the type (AWS_KEY, GitHub_PAT, Stripe_API, etc.) via 200+ detectors in `pkg/detectors/`
3. **Verification:** For high-value types (AWS, GitHub, Stripe), actually attempt login/validation
4. **Analysis:** For certain detectors (AWS, GitHub), enumerate permissions and resource access post-verification

**Output:** Structured JSON report with:
- Detector ID / secret type
- Confidence score (unverified, verified, unknown)
- Raw secret string (masked by default, use `--results=verified` to show only verified credentials)
- Source (file, commit, S3 key, Slack message, etc.)
- Verification result (if attempted)

## Techniques/Protocols Used

- **Git protocol** (SSH or HTTPS for repository cloning/scanning)
- **AWS IAM API** (STS, EC2, S3, IAM for credential verification)
- **GitHub API v3/GraphQL** (token validation, org/repo enumeration)
- **GitLab API** (token validation, group/project enumeration)
- **Slack Web API** (workspace token, user enumeration)
- **Jira Cloud REST API** (credential validation, project enumeration)
- **Amazon S3 API** (bucket listing, object inspection)
- **Google Cloud Storage API** (bucket listing, object inspection)
- **HTTP/HTTPS** (generic API testing for custom detectors)

## Command-Line Switches — Quick Reference

### Universal Flags

| Flag | Purpose | Example |
|------|---------|---------|
| `--json` | Output as JSON (default) | `trufflehog git --json` |
| `--results` | Filter results by type (verified, unverified, unknown, filtered_unverified) | `trufflehog git --results=verified` |
| `--fail` | Exit with code 183 if results found | `trufflehog git --fail` |
| `-o, --output` | Output file path | `trufflehog git -o /tmp/findings.json` |
| `--no-color` | Disable colorized output | `trufflehog git --no-color` |
| `--log-level` | Logging verbosity (0-5, or -1 to disable) | `trufflehog git --log-level=2` |

### Source-Specific Subcommands

**Git Repositories:**
```
trufflehog git https://github.com/owner/repo.git
trufflehog git /local/path/.git
trufflehog git --repo https://github.com/owner/repo.git
```

**GitHub (organizational scan):**
```
trufflehog github --repo owner/repo --token $GITHUB_TOKEN
trufflehog github --org myorg --token $GITHUB_TOKEN
```

**GitLab:**
```
trufflehog gitlab --repo owner/repo --token $GITLAB_TOKEN
```

**AWS S3:**
```
trufflehog s3 --bucket mybucket --role-arn arn:aws:iam::account:role/scanner
```

**Google Cloud Storage:**
```
trufflehog gcs --project-id myproject --service-account /path/to/key.json
```

**Slack:**
```
trufflehog slack --token xoxb-... --workspace-name myworkspace
```

**Jira:**
```
trufflehog jira --url https://jira.mycompany.com --token $JIRA_TOKEN
```

**Filesystem:**
```
trufflehog filesystem /path/to/code
```

**Stdin:**
```
cat logfile.txt | trufflehog stdin
```

## Quick Use-Case List

1. Git repository history scan (local or remote)
2. GitHub organizational credential discovery (all repos)
3. GitLab instance-wide scanning
4. AWS S3 bucket enumeration and secret scanning
5. GCS bucket credential discovery
6. Slack workspace message scanning (API keys in chat history)
7. Jira project scanning (secrets in issue descriptions)
8. Confluence wiki scanning (wiki content, page revisions)
9. Post-compromise lateral movement (verify found credentials)
10. Credential rotation verification (scan after rotation to confirm old secrets removed)
11. Pre-deployment scan (CI/CD pipeline integration)
12. Organizational security audit (continuous monitoring)
13. Insider-threat hunting (who committed what secrets when)
14. Multi-source credential de-duplication (aggregate findings across Git + S3 + Slack)

## Prerequisites

**Network/Access:**
- Outbound HTTPS access to GitHub/GitLab/AWS/GCS/Jira/Slack APIs (if scanning those sources)
- Authentication tokens for APIs (GitHub PAT, GitLab token, AWS credentials, Slack token, etc.)
- Git CLI installed (if scanning local `.git` directories)

**For S3/GCS scanning:**
- AWS IAM credentials or role with `s3:ListBucket` + `s3:GetObject` permissions
- Or GCS service account with `storage.buckets.list` + `storage.objects.list` permissions

**For GitHub/GitLab:**
- Organizational PAT (Personal Access Token) with repo read permissions
- Or OAuth token for user-scoped scanning

**For Slack:**
- Workspace admin token or bot token with permission to read message history

**For verification (optional but strongly recommended):**
- AWS credentials (if verifying AWS keys found)
- GitHub token (if verifying GitHub tokens found)
- Stripe API key (if verifying Stripe secrets)
- Database credentials (if verifying database passwords)

**Privilege level:**
- None required on scanning machine (runs as regular user)
- Credentials themselves determine what the attacker can access once verified
