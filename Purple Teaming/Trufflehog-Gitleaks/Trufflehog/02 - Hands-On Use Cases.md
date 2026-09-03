## Scanning Local Git Repository (T1552.004 — Unsecured Credentials)

Operator has compromised a developer's machine or file server. A `.git` directory exists on disk. Scan it for hardcoded credentials in commit history.

```bash
trufflehog git /home/dev/myproject/.git --json
```

Output: JSON report listing all secrets found, grouped by detector type. Example finding:
```json
{
  "DetectorName": "AWS",
  "Verified": true,
  "Secret": "AKIA...[REDACTED]",
  "CommitHash": "abc123def456...",
  "Author": "john.doe",
  "Email": "john.doe@company.com",
  "File": "config/production.env"
}
```

**MITRE ATT&CK:** T1552.004 (Unsecured Credentials — Credentials In Files), T1213 (Data Staged from Information Repositories) if stealing the whole `.git` directory.

## Scanning GitHub Organization (T1526 — Cloud Service Discovery)

Operator has obtained a GitHub organizational PAT (Personal Access Token). Scan all repositories in an organization for leaked credentials.

```bash
export GITHUB_TOKEN="ghp_..."
trufflehog github --org acme-corp --token $GITHUB_TOKEN --only-verified
```

Prerequisites: GITHUB_TOKEN must have `repo:read` + `org:read` permissions.

**MITRE ATT&CK:** T1526 (Cloud Service Discovery), T1087.003 (Account Discovery — Cloud Account), T1530 (Data from Cloud Storage Object).

## Verifying a Single Leaked AWS Key (T1552.004 + T1496 — Credential Access → Data Exfiltration)

Operator discovered `AKIA...` key in a git log. Confirm if it's still valid and what permissions it has.

```bash
trufflehog git https://github.com/acme/repo.git --only-verified --json | jq '.[] | select(.DetectorName == "AWS")'
```

If verified (field `Verified: true`), the AWS key is live. Trufflehog can optionally probe further:
```bash
# Query what S3 buckets the key can access
aws s3 ls --profile scanner-key
```

Trufflehog doesn't automatically enumerate permissions, but the verified AWS key output confirms the credential is usable.

**MITRE ATT&CK:** T1552.004 (Unsecured Credentials), T1527 (Search Cloud Infrastructure) if using the key to enumerate AWS resources, T1530 (Data from Cloud Storage Object) if accessing S3 buckets.

## Scanning GitLab Instance (T1213 — Data from Information Repositories)

Operator has access to a self-hosted GitLab instance. Scan all projects for secrets.

```bash
export GITLAB_TOKEN="glpat-..."
trufflehog gitlab --url https://gitlab.internal.corp --token $GITLAB_TOKEN --json
```

Prerequisites: GitLab token with `api` + `read_repository` scopes.

**MITRE ATT&CK:** T1213 (Data from Information Repositories — Enterprise Repositories), T1530 (Data from Cloud Storage Object).

## Scanning S3 Bucket (T1530 — Data from Cloud Storage Object)

Operator has AWS access (via compromised IAM key or assumed role). Scan an S3 bucket for objects containing credentials (backup files, logs, config files).

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
trufflehog s3 --bucket company-backups --json
```

Trufflehog lists all objects in the bucket and scans their contents. Useful for finding credentials in:
- Database backups (`.sql` files)
- Configuration exports (CloudFormation templates)
- Application logs
- Container image layers

**MITRE ATT&CK:** T1530 (Data from Cloud Storage Object), T1005 (Data from Local System) if downloading found secrets.

## Scanning Slack Workspace (T1213 — Data from Information Repositories)

Operator has obtained a Slack workspace token (stolen from the organization's OAuth app or API token store). Scan message history for leaked credentials.

```bash
export SLACK_TOKEN="xoxb-..."
trufflehog slack --token $SLACK_TOKEN --json
```

Trufflehog searches all channels and direct messages for credential-like patterns. Commonly finds:
- Database passwords (DMs between engineers)
- API keys (accidentally pasted in #incidents channel)
- Private keys (accidentally pasted during troubleshooting)
- AWS access keys in screenshots/messages

**MITRE ATT&CK:** T1213 (Data from Information Repositories), T1552.004 (Unsecured Credentials — Credentials In Chat Systems).

## Filesystem Scan (T1552.001 — Unsecured Credentials in Filesystem)

Operator has shell access to a development machine. Scan `/opt/app` for hardcoded secrets in source files (not just Git history, but all current files).

```bash
trufflehog filesystem /opt/app --json
```

Useful for:
- Application config files (`.env`, `secrets.yml`, etc.)
- Hardcoded strings in source code (not yet committed)
- Temporary files left by developers
- Downloaded tools/scripts containing credentials

**MITRE ATT&CK:** T1552.001 (Unsecured Credentials — Credentials in Files), T1087.002 (Account Discovery — Domain Accounts) if credentials are for Active Directory.

## Credential Stuffing (Found Secret on Multiple Services — T1110.003 — Password Spraying)

Operator finds an email + password combo in git history. Test if it works on other services (GitHub, AWS, GitLab, Slack, etc.).

```bash
# Found: user@company.com / MyPassword123 in old config
trufflehog github --repo company/repo --token (manual test with found password)
# Result: password doesn't work on GitHub anymore (likely changed)

# Try AWS with same credentials
aws sts get-caller-identity --access-key AKIA... --secret-access-key ...
# Result: valid AWS key!
```

Trufflehog doesn't automate credential stuffing, but the JSON output provides credentials to test manually.

**MITRE ATT&CK:** T1110.003 (Credential Access → Valid Accounts), T1078 (Valid Accounts — Account Takeover via credential reuse).

## Post-Compromise Scanning (Multi-Source Aggregation)

Operator gains access to both an internal GitLab instance and AWS S3. Scan both and de-duplicate findings.

```bash
# Scan GitLab
trufflehog gitlab --url https://gitlab.internal --token $GL_TOKEN --json > /tmp/gitlab_findings.json

# Scan S3
trufflehog s3 --bucket internal-backups --json > /tmp/s3_findings.json

# Combine and deduplicate by secret value
jq -s '.[0] + .[1] | group_by(.Secret) | .[] | .[0]' /tmp/gitlab_findings.json /tmp/s3_findings.json > /tmp/unique_secrets.json
```

Useful for understanding the blast radius: "This AWS key appears in 3 commits + 2 backup files + 1 Slack message."

**MITRE ATT&CK:** T1552 (Unsecured Credentials — aggregated across sources).

## CI/CD Integration (Continuous Scanning)

Operator wants to maintain persistence in the organization's CI/CD pipeline. Add Trufflehog as a build step that scans incoming pull requests.

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan
on: [pull_request]
jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: |
          curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
          trufflehog git /home/runner/work --only-verified --fail
```

This allows an operator to (a) detect when new secrets are added, or (b) disable the scan to allow secrets through.

**MITRE ATT&CK:** T1199 (Trusted Relationship — compromising CI/CD trust boundary), T1195.003 (Supply Chain Compromise — compromised build/pipeline).

## Analyzing Commit History Timeline (T1213 — Data from Information Repositories)

Operator found multiple credentials across commits. Reconstruct when each was introduced and who committed them.

```bash
trufflehog git https://github.com/company/repo.git --json | \
  jq -r '.[] | "\(.CommitHash | .[0:8]) [\(.Author)] \(.Email) - \(.DetectorName) (\(.File))"'
```

Output:
```
abc123de [john] john@company.com - AWS (config.py)
def456ab [jane] jane@company.com - Stripe (payment.py)
ghi789cd [admin] admin@company.com - GitHub (deploy.sh)
```

Useful for understanding:
- Who committed the most secrets (potential insider threat)
- When secrets were introduced (correlate with business events)
- Which files are most problematic (focus remediation on those)

**MITRE ATT&CK:** T1123 (Audio Capture) if analyzing audio/metadata, or more broadly T1213 (Data from Information Repositories).
