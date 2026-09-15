## Scanning Local Git Repository (T1552.004 — Unsecured Credentials)

Operator has gained shell access to a developer machine. A `.git` directory exists. Scan it quickly for hardcoded credentials.

```bash
gitleaks git /home/dev/myproject/.git --json --report-path /tmp/findings.json
```

Output: JSON file with all findings. Example:
```json
{
  "Description": "AWS Manager ID",
  "StartLine": 42,
  "EndLine": 42,
  "Match": "aws_access_key_id = AKIA...[REDACTED]",
  "Secret": "AKIA...[REDACTED]",
  "File": "config/aws.cfg",
  "Commit": "abc123def456...",
  "Entropy": 4.2
}
```

**Key advantage:** Gitleaks is faster than Trufflehog for pure git-history scanning because it doesn't attempt credential verification. Scan a 10K-commit repo in seconds.

**MITRE ATT&CK:** T1552.004 (Unsecured Credentials — Credentials In Files), T1213 (Data Staged from Information Repositories).

## Scanning Remote GitHub Repository (T1526 — Cloud Service Discovery)

Operator has network access. Clone and scan a public or private GitHub repository.

```bash
gitleaks git https://github.com/acme-corp/private-repo.git --json
```

Gitleaks clones the repo (using default credentials if available), scans all commits, and outputs findings.

**Privacy note:** If the repo requires authentication, pass credentials via Git:
```bash
git config --global credential.helper "store --file=/tmp/git-cred"
echo "https://token:ghp_xxxxx@github.com" > /tmp/git-cred
gitleaks git https://github.com/acme-corp/private-repo.git --json
```

**MITRE ATT&CK:** T1526 (Cloud Service Discovery), T1530 (Data from Cloud Storage Object).

## Scanning Directory (Non-Git Files) (T1552.001 — Credentials in Filesystem)

Operator has shell access but the directory isn't a Git repository. Scan all files for credential patterns.

```bash
gitleaks dir /opt/app --json --report-path /tmp/all_secrets.json
```

Scans all files in `/opt/app` recursively, even without a `.git` directory. Useful for:
- Application config directories
- Backup archives (if extracted)
- Docker layer dumps
- Uploaded codebases (no git history, just source files)

**MITRE ATT&CK:** T1552.001 (Unsecured Credentials — Credentials in Files).

## Custom Rule Configuration (Compliance, Target-Specific Secrets)

Create a custom `.gitleaks.toml` to detect organization-specific secrets (internal API keys, vendor tokens, custom password patterns).

```toml
# .gitleaks.toml
[rules.internal_api_key]
description = "Internal company API key (starts with 'INTERNAL-')"
regex = '''INTERNAL-[A-Z0-9]{32}'''
entropy = 4.0

[rules.customer_database_pass]
description = "MySQL password pattern used by company"
regex = '''mysql_password\s*=\s*['\"]?[a-zA-Z0-9!@#$%]{12,}['\"]?'''
entropy = 3.5
```

```bash
gitleaks git /path/to/repo --config /path/to/.gitleaks.toml --json
```

Gitleaks applies both built-in rules AND custom rules. Useful for post-compromise scanning of infrastructure-specific credentials.

**Advantage:** Gitleaks is far more configurable than Trufflehog for custom rules — you own the full TOML syntax.

## Baseline/Ignore List (Tolerate Known Findings)

Operator found a credential in history but decides it's acceptable (rotated key, approved test credential). Create a baseline to ignore it.

```bash
# First run generates findings
gitleaks git /path/to/repo --json --report-path /tmp/initial_findings.json

# Manually review, keep findings to ignore
cat > /tmp/baseline.json << 'EOF'
[
  {
    "Secret": "AKIA1234567890123456",
    "File": "tests/fixtures/aws_key_test.py",
    "Commit": "abc123...",
    "Match": "AKIA1234567890123456"
  }
]
EOF

# Re-run with baseline
gitleaks git /path/to/repo --baseline /tmp/baseline.json --json --report-path /tmp/findings_filtered.json
```

Result: Findings in baseline are suppressed. Only NEW findings appear in output.

**Use case:** Compliance scanning where you need a clean report but legacy code has some acceptable test credentials.

## CI/CD Pre-Commit Integration (T1199 — Trusted Relationship)

Operator adds Gitleaks to development workflow to prevent new credentials being committed. (Or, if compromised, to disable/bypass this check.)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
```

```bash
pre-commit install
```

Now, on every `git commit`, Gitleaks scans staged changes for secrets. Commit fails if secrets found.

**Attacker angle:** Compromise the CI/CD system to disable this check, or use `SKIP=gitleaks git commit` to bypass locally.

**MITRE ATT&CK:** T1199 (Trusted Relationship — compromise CI/CD trust), T1195.003 (Supply Chain Compromise — pipeline).

## GitHub Actions Integration (Continuous Scanning)

Operator maintains repo access. Add Gitleaks to Actions for automated scanning on every push.

```yaml
# .github/workflows/gitleaks.yml
name: Gitleaks Scan
on: [push, pull_request]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

This automatically scans every push for secrets. Can be used by attacker to detect when new secrets are committed, or to gather audit logs showing scanning activity.

## Scanning with Entropy Threshold (No Regex Limit)

Find high-entropy strings (likely random tokens) even if no regex matches.

```bash
gitleaks git /path/to/repo --enable-regexp '[A-Za-z0-9+/]{40,}' --json
```

This regex matches any 40+ character alphanumeric string. Combined with entropy threshold, finds:
- Base64-encoded keys
- Random tokens
- Encryption keys
- Session tokens

**Use case:** Blind scanning of unknown codebase to find any secrets without predefined patterns.

## Scanning with Date Range (Incident Response Timeline)

Operator suspects credentials were leaked on specific dates. Scan only commits within that window.

```bash
gitleaks git /path/to/repo --since 2026-08-01 --until 2026-08-11 --json
```

This scans commits made between Aug 1-11, 2026. Useful for:
- Isolating credentials to specific development period
- Correlating with known breach dates
- Identifying which developer introduced the secret

**MITRE ATT&CK:** T1213 (Data from Information Repositories — timeline correlation).

## Scanning via Stdin (Logs, Exports, Pipes)

Operator has an exported configuration file, log dump, or environment dump. Scan it directly.

```bash
cat /var/log/app.log | gitleaks stdin --json

# Or environment dump
env | gitleaks stdin --json

# Or Docker layer export
docker export container_id | tar x | gitleaks dir / --json
```

No Git context needed. Gitleaks applies all rules to piped content.

## Multi-Repo Audit (Organizational Scanning)

Operator has access to a file server with multiple project directories. Audit all for secrets.

```bash
for dir in /mnt/projects/*/; do
  echo "Scanning $dir"
  gitleaks git "$dir/.git" --json --report-path "/tmp/$(basename $dir)_findings.json"
done

# Aggregate results
jq -s 'add' /tmp/*_findings.json > /tmp/all_findings.json
```

Scan 100+ repos sequentially, aggregate findings into one report.

## Artifact Recovery (Scan Docker Layers/Archives)

Operator extracted a Docker image or tar archive. Scan the extracted files for secrets.

```bash
# Docker layer extraction
docker export container_id > /tmp/image.tar
mkdir /tmp/extracted
cd /tmp/extracted
tar xf /tmp/image.tar

# Scan extracted filesystem
gitleaks dir /tmp/extracted --json
```

Gitleaks scans all files in extracted layer, finds any hardcoded credentials in config files, source code, or installed tools.

**MITRE ATT&CK:** T1552 (Unsecured Credentials), T1005 (Data from Local System).
