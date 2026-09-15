Artifacts left on the **attacking/operator** host during Trufflehog scanning.

## Process Execution

**Command-line evidence:**
```
trufflehog git /path/to/.git --json --only-verified
trufflehog github --org acme-corp --token $GITHUB_TOKEN --json
trufflehog s3 --bucket mybucket --json
trufflehog filesystem /opt/app --json
```

Trufflehog runs as a single binary (Go static binary, no runtime dependencies). Process tree:
- Parent: bash/cmd/PowerShell (or CI/CD job runner, GitHub Actions, Jenkins, etc.)
- Child: `trufflehog` (single process, stays in memory for duration of scan)

**Sysmon 1 / Process Creation:**
- Image: `/path/to/trufflehog` (renamed binaries common — `scanner`, `sec_tool`, `check-secrets`)
- CommandLine: Contains subcommand (`git`, `github`, `s3`, etc.) and authentication tokens (often plaintext or env var reference)
- ParentImage: Whatever spawned it (bash, Jenkins agent, GitHub Actions runner)

**Key observation:** Trufflehog doesn't hide its own name well. Even if renamed, the process will spawn git/curl/AWS CLI subprocesses for scanning, which reveals the toolset being used.

## Command History & Shell History

**Bash/Zsh history (~/.bash_history, ~/.zsh_history):**
```
trufflehog git /home/user/repo/.git --json
trufflehog github --org myorg --token ghp_REDACTED --only-verified
trufflehog s3 --bucket company-backups
```

History file is NOT automatically cleaned by Trufflehog. Operator must manually clear:
```bash
history -c
cat /dev/null > ~/.bash_history
```

**Evidence value:** High. Full command-line reconstructs the scope of scanning (which repos, which organizations).

## Authentication Tokens

Trufflehog accepts authentication tokens in three ways:

1. **Command-line flag:** `--token ghp_...` (captured in process command-line, shell history, Sysmon logs)
2. **Environment variable:** `export GITHUB_TOKEN="ghp_..."` (stored in process env, visible via `/proc/[pid]/environ` on Linux, `tasklist /v` on Windows)
3. **Credential files:** Git credential helper (`~/.git-credentials`), AWS CLI config (`~/.aws/credentials`), Slack API token store

**Artifacts:**
- Trufflehog reads from standard Git/AWS/cloud credential locations
- If tokens in plaintext config files, they're artifacts of prior setup (not Trufflehog-specific)
- Trufflehog itself doesn't create new credential files

## Network Connections

**Outbound HTTPS traffic to:**
- `api.github.com` (GitHub REST API)
- `api.gitlab.com` or internal GitLab instance
- `slack.com` (Slack Web API endpoints)
- `jira.mycompany.com` (Jira instance)
- S3/GCS service endpoints (if scanning cloud buckets)

**Network evidence:**
- Netstat/ss/Process Monitor: Outbound HTTPS connections to known API endpoints
- Firewall logs: Source IP initiating scanning traffic to multiple APIs
- TLS/SSL certificates: Trufflehog validates HTTPS certs, so no bypass/interception possible
- DNS lookups: `api.github.com`, `api.gitlab.com`, `slack.com`, AWS S3 endpoints

**Example (Linux netstat):**
```bash
netstat -npte | grep trufflehog
tcp    0    0 10.0.0.5:54321    140.82.112.6:443   ESTABLISHED  1234/trufflehog
```

## Git Credential Cache

If scanning multiple Git repositories (especially GitHub), Trufflehog may trigger Git credential helper caching.

**Artifacts:**
- `~/.git-credentials` (if credential.helper = store)
- `~/.config/git/credential/github.json` (if using manager-core)
- `/tmp/git-credentials-*` (temporary storage)
- Git reflog entries (local scanning of `.git/logs/HEAD`)

**Evidence value:** Medium. Shows which repos were accessed and in what order.

## Output Files

**JSON report (default):**
```bash
trufflehog git /path --json > /tmp/findings.json
```

Report contains:
- Detector type (AWS, GitHub, Stripe, etc.)
- Secret values (plaintext or masked)
- Commit hashes / file paths
- Author info (name, email)
- Timestamps
- Verification status

**Artifact locations:**
- Operator-specified output file (`-o /tmp/findings.json`)
- Current directory (if no `-o` flag, often goes to stdout/piped)
- Temporary files if intermediate caching happens

**Evidence value:** Very High. Full report names credentials found and their locations.

## SIEM / EDR Artifacts

**AWS CloudTrail (if scanning AWS):**
- `AssumeRole` events (if using temporary credentials)
- S3 ListBucket / GetObject operations
- IAM DescribeUser / GetUser calls (during verification)

**Slack audit logs (if scanning Slack workspace):**
- API token usage (which endpoints called)
- Message read access patterns
- Admin logs if triggering any warnings

**GitHub audit log:**
- Incoming API requests from the token's IP
- Repo cloning attempts
- GraphQL query patterns

**Azure AD sign-in logs (if scanning Azure resources):**
- Trufflehog using Azure SDK triggers sign-in events

## Memory Artifacts

Trufflehog runs as a single Go process. Memory analysis (`memdump`, Volatility) can extract:
- Command-line arguments (if cached in memory)
- Plaintext authentication tokens
- Secrets found during scanning (before output sanitization)

**Extraction:** yara rule for Go binary static strings, or full process dump + strings analysis.

## Timeline Reconstruction

Attacker gains access → acquires Git/API tokens → runs Trufflehog to scan → outputs findings to file.

**Source timeline:**
1. Shell history shows Trufflehog command
2. Netstat/firewall shows outbound API scanning traffic
3. Output file timestamps show when scan completed
4. Git credential cache timestamps show when credentials were accessed
5. Process logs show Trufflehog execution + subprocesses (git clone, curl, AWS CLI calls)

**Correlation:** Trufflehog execution events + Git/AWS/Slack API events on the target side = complete picture of what was scanned.

## Evasion Signals

**How operator might hide:**
- Redirect output to `/dev/null` or `/tmp/` (which is often cleaned)
- Use `--no-color` flag (minimal artifact difference)
- Unset environment variables after execution
- Clear shell history (`history -c`)
- Use environment variable for token: `export GITHUB_TOKEN="..."` in a subshell, reducing shell-history footprint

**What survives evasion:**
- Trufflehog binary execution (Sysmon 1, process logs)
- Network connections (firewall, netstat, packet capture)
- Filesystem artifacts (output files, git cache)
- Target-side API logs (GitHub, GitLab, Slack audit logs)
