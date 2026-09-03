## Hunting on Source (Attacker's Host)

### Process Execution Hunt

**Linux/macOS (bash):**
```bash
# Hunt for trufflehog process or renamed binary
ps aux | grep -i trufflehog
ps aux | grep -E '(git|github|s3|gitlab|slack|jira)' | grep -v grep

# Search for common trufflehog output patterns
find /tmp -name "*.json" -type f -exec grep -l "DetectorName\|Verified\|CommitHash" {} \;
```

**Windows (PowerShell):**
```powershell
# Hunt for trufflehog process (including renamed)
Get-Process | Where-Object {$_.CommandLine -match 'git|github|s3|gitlab|slack'} | Select-Object Name, CommandLine

# Check for JSON output files with credential-finding patterns
Get-ChildItem -Path C:\Users\*\AppData\Local\Temp -Filter "*.json" -Recurse |
  Select-String -Pattern 'DetectorName|Verified|CommitHash'
```

**Windows (via Sysmon/Event logs):**
```
Event ID 1 (Process Creation):
  - Image: *trufflehog* OR (CommandLine contains "trufflehog")
  - Parent: bash.exe, cmd.exe, powershell.exe, jenkins.exe, github-runner, gitlab-runner
  - CommandLine: contains flags like "--json", "--only-verified", "--token"
```

### Shell History Hunt

**Linux/macOS (bash history):**
```bash
# Check shell history for trufflehog commands
cat ~/.bash_history | grep -i trufflehog
cat ~/.zsh_history | grep -i trufflehog

# Check for git scanning patterns
cat ~/.bash_history | grep -E 'git.*--json|github.*--token|s3.*--bucket'

# Check for credential mentions
cat ~/.bash_history | grep -E 'GITHUB_TOKEN|AWS_ACCESS|SLACK_TOKEN|GITLAB_TOKEN'
```

**Windows (PowerShell history):**
```powershell
# Check PowerShell history
(Get-PSReadlineOption).HistorySavePath
cat $PROFILE\..\ConsoleHost_history.txt | Select-String 'trufflehog'

# Check Windows command history (limited)
doskey /history | Select-String 'trufflehog'
```

### Network Connection Hunt

**Linux/macOS:**
```bash
# List established connections to known API endpoints
netstat -npte | grep -E '(github|gitlab|slack|jira|amazonaws|googleapis|s3)' | grep ESTABLISHED

# Historical: check firewall logs for patterns
sudo cat /var/log/firewall.log | grep -E 'api.github.com|api.gitlab|slack.com|jira|amazonaws'
```

**Windows (via Sysmon):**
```
Event ID 3 (Network Connection):
  - DestinationIp: Matches known API endpoints (api.github.com, api.gitlab, slack.com, S3 IPs)
  - DestinationPort: 443 (HTTPS)
  - Protocol: tcp
  - Image: trufflehog.exe or renamed binary
  - User: System, Administrator, or service account
```

### Credential File Hunt

```bash
# Check for Git credentials
cat ~/.git-credentials
cat ~/.config/git/credential/github.json

# Check for AWS credentials
cat ~/.aws/credentials | grep -E 'access_key|secret_key'

# Check for environment variable exports in shell config
grep -r "GITHUB_TOKEN\|GITLAB_TOKEN\|AWS_ACCESS_KEY" ~/.bashrc ~/.bash_profile ~/.zshrc

# Check for .env files with secrets
find /tmp -name ".env" -o -name "*.env" 2>/dev/null | xargs grep -E 'KEY|PASSWORD|TOKEN'
```

### Output File Hunt

```bash
# Search for Trufflehog JSON output (contains DetectorName, Verified fields)
find / -name "*.json" -type f -exec grep -l '"DetectorName"' {} \; 2>/dev/null

# Check /tmp and /var/tmp for recent JSON files
find /tmp /var/tmp -name "*.json" -type f -newer /etc/passwd 2>/dev/null

# Look for common output filenames
find ~ -name "*findings*" -o -name "*secrets*" -o -name "*scan*" 2>/dev/null
```

**Hunting strength:** High. Trufflehog output JSON is structured and distinctive. Even if deleted, unallocated space recovery may recover findings.

## Hunting on Target (Scanned Systems)

### GitHub Audit Log Hunt

```bash
# If you have GitHub admin access, query audit logs
# Via REST API:
curl -s -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/orgs/myorg/audit-log?action=api.GetRepositories" | \
  jq '.[] | select(.created_at > "2026-08-11T00:00:00Z")' | \
  jq -r '.actor, .ip, .created_at, .action'

# Look for unusual API token usage patterns
curl -s -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/orgs/myorg/audit-log?action=api.*" | \
  jq 'group_by(.actor) | .[] | {actor: .[0].actor, count: length}'
```

**Hunt signals:**
- Multiple rapid API calls to repository endpoints
- API token accessing repos outside its usual scope
- Non-UI-based access (pure API, no interactive clicks)
- Source IP not matching known CI/CD/team IPs

### AWS CloudTrail Hunt

**S3 Bucket Scanning Pattern:**
```bash
# AWS CLI to query CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListBucket \
  --start-time 2026-08-11T00:00:00Z \
  --region us-east-1 | \
  jq '.Events[] | {EventTime, CloudTrailEvent}' | \
  jq -r '.CloudTrailEvent | fromjson | "\(.sourceIPAddress) -> \(.requestParameters.bucketName)"'

# Pattern hunt: rapid GetObject after ListBucket
aws s3api get-bucket-logging --bucket company-backups 2>/dev/null
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventSource,AttributeValue=s3.amazonaws.com | \
  jq '.Events[] | select(.CloudTrailEvent | fromjson | .sourceIPAddress == "10.0.0.5")'
```

**Hunt signals:**
- Rapid ListBucket → multiple GetObject pattern
- UserAgent contains "golang" or "aws-cli"
- Scanning buckets not typically accessed
- Access from unexpected IP address
- Multiple GetCallerIdentity (credential verification) calls

### GitLab Audit Log Hunt

```bash
# Via GitLab API (requires admin token)
curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.internal/api/v4/audit_events?action=API_ACCESS" | \
  jq '.[] | {created_at, user_name, action, detail}'

# Hunt for rapid API calls
curl -s --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.internal/api/v4/audit_events" | \
  jq 'group_by(.user_id) | .[] | select(length > 100)' # More than 100 events from one user
```

### Slack Audit Log Hunt (Enterprise Grid)

**Via Slack CLI or API:**
```bash
# Query Slack audit logs for high-volume API access
curl -s -X POST https://slack.com/api/audit.logs.get \
  -H "Authorization: Bearer $SLACK_TOKEN" \
  -d 'action=api_call&limit=1000' | \
  jq '.logs[] | select(.action == "conversations_history") | .actor'

# Hunt for bulk message access patterns
curl -s -X POST https://slack.com/api/audit.logs.get \
  -H "Authorization: Bearer $SLACK_TOKEN" | \
  jq '[.logs[] | select(.action == "conversations_history")] | length'
```

**Hunt signals:**
- High-volume conversations.history calls
- API token (not interactive user)
- Access from unusual IP
- Systematic channel enumeration

### Jira Audit Log Hunt

```bash
# Via Jira Cloud API
curl -s -u "user@company.com:$JIRA_API_TOKEN" \
  "https://jira.company.com/rest/api/3/audit?action=ISSUE_SEARCH" | \
  jq '.records[] | {created, actor, action, details}'

# Hunt for password/secret search patterns
curl -s -u "user@company.com:$JIRA_API_TOKEN" \
  "https://jira.company.com/rest/api/3/audit" | \
  jq '.records[] | select(.details | contains("secret") or contains("password"))'
```

### Google Cloud Audit Log Hunt

```bash
# Query Cloud Logging for suspicious patterns
gcloud logging read \
  'resource.type="gcs_bucket" AND protoPayload.methodName="storage.objects.list"' \
  --limit 50 \
  --format json | \
  jq '.[] | {timestamp: .timestamp, actor: .protoPayload.authenticationInfo.principalEmail}'

# Hunt for bulk object enumeration
gcloud logging read \
  'protoPayload.methodName=("storage.objects.list" OR "storage.buckets.list")' \
  --format json | \
  jq 'group_by(.protoPayload.authenticationInfo.principalEmail) | \
      .[] | {account: .[0].protoPayload.authenticationInfo.principalEmail, count: length}'
```

## Hunting Strength Ranking

| Signal | Survives Evasion | Detection Difficulty | Notes |
|--------|---|---|---|
| **GitHub API audit log (multi-repo scan pattern)** | ✅ High | Easy | Automated tool pattern very obvious |
| **AWS CloudTrail (ListBucket → GetObject sequence)** | ✅ High | Easy | Scanning pattern distinct from normal S3 access |
| **Shell history (trufflehog command)** | ❌ Can be cleared | Easy | Recoverable from unallocated space if not secure-deleted |
| **Process logs (Sysmon 1 trufflehog execution)** | ✅ Medium | Medium | Renamed binary harder to detect, parent process still shows |
| **Jira audit (password/secret search queries)** | ✅ High | Medium | Need access to audit logs, pattern still distinctive |
| **Slack audit (high-volume message access)** | ✅ High | Medium | Enterprise Grid required to see audit logs |
| **Output JSON file (on disk)** | ❌ Can be deleted | Easy | Unallocated space recovery may succeed |
| **Network logs (TLS handshakes to APIs)** | ✅ High | Hard | Requires HTTPS traffic logging; endpoint-only, hard to correlate |
| **Git credential cache** | ⚠️ Medium | Medium | Local-only artifact, can be cleared |

## Hunting Priority

1. **GitHub/GitLab audit logs** — Most obvious, shows automated scanning pattern, attackers rarely clean upstream audit logs
2. **AWS CloudTrail** — S3 ListBucket/GetObject patterns are distinctive, highly reliable
3. **Slack/Jira audit logs** — If enabled (requires Enterprise), very clear evidence
4. **Process logs (Sysmon 1)** — Shows execution, hard to hide if parent process visible
5. **Shell history** — Easy to find, easy to clear, recoverable from deleted blocks
6. **Output files** — High value if found, but attackers likely delete

## Correlation Example

**Timeline: Post-Compromise Credential Discovery**

```
2026-08-11 14:32:18 UTC  → GitHub audit log: API token "ghp_xxxxx" lists all repos (source IP 10.0.0.5)
2026-08-11 14:33:42 UTC  → CloudTrail: ListBucket on "company-backups" from 10.0.0.5
2026-08-11 14:34:15 UTC  → CloudTrail: GetObject (backup_2026_08_10.sql) from 10.0.0.5
2026-08-11 14:35:00 UTC  → CloudTrail: GetCallerIdentity (credential verification)
2026-08-11 14:35:30 UTC  → Slack audit: api_call from bot token, conversations_history x50 calls
2026-08-11 14:36:00 UTC  → Source host shell history: "trufflehog github --org acme-corp --token ghp_xxxxx --only-verified"
2026-08-11 14:36:30 UTC  → Output file /tmp/findings.json contains AWS_KEY + GitHub tokens + Slack tokens
```

**Verdict:** Confirmed Trufflehog scan, credentials found, likely used for subsequent lateral movement (check for those credentials' usage in other systems 2026-08-11 14:37+).
