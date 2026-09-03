Artifacts left on the **scanned** systems (GitHub, GitLab, AWS, Slack, Jira, GCS, etc.) during Trufflehog execution.

## GitHub API Access Logs

**GitHub audit log entry (Organization level):**
```
Timestamp: 2026-08-11T14:32:18Z
Action: api.GetRepositories
Actor: ghp_xxxxx (token name or OAuth app)
IP: 10.0.0.5
User-Agent: GoLang/1.XX
Result: Success
```

**Detection signals:**
- Multiple repository access events in short timeframe (scanning all repos in org)
- API endpoints commonly queried:
  - `/repos` (list repos)
  - `/contents` (file listing)
  - `/commits` (commit history)
  - `/branches` (branch enumeration)
- Bearer token in Authorization header matches Trufflehog's token

**Evidence value:** Very High. Organization audit logs show exactly what repos were accessed and in what order.

**Log location:** GitHub Settings → Audit Log (requires organization member or higher permission to view).

## GitLab Audit Events

**GitLab audit event entry:**
```json
{
  "id": 12345,
  "created_at": "2026-08-11T14:32:18Z",
  "author_id": 999,
  "author_name": "api_scanner_bot",
  "action": "project_access",
  "entity_type": "Project",
  "entity_id": 456,
  "details": "Accessed via API"
}
```

**Detection signals:**
- Rapid API requests to `/projects`, `/repositories`, `/commits`
- Requests using a specific API token
- Scanning all projects sequentially or in parallel
- No UI-based clicks (pure API traffic)

**Log location:** GitLab Admin Settings → Audit Log (or per-project audit if available).

## AWS CloudTrail (S3 Scanning)

**CloudTrail event for S3 ListBucket:**
```json
{
  "eventTime": "2026-08-11T14:32:18Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "ListBucket",
  "requestParameters": {
    "bucketName": "company-backups"
  },
  "sourceIPAddress": "10.0.0.5",
  "userAgent": "aws-cli/2.xx or golang-http-client/x.x"
}
```

**CloudTrail event for S3 GetObject:**
```json
{
  "eventName": "GetObject",
  "requestParameters": {
    "bucketName": "company-backups",
    "key": "backup_2026_08_10.sql"
  },
  "requestMetadata": {
    "sourceIPAddress": "10.0.0.5"
  }
}
```

**Detection signals:**
- Rapid ListBucket followed by multiple GetObject calls
- UserAgent contains "golang" or "trufflehog"
- Scanning objects across multiple prefixes
- Access from non-standard IP (not typical CI/CD runner IP)

**Log location:** AWS CloudTrail (searchable in S3 or CloudTrail console).

## AWS IAM Access Analyzer (Credential Verification)

When Trufflehog verifies an AWS secret key, it typically calls `sts:GetCallerIdentity` to confirm the key is valid.

**CloudTrail event:**
```json
{
  "eventName": "GetCallerIdentity",
  "eventSource": "sts.amazonaws.com",
  "requestParameters": null,
  "sourceIPAddress": "10.0.0.5",
  "userAgent": "golang-http-client"
}
```

**Detection signals:**
- GetCallerIdentity from IP not usually calling STS
- Multiple GetCallerIdentity calls (one per found AWS key)
- Followed by permission-enumeration calls (DescribeUser, ListAccessKeys, etc.)

## Slack Audit Logs

**Slack Enterprise Grid audit log (if enabled):**
```
Event Type: authentication
User: (bot or service account)
Action: api_call
Timestamp: 2026-08-11T14:32:18Z
Endpoint: conversations.history, users.info, messages.list
Scope: read:messages
IP Address: 10.0.0.5
```

**Detection signals:**
- API calls using workspace token
- High volume of `conversations.history` requests (scanning all channels)
- Bulk `users.info` calls (enumerating users)
- Access from non-standard IP / non-Slack client User-Agent

**Log location:** Workspace Settings → Audit Logs (Enterprise Grid feature, requires admin).

## Jira Audit Log

**Jira Cloud audit event:**
```json
{
  "created": "2026-08-11T14:32:18Z",
  "type": "AUTHENTICATED_USER_ACCESS",
  "category": "api",
  "details": {
    "action": "ISSUE_SEARCH_VIA_JQL",
    "query": "(secret OR password OR key)"
  },
  "actor": "api_token_xyz",
  "affectedObjects": []
}
```

**Detection signals:**
- API token usage (not interactive login)
- Search queries scanning many issues
- Text searches for "password", "secret", "key" patterns
- High volume of API requests from non-standard IP

**Log location:** Jira Settings → Audit Log.

## Git Repository (Local Scanning)

If Trufflehog scans a local `.git` directory, filesystem/filesystem timestamp artifacts are left:

**Git reflog updates:**
```
# .git/logs/HEAD shows most-recent read
ref: refs/heads/master
hash: abc123def456...
timestamp: 1691754738 +0000
action: "pull from origin"  (if remote fetch), or
action: "checkout" (if local scan)
```

**Git index/stat changes:**
```
# .git/index mtime updated if git status runs during scan
stat(3, {st_mode=S_IFREG|0644, st_size=16384, st_mtime=1691754738, ...}) = 0
```

**Detection signals:**
- `.git/logs/HEAD` atime/mtime updated during suspected breach window
- `.git/index` modified timestamp indicates git operations during attack
- Full `.git` directory copied to attacker's machine (git clone --mirror)

**Evidence value:** Medium. Shows when repo was accessed, but doesn't directly show what Trufflehog found.

## Confluence Audit Log (if scanning Confluence wikis)

**Confluence audit event:**
```
Time: 2026-08-11 14:32:18
User: api_scanner_bot
Action: VIEW
Entity: Page (multiple pages)
IP: 10.0.0.5
Details: Accessed via REST API /rest/api/content/search
```

**Detection signals:**
- API-driven page access (not interactive clicks)
- Bulk page enumeration
- Search queries for "password", "secret", "key"

## Google Cloud Storage Audit Log

**GCS audit entry (if enabled):**
```json
{
  "timestamp": "2026-08-11T14:32:18Z",
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "service-account@project.iam.gserviceaccount.com"
    },
    "methodName": "storage.buckets.list",
    "resourceName": "projects/_/buckets/company-data"
  },
  "sourceIPAddress": "10.0.0.5"
}
```

**Detection signals:**
- Service account used (not interactive user)
- Rapid bucket.list and objects.list calls
- Access from unusual IP address

**Log location:** Google Cloud Audit Logs (Cloud Console → Logging).

## Detection Timeline

**Post-compromise attack sequence:**
1. **T+0min:** Trufflehog scan initiates
2. **T+0-2min:** GitHub API receives ListRepositories, GetContents, GetCommits requests from attacker IP
3. **T+2-5min:** CloudTrail logs S3 ListBucket + GetObject calls
4. **T+5-10min:** AWS CloudTrail logs credential verification (GetCallerIdentity)
5. **T+10-15min:** Slack audit logs show conversation history scanning
6. **T+15min:** Scan completes, attacker examines output file with validated credentials

**Correlation opportunities:**
- GitHub/GitLab + AWS audit logs show same source IP in same timeframe
- API request patterns (repeated, sequential scanning) indicate automated tool usage
- Credential verification attempts (GetCallerIdentity, etc.) follow repo scanning

## Containment Signals

**If organization detects Trufflehog scanning:**
- Revoke the API token used for scanning
- Force password reset for any compromised credentials found
- Rotate AWS keys / IAM roles accessed during scanning
- Review audit logs for credential usage after scan (did attacker use found secrets?)

**Persistence check:**
- Did attacker access S3 buckets / GitHub repos / Slack channels again after initial scan?
- Were found credentials used to access other systems?
- Is the scanning credential still valid (not revoked)?
