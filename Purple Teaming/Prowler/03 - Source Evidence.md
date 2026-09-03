# Prowler — Source Evidence (Attacker Host)

Evidence left on the **attacking/source** host when Prowler is executed. Prowler's own artifacts are minimal (read-only tool), but the environment/credential setup leaves detectable traces.

---

## Shell Command History

### Bash/Zsh History
```bash
# User runs Prowler
prowler aws -f cis -o json -d ./audit-output

# History file: ~/.bash_history or ~/.zsh_history
# Entry:
# prowler aws -f cis -o json -d ./audit-output
```

**Forensic value:**
- Reveals framework targeted (CIS, NIST, PCI, HIPAA)
- Shows output directory/naming pattern (helps correlate with output files on target via S3 upload)
- Timestamp via shell history metadata (`stat ~/.bash_history`)

**Evasion:**
- Operator may unset `HISTFILE` before running: `HISTFILE=/dev/null prowler ...`
- Or `history -c` clears in-memory history (but not file on disk yet)
- Search for interrupted/missing history entries as a signal

### Shell History With Cloud Credential Leaks
```bash
# Risky but common: hardcoding credentials in command
prowler aws --profile my-audit \
  -a arn:aws:iam::123456789012:role/ProwlerAuditRole \
  -f cis

# History may contain: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY passed as env vars
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... prowler aws ...
```

**Forensic value:**
- Direct credential recovery from shell history
- Confirms which AWS account(s)/cloud environment(s) were targeted

---

## Cloud Credential Files

### AWS Credentials
| Location | Format | Forensic Relevance |
|---|---|---|
| `~/.aws/credentials` | INI format with access keys | Prowler reads default profile or `--profile` arg; can identify specific AWS account audited |
| `~/.aws/config` | INI format with regions/roles | `--profile my-audit` flag reveals which profile was used; role assumption ARN visible |
| `~/.aws/sso/cache/` | JSON token cache | If using AWS SSO, cached tokens reveal federated identity, tenant, and last login time |
| Environment variables | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Operator may use env vars instead of files (less forensically obvious, but process listing reveals them) |

### Azure Credentials
| Location | Format | Forensic Relevance |
|---|---|---|
| `~/.azure/credentials` | JSON | Service principal credentials (if using CLI auth) |
| `~/.azure/msal_token_cache.bin` | Binary cache | MSAL library token cache from `az login` |
| `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` environment variables | Text | Service principal auth via env vars |

### GCP Credentials
| Location | Format | Forensic Relevance |
|---|---|---|
| `/path/to/service-account-key.json` | JSON | Prowler `-a` flag points to service account key file; key contains `project_id`, service account email, and key ID |
| `~/.config/gcloud/` | Structured directory | gcloud CLI cache; `application_default_credentials.json` if using `gcloud auth login` |

**Timeline correlation:**
- Access time of credential files (`atime`) may show recent read when Prowler ran
- Compare credential file timestamps with Prowler scan timestamps in output

---

## Local Prowler Installation Artifacts

### Python Package Installation
```bash
# First-time install
pip install prowler-cloud

# Artifacts:
# 1. ~/.local/lib/python3.x/site-packages/prowler/
#    - All Prowler source code, checks, frameworks installed here
# 2. pip cache: ~/.cache/pip/http-*/ (if using --cache-dir)
# 3. Installation log: /tmp/pip-install-*/ (temporary, often cleaned up)
```

**Forensic value:**
- Presence of `~/.local/lib/python3.x/site-packages/prowler/` confirms Prowler is installed on host
- Version number in `prowler/__init__.py` or via `pip show prowler-cloud` shows when installed/updated
- Timestamps on installed files may indicate when installation occurred

### Git Clone Installation (From Source)
```bash
# Operator clones from GitHub
git clone https://github.com/prowler-cloud/prowler.git /opt/prowler

# Or in `~/prowler/`
# Artifacts:
# 1. `~/prowler/.git/` — git history (clone time, pull times)
# 2. `~/prowler/` source tree (if not cleaned up)
```

**Forensic value:**
- `.git/objects/pack/` contains packed commit history
- `.git/HEAD` + `.git/logs/HEAD` show last branches checked out
- Timestamps on `.git/` objects reveal when repo was cloned/updated
- If operator runs from source, `prowler/` directory itself is the artifact

### Docker Container
```bash
# Operator runs Prowler in container
docker run --rm \
  -e AWS_ACCESS_KEY_ID=AKIA... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -v /path/to/output:/output \
  prowler-cloud/prowler:latest \
  prowler aws -f cis -o json -d /output

# Artifacts:
# 1. Docker image: prowler-cloud/prowler (if pulled locally)
# 2. Container logs: docker logs <container-id>
# 3. Volume mount points: /path/to/output/ (output directory on host)
```

**Forensic value:**
- `docker images` shows Prowler image locally cached
- `docker ps -a` (even after container exits) shows past containers
- `~/.docker/config.json` shows auth tokens if container registry login used
- Volume mount source directory on host filesystem

---

## Output Files (Local)

Prowler writes scan results to a local output directory (default: `./output/`).

```bash
prowler aws -f cis -o json -d ./my-audit-results
```

**Output directory structure:**
```
my-audit-results/
├── json/
│   ├── cis-123456789012-report.json  (consolidated findings)
│   ├── cis-123456789012-report-resource-summary.json
│   ├── cis-123456789012-report-findings.json
│   └── [framework-accountid-report-*.json]  (one per framework per account)
├── html/
│   ├── cis-123456789012-report.html  (browsable report)
│   └── index.html  (report index)
├── csv/
│   └── cis-123456789012-report.csv  (spreadsheet-friendly)
└── sarif/
    └── cis-123456789012-report.sarif  (IDE/CI integration)
```

### JSON Output File Structure
```json
{
  "Metadata": {
    "Provider": "aws",
    "Checks Passed": 187,
    "Checks Failed": 43,
    "Checks Skipped": 12,
    "Scan Date": "2026-08-11T14:32:00Z",
    "Prowler Version": "5.25.0"
  },
  "findings": [
    {
      "FindingId": "aws_cis_1_1",
      "FindingType": "Software and Configuration Checks/AWS Security Best Practices",
      "Resource": "arn:aws:iam::123456789012:root",
      "Status": "FAILED",
      "Message": "Root account MFA is not enabled",
      "Framework": "cis",
      "CisControlId": "1.1",
      "ThreatScore": 9.5,
      "Remediation": "Enable MFA on root account"
    }
  ]
}
```

**Forensic value:**
- **Metadata:** Scan timestamp, provider targeted, framework used, version of Prowler
- **Per-finding:** Account ID, resource URN/ARN, status (PASSED/FAILED), threat score
- **Remediation hints:** Reverse-engineer attacker's priorities from high-ThreatScore findings

### Timeline Correlation
- **File modification time** (`mtime`) on JSON/HTML output = scan completion time
- **Account ID in findings** → confirms which AWS account was scanned
- **ThreatScore sorting** → what the attacker deemed highest priority
- **Framework names** → whether scan was CIS (generic hardening), PCI (payment), HIPAA (healthcare), etc.

---

## Process Artifacts

### Process Listing During Execution
```bash
# While Prowler runs (short-lived process)
ps aux | grep prowler
# python /usr/local/bin/prowler aws -f cis -o json -d ./output

# Child processes:
# - Python interpreter (process parent)
# - AWS CLI (if subprocess calling `aws` commands for specific checks)
# - Boto3 library operations (AWS SDK, no separate process)
```

**Forensic value:**
- Process name: `python` or `python3` (generic, not distinctive)
- Command-line args in process list: `-f cis`, `-o json`, AWS account ID (if passed as argument)
- CPU/memory usage during scan (AWS API calls are I/O-heavy, not CPU-heavy)

### Environment Variables (Live Process)
```bash
# Running process exposes env vars
cat /proc/PID/environ | tr '\0' '\n' | grep -E 'AWS|AZURE|GCP'

# Typical output:
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=...
# AWS_DEFAULT_REGION=us-east-1
```

**Forensic value:**
- Direct credential recovery from live process
- Region targeted
- Account number (if embedded in credential profile name)

---

## OS-Level Audit Trail

### Command Audit (auditd on Linux)
```bash
# If host has auditd enabled, Prowler execution is logged:
ausearch -m EXECVE -ts recent | grep prowler
# OUTPUT: type=EXECVE msg=audit(...) exe=/usr/bin/python3 a0=prowler a1=aws a2=-f ...

# Child process calls (e.g., boto3 making AWS API calls)
ausearch -m EXECVE -ts recent | grep -E 'boto|aws|http'
```

**Forensic value:**
- Full command-line reconstruction
- Timestamp of execution
- User ID running command (UID)
- Return code (success/failure)

### File Access Audit (auditd Watch Rules)
```bash
# If admin has auditd rule watching cloud credential files:
auditctl -w ~/.aws/credentials -p ra -k aws_creds_read
# logs reads of ~/.aws/credentials

# When Prowler runs, this rule fires:
ausearch -k aws_creds_read | grep PATH=/home/user/.aws/credentials
```

**Forensic value:**
- Confirms credential file was accessed at specific time
- Correlates with Prowler execution timestamp

### System Logging (syslog/journalctl)
```bash
# SSH login (if scanning from remote host)
journalctl --grep ssh | grep "user@host"

# Sudo elevation (if Prowler run with sudo for some reason)
journalctl SYSLOG_IDENTIFIER=sudo
```

**Forensic value:**
- Identifies user account running Prowler
- Login/logout times (if remote execution)

---

## Network Traffic (Source Side)

### DNS Resolution
```bash
# Prowler resolves API endpoints:
# DNS query: api.shodan.io (if using Shodan integration, rare but possible)
# DNS query: *.amazonaws.com, *.azure.com, *.googleapis.com (cloud API endpoints)

# Recoverable via:
# 1. tcpdump on host: tcpdump -i any -w prowler.pcap port 53
# 2. systemd-resolved cache: resolvectl query <domain>
# 3. Browser DNS cache (if using GUI tools)
```

**Forensic value:**
- Cloud provider (AWS/Azure/GCP) identified by DNS queries
- Region endpoints (e.g., `us-east-1.amazonaws.com` vs. `eu-west-1.amazonaws.com`)

### HTTP/HTTPS Outbound Connections
```bash
# Prowler makes HTTPS calls to cloud APIs:
# Network: host -> *.amazonaws.com:443 (AWS APIs)
# Network: host -> *.blob.core.windows.net:443 (Azure)
# Network: host -> *.googleapis.com:443 (GCP)

# Recoverable via:
# 1. netstat: netstat -tln | grep ESTABLISHED
# 2. ss: ss -tln | grep api.amazonaws.com
# 3. tcpdump: tcpdump -i any -n "host *.amazonaws.com"
```

**Forensic value:**
- Cloud provider confirmation
- Port 443 (encrypted, no payload visibility)
- If capturing TLS handshake: SNI (Server Name Indication) reveals domain (e.g., `ec2.us-east-1.amazonaws.com`)
- Connection count/duration hints at scan scope (many accounts/regions = longer scan)

### Proxy/VPN Bypass Detection
```bash
# If operator uses proxy to hide IP:
# Prowler traffic routes through proxy server
# Visible in netstat as connection to proxy host instead of AWS

# Detection: compare DNS queries vs. actual connections
# DNS: api.amazonaws.com resolved to AWS IP
# Connection: to proxy IP instead (suspicious mismatch)
```

---

## Memory Artifacts

### Process Memory Dump
```bash
# If process is still running, dump memory:
gdb -p PID --batch --ex "dump memory prowler.dump 0x0 0xffffffffffffffff"

# Or use tools like Volatility:
volatility -f prowler.dump linux.bash.bash_env
# Recovers environment variables, including AWS credentials
```

**Forensic value:**
- AWS access keys in plaintext memory
- Scan parameters (frameworks, services, regions)
- API response data (list of resources scanned)

### Python Bytecode Cache
```bash
# Prowler (Python) may leave compiled bytecode
find ~/.local/lib/python3.x/site-packages/prowler -name "*.pyc"
# These are compiled Python opcodes; can be decompiled back to source

# Temporal clue: file timestamps show when Python imported the module
```

**Forensic value:**
- Confirms Prowler was imported/executed
- Timestamps show execution window

---

## Timeline Correlation (Source to Target)

| Event | Time | Source Artifact | Target Artifact |
|---|---|---|---|
| **Operator installs Prowler** | T-1 day | Package files in `~/.local/lib/python3.x/site-packages/prowler/` | (none — local only) |
| **Operator configures AWS creds** | T-6 hours | `~/.aws/credentials` file modified | (none — local creds) |
| **Prowler scan starts** | T | Shell history: `prowler aws -f cis ...` | CloudTrail: first `DescribeInstances` call |
| **Prowler scan completes** | T+5min | JSON output file written to `./output/` | CloudTrail: last API call; `StartEventTime` / `EventTime` |
| **Operator reviews findings** | T+10min | JSON file read (`atime` updated) | (none — read-only tool) |
| **Operator uploads to S3** | T+20min | `prowler aws ... -b my-bucket` | S3 PutObject call in CloudTrail |

**Blue team use:** Cross-correlate source (shell history, file timestamps) with target (CloudTrail timestamps) to establish exact scan window and confirm operator identity.

---

## Evasion & Minimal-Trace Tactics

### Credential-Less Evasion (Compromised EC2 Role)
```bash
# Operator already has EC2 shell; uses instance's attached IAM role
# No credential files downloaded; boto3 auto-fetches from metadata service
prowler aws -f cis -o json -d /tmp/audit

# Forensic difficulty:
# - No ~/.aws/credentials (cloud creds invisible)
# - Only process listing shows prowler running
# - Shell history visible (but no -a flag for credentials)
```

**Blue team response:**
- Monitor CloudTrail for API calls from EC2 role (metadata-service origin)
- CloudTrail `userIdentity.principalId` shows `AIDA...` (role, not access key)
- Look for sudden spike in Describe* API calls from that role

### Cleanup & History Deletion
```bash
# Operator cleans up after run:
rm -rf ./output/
history -c
unset HISTFILE
```

**Remaining artifacts:**
- Deleted files may be recoverable via `extundelete` or forensic tools (unallocated disk clusters)
- Shell history may be synced to centralized logging (syslog)
- AWS credentials in `~/.aws/credentials` still present (not auto-deleted)
- Cloud audit logs (CloudTrail) on target side are permanent

---

## Detection Signals (Hunting)

See `05 - Detection and Hunting.md` for specific hunt commands on source host (e.g., grep shell history, scan for Prowler packages, find output directories).

