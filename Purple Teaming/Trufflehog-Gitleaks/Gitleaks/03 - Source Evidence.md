Artifacts left on the **attacking/operator** host during Gitleaks scanning.

## Process Execution

**Command-line evidence:**
```
gitleaks git /path/to/.git --json --report-path /tmp/findings.json
gitleaks dir /opt/app --json
gitleaks git https://github.com/owner/repo.git --config /tmp/custom_rules.toml
cat logfile.txt | gitleaks stdin --json
```

Gitleaks runs as a single Go binary (static, no runtime dependencies). Process tree:
- Parent: bash, cmd.exe, PowerShell, Jenkins job, GitHub Actions runner, pre-commit hook
- Child: `gitleaks` (single process for entire scan)
- No subprocesses unless scanning remote repo (triggers `git clone`)

**Sysmon 1 / Process Creation:**
- Image: `/usr/bin/gitleaks` or renamed binary (`scanner`, `audit`, `check`, etc.)
- CommandLine: Contains subcommand (`git`, `dir`, `stdin`), path argument, optional config/baseline flags
- ParentImage: Git, bash, Jenkins, or development IDE

**Key observation:** Unlike Trufflehog, Gitleaks doesn't spawn AWS/GitHub/Slack API clients. If Gitleaks scans a remote repo, it uses `git clone` subcommand (visible in parent-child relationship).

## Shell History

**Bash/Zsh history (~/.bash_history, ~/.zsh_history):**
```
gitleaks git /home/user/repo/.git --json --report-path /tmp/findings.json
gitleaks git https://github.com/company/internal-repo.git --baseline /tmp/baseline.json
gitleaks dir /opt/app --enable-rule aws,github
cat app.log | gitleaks stdin --json
```

History file is NOT automatically cleaned. Operator must manually clear:
```bash
history -c
echo "" > ~/.bash_history
```

**Evidence value:** High. Full command-line reconstructs the scope of scanning (local repo, remote repo, directory, custom rules).

## Git Cloning (Remote Repo Scan)

If Gitleaks scans a remote repository via HTTPS:
```bash
gitleaks git https://github.com/company/repo.git
```

Gitleaks clones the repo to a temporary directory (often `/tmp/gitleaks-*` or OS temp). Git artifacts:
- `~/.git-credentials` (if repo requires authentication)
- Git HTTP traffic (captured in firewall logs, network traffic)
- Temporary `.git` directory (deleted after scan completes, but recoverable from unallocated space)

**Evidence value:** Medium. Shows which repos were accessed.

## Configuration Files

**Custom TOML config file (.gitleaks.toml):**
```toml
[rules.custom_api_key]
description = "Company API key"
regex = '''COMPANY_API_[A-Z0-9]{32}'''
```

If operator created custom rules, the config file is an artifact showing:
- What secret patterns they're hunting for (reveals organization's security model)
- Custom rule sophistication (indicates whether it's automated scanning or manual)

**Baseline file (.gitleaksignore or baseline.json):**
```json
[
  {"Secret": "AKIA1234567890123456", "File": "tests/fixtures/..."},
  {"Secret": "ghp_oldtoken123", "File": "scripts/deploy.py"}
]
```

If operator created baseline, it shows:
- Known/tolerated credentials (development/test keys)
- Which files historically contained secrets (may indicate security lapses)

**Evidence value:** Medium-to-High. Baseline reveals what findings operator decided to ignore or accept.

## Output Files

**JSON report (default):**
```bash
gitleaks git /path --json > /tmp/findings.json
```

Report contains:
- Secrets found (field values, regex matches, entropy scores)
- File paths, commit hashes, author info
- Line numbers, match excerpts
- Rule IDs and descriptions

**SARIF format (security-audit-report-format):**
```bash
gitleaks git /path --sarif > /tmp/findings.sarif
```

SARIF is a standardized security finding format. Same content as JSON, just different structure.

**CSV format:**
```bash
gitleaks git /path --csv > /tmp/findings.csv
```

Spreadsheet-friendly format of findings.

**Artifact locations:**
- Operator-specified via `--report-path` flag
- Current directory if using stdout redirect
- `/tmp/` is common (often left behind post-scan)

**Evidence value:** Very High. Report contains exact credentials found, their locations, and git metadata.

## Network Activity (Remote Repo Scan)

If scanning a remote GitHub/GitLab repo:
- DNS lookup: `github.com` or `gitlab.com`
- HTTPS connection to GitHub/GitLab API (port 443)
- Git clone traffic (authenticated via SSH key or HTTPS token)
- TLS handshake (captures server certificate)

**Firewall/proxy logs:**
```
10.0.0.5:54321 -> 140.82.112.6:443 (github.com API)
10.0.0.5:54322 -> 10.20.0.15:443 (internal gitlab.internal)
```

**IDS/IPS signatures:**
- Git over HTTPS is common, not easily fingerprinted
- `git-upload-pack` protocol (if SSH) is distinctive

**Evidence value:** Medium. Shows which repositories were accessed.

## Git Credential Cache

If operator authenticated with GitHub/GitLab, Git caches credentials:
- `~/.git-credentials` (plaintext, if `credential.helper = store`)
- `~/.config/git/credentials/` (various formats)
- In-memory credential helper socket (transient)

**Evidence value:** Low-to-Medium. Indicates the operator has authenticated access to specific repos.

## Process Environment Variables

Gitleaks may read environment variables for authentication (if Git is configured to use them):
- `GIT_USERNAME`, `GIT_PASSWORD`
- `GITHUB_TOKEN`
- Custom env vars for CI/CD integration

**Visible via:**
- `/proc/[pid]/environ` (Linux)
- `tasklist /v` (Windows, if env vars displayed)

**Evidence value:** Medium. Shows what credentials were available in the operator's environment.

## Timeline Reconstruction

**Post-compromise scanning sequence:**
1. Operator gains shell access to dev machine
2. Discovers `.git` directory at `/home/dev/project/.git`
3. Runs `gitleaks git /home/dev/project/.git --json > /tmp/findings.json`
4. Scans complete in 5-10 seconds (typical for small-to-medium repos)
5. Examines output file `/tmp/findings.json`, finds AWS key, GitHub token, database password
6. Uses found credentials for lateral movement

**Source timeline:**
- Process logs show gitleaks execution + parent process (bash)
- Shell history shows command run
- Output file timestamp shows when scan completed
- File modification times on credential files (if accessed)

## Evasion Signals

**How operator might hide:**
- Use temporary renamed binary: `mv gitleaks /tmp/scan && /tmp/scan git ...`
- Redirect to `/dev/null`: `gitleaks git /path > /dev/null`
- Clear shell history: `history -c && cat /dev/null > ~/.bash_history`
- Delete output files: `rm /tmp/findings.json`
- Use pipe instead of file: `gitleaks git /path --json | grep -o '"Secret":"[^"]*"'`

**What survives evasion:**
- Gitleaks binary execution (Sysmon 1, process logs, parent-child process tree)
- Git clone/network activity (firewall logs, TLS handshakes)
- Output if piped to another command (that command's logs, memory, artifacts)
- Unallocated space recovery (deleted output files may survive on disk)

**Strongest signal:** Renamed gitleaks binary spawning `git clone` for remote repos — parent-child process relationship is hard to hide without disabling process auditing entirely.
