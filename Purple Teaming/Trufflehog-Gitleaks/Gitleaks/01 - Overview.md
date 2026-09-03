🔴 **RED FLAG:** Gitleaks is a Git-history-focused secret scanner that finds credentials in commit history through regex pattern matching and entropy analysis. Unlike Trufflehog's multi-source scope and credential verification, Gitleaks is simpler and faster — making it the operator's choice for quick local repo scanning or CI/CD integration.

## History

**Gitleaks** is an open-source secret detection tool maintained by **Zachary Rice** (`zricethezav`), developed initially as a Git-history-only scanning tool and evolved into a production secret scanner. The project lives at **[github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)** with current version **v8.30.1** (released 2026-03-21).

**Status: Feature-complete, maintenance mode.** The author announced (in v8.30+) that Gitleaks is no longer accepting new features — all future development effort is shifting to a successor project, **Betterleaks**. However, Gitleaks remains actively maintained for security patches and bugfixes.

Historical context:
- **v1-v3 (2017-2019):** Simple regex-based git-history scanner
- **v4-v7 (2019-2021):** Added entropy-based detection, custom rules support, parallel scanning
- **v8 (2021-present):** Mature feature set (TOML config, fingerprinting, baseline tolerance, pre-commit integration)
- **v8.30 (2026-03):** Last planned feature release; maintenance-only after this

Licensed under MIT.

## Key Mechanics

**Git-History-Focused Scanner:**
- Clones or reads local Git repositories
- Iterates through all commits in repository history (default: all branches)
- Examines file contents for each commit
- Applies rules (regex patterns + entropy thresholds) to detect credential-like strings
- Outputs findings with commit metadata (hash, author, email, date, line number)

**Rule Engine (TOML-based):**
- Each rule is a stanza in `.gitleaks.toml` configuration file
- Rule components:
  - Regex pattern (matches the secret format)
  - Entropy threshold (optional, flags high-entropy strings if regex too broad)
  - Keywords (optional, contextual words that raise confidence)
  - Description (what this rule detects)
- ~100 pre-built rules shipped with binary (AWS, GitHub, Stripe, Slack, etc.)
- Custom rules easily added via TOML config

**Scanning modes:**
- **Local repository:** `gitleaks git /path/to/repo`
- **Remote repository:** `gitleaks git https://github.com/owner/repo.git`
- **Directory scan:** `gitleaks dir /path/to/directory` (scans all files, not just git)
- **Stdin:** `cat logfile.txt | gitleaks stdin`

**Output:** JSON report or SARIF (Security Audit Report Format) with:
- Finding ID (fingerprint)
- Secret value
- Commit hash, author, email, date
- File and line number
- Matching rule ID
- Entropy score
- Match text excerpt

## Techniques/Protocols Used

- **Git protocol** (SSH or HTTPS for repository cloning)
- **Regex pattern matching** (core detection engine)
- **Entropy analysis** (Shannon entropy calculation for randomness detection)
- **TOML parsing** (configuration file format)
- **Go filesystem I/O** (repository traversal, file reading)

## Command-Line Switches — Quick Reference

| Flag | Purpose | Example |
|------|---------|---------|
| `-c, --config` | Use custom TOML config file | `gitleaks git --config /tmp/rules.toml` |
| `-b, --baseline-path` | Ignore findings in baseline report | `gitleaks git --baseline-path /tmp/baseline.json` |
| `--max-archive-depth` | Nested archive scanning depth (default: 0) | `gitleaks git --max-archive-depth 5` |
| `--enable-rule` | Only enable specific rule IDs (comma-separated) | `gitleaks git --enable-rule aws,github` |
| `-i, --gitleaks-ignore-path` | Path to `.gitleaksignore` file | `gitleaks git --gitleaks-ignore-path /tmp/.gitleaksignore` |
| `--exit-code` | Exit code when leaks found (default: 1) | `gitleaks git --exit-code 2` |
| `-f, --report-format` | Output format (json, csv, sarif, junit, template) | `gitleaks git --report-format json` |
| `-r, --report-path` | Output file path | `gitleaks git --report-path /tmp/findings.json` |
| `-v, --verbose` | Enable verbose scan output | `gitleaks git --verbose` |
| `-l, --log-level` | Log level (trace, debug, info, warn, error, fatal) | `gitleaks git --log-level debug` |
| `--max-decode-depth` | Recursive decoding depth (default: 0) | `gitleaks git --max-decode-depth 2` |
| `--redact` | Redact secrets from output (0-100%, default: 100%) | `gitleaks git --redact 75` |

## Subcommands

| Subcommand | Purpose |
|------------|---------|
| `git` | Scan Git repository (local or remote) |
| `dir` | Scan directory (all files, not git-specific) |
| `stdin` | Scan input from stdin (pipes, logs, etc.) |
| `completion` | Shell completion script |
| `version` | Show version |
| `help` | Show help |

## Quick Use-Case List

1. Git repository history scan (local `.git`)
2. Remote GitHub/GitLab repo scan
3. Directory/filesystem scan (non-git files)
4. CI/CD integration (pre-commit hook, GitHub Actions)
5. Custom rule configuration (TOML-based)
6. Baseline ignore list (tolerate known/approved findings)
7. Compliance scanning (audit all repos for secrets)
8. Post-compromise scan (found repo access, scan for credentials)
9. Credential rotation verification (confirm old secrets removed from history)
10. Incident response (found leak, scan for extent of exposure)
11. Stdin piping (scan logs, environment dumps, config exports)
12. Archive scanning (zip/tar files with nested git repos)

## Prerequisites

**Network/Access:**
- Git CLI installed (for remote repo cloning via `git` subcommand)
- Read access to local `.git` directory (if scanning local repo)
- Outbound HTTPS (if cloning remote repository)
- SSH keys (if using SSH URLs for Git)

**Local Setup:**
- `.gitleaks.toml` config file (optional, uses built-in rules by default)
- `.gitleaksignore` file (optional, for baseline/ignore patterns)

**Privilege level:**
- None required (runs as regular user)
- Read access to `.git` directory is sufficient

**Performance considerations:**
- Large repositories (1000+ commits) scan slower than small ones
- Entropy calculation adds overhead to rule evaluation
- Archive scanning depth (`--max-archive-depth`) can significantly increase scan time for repos with binary archives
