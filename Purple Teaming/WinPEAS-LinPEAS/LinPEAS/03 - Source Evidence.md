# LinPEAS — Source Evidence

LinPEAS is a **remote-execution tool** — the actual enumeration happens on the target Linux host; the attacker's workstation typically holds only the script itself, outputs, and analysis artifacts. Unlike tools that establish network-protocol sessions or install persistent infrastructure (e.g., Metasploit Meterpreter, Cobalt Strike Beacon), LinPEAS leaves minimal forensic footprint on the source/attacker side: a shell script file, downloaded outputs, and command-line history.

## Contents

- [LinPEAS Binary / Script Storage](#linpeas-binary--script-storage)
- [Command-Line History and Execution Artifacts](#command-line-history-and-execution-artifacts)
- [Downloaded Output Files](#downloaded-output-files)
- [Tool-Related Metadata](#tool-related-metadata)
- [Timeline and Source-to-Target Correlation](#timeline-and-source-to-target-correlation)

---

## LinPEAS Binary / Script Storage

**Artifact type:** Filesystem

The LinPEAS script itself (a single `.sh` file, typically 500-800 KB, containing bash and shell-utility calls bundled into one) must exist on the attacker's workstation. Common storage locations:

| Storage Location | Context |
|---|---|
| `~/tools/linpeas/linpeas.sh` | Attacker's dedicated tools directory (versioned with git or manual date-naming) |
| `~/Downloads/linpeas.sh` | Casual/ad-hoc download from GitHub (browser-downloaded, may have `.Z`/`.gz` extension) |
| `/opt/PEASS-ng/linpeas/linpeas.sh` | Cloned from `peass-ng/PEASS-ng` repo, integrated into a larger pentest framework |
| `/tmp/linpeas.sh` | Temporary staging for an active engagement, often deleted post-engagement |
| `~/Desktop/linpeas.sh` | Desktop shortcut/staging area for visual tools framework (less common in hands-on pentest) |

**Evidentiary value:** The presence of LinPEAS on the source machine proves the attacker *intended* to enumerate target-side privilege-escalation vectors. Filesystem timestamp analysis (creation date, last-access date via `stat` or similar) reveals:
- When the tool was downloaded/copied to the source
- Whether it was frequently re-used (multiple accesses) or a one-time download
- Whether it was staged in a temporary directory (suggesting ephemeral engagement infrastructure) or a permanent tools directory (suggesting established operations)

**SHA256 hashing:** LinPEAS script distributions can be compared against known good hashes from the official GitHub repo (`peass-ng/PEASS-ng`) to determine whether the attacker downloaded the legitimate public version or a modified/compromised variant. A mismatch (attacker hash ≠ official GitHub hash) suggests either:
- The attacker modified the script (added evasion code, disabled certain checks, etc.)
- The attacker downloaded from a compromised source (malware-injected fork, compromised web server, etc.)

## Command-Line History and Execution Artifacts

**Artifact type:** Shell history

Bash/zsh command history on the attacker's workstation reveals LinPEAS invocation patterns, flag combinations, and targeted use cases:

```bash
# Typical entries in ~/.bash_history
bash linpeas.sh > /tmp/target1_enum.txt 2>&1
bash linpeas.sh -q > target2_enum.txt
scp linpeas.sh user@192.168.1.100:/tmp/
ssh user@target "bash /tmp/linpeas.sh -j > linpeas_output.json"
```

**Evidentiary value:** Command history reveals:
- Frequency of LinPEAS use (engaged attacker running multiple recons suggests active campaign)
- Target IP addresses / hostnames (when visible in the command, e.g., `ssh user@10.0.0.5 "bash linpeas.sh"`)
- Attack patterns (e.g., `-q` quiet flag use suggests operational security awareness; HTML report generation suggests preparation of formal engagement deliverables)
- Chaining with other tools (e.g., `grep` on LinPEAS output, piping to `tee`, post-processing with `cut`/`awk` suggests forensic-aware analysis on the attacker side)

**Mitigations/Evasion:** An attacker aware of history logging can:
- Export the command to run without history: `export HISTFILE=/dev/null; bash linpeas.sh ...`
- Use `history -c` to clear history immediately after the session
- Use `ssh -t target "bash < /dev/stdin" < linpeas.sh` to run over stdin (less likely to be logged in `~/.bash_history`)

However, these evasion techniques themselves are suspicious — the *absence* of expected LinPEAS invocations in a timeline where other recon tools are active suggests log tampering.

## Downloaded Output Files

**Artifact type:** Filesystem (text, JSON, HTML files)

LinPEAS generates output in multiple formats, each typically 1-5 MB depending on target verbosity and package count. On the attacker's workstation, downloaded/exfiltrated output files indicate exactly what the attacker enumerated and when:

| Output Type | Filename Pattern | Evidence Content |
|---|---|---|
| Raw text | `linpeas_output.txt`, `target_enum.log`, `hostname_linpeas.txt` | Full raw stdout/stderr from target-side LinPEAS run, human-readable |
| JSON | `linpeas_output.json`, `findings.json` | Structured data: severity rankings, category tags, CVE cross-references |
| HTML report | `linpeas_report.html`, `enum_report_2026-08-11.html` | Standalone HTML with collapsible sections, visual severity indicators |
| Parsed subsets | `cron_findings.txt`, `sudo_findings.txt`, `kernel_vulns.txt` | Attacker-generated extracts (via `grep`, `cut`, etc.) targeting specific finding categories |

**Timeline reconstruction:**
- File creation timestamp (attacker-side exfiltration time) vs. file modification timestamp on target (when LinPEAS ran on target)
- If both timestamps are available, they reveal the time delta between target enumeration and attacker download — a long delta suggests delayed analysis or batched post-engagement processing; a short delta suggests real-time analysis during active sessions

**Content analysis:**
- Output file size reveals target complexity (large = many packages, services, users, etc.)
- Presence of multiple output files for the same target (e.g., `target_enum_v1.txt`, `target_enum_v2.txt`) suggests iterative refinement — first run was noisy, second run applied filters or deeper analysis
- JSON output presence suggests programmatic downstream processing (ingestion into a database, automated severity ranking, etc.)

## Tool-Related Metadata

**Artifact type:** Filesystem metadata

Beyond the script and outputs themselves, source-side evidence includes:

| Artifact | Collection Method | Value |
|---|---|---|
| Git repository state | `git log <linpeas-repo-path>` | If LinPEAS was cloned from `peass-ng/PEASS-ng` and not updated, `git log` shows last commit date; ancient commits = old/stale tooling |
| Modified script versions | `diff linpeas.sh.bak linpeas.sh` | If the attacker kept a backup of an unmodified LinPEAS and then modified it for specific targets, diffing reveals what was changed (evasion techniques, disabled checks, hardcoded flags) |
| Symbolic links | `ls -la ~/tools/linpeas/linpeas.sh` | If a symlink points to a central tools repo or shared drive, the symlink target reveals shared infrastructure (shared pentest team tools, centralized C2 host, etc.) |
| Access logs (if shared infrastructure) | `grep linpeas /var/log/auth.log` | If LinPEAS binary is stored on a shared samba/NFS mount or central tools server, the server's access logs show *which accounts* accessed LinPEAS and *when* — useful for attribution if multiple operators exist |

## Timeline and Source-to-Target Correlation

**Artifact type:** Cross-host timeline

Tying source-side artifacts to target-side evidence (see `04 - Target Evidence.md`) reveals the attack sequence and timing:

```
Attacker workstation timeline        Target timeline
─────────────────────────────────    ─────────────────
2026-08-11 14:23:15                 (parallel)
  linpeas.sh downloaded to ~/tools

2026-08-11 14:45:02
  ssh user@target "bash <linpeas.sh" ──────────→ 2026-08-11 14:45:03 (UTC+0)
                                                  /tmp/linpeas.sh created
                                    ────────────  2026-08-11 14:45:05
                                                  LinPEAS processes run
2026-08-11 14:47:30
  scp user@target:/tmp/linpeas_output.json . ←────── 2026-08-11 14:47:00
                                                  Output file written to /tmp
```

**Correlation value:** If an attacker's workstation and a compromised target both have forensic artifacts available:
1. Source timestamps narrow the window of LinPEAS invocation (attacker's command history → execution time)
2. Target-side process artifacts and log entries confirm *when* LinPEAS ran on the target (process creation time, auditd events, bash history)
3. File transfer logs (scp, curl, wget on target) confirm *when* the output was exfiltrated back to source

The tighter the correlation, the stronger the evidence of coordinated attack activity. A loose correlation (attacker downloaded LinPEAS weeks ago, but the target was only compromised yesterday) suggests the attacker opportunistically grabbed a pre-existing tool from their cache.

**Evasion:** Attackers can break this correlation by:
- Running LinPEAS via in-memory execution (e.g., piping the script over SSH without writing it to disk on target)
- Deleting source-side evidence immediately after exfiltration
- Using intermediate C2 infrastructure to obscure the direct attacker↔target connection (e.g., the LinPEAS output goes to a C2 server, not directly to the attacker's workstation)
- Timestomping source-side files to match target timestamps (unlikely to succeed perfectly, as timezone/clock-skew differences often leak)

The presence of LinPEAS on a source machine is a high-confidence indicator of *privilege-escalation reconnaissance intent*, even if the actual escalation was never attempted or never succeeded.
