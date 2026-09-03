# ffuf — Source Evidence

## Command-Line History & Shell Artifacts

### Bash / Zsh History

The primary evidence trail on the attacker's host is the command-line invocation itself:

```bash
# .bash_history or .zsh_history entry
ffuf -u https://target.com/FUZZ -w /path/to/SecLists/common-paths.txt -mc 200

# Timeline: command executed, timestamp in shell history
# This entry records: target URL, wordlist path, match criteria
```

**Forensic value:** The command line directly names the target and the wordlist file used. If the wordlist is accessible on the attacker's disk, you can enumerate exactly what paths were tested against the target.

**Artifact details:**
- **Bash:** `~/.bash_history` (one entry per command, oldest first)
- **Zsh:** `~/.zsh_history` (stores command with timestamp and execution duration)
- **Fish:** `~/.local/share/fish/fish_history` (JSON-formatted, includes command duration)

**Timestamp preservation:** All three shells preserve timestamps via the shell's own internal history mechanism, independent of the OS's file-system modification times.

---

## Wordlist Caches and Temporary Files

### Wordlist Staging

If the attacker staged wordlists on the source machine:

```
/home/attacker/wordlists/SecLists/Discovery/Web-Content/common.txt
/home/attacker/SecLists/Discovery/Web-Content/raft-small-directories.txt
/tmp/custom_subdomains.txt
```

These files are **not automatically deleted** by ffuf — they persist until the attacker manually removes them or the system's `tmp` cleanup policy (typically 30 days) expires them.

**Forensic value:** The wordlist files themselves are the strongest indicator of what the attacker was searching for. A wordlist full of API endpoint names (`/api/v1/users`, `/api/v2/payments`, etc.) tells a blue team exactly which API surface the attacker prioritized.

---

## Process Artifacts

### Process List and Running Processes

While ffuf is executing, it appears in the process list:

```
$ ps aux | grep ffuf
attacker 12345  25.3 15.2 123456 1024000 ?  Sl  14:32   0:45 ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt

# Arguments visible in:
# - ps aux (parent shell passes them)
# - /proc/[PID]/cmdline (raw command line with null separators)
```

**Forensic value:** The running process reveals the exact command line, including target URL and wordlist path. Even if shell history is cleared, an in-memory snapshot via `/proc/[PID]/cmdline` (on Linux) or similar (`ps aux` dump) captures the full invocation.

**Persistence:** Only while ffuf is executing. Once the process terminates, it's gone from the process list (but shell history remains).

---

## Network Connections and Connection State

### Network Stack State

While ffuf is running, each goroutine (worker thread) holds an open TCP connection. On the source machine:

```bash
# Active connections while ffuf is running
netstat -tpn | grep ffuf
tcp  0  0 192.168.1.100:54321 203.0.113.50:443 ESTABLISHED 12345/ffuf

# Multiple concurrent connections (default 40 threads = up to 40 simultaneous sockets)
netstat -tpn | grep -c "203.0.113.50"
# Output: 38  (currently open)

# Per-connection tracking in /proc/net/tcp (Linux)
cat /proc/net/tcp | grep ffuf | wc -l
# Output: 38
```

**Forensic value:** Live network connections reveal the target and the concurrency level. An unusually high number of connections to a single destination from a single source process is a red flag for automated scanning.

**Persistence:** While ffuf is running. After termination, TIME-WAIT sockets may persist for 30–120 seconds (OS-dependent, configurable via `net.ipv4.tcp_fin_timeout`).

---

## DNS Resolution Artifacts

### Resolver Cache and Query Logs

If the attacker fuzzes subdomains (e.g., `-H "Host: FUZZ.target.com"`), the source machine's DNS resolver attempts to resolve them:

```bash
# systemd-resolve (common on modern Linux)
journalctl -u systemd-resolved | grep target.com
# Output: Resolved admin.target.com, api.target.com, backup.target.com, ... (only if attempted)

# dnsmasq logs (if used as a forwarder)
grep "target.com" /var/log/dnsmasq.log

# OS-level DNS cache (varies by OS)
# macOS: log show --predicate 'eventMessage contains "target.com"'
# Windows: Get-DnsClientCache | Select-String "target.com"
```

**Forensic value:** DNS logs reveal which subdomains the attacker probed, even if none of them resolved. A burst of failed DNS queries to `sub1.target.com`, `sub2.target.com`, ... indicates subdomain fuzzing.

**Caveat:** Modern systems cache DNS at multiple levels (OS resolver, systemd-resolved, browser cache, etc.). The strongest signal is in the OS-level resolver logs.

---

## Output Files

### Saved Results

If the attacker saved results via `-o` or `-od`:

```bash
# JSON output file (contains every response with metadata)
/home/attacker/results/target_com_fuzz.json
{
  "results": [
    {
      "input": {"FUZZ": "admin"},
      "position": 0,
      "status": 200,
      "length": 4521,
      "words": 213,
      "lines": 87,
      "duration": 124000000,
      "resultfile": ""
    },
    ... (one object per discovered path)
  ]
}

# CSV output
/home/attacker/results/target_com_fuzz.csv
url,status,size,words,lines,duration
https://target.com/admin,200,4521,213,87,124000000
https://target.com/api,200,3240,156,64,98000000

# HTML report
/home/attacker/results/target_com_fuzz.html
```

**Forensic value:** Extremely high. The output files contain:
- Every path successfully discovered (exact list of what the target was hiding).
- Response sizes, word counts, and HTTP status codes for each discovery.
- Execution timestamps (embedded in JSON metadata).
- Target URL (clearly stated in every result record).

**Artifact persistence:** Indefinite, unless the attacker actively deletes the files. Output files are often left behind during rapid offensive operations (time pressure, mistakes, forgotten cleanup).

---

## Tool Binary and Installation

### Binary Location

The ffuf binary itself:

```bash
# Default installation via compiled release
/home/attacker/tools/ffuf
/usr/local/bin/ffuf  (if installed system-wide via package manager)

# Compiled from source
/home/attacker/go/src/github.com/ffuf/ffuf/ffuf

# Modified binary (recompiled with custom behavior)
sha256sum ffuf  # Should match official release hash if unmodified
```

**Forensic value:** The binary's presence on-disk indicates ffuf was installed or staged. If recompiled, custom strings or timestamps may reveal when the compilation occurred.

---

## Memory Forensics (Live System Only)

### In-Memory Artifacts

While ffuf is running, memory contains:

- The entire wordlist (potentially 100MB+ if a large SecLists file is loaded).
- All matched results (status codes, response bodies, wordlist entries).
- Active network connections and their state.
- Command-line arguments (visible in `/proc/[PID]/cmdline`).

**Forensic value:** A memory dump of the ffuf process during execution would reveal:
- Exact target being scanned.
- Complete wordlist loaded.
- Current results as of the dump time.
- Concurrency level and thread state.

**Persistence:** Only during execution. Post-execution memory is overwritten by other processes.

---

## Summary: Artifact Priority

**Tier 1 (Strongest Signals):**
1. Shell history (`~/.bash_history`, `~/.zsh_history`)
2. Output files (`results.json`, `results.csv`) if saved
3. Wordlist files (if staged locally)

**Tier 2:**
4. DNS resolver logs (if subdomain fuzzing)
5. Network connection state (while running)
6. Process arguments (`/proc/[PID]/cmdline`)

**Tier 3 (Weak/Transient):**
7. Binary presence (easily installed/uninstalled)
8. Memory artifacts (only while running)

