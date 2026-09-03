# Gobuster — Source Evidence

## Command-Line History & Shell Artifacts

### Bash / Zsh History

The primary evidence trail is the shell command invocation:

```bash
# .bash_history entry
gobuster dir -u https://target.com -w /path/to/SecLists/common-paths.txt -sc 200 -o results.txt

# .zsh_history entry with timestamp
gobuster dns -d target.com -w /path/to/subdomains.txt -z -r 8.8.8.8:53
```

**Forensic value:** The command line reveals:
- Target URL/domain
- Wordlist file path
- Operational parameters (-t threads, --delay, --timeout)
- Output file location
- Mode used (dir, dns, vhost)

**Artifact preservation:**
- **Bash:** `~/.bash_history` (one entry per command, oldest first, limited to configured history size, often 1000 lines)
- **Zsh:** `~/.zsh_history` (includes timestamps, duration, session ID)
- **Fish:** `~/.local/share/fish/fish_history` (JSON format with full metadata)

**Timeline value:** Shell history timestamps (especially in zsh/Fish) correlate attack timing to other events.

---

## Wordlist Staging

If the attacker staged wordlist files locally:

```
/home/attacker/wordlists/SecLists/Discovery/Web-Content/common.txt
/home/attacker/subdomains.txt
/tmp/api-endpoints.txt
```

These files persist on-disk indefinitely unless the attacker actively deletes them.

**Forensic value:** Wordlist files directly indicate what the attacker was searching for:
- A `subdomains.txt` with 1000s of entries indicates broad subdomain reconnaissance.
- An `api-endpoints.txt` with entries like `/users`, `/payments`, `/orders` indicates targeted API discovery.

**File metadata:**
- Modification time indicates when the wordlist was last updated (correlates to attack timeline).
- File size may indicate whether it's a custom or standard SecLists wordlist.

---

## Process Artifacts

### Running Process and Command-Line Arguments

While gobuster is executing:

```bash
# Process list shows gobuster with its arguments
$ ps aux | grep gobuster
attacker 12345  45.2 8.3 102400 524288 ?  Sl  14:32   2:15 \
  gobuster dns -d target.com -w /path/to/subdomains.txt -r 8.8.8.8:53

# Linux /proc/[PID]/cmdline reveals full command
$ cat /proc/12345/cmdline
gobuster\x00dns\x00-d\x00target.com\x00-w\x00/path/to/subdomains.txt\x00-r\x00...
```

**Forensic value:** The full command line is visible while the process runs, revealing exact parameters.

**Persistence:** Only while gobuster is executing. Once terminated, it's no longer in the process list.

---

## Network Connections and Connection State

### Active Network Connections

While gobuster is running (especially in `dns` mode), the attacker's system shows active network state:

```bash
# Inbound DNS queries (dns mode)
$ netstat -tpn | grep 53
udp  0  0 192.168.1.100:54321 8.8.8.8:53 ESTABLISHED 12345/gobuster
# Multiple concurrent DNS connections (up to -t concurrency)

# Outbound HTTP connections (dir/vhost modes)
$ netstat -tpn | grep gobuster
tcp  0  0 192.168.1.100:54321 203.0.113.50:443 ESTABLISHED 12345/gobuster
tcp  0  0 192.168.1.100:54322 203.0.113.50:443 ESTABLISHED 12345/gobuster
# Multiple connections (up to -t concurrency, default 10)
```

**Forensic value:**
- Reveals target IP/port
- Shows concurrency level (number of open sockets)
- Indicates protocol (DNS vs. HTTP/HTTPS)

**Persistence:** While gobuster runs. After termination, TIME-WAIT sockets may persist 30–120 seconds.

---

## Output Files

### Saved Results Files

If the attacker used `-o` flag:

```bash
# Plain text results file
/home/attacker/results.txt
https://target.com/admin (Status: 200)
https://target.com/api (Status: 301)
https://target.com/backup (Status: 200)

# DNS results
/home/attacker/dns-results.txt
api.target.com: 192.0.2.50
admin.target.com: 192.0.2.50
backup.target.com: 192.0.2.51

# Vhost results
/home/attacker/vhost-results.txt
https://target.com (Status: 200, Host: api.target.com)
https://target.com (Status: 200, Host: admin.target.com)
```

**Forensic value:** Very high — directly shows enumeration results and discovered resources.

**Format:** Plain text (one result per line), not JSON/CSV like ffuf's default. Easier for manual reading but harder for automated parsing.

---

## DNS Resolver Configuration

### Resolver Cache and Query Logs

If gobuster used DNS mode (`dns`), the attacker's DNS resolver logs queries:

```bash
# systemd-resolved logs (modern Linux)
$ journalctl -u systemd-resolved | grep target.com
Aug 12 14:32:45 attacker-box systemd-resolved[1234]: Resolved api.target.com. → 192.0.2.50
Aug 12 14:32:45 attacker-box systemd-resolved[1234]: Resolved admin.target.com. → 192.0.2.50
Aug 12 14:32:45 attacker-box systemd-resolved[1234]: Resolved backup.target.com. → NXDOMAIN

# dnsmasq logs (if used)
grep "target.com" /var/log/dnsmasq.log

# DNS query logs (if custom resolver with logging is used)
/var/log/bind/query.log  # ISC BIND
/var/log/powerdns-admin.log  # PowerDNS
```

**Forensic value:** DNS logs reveal exactly which subdomains were queried, even if they didn't resolve.

**Caveat:** Only relevant if DNS mode (`dns`) is used. For `dir`/`vhost` modes (HTTP-based), no DNS queries occur unless the target domain is first resolved to an IP.

---

## DNS Resolver Selection

If gobuster was run with `-r` (custom resolver):

```bash
# Command history shows the resolver used
grep "gobuster dns" ~/.bash_history | grep "\-r"
# Output: gobuster dns -d target.com -w subdomains.txt -r 10.0.0.1:53
```

**Forensic value:** Indicates whether the attacker used a corporate/internal DNS server (10.0.0.1) or public DNS (8.8.8.8), revealing network reconnaissance strategy.

---

## Binary Installation and Versioning

### Gobuster Binary Location

```bash
# Binary locations
/home/attacker/tools/gobuster
/usr/local/bin/gobuster  (if installed system-wide)
/home/attacker/go/bin/gobuster  (if compiled from source)

# Version string
$ gobuster -h | grep Version
gobuster 3.5.0 by OJ Reeves (@TheColonial)
```

**Forensic value:** The binary's presence indicates gobuster was used at some point. Compilation date/binary timestamp may indicate deployment timeline.

---

## Memory Forensics (Live System)

### In-Memory Artifacts

While gobuster is running, memory contains:
- Entire wordlist (potentially 10–100 MB)
- All discovered results (IP addresses, subdomains, HTTP status codes)
- Active network connections and sockets
- Command-line arguments
- Internal state (current wordlist position, thread pool state)

**Forensic value:** A memory dump would reveal:
- Exact target being scanned
- Wordlist loaded
- Current results as of the dump time
- Concurrency level and thread state

**Persistence:** Only during execution. Post-execution memory is overwritten.

---

## Shell Environment Variables

### Proxy and DNS Configuration

The attacker's shell environment may reveal proxy/DNS settings used:

```bash
# Environment variable check
$ env | grep -i proxy
HTTP_PROXY=http://10.0.0.1:8080
HTTPS_PROXY=http://10.0.0.1:8080

# DNS resolution behavior (if custom)
$ cat /etc/resolv.conf
nameserver 10.0.0.1
nameserver 8.8.8.8
```

**Forensic value:** Indicates whether gobuster's traffic was proxied through a company proxy or direct internet.

---

## Summary: Artifact Priority (Source Side)

**Tier 1 (Strongest Signals):**
1. Shell history (`~/.bash_history`, `~/.zsh_history`)
2. Output results files (`results.txt`, `dns-results.txt`) if saved
3. Wordlist files (if staged locally)

**Tier 2:**
4. DNS resolver logs (if `dns` mode used)
5. Network connection state (while running)
6. Process arguments (`/proc/[PID]/cmdline`)
7. DNS resolver configuration (if custom resolver with logging)

**Tier 3 (Weaker/Transient):**
8. Binary presence (easily installed/uninstalled)
9. Environment variables (proxy/DNS config)
10. Memory artifacts (only while running)

