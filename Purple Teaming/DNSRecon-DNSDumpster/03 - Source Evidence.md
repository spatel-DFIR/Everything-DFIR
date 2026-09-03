# DNSRecon-DNSDumpster — Source Evidence

## Contents
- [DNSRecon Source Evidence](#dnsrecon-source-evidence)
- [DNSDumpster Source Evidence](#dnsdumpster-source-evidence)
- [Correlation and Timeline Building](#correlation-and-timeline-building)

---

## DNSRecon Source Evidence

DNSRecon's footprint on the attacker's host is process/file-based — the tool itself is a Python interpreter running `dnsrecon.py` and its supporting libraries, leaving artifacts in shell history, process logs, and output files. **No service, no persistence mechanism, no network-level listener.**

### Process Creation and Command-Line Logging

| Log | Event ID | Signal |
|---|---|---|
| Sysmon | 1 (Process Create) | Full command line — `python -m dnsrecon -d target.com -t std`, the target domain, enum type (`-t brt`, `-t axfr`, etc.), any Shodan API key if passed via `-s` |
| Security | 4688 (Process Creation) | Same, **only if** "Include command line in process creation events" enabled |
| ps/ps aux (Linux/macOS) | N/A | Running process can be observed with `ps aux \| grep dnsrecon` or `pgrep -a` |

DNSRecon's Python entry point (`dnsrecon.py` or wrapped as a `dnsrecon` console script) is reliably captured in Sysmon 1 alongside the target domain and enum type, making it the strongest source-side signal.

### Shell / Console History

| Shell | Artifact |
|---|---|
| PowerShell | `ConsoleHost_history.txt` under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\` — persists across sessions |
| bash/zsh | `~/.bash_history` or `~/.zsh_history` — typically persistent by default |
| Interactive cmd.exe | No persistent history unless captured elsewhere (Sysmon 1, process logging) |

The full invocation (domain, wordlist path, thread count, output file) is present in shell history if the operator ran DNSRecon interactively.

### Output Files Left Behind

| Artifact | Notes |
|---|---|
| Operator-specified output file (e.g., `-o target_recon.txt`, `-oX results.xml`) | DNSRecon supports multiple output formats: plaintext, XML, JSON. Filenames follow operator convention but often include the target domain name or "recon" in the filename |
| Wordlist files used for brute force (`-D /path/to/wordlist.txt`) | If a custom wordlist was specified, that file path appears in the command line; the wordlist itself is rarely deleted by DNSRecon (it's an input, not a generated artifact) |
| Crash or error logs | If DNSRecon crashes mid-run, some platforms generate a Python traceback to stderr or to a temp file |

### Local Network-Connection State

```bash
netstat -ano | grep -E ':53|:5053'  # Windows
ss -tlnp 2>/dev/null | grep -E ':53|:5053'  # Linux
```

While DNSRecon is running, outbound UDP/TCP connections to **port 53** (DNS) or **port 5053** (DNS over TLS) are visible in `netstat`/`ss` or via EDR network telemetry. The destination IPs are the target domain's authoritative nameservers (discovered via NS lookup). Because DNS queries are typically quick, catching this in a live `netstat` snapshot requires tight timing; EDR products with historical connection logging are more reliable.

### Cached Credential Material

If a Shodan API key was passed via the `-s` switch:
- Command line captures the API key in plaintext — visible in Sysmon 1 and shell history
- The key is **not** obfuscated by DNSRecon (unlike AdFind's optional `-encpwd`)
- This is the operator's single Shodan account credential, useful for lateral-account compromise if captured

### Memory Forensics

DNSRecon is typically a short-lived process (seconds to minutes). If captured in a live memory dump or crash dump, the Python process's command-line arguments (visible via PEB.ProcessParameters.CommandLine in tools like Volatility) are the highest-value recoverable artifact.

---

## DNSDumpster Source Evidence

DNSDumpster's footprint is **browser-based** — all traffic goes to `dnsdumpster.com` or `api.dnsdumpster.com`, leaving HTTP access logs and browser history, but **zero DNS queries originating from the operator's IP** (the target's DNS infrastructure is blind to this activity).

### Browser History

| Browser | Artifact |
|---|---|
| Firefox | `places.sqlite` or `places.sqlite-wal` under `~/.mozilla/firefox/[profile]/` — contains full URL history including `https://dnsdumpster.com` searches and timestamps |
| Chrome/Chromium | `History` database under `~/.config/google-chrome/Default/` or `AppData\Local\Google\Chrome\User Data\Default\` — same URL history with visit timestamps |
| Edge | `History` database under `AppData\Local\Microsoft\Edge\User Data\Default\` |
| Internet Explorer | `index.dat` (legacy) or Windows 10+ WebCache databases under `AppData\Local\Microsoft\Windows\WebCache\` |

Browser history typically includes the **full URL searched** and **timestamp**, and persists indefinitely by default. A search for `dnsdumpster.com/?domain=target.com` in browser history is a permanent record of the reconnaissance, even if the operator clears shell history or deletes files.

### HTTP Access Logs (Network-Level)

| Log Source | Artifact |
|---|---|
| Proxy/firewall HTTPS logs (if deployed) | Outbound HTTPS to `api.dnsdumpster.com` or `dnsdumpster.com` (port 443), with timestamps and destination IP (HackerTarget's infrastructure IP) |
| EDR/endpoint network telemetry | Outbound HTTPS connection to `dnsdumpster.com` domain, even if the proxy doesn't log packet-level details |

Organizations with outbound HTTPS logging via a proxy or endpoint security product will see connection attempts to `dnsdumpster.com`. The target domain name is **not** visible at the network layer (it's encrypted in the HTTPS request body); only the destination domain/IP is logged.

### Local Network-Connection State

```bash
netstat -ano | grep 443
ss -tlnp 2>/dev/null | grep 443
```

A live outbound TCP connection from the operator's host to `api.dnsdumpster.com` or `dnsdumpster.com` (typically resolved to HackerTarget's IP, e.g., 104.21.x.x) on port 443 while the request is in flight. Connection is typically brief (sub-second for API calls).

### Output Files and Clipboard

If the operator used the web form:
- Results are displayed in the browser (no file written by the site itself)
- Operator may copy/paste results to a local file (filename/content are operator-chosen)
- Saving the HTML page via `Ctrl+S` would save a local snapshot of the results page

If the operator used the API and piped output to a file:
```bash
curl "https://api.dnsdumpster.com/v2/dns-lookup/target.com" > target_dns.json
```
- Output file (`target_dns.json` in this example) contains JSON-formatted DNS records from HackerTarget's database

### Process Logging for API Calls

If DNSDumpster API queries are made via `curl`, `wget`, or a custom script:
- `curl` or `wget` process creation is logged (Sysmon 1, Security 4688)
- The target domain may appear in the command line: `curl "https://api.dnsdumpster.com/v2/dns-lookup/target.com"`
- No Shodan key or authentication is typically required, so credential exposure is minimal

---

## Correlation and Timeline Building

The asymmetric detection profile is the key insight: **DNSRecon leaves a wider local footprint but a narrow target-side footprint** (DNS query logs), while **DNSDumpster leaves minimal local footprint** (if browser history is cleared) **and zero target-side footprint** (the target's DNS infrastructure sees nothing).

**On source (attacker's host):**
- Sysmon 1 / Security 4688 process creation for `python -m dnsrecon` or `curl` → timestamp
- Shell history for the invocation → exact command and target domain
- Output files → evidence of enumeration scope
- Browser history for `dnsdumpster.com` → persistent even after cache/history clear attempts (can be recovered via forensic carving)

**On target (DNS infrastructure):**
- DNS query logs for the target domain (if logging enabled) showing queries from the operator's source IP
- Firewall/NSM logs showing UDP/TCP port 53 traffic from an external/unexpected source
- Sysmon/EDR on domain controllers (if deployed there) showing no unusual activity (LDAP searches won't spike just from DNS reconnaissance)

**Timeline correlation:** Source host process creation `[time T]` for `dnsrecon -d target.com` matches against target DNS query logs showing high query volume from that source IP in the same few seconds (T to T+30s, depending on enum type and wordlist size).
