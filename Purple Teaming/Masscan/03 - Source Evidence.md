# Masscan — Source Evidence

Evidence left on the **scanning/operator** host. Masscan writes no session log of its own beyond whatever output file the operator explicitly requested with `-o*` — there's no built-in audit trail. What's recoverable here splits into two categories: generic OS/shell artifacts of running any command-line tool, and artifacts specific to masscan's need for **raw packet access**, which is a materially bigger footprint than a normal userland network tool leaves.

## Contents
- [Shell History](#shell-history)
- [Live Process State and Privilege Footprint](#live-process-state-and-privilege-footprint)
- [Output Files on Disk](#output-files-on-disk)
- [Local Network/Interface State](#local-networkinterface-state)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Installation Artifacts](#installation-artifacts)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Full invocation, including target ranges, exclude-file paths, and any `--http-user-agent`/`--hello-string` customization used for evasion |
| zsh | `~/.zsh_history` | Same content, plus timestamps by default if `EXTENDED_HISTORY` is set in `.zshrc` |
| root's history | `/root/.bash_history` or equivalent | Masscan requires raw-socket privilege, so the invoking command is very often run as **root** (directly, or via `sudo`) — check root's history specifically, not just the operator's unprivileged account, and cross-reference with `sudo` logs (`/var/log/auth.log` or `/var/log/secure`) for exactly which unprivileged user escalated |

A config file passed with `-c` moves the target/port/rate specification out of the command line entirely — if the operator used `-c myscan.conf` rather than inline flags, the shell history alone won't reveal scope; the config file itself (see [Output Files on Disk](#output-files-on-disk)) becomes the primary artifact.

## Live Process State and Privilege Footprint

```bash
ps aux | grep -i masscan
```

Unlike a normal userland scanner, masscan's process typically runs with **elevated privileges** (root, or `CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux via `setcap`) because it crafts and injects raw Ethernet frames rather than using OS sockets. On Linux this is directly visible:

```bash
# Confirm root/effective UID of a running masscan process
ps -o pid,user,euid,cmd -C masscan

# If run unprivileged with capabilities granted directly to the binary
getcap $(which masscan)
```

A `getcap` result showing `cap_net_raw,cap_net_admin+eip` on the masscan binary is itself a durable artifact independent of *when* the tool last ran — it shows the binary was deliberately provisioned for raw-packet operation on this host at some point, even if the process isn't currently running.

## Output Files on Disk

| Artifact | Notes |
|---|---|
| `-oX`/`-oJ`/`-oG`/`-oL`/`-oB` output file | Whatever path the operator specified — mtime brackets scan completion (or the last flush before a Ctrl-C), and the file's own content directly documents scope (targets, ports) and results |
| `paused.conf` | Written automatically to the **current working directory** on Ctrl-C — its mere presence indicates an interrupted scan, and its content is a full config dump (targets, ports, rate, exclude file path, resume index) even if the operator never intended to keep a record |
| Custom `-c` config file | If the operator scripted the scan via a config file rather than flags, this file is a complete, human-readable record of the scan plan and typically persists on disk after the scan completes |
| `--pcap FILE` | If used, a full libpcap capture of everything masscan *received* during the scan — a byte-for-byte record of every reply from every target |
| `/etc/masscan/masscan.conf` | The default config masscan loads on every invocation before anything else — if present and populated (e.g. with a standing `excludefile` entry), it reveals a host that's set up for **repeated, routine** scanning rather than a one-off run |

## Local Network/Interface State

| Artifact | Command | Notes |
|---|---|---|
| Interface/adapter selection | `masscan --iflist` (if re-run), or `ip link` / `ifconfig` history | If `--adapter-ip`/`--source-ip` spoofing was used (see `01 - Overview.md`), the spoofed IP itself may show up transiently in `ip addr`/ARP tables on the local segment during the scan window |
| Firewall rules | `iptables -L -n` / `pf` rule listing | A `DROP` rule targeting a specific high port (e.g. `--dport 61000 -j DROP`) that has no other plausible business purpose is a strong indicator of the `--source-port` banner-grab workaround documented in `01 - Overview.md` and `02 - Hands-On Use Cases.md` — check `iptables-save` output or the firewall's own change log for when the rule was added |
| Live socket/packet state | `ss -a`, or a live `tcpdump`/`dumpcap` capture on the scanning interface | While masscan is actively transmitting, an extremely high volume of outbound SYNs from one process (visible via `ss -tnp` only for the *local OS's* own sockets — masscan's raw-socket traffic won't show up in normal `ss`/`netstat` output at all, since it never opens OS-level TCP sockets for the scan itself) |

## OS-Level Audit Trail

If `auditd` is running with syscall auditing enabled:

```bash
ausearch -x masscan 2>/dev/null
# or, if a rule watches raw-socket creation specifically:
ausearch -k raw_socket_create 2>/dev/null
```

Masscan's use of raw sockets (`socket(AF_PACKET, ...)` on Linux, or libpcap's own device-open call) is itself a distinctive `execve`/`socket` syscall pattern worth a dedicated audit rule on any host expected to run offensive tooling — this survives a shell-history wipe since it's captured at the kernel level.

## Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Package/binary presence | `which masscan`, `dpkg -l masscan` / `rpm -q masscan` (if installed via package manager), or `find / -iname masscan -type f 2>/dev/null` | Confirms the binary exists and where; a source-built copy (`git clone` + `make`) leaves a full checkout directory instead of a package-manager entry |
| Git checkout evidence | `.git/logs/HEAD`, `git log` inside a cloned `masscan/` directory | If built from source, commit history/dates pin the exact revision — relevant because packet-template details (see `04 - Target Evidence.md`) are stable across the project's history but binary hashes/build artifacts are not |
| Build artifacts | `masscan` binary's own mtime, and any `Makefile`/`bin/` directory left from a `make` build | mtime provides an upper bound on "when this copy was built/installed," independent of shell history |

## Memory Forensics

If the operator box is seized/imaged:
- Process memory of a running `masscan` process contains the full in-flight configuration — target ranges, exclude ranges, and the SipHash entropy/seed value used for that run's cookie generation and permutation — even if none of it was passed via a now-history-wiped command line.
- Because masscan holds its transmit and receive threads' state in a small number of long-lived structures (not per-connection heap churn the way a stateful scanner would), a memory snapshot taken mid-scan is unusually likely to still contain the resolved target-range and port-list data structures intact, rather than fragments.

## Timeline Correlation Value

The source side alone rarely proves intent or scope with confidence — its value is **correlating against the target side**. A `paused.conf`/output-file mtime or an `auditd` raw-socket-creation timestamp on the scanning host, matched against a burst of SYNs with the fixed packet fingerprint (TTL 255 / DF clear / window 1025 / single MSS option) arriving at a target-side sensor in `04 - Target Evidence.md`, is what turns "this host has masscan installed" into "this host performed this specific scan against this specific range in this specific window."
