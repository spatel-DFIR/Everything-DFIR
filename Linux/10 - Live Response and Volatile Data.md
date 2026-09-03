# Live Response and Volatile Data

The run-first commands on a live host: processes, the `/proc` goldmine, network state, open files, fileless/deleted-binary hunting, and firewall posture. This tier is where you catch the things disk forensics can't see — a process running from a binary that's already been deleted, a payload that exists only in `/dev/shm` or a `memfd`, an `LD_PRELOAD` injected into a live process, a socket a rootkit is hiding. All of it is destroyed the instant the host reboots, so live response is both the most fragile evidence and often the most incriminating.

> 🔴 Capture volatile state *before* you image or reboot, and follow the order of volatility (RAM → `/proc` → network → sessions → disk). The single highest-value live-only artifact is a running process whose `exe` is `(deleted)` or `memfd:` — self-deleting or fileless malware that you can still recover from `/proc/PID/exe` while it runs, but not one second after it exits.

> ⚠️ **On Alpine / minimal containers the tools are BusyBox** — `ps`, `ss`, `netstat`, `find`, `stat` are stripped-down and reject GNU flags (`ps -eo …`, `find -newermt`, `ss -p` may fail or lack detail), and `lsof`/`ss` may be **absent** entirely. `/proc` is always there, though — so on a BusyBox host lean on raw `/proc` (`cat /proc/*/cmdline`, `ls -l /proc/*/exe`, `cat /proc/net/tcp`) rather than the userland wrappers, or copy static binaries in.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Order of Volatility](#order-of-volatility)
- [Processes](#processes)
- [The proc Goldmine](#the-proc-goldmine)
- [Injected Code and Hidden Processes](#injected-code-and-hidden-processes)
- [Fileless and Deleted Binaries](#fileless-and-deleted-binaries)
- [Network Connections](#network-connections)
- [Decoding proc net tcp Offline](#decoding-proc-net-tcp-offline)
- [Firewall and Proxy State](#firewall-and-proxy-state)
- [Open Files and Handles](#open-files-and-handles)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Process tree with args
ps -eo pid,ppid,user,stat,start,cmd --forest

# Established + listening sockets mapped to processes
ss -tunap

# Deleted-but-running executables (self-deleting malware)
ls -l /proc/*/exe 2>/dev/null | grep deleted

# Processes running from temp/memory
ps auxww | grep -Ei "/tmp|/dev/shm|memfd|/run/user"

# Unlinked files still held open
lsof +L1

# Listeners on odd/high ports
ss -ltnp
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Self-deleting / fileless malware? | `ls -l /proc/*/exe \| grep -E 'deleted\|memfd'` |
| What's a process *really* running? | `/proc/PID/cmdline`, `/proc/PID/exe` (defeats fake `ps` name) |
| Injected shellcode/code? | anon `rwxp` region in `/proc/PID/maps` |
| A rootkit hiding a process? | `/proc` walk vs `ps` (PID in `/proc`, not in `ps`) |
| Injected library (`LD_PRELOAD`)? | `/proc/PID/environ`; deleted `.so` in `map_files` |
| C2 / backdoor listener? | `ss -tulnp` → binary in `/tmp`/`/dev/shm` |
| Who spawned the suspect? | `/proc/PID/stat` field 4 (PPID); parent-hunt |
| Firewall/proxy evasion? | `nft list ruleset`; proxy env vars |
| Recover a process's memory? | `gcore <PID>`; `/proc/PID/mem` + `maps` |
| Capture everything before reboot? | structured order-of-volatility dump (below) |

## Order of Volatility

Capture most-volatile first — each step down survives longer:

1. **RAM** (full memory image — see Memory Forensics note).
2. **`/proc`** live process state (cmdline, exe, maps, fd, environ).
3. **Network** connections + listening sockets + ARP.
4. **Logged-in users** and running processes.
5. **Disk** (image last).

```bash
# Baseline context first
date -u; uptime; who; w; hostname; id
```

## Processes

```bash
# Full listing (wide, don't truncate args)
ps auxww

# Tree view
pstree -ap

ps -eo pid,ppid,user,cmd --forest

# Suspicious interpreters / tooling
ps auxww | grep -Ei "curl|wget|nc |ncat|socat|bash -i|python|perl|/dev/tcp"

# Zombies and orphans (PPID 1 for a non-daemon is odd)
ps auxww | awk '$8 ~ /Z/ || $3 == 1'

# Fileless / in-memory execution
ps auxww | grep -Ei "/dev/shm|/tmp|memfd|/run/user"

# Privileged processes
ps -eo pid,ppid,user,cmd | awk '$3=="root"'
```

🔴 A process whose name mimics a kernel thread (`[kworker/...]`) but has a real command line, runs from `/tmp`/`/dev/shm`, or has PPID 1 without being a legitimate daemon, deserves a full `/proc` workup.

## The proc Goldmine

`/proc/<PID>/` exposes everything about a live process — the single richest live-forensics source. Only exists on the running host.

```bash
# True command line (defeats fake ps names)
cat /proc/<PID>/cmdline | tr '\0' ' '; echo

# Backing executable (resolves even if deleted from disk)
ls -l /proc/<PID>/exe

cp /proc/<PID>/exe /tmp/recovered_bin      # recover the binary

# Working directory
ls -l /proc/<PID>/cwd

# Environment (LD_PRELOAD, injected vars, creds)
cat /proc/<PID>/environ | tr '\0' '\n'

# Open file descriptors (0 stdin,1 stdout,2 stderr, sockets, files)
ls -la /proc/<PID>/fd/

# Memory maps (loaded libs, injected/anon regions, deleted maps)
cat /proc/<PID>/maps

# Loaded shared objects as files
ls -la /proc/<PID>/map_files/

# Status (UIDs, capabilities, parent, threads)
cat /proc/<PID>/status

# Namespace / chroot detection (containers, jailed processes)
ls -la /proc/<PID>/root

# Parent PID from stat
awk '{print $4}' /proc/<PID>/stat
```

**Parent-hunting** (find who spawned a suspect, incl. short-lived parents):

```bash
# Parent of a PID
ps -auxww | grep "$(awk '{print $4}' /proc/<PID>/stat)" | grep -v grep | awk '{print $11,$12}'

# Hunt the short-lived parent of a "sleep 1" style loader
ps -auxww | grep "$(awk '{print $4}' /proc/$(ps -auxww | grep "sleep 1" | grep -v grep | awk '{print $2}')/stat)" | awk '{print $11,$12}'
```

**Network state from `/proc`** (per-process, hex little-endian addresses):

```bash
cat /proc/<PID>/net/tcp        # local/remote addr:port in hex, little-endian

cat /proc/<PID>/net/arp
```

The IP/port fields are little-endian hex — convert them (see "Decoding proc net tcp Offline" below, or CyberChef's *Swap endianness* → *Change IP format* recipe).

## Injected Code and Hidden Processes

🔴 Two live-only rootkit/injection tells that `ps` and `ls` alone won't surface:

```bash
# 1. Injected code: anonymous EXECUTABLE (rwxp) memory with NO file backing
#    Legit code is r-xp from a .so/binary; rwxp anon = shellcode / runtime-patched code
for m in /proc/[0-9]*/maps; do
  grep -Eq 'rwxp .* 0[[:space:]]+0?$' "$m" && echo "RWX-anon in ${m%/maps}: $(cat ${m%maps}comm 2>/dev/null)"
done

# 2. Hidden process: a PID in the /proc walk but hidden from ps (LKM rootkit)
comm -23 <(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n) \
         <(ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n)

# 3. What a suspect thread is doing right now
cat /proc/<PID>/wchan; echo; cat /proc/<PID>/syscall 2>/dev/null

# 4. Dump the process image for strings/YARA
gcore -o /evidence/core <PID> 2>/dev/null    # or read /proc/<PID>/mem guided by maps
```

🔴 An `rwxp` anonymous region is classic in-memory code injection; a PID visible in `/proc` but not in `ps` is a kernel-rootkit-hidden process — escalate to the LKM and Memory notes.

## Fileless and Deleted Binaries

```bash
# Every deleted-but-running executable
ls -l /proc/*/exe 2>/dev/null | grep deleted

# Deleted files still open (recover from the fd)
lsof +L1

# Deleted shared objects still mapped (injected libs)
ls -la /proc/*/map_files/* 2>/dev/null | grep "\.so" | grep "(deleted)"

# Full per-PID deleted-.so + LD_PRELOAD workup
for pid in /proc/[0-9]*; do
  n=$(basename "$pid")
  if ls -la "$pid/map_files/" 2>/dev/null | grep -q "\.so.*(deleted)"; then
    echo "===== PID $n ====="
    ps -p "$n" -o user,pid,ppid,cmd --no-headers
    ls -la "$pid/map_files/" | grep "\.so" | grep "(deleted)"
    tr '\0' '\n' < "$pid/environ" 2>/dev/null | grep -E "LD_PRELOAD|LD_LIBRARY"
  fi
done

# memfd-backed processes (classic fileless technique)
ls -l /proc/*/exe 2>/dev/null | grep -i memfd

# Processes using /dev/shm objects
fuser -v /dev/shm/* 2>/dev/null
```

🔴 `memfd:` or `(deleted)` as a process's `exe`, plus any deleted `.so` in `map_files`, is fileless malware — recover the artifact from `/proc` immediately, it's gone on process exit.

## Network Connections

```bash
# All sockets + process (modern, preferred)
ss -tunap

# Listeners only (backdoors)
ss -ltunp

netstat -tulnp

# Established connections
ss -antp | grep ESTAB

# Exclude loopback to focus on external
ss -tunap | grep -v "127.0.0.1"

# Process <-> port
ss -ltnp | grep :4444

# Map ports to processes (fuller)
lsof -Pni

lsof -i :80

lsof -i @10.0.0.5

# ARP / neighbors (local discovery)
arp -a

ip neigh

# Routing + interfaces + stats
ip route; route -n

ip a; ip -s link

# Suspicious patterns
ss -ltnp | awk '$4 ~ /:[0-9]{5}/'          # high random ports

ps aux | grep -E "nc|netcat|ncat|socat|bash -i"
```

🔴 A listener on a high/odd port bound to a binary in `/tmp`/`/dev/shm`, an outbound connection to an unfamiliar IP from an unexpected process, or `ss`/`netstat`/`ps` disagreeing (rootkit hiding a socket) are the top network reds.

## Decoding proc net tcp Offline

When you can't reach CyberChef, decode the little-endian hex `addr:port` from `/proc/*/net/tcp` with awk. Column 2 = local, column 3 = remote.

```bash
# Decode the REMOTE endpoint of each connection (col 3) to dotted-decimal:port
awk 'NR>1{split($3,a,":");
  printf "%d.%d.%d.%d:%d\n",
    strtonum("0x"substr(a[1],7,2)),strtonum("0x"substr(a[1],5,2)),
    strtonum("0x"substr(a[1],3,2)),strtonum("0x"substr(a[1],1,2)),
    strtonum("0x"a[2])}' /proc/<PID>/net/tcp

# System-wide (all processes)
awk 'NR>1{split($3,a,":");printf "%d.%d.%d.%d:%d\n",strtonum("0x"substr(a[1],7,2)),strtonum("0x"substr(a[1],5,2)),strtonum("0x"substr(a[1],3,2)),strtonum("0x"substr(a[1],1,2)),strtonum("0x"a[2])}' /proc/net/tcp | sort | uniq -c | sort -nr
```

🔴 `/proc/net/tcp` is read straight from the kernel's socket table — useful when a userland tool (`ss`/`netstat`) is being lied to by a rootkit but the raw table still shows the connection.

## Firewall and Proxy State

```bash
# nftables (modern)
nft list ruleset

# iptables (legacy / compat)
iptables -L -n -v; iptables -t nat -L -n -v

iptables-save

# Front-ends
ufw status verbose            # Debian/Ubuntu

firewall-cmd --list-all       # RHEL

# Proxy environment (C2 tunneling / traffic redirection)
env | grep -i proxy

cat /etc/environment

grep -riE "http_proxy|https_proxy|ProxyCommand" /etc/profile* /home/*/.*rc 2>/dev/null
```

🔴 A NAT/redirect rule sending traffic to an attacker host, a firewall rule opening a backdoor port, or proxy env vars pointing at an unexpected host = evasion/C2 infrastructure.

## Open Files and Handles

```bash
# Everything a process has open
lsof -p <PID>

# What has a file/dir open
lsof /var/log/auth.log

# Unlinked-but-open files (deleted, still recoverable)
lsof +L1

# Sockets held by a process
lsof -a -p <PID> -i
```

## Deep Threat Hunts

Live-only recovery + injection + hidden-artifact sweep. *(seasoned-DFIR)*

```bash
# 1. Recover every deleted/memfd exe WITH ps context (before processes exit)
for e in /proc/[0-9]*/exe; do
  ls -l "$e" 2>/dev/null | grep -qE '\(deleted\)|memfd:' || continue
  pid=$(echo "$e" | cut -d/ -f3); echo "== PID $pid =="
  ps -p "$pid" -o user,ppid,cmd --no-headers; cp "$e" "/evidence/exe_$pid" 2>/dev/null
done

# 2. Injected code: anonymous rwx memory regions
for m in /proc/[0-9]*/maps; do grep -Eq 'rwxp .* 0[[:space:]]+0?$' "$m" && echo "RWX-anon: ${m%/maps}"; done

# 3. Hidden processes: /proc walk vs ps
comm -23 <(ls /proc | grep -E '^[0-9]+$' | sort -n) <(ps -eo pid= | tr -d ' ' | sort -n)

# 4. Any process carrying LD_PRELOAD / LD_AUDIT
for p in /proc/[0-9]*; do tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -qE 'LD_PRELOAD|LD_AUDIT' && echo "$(cat $p/comm 2>/dev/null) $p"; done

# 5. Listeners + established connections bound to temp-path binaries
ss -tulnp | grep -E '/tmp|/dev/shm'; ss -antp | grep ESTAB | grep -vE '127.0.0.1|::1'

# 6. Raw kernel socket table (rootkit-resistant) vs ss
awk 'NR>1{print $3}' /proc/net/tcp | sort -u    # compare count/entries against ss -ant

# 7. Structured order-of-volatility capture to evidence (run FIRST)
{ echo "=== CONTEXT ==="; date -u; uptime; hostname; id; who; w
  echo "=== PROCESSES ==="; ps -eo pid,ppid,user,lstart,stat,cmd --forest
  echo "=== NETWORK ==="; ss -tunap; echo "=== DELETED EXE ==="; ls -l /proc/*/exe 2>/dev/null | grep deleted
  echo "=== OPEN-DELETED ==="; lsof +L1
} > "/evidence/live_$(hostname)_$(date +%s).txt" 2>/dev/null
```

**Hunt ideas:**

- **The order-of-volatility capture (#7) runs first** — it snapshots the whole volatile tier to evidence before anything you do can change it or a reboot destroys it.
- **Anonymous `rwxp` regions = injected code** — legit code is `r-xp` from a file; writable-executable anon memory is shellcode or a runtime patch.
- **Hidden-process detection** (`/proc` walk vs `ps`) catches an LKM rootkit concealing a PID — the raw `/proc` and `/proc/net/tcp` often still show what `ps`/`ss` hide.
- **Recover fileless/deleted binaries with `ps` context in one loop** — attributable and gone the moment the process exits.
- **`gcore`/`/proc/PID/mem` dumps a process's memory** for strings/YARA without a full RAM image.

## Getting Max Value

- **Capture in order of volatility, to a structured evidence file, BEFORE imaging or reboot** — this tier is destroyed on restart.
- **`/proc` is the only place fileless/deleted artifacts live** — recover `exe`/`fd`/`map_files` immediately, with process context.
- **Cross-check `ss`/`ps`/`netstat` against raw `/proc`** — a disagreement is a hidden socket/process (rootkit).
- **`gcore`/`/proc/PID/mem`** gives you a process memory dump for `strings`/YARA when a full RAM image isn't practical.
- **Decode `/proc/net/tcp` offline** (awk) so you can read endpoints without external tools.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Full RAM image + trusted-context analysis | **Memory Forensics** (11) |
| Process lineage / how it was launched | **Process Trees and Execution Lineage** (10b) |
| Packet capture of the connections | **Network and PCAP Forensics** (10c) |
| eBPF-based live tracing | **eBPF Tooling for DFIR** (10d) |
| Triage a recovered binary | **ELF and Malware Triage** (11b), **IOC and YARA Scanning** (11d) |
| Is a rootkit hiding this? | **Rootkit Detection Tooling** (11c), **Preload Hijacking**, **LKM** |
| Preserve the volatile capture properly | **Evidence Collection and Triage** (12) |

## Scenarios

- **Self-deleting malware:** `/proc/PID/exe` shows `(deleted)` — recover the binary live before the process exits.
- **Fileless:** a `memfd:` exe that never touched disk — `/proc` is the only copy.
- **Code injection:** an anonymous `rwxp` region in a legit process's `maps`.
- **Hidden process:** a PID in the `/proc` walk that `ps` won't show — kernel rootkit.
- **Backdoor listener:** `ss` shows a listener on an odd port bound to a `/dev/shm` binary.
- **C2:** an established connection to an unfamiliar IP from an unexpected process.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `/proc/PID/exe` = `(deleted)` or `memfd:` | Self-deleting / fileless malware |
| Deleted `.so` in `map_files` + `LD_PRELOAD` set | Injected userland rootkit |
| Process running from `/tmp`/`/dev/shm` | Staged payload |
| Fake kernel-thread name with real cmdline | Masquerading process |
| Listener on odd port bound to temp-path binary | Backdoor |
| `ss`/`ps`/`netstat` inconsistencies | Rootkit hiding artifacts |
| NAT/redirect firewall rule or unexpected proxy env | C2 / evasion |
| Anonymous `rwxp` region in `/proc/PID/maps` | In-memory code injection |
| PID in `/proc` walk but hidden from `ps` | Kernel-rootkit-hidden process |

## Resources

- `proc(5)`, `ss(8)`, `lsof(8)`, `gcore(1)` man pages
- CyberChef (endianness / IP-format conversions) — https://gchq.github.io/CyberChef
- MITRE ATT&CK: T1055 (Process Injection), T1620 (Reflective/Fileless Loading), T1014 (Rootkit), T1571 (Non-Standard Port), T1049 (System Network Connections Discovery)
