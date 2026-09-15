# Cryptojacking Playbook

The most common Linux enterprise incident: an attacker lands on a host (exposed service, weak SSH, container escape) and runs a cryptominer that pins the CPU, persists, and calls a mining pool. Fast to detect, but scope the foothold behind it — the miner is rarely the whole story.

> 🔴 The miner is the *symptom*, not the intrusion. It's trivial to spot (100% CPU, a `stratum` connection) and trivial to kill — which is exactly the trap. The real questions are how they got in, what persistence redeploys the miner, and whether they harvested SSH keys or cloud credentials to spread. Treat the miner as your entry point into scoping, not the end of the case.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Identify the Miner](#identify-the-miner)
- [Scope the Foothold](#scope-the-foothold)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)

## Attack Chain

Initial access (exposed app / weak SSH / exposed Docker or K8s API / vulnerable service) → drop + `chmod +x` a miner in `/tmp` or `/dev/shm` → establish persistence (cron/systemd) → connect to a mining pool → often kill competing miners and disable security tooling → sometimes spread laterally with harvested keys.

## Quick Triage

```bash
# Top CPU consumers (miner usually at/near 100%)
ps -eo pid,ppid,user,%cpu,cmd --sort=-%cpu | head

top -bn1 | head -20

# Known miner names / staging paths
ps auxww | grep -Ei "xmrig|kdevtmpfsi|kinsing|kthreaddi|minerd|/tmp/|/dev/shm|--donate-level|stratum"

# Outbound pool connections (stratum, odd high ports)
ss -tunap | grep -v 127.0.0.1

# Deleted-but-running executable
ls -l /proc/*/exe 2>/dev/null | grep -E "deleted|memfd"
```

## Identify the Miner

```bash
# Confirm the suspect PID's real identity
cat /proc/<PID>/cmdline | tr '\0' ' '; echo

ls -l /proc/<PID>/exe                       # path (or "(deleted)")

cp /proc/<PID>/exe /evidence/miner.bin      # recover binary before killing

cat /proc/<PID>/environ | tr '\0' '\n'      # pool/wallet in env?

# Where it connects (pool)
ss -tnp | grep <PID>

# CPU throttling / masquerade tells
ls -l /proc/<PID>/exe | grep -Ei "kworker|systemd|kdevtmpfsi"   # fake kernel-thread name
```

🔴 Miners commonly masquerade as `[kworker/...]`, `kdevtmpfsi`, or `systemd-*`, delete their own binary, and use `memfd`. Recover the binary from `/proc/PID/exe` and capture the wallet/pool from the cmdline or config before eradicating.

## Scope the Foothold

The miner is the payload; find how it got in and what else it planted.

```bash
# Persistence (full sweep in the Persistence note)
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done

grep -rIE "curl|wget|xmrig|/tmp/|/dev/shm|stratum" /etc/systemd/system /etc/cron* 2>/dev/null

cat /etc/ld.so.preload 2>/dev/null

# Initial access clues
grep -Ei "Accepted|Failed" /var/log/auth.log 2>/dev/null | tail

find /var/www -type f -mtime -3 -ls 2>/dev/null        # webshell?

# Lateral movement prep
find / -name authorized_keys -exec cat {} \; 2>/dev/null

cat /home/*/.ssh/known_hosts 2>/dev/null
```

## Timeline

```bash
# When did the miner + persistence land?
stat /tmp/<miner> /etc/systemd/system/<evil>.service 2>/dev/null

# Bracket the drop window
find / -newermt "$(stat -c %y /proc/<PID>/exe 2>/dev/null | cut -d. -f1)" ! -newermt "now" -type f 2>/dev/null | head

# Correlate with auth + cron logs
grep -i CRON /var/log/syslog 2>/dev/null | tail
```

## Eradication

```bash
# Remove persistence FIRST so the miner can't respawn (see Remediation note)
sudo systemctl disable --now <evil>.service; sudo systemctl mask <evil>.service
sudo rm /etc/systemd/system/<evil>.service; sudo systemctl daemon-reload
crontab -r -u <user>            # after saving a copy
sudo chattr -i /tmp/<miner> 2>/dev/null

# Then kill and remove the miner
sudo kill -9 <PID>; sudo rm -f /tmp/<miner> /dev/shm/<miner>

# Remove any ld.so.preload / disabled-security tampering it added
```

## Credential Reset

Rotate anything the host could reach — miners frequently harvest SSH keys and cloud credentials to spread:

```bash
# SSH keys present on the box (rotate all)
find / -name "id_*" ! -name "*.pub" -o -name "*.pem" 2>/dev/null

# Cloud/API creds
ls -la /home/*/.aws /home/*/.config/gcloud /root/.aws 2>/dev/null
```

Revoke at the source (cloud IAM, IdP), reset local passwords, and regenerate SSH host/user keys.

## Fleet Hunt

Scope IOCs across the estate: miner binary hash, wallet address, pool domain/IP, dropped file paths, the persistence unit name.

```bash
# Same-family sweep to run everywhere (via EDR/osquery/Velociraptor)
ps auxww | grep -Ei "xmrig|kdevtmpfsi|kinsing|stratum"

ss -tunap | grep -E "<pool_ip>|:3333|:4444|:5555|:14444"

find /tmp /var/tmp /dev/shm -type f -perm -111 2>/dev/null
```

## Correlate With

| Stage / to go deeper on… | Pivot to |
|--------------------------|----------|
| Recover the miner from `/proc`, live sockets | **Live Response** (10) |
| The pool connection / C2 (stratum, beacon) | **Network and PCAP Forensics** (10c) |
| Triage/hash the miner binary | **ELF and Malware Triage** (11b), **IOC and YARA** (11d) |
| The persistence that redeploys it | **Persistence** (cron / systemd / preload) |
| How it got in (SSH / web / container) | **Auth Records**, **App/DB Logs**, **Container** |
| The staging in `/tmp`·`/dev/shm` | **Temp and Staging** (08) |
| Respawn-safe eradication + cloud rotation | **Remediation and Containment** (14) |
| Timeline the drop + persistence | **Timelining** (13) |

## Red Flags

| Finding | Meaning |
|---------|---------|
| Process at 100% CPU with `stratum`/pool connection | Active mining |
| Fake `[kworker]`/`kdevtmpfsi` name, deleted exe | Masqueraded miner |
| cron/systemd unit fetching a miner | Persistence |
| Security tooling disabled around the drop | Defense evasion |
| SSH keys/cloud creds accessed | Lateral-movement prep |
| Same wallet/pool IOC on other hosts | Fleet-wide campaign |
