# SSH Brute-Force and Foothold Playbook

Internet-facing SSH is brute-forced or credential-stuffed, one attempt succeeds, and the attacker drops a key, escalates, and pivots. The `btmp`→`Accepted` transition and the compromised account's `known_hosts` tell the story.

> 🔴 The pivot that cracks the case is the *same source IP appearing in both failures and a success* — many `Failed password` lines then an `Accepted`, from one address. That's the moment of compromise; everything that session did is now in scope. From there, the compromised account's `known_hosts` is your lateral-movement map — every host in it is a next hop to check.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Confirm the Successful Login](#confirm-the-successful-login)
- [Scope the Session](#scope-the-session)
- [Trace Lateral Movement](#trace-lateral-movement)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)

## Attack Chain

Mass failed logins (brute-force / password spray / credential stuffing) → one `Accepted` from the attacker IP → attacker drops an `authorized_keys` entry for durable access → local recon → privesc → pivots to hosts in `known_hosts` using harvested keys.

## Quick Triage

```bash
# Failed-login volume by source IP (brute-force signature)
grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -nr | head

sudo lastb | head -30

# Successful logins (the payoff)
grep "Accepted" /var/log/auth.log 2>/dev/null | tail

last -Fa | head

# New / attacker-added SSH keys
find / -name authorized_keys -newermt "7 days ago" -exec ls -l {} \; -exec cat {} \; 2>/dev/null
```

## Confirm the Successful Login

🔴 The key pivot: an IP with many `Failed password` lines that then produces an `Accepted` line = successful brute force.

```bash
# For a suspect IP, show fails then the success
grep "<attacker_ip>" /var/log/auth.log | grep -E "Failed|Accepted|Invalid"

# Which account fell, and how (password vs key)
grep "Accepted" /var/log/auth.log | grep "<attacker_ip>"

# Invalid-user spray targets
grep "Invalid user" /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -nr

# Session tie-in (wtmp)
last -Fa <user>
```

## Scope the Session

```bash
# What did the account do after login?
grep "<user>" /var/log/auth.log | grep -Ei "sudo|COMMAND="

cat /home/<user>/.bash_history 2>/dev/null

journalctl _COMM=sudo | grep <user>

# Persistence planted (see Persistence note)
crontab -l -u <user> 2>/dev/null

cat /home/<user>/.ssh/authorized_keys 2>/dev/null

# Privesc
getcap -r / 2>/dev/null; find / -perm -4000 -newermt "7 days ago" -ls 2>/dev/null
```

## Trace Lateral Movement

```bash
# Hosts the compromised account reached out to
cat /home/<user>/.ssh/known_hosts 2>/dev/null

# If hashed, test candidate internal IPs
ssh-keygen -F <internal_ip> -f /home/<user>/.ssh/known_hosts

# Keys available to pivot with
ls -la /home/<user>/.ssh/

# Outbound SSH in the logs
grep "sshd.*Accepted" /var/log/auth.log     # on the NEXT hop, look for this source
```

🔴 Every host in the compromised account's `known_hosts` is a lateral-movement candidate — pull their auth logs for an `Accepted` from this host/account.

## Timeline

```bash
# Login -> actions -> persistence, in order
last -Fa <user>

grep "<user>" /var/log/auth.log | head

stat /home/<user>/.ssh/authorized_keys 2>/dev/null    # when the key was added
```

## Eradication

```bash
# Kill live sessions + remove the attacker key
sudo pkill -KILL -u <user>

sudo sed -i '/<attacker_key_comment_or_string>/d' /home/<user>/.ssh/authorized_keys

# Remove any persistence found in scoping
crontab -r -u <user> 2>/dev/null

# Block the source (network/EDR preferred), harden SSH:
#   PasswordAuthentication no, PermitRootLogin no, key-only, rate-limit/fail2ban
```

## Credential Reset

```bash
# Reset the compromised account + rotate its keys everywhere they were trusted
sudo passwd <user>

# Regenerate host keys if the box may have been used to impersonate
sudo rm /etc/ssh/ssh_host_*; sudo dpkg-reconfigure openssh-server
```

Assume any private key that lived on the host is burned — rotate it and remove its public half from every `authorized_keys` across the fleet.

## Fleet Hunt

IOCs: attacker source IP(s), the added public key string/comment, the compromised username.

```bash
# The attacker's key on any host
grep -rl "<attacker_pubkey_string>" /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null

# Successful logins from the attacker IP anywhere
grep -rl "<attacker_ip>" /var/log/auth.log* /var/log/secure* 2>/dev/null

# Same account logging in from odd sources across hosts
```

## Correlate With

| Stage / to go deeper on… | Pivot to |
|--------------------------|----------|
| Login-record detail (`wtmp`/`btmp`, `[preauth]` shapes, pubkey fingerprint) | **Authentication and Login Records** (06) |
| The dropped key / agent-hijack / ControlMaster | **Persistence → SSH Keys**, **SSH Artifacts** (08) |
| What the session ran after login | **Shells** (04), **Auditd**, **Process Trees** (10b) |
| Lateral-movement map + next hops | **Cross-Artifact Correlation** (00) + the next host's auth logs |
| Persistence planted by the account | **Persistence Mechanisms** |
| Attacker source IP geo / ASN / C2 | **Network and PCAP Forensics** (10c) |
| Eradication + SSH hardening + key rotation | **Remediation and Containment** (14) |

## Red Flags

| Finding | Meaning |
|---------|---------|
| Many `Failed password` then `Accepted` from one IP | Successful brute force |
| `Accepted` for root / a service account | High-impact compromise |
| authorized_keys added right after the login | Durable backdoor |
| Login from unusual geo/IP or odd hour | Compromised credential |
| Internal hosts appearing in `known_hosts` | Lateral-movement trail |
| Same attacker key/IP on multiple hosts | Fleet-wide spread |
