# Remediation and Containment

Enterprise eradication and recovery: killing a payload so it stays dead, removing every persistence foothold, rotating what was exposed, restoring protections, and deciding when to rebuild instead of clean. The recurring failure mode in Linux remediation is *incomplete* eradication — you kill the process but not the systemd `Restart=` that respawns it, you delete the cron job but miss the second one, you reset passwords but not the SSH keys and cloud tokens the attacker actually used. This note is ordered to prevent that: scope fully, contain, remove persistence *before* killing processes, rotate credentials at the source, restore protections, and verify with a reboot.

> 🔴 Two rules dominate. **Scope before you eradicate** — removing footholds you haven't inventoried leaves the ones you missed and destroys evidence you needed. And **remove the thing that respawns the payload before you kill the payload** (the systemd `Restart=`, the `@reboot` cron, the watchdog), or it comes right back and you've just tipped the attacker off.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Containment First](#containment-first)
- [Kill Without Respawn](#kill-without-respawn)
- [Remove Every Foothold](#remove-every-foothold)
- [Account and Credential Remediation](#account-and-credential-remediation)
- [Restore Protections](#restore-protections)
- [Repair Trojaned Binaries](#repair-trojaned-binaries)
- [When to Rebuild](#when-to-rebuild)
- [Fleet and Cloud Remediation](#fleet-and-cloud-remediation)
- [Verify](#verify)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Snapshot everything BEFORE you change it (evidence + scoping)
sudo ./uac -p ir_triage /evidence/    # or your collection of choice

# Confirm scope: persistence sweep (see Persistence note)
cat /etc/ld.so.preload 2>/dev/null; systemctl list-unit-files --state=enabled

# Only then contain / eradicate
```

> Collect evidence and scope the full intrusion **before** eradicating. Removing footholds you haven't inventoried leaves the ones you missed — and destroys evidence. Eradicate only once scope is understood.

## What to Check for What

| Remediation decision | Action |
|----------------------|--------|
| Is scope fully understood? | If **no**, don't eradicate yet — collect + scope first |
| What respawns the payload? | Remove it (systemd `Restart=`, `@reboot`, watchdog) **before** the kill |
| Is the foothold immutable? | `chattr -i` before `rm` |
| Kernel rootkit / unknown scope / trojaned toolchain? | **Rebuild**, don't clean |
| What credentials were exposed? | Rotate at the **source** (SSH keys, cloud, tokens, DB) |
| Protections disabled? | Re-enable + relabel before return to service |
| Did it survive a reboot? | The real verification test |
| Other hosts affected? | Fleet-hunt the IOCs, remediate every one |

## Containment First

```bash
# Isolate at the network level (EDR/firewall preferred over host commands)
# Host-level fallback - drop all but management access:
iptables -A INPUT -s <mgmt_ip> -j ACCEPT; iptables -A OUTPUT -d <mgmt_ip> -j ACCEPT
iptables -P INPUT DROP; iptables -P OUTPUT DROP

# Kill active attacker sessions (identify first)
who; ss -tnp | grep sshd

pkill -KILL -t pts/2          # a specific tty, once confirmed
```

Prefer EDR/network isolation to host-level firewalling — a root-level attacker can undo host rules. Isolation buys time to eradicate without live interference.

## Kill Without Respawn

A naive `kill` fails when the payload has a supervisor that restarts it. Neutralize the supervisor first.

```bash
# What keeps it alive? Check for a systemd Restart= / cron @reboot / KeepAlive-style loop
systemctl status <suspect>.service

grep -rE "Restart=" /etc/systemd/system/<suspect>.service

# Stop + disable + mask the service so it can't be re-enabled
sudo systemctl stop <suspect>.service

sudo systemctl disable --now <suspect>.service

sudo systemctl mask <suspect>.service

# Remove the cron/@reboot re-add, THEN kill the process
crontab -r -u <user>     # after saving a copy

sudo kill -9 <PID>

# If a watchdog respawns it, remove the watchdog first, then kill both
```

🔴 Order matters: remove the persistence that respawns it (systemd `Restart=`, cron `@reboot`, a bash-loop parent) **before** killing the process, or it comes right back.

## Remove Every Foothold

Walk the Persistence note's list and clear each confirmed item (save a copy to evidence first):

```bash
# Immutable bit blocks removal - clear it first
sudo chattr -i /path/to/persistence

# Then remove the confirmed artifact
sudo rm /etc/ld.so.preload                       # if malicious
sudo rm /etc/systemd/system/<evil>.service; sudo systemctl daemon-reload
sudo sed -i '/attacker-key/d' /home/*/.ssh/authorized_keys
sudo rm /etc/cron.d/<evil> /etc/update-motd.d/<evil>
```

| Foothold | Removal |
|----------|---------|
| systemd unit/timer | `disable --now` + `mask` + delete file + `daemon-reload` |
| cron/at | remove line/file from spool; check all users |
| SSH key | delete the offending `authorized_keys` line |
| ld.so.preload / LD_PRELOAD | delete file / unset in env & unit files |
| PAM backdoor | restore module from package; remove rogue lines |
| kernel module | `rmmod`/`modprobe -r`; blacklist; **may need reboot** |
| shell rc / profile.d | remove injected lines |
| udev / NetworkManager / MOTD | delete the trigger script |

## Account and Credential Remediation

Assume anything reachable from the host is compromised.

```bash
# Lock / expire attacker or compromised accounts
sudo passwd -l <user>; sudo usermod --expiredate 1 <user>

# Kill their sessions + cron
sudo pkill -KILL -u <user>; crontab -r -u <user>

# Remove from privileged groups
sudo gpasswd -d <user> sudo; sudo gpasswd -d <user> docker

# Rotate what was exposed:
# - all local passwords (force reset)
# - SSH host keys + every user key that lived on the box
# - service/API tokens, DB creds, cloud keys found on the host
sudo rm /etc/ssh/ssh_host_*; sudo dpkg-reconfigure openssh-server   # regenerate host keys
```

🔴 Rotate **service and cloud credentials**, not just user passwords — private keys in `~/.ssh`, `.aws/credentials`, `.kube/config`, DB passwords in app configs, and API tokens are the attacker's real prize. Revoke at the source (IdP/cloud/CI), don't just change them locally.

## Restore Protections

```bash
# Re-enable SELinux / AppArmor if it was disabled
sudo setenforce 1; sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

sudo aa-enforce /etc/apparmor.d/*

# Restore correct SELinux labels the attacker may have changed
sudo restorecon -R -v /etc /var/www /home

# Remove rogue CAs, repos, GPG keys
sudo rm /usr/local/share/ca-certificates/<rogue>.crt; sudo update-ca-certificates --fresh
sudo rm /etc/apt/sources.list.d/<rogue>.list; sudo rm /etc/yum.repos.d/<rogue>.repo

# Reset firewall to the approved baseline
```

## Repair Trojaned Binaries

```bash
# Confirm which system files were altered
rpm -Va | grep -E '^..5'; debsums -c

# Reinstall the owning package to restore clean binaries
sudo apt install --reinstall <pkg>      # Debian

sudo dnf reinstall <pkg>                 # RHEL

# Re-verify
rpm -V <pkg>; debsums <pkg>
```

## When to Rebuild

🔴 Clean-in-place is not trustworthy for:
- **Kernel rootkits** (LKM/`tainted`) — you cannot be sure what the kernel is hiding.
- **Unknown scope** — if you can't fully account for how far the attacker got.
- **Trojaned toolchain** (compiler/package manager) — future "clean" installs can't be trusted.

In those cases, **rebuild from known-good media/images**, restore data from a pre-compromise backup/snapshot (verify it's clean), and re-apply the credential rotation before returning to service.

## Fleet and Cloud Remediation

🔴 Remediating one host doesn't close the incident if the campaign hit others. Scope the IOCs, hunt them fleet-wide, and remediate *every* affected system — and in cloud, rotate and rebuild at the platform, not just in-guest.

```bash
# Fleet: hunt the scoped IOCs (hashes/paths/keys/IPs) across every host, then remediate
#   Velociraptor hunt / osquery pack / EDR — see IOC and YARA + Enterprise notes

# Cloud IAM: rotate and REVOKE at the provider (in-guest key changes aren't enough)
aws iam list-access-keys --user-name <u>; aws iam delete-access-key --access-key-id <id>
#   revoke active STS sessions; rotate instance-profile roles; check for attacker-created IAM users/keys

# Cloud rebuild: replace the instance from a KNOWN-GOOD golden image (not a clean-in-place)
#   AWS: terminate + relaunch from a trusted AMI; GCP/Azure: redeploy from a golden image

# Kubernetes/containers: never "clean" a container — recreate from a clean image
kubectl delete pod <compromised>; kubectl rollout restart deploy/<app>
#   rotate the compromised service-account token; check for attacker-created RBAC (see Container/K8s)
```

🔴 In cloud, the attacker's real prize is often **IAM** — an access key or an attacker-created role persists across any host rebuild. Revoke keys/sessions at the provider and audit for rogue IAM users/roles before declaring closure.

## Verify

```bash
# Reboot and re-check persistence is gone (respawn test)
sudo reboot
# after reboot:
cat /etc/ld.so.preload 2>/dev/null; systemctl list-unit-files --state=enabled
ss -tunap | grep -v 127.0.0.1; ps auxww | grep -Ei "/tmp|/dev/shm"

# Confirm protections restored
getenforce; aa-status | head -1; cat /proc/sys/kernel/tainted
```

Reboot is the real test — `KeepAlive`/`@reboot`/module-reload persistence only reveals itself if it survives one. Hunt the scoped IOCs across the fleet before declaring closure.

## Getting Max Value

- **Scope before you eradicate; remove the respawner before the payload** — the two rules that prevent incomplete eradication.
- **Rotate at the source** (IdP/cloud/CI), not just locally — SSH keys, cloud IAM, and API tokens are the attacker's real prize and survive a host rebuild.
- **Rebuild, don't clean** for a kernel rootkit, unknown scope, or a trojaned toolchain — you can't trust the host to fix itself.
- **A reboot is the real verification** — `@reboot`/`Restart=`/module-reload persistence only reveals itself if it survives one.
- **Remediate the fleet, not one host** — hunt the scoped IOCs everywhere and clear every affected system before closure.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| The full persistence inventory to remove | **Persistence Overview and Sweep** (+ each mechanism) |
| Confirm a kernel rootkit (rebuild trigger) | **Memory Forensics** (11), **LKM**, **Rootkit Detection** (11c) |
| Repair trojaned binaries | **Package Managers and Integrity** (08) |
| Scope + collect *before* eradicating | **Evidence Collection and Triage** (12) |
| Fleet-hunt the scoped IOCs | **IOC and YARA Scanning** (11d), **Enterprise** (16) |
| Container / Kubernetes eradication | **Container** section (escapes, K8s) |
| Restore SELinux/AppArmor/kernel protections | **SELinux AppArmor and Kernel Hardening** (05) |

## Scenarios

- **Incomplete eradication:** the payload is killed but a systemd `Restart=` respawns it — remove the unit first.
- **Kernel rootkit:** `tainted`/LKM confirmed — rebuild from known-good media, don't clean.
- **Credential prize:** rotate SSH keys, cloud IAM, and tokens at the source — local password resets miss the real access.
- **Fleet campaign:** one host is cleaned but the scoped IOCs match a dozen more — remediate all before closure.
- **Verification:** a reboot exposes `@reboot`/module-reload persistence that clean-in-place missed.

## Red Flags

| Situation | Action |
|-----------|--------|
| Payload respawns after kill | Persistence not fully removed — re-sweep |
| Kernel `tainted` / LKM rootkit | Rebuild, don't clean |
| Trojaned compiler/package manager | Rebuild; distrust in-place fixes |
| Only local passwords rotated | Rotate service/cloud/SSH keys too |
| SELinux/AppArmor left disabled | Re-enable + relabel before return to service |
| No pre-compromise clean backup | Rebuild + restore data selectively |
| Only the compromised host remediated | Fleet-hunt IOCs; others may still be compromised |
| Host rebuilt but cloud IAM keys not revoked | Attacker keeps access via IAM |

## Resources

- MITRE ATT&CK mitigations (Linux) — https://attack.mitre.org
- MITRE ATT&CK: T1531 (Account Access Removal — containment), T1070 (context for what to undo)
