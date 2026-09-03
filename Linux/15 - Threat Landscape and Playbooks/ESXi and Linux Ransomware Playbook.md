# ESXi and Linux Ransomware Playbook

Ransomware crews increasingly target Linux and — for maximum blast radius — VMware ESXi hypervisors, encrypting many VMs at once by hitting the datastore. This covers both the Linux-host and ESXi-appliance cases: detection, the encryption chain, and recovery.

> 🔴 On ESXi the attack has a distinctive prelude: they **enable SSH/shell** (normally off), then **power off the running VMs** to unlock the `.vmdk` files, then run the encryptor across `/vmfs/volumes/`. That sequence in `hostd.log`/`auth.log` is the tell. Recovery hinges entirely on backups the attacker couldn't reach — online/attached backups and snapshots are deleted first, so offline/immutable backups are what save the environment.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Identify the Ransomware](#identify-the-ransomware)
- [ESXi Specifics](#esxi-specifics)
- [Scope](#scope)
- [Timeline](#timeline)
- [Containment and Recovery](#containment-and-recovery)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)

## Attack Chain

Initial access (VPN/RDP-adjacent, stolen creds, exposed service) → escalate to admin/root → for ESXi: enable SSH/shell, authenticate to the hypervisor, **stop running VMs** (to unlock their `.vmdk` files), then run the encryptor across the datastore → drop ransom notes → often delete snapshots/backups first. On plain Linux: enumerate + encrypt data directories, delete shadow copies/snapshots, drop notes.

## Quick Triage

```bash
# Mass files renamed to a new extension + ransom notes
find / -maxdepth 4 -type f \( -name "*.enc" -o -name "*.crypt" -o -iname "*READ*ME*" -o -iname "*RECOVER*" -o -iname "*DECRYPT*" \) -ls 2>/dev/null

# High disk/CPU from an unknown process (active encryption)
ps -eo pid,user,%cpu,cmd --sort=-%cpu | head

# ESXi: is the shell/SSH freshly enabled? running VMs stopped?
vim-cmd vmsvc/getallvms 2>/dev/null

esxcli system version get 2>/dev/null
```

## Identify the Ransomware

```bash
# The encryptor process + binary
cat /proc/<PID>/cmdline | tr '\0' ' '; ls -l /proc/<PID>/exe

cp /proc/<PID>/exe /evidence/ransomware.bin      # capture before killing

# Ransom note content (family attribution, contact, ID)
cat /<path>/READ_ME*.txt 2>/dev/null

# Encrypted-file pattern + which dirs are hit
find / -name "*.<ext>" -newermt "3 hours ago" 2>/dev/null | head
```

## ESXi Specifics

ESXi is a stripped Linux-based appliance; the encryptor is usually an ELF run from the ESXi shell.

```bash
# ESXi log locations (also under /scratch/log -> often a symlink)
ls -la /var/log/                       # hostd.log, vmkernel.log, auth.log, shell.log, vobd.log

# Was the shell/SSH enabled by the attacker? (should normally be OFF)
grep -i "SSH" /var/log/auth.log /var/log/hostd.log 2>/dev/null

grep -iE "shell|enabled" /var/log/shell.log /var/log/hostd.log 2>/dev/null

# VM inventory + power state (encryptor stops VMs to lock the vmdks)
vim-cmd vmsvc/getallvms

vim-cmd vmsvc/power.getstate <vmid>

# Datastores where the .vmdk files (and the damage) live
esxcli storage filesystem list

ls -la /vmfs/volumes/*/
```

🔴 On ESXi, look for: SSH/shell **enabled** in `hostd.log`/`auth.log` shortly before the incident, a burst of VM power-offs, then an ELF encryptor iterating `/vmfs/volumes/`. The attacker stops VMs first because a running VM keeps its `.vmdk` locked.

## Scope

```bash
# How they got in / escalated (Linux host)
grep -Ei "Accepted|Failed|sudo" /var/log/auth.log 2>/dev/null | tail

# Did they delete snapshots/backups first? (recovery-denial)
# Linux: check LVM/Btrfs snapshots, backup jobs
btrfs subvolume list -s / 2>/dev/null

# ESXi: snapshot deletion in the logs
grep -i "snapshot" /var/log/hostd.log 2>/dev/null

# Lateral spread (which hosts/datastores)
```

## Timeline

```bash
# When did encryption start? (first renamed file / note)
stat /<path>/READ_ME*.txt 2>/dev/null

find / -name "*.<ext>" -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | head

# ESXi: correlate shell-enable -> VM power-off -> encryptor run
grep -iE "ssh|shell|power" /var/log/hostd.log /var/log/auth.log 2>/dev/null | sort
```

## Containment and Recovery

```bash
# STOP the encryptor immediately (it's still running through the data)
sudo kill -9 <PID>          # or halt the host if encryption is spreading fast

# Isolate the host/hypervisor from the network (limit spread)

# Do NOT reboot ESXi mid-encryption if VMs are still salvageable - preserve state

# Recovery order:
# 1. Restore VMs/data from verified-clean, offline backups (attackers hit online backups)
# 2. Check for un-deleted snapshots (Btrfs/LVM/ESXi) predating the attack
# 3. Rebuild the hypervisor/host from known-good media if the platform itself is compromised
```

🔴 Recovery hinges on **backups the attacker couldn't reach**. Online/attached backups and snapshots are usually deleted first — offline/immutable backups are what save the environment. Preserve encrypted samples + the note + the encryptor binary for law-enforcement/decryptor checks before wiping.

## Credential Reset

- Rotate **all** hypervisor/vCenter/ESXi credentials and disable the shell/SSH access the attacker enabled.
- Rotate domain and service accounts that could reach the hypervisor management network.
- Rotate backup-system credentials (that's how backups got deleted).

## Fleet Hunt

IOCs: encryptor hash, ransom-note filename/text, attacker IP, the extension appended.

```bash
# Other hosts with the same note / extension
find / -iname "*<note_name>*" 2>/dev/null

# ESXi hosts with SSH/shell newly enabled
for h in <esxi_hosts>; do ssh "$h" 'grep -i ssh /var/log/auth.log | tail'; done
```

## Correlate With

| Stage / to go deeper on… | Pivot to |
|--------------------------|----------|
| ESXi/vCenter triage (`esxcli`/`vim-cmd`, log locations) | **ESXi and vCenter** (17) |
| Triage the encryptor binary | **ELF and Malware Triage** (11b), **IOC and YARA** (11d) |
| How they got in (SSH/creds) | **Authentication and Login Records** (06), **SSH Brute-Force Playbook** |
| Snapshot recovery (Btrfs/LVM/ESXi) | **Btrfs**, **Filesystem Triage** (07) |
| Timeline the shell-enable → power-off → encrypt sequence | **Timelining** (13) |
| Backup-cred + hypervisor rotation, rebuild | **Remediation and Containment** (14) |
| Lateral spread / management-network reach | **Network and PCAP** (10c), **Cross-Artifact Correlation** (00) |

## Red Flags

| Finding | Meaning |
|---------|---------|
| Mass files renamed to one new extension + ransom note | Active/completed encryption |
| ESXi SSH/shell enabled just before the incident | Attacker prepping the hypervisor |
| Burst of VM power-offs then an ELF running over `/vmfs/volumes` | ESXi encryptor at work |
| Snapshots/backups deleted just before encryption | Recovery denial |
| Encryptor process at high CPU touching many dirs | Encryption in progress — stop it |
| Only online backups exist | High risk — they were likely targeted |

## Resources

- VMware/Broadcom KB: ESXi log file locations
- VMware/Broadcom KB: vCenter Server log file locations
- No More Ransom project — nomoreransom.org
