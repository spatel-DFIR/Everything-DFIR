# ESXi and vCenter

VMware ESXi is a stripped, Linux-adjacent hypervisor appliance; vCenter manages many ESXi hosts. Both are high-value ransomware and lateral-movement targets precisely because one compromised hypervisor puts every VM it hosts within reach. This note covers log locations, the `esxcli`/`vim-cmd` triage surface, and the attacker TTPs specific to the platform — most of which revolve around the fact that ESXi ships hardened (shell and SSH off) and the attacker has to *turn things on*, leaving a trail.

> 🔴 ESXi's default-hardened posture works in your favor: the shell and SSH are normally **off**, so an *enable* event in `hostd.log`/`auth.log` shortly before an incident is itself a strong signal. And ESXi logs can be **volatile** (RAM-backed `/scratch` unless remote syslog is configured), so check `esxcli system syslog config get` for a central copy before a reboot loses them.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [ESXi Log Locations](#esxi-log-locations)
- [Shell and SSH as a TTP](#shell-and-ssh-as-a-ttp)
- [esxcli and vim-cmd Triage](#esxcli-and-vim-cmd-triage)
- [ESXi Persistence](#esxi-persistence)
- [Datastores and VMs](#datastores-and-vms)
- [vCenter](#vcenter)
- [Attacker Playbook on ESXi](#attacker-playbook-on-esxi)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Version + host identity
esxcli system version get; vmware -vl

# Is the (normally-off) shell/SSH enabled?
vim-cmd hostsvc/enable_ssh 2>/dev/null; grep -i ssh /var/log/hostd.log | tail

# VM inventory + power state (ransomware stops VMs to lock vmdks)
vim-cmd vmsvc/getallvms

# Recent auth activity
tail -50 /var/log/auth.log

# Datastores (where the damage/data lives)
esxcli storage filesystem list
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Shell/SSH enabled (normally off)? | `vim-cmd hostsvc/get_service_status TSM-SSH`; `hostd.log`/`auth.log` |
| Is a central log copy safe from reboot? | `esxcli system syslog config get` |
| What ran in the shell? | `/var/log/shell.log` |
| Rogue/unsigned VIB persistence? | `esxcli software vib list \| grep -iv VMware`; acceptance level |
| ESXi-native boot persistence? | `/etc/rc.local.d/local.sh`; root crontab; `boot.cfg` |
| Backdoor local account? | `esxcli system account list`; `permission list` |
| VMs stopped to unlock vmdks (ransomware)? | `vim-cmd vmsvc/getallvms` + power state |
| Snapshots/backups deleted? | `snapshot.get`; `hostd.log` snapshot events |
| vCenter (VCSA) abuse? | `/var/log/vmware/vpxd/vpxd.log` logins/permissions |

## ESXi Log Locations

ESXi logs live in `/var/log/` (often symlinked to `/scratch/log`, which may be on a datastore).

| Log | Content |
|-----|---------|
| `hostd.log` | 🔴 Host management agent — VM ops, shell/SSH enable, task/user actions |
| `vmkernel.log` | Kernel/storage/hardware events |
| `auth.log` | 🔴 Authentication (SSH/DCUI/shell logins) |
| `shell.log` | 🔴 Commands typed in the ESXi shell |
| `vobd.log` | VMkernel observation events (config changes, alarms) |
| `vpxa.log` | vCenter agent (host↔vCenter comms) |
| `fdm.log` | HA agent |
| `syslog.log` | General messages |
| `/scratch/log/` | Where the above often physically reside |

```bash
# Read + search (BusyBox environment: grep/less available)
tail -f /var/log/hostd.log

grep -iE "user|logged in|shell|ssh|enable" /var/log/hostd.log

# Persistent/remote syslog config (ESXi can forward - check for a central copy)
esxcli system syslog config get
```

🔴 ESXi logs can be **volatile** (RAM-backed `/scratch` on some configs) — if remote syslog isn't configured, a reboot loses them. Check `esxcli system syslog config get` for a remote host and pull the central copy.

## Shell and SSH as a TTP

ESXi ships with the shell and SSH **disabled**. Attackers enable them to run the encryptor / recon — so an *enable* event is itself a strong signal.

```bash
# Current state
vim-cmd hostsvc/get_service_status TSM-SSH        # SSH service

vim-cmd hostsvc/get_service_status TSM            # ESXi Shell

# History of enable/disable + logins in the logs
grep -iE "TSM-SSH|SSH access|shell|enabled|started" /var/log/hostd.log /var/log/auth.log

# Lockdown mode (should often be enabled in hardened envs)
vim-cmd hostsvc/hostsummary | grep -i lockdown
```

## esxcli and vim-cmd Triage

```bash
# System / patch level
esxcli system version get

esxcli software vib list          # installed VIBs (rogue/unsigned VIB = persistence)

esxcli software vib list | grep -iv "VMware\|vmw"   # non-VMware VIBs

# Acceptance level (attackers lower it to install unsigned VIBs)
esxcli software acceptance get

# Accounts + permissions
esxcli system account list

esxcli system permission list

# Firewall
esxcli network firewall get; esxcli network firewall ruleset list

# Running processes (VMkernel world list)
esxcli system process list 2>/dev/null; ps -c 2>/dev/null
```

🔴 A non-VMware **VIB** installed with acceptance level lowered to `CommunitySupported`, or a new local account/permission, is hypervisor persistence.

## ESXi Persistence

🔴 ESXi has its own persistence surface — and its own trap: most of the filesystem is a **RAM disk restored from `/bootbank` on boot**, so a payload in RAM vanishes on reboot *unless* it's written to a persisted location. Those persisted spots are exactly what to check.

```bash
# Boot-time script (the ESXi rc.local) - runs on every boot, persists
cat /etc/rc.local.d/local.sh 2>/dev/null

# ESXi root crontab (a persisted scheduler)
cat /var/spool/cron/crontabs/root 2>/dev/null

# Persisted VIBs + boot modules (survive reboot via bootbank)
esxcli software vib list | grep -iv "VMware\|vmw"

ls -la /bootbank /altbootbank 2>/dev/null; grep -i modules /bootbank/boot.cfg 2>/dev/null

# SSH keys added for durable hypervisor access
cat /etc/ssh/keys-root/authorized_keys 2>/dev/null

# Known ESXi VIB backdoor families (Mandiant): VirtualPita, VirtualPie, VirtualGate
esxcli software vib list | grep -iE 'pita|pie|gate|VMware_bootbank_[^ ]*' 2>/dev/null
```

🔴 An `/etc/rc.local.d/local.sh` or root crontab with an unexpected command, a non-VMware VIB, or a python/ELF backdoor referenced from `local.sh` is hypervisor persistence — and the **known VIB-backdoor families** (VirtualPita/VirtualPie/VirtualGate) hide as legitimate-looking VIBs to survive reboot and upgrade.

## Datastores and VMs

```bash
# VM inventory with IDs
vim-cmd vmsvc/getallvms

# Power state of a VM
vim-cmd vmsvc/power.getstate <vmid>

# Snapshots (recovery lever - and an attacker deletion target)
vim-cmd vmsvc/snapshot.get <vmid>

# Datastore contents (encryptors iterate these)
esxcli storage filesystem list

ls -la /vmfs/volumes/*/

# Find recently modified VM files (encryption in progress / completed)
find /vmfs/volumes -name "*.vmdk" -o -name "*.vmx" 2>/dev/null | head
```

## vCenter

vCenter (the appliance, VCSA, is Linux-based) centrally manages ESXi hosts — compromise here = control of the whole virtual estate.

- Key logs live under `/var/log/vmware/` on the VCSA (e.g. `vpxd/vpxd.log`, `sso/`, `vsphere-ui/`) — exact paths vary by version; consult the vendor KB for the running version.
- Check SSO/identity-source config and administrator logins for abuse.
- vpxd logs tie management actions (VM power ops, permission changes) to users and source IPs.

```bash
# On the VCSA (Linux) - management + SSO logs
ls -la /var/log/vmware/vpxd/ /var/log/vmware/sso/ 2>/dev/null

grep -iE "login|permission|role" /var/log/vmware/vpxd/vpxd.log 2>/dev/null | tail
```

## Attacker Playbook on ESXi

1. Obtain valid creds / reach the management network.
2. **Enable SSH/shell** on the ESXi host (`hostd.log`/`auth.log` event).
3. Authenticate; optionally lower VIB acceptance / add an account for persistence.
4. **Stop running VMs** (`vim-cmd vmsvc/power.off`) so their `.vmdk` files unlock.
5. Delete snapshots/backups.
6. Run an ELF **encryptor** across `/vmfs/volumes/`.
7. Drop ransom notes. (See the ESXi and Linux Ransomware playbook.)

## Deep Threat Hunts

*(seasoned-DFIR; ESXi ships hardened — the attacker has to *turn things on*, leaving a trail)*

```bash
# 1. Shell/SSH enable event + its logins (the ESXi tell)
grep -iE "TSM-SSH|SSH access|shell|enabled|logged in" /var/log/hostd.log /var/log/auth.log 2>/dev/null

# 2. Central log copy before a reboot loses volatile logs
esxcli system syslog config get

# 3. Persistence: rc.local.d, root crontab, non-VMware VIB, boot modules
cat /etc/rc.local.d/local.sh /var/spool/cron/crontabs/root 2>/dev/null

esxcli software vib list | grep -iv "VMware\|vmw"; esxcli software acceptance get

# 4. Known VIB-backdoor families
esxcli software vib list | grep -iE 'pita|pie|gate'

# 5. Backdoor accounts / permissions
esxcli system account list; esxcli system permission list

# 6. Ransomware prelude: VMs powered off + snapshots deleted
vim-cmd vmsvc/getallvms; grep -i "snapshot\|power" /var/log/hostd.log 2>/dev/null

# 7. Encryptor iterating the datastore
find /vmfs/volumes -newermt "3 hours ago" \( -name "*.vmdk" -o -name "*READ*ME*" \) 2>/dev/null | head

# 8. vCenter (VCSA) management-action abuse
grep -iE "login|permission|role" /var/log/vmware/vpxd/vpxd.log 2>/dev/null | tail
```

**Hunt ideas:**

- **An SSH/shell *enable* event is the signature** — ESXi ships with them off, so turning them on shortly before an incident is high-signal in `hostd.log`/`auth.log`.
- **ESXi logs are volatile** (RAM-backed `/scratch`) — pull the remote-syslog copy *before* a reboot destroys them.
- **Persistence lives in the persisted spots** — `rc.local.d/local.sh`, root crontab, VIBs, `boot.cfg` modules — not the RAM disk that resets on boot.
- **The known VIB backdoors (VirtualPita/VirtualPie/VirtualGate)** masquerade as legitimate VIBs to survive reboot and upgrade — list non-VMware VIBs.
- **The ransomware prelude is a sequence** — enable shell → power off VMs → delete snapshots → run the ELF encryptor; correlate those in the logs.

## Getting Max Value

- **Capture logs first** — check `esxcli system syslog config get` for a remote copy; RAM-backed ESXi logs die on reboot.
- **The enable-event is your anchor** — SSH/shell turning on brackets the intrusion window.
- **Check the persisted-only spots** for persistence (`rc.local.d`, crontab, VIBs, bootbank) — the RAM disk resets, so anything that survives is deliberately persisted.
- **Preserve VM/datastore state during ransomware** — don't reboot mid-encryption if VMs are salvageable; capture encrypted samples + note + encryptor.
- **Pivot to vCenter** — a VCSA compromise controls the whole estate; its `vpxd.log` ties actions to users and source IPs.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| The full ransomware chain + recovery | **ESXi and Linux Ransomware Playbook** (15) |
| Triage the ELF encryptor / VIB backdoor | **ELF and Malware Triage** (11b), **IOC and YARA** (11d) |
| How they reached the management network | **Authentication and Login Records** (06), **Network and PCAP** (10c) |
| Snapshot-based recovery | **Btrfs**/**Filesystem Triage** (07) (guest side) |
| Timeline enable → power-off → encrypt | **Timelining** (13) |
| Credential rotation + hypervisor rebuild | **Remediation and Containment** (14) |

## Scenarios

- **Ransomware prelude:** SSH enabled → VMs powered off → snapshots deleted → ELF encryptor over `/vmfs/volumes/`.
- **VIB backdoor:** a non-VMware VIB (acceptance lowered) or a VirtualPita/Pie/Gate family member persists across reboot.
- **Boot persistence:** an unexpected command in `/etc/rc.local.d/local.sh` or root crontab.
- **Volatile-log loss:** no remote syslog configured — a reboot erases the RAM-backed evidence.
- **vCenter takeover:** VCSA `vpxd.log` shows an admin login abusing permissions across the estate.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| SSH/shell enabled on a host that should have it off | Attacker access prep |
| Non-VMware VIB + lowered acceptance level | Hypervisor persistence |
| Burst of VM power-offs | Unlocking vmdks before encryption |
| Snapshots deleted before an incident | Recovery denial |
| New local ESXi account / permission | Backdoor |
| Remote syslog not configured (volatile logs) | Evidence loss on reboot |
| Encryptor ELF iterating `/vmfs/volumes` | Active ransomware |
| Command in `/etc/rc.local.d/local.sh` or root crontab | ESXi boot persistence |
| VirtualPita/VirtualPie/VirtualGate-style VIB | Known ESXi VIB backdoor |

## Resources

- Broadcom KB — Location of ESXi log files: https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html
- Broadcom KB — Location of vCenter Server log files: https://knowledge.broadcom.com/external/article/312194/location-of-vcenter-server-log-files.html
- Broadcom KB — Log files for VMware products: https://knowledge.broadcom.com/external/article?articleNumber=322834
- ESXi log file locations (vSphere docs): https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/vsphere-security/securing-esxi-hosts/managing-esxi-log-files/esxi-log-file-locations.html
- Mandiant — malicious ESXi VIB backdoors (VirtualPita/VirtualPie/VirtualGate)
- MITRE ATT&CK: T1053.003 (Cron), T1543 (Create/Modify System Process), T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1562 (Impair Defenses)
