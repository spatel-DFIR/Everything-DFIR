# Enterprise Management and Baseline

The "expected vs attacker-added" baseline for fleet Linux. Config-management agents, EDR/monitoring, domain join, TLS trust, and cloud provisioning all look like remote code execution — know your legitimate management stack before you hunt, or you'll chase Ansible as malware. This note has two jobs: help you recognize the legitimate management footprint so you don't false-positive on it, and flag the specific ways that same footprint gets subverted (a hijacked config-management server is root on every host; a rogue CA is silent TLS interception; a cloud-init backdoor reappears on every reprovision).

> 🔴 Legitimate fleet management *is* remote code execution running as root on a schedule — which is indistinguishable from an attacker's dream unless you know the baseline. Establish what management tooling is supposed to be here (and which servers it trusts) *before* you hunt, then look for the subversions: a config-management agent pointed at an unexpected server, an extra trusted CA, an `sssd.conf` LDAP redirect, or a backdoor in cloud-init user-data.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Configuration Management](#configuration-management)
- [Enterprise Agents](#enterprise-agents)
- [Domain Join and Directory](#domain-join-and-directory)
- [TLS Trust and Certificates](#tls-trust-and-certificates)
- [Cloud Provisioning](#cloud-provisioning)
- [Cloud Metadata and IMDS](#cloud-metadata-and-imds)
- [Package Repos and Keys](#package-repos-and-keys)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# What management tooling is installed/running?
systemctl list-units --type=service --state=running | grep -Ei "ansible|puppet|chef|salt|osquery|wazuh|ossec|falcon|datadog|splunk|filebeat|zabbix|nessus|qualys"

# Config-management config dirs
ls -d /etc/ansible /etc/puppetlabs /etc/chef /etc/salt 2>/dev/null

# Domain join state
realm list 2>/dev/null; systemctl status sssd 2>/dev/null | head -3

# Trusted CAs (rogue CA = interception)
ls -la /usr/local/share/ca-certificates/ /etc/pki/ca-trust/source/anchors/ 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| What management tooling is legit here? | running services grep (Ansible/Puppet/Salt/EDR/…) |
| Config-mgmt pointed at a rogue server? | `puppet.conf server=`, `salt/minion master=`, `ansible-pull` git URL |
| Is a "management" process actually C2? | baseline agent binary path + endpoint |
| Rogue CA = TLS interception? | `/usr/local/share/ca-certificates/`, `trust list` |
| Directory redirect / cred theft? | `sssd.conf` LDAP server; `/var/lib/sss/db/` |
| Cloud-init backdoor (re-provisions)? | `/var/lib/cloud/instance/user-data.txt`; `runcmd` |
| Cloud creds stolen via metadata SSRF? | IMDS access from an app; `curl 169.254.169.254/…/iam/` |
| Rogue repo / signing key? | `sources.list.d`, `yum.repos.d`, `gpgcheck=0` |

## Configuration Management

🔴 These tools *are* legitimate remote execution — they run as root, pull code from a server, and change the system on a schedule. That's also exactly what an attacker wants, so baseline them: know the server they talk to and what they're allowed to do.

```bash
# Ansible (usually push, but ansible-pull runs from cron/git)
ls -la /etc/ansible/; grep -rH "ansible-pull" /etc/cron* 2>/dev/null

# Puppet
cat /etc/puppetlabs/puppet/puppet.conf 2>/dev/null       # server=
ls -la /opt/puppetlabs/puppet/cache/reports/ 2>/dev/null # run history

# Chef
cat /etc/chef/client.rb 2>/dev/null                       # chef_server_url
ls -la /var/log/chef/ 2>/dev/null

# SaltStack (minion pulls from master and executes)
cat /etc/salt/minion 2>/dev/null | grep -E "^master|^id"
```

Abuse angle: an attacker who compromises the config-management **server** (or edits a local `ansible-pull` git URL / salt master pointer) gets root on every managed host. Verify the server endpoint each agent trusts is the real one.

## Enterprise Agents

Inventory the expected monitoring/security agents so their processes and network connections aren't mistaken for C2:

```bash
# EDR / AV / HIDS
systemctl list-units | grep -Ei "falcon|defender|mdatp|sentinel|carbonblack|cortex|osquery|wazuh|ossec|auditbeat"

# osquery (fleet queries)
cat /etc/osquery/osquery.conf 2>/dev/null; ls /etc/osquery/

# Log shippers / telemetry
ls -d /etc/filebeat /etc/rsyslog.d /opt/splunkforwarder /etc/datadog-agent 2>/dev/null

# Backup agents
systemctl list-units | grep -Ei "veeam|bacula|restic|borg|commvault|rubrik"
```

Record each agent's binary path, service name, and the endpoint it talks to — this is your allowlist when triaging processes and sockets on the fleet.

## Domain Join and Directory

```bash
# SSSD (most common modern AD/LDAP integration)
cat /etc/sssd/sssd.conf 2>/dev/null                       # domains, LDAP/AD servers
ls -la /var/lib/sss/db/ 2>/dev/null                        # cached credentials

# realmd
realm list

# Winbind / Samba
cat /etc/samba/smb.conf 2>/dev/null | grep -Ei "realm|workgroup|security"

# Kerberos
cat /etc/krb5.conf 2>/dev/null; klist 2>/dev/null          # cached tickets

# NSS resolution order
cat /etc/nsswitch.conf
```

Domain-joined hosts resolve users via the directory — a local account shadowing a domain name, or a change to `sssd.conf` pointing at a rogue LDAP server, is suspicious. Cached SSSD credentials can be a credential-theft target.

## TLS Trust and Certificates

🔴 A rogue CA in the system trust store lets an attacker intercept TLS (MITM proxy, fake update server) with no warnings.

```bash
# Debian: locally-added trusted CAs
ls -la /usr/local/share/ca-certificates/; cat /etc/ca-certificates.conf

# RHEL: trust anchors
ls -la /etc/pki/ca-trust/source/anchors/

# List everything currently trusted, look for unexpected issuers
trust list 2>/dev/null | grep -i "label" | sort | uniq

awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{c=cmd} {print | c} /END/{close(c)}' /etc/ssl/certs/ca-certificates.crt 2>/dev/null | sort -u | head
```

Compare the trusted-CA set to a known-good host of the same build; any extra locally-added CA needs an owner and a reason.

## Cloud Provisioning

🔴 cloud-init user-data runs (often as root) at first boot — a backdoor placed there re-appears on every re-provision.

```bash
# cloud-init config + the user-data it ran
cat /var/lib/cloud/instance/user-data.txt 2>/dev/null

ls -la /var/lib/cloud/instance/scripts/ 2>/dev/null

cat /etc/cloud/cloud.cfg 2>/dev/null | grep -Ei "users|runcmd|ssh"

# cloud-init logs (what ran at provision time)
cat /var/log/cloud-init.log /var/log/cloud-init-output.log 2>/dev/null | tail -50

```

## Cloud Metadata and IMDS

🔴 The instance metadata service (`169.254.169.254`) hands out the instance's **IAM role credentials** to anything on the host that can reach it. A compromised web app (via SSRF) or any foothold can pull those creds and then act as the instance's cloud role — one of the most common cloud-Linux escalation paths.

```bash
# Was the metadata service hit for credentials? (app logs / auth / shell history)
grep -rEn '169\.254\.169\.254|metadata\.google|/latest/meta-data|/iam/security-credentials' \
  /var/log /home/*/.*history /root/.*history 2>/dev/null

# IMDSv1 (no token) is the risky one; IMDSv2 requires a PUT token first
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null   # if this returns a role, IMDSv1 is open

# The creds an attacker would harvest on-disk
ls -la /home/*/.aws /root/.aws /home/*/.config/gcloud /var/lib/kubelet 2>/dev/null
```

🔴 An app or shell reaching `169.254.169.254/…/iam/security-credentials/` — especially with IMDSv1 (no token) enabled — is likely cloud-credential theft. Rotate the instance role at the provider (a host rebuild doesn't revoke stolen role creds).

## Package Repos and Keys

Cross-referenced with the Package Managers note — part of the baseline:

```bash
# Approved repos + signing keys (rogue entry = malicious packages install cleanly)
ls -l /etc/apt/sources.list.d/ /etc/yum.repos.d/ 2>/dev/null

grep -rH "gpgcheck=0" /etc/yum.repos.d/ 2>/dev/null       # signature enforcement off
```

## Deep Threat Hunts

Baseline-diff the management stack, then hunt the subversions. *(seasoned-DFIR)*

```bash
# 1. Config-mgmt pointed at an unexpected server (root on every managed host)
grep -rEn '^server|^master|chef_server_url|ansible-pull' /etc/puppetlabs /etc/salt/minion /etc/chef 2>/dev/null

grep -rH 'ansible-pull' /etc/cron* /etc/systemd 2>/dev/null

# 2. Extra locally-added trusted CA vs a golden host (TLS interception)
ls -la /usr/local/share/ca-certificates/ /etc/pki/ca-trust/source/anchors/ 2>/dev/null

trust list 2>/dev/null | grep -i label | sort -u

# 3. Directory redirect / cached-cred theft
grep -Ei 'ldap_uri|ad_server' /etc/sssd/sssd.conf 2>/dev/null; ls -la /var/lib/sss/db/ 2>/dev/null

# 4. Cloud-init backdoor that reappears on reprovision
cat /var/lib/cloud/instance/user-data.txt 2>/dev/null; grep -A5 -iE 'runcmd|bootcmd' /etc/cloud/cloud.cfg 2>/dev/null

# 5. Cloud metadata / IAM cred theft
grep -rEn '169\.254\.169\.254|/iam/security-credentials' /var/log /home/*/.*history 2>/dev/null

# 6. "Management" agent that isn't in the approved allowlist
systemctl list-units --type=service --state=running | grep -Ei 'ansible|puppet|salt|osquery|wazuh|falcon|splunk|datadog'

# 7. Rogue repo / signing key
grep -rH 'gpgcheck=0' /etc/yum.repos.d/ 2>/dev/null; grep -rhE '^deb .*http:' /etc/apt/sources.list* 2>/dev/null
```

**Hunt ideas:**

- **Baseline the whole management footprint against a golden host** — config-mgmt endpoints, agents, trusted CAs, repos, cloud-init — the delta is the subversion.
- **A config-management server pointer is root on every managed host** — verify each agent's `server=`/`master=` is the real one.
- **The metadata service is the cloud escalation path** — a foothold reaching `169.254.169.254/…/iam/` steals the instance role; rotate at the provider.
- **A rogue trusted CA is silent TLS interception** — diff the trust store; any extra locally-added CA needs an owner.
- **Cloud-init `runcmd`/user-data reappears on every reprovision** — a backdoor there survives instance replacement.

## Getting Max Value

- **Establish the legitimate baseline *before* you hunt** — legit fleet management is root-level remote execution; without the allowlist you'll chase Ansible as malware.
- **Diff against a golden host** for CAs, agents, repos, config-mgmt endpoints, and cloud-init.
- **Rotate cloud IAM at the provider, not just on the host** — stolen role creds and metadata-derived tokens survive a rebuild.
- **Record each agent's binary path + endpoint** as your process/socket allowlist for the fleet.
- **Cross-ref Package Managers** for repo/key integrity and the `rpm --rebuilddb` caveat.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Repo/signing-key integrity + `rpm -Va` | **Package Managers and Integrity** (08) |
| Domain accounts / SSSD cache / local-shadow-of-domain | **Users Groups and Authentication** (03) |
| A "management" agent that's actually C2 | **Live Response** (10), **Network and PCAP** (10c) |
| Fleet-wide subversion hunt | **IOC and YARA Scanning** (11d), **Evidence Collection** (12) |
| Rotate cloud/IdP creds + rebuild | **Remediation and Containment** (14) |
| eBPF/EDR monitoring baseline | **eBPF Tooling** (10d) |

## Scenarios

- **Config-mgmt hijack:** a Puppet/Salt master (or an `ansible-pull` git URL) pointed at an attacker server = root on every managed host.
- **TLS interception:** an extra locally-added CA in the trust store silently MITMs updates/traffic.
- **Directory redirect:** `sssd.conf` pointed at a rogue LDAP server harvests domain auth.
- **Reprovision backdoor:** a payload in cloud-init user-data reappears on every instance rebuild.
- **Cloud cred theft:** an app SSRFs the metadata service and steals the instance IAM role.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `ansible-pull`/salt master/chef server pointing at an unexpected host | Config-mgmt hijack → fleet root |
| New/unknown "management" agent process | Possible C2 masquerading as tooling |
| Extra locally-added trusted CA | TLS interception |
| `sssd.conf` LDAP server changed | Directory redirection / cred theft |
| Backdoor in cloud-init user-data | Re-appears on every re-provision |
| Rogue repo or `gpgcheck=0` | Malicious packages install as trusted |
| Cached SSSD/Kerberos creds accessed by odd process | Credential theft |
| App/shell reaching `169.254.169.254/…/iam/` | Cloud IAM credential theft |
| IMDSv1 (no-token metadata) enabled | Easier metadata SSRF |

## Resources

- Ansible, Puppet, Chef, SaltStack docs (for expected file layouts)
- SSSD documentation — https://sssd.io
- cloud-init documentation — https://cloudinit.readthedocs.io
- AWS IMDSv2 (mitigation) — https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- MITRE ATT&CK: T1552.005 (Cloud Instance Metadata API), T1556 (Modify Auth Process), T1554 (Compromise Host Software), T1195 (Supply Chain), T1072 (Software Deployment Tools)
