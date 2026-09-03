# Enterprise Management Artifacts

The management baseline of a corporate Mac — **MDM enrollment, configuration profiles, managed preferences, the management agent (Jamf/Intune/Munki/…), directory binding, and enterprise SSO**. Two reasons this matters in IR: (1) it defines **"expected" vs attacker-added** so you can spot a rogue profile, planted trust cert, or fraudulent MDM enrollment; (2) management itself is a **push channel for persistence** (profiles install LaunchDaemons, certs, proxies, and can run scripts as root). This is the read-side companion to the remediation note.

> 🔴 A profile or MDM enrollment is **root-level, remotely-controlled persistence**. Enumerate what's installed and *how it got there* (DEP/automated vs user-approved vs manual/phishing). An unexpected enrollment, a `PayloadRemovalDisallowed` profile from a web page, or a planted trusted root CA is a finding — remove at the source, not the endpoint. Cross-ref [`16 - Remediation`](<16 - Remediation and Containment.md>).

## Contents
- [Quick Triage](#quick-triage)
- [MDM Enrollment State](#mdm-enrollment-state)
- [Configuration Profiles](#configuration-profiles)
- [Managed Preferences (MCX)](#managed-preferences-mcx)
- [Management Agents](#management-agents)
- [Enterprise SSO and Directory](#enterprise-sso-and-directory)
- [Trust: Certificates, VPN, Wi-Fi](#trust-certificates-vpn-wi-fi)
- [FileVault Key Escrow](#filevault-key-escrow)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Is it MDM-managed, and HOW enrolled? (DEP/automated, user-approved, or manual)
sudo profiles status -type enrollment
sudo profiles list -verbose                 # every installed profile + identifier + install info

# Full payload contents (proxies, certs, restrictions, pushed daemons)
sudo profiles show 2>/dev/null | less

# Which management agent is present
ls -la /usr/local/jamf/bin/jamf /Library/Managed\ Installs /usr/local/bin/munki* \
       /Library/Intune* ~/Library/Logs/Microsoft/Intune 2>/dev/null

# Directory binding + enterprise SSO extension
dsconfigad -show 2>/dev/null
app-sso platform -s 2>/dev/null             # Platform SSO / Kerberos SSO extension state

# MDM client activity
sudo log show --last 1d --predicate 'process == "mdmclient" OR subsystem == "com.apple.ManagedClient"' 2>/dev/null | tail -40
```

---

## MDM Enrollment State

```bash
sudo profiles status -type enrollment
```

| Output | Meaning | Removable locally? |
|---|---|---|
| `MDM enrollment: No` | Not managed — any profile is **manual/phishing** | n/a |
| `MDM enrollment: Yes (User Approved)` | User-approved MDM — profiles are managed | Yes (`profiles remove -type enrollment`) |
| `Enrolled via DEP: Yes` / **Supervised** | Automated Device Enrollment (ABM/ASM) | 🔴 **No** — remove at the MDM/ABM console |

Supporting state:
```bash
ls -la /var/db/ConfigurationProfiles/Setup       # cloud-config / DEP setup state
cat /var/db/.AppleSetupDone 2>/dev/null           # provisioning marker
sudo profiles show -type enrollment               # enrollment profile detail (server URL, org)
```
The enrollment **server URL / org name** confirms *which* MDM owns the device — a mismatch = rogue enrollment.

---

## Configuration Profiles

Profiles are stored under `/var/db/ConfigurationProfiles/` and enumerated with `profiles`. Each contains one or more **payloads**: restrictions, certs, Wi-Fi/VPN, proxies, MCX prefs, or even LaunchDaemons.

```bash
sudo profiles list -verbose
sudo profiles show                                        # all payloads, decoded
ls -la /var/db/ConfigurationProfiles/Store/               # on-disk profile store
```

| Payload type in a profile | Why it matters in IR |
|---|---|
| `com.apple.mdm` | The enrollment itself |
| Certificate / SCEP / AD Cert | Trust injection — a planted root CA enables MITM |
| Web/Global **HTTP proxy**, Proxy PAC | Traffic redirection |
| VPN / Wi-Fi (802.1X) | Network access / on-path |
| `com.apple.ManagedClient` (MCX) | Managed preferences (can force settings, login items) |
| **LaunchDaemon/Agent payload** | Root persistence pushed via profile |
| Restrictions / TCC (PPPC) | Grants an app privacy permissions silently |

> A **PPPC** (Privacy Preferences Policy Control) payload can pre-grant TCC (camera, Full Disk Access, Accessibility) to a bundle id **without a user prompt** — an attacker profile using PPPC to grant itself Accessibility/FDA is high-severity. Cross-ref [`06 - TCC`](<06 - Transparency Consent and Control (TCC).md>).

---

## Managed Preferences (MCX)

MDM-forced settings land as plists under `/Library/Managed Preferences/`.

```bash
ls -la /Library/Managed\ Preferences/                 # /<user>/ and machine-level
ls -la /Library/Managed\ Preferences/<user>/
defaults read /Library/Managed\ Preferences/<user>/<domain> 2>/dev/null
```

These enforce things like login items, restrictions, and app config org-wide. An unexpected managed domain (e.g., a forced proxy or a login item you can't attribute to your MDM) is worth scrutiny — but remember these are **pushed**, so remediate at the MDM.

---

## Management Agents

Enterprise Macs run one (sometimes several) management/patching agents. Know the artifact paths so you can tell **expected tooling** from attacker software, and to pull their logs (install history, script runs, check-ins).

| Agent | Key paths | Logs |
|---|---|---|
| **Jamf Pro** | `/usr/local/jamf/`, `/Library/Application Support/JAMF/`, `jamf` binary | `/var/log/jamf.log` |
| **Munki** | `/Library/Managed Installs/`, `/usr/local/munki/` | `/Library/Managed Installs/Logs/ManagedSoftwareUpdate.log` |
| **Microsoft Intune** | Company Portal, `/Library/Intune/`, Intune agent | `~/Library/Logs/Microsoft/Intune/` |
| **Kandji** | `/Library/Kandji/`, `kandji` agent | `/Library/Kandji/…/logs` |
| **Mosyle** | `/private/var/mosyle/`, agent app | agent logs |
| **Addigy** | `/Library/Addigy/` | `/Library/Addigy/…` |
| **osquery / Fleet** | `/private/var/osquery/`, `/etc/osquery/` | osquery results log |
| **Chef / Puppet** | `/opt/chef/`, `/opt/puppetlabs/` | run logs |

```bash
# Jamf policy/script history (what management ran, and when)
sudo tail -50 /var/log/jamf.log 2>/dev/null
# Munki install history
sudo tail -50 /Library/Managed\ Installs/Logs/ManagedSoftwareUpdate.log 2>/dev/null
```

> These agents run as **root** and execute scripts on a schedule — a legitimate but powerful surface. Verify the agent binary's signature and that its LaunchDaemon matches the vendor; a "management agent" that isn't in your fleet's baseline is a red flag. (EDR/security agents surface as **system extensions** — enumerate with `systemextensionsctl list`; see [`12 - System Extensions`](<12 - Persistence Mechanisms/System Extensions.md>).)

---

## Enterprise SSO and Directory

Modern enterprise Macs authenticate against an IdP via an **SSO extension** (Platform SSO for Entra/Okta, or Kerberos SSO), and/or bind to **Active Directory**.

```bash
# SSO extension state (registration, IdP, device/user tokens)
app-sso platform -s 2>/dev/null                 # Platform SSO status
app-sso -l 2>/dev/null                          # list SSO tokens/realms
ls -la /Library/Managed\ Preferences/*/com.apple.extensiblesso* 2>/dev/null

# Active Directory / directory services
dsconfigad -show 2>/dev/null                    # AD domain, computer account, options
odutil show all 2>/dev/null | head              # OpenDirectory sessions/nodes
dscl localhost -list /                          # visible directory nodes (Local, Active Directory, LDAP)
```

Forensic value: the **IdP/realm** and **computer account** the Mac authenticates through. A SSO extension pointing at an **unexpected IdP**, or an AD bind to a domain that isn't yours, is identity compromise. Cross-ref [`03 - Users and Groups`](<03 - Users and Groups.md>).

---

## Trust: Certificates, VPN, Wi-Fi

Profiles and MDM commonly install **trusted certificates** and network configs. Inventory them — a planted root CA is a decrypt-everything capability.

```bash
# Admin-trusted roots + system keychain certs
sudo security dump-trust-settings -d
sudo security find-certificate -a -p /Library/Keychains/System.keychain | grep -c 'BEGIN CERT'
# Proxies currently in effect (profile-pushed or not)
scutil --proxy
networksetup -getwebproxy "Wi-Fi"; networksetup -getsecurewebproxy "Wi-Fi"
```

Map each trusted root and proxy back to a profile payload (`profiles show`). Anything trusted that isn't in a known profile → investigate. Removal steps live in [`16 - Remediation ▸ Malicious Certificates and Proxies`](<16 - Remediation and Containment.md>).

---

## FileVault Key Escrow

Managed Macs typically **escrow** the FileVault recovery key to MDM (institutional or personal recovery key). Relevant to IR access and to spotting tampering.

```bash
sudo fdesetup status                             # on/off, decrypting
sudo fdesetup list                               # enabled users
sudo fdesetup haspersonalrecoverykey             # personal recovery key present?
sudo fdesetup hasinstitutionalrecoverykey        # institutional (MDM) key present?
```

If escrow is expected but absent, or a recovery key was regenerated off-schedule, treat it as tampering with recovery/access. Detail: [`08 - FileVault`](<08 - FileVault.md>).

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `MDM enrollment` to a **server/org you don't recognize** | Rogue/fraudulent MDM enrollment (full remote control) |
| A profile installed via a **web page**, `PayloadRemovalDisallowed = true` | Phishing profile locking itself in |
| **PPPC** payload granting an app Accessibility / Full Disk Access silently | Privilege/TCC bypass via profile |
| Trusted **root CA** not tied to a known profile | TLS interception |
| Profile-pushed **proxy / PAC** you can't attribute | Traffic redirection / MITM |
| A **LaunchDaemon payload** inside a profile from an untrusted source | Root persistence via MDM/profile |
| A **management agent** not in your fleet baseline (or unsigned) | Attacker tooling masquerading as management |
| SSO extension / AD bind pointing at an **unexpected IdP/domain** | Identity infrastructure compromise |
| FileVault escrow **missing** where policy requires it, or key regenerated | Recovery/access tampering |

---

## Resources
- `man` pages: `profiles(1)`, `mdmclient`, `dsconfigad(8)`, `odutil(1)`, `app-sso(1)`, `security(1)`, `fdesetup(8)`
- [`16 - Remediation and Containment`](<16 - Remediation and Containment.md>) — removing rogue profiles, certs, proxies, and enrollments
- [`06 - Transparency Consent and Control (TCC)`](<06 - Transparency Consent and Control (TCC).md>) — PPPC-granted permissions
- [`12 - Persistence Mechanisms/System Extensions`](<12 - Persistence Mechanisms/System Extensions.md>) — EDR/security agents as system extensions
- [`03 - Users and Groups`](<03 - Users and Groups.md>) · [`08 - FileVault`](<08 - FileVault.md>)
