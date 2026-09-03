# Remediation and Containment

The **eradication and recovery** commands for a compromised enterprise Mac. You got an EDR/SIEM alert, triaged it ([`15 - Live Response`](<15 - Live Response and Volatile Data.md>)), confirmed the activity is malicious — now you remove the footholds, remediate the account and its cloud identity, reset what's exposed, and restore posture. Authorized IR work on a managed endpoint; this is the one note in this reference that intentionally **changes the system**.

> 🔴 **The macOS re-spawn trap:** a LaunchDaemon/Agent with `KeepAlive` **restarts within seconds** of a `kill`. The reliable sequence is always **unload → disable → delete the plist → delete the payload → kill the process → verify**. Killing the PID alone accomplishes nothing.
>
> 🔴 **Identity is the real crown jewel.** On a modern enterprise Mac the endpoint is replaceable — the user's **SSO identity and its live cloud sessions** are what the attacker actually wants. Cleaning the Mac without revoking sessions/tokens at the IdP leaves them logged in.

## Contents
- [Remediation Flow](#remediation-flow)
- [Kill the Running Payload](#kill-the-running-payload)
- [Remove Persistence](#remove-persistence)
  - [Launch Daemons and Agents](#launch-daemons-and-agents)
  - [Cron and Periodic](#cron-and-periodic)
  - [Login Items and Background Tasks](#login-items-and-background-tasks)
  - [System Extensions and Kexts](#system-extensions-and-kexts)
  - [Privileged Helper Tools](#privileged-helper-tools)
  - [SSH Backdoors](#ssh-backdoors)
  - [Dylib Injection](#dylib-injection)
  - [Sudoers and PAM](#sudoers-and-pam)
- [Configuration Profiles and MDM](#configuration-profiles-and-mdm)
- [Malicious Certificates and Proxies](#malicious-certificates-and-proxies)
- [Account Remediation](#account-remediation)
- [Credential, SSO, and Session Reset](#credential-sso-and-session-reset)
- [EDR Coordination and Fleet Scope](#edr-coordination-and-fleet-scope)
- [Restore Security Posture](#restore-security-posture)
- [Verify Remediation](#verify-remediation)
- [Network Isolation (EDR fallback)](#network-isolation-edr-fallback)
- [Common Mistakes](#common-mistakes)
- [Resources](#resources)

---

## Remediation Flow

The order that avoids re-spawn and re-infection:

| Step | Action |
|---|---|
| 1 | **Kill** the running payload (via launchd if it's a managed job, so it doesn't relaunch) |
| 2 | **Remove persistence** — every foothold, plus the binary/support files it drops |
| 3 | **Strip malicious config** — profiles, root certs, proxies (phishing-delivered) |
| 4 | **Remediate the account** — disable/delete rogue users, strip admin, revoke Secure Token |
| 5 | **Reset identity** — force reset, **revoke SSO sessions/tokens & reset MFA server-side** |
| 6 | **Restore posture** — Gatekeeper, firewall, XProtect, FileVault (SIP needs Recovery) |
| 7 | **Scope + verify** — hunt the IOCs fleet-wide, re-sweep, then **reboot** and re-sweep |

Each removal below maps to a [`12 - Persistence Mechanisms`](<12 - Persistence Mechanisms/Launch Daemons and Launch Agents.md>) surface and a [`hunt_persistence.sh`](scripts/hunt_persistence.sh) module, so what you found is what you remove.

---

## Kill the Running Payload

```bash
# If it's launchd-managed (most macOS malware is), stop the JOB — a plain kill re-spawns.
sudo launchctl print system | grep -i '<label>'          # confirm the service label
sudo launchctl kill SIGKILL system/<label>               # kill via launchd
sudo launchctl bootout system/<label>                    # unload for this boot
sudo launchctl disable system/<label>                    # stays unloaded across reboots

# Standalone process (or the GUI-session variant of the above → gui/$(id -u)/<label>)
sudo kill -9 <PID>
sudo pkill -9 -f '<binary-or-path-substring>'

# Confirm it's gone and NOT coming back
sleep 3; pgrep -fl '<pattern>' || echo "process gone"
```

| Symptom | What it means / do |
|---|---|
| PID returns seconds after `kill` | `KeepAlive` job — `bootout` + `disable` + delete the plist, then kill |
| `bootout` says "No such process" | Wrong domain — daemons are `system/`, per-user agents are `gui/$(id -u)/` |
| Binary path shows `(deleted)` | It unlinked itself; killing it frees the last handle — fine, it's already off disk |

---

## Remove Persistence

Enterprise-Mac reality: most infections are an **adware/stealer LaunchAgent** pointing at a payload in `~/Library/Application Support/<random>/`, a **rogue login item**, or a **config profile from a phishing page**. Remove the launch point **and** the files it runs — a leftover payload gets re-registered by a second stage.

### Launch Daemons and Agents
```bash
P=/Library/LaunchDaemons/<name>.plist            # or /Library/LaunchAgents, ~/Library/LaunchAgents
LABEL=$(defaults read "${P%.plist}" Label 2>/dev/null)
BIN=$(defaults read "${P%.plist}" Program 2>/dev/null \
      || defaults read "${P%.plist}" ProgramArguments 2>/dev/null | sed -n '2p' | xargs)

sudo launchctl bootout system "$P" 2>/dev/null   # agent variant: launchctl bootout gui/$(id -u) "$P"
sudo launchctl disable system/"$LABEL"
sudo rm -f "$P"                                   # remove the launch point
sudo rm -rf "$BIN"                                # remove the payload it launched
rm -rf ~/Library/Application\ Support/<random-name>   # adware usually drops a support dir too
```

### Cron and Periodic
```bash
sudo crontab -r -u <user>                          # remove that user's crontab
sudo rm -f /usr/local/etc/periodic/*/<script>      # non-standard periodic scripts
sudo sed -i '' '/<malicious-line>/d' /etc/crontab 2>/dev/null
```

### Login Items and Background Tasks
```bash
osascript -e 'tell application "System Events" to delete login item "<Name>"'   # per-user, run as that user
# App-bundled SMLoginItem / BTM item: delete the parent .app, then if the BTM store is polluted:
sudo sfltool resetbtm                              # rebuilds the Background Task Mgmt DB (all users)
sudo defaults delete /var/root/Library/Preferences/com.apple.loginwindow LoginHook 2>/dev/null   # legacy hooks
```

### System Extensions and Kexts
```bash
systemextensionsctl list
sudo systemextensionsctl uninstall <TeamID> <bundleID>     # needs owning app; SIP-aware

sudo kmutil unload -b <bundleID> 2>/dev/null || sudo kextunload -b <bundleID>
sudo rm -rf /Library/Extensions/<name>.kext
sudo kmutil install --update-all 2>/dev/null               # rebuild boot kext collection
```

### Privileged Helper Tools
```bash
sudo launchctl bootout system/<id> 2>/dev/null
sudo rm -f /Library/PrivilegedHelperTools/<id>
sudo rm -f /Library/LaunchDaemons/<id>.plist               # the daemon that launches it
```

### SSH Backdoors
```bash
sudo sed -i '' '/<attacker-key-substring>/d' /Users/<user>/.ssh/authorized_keys
sudo rm -f /Users/<user>/.ssh/authorized_keys2             # rarely legitimate
sudo vi /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*      # revert ForceCommand / AuthorizedKeysCommand / PermitRootLogin yes
sudo rm /etc/ssh/ssh_host_* && sudo ssh-keygen -A          # rotate host keys if fully owned
```

### Dylib Injection
```bash
sudo launchctl unsetenv DYLD_INSERT_LIBRARIES              # clear global injection
sudo rm -f /etc/launchd.conf                               # legacy global injector
grep -rIl 'DYLD_INSERT_LIBRARIES' /Users/*/.z* /Users/*/.bash* /etc 2>/dev/null   # then edit those out
```

### Sudoers and PAM
```bash
sudo visudo                                        # remove NOPASSWD / rogue user grants (visudo VALIDATES)
sudo rm -f /etc/sudoers.d/<file>
ls -la /etc/pam.d/                                 # restore a tampered file from a known-good same-version Mac
```

---

## Configuration Profiles and MDM

Two very different situations hide behind "there's a profile" — handle them differently. Phishing pages talk users into installing a `.mobileconfig` that sets a **rogue proxy, a trusted root CA (TLS intercept), a forced search engine, or even its own LaunchDaemon**; a nastier variant **enrolls the Mac into an attacker-controlled MDM**.

**1. Identify what you're looking at (needs root):**
```bash
sudo profiles show                       # full payload contents: proxies, certs, restrictions, MCX
sudo profiles list -verbose              # each profile + its identifier and install info
profiles status -type enrollment         # is this Mac MDM-enrolled? DEP/Automated? User-Approved?
```

| `profiles status -type enrollment` says | Meaning |
|---|---|
| `MDM enrollment: No` | No MDM — any profile here was installed **manually/by phishing** → remove locally |
| `MDM enrollment: Yes (User Approved)` | Enrolled, user-approvable — profiles are MDM-managed; **user-approved enrollment is removable** locally |
| `Enrolled via DEP: Yes` / supervised | Automated Device Enrollment — **cannot be unenrolled locally**; do it at the MDM/ABM console |

**2a. Manually / phishing-installed profile (no MDM, or a stray user profile):**
```bash
sudo profiles remove -identifier <profile-identifier>    # remove one
# GUI equivalent: System Settings ▸ Privacy & Security ▸ Profiles ▸ select ▸ (–)
```
A `PayloadRemovalDisallowed = true` key can block removal — a common attacker trick. If `profiles remove` refuses, delete the on-disk profile store and reboot:
```bash
sudo ls -la /var/db/ConfigurationProfiles/Store/    # (or /Library/Managed Preferences for MCX)
```
Then continue to **Malicious Certificates and Proxies** below — removing the profile does **not** always remove the CA/proxy it installed.

**2b. Company profile the attacker abused, or a device that's legitimately MDM-managed:**
- **Don't fight it locally** — an MDM-pushed profile reinstalls minutes after you delete it. Fix it at the source: in your **MDM console** (Jamf, Intune, Kandji, Mosyle, …) send a **RemoveProfile** command for the bad payload, then push a corrected profile/policy to the device (and, if the payload was mis-scoped, to the whole affected group).
- Use MDM to **re-enforce** posture at scale — FileVault, Gatekeeper, firewall, allowed system extensions — rather than touching each Mac by hand.
- If the profile installed a **certificate or proxy**, also push a policy that removes/replaces it; MDM-delivered certs must be pulled by MDM.

**2c. Rogue MDM enrollment (attacker's MDM):**
```bash
profiles status -type enrollment                      # confirm the enrollment
sudo profiles remove -type enrollment                 # unenroll — works only if User-Approved & NOT supervised
```
If it's supervised / DEP-enrolled into the attacker's Apple Business Manager, you **cannot** remove it locally — the device must be **erased and re-provisioned** through your own ABM/MDM, and the fraudulent ABM enrollment disputed with Apple.

---

## Malicious Certificates and Proxies

A phishing profile's real damage is often a **root CA + web proxy** that lets the attacker read TLS traffic. Remove these explicitly — they can outlive the profile.

```bash
# List admin-trusted roots and system-keychain certs; spot the attacker CA
sudo security dump-trust-settings -d
sudo security find-certificate -a -Z /Library/Keychains/System.keychain | grep -iE 'labl|SHA-1'

# Delete the malicious CA (by common name) from System + login keychains
sudo security delete-certificate -c "<Cert Common Name>" /Library/Keychains/System.keychain
security delete-certificate -c "<Cert Common Name>" ~/Library/Keychains/login.keychain-db

# Rip out a forced web proxy (per network service)
networksetup -listallnetworkservices
networksetup -getwebproxy "Wi-Fi"; networksetup -getsecurewebproxy "Wi-Fi"; networksetup -getautoproxyurl "Wi-Fi"
sudo networksetup -setwebproxystate "Wi-Fi" off
sudo networksetup -setsecurewebproxystate "Wi-Fi" off
sudo networksetup -setautoproxystate "Wi-Fi" off
scutil --proxy                              # confirm: no HTTPProxy / ProxyAutoConfig left
```

| Look for | Why it matters |
|---|---|
| A non-Apple root in `dump-trust-settings` you can't attribute | TLS interception — attacker can decrypt the user's HTTPS |
| `HTTPSProxy` / `ProxyAutoConfigURLString` in `scutil --proxy` | Traffic is being funneled through an attacker host |
| Cert whose install time matches the phishing profile | Delivered together — remove both |

---

## Account Remediation

```bash
U=<user>

# Disable (reversible) — good enough while the ticket is open
sudo pwpolicy -u "$U" -disableuser
sudo pkill -u "$U"                                   # end their live local sessions

# Strip privilege
sudo dseditgroup -o edit -d "$U" -t user admin       # remove from local admin
sudo sysadminctl -secureTokenOff "$U" -password -    # revoke Secure Token (FileVault / crypto)

# Delete once confirmed
sudo sysadminctl -deleteUser "$U"                    # add -keepHome to retain /Users/Deleted Users/<u>
```

| Command | Effect |
|---|---|
| `pwpolicy -disableuser` | Blocks login, account intact (reversible) |
| `dseditgroup -d … admin` | Drops local-admin rights |
| `sysadminctl -secureTokenOff` | Revokes the token that unlocks FileVault / grants crypto ops |
| `sysadminctl -deleteUser` | Removes the account (`-keepHome` preserves the home dir) |

> **AD/Entra/network accounts aren't in the local node** — a mobile account you delete with `dscl` still exists upstream. Disable it at the directory server, and see the IdP steps next. Ref: [`03 - Users and Groups`](<03 - Users and Groups.md>).

---

## Credential, SSO, and Session Reset

The password change is the easy half — **killing live sessions and tokens is what actually locks the attacker out.** A stealer that grabbed browser cookies or an OAuth refresh token doesn't need the password again.

**On the host (invalidate what's cached locally):**
```bash
sudo sysadminctl -resetPasswordFor <user> -newPassword - -adminUser <admin> -adminPassword -   # local pw
sudo kdestroy -A 2>/dev/null                                   # destroy Kerberos tickets
security lock-keychain ~/Library/Keychains/login.keychain-db   # lock the login keychain

# Cloud/dev tokens sitting in the home dir — remove locally, then ROTATE at the provider
gcloud auth revoke --all 2>/dev/null; rm -rf ~/.config/gcloud
rm -f ~/.aws/credentials          # then deactivate/rotate the key in AWS IAM
rm -f ~/.kube/config ~/.docker/config.json ~/.netrc
# GitHub (~/.config/gh), npm (~/.npmrc): delete here AND revoke the token/PAT server-side
```

**At the IdP — this is the part that ends the intrusion.** Do it in your identity provider's admin console (Okta, Microsoft Entra ID, Google Workspace, …):

| Action | Why |
|---|---|
| **Force password reset** at the IdP | Local reset doesn't touch the cloud identity |
| **Revoke all active sessions / sign-in tokens** | Kills live web sessions and issued refresh tokens |
| **Revoke OAuth app grants** | Third-party app tokens are token-persistence that survives a password change |
| **Reset & re-enroll MFA factors** | The attacker may have registered their own authenticator/passkey — a classic backdoor |
| **Remove app passwords / legacy API tokens** | Bypass credentials that skip MFA |
| **Force sign-out of browser & OS sessions** | Invalidate stolen browser cookies (stealer's payload) |

Concrete equivalents:
- **Entra ID:** `Revoke-MgUserSignInSession -UserId user@corp.com` (Graph PowerShell) + reset password → forces reauth everywhere.
- **Okta:** admin → "Clear user sessions" + "Reset Multifactor" (API: `DELETE /api/v1/users/{id}/sessions`, `POST /api/v1/users/{id}/lifecycle/reset_factors`).
- **Google Workspace:** admin → user → "Reset sign-in cookies" (sign out everywhere) + reset password + review "Connected apps."

---

## EDR Coordination and Fleet Scope

An enterprise incident is rarely one Mac. Before you close the ticket:

- **Confirm the agent is healthy** and reporting — malware sometimes disables/blinds it. Don't declare a host clean on the word of an agent the payload may have neutered.
- **Use the EDR console** to network-contain the host, confirm/trigger quarantine of the sample, and submit the file **hash** to threat intel. If EDR already quarantined it, don't hunt a file it moved.
- **Pivot the IOCs across the fleet** — same **file hash**, **LaunchAgent label**, **C2 domain/IP**, **installer/profile name**, or the **phishing sender**. Collect them from this host to hand to the hunt:
```bash
shasum -a 256 <payload-path>                       # file hash
echo '<launchd-label>  <c2-host-or-ip>'            # label + network IOC from triage
sudo hunt_persistence.sh deep | tee /tmp/host-iocs.txt   # foothold inventory for comparison
```
- After cleanup, **re-scan** in the EDR and confirm the detection resolves; open a detection-gap review if the technique ran unblocked.

---

## Restore Security Posture

```bash
sudo spctl --master-enable                                 # Gatekeeper back on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on --setstealthmode on
sudo softwareupdate --background-critical                  # pull latest XProtect defs; let XProtect Remediator run
fdesetup status                                            # enable FileVault if the attacker disabled it

# SIP CANNOT be re-enabled live. Reboot to Recovery (Apple silicon: hold power), then Terminal:
#   csrutil enable ; reboot
csrutil status
```

| Control | Re-enable live? |
|---|---|
| Gatekeeper (`spctl`) | Yes |
| App firewall (`socketfilterfw`) | Yes |
| XProtect defs (`softwareupdate`) | Yes |
| FileVault (`fdesetup`) | Yes |
| **SIP (`csrutil`)** | **No — Recovery Mode + reboot** |

Where you have MDM, push these as enforced policies fleet-wide instead of setting them per host.

---

## Verify Remediation

```bash
# 1. Payload not running / not listening
pgrep -fl '<pattern>' || echo "not running"
sudo lsof -nP -iTCP -sTCP:LISTEN | grep -i '<port-or-bin>' || echo "no listener"

# 2. Persistence + profiles gone — full read-only re-sweep
sudo bash scripts/hunt_persistence.sh deep
sudo profiles show | grep -i '<bad-identifier>' || echo "profile gone"

# 3. Account gone / disabled
dscl . -list /Users | grep -x '<user>' && echo "STILL PRESENT" || echo "removed"

# 4. THE REAL TEST: reboot, then re-sweep. Persistence that survives a reboot is what mattered.
sudo shutdown -r now
#   …after reboot…  sudo bash scripts/hunt_persistence.sh deep
```

Then trigger a fresh EDR scan and confirm the IdP shows no active sessions for the user.

---

## Network Isolation (EDR fallback)

Your EDR/MDM usually **network-contains** the host for you — use that first. Reach for these only when there's no agent, the agent is down, or you need an immediate manual cut:

```bash
# Block all inbound + stealth (keeps outbound mgmt path)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on --setblockall on --setstealthmode on

# Disable inbound remote access
sudo systemsetup -setremotelogin off
sudo launchctl bootout system/com.openssh.sshd 2>/dev/null

# Full cut (console-side — this also drops your own remote access)
sudo ifconfig en0 down
sudo networksetup -setairportpower en0 off
echo 'block drop all' | sudo pfctl -f - 2>/dev/null; sudo pfctl -e 2>/dev/null
```

---

## Common Mistakes

| ✋ Mistake | Consequence / fix |
|---|---|
| `kill` a `KeepAlive` job without `bootout` | Re-spawns in seconds — unload + disable + delete the plist, then kill |
| Deleting the plist but leaving the payload binary/support dir | Re-registered by a second stage — remove both |
| Removing the profile but leaving its **root CA / proxy** | TLS interception continues — delete the cert and clear the proxy explicitly |
| Fighting an **MDM-pushed** profile on the host | It reinstalls — remove it at the MDM console, push the fix from there |
| Editing `/etc/sudoers` with `vi` | One typo locks out **all** sudo — always `visudo` (it validates) |
| Rotating only the **local/on-host** password | Live SSO/cloud sessions & refresh tokens still valid — revoke server-side |
| Resetting the password but **not the MFA factors** | Attacker's enrolled authenticator/passkey is still a valid second factor |
| Disabling a **mobile AD/Entra account** locally and calling it done | Upstream identity still active — disable at the directory/IdP |
| Assuming `spctl --master-enable` re-enabled SIP | It didn't — **SIP needs Recovery Mode** |
| Remediating one Mac and closing the ticket | Hunt the IOCs fleet-wide — phishing campaigns hit more than one user |
| One clean sweep = done | Re-sweep **after a reboot** — that's the true persistence test |

---

## Resources

- `man` pages: `launchctl(1)`, `sysadminctl(8)`, `dscl(1)`, `dseditgroup(8)`, `pwpolicy(8)`, `profiles(1)`, `security(1)`, `networksetup(8)`, `spctl(8)`, `csrutil(8)`, `fdesetup(8)`, `socketfilterfw(8)`
- [`12 - Persistence Mechanisms`](<12 - Persistence Mechanisms/Launch Daemons and Launch Agents.md>) — what each foothold is, so you remove the right thing
- [`15 - Live Response and Volatile Data`](<15 - Live Response and Volatile Data.md>) — the triage that confirms what to remediate
- [`scripts/hunt_persistence.sh`](scripts/hunt_persistence.sh) — read-only sweep to find footholds and to **verify** they're gone post-remediation
