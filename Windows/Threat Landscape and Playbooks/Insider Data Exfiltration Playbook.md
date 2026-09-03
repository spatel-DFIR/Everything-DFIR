# Insider Data Exfiltration Playbook

The scenario this playbook owns: an authorized user — most often a departing or recently-resigned employee, sometimes someone acting while still employed — takes data out through a channel their own legitimate access already permits, using a cloud-sync client or a USB device rather than any exploit or malware. This module already has strong dedicated evidence coverage for both vectors: [`13 - Cloud Storage Artifacts (Local Evidence)`](<../13 - Cloud Storage Artifacts (Local Evidence)>) (OneDrive, Google Drive for Desktop, Box Drive, Dropbox) and [`09 - Removable Device (USB) Forensics`](<../09 - Removable Device (USB) Forensics.md>) — what was missing was the stitched investigative sequence this playbook provides.

> 🔴 **This is usually a "was here, is gone" investigation, not a "catch it live" one.** Unlike most playbooks in this folder, discovery here typically happens well after the fact — a tip, a competitor's suspiciously similar product, or a routine offboarding review, not a real-time alert. That changes the priority order: **preserve evidence and lock down access immediately once suspicion arises**, because the exfiltration itself is likely long since complete, and what you can still control is whether the access channel stays open and whether the evidence trail survives normal log rotation and re-imaging before you've collected it.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Identify the Vector](#identify-the-vector)
- [Scope What Was Taken](#scope-what-was-taken)
- [Timeline](#timeline)
- [Containment](#containment)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Attack Chain

An employee with legitimate access to sensitive data — frequently one who has resigned, been given notice, or is otherwise disgruntled — decides to take data with them → they stage what to take, which often produces a detectable spike in file-access volume or scope (opening far more files, or files well outside their normal job function, in a short window) as they locate and review what's worth copying → they move the data out through a channel their own access already permits, most commonly either **(a)** a cloud-sync client (OneDrive, Google Drive, Dropbox, Box) already installed on the corporate machine, signed into or newly authorized against a **personal** (non-corporate) account, or **(b)** a **removable USB device** plugged in specifically for the copy → this activity frequently clusters tightly around a resignation-notice date, well before the employee's actual last day → the employee departs, and the exfiltration is often discovered much later, if at all — through a tip, competitive intelligence, or a routine offboarding audit rather than any real-time security alert.

## Quick Triage

Run this the moment a suspicion surfaces — a resignation, an HR referral, a manager's tip, or a DLP alert. Because discovery is usually retrospective, "quick" here means fast to run, not necessarily fast to resolve.

```powershell
# Any cloud-sync client installed, and is it signed into a personal account - the fastest single check
# (per-provider registry/config paths - see the 13/ note for the specific client in question)
Get-ItemProperty 'HKCU:\Software\Microsoft\OneDrive\Accounts\*' -ErrorAction SilentlyContinue | Select-Object *
Get-ItemProperty 'HKCU:\Software\Google\DriveFS' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKCU:\Software\Box' -ErrorAction SilentlyContinue

# USB storage device connection history - the fastest single check (09's core artifact)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue |
    Select-Object FriendlyName, @{N='Serial';E={$_.PSChildName}}

# File-access volume spike - RecentDocs/LNK count in the suspected window vs. this user's normal baseline (07)
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\*.lnk" | Where-Object LastWriteTime -gt (Get-Date).AddDays(-14) |
    Measure-Object | Select-Object Count
```

## Identify the Vector

### Cloud-sync

1. **Confirm the account signed into the sync client is personal, not corporate** — the single most decisive fact for this vector. A corporate-account sync to a corporate-sanctioned tenant is routine business use; a personal Gmail/personal Microsoft account signed into the same client on a corporate machine is the finding.
2. **Check sync-folder membership changes** — a folder newly added to the sync scope shortly before departure, especially one covering a sensitive share the employee doesn't normally sync, is a strong staging tell.
3. **Confirm actual upload activity, not just client presence** — a signed-in personal account with no corresponding local-cache write/upload activity in the suspected window is a weaker finding than one with confirmed file movement. Each provider's note under `13/` covers its own local-cache/log mechanics in depth; don't re-derive that here.

### Removable media

1. **Pull the full USBSTOR linkage chain** (note 09) — vendor/product, serial number, connection timestamps, and drive-letter mapping for any device connected in the suspected window.
2. **Confirm user attribution** — which logged-on user's session the device was connected under, via the same registry/event correlation note 09 already covers.
3. **Check actual file-interaction evidence, not just device presence**, if object-access auditing (4663/4656) was enabled — a device merely being *connected* proves opportunity, not that anything was actually copied to it; the file-interaction events (or their absence) are what separates the two.

**Key evidence artifact to check first:** for cloud-sync, the account identity signed into the client; for USB, the device's connection timestamp cross-referenced against the file-access-volume spike from Quick Triage.

**What a positive finding looks like in practice:** a personal cloud account newly signed into a corporate machine's sync client, with a sensitive folder added to sync scope and confirmed upload activity, in the days immediately following a resignation notice — or a USB device with no prior history on the host, connected once in a similar window, with a burst of RecentDocs/LNK/Shellbags activity touching files outside the user's normal scope shortly beforehand.

## Scope What Was Taken

The goal here is a specific file list, not just "exfiltration occurred."

```powershell
# Cross-reference the RecentDocs/LNK/Shellbags targets from the access-volume-spike window (07) against
# the sync-folder path or the window the USB device was connected - this is what turns "some activity
# happened" into "these specific files were accessed and are candidates for what left the building"
Get-ChildItem "$env:AppData\Microsoft\Windows\Recent\*.lnk" | Where-Object LastWriteTime -gt '<spike_window_start>' |
    Select-Object Name, LastWriteTime, Target

# For cloud-sync: local cache modification times within the sync client's own log/database (13/ per-provider notes)
# For USB: object-access Security events (4663) scoped to the connection window, if auditing was enabled (09)
```

Report the actual file list (or the best reconstruction of it) to whoever owns the response decision — legal, HR, or leadership — since what was taken (customer data, source code, financial records) drives everything downstream, from breach-notification obligations to whether law enforcement or civil action is warranted. That determination is outside this playbook's scope, but the evidence feeding it isn't.

## Timeline

```powershell
# The four dates that matter, in order: resignation-notice date (from HR, not forensics) -> file-access-
# volume-spike window (07) -> sync-upload or USB-connection timestamp (13/09) -> actual departure date
```

The classic pattern — and the strongest circumstantial evidence when present — is a tight cluster of unusual file access and exfiltration activity landing **after the resignation notice but before the actual departure date**. Access that happened routinely over months beforehand, with no spike near the notice date, is much weaker evidence of intentional theft and may just be normal job-function access.

## Containment

Unlike a malware incident, there is no payload to eradicate — containment here means cutting off the channel and preserving what's left.

```powershell
# Disable the account immediately once suspicion is confirmed - don't wait for a scheduled offboarding date
Disable-ADAccount -Identity '<departing_employee_account>'

# Revoke the cloud-sync client's OAuth/app authorization at the tenant/admin-console level (provider-specific;
# the local registry checks above only confirm client-side state, not whether the grant is still live)

# If the device is MDM-enrolled and still in the employee's possession, a remote wipe may be warranted -
# coordinate with legal/HR before doing this, since it can also destroy evidence you still need to collect
```

**Preserve evidence before or in parallel with containment, not after** — a re-image or account deletion following routine offboarding procedure can destroy exactly the artifacts this playbook depends on. Coordinate with whoever owns offboarding to pause standard procedure the moment this investigation opens (note 02's acquisition/imaging discipline applies here as much as in any other case).

## Credential Reset

```powershell
# Rotate any shared or service credential the departing employee had access to or knowledge of -
# not just their own personal account, which disabling above already handles
```

Revoke any API keys, shared service-account passwords, or admin credentials this specific individual had access to or knew — a disabled personal AD account doesn't address a shared credential they could still use or has already shared elsewhere. Review their access history for any credential handed to them during their tenure that was never subsequently rotated.

## Fleet Hunt

```powershell
# Broader compliance sweep, independent of this specific case: any host with a personal cloud-sync
# account signed in - a standing policy violation worth surfacing regardless of active suspicion
Invoke-Command -ComputerName (Get-Content C:\hunt\all_hosts.txt) -ScriptBlock {
    Get-ItemProperty 'HKCU:\Software\Microsoft\OneDrive\Accounts\*' -ErrorAction SilentlyContinue
}

# Check whether other employees who departed or gave notice around the same time show the same
# access-spike-then-exfil pattern - coordinated or copycat insider activity is worth ruling out
```

## Correlate With

| To go deeper on… | Open |
|---|---|
| Per-provider cloud-sync local cache, registry artifacts, account-identity detection, sync-folder mechanics | [`13 - Cloud Storage Artifacts (Local Evidence)`](<../13 - Cloud Storage Artifacts (Local Evidence)>) — OneDrive, Google Drive for Desktop, Box Drive, Dropbox |
| USBSTOR linkage chain, connection timestamps, user attribution, file-interaction auditing | [`09 - Removable Device (USB) Forensics`](<../09 - Removable Device (USB) Forensics.md>) |
| RecentDocs, Shellbags, LNK files, WordWheelQuery — the file-access-volume evidence this playbook's scoping step depends on | [`07 - File and Folder Opening (User Activity)`](<../07 - File and Folder Opening (User Activity).md>) |
| Evidence acquisition/imaging discipline for preserving state before offboarding/re-imaging proceeds | [`02 - Evidence Acquisition & Imaging`](<../02 - Evidence Acquisition & Imaging.md>) |
| Account/logon record correlation for user attribution | [`05 - Users, Groups & Authentication`](<../05 - Users, Groups & Authentication.md>) |

## Red Flags

| 🔴 Finding | Meaning |
|---|---|
| Personal (non-corporate) account signed into a cloud-sync client on a corporate machine | The single most decisive cloud-sync tell |
| Sync-folder scope expanded to include a sensitive share shortly before departure | Staging behavior — the employee widened what the sync client could see |
| USB device with no prior history on the host, connected once in the suspected window | Purpose-brought device, not routine peripheral use |
| Burst of file-access-volume (RecentDocs/LNK/Shellbags) outside the user's normal job scope | Staging/review activity ahead of the actual copy |
| Access spike and exfil activity clustering tightly after a resignation notice but before departure | The classic insider-exfiltration timing pattern |
| Standard offboarding (re-image, account deletion) proceeding before evidence preservation | Destroys exactly the artifacts this investigation depends on |
| Shared/service credential known to the departing employee left unrotated post-departure | A standing access risk independent of whether exfiltration is proven |

## Resources

- MITRE ATT&CK **T1567.002** (Exfiltration Over Web Service: Exfiltration to Cloud Storage) — https://attack.mitre.org/techniques/T1567/002/
- MITRE ATT&CK **T1052.001** (Exfiltration Over Physical Medium: Exfiltration over USB) — https://attack.mitre.org/techniques/T1052/001/
- MITRE ATT&CK **T1074** (Data Staged) — https://attack.mitre.org/techniques/T1074/
